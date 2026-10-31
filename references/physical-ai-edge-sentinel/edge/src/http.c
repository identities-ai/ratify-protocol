/*
 * Bounded HTTP/1.1 listener.
 *
 * Deliberately minimal, and deliberately parses no JSON of its own: the action
 * arrives in headers and the request body is handed to the Ratify library
 * byte for byte, which decodes it strictly.
 *
 *   GET  /challenge  action headers -> challenge bound to the action
 *   POST /action     action headers, body = proof bundle -> decision
 *   POST /status     X-Sentinel-Status-Kind: list|push, body = signed object
 *   GET  /health     ready or recovering, quarantine, actuator count
 *
 * Action headers: X-Sentinel-Scope, X-Sentinel-Zone, X-Sentinel-Resource,
 * X-Sentinel-Duration-Ms, X-Sentinel-Invocation.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "http.h"
#include "actuator.h"

#define HEADER_MAX 8192
#define SOCKET_TIMEOUT_S 5
#define MIN_ACTION_INTERVAL_MS 100   /* crude rate limit; see note below */
#define DEFAULT_DURATION_MS 500

static volatile sig_atomic_t stop_requested = 0;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }

static void send_response(int fd, int code, const char *status,
                          const char *body)
{
    char head[256];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     code, status, strlen(body));
    if (write(fd, head, (size_t)n) < 0) return;
    if (write(fd, body, strlen(body)) < 0) return;
}

/* Read until the header terminator or the cap, whichever comes first. */
static ssize_t read_headers(int fd, char *buf, size_t cap, size_t *body_start)
{
    size_t used = 0;
    while (used < cap - 1) {
        ssize_t n = read(fd, buf + used, cap - 1 - used);
        if (n <= 0) return -1;
        used += (size_t)n;
        buf[used] = '\0';
        char *end = strstr(buf, "\r\n\r\n");
        if (end) {
            *body_start = (size_t)(end - buf) + 4;
            return (ssize_t)used;
        }
    }
    return -1;   /* headers too large */
}

/* Case-insensitive single-header lookup into `out`. Returns 1 if found. */
static int header_value(const char *headers, const char *name, char *out,
                        size_t out_cap)
{
    size_t namelen = strlen(name);
    const char *p = headers;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, name, namelen) == 0 && p[namelen] == ':') {
            const char *v = p + namelen + 1;
            while (*v == ' ' || *v == '\t') v++;
            const char *e = strpbrk(v, "\r\n");
            size_t len = e ? (size_t)(e - v) : strlen(v);
            if (len >= out_cap) len = out_cap - 1;
            memcpy(out, v, len);
            out[len] = '\0';
            return 1;
        }
    }
    return 0;
}

static void read_action(const char *headers, actx_action *a, int default_duration_ms)
{
    char durbuf[16] = "";
    memset(a, 0, sizeof *a);
    header_value(headers, "X-Sentinel-Scope", a->scope, sizeof a->scope);
    header_value(headers, "X-Sentinel-Zone", a->zone, sizeof a->zone);
    header_value(headers, "X-Sentinel-Resource", a->resource, sizeof a->resource);
    header_value(headers, "X-Sentinel-Invocation", a->invocation, sizeof a->invocation);
    a->duration_ms = header_value(headers, "X-Sentinel-Duration-Ms", durbuf, sizeof durbuf) ? atoi(durbuf)
                                                                                          : default_duration_ms;
}

/* Issuance failures collapse into one public answer; the class goes to the
 * device log only (SPEC-v2 §7.3). */
static void handle_challenge(sentinel_ctx *ctx, int fd, const char *headers, int default_duration_ms)
{
    actx_action a;
    read_action(headers, &a, default_duration_ms);
    sentinel_challenge ch;
    char reason[SENTINEL_TEXT_MAX];
    if (sentinel_issue_challenge(ctx, &a, &ch, reason) != 0) {
        printf("challenge refused reason=%s\n", reason);
        fflush(stdout);
        send_response(fd, 503, "Service Unavailable", "{\"error\":\"challenge_unavailable\"}");
        return;
    }
    char body[512];
    snprintf(body, sizeof body,
             "{\"challenge_b64\":\"%s\",\"session_context_b64\":\"%s\",\"verifier_id\":\"%s\",\"issued_at\":%lld,"
             "\"expires_at\":%lld,\"quarantine_remaining\":%lld}",
             ch.challenge_b64, ch.session_context_b64, ch.verifier_id, (long long)ch.issued_at,
             (long long)ch.expires_at, (long long)sentinel_quarantine_remaining(ctx));
    send_response(fd, 200, "OK", body);
}

static void handle_action(sentinel_ctx *ctx, int fd, const char *headers, const char *body, size_t body_len,
                          int default_duration_ms)
{
    actx_action a;
    read_action(headers, &a, default_duration_ms);
    sentinel_decision d;
    sentinel_decide(ctx, body, body_len, &a, &d);

    /* The release gate, immediately before the write. A released allow for
     * any scope other than physical:actuate authorizes no actuation. */
    int fired = 0;
    uint64_t token = 0;
    if (d.actionable && sentinel_release_gate(ctx, &d, &token)) fired = actuator_fire(token, a.duration_ms, d.claim_id) == 0;
    token = 0;

    /* A preflight rejection is one public answer; its class is logged. */
    int preflight = strcmp(d.stage, "preflight") == 0;
    char out[1400];
    snprintf(out, sizeof out,
             "{\"serial\":%lld,\"allow\":%s,\"stage\":\"%s\",\"status\":\"%s\",\"release\":\"%s\","
             "\"decision\":\"%s\",\"reason\":\"%s\",\"identity_status\":\"%s\",\"local_policy\":\"%s\","
             "\"decided_at\":%lld,\"clock_trusted\":%s,\"test_quarantine_override\":%s,\"actuated\":%s,"
             "\"actuator_invocations\":%lu}",
             (long long)d.serial, fired ? "true" : "false", d.stage, preflight ? "rejected" : d.status, d.release,
             d.decision, d.reason, d.identity_status, d.local_policy, (long long)d.decided_at,
             d.clock_trusted ? "true" : "false", d.quarantine_override ? "true" : "false", fired ? "true" : "false",
             actuator_invocations());
    printf("decision serial=%lld stage=%s status=%s release=%s decision=%s reason=%s identity=%s local=%s "
           "scope=%s zone=%s resource=%s ms=%d actuated=%d invocations=%lu\n",
           (long long)d.serial, d.stage, d.status, d.release[0] ? d.release : "-", d.decision[0] ? d.decision : "-",
           d.reason[0] ? d.reason : "-", d.identity_status[0] ? d.identity_status : "-",
           d.local_policy[0] ? d.local_policy : "-", a.scope, a.zone, a.resource, a.duration_ms, fired,
           actuator_invocations());
    fflush(stdout);
    sentinel_decision_free(&d);
    send_response(fd, fired ? 200 : 403, fired ? "OK" : "Forbidden", out);
}

/* Signed status objects are verified against the pinned status key before
 * they touch the journal, so this endpoint needs no other authentication. */
static void handle_status(sentinel_ctx *ctx, int fd, const char *headers, const char *body, size_t body_len)
{
    char kind[16] = "";
    header_value(headers, "X-Sentinel-Status-Kind", kind, sizeof kind);
    int k = !strcmp(kind, "list") ? RatifyV2KindRevocationList : !strcmp(kind, "push") ? RatifyV2KindRevocationPush : 0;
    char reason[SENTINEL_TEXT_MAX] = "bad_kind";
    int ok = k && sentinel_stage_status(ctx, k, (const uint8_t *)body, body_len, reason) == 0;
    printf("status staged=%d kind=%s reason=%s\n", ok, kind, reason[0] ? reason : "-");
    fflush(stdout);
    char out[256];
    snprintf(out, sizeof out, "{\"staged\":%s,\"reason\":\"%s\"}", ok ? "true" : "false", reason);
    send_response(fd, ok ? 200 : 422, ok ? "OK" : "Unprocessable Entity", out);
}

static void handle_health(sentinel_ctx *ctx, int fd)
{
    char out[256];
    snprintf(out, sizeof out, "{\"health\":\"%s\",\"quarantine_remaining\":%lld,\"actuator_invocations\":%lu}",
             sentinel_health(ctx), (long long)sentinel_quarantine_remaining(ctx), actuator_invocations());
    send_response(fd, 200, "OK", out);
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int http_serve(sentinel_ctx *ctx, const char *bind_addr, int port)
{
    /* sigaction without SA_RESTART, deliberately. signal() on glibc installs
     * BSD semantics, which restart accept() automatically: the handler runs,
     * sets the flag, and the loop condition is never re-evaluated, so the
     * daemon ignores SIGTERM entirely and survives its own shutdown. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return -1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        fprintf(stderr, "http: bad bind address %s\n", bind_addr);
        close(srv);
        return -1;
    }
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind"); close(srv); return -1;
    }
    if (listen(srv, 4) != 0) { perror("listen"); close(srv); return -1; }

    printf("edge: listening on %s:%d, quarantine %lld s remaining\n",
           bind_addr, port, (long long)sentinel_quarantine_remaining(ctx));
    fflush(stdout);

    long long last_action_ms = 0;

    while (!stop_requested) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        struct timeval tv = { SOCKET_TIMEOUT_S, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        char headers[HEADER_MAX];
        size_t body_start = 0;
        ssize_t got = read_headers(fd, headers, sizeof(headers), &body_start);
        if (got < 0) {
            send_response(fd, 431, "Request Header Fields Too Large",
                          "{\"error\":\"headers_too_large\"}");
            close(fd);
            continue;
        }

        if (strncmp(headers, "GET /challenge", 14) == 0) {
            handle_challenge(ctx, fd, headers, DEFAULT_DURATION_MS);
            close(fd);
            continue;
        }
        if (strncmp(headers, "GET /health", 11) == 0) {
            handle_health(ctx, fd);
            close(fd);
            continue;
        }

        int is_status = strncmp(headers, "POST /status", 12) == 0;
        if (!is_status && strncmp(headers, "POST /action", 12) != 0) {
            send_response(fd, 404, "Not Found", "{\"error\":\"not_found\"}");
            close(fd);
            continue;
        }

        /* Rate limit before doing signature work. A challenge this receiver
         * did not issue is rejected at preflight before any claim, so this
         * bounds the cost of a caller who does hold live challenges. It is
         * per-process, not per-peer: a deployment facing a hostile network
         * needs a real limiter in front. */
        long long t = now_ms();
        if (t - last_action_ms < MIN_ACTION_INTERVAL_MS) {
            send_response(fd, 429, "Too Many Requests",
                          "{\"error\":\"rate_limited\"}");
            close(fd);
            continue;
        }
        last_action_ms = t;

        char lenbuf[32];
        if (!header_value(headers, "Content-Length", lenbuf, sizeof(lenbuf))) {
            send_response(fd, 411, "Length Required",
                          "{\"error\":\"content_length_required\"}");
            close(fd);
            continue;
        }
        char *endp = NULL;
        long long clen = strtoll(lenbuf, &endp, 10);

        /* Refuse by declared size, before allocating anything. */
        if (clen < 0 || clen > SENTINEL_MAX_BUNDLE_BYTES) {
            send_response(fd, 413, "Payload Too Large",
                          "{\"error\":\"request_too_large\"}");
            close(fd);
            continue;
        }

        size_t have = (size_t)got - body_start;
        char *body = malloc((size_t)clen + 1);
        if (!body) { close(fd); continue; }
        if (have > (size_t)clen) have = (size_t)clen;
        memcpy(body, headers + body_start, have);

        int short_read = 0;
        while (have < (size_t)clen) {
            ssize_t n = read(fd, body + have, (size_t)clen - have);
            if (n <= 0) { short_read = 1; break; }
            have += (size_t)n;
        }
        body[have] = '\0';

        if (short_read) {
            send_response(fd, 400, "Bad Request",
                          "{\"error\":\"incomplete_body\"}");
        } else if (is_status) {
            handle_status(ctx, fd, headers, body, have);
        } else {
            handle_action(ctx, fd, headers, body, have, DEFAULT_DURATION_MS);
        }
        free(body);
        close(fd);
    }

    printf("edge: shutting down\n");
    close(srv);
    return 0;
}
