/*
 * Bounded HTTP/1.1 listener.
 *
 * Deliberately minimal, and deliberately parses no JSON of its own: the action
 * scope arrives in a header and the request body is handed to the Ratify SDK
 * byte-for-byte. The edge binary therefore has no hand-written JSON parser on
 * its attack surface.
 *
 *   GET  /challenge   -> {"challenge":"<64 hex>","session_context":"<64 hex>","expires_at":N,"quarantine_remaining":N}
 *   POST /action      -> body is the proof bundle; X-Sentinel-Scope names the scope
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
#include "trust.h"
#include "actuator.h"

#define HEADER_MAX 8192
#define SOCKET_TIMEOUT_S 5
#define MIN_ACTION_INTERVAL_MS 100   /* crude rate limit; see note below */

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

static void handle_challenge(sentinel_ctx *ctx, int fd, const char *headers)
{
    char scope[128] = {0}, zone[64] = {0}, durbuf[16] = {0};
    header_value(headers, "X-Sentinel-Scope", scope, sizeof(scope));
    header_value(headers, "X-Sentinel-Zone", zone, sizeof(zone));
    header_value(headers, "X-Sentinel-Duration-Ms", durbuf, sizeof(durbuf));
    sentinel_request req = { scope, zone, durbuf[0] ? atoi(durbuf) : 0 };
    char hex[SENTINEL_CHALLENGE_HEX + 1];
    char context_hex[SENTINEL_CHALLENGE_HEX + 1];
    int64_t expires = 0;
    if (sentinel_issue_challenge(ctx, &req, hex, context_hex, &expires) != 0) {
        send_response(fd, 503, "Service Unavailable",
                      "{\"error\":\"challenge_unavailable\"}");
        return;
    }
    char body[256];
    snprintf(body, sizeof(body),
             "{\"challenge\":\"%s\",\"session_context\":\"%s\",\"expires_at\":%lld,"
             "\"quarantine_remaining\":%lld}",
             hex, context_hex, (long long)expires,
             (long long)sentinel_quarantine_remaining(ctx));
    send_response(fd, 200, "OK", body);
}

static void handle_action(sentinel_ctx *ctx, int fd, const char *headers,
                          const char *body, size_t body_len, int actuate_ms,
                          const char *actuate_scope)
{
    char scope[128] = {0};
    if (!header_value(headers, "X-Sentinel-Scope", scope, sizeof(scope))) {
        send_response(fd, 400, "Bad Request",
                      "{\"error\":\"missing X-Sentinel-Scope\"}");
        return;
    }

    char zone[TRUST_ZONE_MAX] = {0};
    char durbuf[16] = {0};
    header_value(headers, "X-Sentinel-Zone", zone, sizeof(zone));
    int requested_ms = header_value(headers, "X-Sentinel-Duration-Ms",
                                    durbuf, sizeof(durbuf))
                       ? atoi(durbuf) : actuate_ms;

    sentinel_request req;
    req.scope = scope;
    req.zone = zone;
    req.duration_ms = requested_ms;

    sentinel_decision d;
    sentinel_decide(ctx, body, body_len, &req, &d);

    /* Authorization is necessary but not sufficient to actuate. An allowed
     * infrastructure:monitor request is authorized to READ; routing every
     * allow to the actuator would light the beacon on a monitoring call. The
     * actuator is reachable only by the one scope that means "actuate". */
    int fired = 0;
    if (d.allow && strcmp(scope, actuate_scope) == 0)
        fired = (actuator_fire(&d, requested_ms) == 0);

    /* The decision record. No key material, no bundle contents. */
    char out[768];
    snprintf(out, sizeof(out),
             "{\"allow\":%s,\"status\":\"%s\",\"detail\":\"%s\","
             "\"human_id\":\"%s\",\"agent_id\":\"%s\",\"decided_at\":%lld,"
             "\"clock_trusted\":%s,\"test_quarantine_override\":%s,"
             "\"actuated\":%s,\"actuator_invocations\":%lu}",
             d.allow ? "true" : "false", d.status, d.reason,
             d.human_id, d.agent_id, (long long)d.decided_at,
             d.clock_trusted ? "true" : "false",
             d.quarantine_override ? "true" : "false",
             fired ? "true" : "false", actuator_invocations());

    printf("decision allow=%d status=%s scope=%s agent=%s actuated=%d\n",
           d.allow, d.status, scope, d.agent_id, fired);
    fflush(stdout);

    send_response(fd, d.allow ? 200 : 403,
                  d.allow ? "OK" : "Forbidden", out);
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int http_serve(sentinel_ctx *ctx, const char *bind_addr, int port,
               int actuate_ms, const char *actuate_scope)
{
    /* sigaction without SA_RESTART, deliberately. signal() on glibc installs
     * BSD semantics, which restart accept() automatically — the handler runs,
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
            handle_challenge(ctx, fd, headers);
            close(fd);
            continue;
        }

        if (strncmp(headers, "POST /action", 12) != 0) {
            send_response(fd, 404, "Not Found", "{\"error\":\"not_found\"}");
            close(fd);
            continue;
        }

        /* Rate limit before doing ~24.5 ms of work. A challenge this verifier
         * did not issue is already rejected cheaply inside the SDK (SPEC §10
         * step 2b), so this bounds the cost of a caller who does hold live
         * challenges. It is per-process, not per-peer: a deployment facing a
         * hostile network needs a real limiter in front. */
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
        } else {
            handle_action(ctx, fd, headers, body, have, actuate_ms, actuate_scope);
        }
        free(body);
        close(fd);
    }

    printf("edge: shutting down\n");
    close(srv);
    return 0;
}
