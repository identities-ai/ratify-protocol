/*
 * Ratify Edge Sentinel — laptop/cloud controller.
 *
 * Generates the operator root and the agent identity, then acts on commands
 * from stdin so a script can provision the Pi's trust anchor between startup
 * and the first request.
 *
 * Why stdin rather than a one-shot CLI: the C SDK can mint a HumanRoot and
 * serialise it, but has no import function, so an identity cannot survive a
 * process exit. Provisioning and acting must therefore happen in one process.
 * See CHECKPOINT-B.md finding B1.
 *
 * Commands (one per line):
 *   provision DIR      write the device trust material (anchor, operator public
 *                      key, empty signed revocation list, local policy)
 *   actuate            present physical:actuate
 *   monitor            present infrastructure:monitor
 *   capture FILE       build an actuate bundle, save it, do not send
 *   replay FILE        POST a previously saved bundle
 *   quit
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "ratify.h"

#define ACTUATE_SCOPE "physical:actuate"
#define MONITOR_SCOPE "infrastructure:monitor"
#define CHALLENGE_BYTES 32

static char host[128] = "127.0.0.1";
static char zone[64] = "north-paddock";
static int  port = 8088;
static int  duration_ms = 500;

static int connect_edge(void)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* Send a request and return the response body (caller frees), or NULL. */
static char *http_do(const char *req, size_t req_len)
{
    int fd = connect_edge();
    if (fd < 0) { fprintf(stderr, "controller: cannot reach edge\n"); return NULL; }
    if (write(fd, req, req_len) < 0) { close(fd); return NULL; }

    size_t cap = 8192, used = 0;
    char *buf = malloc(cap);
    for (;;) {
        if (used + 1024 > cap) { cap *= 2; buf = realloc(buf, cap); }
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
    }
    buf[used] = '\0';
    close(fd);

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) { free(buf); return NULL; }
    char *out = strdup(body + 4);
    free(buf);
    return out;
}

static int fetch_challenge(unsigned char *out32)
{
    char req[256];
    int n = snprintf(req, sizeof(req),
                     "GET /challenge HTTP/1.1\r\nHost: %s\r\n"
                     "Connection: close\r\n\r\n", host);
    char *body = http_do(req, (size_t)n);
    if (!body) return -1;

    char *p = strstr(body, "\"challenge\":\"");
    if (!p) { fprintf(stderr, "controller: %s\n", body); free(body); return -1; }
    p += strlen("\"challenge\":\"");
    for (int i = 0; i < CHALLENGE_BYTES; i++) {
        unsigned v;
        if (sscanf(p + i * 2, "%2x", &v) != 1) { free(body); return -1; }
        out32[i] = (unsigned char)v;
    }
    free(body);
    return 0;
}

static char *build_bundle(RatifyHumanRoot *root, RatifyAgent *agent,
                          const char *scope, const unsigned char *challenge)
{
    char scopes[160];
    snprintf(scopes, sizeof(scopes), "[\"%s\"]", scope);

    int64_t now = (int64_t)time(NULL);
    char *err = NULL;
    RatifyDelegationCert *cert = NULL;
    if (ratify_delegation_issue(root, agent, scopes, now, now + 3600,
                                &cert, &err) != RatifyOk) {
        fprintf(stderr, "controller: delegation failed: %s\n", err ? err : "?");
        ratify_error_free(err);
        return NULL;
    }
    char *cert_json = ratify_delegation_cert_to_json(cert, &err);
    ratify_delegation_cert_free(cert);
    if (!cert_json) return NULL;

    RatifyProofBundle *bundle = NULL;
    RatifyStatus st = ratify_proof_bundle_create(agent, cert_json, challenge,
                                                 CHALLENGE_BYTES, now,
                                                 &bundle, &err);
    ratify_string_free(cert_json);
    if (st != RatifyOk) {
        fprintf(stderr, "controller: bundle failed: %s\n", err ? err : "?");
        ratify_error_free(err);
        return NULL;
    }
    char *json = ratify_proof_bundle_to_json(bundle, &err);
    ratify_proof_bundle_free(bundle);
    return json;
}

static void post_action(const char *bundle_json, const char *scope)
{
    size_t blen = strlen(bundle_json);
    size_t cap = blen + 512;
    char *req = malloc(cap);
    int n = snprintf(req, cap,
                     "POST /action HTTP/1.1\r\nHost: %s\r\n"
                     "X-Sentinel-Scope: %s\r\n"
                     "X-Sentinel-Zone: %s\r\n"
                     "X-Sentinel-Duration-Ms: %d\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     host, scope, zone, duration_ms, blen);
    memcpy(req + n, bundle_json, blen);

    char *resp = http_do(req, (size_t)n + blen);
    free(req);
    printf("%s\n", resp ? resp : "{\"error\":\"no response\"}");
    fflush(stdout);
    free(resp);
}

static void write_file(const char *dir, const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "controller: cannot write %s\n", path); return; }
    fputs(body, f);
    fclose(f);
}

/* Provision a device the way an operator would. The controller can do this
 * because it holds the operator root key; in a real deployment this material
 * is carried to the device out of band, not over the network. */
static void provision(RatifyHumanRoot *root, const char *root_id,
                      const char *zone_name, const char *dir)
{
    char *err = NULL;
    char line[128];
    snprintf(line, sizeof(line), "%s\n", root_id);
    write_file(dir, "pinned_human_id", line);

    char *pub = ratify_human_root_pub_key_json(root, &err);
    if (!pub) { fprintf(stderr, "controller: no public key\n"); return; }
    write_file(dir, "operator_pub_key.json", pub);
    ratify_string_free(pub);

    char policy[256];
    snprintf(policy, sizeof(policy),
             "zone = %s\nmax_activation_ms = 1000\nrevocation_max_age_s = 86400\n",
             zone_name);
    write_file(dir, "policy.conf", policy);

    RatifyRevocationList *list = NULL;
    if (ratify_revocation_list_issue(root, "[]", (int64_t)time(NULL),
                                     &list, &err) != RatifyOk) {
        fprintf(stderr, "controller: revocation issue failed: %s\n",
                err ? err : "?");
        ratify_error_free(err);
        return;
    }
    char *json = ratify_revocation_list_to_json(list, &err);
    write_file(dir, "revocation.json", json);
    ratify_string_free(json);
    ratify_revocation_list_free(list);
    printf("PROVISIONED %s\n", dir);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--host") && i + 1 < argc)
            snprintf(host, sizeof(host), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--zone") && i + 1 < argc)
            snprintf(zone, sizeof(zone), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--ms") && i + 1 < argc)
            duration_ms = atoi(argv[++i]);
    }

    RatifyHumanRoot *root = NULL;
    RatifyAgent *agent = NULL;
    if (ratify_human_root_generate(&root) != RatifyOk ||
        ratify_agent_generate("EdgeSentinelController", "controller",
                              &agent) != RatifyOk) {
        fprintf(stderr, "controller: identity generation failed\n");
        return 1;
    }

    /* The provisioning handshake: print the anchor, then wait. A script copies
     * this to the device's trust directory before sending any command. */
    char *root_id = ratify_human_root_id(root);
    printf("ANCHOR %s\n", root_id);
    fflush(stdout);

    char line[512];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!*line) continue;

        if (!strcmp(line, "quit")) break;

        if (!strncmp(line, "provision ", 10)) {
            provision(root, root_id, zone, line + 10);
            continue;
        }

        if (!strcmp(line, "actuate") || !strcmp(line, "monitor")) {
            const char *scope = !strcmp(line, "actuate")
                ? ACTUATE_SCOPE : MONITOR_SCOPE;
            unsigned char challenge[CHALLENGE_BYTES];
            if (fetch_challenge(challenge) != 0) continue;
            char *b = build_bundle(root, agent, scope, challenge);
            if (b) { post_action(b, scope); ratify_string_free(b); }
            continue;
        }

        if (!strncmp(line, "capture ", 8)) {
            unsigned char challenge[CHALLENGE_BYTES];
            if (fetch_challenge(challenge) != 0) continue;
            char *b = build_bundle(root, agent, ACTUATE_SCOPE, challenge);
            if (b) {
                FILE *f = fopen(line + 8, "w");
                if (f) { fputs(b, f); fclose(f); printf("CAPTURED %s\n", line + 8); }
                ratify_string_free(b);
                fflush(stdout);
            }
            continue;
        }

        if (!strncmp(line, "replay ", 7)) {
            FILE *f = fopen(line + 7, "r");
            if (!f) { printf("{\"error\":\"no such capture\"}\n"); continue; }
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            char *b = malloc((size_t)sz + 1);
            size_t rd = fread(b, 1, (size_t)sz, f);
            b[rd] = '\0';
            fclose(f);
            post_action(b, ACTUATE_SCOPE);
            free(b);
            continue;
        }

        printf("{\"error\":\"unknown command\"}\n");
        fflush(stdout);
    }

    ratify_string_free(root_id);
    ratify_agent_free(agent);
    ratify_human_root_free(root);
    return 0;
}
