/*
 * Ratify Edge Sentinel controller: the principal, its status publisher, and
 * the agent, for demonstrations and the scenario matrix.
 *
 * It holds four key pairs as seed files in its own directory: the root that
 * issues delegations, the root's separate status key, the agent that presents
 * proofs, and an unrelated "rogue" root used to show that an untrusted chain
 * is refused. These are demonstration keys in plain files; a deployment keeps
 * the root and status keys in an HSM or KMS (RatifyV2ExternalSigner).
 *
 *   controller init CDIR
 *   controller provision CDIR TRUST --checkpoint-pub FILE [--status-key-from-root]
 *   controller delegate CDIR OUT --scope S [--scope S] --zone Z --resource R --max-ms N
 *              [--lifetime N | --valid-until T] [--valid-from T] [--cert-id ID] [--issuer rogue]
 *   controller act CDIR --cert FILE [--scope S] [--zone Z] [--resource R] [--ms N] [--invocation I]
 *              [--present-zone Z] [--present-ms N] [--tamper] [--capture FILE] [--host H] [--port P]
 *   controller replay CDIR --capture FILE [--host H] [--port P]
 *   controller revoke CDIR --cert-id ID [--host H] [--port P]
 *   controller heartbeat CDIR [--host H] [--port P]
 *   controller health CDIR [--host H] [--port P]
 *
 * act, replay, revoke, and heartbeat print the receiver's JSON answer.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "actx.h"
#include "ratify.h"
#include "util.h"

#define STATUS_LIFETIME_S 3600

static char host[128] = "127.0.0.1";
static int port = 8088;
static const char *cdir = NULL;

static void die(const char *what)
{
    fprintf(stderr, "controller: %s\n", what);
    exit(1);
}

#define CHECK(call)                                                                                  \
    do {                                                                                             \
        int32_t rc_ = (call);                                                                        \
        if (rc_ != 0) {                                                                              \
            fprintf(stderr, "controller: %s: %s (%s)\n", #call, ratify_v2_error_class_str(rc_),      \
                    ratify_v2_last_error_message());                                                 \
            exit(1);                                                                                 \
        }                                                                                            \
    } while (0)

/* The controller's own clock. In the scenario matrix it reads the same
 * fixture file as the test receiver so certificate times line up. */
static int64_t ctl_now(void)
{
    const char *path = getenv("SENTINEL_TEST_CLOCK_FILE");
    if (path && *path) {
        FILE *f = fopen(path, "r");
        long long t = 0;
        if (f && fscanf(f, "%lld", &t) == 1) {
            fclose(f);
            return t;
        }
        if (f) fclose(f);
    }
    return (int64_t)time(NULL);
}

static char *cpath(const char *name)
{
    return xformat("%s/%s", cdir, name);
}

typedef struct {
    RatifyV2KeyPair *kp;
    RatifyV2PublicKey pub;
    char id[RATIFY_V2_KEY_ID_BUF_LEN];
    char *json;
} key;

static void key_load(const char *name, key *k)
{
    char *p = cpath(name);
    k->kp = keypair_load(p);
    free(p);
    if (!k->kp) die("missing key; run init first");
    CHECK(ratify_v2_keypair_public_key(k->kp, &k->pub));
    CHECK(ratify_v2_keypair_key_id(k->kp, k->id, sizeof k->id));
    k->json = public_key_json(&k->pub);
}

static void key_free(key *k)
{
    ratify_v2_keypair_free(k->kp);
    free(k->json);
}

static void write_text(const char *path, const char *text, int mode)
{
    if (write_file_durable(path, text, strlen(text), mode) != 0) {
        fprintf(stderr, "controller: cannot write %s\n", path);
        exit(1);
    }
}

/* ---- HTTP ------------------------------------------------------------------- */

static char *http_do(const char *req, size_t req_len)
{
    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return NULL;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return NULL;
    if (write(fd, req, req_len) < 0) {
        close(fd);
        return NULL;
    }
    size_t cap = 8192, used = 0;
    char *buf = malloc(cap);
    for (;;) {
        if (used + 1024 > cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
    }
    buf[used] = '\0';
    close(fd);
    char *body = strstr(buf, "\r\n\r\n");
    char *out = body ? xformat("%s", body + 4) : NULL;
    free(buf);
    return out;
}

static char *action_headers(const actx_action *a)
{
    return xformat("X-Sentinel-Scope: %s\r\nX-Sentinel-Zone: %s\r\nX-Sentinel-Resource: %s\r\n"
                   "X-Sentinel-Duration-Ms: %d\r\nX-Sentinel-Invocation: %s\r\n",
                   a->scope, a->zone, a->resource, a->duration_ms, a->invocation);
}

static char *post(const char *path, const char *extra_headers, const char *body, size_t blen)
{
    char *head = xformat("POST %s HTTP/1.1\r\nHost: %s\r\n%sContent-Type: application/json\r\n"
                         "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                         path, host, extra_headers, blen);
    size_t hlen = strlen(head);
    char *req = malloc(hlen + blen);
    memcpy(req, head, hlen);
    memcpy(req + hlen, body, blen);
    free(head);
    char *resp = http_do(req, hlen + blen);
    free(req);
    return resp;
}

static void print_answer(char *resp)
{
    printf("%s\n", resp ? resp : "{\"error\":\"no response\"}");
    fflush(stdout);
    free(resp);
}

/* ---- Status publisher ------------------------------------------------------- */

/* The publisher's role configuration lives in a small journal of its own. */
typedef struct {
    uint8_t *snap;
    size_t len;
    uint64_t gen;
    char digest[112];
} mem_journal;

static int32_t mj_load(void *user, RatifyV2JournalSnapshot *out)
{
    mem_journal *j = user;
    out->snapshot.ptr = j->snap;
    out->snapshot.len = j->len;
    out->generation = j->gen;
    out->digest = j->digest;
    return 0;
}

static int32_t mj_cas(void *user, uint64_t gen, const char *digest, const RatifyV2JournalSnapshot *next)
{
    mem_journal *j = user;
    if (gen != j->gen || strcmp(digest, j->digest) != 0) return RatifyV2StoreJournalConflict;
    free(j->snap);
    j->snap = malloc(next->snapshot.len);
    memcpy(j->snap, next->snapshot.ptr, next->snapshot.len);
    j->len = next->snapshot.len;
    j->gen = next->generation;
    snprintf(j->digest, sizeof j->digest, "%s", next->digest);
    return 0;
}

static int32_t publisher_journal(mem_journal *j, RatifyV2JournalStoreCallbacks *cb, const key *root,
                                 const RatifyV2PublicKey *status_pub)
{
    RatifyV2Buffer snap = {0};
    char *digest = NULL;
    CHECK(ratify_v2_journal_genesis(&snap, &j->gen, &digest));
    j->snap = malloc(snap.len);
    memcpy(j->snap, snap.ptr, snap.len);
    j->len = snap.len;
    snprintf(j->digest, sizeof j->digest, "%s", digest);
    ratify_v2_string_free(digest);
    ratify_v2_buffer_free(snap);
    *cb = (RatifyV2JournalStoreCallbacks){j, mj_load, mj_cas};
    int32_t rc = ratify_v2_journal_record_key_role(cb, "issuer", &root->pub);
    if (rc == 0) rc = ratify_v2_journal_configure_status_key(cb, root->id, 1, status_pub);
    return rc;
}

/* One publisher transition; writes the next state before returning the
 * signed objects (persist before publish). */
static void publish(int32_t op, const char *revoke_json, RatifyV2Buffer *list, RatifyV2Buffer *push)
{
    key root, status;
    key_load("root.key", &root);
    key_load("status.key", &status);
    mem_journal j = {0};
    RatifyV2JournalStoreCallbacks cb;
    CHECK(publisher_journal(&j, &cb, &root, &status.pub));
    char *state_path = cpath("publisher.state");
    size_t slen = 0;
    char *state = op == RatifyV2PublishGenesis ? NULL : read_file(state_path, 1 << 20, &slen);
    if (op != RatifyV2PublishGenesis && !state) die("no publisher state; provision first");
    RatifyV2Buffer next = {0};
    CHECK(ratify_v2_status_publish(op, &cb, &root.pub, status.kp, NULL, STATUS_LIFETIME_S, (const uint8_t *)state, slen,
                                   (const uint8_t *)revoke_json, revoke_json ? strlen(revoke_json) : 0, ctl_now(), list,
                                   push, &next));
    char *ns = take_buffer(next, NULL);
    write_text(state_path, ns, 0600);
    free(ns);
    free(state);
    free(state_path);
    free(j.snap);
    key_free(&root);
    key_free(&status);
}

static void stage(const char *kind, RatifyV2Buffer obj)
{
    if (!obj.len) return;
    char *hdr = xformat("X-Sentinel-Status-Kind: %s\r\n", kind);
    char *resp = post("/status", hdr, (const char *)obj.ptr, obj.len);
    free(hdr);
    print_answer(resp);
    usleep(150000); /* the receiver rate-limits POSTs */
}

/* ---- Commands --------------------------------------------------------------- */

static int cmd_init(void)
{
    mkdir(cdir, 0700);
    const char *names[4] = {"root.key", "status.key", "agent.key", "rogue.key"};
    for (int i = 0; i < 4; i++) {
        char *p = cpath(names[i]);
        if (access(p, F_OK) != 0) {
            RatifyV2KeyPair *kp = keypair_create(p);
            if (!kp) die("key generation failed");
            ratify_v2_keypair_free(kp);
        }
        free(p);
    }
    char *ws = cpath("workspace_id");
    if (access(ws, F_OK) != 0) {
        uint8_t u[16];
        random_bytes(u, sizeof u);
        u[6] = (uint8_t)((u[6] & 0x0f) | 0x40);
        u[8] = (uint8_t)((u[8] & 0x3f) | 0x80);
        char h[33];
        hex_encode(u, 16, h);
        char *text = xformat("%.8s-%.4s-%.4s-%.4s-%.12s\n", h, h + 8, h + 12, h + 16, h + 20);
        write_text(ws, text, 0600);
        free(text);
    }
    free(ws);
    key root, status, agent;
    key_load("root.key", &root);
    key_load("status.key", &status);
    key_load("agent.key", &agent);
    printf("ROOT %s\nSTATUS %s\nAGENT %s\n", root.id, status.id, agent.id);
    key_free(&root);
    key_free(&status);
    key_free(&agent);
    return 0;
}

static char *workspace(void)
{
    char *p = cpath("workspace_id");
    char *w = read_file(p, 64, NULL);
    free(p);
    if (!w) die("no workspace_id; run init first");
    w[strcspn(w, "\r\n")] = '\0';
    return w;
}

static int cmd_provision(const char *trust, const char *checkpoint_pub, int status_from_root)
{
    mkdir(trust, 0700);
    key root, status, agent;
    key_load("root.key", &root);
    key_load("status.key", &status);
    key_load("agent.key", &agent);
    char *p;
    p = xformat("%s/root_pub.json", trust);
    write_text(p, root.json, 0644);
    free(p);
    p = xformat("%s/agent_pub.json", trust);
    write_text(p, agent.json, 0644);
    free(p);
    p = xformat("%s/status_pub.json", trust);
    write_text(p, status_from_root ? root.json : status.json, 0644);
    free(p);
    char *ck = read_file(checkpoint_pub, 1 << 16, NULL);
    if (!ck) die("cannot read the checkpoint public key");
    p = xformat("%s/checkpoint_pub.json", trust);
    write_text(p, ck, 0644);
    free(p);
    free(ck);
    char *ws = workspace();
    char *policy = xformat("zone = greenhouse-b\nmax_activation_ms = 1000\nworkspace_id = %s\n"
                           "status_max_age_s = %d\nchallenge_lifetime_s = 120\nmax_challenge_age_s = 240\n",
                           ws, STATUS_LIFETIME_S);
    p = xformat("%s/policy.conf", trust);
    write_text(p, policy, 0644);
    free(p);
    free(policy);
    free(ws);

    if (status_from_root) {
        /* The v1 arrangement: the root key signs its own status. v2 refuses
         * it in the publisher and in the receiver's trust configuration. */
        mem_journal j = {0};
        RatifyV2JournalStoreCallbacks cb;
        RatifyV2Buffer l = {0}, ps = {0}, st = {0};
        const char *step = "configure the root key as its own status key";
        int32_t rc = publisher_journal(&j, &cb, &root, &root.pub);
        if (rc == 0) {
            step = "sign status with the root key";
            rc = ratify_v2_status_publish(RatifyV2PublishGenesis, &cb, &root.pub, root.kp, NULL, STATUS_LIFETIME_S,
                                          NULL, 0, NULL, 0, ctl_now(), &l, &ps, &st);
        }
        if (rc == 0)
            printf("PUBLISHER_WITH_ROOT_AS_STATUS_KEY accepted\n");
        else
            printf("PUBLISHER_WITH_ROOT_AS_STATUS_KEY refused at \"%s\": %s\n", step, ratify_v2_error_class_str(rc));
        ratify_v2_buffer_free(l);
        ratify_v2_buffer_free(ps);
        ratify_v2_buffer_free(st);
        free(j.snap);
    } else {
        RatifyV2Buffer list = {0}, push = {0};
        publish(RatifyV2PublishGenesis, NULL, &list, &push);
        p = xformat("%s/status-list.json", trust);
        if (write_file_durable(p, list.ptr, list.len, 0644) != 0) die("cannot write status list");
        free(p);
        ratify_v2_buffer_free(list);
        ratify_v2_buffer_free(push);
    }
    printf("PROVISIONED %s\n", trust);
    key_free(&root);
    key_free(&status);
    key_free(&agent);
    return 0;
}

static int cmd_delegate(const char *out, char scopes[][ACTX_FIELD_MAX], int nscopes, const char *zone,
                        const char *resource, int max_ms, int64_t valid_from, int64_t valid_until,
                        const char *cert_id, const char *issuer)
{
    key root, agent;
    key_load(issuer && !strcmp(issuer, "rogue") ? "rogue.key" : "root.key", &root);
    key_load("agent.key", &agent);
    char scope_json[512] = "";
    for (int i = 0; i < nscopes; i++) {
        size_t n = strlen(scope_json);
        snprintf(scope_json + n, sizeof scope_json - n, "%s\"%s\"", i ? "," : "", scopes[i]);
    }
    char *cert_in = xformat(
        "{\"cert_id\":\"%s\",\"constraints\":[{\"path_prefix\":\"/%s\",\"resource_id\":\"%s\",\"type\":\"resource_path\"},"
        "{\"params\":{\"counter\":\"%s\",\"max\":%d},\"type\":\"%s\"}],\"expires_at\":%lld,\"issued_at\":%lld,"
        "\"issuer_id\":\"%s\",\"issuer_pub_key\":%s,\"scope\":[%s],\"subject_id\":\"%s\",\"subject_pub_key\":%s,"
        "\"version\":2}",
        cert_id, resource, zone, ACTX_DURATION_COUNTER, max_ms, ACTX_MAX_COUNT_TYPE, (long long)valid_until,
        (long long)valid_from, root.id, root.json, scope_json, agent.id, agent.json);
    RatifyV2Buffer cert = {0};
    CHECK(ratify_v2_sign_delegation_certificate((const uint8_t *)cert_in, strlen(cert_in), root.kp, NULL, &cert));
    free(cert_in);
    if (write_file_durable(out, cert.ptr, cert.len, 0600) != 0) die("cannot write certificate");
    printf("DELEGATED %s scope=[%s] zone=%s resource=%s max_ms=%d valid=[%lld,%lld)\n", cert_id, scope_json, zone,
           resource, max_ms, (long long)valid_from, (long long)valid_until);
    ratify_v2_buffer_free(cert);
    key_free(&root);
    key_free(&agent);
    return 0;
}

static int cmd_act(const char *cert_path, const actx_action *a, const actx_action *presented, int tamper,
                   const char *capture)
{
    key agent;
    key_load("agent.key", &agent);
    char *cert = read_file(cert_path, 1 << 20, NULL);
    if (!cert) die("cannot read certificate");
    char *hdr = action_headers(a);
    char *req = xformat("GET /challenge HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n", host, hdr);
    free(hdr);
    char *resp = http_do(req, strlen(req));
    free(req);
    char challenge[64] = "", verifier_id[80] = "", device_sc[64] = "";
    int64_t issued_at = 0;
    if (!resp || !json_get_str(resp, "challenge_b64", challenge, sizeof challenge) ||
        !json_get_str(resp, "verifier_id", verifier_id, sizeof verifier_id) ||
        !json_get_str(resp, "session_context_b64", device_sc, sizeof device_sc) ||
        !json_get_int(resp, "issued_at", &issued_at)) {
        print_answer(resp ? resp : xformat("{\"error\":\"challenge_unavailable\"}"));
        free(cert);
        key_free(&agent);
        return 1;
    }
    free(resp);

    /* The agent derives the session context from its own intended action
     * and refuses a challenge bound to anything else. */
    char *ws = workspace();
    uint8_t sc[32];
    if (actx_session_context(a, verifier_id, ws, agent.id, sc) != 0) die("invalid action");
    free(ws);
    char *sc_b64 = b64_encode(sc, 32);
    if (strcmp(sc_b64, device_sc) != 0) die("the receiver bound the challenge to a different action");

    char *bundle_in = xformat("{\"agent_id\":\"%s\",\"agent_pub_key\":%s,\"challenge\":\"%s\",\"challenge_at\":%lld,"
                              "\"delegations\":[%s],\"session_context\":\"%s\",\"stream_id\":null,\"stream_seq\":null,"
                              "\"verifier_id\":\"%s\",\"version\":2}",
                              agent.id, agent.json, challenge, (long long)issued_at, cert, sc_b64, verifier_id);
    free(sc_b64);
    free(cert);
    RatifyV2Buffer bundle_buf = {0};
    CHECK(ratify_v2_sign_proof_bundle((const uint8_t *)bundle_in, strlen(bundle_in), agent.kp, NULL, &bundle_buf));
    free(bundle_in);
    size_t blen = 0;
    char *bundle = take_buffer(bundle_buf, &blen);
    if (tamper) {
        /* Change one byte of the agent's Ed25519 challenge signature. The
         * bundle still decodes; its signature no longer verifies. */
        char *sig = strstr(bundle, "\"challenge_sig\":{\"ed25519\":\"");
        if (!sig) die("cannot locate the challenge signature");
        char *c = sig + strlen("\"challenge_sig\":{\"ed25519\":\"");
        *c = *c == 'A' ? 'B' : 'A';
    }
    if (capture) {
        char *text = xformat("%s %s %s %d %s\n%s", presented->scope, presented->zone, presented->resource,
                             presented->duration_ms, presented->invocation, bundle);
        write_text(capture, text, 0600);
        free(text);
        printf("{\"captured\":\"%s\"}\n", capture);
    } else {
        char *ph = action_headers(presented);
        print_answer(post("/action", ph, bundle, blen));
        free(ph);
    }
    free(bundle);
    key_free(&agent);
    return 0;
}

static int cmd_replay(const char *capture)
{
    char *text = read_file(capture, 1 << 20, NULL);
    if (!text) die("no such capture");
    char *nl = strchr(text, '\n');
    if (!nl) die("bad capture");
    *nl = '\0';
    actx_action a;
    memset(&a, 0, sizeof a);
    if (sscanf(text, "%63s %63s %63s %d %63s", a.scope, a.zone, a.resource, &a.duration_ms, a.invocation) != 5)
        die("bad capture");
    char *hdr = action_headers(&a);
    print_answer(post("/action", hdr, nl + 1, strlen(nl + 1)));
    free(hdr);
    free(text);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: see the comment at the top of controller.c\n");
        return 2;
    }
    if (ratify_v2_abi_version() != RATIFY_V2_ABI_VERSION) die("Ratify v2 ABI mismatch");
    const char *cmd = argv[1];
    cdir = argv[2];
    actx_action a, presented;
    memset(&a, 0, sizeof a);
    snprintf(a.scope, sizeof a.scope, "physical:actuate");
    snprintf(a.zone, sizeof a.zone, "greenhouse-b");
    snprintf(a.resource, sizeof a.resource, "irrigation-valve-3");
    snprintf(a.invocation, sizeof a.invocation, "manual");
    a.duration_ms = 500;
    char scopes[8][ACTX_FIELD_MAX];
    int nscopes = 0, tamper = 0, max_ms = 20000, status_from_root = 0;
    int64_t valid_from = -1, valid_until = -1, lifetime = 3600;
    const char *cert = NULL, *capture = NULL, *cert_id = "edge-cert-1", *issuer = NULL, *ckpt_pub = NULL;
    const char *present_zone = NULL;
    int present_ms = -1;
    const char *pos = NULL;
    for (int i = 3; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(k, "--tamper")) tamper = 1;
        else if (!strcmp(k, "--status-key-from-root")) status_from_root = 1;
        else if (!v) pos = k;
        else if (!strcmp(k, "--scope")) {
            snprintf(a.scope, sizeof a.scope, "%s", v);
            if (nscopes < 8) snprintf(scopes[nscopes++], ACTX_FIELD_MAX, "%s", v);
            i++;
        } else if (!strcmp(k, "--zone")) { snprintf(a.zone, sizeof a.zone, "%s", v); i++; }
        else if (!strcmp(k, "--resource")) { snprintf(a.resource, sizeof a.resource, "%s", v); i++; }
        else if (!strcmp(k, "--ms")) { a.duration_ms = atoi(v); i++; }
        else if (!strcmp(k, "--invocation")) { snprintf(a.invocation, sizeof a.invocation, "%s", v); i++; }
        else if (!strcmp(k, "--present-zone")) { present_zone = v; i++; }
        else if (!strcmp(k, "--present-ms")) { present_ms = atoi(v); i++; }
        else if (!strcmp(k, "--cert")) { cert = v; i++; }
        else if (!strcmp(k, "--capture")) { capture = v; i++; }
        else if (!strcmp(k, "--cert-id")) { cert_id = v; i++; }
        else if (!strcmp(k, "--issuer")) { issuer = v; i++; }
        else if (!strcmp(k, "--max-ms")) { max_ms = atoi(v); i++; }
        else if (!strcmp(k, "--lifetime")) { lifetime = atoll(v); i++; }
        else if (!strcmp(k, "--valid-from")) { valid_from = atoll(v); i++; }
        else if (!strcmp(k, "--valid-until")) { valid_until = atoll(v); i++; }
        else if (!strcmp(k, "--checkpoint-pub")) { ckpt_pub = v; i++; }
        else if (!strcmp(k, "--host")) { snprintf(host, sizeof host, "%s", v); i++; }
        else if (!strcmp(k, "--port")) { port = atoi(v); i++; }
        else if (!pos) pos = k;
        else die("unknown argument");
    }

    if (!strcmp(cmd, "init")) return cmd_init();
    if (!strcmp(cmd, "provision")) {
        if (!pos || !ckpt_pub) die("provision CDIR TRUST --checkpoint-pub FILE");
        return cmd_provision(pos, ckpt_pub, status_from_root);
    }
    if (!strcmp(cmd, "delegate")) {
        if (!pos) die("delegate CDIR OUT ...");
        if (nscopes == 0) snprintf(scopes[nscopes++], ACTX_FIELD_MAX, "physical:actuate");
        int64_t now = ctl_now();
        if (valid_from < 0) valid_from = now;
        if (valid_until < 0) valid_until = valid_from + lifetime;
        return cmd_delegate(pos, scopes, nscopes, a.zone, a.resource, max_ms, valid_from, valid_until, cert_id, issuer);
    }
    if (!strcmp(cmd, "act")) {
        if (!cert) die("act needs --cert");
        presented = a;
        if (present_zone) snprintf(presented.zone, sizeof presented.zone, "%s", present_zone);
        if (present_ms >= 0) presented.duration_ms = present_ms;
        return cmd_act(cert, &a, &presented, tamper, capture);
    }
    if (!strcmp(cmd, "replay")) {
        if (!capture) die("replay needs --capture");
        return cmd_replay(capture);
    }
    if (!strcmp(cmd, "health")) {
        char *req = xformat("GET /health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
        print_answer(http_do(req, strlen(req)));
        free(req);
        return 0;
    }
    if (!strcmp(cmd, "revoke") || !strcmp(cmd, "heartbeat")) {
        RatifyV2Buffer list = {0}, push = {0};
        char *ids = !strcmp(cmd, "revoke") ? xformat("[\"%s\"]", cert_id) : NULL;
        publish(ids ? RatifyV2PublishRevoke : RatifyV2PublishHeartbeat, ids, &list, &push);
        free(ids);
        stage("push", push);
        stage("list", list);
        ratify_v2_buffer_free(list);
        ratify_v2_buffer_free(push);
        return 0;
    }
    die("unknown command");
    return 2;
}
