/*
 * Ratify Edge Sentinel checkpoint: the receipt-log checkpoint and state
 * anchor of the single-device offline profile (SPEC-v2 §7.8, §7.13), run as a
 * separate process with its own key and its own storage.
 *
 * What it holds: its own hybrid signing key (generated here, never sent to
 * the receiver), the receiver's anchored complete-state digest, and for every
 * acknowledged receipt-log sequence the log ID, sequence, entry hash, state
 * digest, and timestamp. Every answer is a witness entry (SPEC-v2 §5.6) in
 * the checkpoint's own witness log, signed with its key.
 *
 * What it enforces: an anchor is accepted only when its previous digest is
 * the anchored one; an acknowledgement only for the next sequence, whose
 * previous entry hash is the head and whose state digest is the anchored
 * digest; an identical retry returns the original acknowledgement; a
 * different entry hash at an acknowledged sequence freezes it. It never
 * overwrites a record and refuses once its capacity is used. It timestamps
 * from the device security clock and refuses on a regression.
 *
 * What it cannot do on a Raspberry Pi without a secure element: protect its
 * key or its storage from root on the same host. See docs/v2-design.md.
 *
 *   edge-checkpoint --init --dir DIR [--capacity N]
 *   edge-checkpoint --dir DIR --socket PATH [--allow-uid UID]
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#if defined(__linux__)
#define _GNU_SOURCE
#elif defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "clock.h"
#include "ratify.h"
#include "util.h"

#define STATE_MAGIC "ratify-edge-checkpoint 1"
#define DEFAULT_CAPACITY 10000

typedef struct {
    int64_t seq;
    uint8_t entry_hash[48];
    char state[97];
    int64_t timestamp;
    char *witness_b64;
} ack_rec;

typedef struct {
    char dir[512];
    RatifyV2KeyPair *key;
    char key_id[RATIFY_V2_KEY_ID_BUF_LEN];
    char wlog[33];
    int64_t wseq;
    uint8_t whead[48];
    char primary_log[40];
    char anchored[97];
    int frozen;
    int64_t clock_hw;
    int64_t capacity;
    ack_rec *acks;
    int64_t nacks;
} ckpt;

static volatile sig_atomic_t stop_requested = 0;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }

static void state_path(const ckpt *c, char *out, size_t cap) { snprintf(out, cap, "%s/checkpoint.state", c->dir); }

static void free_acks(ckpt *c)
{
    for (int64_t i = 0; i < c->nacks; i++) free(c->acks[i].witness_b64);
    free(c->acks);
    c->acks = NULL;
    c->nacks = 0;
}

static int save_state(const ckpt *c)
{
    char *whead = b64_encode(c->whead, 48);
    size_t cap = 4096;
    for (int64_t i = 0; i < c->nacks; i++) cap += strlen(c->acks[i].witness_b64) + 512;
    char *buf = malloc(cap);
    size_t n = (size_t)snprintf(buf, cap,
                                "%s\nwlog %s %lld %s\nprimary_log %s\nanchored %s\nfrozen %d\nclock_hw %lld\n"
                                "capacity %lld\n",
                                STATE_MAGIC, c->wlog, (long long)c->wseq, whead, c->primary_log[0] ? c->primary_log : "-",
                                c->anchored[0] ? c->anchored : "-", c->frozen, (long long)c->clock_hw,
                                (long long)c->capacity);
    free(whead);
    for (int64_t i = 0; i < c->nacks; i++) {
        char *h = b64_encode(c->acks[i].entry_hash, 48);
        n += (size_t)snprintf(buf + n, cap - n, "ack %lld %s %s %lld %s\n", (long long)c->acks[i].seq, h,
                              c->acks[i].state, (long long)c->acks[i].timestamp, c->acks[i].witness_b64);
        free(h);
    }
    char path[600];
    state_path(c, path, sizeof path);
    int rc = write_file_durable(path, buf, n, 0600);
    free(buf);
    return rc;
}

static int load_state(ckpt *c)
{
    char path[600];
    state_path(c, path, sizeof path);
    size_t len = 0;
    char *text = read_file(path, 512u << 20, &len);
    if (!text) return -1;
    free_acks(c);
    int ok = strncmp(text, STATE_MAGIC "\n", strlen(STATE_MAGIC) + 1) == 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); ok && line; line = strtok_r(NULL, "\n", &save)) {
        char a[200], b[200];
        long long x, y;
        if (strncmp(line, "ratify-edge-checkpoint", 22) == 0) continue;
        if (sscanf(line, "wlog %32s %lld %199s", c->wlog, &x, a) == 3) {
            c->wseq = x;
            ok = b64_decode(a, c->whead, 48) == 48;
        } else if (sscanf(line, "primary_log %39s", a) == 1) {
            snprintf(c->primary_log, sizeof c->primary_log, "%s", strcmp(a, "-") ? a : "");
        } else if (sscanf(line, "anchored %199s", a) == 1) {
            snprintf(c->anchored, sizeof c->anchored, "%s", strcmp(a, "-") ? a : "");
        } else if (sscanf(line, "frozen %lld", &x) == 1) {
            c->frozen = (int)x;
        } else if (sscanf(line, "clock_hw %lld", &x) == 1) {
            c->clock_hw = x;
        } else if (sscanf(line, "capacity %lld", &x) == 1) {
            c->capacity = x;
        } else if (strncmp(line, "ack ", 4) == 0) {
            char *w = malloc(strlen(line));
            if (sscanf(line, "ack %lld %199s %199s %lld %s", &x, a, b, &y, w) != 5) {
                free(w);
                ok = 0;
                break;
            }
            c->acks = realloc(c->acks, (size_t)(c->nacks + 1) * sizeof *c->acks);
            ack_rec *r = &c->acks[c->nacks++];
            r->seq = x;
            r->timestamp = y;
            snprintf(r->state, sizeof r->state, "%s", b);
            r->witness_b64 = w;
            ok = b64_decode(a, r->entry_hash, 48) == 48 && r->seq == c->nacks;
        } else {
            ok = 0;
        }
    }
    free(text);
    return ok ? 0 : -1;
}

/* Read the security clock and refuse a regression. */
static int read_clock(ckpt *c, int64_t *now, const char **why)
{
    int trusted;
    if (clock_read(now, &trusted) != 0) {
        *why = "clock_unavailable";
        return -1;
    }
    if (*now < c->clock_hw) {
        *why = "clock_regressed";
        return -1;
    }
    /* SPEC-v2 §2.5, §7.8: every checkpoint timestamp is in the timestamp domain. */
    if (*now < 0 || *now > 253402300799LL) {
        *why = "clock_out_of_range";
        return -1;
    }
    c->clock_hw = *now;
    return 0;
}

/* Sign one event as the next witness entry. Returns the wire as base64. */
static char *sign_event(ckpt *c, const char *event, const char *nonce, const char *log_id, int64_t sequence,
                        const uint8_t *entry_hash, const char *previous_digest, int64_t now)
{
    char *eh = entry_hash ? b64_encode(entry_hash, 48) : xformat("");
    char *data = xformat("{\"ack_head\":%lld,\"anchored_digest\":\"%s\",\"entry_hash_b64\":\"%s\",\"event\":\"%s\","
                         "\"frozen\":%s,\"log_id\":\"%s\",\"nonce\":\"%s\",\"previous_digest\":\"%s\","
                         "\"sequence\":%lld,\"timestamp\":%lld}",
                         (long long)c->nacks, c->anchored, eh, event, c->frozen ? "true" : "false", log_id, nonce,
                         previous_digest, (long long)sequence, (long long)now);
    free(eh);
    char *data_b64 = b64_encode((const uint8_t *)data, strlen(data));
    free(data);
    char *prev = b64_encode(c->whead, 48);
    char *obj = xformat("{\"entry_data\":\"%s\",\"log_id\":\"%s\",\"prev_hash\":\"%s\",\"sequence\":%lld,"
                        "\"timestamp\":%lld,\"version\":2,\"witness_id\":\"%s\"}",
                        data_b64, c->wlog, prev, (long long)(c->wseq + 1), (long long)now, c->key_id);
    free(data_b64);
    free(prev);
    RatifyV2Buffer wire = {0};
    int32_t rc = ratify_v2_sign_witness_entry((const uint8_t *)obj, strlen(obj), c->key, NULL, &wire);
    free(obj);
    if (rc != 0) {
        fprintf(stderr, "checkpoint: signing failed: %s\n", ratify_v2_last_error_message());
        return NULL;
    }
    RatifyV2Buffer digest = {0};
    if (ratify_v2_object_body_digest(RatifyV2KindWitnessEntry, wire.ptr, wire.len, &digest) != 0 || digest.len != 48) {
        ratify_v2_buffer_free(digest);
        ratify_v2_buffer_free(wire);
        return NULL;
    }
    memcpy(c->whead, digest.ptr, 48);
    ratify_v2_buffer_free(digest);
    c->wseq++;
    char *out = b64_encode(wire.ptr, wire.len);
    ratify_v2_buffer_free(wire);
    return out;
}

static int is_hex(const char *s, size_t n)
{
    if (strlen(s) != n) return 0;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    return 1;
}

/* An ACK for an already acknowledged sequence needs no time (SPEC-v2 §7.8):
 * an identical retry of (log, sequence, previous entry, entry) returns the
 * original acknowledgement, and a different entry is a fork that freezes the
 * log. Returns the answer, or NULL when the request is not such an ACK. */
static char *ack_acknowledged(ckpt *c, const char *line)
{
    char log_id[40], prev_b64[100], entry_b64[100], state[120];
    long long seq;
    uint8_t prev[48], entry[48], zero[48] = {0};
    if (sscanf(line, "ACK %*s %39s %lld %99s %99s %119s", log_id, &seq, prev_b64, entry_b64, state) != 5 ||
        b64_decode(prev_b64, prev, 48) != 48 || b64_decode(entry_b64, entry, 48) != 48 || !is_hex(state, 96) ||
        strcmp(log_id, c->primary_log) != 0 || seq < 1 || seq > c->nacks)
        return NULL;
    ack_rec *r = &c->acks[seq - 1];
    if (memcmp(r->entry_hash, entry, 48) != 0) {
        c->frozen = 1; /* a different entry at an acknowledged sequence is a fork */
        if (save_state(c) != 0) load_state(c);
        return xformat("ERR log_fork");
    }
    if (memcmp(prev, seq > 1 ? c->acks[seq - 2].entry_hash : zero, 48) != 0)
        return xformat("ERR previous_entry_mismatch");
    return xformat("OK %s", r->witness_b64);
}

/* Handle one request line. Returns a malloc'd answer line (no newline). The
 * state is persisted before any OK is returned; on a persistence failure
 * the in-memory state is reloaded and the request refused. */
static char *handle(ckpt *c, char *line)
{
    char cmd[16] = "", nonce[40] = "";
    if (sscanf(line, "%15s %39s", cmd, nonce) != 2 || !is_hex(nonce, 32)) return xformat("ERR bad_request");
    int64_t now;
    const char *why = NULL;

    if (strcmp(cmd, "GET") == 0) {
        char log_id[40];
        long long seq;
        if (sscanf(line, "GET %*s %39s %lld", log_id, &seq) != 2) return xformat("ERR bad_request");
        if (strcmp(log_id, c->primary_log) != 0 || seq < 1 || seq > c->nacks) return xformat("NOTFOUND");
        return xformat("OK %s", c->acks[seq - 1].witness_b64);
    }

    if (strcmp(cmd, "ACK") == 0) {
        char *answer = ack_acknowledged(c, line);
        if (answer) return answer;
    }

    if (read_clock(c, &now, &why) != 0) return xformat("ERR %s", why);
    char *wire = NULL;

    if (strcmp(cmd, "HEAD") == 0) {
        wire = sign_event(c, "head", nonce, c->primary_log, 0, NULL, "", now);
    } else if (c->frozen && strcmp(cmd, "ACK") != 0) {
        return xformat("ERR frozen");
    } else if (strcmp(cmd, "PROVISION") == 0) {
        char log_id[40], digest[120];
        if (sscanf(line, "PROVISION %*s %39s %119s", log_id, digest) != 2 || !is_hex(log_id, 32) ||
            !is_hex(digest, 96))
            return xformat("ERR bad_request");
        if (c->anchored[0] && (strcmp(c->anchored, digest) != 0 || strcmp(c->primary_log, log_id) != 0))
            return xformat("ERR already_provisioned");
        snprintf(c->primary_log, sizeof c->primary_log, "%s", log_id);
        snprintf(c->anchored, sizeof c->anchored, "%s", digest);
        wire = sign_event(c, "provision", nonce, c->primary_log, 0, NULL, "", now);
    } else if (strcmp(cmd, "ANCHOR") == 0) {
        char prev[120], next[120];
        if (sscanf(line, "ANCHOR %*s %119s %119s", prev, next) != 2 || !is_hex(prev, 96) || !is_hex(next, 96))
            return xformat("ERR bad_request");
        if (!c->anchored[0]) return xformat("ERR not_provisioned");
        if (strcmp(prev, c->anchored) != 0) return xformat("ERR anchor_mismatch");
        snprintf(c->anchored, sizeof c->anchored, "%s", next);
        wire = sign_event(c, "anchor", nonce, c->primary_log, 0, NULL, prev, now);
    } else if (strcmp(cmd, "ACK") == 0) {
        char log_id[40], prev_b64[100], entry_b64[100], state[120];
        long long seq;
        uint8_t prev[48], entry[48];
        if (sscanf(line, "ACK %*s %39s %lld %99s %99s %119s", log_id, &seq, prev_b64, entry_b64, state) != 5 ||
            b64_decode(prev_b64, prev, 48) != 48 || b64_decode(entry_b64, entry, 48) != 48 || !is_hex(state, 96))
            return xformat("ERR bad_request");
        if (strcmp(log_id, c->primary_log) != 0) return xformat("ERR unknown_log");
        uint8_t zero[48] = {0};
        /* An acknowledged sequence was answered before the clock read. After
         * a fork only identical retries of earlier acknowledgements are
         * answered (SPEC-v2 §7.8). */
        if (c->frozen) return xformat("ERR frozen");
        if (seq != c->nacks + 1) return xformat("ERR log_gap");
        if (memcmp(prev, c->nacks ? c->acks[c->nacks - 1].entry_hash : zero, 48) != 0)
            return xformat("ERR previous_entry_mismatch");
        if (strcmp(state, c->anchored) != 0) return xformat("ERR state_digest_mismatch");
        if (c->nacks >= c->capacity) return xformat("ERR storage_full");
        c->acks = realloc(c->acks, (size_t)(c->nacks + 1) * sizeof *c->acks);
        ack_rec *r = &c->acks[c->nacks];
        r->seq = seq;
        memcpy(r->entry_hash, entry, 48);
        snprintf(r->state, sizeof r->state, "%s", state);
        r->timestamp = now;
        c->nacks++;
        r->witness_b64 = sign_event(c, "ack", nonce, log_id, seq, entry, "", now);
        if (!r->witness_b64) {
            load_state(c);
            return xformat("ERR signing_failed");
        }
        wire = xformat("%s", r->witness_b64);
    } else {
        return xformat("ERR bad_request");
    }

    if (!wire || save_state(c) != 0) {
        free(wire);
        load_state(c);
        return xformat("ERR storage_unavailable");
    }
    char *answer = xformat("OK %s", wire);
    free(wire);
    return answer;
}

static int peer_allowed(int fd, long allow_uid)
{
#if defined(__linux__)
    struct ucred cred;
    socklen_t len = sizeof cred;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return 0;
    return (long)cred.uid == allow_uid;
#else
    uid_t uid;
    gid_t gid;
    if (getpeereid(fd, &uid, &gid) != 0) return 0;
    return (long)uid == allow_uid;
#endif
}

static int init_dir(const char *dir, long long capacity)
{
    ckpt c;
    memset(&c, 0, sizeof c);
    snprintf(c.dir, sizeof c.dir, "%s", dir);
    mkdir(dir, 0700);
    char path[600];
    state_path(&c, path, sizeof path);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "checkpoint: %s already exists; refusing to reinitialize\n", path);
        return 1;
    }
    snprintf(path, sizeof path, "%s/checkpoint.key", dir);
    c.key = keypair_create(path);
    if (!c.key) {
        fprintf(stderr, "checkpoint: key generation failed\n");
        return 1;
    }
    RatifyV2PublicKey pub;
    ratify_v2_keypair_public_key(c.key, &pub);
    ratify_v2_keypair_key_id(c.key, c.key_id, sizeof c.key_id);
    uint8_t id[16];
    random_bytes(id, sizeof id);
    hex_encode(id, sizeof id, c.wlog);
    c.capacity = capacity;
    if (save_state(&c) != 0) return 1;
    char *pj = public_key_json(&pub);
    snprintf(path, sizeof path, "%s/checkpoint_pub.json", dir);
    int rc = write_file_durable(path, pj, strlen(pj), 0644);
    free(pj);
    printf("CHECKPOINT_KEY_ID %s\n", c.key_id);
    ratify_v2_keypair_free(c.key);
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *dir = NULL, *sock = NULL;
    long long capacity = DEFAULT_CAPACITY;
    long allow_uid = (long)getuid();
    int init = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--init")) init = 1;
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) dir = argv[++i];
        else if (!strcmp(argv[i], "--socket") && i + 1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--capacity") && i + 1 < argc) capacity = atoll(argv[++i]);
        else if (!strcmp(argv[i], "--allow-uid") && i + 1 < argc) allow_uid = atol(argv[++i]);
        else {
            fprintf(stderr, "usage: %s --init --dir DIR [--capacity N]\n"
                            "       %s --dir DIR --socket PATH [--allow-uid UID]\n", argv[0], argv[0]);
            return 2;
        }
    }
    if (!dir) return 2;
    if (ratify_v2_abi_version() != RATIFY_V2_ABI_VERSION) {
        fprintf(stderr, "checkpoint: Ratify v2 ABI mismatch\n");
        return 1;
    }
    if (init) return init_dir(dir, capacity < 1 ? 1 : capacity);
    if (!sock) return 2;

    ckpt c;
    memset(&c, 0, sizeof c);
    snprintf(c.dir, sizeof c.dir, "%s", dir);
    char path[600];
    snprintf(path, sizeof path, "%s/checkpoint.key", dir);
    c.key = keypair_load(path);
    if (!c.key || load_state(&c) != 0) {
        fprintf(stderr, "checkpoint: cannot load key or state from %s\n", dir);
        return 1;
    }
    ratify_v2_keypair_key_id(c.key, c.key_id, sizeof c.key_id);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    if (strlen(sock) >= sizeof addr.sun_path) {
        fprintf(stderr, "checkpoint: socket path longer than %zu bytes\n", sizeof addr.sun_path - 1);
        return 1;
    }
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", sock);
    unlink(sock);
    if (srv < 0 || bind(srv, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(srv, 8) != 0) {
        perror("checkpoint: bind");
        return 1;
    }
    chmod(sock, 0660);
    printf("checkpoint: serving %s (key %s, acknowledged %lld, %s)\n", sock, c.key_id, (long long)c.nacks,
           c.frozen ? "FROZEN" : c.anchored[0] ? "anchored" : "unprovisioned");
    fflush(stdout);

    while (!stop_requested) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        char line[1024];
        size_t used = 0;
        while (used < sizeof line - 1) {
            ssize_t n = read(fd, line + used, sizeof line - 1 - used);
            if (n <= 0) break;
            used += (size_t)n;
            if (memchr(line, '\n', used)) break;
        }
        line[used] = '\0';
        char *nl = strchr(line, '\n');
        char *answer;
        if (!nl) answer = xformat("ERR bad_request");
        else if (!peer_allowed(fd, allow_uid)) answer = xformat("ERR peer_not_allowed");
        else {
            *nl = '\0';
            answer = handle(&c, line);
        }
        printf("checkpoint: %.*s -> %.*s\n", (int)strcspn(line, " "), line, answer[0] == 'O' ? 2 : 60, answer);
        fflush(stdout);
        if (write(fd, answer, strlen(answer)) < 0 || write(fd, "\n", 1) < 0) { /* peer gone */ }
        free(answer);
        close(fd);
    }
    close(srv);
    unlink(sock);
    free_acks(&c);
    ratify_v2_keypair_free(c.key);
    return 0;
}
