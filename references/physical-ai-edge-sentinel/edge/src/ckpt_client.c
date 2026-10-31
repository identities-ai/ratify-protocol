#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "ckpt_client.h"
#include "util.h"

static void set_reason(char *reason, const char *text)
{
    if (reason) snprintf(reason, 64, "%s", text);
}

/* One request, one answer line. Returns a malloc'd answer or NULL. */
static char *roundtrip(const ckpt_client *c, const char *request)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof addr.sun_path, "%s", c->socket_path);
    struct timeval tv = {10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return NULL;
    }
    size_t len = strlen(request);
    if (write(fd, request, len) != (ssize_t)len || write(fd, "\n", 1) != 1) {
        close(fd);
        return NULL;
    }
    char *buf = malloc(CKPT_LINE_MAX);
    size_t used = 0;
    while (used < CKPT_LINE_MAX - 1) {
        ssize_t n = read(fd, buf + used, CKPT_LINE_MAX - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
        if (memchr(buf, '\n', used)) break;
    }
    close(fd);
    buf[used] = '\0';
    char *nl = strchr(buf, '\n');
    if (!nl) {
        free(buf);
        return NULL;
    }
    *nl = '\0';
    return buf;
}

int ckpt_parse_event(const char *data, ckpt_event *out, char *nonce, size_t nonce_cap)
{
    memset(out, 0, sizeof *out);
    char hash_b64[128] = "";
    int64_t frozen = 0;
    if (!json_get_str(data, "event", out->event, sizeof out->event) ||
        !json_get_str(data, "log_id", out->log_id, sizeof out->log_id) ||
        !json_get_int(data, "sequence", &out->sequence) ||
        !json_get_str(data, "entry_hash_b64", hash_b64, sizeof hash_b64) ||
        !json_get_str(data, "anchored_digest", out->anchored_digest, sizeof out->anchored_digest) ||
        !json_get_int(data, "ack_head", &out->ack_head) || !json_get_int(data, "timestamp", &out->timestamp) ||
        !json_get_str(data, "nonce", nonce, nonce_cap))
        return -1;
    /* frozen is a JSON boolean */
    const char *f = strstr(data, "\"frozen\":");
    if (!f) return -1;
    frozen = strncmp(f + 9, "true", 4) == 0;
    out->frozen = (int)frozen;
    if (hash_b64[0]) {
        if (b64_decode(hash_b64, out->entry_hash, sizeof out->entry_hash) != 48) return -1;
        out->has_entry_hash = 1;
    }
    return 0;
}

/* Send a request and accept only a witness entry signed by the pinned
 * checkpoint key whose event carries `nonce` (when non-NULL). */
static int signed_call(const ckpt_client *c, const char *request, const char *nonce, ckpt_event *out, char *reason)
{
    char *answer = roundtrip(c, request);
    if (!answer) {
        set_reason(reason, "checkpoint_unavailable");
        return -1;
    }
    if (strcmp(answer, "NOTFOUND") == 0) {
        free(answer);
        return 1;
    }
    if (strncmp(answer, "ERR ", 4) == 0) {
        set_reason(reason, answer + 4);
        free(answer);
        return -1;
    }
    if (strncmp(answer, "OK ", 3) != 0) {
        set_reason(reason, "checkpoint_bad_answer");
        free(answer);
        return -1;
    }
    size_t cap = strlen(answer);
    uint8_t *wire = malloc(cap);
    long wlen = b64_decode(answer + 3, wire, cap);
    free(answer);
    int rc = -1;
    if (wlen <= 0) {
        set_reason(reason, "checkpoint_bad_answer");
        goto done;
    }
    RatifyV2Buffer result = {0};
    if (ratify_v2_archival_verify(RatifyV2KindWitnessEntry, wire, (uintptr_t)wlen, NULL, &c->key, &result) != 0) {
        ratify_v2_buffer_free(result);
        set_reason(reason, "checkpoint_signature_invalid");
        goto done;
    }
    ratify_v2_buffer_free(result);
    char *text = malloc((size_t)wlen + 1);
    memcpy(text, wire, (size_t)wlen);
    text[wlen] = '\0';
    char data_b64[8192];
    if (!json_get_str(text, "entry_data", data_b64, sizeof data_b64)) {
        free(text);
        set_reason(reason, "checkpoint_bad_answer");
        goto done;
    }
    free(text);
    char data[8192];
    long dlen = b64_decode(data_b64, (uint8_t *)data, sizeof data - 1);
    if (dlen <= 0) {
        set_reason(reason, "checkpoint_bad_answer");
        goto done;
    }
    data[dlen] = '\0';
    char got_nonce[80];
    if (ckpt_parse_event(data, out, got_nonce, sizeof got_nonce) != 0) {
        set_reason(reason, "checkpoint_bad_event");
        goto done;
    }
    if (nonce && strcmp(nonce, got_nonce) != 0) {
        set_reason(reason, "checkpoint_stale_answer");
        goto done;
    }
    rc = 0;
done:
    free(wire);
    return rc;
}

static void new_nonce(char out[33])
{
    uint8_t n[16];
    if (random_bytes(n, sizeof n) != 0) memset(n, 0, sizeof n);
    hex_encode(n, sizeof n, out);
}

int ckpt_head(const ckpt_client *c, ckpt_event *out, char *reason)
{
    char nonce[33], req[128];
    new_nonce(nonce);
    snprintf(req, sizeof req, "HEAD %s", nonce);
    int rc = signed_call(c, req, nonce, out, reason);
    if (rc == 0 && strcmp(out->event, "head") != 0) {
        set_reason(reason, "checkpoint_bad_event");
        return -1;
    }
    return rc == 0 ? 0 : -1;
}

int ckpt_provision(const ckpt_client *c, const char *log_id, const char *digest, char *reason)
{
    char nonce[33], req[512];
    ckpt_event ev;
    new_nonce(nonce);
    snprintf(req, sizeof req, "PROVISION %s %s %s", nonce, log_id, digest);
    if (signed_call(c, req, nonce, &ev, reason) != 0) return -1;
    if (strcmp(ev.event, "provision") != 0 || strcmp(ev.anchored_digest, digest) != 0) {
        set_reason(reason, "checkpoint_bad_event");
        return -1;
    }
    return 0;
}

int ckpt_anchor(const ckpt_client *c, const char *prev, const char *next, char *reason)
{
    char nonce[33], req[512];
    ckpt_event ev;
    new_nonce(nonce);
    snprintf(req, sizeof req, "ANCHOR %s %s %s", nonce, prev, next);
    CRASH_POINT("anchor", NULL, 0);
    int rc = signed_call(c, req, nonce, &ev, reason);
    CRASH_POINT("anchor", NULL, 1);
    if (rc != 0) return -1;
    if (strcmp(ev.event, "anchor") != 0 || strcmp(ev.anchored_digest, next) != 0) {
        set_reason(reason, "checkpoint_bad_event");
        return -1;
    }
    return 0;
}

static int ack_matches(const ckpt_event *ev, const char *log_id, int64_t sequence, const uint8_t *entry)
{
    return strcmp(ev->event, "ack") == 0 && strcmp(ev->log_id, log_id) == 0 && ev->sequence == sequence &&
           ev->has_entry_hash && (!entry || memcmp(ev->entry_hash, entry, 48) == 0);
}

int ckpt_ack(const ckpt_client *c, const char *log_id, int64_t sequence, const uint8_t prev[48],
             const uint8_t entry[48], const char *state_digest, ckpt_event *out, char *reason)
{
    char nonce[33];
    new_nonce(nonce);
    char *p = b64_encode(prev, 48), *e = b64_encode(entry, 48);
    char *req = xformat("ACK %s %s %lld %s %s %s", nonce, log_id, (long long)sequence, p, e, state_digest);
    free(p);
    free(e);
    /* An identical retry returns the original acknowledgement, which carries
     * the original request's nonce; the signed fields still must match. */
    CRASH_POINT("ack", NULL, 0);
    int rc = signed_call(c, req, NULL, out, reason);
    CRASH_POINT("ack", NULL, 1);
    free(req);
    if (rc != 0) return -1;
    if (!ack_matches(out, log_id, sequence, entry)) {
        set_reason(reason, "checkpoint_bad_event");
        return -1;
    }
    return 0;
}

int ckpt_get(const ckpt_client *c, const char *log_id, int64_t sequence, ckpt_event *out, char *reason)
{
    char nonce[33], req[256];
    new_nonce(nonce);
    snprintf(req, sizeof req, "GET %s %s %lld", nonce, log_id, (long long)sequence);
    int rc = signed_call(c, req, NULL, out, reason);
    if (rc != 0) return rc;
    if (!ack_matches(out, log_id, sequence, NULL)) {
        set_reason(reason, "checkpoint_bad_event");
        return -1;
    }
    return 0;
}
