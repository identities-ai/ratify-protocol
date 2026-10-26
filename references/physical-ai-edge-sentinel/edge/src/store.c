#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clock.h"
#include "store.h"
#include "util.h"

#define STATE_MAGIC "ratify-edge-primary 1"
#define STATE_LABEL "ratify-edge-sentinel/primary-state/v1"
#define STATE_CAP (256u << 20)

typedef struct {
    char claim_id[80];
    char owner_hex[97];
    int64_t claimed_at, lease_expires_at, expires_at, allow_horizon, finalized_at, log_sequence;
    int terminal, abandoned;
    uint8_t *record, *progress, *terminal_result, *body;
    size_t record_len, progress_len, terminal_len, body_len;
    char outbox_digest[112];
    int has_release;
    uint8_t release_hash[48];
    int64_t release_ts;
    int32_t release_outcome; /* RatifyV2ReleaseReleased or RatifyV2ReleaseWithheld */
    char release_reason[32]; /* "" for a release */
} claim_rec;

typedef struct {
    char ns[128];
    int64_t epoch;
    uint8_t digest[48];
    int64_t expires_at;
    uint8_t *record;
    size_t record_len;
} issue_rec;

typedef struct {
    int64_t seq;
    char claim_id[80];
    int appended;
    uint8_t entry_hash[48];
    int acked; /* runtime only: acknowledged during this process */
} entry_rec;

struct store {
    char dir[512];
    ckpt_client ckpt;
    int genesis;
    RatifyV2KeyPair *verifier;
    RatifyV2PublicKey verifier_pub;
    char verifier_id[RATIFY_V2_KEY_ID_BUF_LEN];
    char log_id[33];
    int log_frozen;
    int64_t replay_epoch;
    uint64_t jgen;
    char jdigest[112];
    uint8_t *jsnap;
    size_t jsnap_len;
    claim_rec *claims;
    size_t nclaims;
    issue_rec *issues;
    size_t nissues;
    entry_rec *entries;
    size_t nentries;
    char digest[97];
    int recovering;
    char why[128];
    int64_t clock_hw;
    uint8_t token[32];
    uint8_t ack_hash[48];
    RatifyV2ClaimStoreCallbacks claim_cb;
};

/* ---- Paths and records ----------------------------------------------------- */

static void path_of(const store *s, const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", s->dir, name);
}

static void free_records(store *s)
{
    for (size_t i = 0; i < s->nclaims; i++) {
        free(s->claims[i].record);
        free(s->claims[i].progress);
        free(s->claims[i].terminal_result);
        free(s->claims[i].body);
    }
    for (size_t i = 0; i < s->nissues; i++) free(s->issues[i].record);
    free(s->claims);
    free(s->issues);
    free(s->entries);
    free(s->jsnap);
    s->claims = NULL;
    s->issues = NULL;
    s->entries = NULL;
    s->jsnap = NULL;
    s->nclaims = s->nissues = s->nentries = 0;
    s->jsnap_len = 0;
}

static uint8_t *dup_bytes(const uint8_t *p, size_t len)
{
    uint8_t *out = malloc(len + 1);
    if (len) memcpy(out, p, len);
    out[len] = 0;
    return out;
}

static int same(const uint8_t *a, size_t al, RatifyV2Slice b)
{
    return al == b.len && (al == 0 || memcmp(a, b.ptr, al) == 0);
}

static claim_rec *find_claim(store *s, const char *id)
{
    for (size_t i = 0; i < s->nclaims; i++)
        if (strcmp(s->claims[i].claim_id, id) == 0) return &s->claims[i];
    return NULL;
}

/* ---- Serialization ------------------------------------------------------- */

static char *b64_or_dash(const uint8_t *p, size_t len)
{
    return len ? b64_encode(p, len) : xformat("-");
}

static int cmp_claim(const void *a, const void *b)
{
    return strcmp((*(claim_rec *const *)a)->claim_id, (*(claim_rec *const *)b)->claim_id);
}

static int cmp_issue(const void *a, const void *b)
{
    const issue_rec *x = *(issue_rec *const *)a, *y = *(issue_rec *const *)b;
    int c = strcmp(x->ns, y->ns);
    if (c) return c;
    if (x->epoch != y->epoch) return x->epoch < y->epoch ? -1 : 1;
    return memcmp(x->digest, y->digest, 48);
}

typedef struct {
    char *buf;
    size_t len, cap;
} sbuf;

static void sb_add(sbuf *b, const char *text)
{
    size_t n = strlen(text);
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->buf = realloc(b->buf, b->cap);
    }
    memcpy(b->buf + b->len, text, n + 1);
    b->len += n;
}

static void sb_take(sbuf *b, char *text)
{
    sb_add(b, text);
    free(text);
}

/* Deterministic: claims by claim ID, issuance records by (namespace, epoch,
 * digest), outbox entries by sequence. */
static char *serialize(const store *s, size_t *len)
{
    sbuf b = {0};
    char *jsnap = b64_encode(s->jsnap, s->jsnap_len);
    sb_take(&b, xformat("%s\nepoch %lld\nlog %s %d\njournal %llu %s %s\n", STATE_MAGIC, (long long)s->replay_epoch,
                        s->log_id, s->log_frozen, (unsigned long long)s->jgen, s->jdigest, jsnap));
    free(jsnap);

    issue_rec **is = malloc((s->nissues + 1) * sizeof *is);
    for (size_t i = 0; i < s->nissues; i++) is[i] = &s->issues[i];
    qsort(is, s->nissues, sizeof *is, cmp_issue);
    for (size_t i = 0; i < s->nissues; i++) {
        char *d = b64_encode(is[i]->digest, 48), *r = b64_encode(is[i]->record, is[i]->record_len);
        sb_take(&b, xformat("issue %s %lld %s %lld %s\n", is[i]->ns, (long long)is[i]->epoch, d,
                            (long long)is[i]->expires_at, r));
        free(d);
        free(r);
    }
    free(is);

    claim_rec **cs = malloc((s->nclaims + 1) * sizeof *cs);
    for (size_t i = 0; i < s->nclaims; i++) cs[i] = &s->claims[i];
    qsort(cs, s->nclaims, sizeof *cs, cmp_claim);
    for (size_t i = 0; i < s->nclaims; i++) {
        const claim_rec *c = cs[i];
        char *rec = b64_or_dash(c->record, c->record_len), *pr = b64_or_dash(c->progress, c->progress_len),
             *te = b64_or_dash(c->terminal_result, c->terminal_len), *bo = b64_or_dash(c->body, c->body_len),
             *rh = c->has_release ? b64_encode(c->release_hash, 48) : xformat("-");
        sb_take(&b, xformat("claim %s %s %lld %lld %lld %d %lld %lld %lld %d %s %s %s %s %s %lld %d %s\n", c->claim_id,
                            c->owner_hex, (long long)c->claimed_at, (long long)c->lease_expires_at,
                            (long long)c->expires_at, c->terminal, (long long)c->allow_horizon,
                            (long long)c->finalized_at, (long long)c->log_sequence, c->abandoned, rec, pr, te, bo, rh,
                            (long long)c->release_ts, (int)c->release_outcome,
                            c->release_reason[0] ? c->release_reason : "-"));
        free(rec);
        free(pr);
        free(te);
        free(bo);
        free(rh);
    }
    free(cs);

    for (size_t i = 0; i < s->nentries; i++) {
        char *h = s->entries[i].appended ? b64_encode(s->entries[i].entry_hash, 48) : xformat("-");
        sb_take(&b, xformat("entry %lld %s %s\n", (long long)s->entries[i].seq, s->entries[i].claim_id, h));
        free(h);
    }
    *len = b.len;
    return b.buf;
}

static int b64_field(const char *text, uint8_t **out, size_t *len)
{
    *out = NULL;
    *len = 0;
    if (strcmp(text, "-") == 0) return 0;
    size_t cap = strlen(text);
    *out = malloc(cap + 1);
    long n = b64_decode(text, *out, cap);
    if (n < 0) return -1;
    *len = (size_t)n;
    return 0;
}

static void set_outbox_digest(claim_rec *c)
{
    c->outbox_digest[0] = '\0';
    if (!c->terminal || !c->body_len) return;
    char *d = NULL;
    if (ratify_v2_receipt_outbox_digest(c->body, c->body_len, &d) == 0 && d)
        snprintf(c->outbox_digest, sizeof c->outbox_digest, "%s", d);
    ratify_v2_string_free(d);
}

static int parse(store *s, char *text)
{
    free_records(s);
    if (strncmp(text, STATE_MAGIC "\n", strlen(STATE_MAGIC) + 1) != 0) return -1;
    char *save = NULL;
    int ok = 1;
    for (char *line = strtok_r(text, "\n", &save); ok && line; line = strtok_r(NULL, "\n", &save)) {
        char *tok[20];
        int nt = 0;
        char *ts = NULL;
        for (char *t = strtok_r(line, " ", &ts); t && nt < 20; t = strtok_r(NULL, " ", &ts)) tok[nt++] = t;
        if (nt == 0) continue;
        if (!strcmp(tok[0], "ratify-edge-primary")) continue;
        if (!strcmp(tok[0], "epoch") && nt == 2) {
            s->replay_epoch = strtoll(tok[1], NULL, 10);
        } else if (!strcmp(tok[0], "log") && nt == 3) {
            snprintf(s->log_id, sizeof s->log_id, "%s", tok[1]);
            s->log_frozen = atoi(tok[2]);
        } else if (!strcmp(tok[0], "journal") && nt == 4) {
            s->jgen = strtoull(tok[1], NULL, 10);
            snprintf(s->jdigest, sizeof s->jdigest, "%s", tok[2]);
            ok = b64_field(tok[3], &s->jsnap, &s->jsnap_len) == 0;
        } else if (!strcmp(tok[0], "issue") && nt == 6) {
            s->issues = realloc(s->issues, (s->nissues + 1) * sizeof *s->issues);
            issue_rec *r = &s->issues[s->nissues++];
            memset(r, 0, sizeof *r);
            snprintf(r->ns, sizeof r->ns, "%s", tok[1]);
            r->epoch = strtoll(tok[2], NULL, 10);
            r->expires_at = strtoll(tok[4], NULL, 10);
            ok = b64_decode(tok[3], r->digest, 48) == 48 && b64_field(tok[5], &r->record, &r->record_len) == 0;
        } else if (!strcmp(tok[0], "claim") && (nt == 17 || nt == 19)) {
            s->claims = realloc(s->claims, (s->nclaims + 1) * sizeof *s->claims);
            claim_rec *c = &s->claims[s->nclaims++];
            memset(c, 0, sizeof *c);
            snprintf(c->claim_id, sizeof c->claim_id, "%s", tok[1]);
            snprintf(c->owner_hex, sizeof c->owner_hex, "%s", tok[2]);
            c->claimed_at = strtoll(tok[3], NULL, 10);
            c->lease_expires_at = strtoll(tok[4], NULL, 10);
            c->expires_at = strtoll(tok[5], NULL, 10);
            c->terminal = atoi(tok[6]);
            c->allow_horizon = strtoll(tok[7], NULL, 10);
            c->finalized_at = strtoll(tok[8], NULL, 10);
            c->log_sequence = strtoll(tok[9], NULL, 10);
            c->abandoned = atoi(tok[10]);
            ok = b64_field(tok[11], &c->record, &c->record_len) == 0 &&
                 b64_field(tok[12], &c->progress, &c->progress_len) == 0 &&
                 b64_field(tok[13], &c->terminal_result, &c->terminal_len) == 0 &&
                 b64_field(tok[14], &c->body, &c->body_len) == 0;
            if (ok && strcmp(tok[15], "-") != 0) {
                ok = b64_decode(tok[15], c->release_hash, 48) == 48;
                c->has_release = 1;
            }
            c->release_ts = strtoll(tok[16], NULL, 10);
            /* A line without the release outcome and reason was written
             * before withheld results were recorded: its record is a release. */
            if (nt == 19) {
                c->release_outcome = (int32_t)atoi(tok[17]);
                snprintf(c->release_reason, sizeof c->release_reason, "%s", strcmp(tok[18], "-") ? tok[18] : "");
            } else if (c->has_release) {
                c->release_outcome = RatifyV2ReleaseReleased;
            }
            set_outbox_digest(c);
        } else if (!strcmp(tok[0], "entry") && nt == 4) {
            s->entries = realloc(s->entries, (s->nentries + 1) * sizeof *s->entries);
            entry_rec *e = &s->entries[s->nentries++];
            memset(e, 0, sizeof *e);
            e->seq = strtoll(tok[1], NULL, 10);
            snprintf(e->claim_id, sizeof e->claim_id, "%s", tok[2]);
            if (strcmp(tok[3], "-") != 0) {
                ok = b64_decode(tok[3], e->entry_hash, 48) == 48;
                e->appended = 1;
            }
            ok = ok && e->seq == (int64_t)s->nentries;
        } else {
            ok = 0;
        }
    }
    return ok ? 0 : -1;
}

static int digest_of_file(const char *path, char out[97])
{
    size_t len = 0;
    char *text = read_file(path, STATE_CAP, &len);
    if (!text) return -1;
    sha384_labelled_hex(STATE_LABEL, (const uint8_t *)text, len, out);
    free(text);
    return 0;
}

static int reload(store *s)
{
    char path[600];
    path_of(s, "state", path, sizeof path);
    size_t len = 0;
    char *text = read_file(path, STATE_CAP, &len);
    if (!text) return -1;
    sha384_labelled_hex(STATE_LABEL, (const uint8_t *)text, len, s->digest);
    int rc = parse(s, text);
    free(text);
    return rc;
}

/* Persist the in-memory state. Outside genesis the new digest is anchored in
 * the checkpoint between writing state.next and renaming it into place; a
 * refused anchor discards the change. */
static int commit(store *s)
{
    if (s->recovering) {
        reload(s);
        return -1;
    }
    size_t len = 0;
    char *text = serialize(s, &len);
    char next[97];
    sha384_labelled_hex(STATE_LABEL, (const uint8_t *)text, len, next);
    if (strcmp(next, s->digest) == 0) {
        free(text);
        return 0;
    }
    char path[600], staged[600], why[64] = "";
    path_of(s, "state", path, sizeof path);
    path_of(s, "state.next", staged, sizeof staged);
    if (write_file_sync(staged, text, len, 0600) != 0 || fsync_dir_of(staged) != 0) {
        free(text);
        unlink(staged);
        reload(s);
        return -1;
    }
    free(text);
    if (!s->genesis && ckpt_anchor(&s->ckpt, s->digest, next, why) != 0) {
        fprintf(stderr, "store: anchor refused (%s); change discarded\n", why);
        unlink(staged);
        reload(s);
        return -1;
    }
    /* Anchored: the change is committed. A crash before the rename is
     * resolved at startup by promoting state.next, whose digest is the
     * anchored one. */
    if (rename(staged, path) != 0 || fsync_dir_of(path) != 0)
        fprintf(stderr, "store: rename after anchor failed; startup will promote state.next\n");
    snprintf(s->digest, sizeof s->digest, "%s", next);
    return 0;
}

/* ---- Clock ------------------------------------------------------------------- */

int store_now(store *s, int64_t *now)
{
    int trusted;
    if (clock_read(now, &trusted) != 0) return RatifyV2StoreUnavailable;
    if (*now < s->clock_hw) return RatifyV2ClockRegressed;
    if (*now > s->clock_hw) {
        char path[600], text[32];
        path_of(s, "clock.hw", path, sizeof path);
        int n = snprintf(text, sizeof text, "%lld\n", (long long)*now);
        if (write_file_durable(path, text, (size_t)n, 0600) != 0) return RatifyV2StoreUnavailable;
        s->clock_hw = *now;
    }
    return 0;
}

static int32_t cb_now(void *user, int64_t *out) { return store_now(user, out); }

/* ---- Claim store ------------------------------------------------------------- */

static void owner_digest(const uint8_t *token, size_t len, char out[97])
{
    uint8_t d[48];
    sha384(token, len, d);
    hex_encode(d, 48, out);
}

static int32_t cb_claim(void *user, const RatifyV2ClaimView *view, RatifyV2ClaimResult *out)
{
    store *s = user;
    /* SPEC-v2 §7.3: claims are keyed by claim ID, so an ID not derived from
     * the replay key could open a second claim for one challenge. */
    if (!ratify_v2_claim_id_matches_key(view)) return RatifyV2ConfigurationInvalid;
    int64_t now;
    if (s->recovering || store_now(s, &now) != 0) return RatifyV2ClaimStoreUnavailable;
    claim_rec *r = find_claim(s, view->claim_id);
    if (r) {
        if (!same(r->record, r->record_len, view->record)) return RatifyV2StoreClaimProofConflict;
        out->disposition = r->terminal ? RatifyV2DispositionTerminalReplay : RatifyV2DispositionInProgress;
        out->claimed_at = r->claimed_at;
        out->owner_token.ptr = NULL;
        out->owner_token.len = 0;
        return 0;
    }
    if (!ratify_v2_challenge_time_current(view->issued_at, view->expires_at, view->max_age_seconds,
                                          view->clock_skew_seconds, now))
        return RatifyV2ChallengeNotFresh;
    if (view->has_stream_id || view->has_stream_seq) return RatifyV2Malformed; /* streams are not served */
    if (random_bytes(s->token, sizeof s->token) != 0) return RatifyV2ClaimStoreUnavailable;
    s->claims = realloc(s->claims, (s->nclaims + 1) * sizeof *s->claims);
    r = &s->claims[s->nclaims++];
    memset(r, 0, sizeof *r);
    snprintf(r->claim_id, sizeof r->claim_id, "%s", view->claim_id);
    owner_digest(s->token, sizeof s->token, r->owner_hex);
    r->record = dup_bytes(view->record.ptr, view->record.len);
    r->record_len = view->record.len;
    r->claimed_at = now;
    r->lease_expires_at = now + STORE_LEASE_SECONDS;
    r->expires_at = view->expires_at;
    if (commit(s) != 0) return RatifyV2ClaimStoreUnavailable;
    out->disposition = RatifyV2DispositionCreated;
    out->claimed_at = now;
    out->owner_token.ptr = s->token;
    out->owner_token.len = sizeof s->token;
    return 0;
}

static int32_t owner(store *s, const char *id, RatifyV2Slice token, claim_rec **out, int64_t *now)
{
    claim_rec *r = find_claim(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    char digest[97];
    owner_digest(token.ptr, token.len, digest);
    if (token.len != 32 || strcmp(digest, r->owner_hex) != 0) return RatifyV2ClaimLeaseLost;
    *out = r;
    if (r->terminal) return RatifyV2ClaimAlreadyTerminal;
    int32_t rc = store_now(s, now);
    if (rc) return rc;
    if (*now < r->claimed_at) return RatifyV2ClockRegressed;
    if (*now >= r->lease_expires_at) return RatifyV2ClaimLeaseLost;
    return 0;
}

/* Seal a terminal result and its outbox entry at the next log sequence. */
static void seal(store *s, claim_rec *r, RatifyV2Slice terminal, RatifyV2Slice body, int64_t horizon, int64_t at)
{
    r->terminal = 1;
    r->terminal_result = dup_bytes(terminal.ptr, terminal.len);
    r->terminal_len = terminal.len;
    r->body = dup_bytes(body.ptr, body.len);
    r->body_len = body.len;
    r->allow_horizon = horizon;
    r->finalized_at = at;
    set_outbox_digest(r);
    s->entries = realloc(s->entries, (s->nentries + 1) * sizeof *s->entries);
    entry_rec *e = &s->entries[s->nentries++];
    memset(e, 0, sizeof *e);
    e->seq = (int64_t)s->nentries;
    snprintf(e->claim_id, sizeof e->claim_id, "%s", r->claim_id);
    r->log_sequence = e->seq;
}

/* Whether the canonical encoding of a receipt outbox body holds `member`
 * (for example "\"decision\":\"allow\""). In canonical JSON every quote inside
 * a string value is escaped, and a receipt body has one decision and one
 * decision_reason member, so an exact match is that member. */
static int body_has(RatifyV2Slice body, const char *member)
{
    RatifyV2Buffer canonical = {0};
    if (ratify_v2_object_decode(RatifyV2KindVerificationReceiptBody, body.ptr, body.len, &canonical) != 0) return 0;
    size_t n = strlen(member);
    int found = 0;
    for (size_t i = 0; !found && canonical.len >= n && i <= canonical.len - n; i++)
        found = memcmp(canonical.ptr + i, member, n) == 0;
    ratify_v2_buffer_free(canonical);
    return found;
}

static int32_t cb_finalize(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice terminal, RatifyV2Slice body,
                           int64_t allow_valid_until, int32_t *committed)
{
    store *s = user;
    claim_rec *r = NULL;
    int64_t now = 0;
    int32_t rc = owner(s, id, token, &r, &now);
    if (rc == RatifyV2ClaimAlreadyTerminal) {
        if (same(r->terminal_result, r->terminal_len, terminal) && same(r->body, r->body_len, body)) {
            *committed = 0;
            return 0;
        }
        return rc;
    }
    if (rc) return rc;
    /* SPEC-v2 §7.5: the receipt body binds the sealed claim; a refused body
     * commits nothing. */
    rc = ratify_v2_validate_finalization_payload(r->record, r->record_len, terminal.ptr, terminal.len, body.ptr, body.len);
    if (rc) return rc;
    /* SPEC-v2 §6.8: an allow carries a horizon in the timestamp domain and
     * every other decision carries none. */
    int allow = body_has(body, "\"decision\":\"allow\"");
    if (allow ? (allow_valid_until <= 0 || allow_valid_until > 253402300799LL) : allow_valid_until != 0)
        return RatifyV2ConfigurationInvalid;
    if (allow_valid_until > 0 && (now >= allow_valid_until || now >= r->expires_at)) return RatifyV2AllowHorizonPassed;
    seal(s, r, terminal, body, allow_valid_until, now);
    if (commit(s) != 0) return RatifyV2StoreUnavailable;
    *committed = 1;
    return 0;
}

static int32_t cb_progress(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice progress)
{
    store *s = user;
    claim_rec *r = NULL;
    int64_t now = 0;
    int32_t rc = owner(s, id, token, &r, &now);
    if (rc) return rc;
    /* SPEC-v2 §7.5: an invalid progress record is malformed and not stored,
     * so recovery never reads a record it cannot seal. */
    if (!ratify_v2_valid_evaluation_progress(progress.ptr, progress.len)) return RatifyV2Malformed;
    free(r->progress);
    r->progress = dup_bytes(progress.ptr, progress.len);
    r->progress_len = progress.len;
    return commit(s) == 0 ? 0 : RatifyV2StoreUnavailable;
}

static int32_t cb_load_interrupted(void *user, const char *id, RatifyV2InterruptedClaim *out)
{
    store *s = user;
    claim_rec *r = find_claim(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    int64_t now;
    int32_t rc = store_now(s, &now);
    if (rc) return rc;
    if (!r->terminal && now < r->lease_expires_at) return RatifyV2ClaimLeaseLive;
    out->record.ptr = r->record;
    out->record.len = r->record_len;
    out->claimed_at = r->claimed_at;
    out->progress.ptr = r->progress;
    out->progress.len = r->progress_len;
    return 0;
}

static int32_t cb_recover(void *user, const char *id, RatifyV2Slice terminal, RatifyV2Slice body, int32_t *committed)
{
    store *s = user;
    claim_rec *r = find_claim(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    if (r->terminal) {
        if (same(r->terminal_result, r->terminal_len, terminal) && same(r->body, r->body_len, body)) {
            *committed = 0;
            return 0;
        }
        return RatifyV2ClaimAlreadyTerminal;
    }
    int64_t now;
    int32_t rc = store_now(s, &now);
    if (rc) return rc;
    if (now < r->lease_expires_at) return RatifyV2ClaimLeaseLive;
    /* SPEC-v2 §7.5: recovery validates exactly as finalization does and
     * commits only indeterminate / evaluation_interrupted. */
    rc = ratify_v2_validate_finalization_payload(r->record, r->record_len, terminal.ptr, terminal.len, body.ptr, body.len);
    if (rc) return rc;
    if (!body_has(body, "\"decision\":\"indeterminate\"") || !body_has(body, "\"decision_reason\":\"evaluation_interrupted\""))
        return RatifyV2ConfigurationInvalid;
    seal(s, r, terminal, body, 0, now);
    if (commit(s) != 0) return RatifyV2StoreUnavailable;
    *committed = 1;
    return 0;
}

/* ---- Release store ----------------------------------------------------------- */

static int32_t cb_load_terminal(void *user, const char *id, RatifyV2TerminalClaim *out)
{
    store *s = user;
    claim_rec *r = find_claim(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    out->terminal = r->terminal;
    out->receipt_outbox_digest = r->terminal ? r->outbox_digest : "";
    out->challenge_expires_at = r->expires_at;
    out->allow_horizon = r->allow_horizon;
    out->finalized_at = r->finalized_at;
    out->receipt_abandoned = r->abandoned;
    out->has_release = r->has_release;
    out->release_claim_id = r->claim_id;
    out->release_entry_hash.ptr = r->has_release ? r->release_hash : NULL;
    out->release_entry_hash.len = r->has_release ? 48 : 0;
    out->release_ack_timestamp = r->release_ts;
    out->release_outcome = r->release_outcome;
    out->release_reason = r->release_reason;
    return 0;
}

static int32_t cb_record_release(void *user, const RatifyV2ReleaseRecord *rec)
{
    store *s = user;
    claim_rec *r = find_claim(s, rec->claim_id);
    /* A release, or a withheld result of release steps 7 and 8 (SPEC-v2
     * §6.9); the first record for a claim wins. */
    if (!ratify_v2_valid_release_record_outcome(rec->outcome, rec->reason)) return RatifyV2ConfigurationInvalid;
    if (!r || !r->terminal) return RatifyV2StoreReleaseStateMismatch;
    if (r->has_release)
        return same(r->release_hash, 48, rec->entry_hash) && r->release_ts == rec->ack_timestamp &&
                       r->release_outcome == rec->outcome && strcmp(r->release_reason, rec->reason) == 0
                   ? 0 : RatifyV2StoreReleaseStateMismatch;
    if (rec->entry_hash.len != 48 || strlen(rec->reason) >= sizeof r->release_reason)
        return RatifyV2StoreReleaseStateMismatch;
    memcpy(r->release_hash, rec->entry_hash.ptr, 48);
    r->release_ts = rec->ack_timestamp;
    r->release_outcome = rec->outcome;
    snprintf(r->release_reason, sizeof r->release_reason, "%s", rec->reason);
    r->has_release = 1;
    return commit(s) == 0 ? 0 : RatifyV2StoreUnavailable;
}

/* ---- Checkpoint -------------------------------------------------------------- */

static int32_t fill_ack(store *s, const ckpt_event *ev, RatifyV2Acknowledgement *out)
{
    memcpy(s->ack_hash, ev->entry_hash, 48);
    out->log_id = s->log_id;
    out->sequence = ev->sequence;
    out->entry_hash.ptr = s->ack_hash;
    out->entry_hash.len = 48;
    out->timestamp = ev->timestamp;
    return 0;
}

static int32_t cb_acknowledge(void *user, const char *log_id, int64_t sequence, RatifyV2Slice previous,
                              RatifyV2Slice entry, RatifyV2Acknowledgement *out)
{
    store *s = user;
    if (previous.len != 48 || entry.len != 48) return RatifyV2StoreUnavailable;
    ckpt_event ev;
    if (ckpt_ack(&s->ckpt, log_id, sequence, previous.ptr, entry.ptr, s->digest, &ev, NULL) != 0)
        return RatifyV2StoreUnavailable;
    return fill_ack(s, &ev, out);
}

static int32_t cb_get_ack(void *user, const char *log_id, int64_t sequence, RatifyV2Acknowledgement *out)
{
    store *s = user;
    ckpt_event ev;
    int rc = ckpt_get(&s->ckpt, log_id, sequence, &ev, NULL);
    if (rc == 1) return RatifyV2StoreAcknowledgementNotFound;
    if (rc != 0) return RatifyV2StoreUnavailable;
    return fill_ack(s, &ev, out);
}

/* ---- Issuance store ---------------------------------------------------------- */

static issue_rec *find_issue(store *s, const char *ns, int64_t epoch, RatifyV2Slice digest)
{
    if (digest.len != 48) return NULL;
    for (size_t i = 0; i < s->nissues; i++)
        if (strcmp(s->issues[i].ns, ns) == 0 && s->issues[i].epoch == epoch &&
            memcmp(s->issues[i].digest, digest.ptr, 48) == 0)
            return &s->issues[i];
    return NULL;
}

static int32_t cb_issue_persist(void *user, const char *ns, int64_t epoch, RatifyV2Slice digest, RatifyV2Slice record)
{
    store *s = user;
    if (s->recovering || digest.len != 48 || strlen(ns) >= 128 || strchr(ns, ' ')) return RatifyV2StoreUnavailable;
    if (find_issue(s, ns, epoch, digest)) return RatifyV2StoreIssuanceConflict;
    char *text = malloc(record.len + 1);
    memcpy(text, record.ptr, record.len);
    text[record.len] = '\0';
    int64_t expires_at = 0;
    json_get_int(text, "expires_at", &expires_at);
    free(text);
    s->issues = realloc(s->issues, (s->nissues + 1) * sizeof *s->issues);
    issue_rec *r = &s->issues[s->nissues++];
    memset(r, 0, sizeof *r);
    snprintf(r->ns, sizeof r->ns, "%s", ns);
    r->epoch = epoch;
    memcpy(r->digest, digest.ptr, 48);
    r->expires_at = expires_at;
    r->record = dup_bytes(record.ptr, record.len);
    r->record_len = record.len;
    return commit(s) == 0 ? 0 : RatifyV2StoreUnavailable;
}

static int32_t cb_issue_load(void *user, const char *ns, int64_t epoch, RatifyV2Slice digest, RatifyV2Slice *record)
{
    store *s = user;
    issue_rec *r = find_issue(s, ns, epoch, digest);
    if (!r) return RatifyV2StoreIssuanceNotFound;
    record->ptr = r->record;
    record->len = r->record_len;
    return 0;
}

/* ---- Journal store ----------------------------------------------------------- */

static int32_t cb_journal_load(void *user, RatifyV2JournalSnapshot *out)
{
    store *s = user;
    out->snapshot.ptr = s->jsnap;
    out->snapshot.len = s->jsnap_len;
    out->generation = s->jgen;
    out->digest = s->jdigest;
    return 0;
}

static int32_t cb_journal_cas(void *user, uint64_t expected_generation, const char *expected_digest,
                              const RatifyV2JournalSnapshot *next)
{
    store *s = user;
    if (expected_generation != s->jgen || strcmp(expected_digest, s->jdigest) != 0) return RatifyV2StoreJournalConflict;
    if (strlen(next->digest) >= sizeof s->jdigest) return RatifyV2StoreUnavailable;
    free(s->jsnap);
    s->jsnap = dup_bytes(next->snapshot.ptr, next->snapshot.len);
    s->jsnap_len = next->snapshot.len;
    s->jgen = next->generation;
    snprintf(s->jdigest, sizeof s->jdigest, "%s", next->digest);
    return commit(s) == 0 ? 0 : RatifyV2StoreUnavailable;
}

/* ---- Lifecycle --------------------------------------------------------------- */

void store_callbacks(store *s, RatifyV2ClaimStoreCallbacks *claim, RatifyV2ReleaseStoreCallbacks *release,
                     RatifyV2CheckpointCallbacks *checkpoint, RatifyV2ClockCallbacks *clock,
                     RatifyV2IssuanceStoreCallbacks *issuance, RatifyV2JournalStoreCallbacks *journal)
{
    if (claim) *claim = s->claim_cb;
    if (release) *release = (RatifyV2ReleaseStoreCallbacks){s, cb_now, cb_load_terminal, cb_record_release};
    if (checkpoint) *checkpoint = (RatifyV2CheckpointCallbacks){s, cb_acknowledge, cb_get_ack};
    if (clock) *clock = (RatifyV2ClockCallbacks){s, cb_now};
    if (issuance) *issuance = (RatifyV2IssuanceStoreCallbacks){s, cb_issue_persist, cb_issue_load};
    if (journal) *journal = (RatifyV2JournalStoreCallbacks){s, cb_journal_load, cb_journal_cas};
}

int store_create(const char *dir, int64_t replay_epoch)
{
    store s;
    memset(&s, 0, sizeof s);
    snprintf(s.dir, sizeof s.dir, "%s", dir);
    mkdir(dir, 0700);
    char path[600];
    path_of(&s, "state", path, sizeof path);
    if (access(path, F_OK) == 0) {
        fprintf(stderr, "store: %s already exists; refusing to reinitialize\n", path);
        return -1;
    }
    char rdir[600];
    path_of(&s, "receipts", rdir, sizeof rdir);
    mkdir(rdir, 0700);
    path_of(&s, "verifier.key", path, sizeof path);
    RatifyV2KeyPair *kp = keypair_create(path);
    if (!kp) return -1;
    ratify_v2_keypair_free(kp);
    uint8_t id[16];
    if (random_bytes(id, sizeof id) != 0) return -1;
    hex_encode(id, sizeof id, s.log_id);
    s.replay_epoch = replay_epoch;
    RatifyV2Buffer snap = {0};
    char *digest = NULL;
    if (ratify_v2_journal_genesis(&snap, &s.jgen, &digest) != 0) return -1;
    snprintf(s.jdigest, sizeof s.jdigest, "%s", digest);
    ratify_v2_string_free(digest);
    s.jsnap = dup_bytes(snap.ptr, snap.len);
    s.jsnap_len = snap.len;
    ratify_v2_buffer_free(snap);
    size_t len = 0;
    char *text = serialize(&s, &len);
    path_of(&s, "state", path, sizeof path);
    int rc = write_file_durable(path, text, len, 0600);
    free(text);
    free_records(&s);
    return rc;
}

store *store_open(const char *dir, const ckpt_client *ckpt, int genesis, char why[128])
{
    store *s = calloc(1, sizeof *s);
    snprintf(s->dir, sizeof s->dir, "%s", dir);
    if (ckpt) s->ckpt = *ckpt;
    s->genesis = genesis;
    why[0] = '\0';
    char path[600];
    path_of(s, "verifier.key", path, sizeof path);
    s->verifier = keypair_load(path);
    if (!s->verifier || reload(s) != 0) {
        snprintf(why, 128, "state directory unreadable");
        store_free(s);
        return NULL;
    }
    ratify_v2_keypair_public_key(s->verifier, &s->verifier_pub);
    ratify_v2_keypair_key_id(s->verifier, s->verifier_id, sizeof s->verifier_id);
    path_of(s, "clock.hw", path, sizeof path);
    char *hw = read_file(path, 64, NULL);
    s->clock_hw = hw ? strtoll(hw, NULL, 10) : 0;
    free(hw);
    s->claim_cb = (RatifyV2ClaimStoreCallbacks){s,           0,           cb_now,
                                                cb_claim,    cb_finalize, cb_progress,
                                                cb_load_interrupted,      cb_recover};
    if (genesis) return s;

    /* Startup comparison with the checkpoint (SPEC-v2 §7.13). */
    ckpt_event head;
    char reason[64] = "";
    if (ckpt_head(&s->ckpt, &head, reason) != 0) {
        s->recovering = 1;
        snprintf(s->why, sizeof s->why, "checkpoint unavailable (%s)", reason);
    } else if (head.frozen) {
        s->recovering = 1;
        snprintf(s->why, sizeof s->why, "checkpoint frozen");
    } else if (strcmp(head.log_id, s->log_id) != 0) {
        s->recovering = 1;
        snprintf(s->why, sizeof s->why, "checkpoint serves a different receipt log");
    } else if (strcmp(head.anchored_digest, s->digest) != 0) {
        char staged[600], staged_digest[97];
        path_of(s, "state.next", staged, sizeof staged);
        path_of(s, "state", path, sizeof path);
        if (digest_of_file(staged, staged_digest) == 0 && strcmp(staged_digest, head.anchored_digest) == 0 &&
            rename(staged, path) == 0 && fsync_dir_of(path) == 0 && reload(s) == 0) {
            fprintf(stderr, "store: promoted the anchored state.next after an interrupted commit\n");
        } else {
            s->recovering = 1;
            snprintf(s->why, sizeof s->why, "state digest differs from the anchored digest");
        }
    }
    int64_t appended = 0;
    for (size_t i = 0; i < s->nentries; i++) appended += s->entries[i].appended;
    if (!s->recovering && head.ack_head > appended) {
        s->recovering = 1;
        snprintf(s->why, sizeof s->why, "checkpoint acknowledged entries this state does not hold");
    }
    if (s->recovering) snprintf(why, 128, "%s", s->why);
    return s;
}

int store_provision(store *s)
{
    char reason[64] = "";
    if (ckpt_provision(&s->ckpt, s->log_id, s->digest, reason) != 0) {
        fprintf(stderr, "store: checkpoint provisioning refused (%s)\n", reason);
        return -1;
    }
    s->genesis = 0;
    return 0;
}

void store_free(store *s)
{
    if (!s) return;
    free_records(s);
    ratify_v2_keypair_free(s->verifier);
    free(s);
}

store_health store_status(const store *s, const char **why)
{
    if (why) *why = s->why;
    return s->recovering ? STORE_RECOVERING : STORE_READY;
}

const char *store_log_id(const store *s) { return s->log_id; }
const char *store_verifier_id(const store *s) { return s->verifier_id; }
const RatifyV2PublicKey *store_verifier_key(const store *s) { return &s->verifier_pub; }
int64_t store_replay_epoch(const store *s) { return s->replay_epoch; }
const char *store_digest(const store *s) { return s->digest; }

/* ---- Receipt publisher ------------------------------------------------------- */

static void receipt_path(const store *s, int64_t seq, char *out, size_t cap)
{
    snprintf(out, cap, "%s/receipts/%lld.json", s->dir, (long long)seq);
}

static char *log_head_json(const store *s, int64_t upto)
{
    sbuf acc = {0};
    sb_add(&acc, "");
    for (int64_t i = 0; i < upto; i++) {
        char *d = b64_encode(s->entries[i].entry_hash, 48);
        sb_take(&acc, xformat("%s\"%lld\":\"%s\"", i ? "," : "", (long long)(i + 1), d));
        free(d);
    }
    uint8_t zero[48] = {0};
    char *prev = b64_encode(upto ? s->entries[upto - 1].entry_hash : zero, 48);
    char *head = xformat("{\"log_id\":\"%s\",\"verifier_id\":\"%s\",\"sequence\":%lld,\"head_hash_b64\":\"%s\","
                         "\"accepted_digests_b64\":{%s},\"frozen\":false}",
                         s->log_id, s->verifier_id, (long long)upto, prev, acc.buf);
    free(prev);
    free(acc.buf);
    return head;
}

int store_publish(store *s, const char *claim_id, uint8_t **wire, size_t *wire_len, char reason[64])
{
    *wire = NULL;
    *wire_len = 0;
    snprintf(reason, 64, "%s", "");
    claim_rec *r = find_claim(s, claim_id);
    if (s->recovering || !r || !r->terminal || r->log_sequence < 1 || r->log_sequence > (int64_t)s->nentries) {
        snprintf(reason, 64, "not_publishable");
        return -1;
    }
    int64_t k = r->log_sequence;
    for (int64_t i = 0; i < k - 1; i++)
        if (!s->entries[i].appended) {
            snprintf(reason, 64, "head_of_line_blocked");
            return -1;
        }
    char rpath[700];
    receipt_path(s, k, rpath, sizeof rpath);
    if (s->entries[k - 1].appended) {
        size_t n = 0;
        char *text = read_file(rpath, 1 << 20, &n);
        if (text) {
            *wire = (uint8_t *)text;
            *wire_len = n;
        }
    }
    if (!*wire) {
        /* Sign the sealed body at its position and verify the append. A
         * re-signature of the same body has the same entry hash. */
        char *head = log_head_json(s, k - 1);
        RatifyV2Buffer signed_receipt = {0};
        int32_t rc = ratify_v2_sign_prepared_verification_receipt(r->body, r->body_len, (const uint8_t *)head,
                                                                   strlen(head), s->verifier, NULL, &signed_receipt);
        int32_t result = 0;
        RatifyV2Buffer digest = {0};
        if (rc == 0)
            rc = ratify_v2_verification_receipt_append(signed_receipt.ptr, signed_receipt.len, (const uint8_t *)head,
                                                       strlen(head), &s->verifier_pub, &result, &digest);
        free(head);
        if (rc != 0 || result != RatifyV2LogAppended || digest.len != 48) {
            snprintf(reason, 64, "append_failed:%s", ratify_v2_error_class_str(rc));
            ratify_v2_buffer_free(signed_receipt);
            ratify_v2_buffer_free(digest);
            return -1;
        }
        entry_rec *e = &s->entries[k - 1];
        if (e->appended && memcmp(e->entry_hash, digest.ptr, 48) != 0) {
            snprintf(reason, 64, "entry_hash_changed");
            ratify_v2_buffer_free(signed_receipt);
            ratify_v2_buffer_free(digest);
            return -1;
        }
        if (write_file_durable(rpath, signed_receipt.ptr, signed_receipt.len, 0600) != 0) {
            snprintf(reason, 64, "receipt_write_failed");
            ratify_v2_buffer_free(signed_receipt);
            ratify_v2_buffer_free(digest);
            return -1;
        }
        if (!e->appended) {
            e->appended = 1;
            memcpy(e->entry_hash, digest.ptr, 48);
            ratify_v2_buffer_free(digest);
            if (commit(s) != 0) {
                snprintf(reason, 64, "append_not_anchored");
                ratify_v2_buffer_free(signed_receipt);
                return -1;
            }
        } else {
            ratify_v2_buffer_free(digest);
        }
        *wire_len = signed_receipt.len;
        *wire = dup_bytes(signed_receipt.ptr, signed_receipt.len);
        ratify_v2_buffer_free(signed_receipt);
    }
    /* Submit the appended entry to the checkpoint. An identical retry
     * returns the original acknowledgement. */
    uint8_t zero[48] = {0};
    ckpt_event ev;
    char why[64] = "";
    if (ckpt_ack(&s->ckpt, s->log_id, k, k > 1 ? s->entries[k - 2].entry_hash : zero, s->entries[k - 1].entry_hash,
                 s->digest, &ev, why) != 0) {
        snprintf(reason, 64, "checkpoint:%s", why);
        return 1; /* appended, acknowledgement pending */
    }
    s->entries[k - 1].acked = 1;
    return 0;
}

int store_drain(store *s)
{
    if (s->recovering) return -1;
    int64_t now;
    if (store_now(s, &now) != 0) return -1;
    for (size_t i = 0; i < s->nclaims; i++) {
        claim_rec *c = &s->claims[i];
        if (c->terminal || now < c->lease_expires_at) continue;
        RatifyV2Committed *committed = NULL;
        char id[80];
        snprintf(id, sizeof id, "%s", c->claim_id);
        if (ratify_v2_recover_interrupted_claim(&s->claim_cb, id, &committed) == 0)
            fprintf(stderr, "store: recovered interrupted claim %.16s as evaluation_interrupted\n", id);
        ratify_v2_committed_free(committed);
    }
    for (size_t i = 0; i < s->nentries; i++) {
        if (s->entries[i].acked) continue;
        uint8_t *wire = NULL;
        size_t len = 0;
        char reason[64];
        char id[80];
        snprintf(id, sizeof id, "%s", s->entries[i].claim_id);
        int rc = store_publish(s, id, &wire, &len, reason);
        free(wire);
        if (rc != 0) return -1;
    }
    return 0;
}
