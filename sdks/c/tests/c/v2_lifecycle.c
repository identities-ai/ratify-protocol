/*
 * A release lifecycle with a C-implemented in-memory Part B store: claim
 * store (leases, owner tokens, finalization compare-and-set, evaluation
 * progress, lease-expiry recovery), authoritative clock, receipt outbox and
 * publisher (signing through ratify_v2_sign_prepared_verification_receipt),
 * release store, and checkpoint. TEST ONLY: nothing here is durable, and
 * the owner token is compared directly rather than through a one-way hash.
 *
 * Manifest: lifecycle/meta.txt ("verifier_seeds <ed> <ml>", "log_id <id>",
 * "lease <seconds>", "allow <request dir>", "cancel <request dir>") and the
 * request directories in the ordering format (their meta also carries
 * "now", "namespace", "replay_epoch", and "challenge_file").
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v2c.h"

#define MAX_CLAIMS 16

typedef struct {
    char claim_id[80];
    uint8_t *record;
    size_t record_len;
    uint8_t token[64];
    size_t token_len;
    int terminal;
    int64_t claimed_at, lease_expires_at, expires_at, allow_horizon, finalized_at;
    char agent_id[160];
    int64_t issued_at, max_age_seconds, clock_skew_seconds; /* the view's, for tests */
    uint8_t *progress, *terminal_result, *body;
    size_t progress_len, terminal_len, body_len;
    char outbox_digest[128];
    int has_release;
    uint8_t release_hash[64];
    size_t release_hash_len;
    int64_t release_ts;
    int32_t release_outcome;
    char release_reason[64];
    int outbox_index;
} claim_rec;

typedef struct {
    int claim;
    uint8_t *wire;
    size_t wire_len;
    uint8_t digest[48];
    int64_t ack_ts;
    int acked;
} outbox_entry;

typedef struct {
    int64_t now, high_water, lease;
    claim_rec claims[MAX_CLAIMS];
    int nclaims;
    outbox_entry outbox[MAX_CLAIMS];
    int noutbox;
    int checkpoint_frozen; /* a fork was refused (SPEC-v2 §7.8) */
    RatifyV2KeyPair *verifier;
    char verifier_id[RATIFY_V2_KEY_ID_BUF_LEN];
    char log_id[64];
    unsigned token_counter;
} c_store;

static uint8_t *dup_slice(RatifyV2Slice s, size_t *len) {
    uint8_t *p = malloc(s.len + 1);
    if (s.len) memcpy(p, s.ptr, s.len);
    *len = s.len;
    return p;
}

static int same(const uint8_t *a, size_t al, RatifyV2Slice b) {
    return al == b.len && (al == 0 || memcmp(a, b.ptr, al) == 0);
}

static claim_rec *find(c_store *s, const char *id) {
    for (int i = 0; i < s->nclaims; i++)
        if (strcmp(s->claims[i].claim_id, id) == 0) return &s->claims[i];
    return NULL;
}

/* One authoritative reading; below the high-water mark is a regression. */
static int32_t read_clock(c_store *s, int64_t *now) {
    if (s->now < s->high_water) return RatifyV2ClockRegressed;
    s->high_water = s->now;
    *now = s->now;
    return 0;
}

static int32_t st_now(void *user, int64_t *out) { return read_clock(user, out); }

static int32_t st_claim(void *user, const RatifyV2ClaimView *view, RatifyV2ClaimResult *out) {
    c_store *s = user;
    /* SPEC-v2 §7.3: the store is keyed by claim ID, so an ID not derived
     * from the replay key could open a second claim for one challenge. */
    if (!ratify_v2_claim_id_matches_key(view)) return RatifyV2ConfigurationInvalid;
    int64_t now;
    if (read_clock(s, &now) != 0) return RatifyV2ClaimStoreUnavailable;
    claim_rec *r = find(s, view->claim_id);
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
    if (view->has_stream_id || view->has_stream_seq) return RatifyV2Malformed; /* streams not used here */
    if (s->nclaims == MAX_CLAIMS) return RatifyV2StoreUnavailable;
    r = &s->claims[s->nclaims++];
    memset(r, 0, sizeof *r);
    snprintf(r->claim_id, sizeof r->claim_id, "%s", view->claim_id);
    r->record = dup_slice(view->record, &r->record_len);
    r->token_len = 32;
    for (size_t i = 0; i < r->token_len; i++) r->token[i] = (uint8_t)(s->token_counter * 31u + i * 7u + 1u);
    s->token_counter++;
    r->claimed_at = now;
    r->lease_expires_at = now + s->lease;
    r->expires_at = view->expires_at;
    snprintf(r->agent_id, sizeof r->agent_id, "%s", view->agent_id);
    r->issued_at = view->issued_at;
    r->max_age_seconds = view->max_age_seconds;
    r->clock_skew_seconds = view->clock_skew_seconds;
    r->outbox_index = -1;
    out->disposition = RatifyV2DispositionCreated;
    out->claimed_at = now;
    out->owner_token.ptr = r->token;
    out->owner_token.len = r->token_len;
    return 0;
}

/* The evaluator capability of a live, evaluating claim. */
static int32_t owner(c_store *s, const char *id, RatifyV2Slice token, claim_rec **out, int64_t *now) {
    claim_rec *r = find(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    if (!same(r->token, r->token_len, token)) return RatifyV2ClaimLeaseLost;
    *out = r;
    if (r->terminal) return RatifyV2ClaimAlreadyTerminal;
    int32_t rc = read_clock(s, now);
    if (rc) return rc;
    if (*now < r->claimed_at) return RatifyV2ClockRegressed;
    if (*now >= r->lease_expires_at) return RatifyV2ClaimLeaseLost;
    return 0;
}

static void commit(c_store *s, claim_rec *r, RatifyV2Slice terminal, RatifyV2Slice body, int64_t horizon, int64_t at) {
    r->terminal = 1;
    r->terminal_result = dup_slice(terminal, &r->terminal_len);
    r->body = dup_slice(body, &r->body_len);
    r->allow_horizon = horizon;
    r->finalized_at = at;
    char *digest = NULL;
    ratify_v2_receipt_outbox_digest(r->body, r->body_len, &digest);
    snprintf(r->outbox_digest, sizeof r->outbox_digest, "%s", digest ? digest : "");
    ratify_v2_string_free(digest);
    r->outbox_index = s->noutbox;
    outbox_entry *e = &s->outbox[s->noutbox++];
    memset(e, 0, sizeof *e);
    e->claim = (int)(r - s->claims);
}

/* Whether the canonical encoding of a receipt outbox body holds `member`
 * (for example "\"decision\":\"allow\""). Every quote inside a canonical
 * string value is escaped, so an exact match is that member. */
static int body_has(RatifyV2Slice body, const char *member) {
    RatifyV2Buffer canonical = {0};
    if (ratify_v2_object_decode(RatifyV2KindVerificationReceiptBody, body.ptr, body.len, &canonical) != 0) return 0;
    size_t n = strlen(member);
    int found = 0;
    for (size_t i = 0; !found && canonical.len >= n && i <= canonical.len - n; i++)
        found = memcmp(canonical.ptr + i, member, n) == 0;
    ratify_v2_buffer_free(canonical);
    return found;
}

static int32_t st_finalize(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice terminal, RatifyV2Slice body,
                           int64_t allow_valid_until, int32_t *committed) {
    c_store *s = user;
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
    /* SPEC-v2 §7.5: the receipt body must bind the sealed claim; a refused
     * body commits nothing. */
    rc = ratify_v2_validate_finalization_payload(r->record, r->record_len, terminal.ptr, terminal.len, body.ptr, body.len);
    if (rc) return rc;
    /* SPEC-v2 §6.8: an allow carries a horizon in the timestamp domain and
     * every other decision carries none. */
    int allow = body_has(body, "\"decision\":\"allow\"");
    if (allow ? (allow_valid_until <= 0 || allow_valid_until > 253402300799LL) : allow_valid_until != 0)
        return RatifyV2ConfigurationInvalid;
    if (allow_valid_until > 0 && (now >= allow_valid_until || now >= r->expires_at)) return RatifyV2AllowHorizonPassed;
    commit(s, r, terminal, body, allow_valid_until, now);
    *committed = 1;
    return 0;
}

static int32_t st_progress(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice progress) {
    c_store *s = user;
    claim_rec *r = NULL;
    int64_t now = 0;
    int32_t rc = owner(s, id, token, &r, &now);
    if (rc) return rc;
    /* SPEC-v2 §7.5: an invalid progress record is malformed and not stored. */
    if (!ratify_v2_valid_evaluation_progress(progress.ptr, progress.len)) return RatifyV2Malformed;
    free(r->progress);
    r->progress = dup_slice(progress, &r->progress_len);
    return 0;
}

static int32_t st_load(void *user, const char *id, RatifyV2InterruptedClaim *out) {
    c_store *s = user;
    claim_rec *r = find(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    int64_t now;
    int32_t rc = read_clock(s, &now);
    if (rc) return rc;
    if (!r->terminal && now < r->lease_expires_at) return RatifyV2ClaimLeaseLive;
    out->record.ptr = r->record;
    out->record.len = r->record_len;
    out->claimed_at = r->claimed_at;
    out->progress.ptr = r->progress;
    out->progress.len = r->progress_len;
    return 0;
}

static int32_t st_recover(void *user, const char *id, RatifyV2Slice terminal, RatifyV2Slice body, int32_t *committed) {
    c_store *s = user;
    claim_rec *r = find(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    if (r->terminal) {
        if (same(r->terminal_result, r->terminal_len, terminal) && same(r->body, r->body_len, body)) {
            *committed = 0;
            return 0;
        }
        return RatifyV2ClaimAlreadyTerminal;
    }
    int64_t now;
    int32_t rc = read_clock(s, &now);
    if (rc) return rc;
    if (now < r->lease_expires_at) return RatifyV2ClaimLeaseLive;
    /* SPEC-v2 §7.5: recovery validates exactly as finalization does and
     * commits only indeterminate / evaluation_interrupted. */
    rc = ratify_v2_validate_finalization_payload(r->record, r->record_len, terminal.ptr, terminal.len, body.ptr, body.len);
    if (rc) return rc;
    if (!body_has(body, "\"decision\":\"indeterminate\"") || !body_has(body, "\"decision_reason\":\"evaluation_interrupted\""))
        return RatifyV2ConfigurationInvalid;
    commit(s, r, terminal, body, 0, now);
    *committed = 1;
    return 0;
}

static int32_t st_load_terminal(void *user, const char *id, RatifyV2TerminalClaim *out) {
    c_store *s = user;
    claim_rec *r = find(s, id);
    if (!r) return RatifyV2ClaimNotFound;
    out->terminal = r->terminal;
    out->receipt_outbox_digest = r->terminal ? r->outbox_digest : "";
    out->challenge_expires_at = r->expires_at;
    out->allow_horizon = r->allow_horizon;
    out->finalized_at = r->finalized_at;
    out->receipt_abandoned = 0;
    out->has_release = r->has_release;
    out->release_claim_id = r->claim_id;
    out->release_entry_hash.ptr = r->release_hash;
    out->release_entry_hash.len = r->release_hash_len;
    out->release_ack_timestamp = r->release_ts;
    out->release_outcome = r->release_outcome;
    out->release_reason = r->release_reason;
    return 0;
}

static int32_t st_record_release(void *user, const RatifyV2ReleaseRecord *rec) {
    c_store *s = user;
    claim_rec *r = find(s, rec->claim_id);
    /* A release record is released, or withheld with a step 7 or 8 reason. */
    if (!ratify_v2_valid_release_record_outcome(rec->outcome, rec->reason)) return RatifyV2ConfigurationInvalid;
    if (!r || !r->terminal) return RatifyV2StoreReleaseStateMismatch;
    /* The first record wins: an identical repeat is 0, anything else differs. */
    if (r->has_release) {
        return same(r->release_hash, r->release_hash_len, rec->entry_hash) && r->release_ts == rec->ack_timestamp &&
                       r->release_outcome == rec->outcome && strcmp(r->release_reason, rec->reason) == 0
                   ? 0
                   : RatifyV2StoreReleaseStateMismatch;
    }
    if (rec->entry_hash.len != 48 || strlen(rec->reason) >= sizeof r->release_reason)
        return RatifyV2StoreReleaseStateMismatch;
    memcpy(r->release_hash, rec->entry_hash.ptr, rec->entry_hash.len);
    r->release_hash_len = rec->entry_hash.len;
    r->release_ts = rec->ack_timestamp;
    r->release_outcome = rec->outcome;
    snprintf(r->release_reason, sizeof r->release_reason, "%s", rec->reason);
    r->has_release = 1;
    return 0;
}

static int32_t st_get_ack(void *user, const char *log_id, int64_t sequence, RatifyV2Acknowledgement *out) {
    c_store *s = user;
    if (strcmp(log_id, s->log_id) != 0 || sequence < 1 || sequence > s->noutbox) return RatifyV2StoreAcknowledgementNotFound;
    outbox_entry *e = &s->outbox[sequence - 1];
    if (!e->acked) return RatifyV2StoreAcknowledgementNotFound;
    out->log_id = s->log_id;
    out->sequence = sequence;
    out->entry_hash.ptr = e->digest;
    out->entry_hash.len = sizeof e->digest;
    out->timestamp = e->ack_ts;
    return 0;
}

static int32_t st_acknowledge(void *user, const char *log_id, int64_t sequence, RatifyV2Slice previous,
                              RatifyV2Slice entry, RatifyV2Acknowledgement *out) {
    c_store *s = user;
    if (strcmp(log_id, s->log_id) != 0 || sequence < 1 || sequence > s->noutbox) return RatifyV2StoreUnavailable;
    outbox_entry *e = &s->outbox[sequence - 1];
    /* SPEC-v2 §7.8: an identical retry returns the original acknowledgement;
     * a different entry at an acknowledged sequence is a fork, which freezes
     * the log; after it nothing new is acknowledged. */
    if (e->acked && !same(e->digest, sizeof e->digest, entry)) {
        s->checkpoint_frozen = 1;
        return RatifyV2StoreUnavailable;
    }
    if (s->checkpoint_frozen && !e->acked) return RatifyV2StoreUnavailable;
    if (!e->wire || !same(e->digest, sizeof e->digest, entry)) return RatifyV2StoreUnavailable;
    /* Only the next sequence: the predecessor is acknowledged and this entry
     * extends it (its digest, or zero for the first). */
    static const uint8_t zero[48] = {0};
    if (sequence > 1 && !s->outbox[sequence - 2].acked) return RatifyV2StoreUnavailable;
    const uint8_t *head = sequence > 1 ? s->outbox[sequence - 2].digest : zero;
    if (!same(head, 48, previous)) return RatifyV2StoreUnavailable;
    if (!e->acked) {
        int64_t now;
        int32_t rc = read_clock(s, &now);
        if (rc) return rc;
        if (now < 0 || now > 253402300799LL) return RatifyV2StoreUnavailable; /* §2.5 domain */
        e->acked = 1;
        e->ack_ts = now;
    }
    return st_get_ack(user, log_id, sequence, out);
}

/* The receipt publisher (§7.7): sign the committed body at its log position
 * and acknowledge it. */
static int publish(c_store *s, const char *claim_id, uint8_t **wire, size_t *wire_len) {
    claim_rec *r = find(s, claim_id);
    if (!r || !r->terminal) return 0;
    outbox_entry *e = &s->outbox[r->outbox_index];
    if (!e->wire) {
        char head[8192], acc[6000] = "";
        for (int i = 0; i < r->outbox_index; i++) {
            char *d = v2c_b64(s->outbox[i].digest, 48);
            char item[256];
            snprintf(item, sizeof item, "%s\"%d\":\"%s\"", i ? "," : "", i + 1, d);
            strcat(acc, item);
            free(d);
        }
        uint8_t zero[48] = {0};
        char *prev = v2c_b64(r->outbox_index ? s->outbox[r->outbox_index - 1].digest : zero, 48);
        snprintf(head, sizeof head,
                 "{\"log_id\":\"%s\",\"verifier_id\":\"%s\",\"sequence\":%d,\"head_hash_b64\":\"%s\","
                 "\"accepted_digests_b64\":{%s},\"frozen\":false}",
                 s->log_id, s->verifier_id, r->outbox_index, prev, acc);
        free(prev);
        RatifyV2Buffer out = {0};
        int32_t rc = ratify_v2_sign_prepared_verification_receipt(r->body, r->body_len, (const uint8_t *)head,
                                                                   strlen(head), s->verifier, NULL, &out);
        v2c_check(rc == 0, "publish sign", ratify_v2_last_error_message());
        if (rc) return 0;
        e->wire = v2c_take(out, &e->wire_len);
        RatifyV2Buffer d = {0};
        rc = ratify_v2_object_body_digest(RatifyV2KindVerificationReceipt, e->wire, e->wire_len, &d);
        size_t dl;
        uint8_t *digest = v2c_take(d, &dl);
        v2c_check(rc == 0 && dl == 48, "publish digest", ratify_v2_last_error_message());
        memcpy(e->digest, digest, 48);
        free(digest);
        /* The checkpoint acknowledges it under its own rules (§7.8). */
        RatifyV2Slice previous = {r->outbox_index ? s->outbox[r->outbox_index - 1].digest : zero, 48};
        RatifyV2Slice entry = {e->digest, 48};
        RatifyV2Acknowledgement ack;
        st_acknowledge(s, s->log_id, r->outbox_index + 1, previous, entry, &ack);
    }
    *wire = e->wire;
    *wire_len = e->wire_len;
    return 1;
}

static int64_t fixed_clock_value;
static int32_t fixed_clock(void *user, int64_t *now) { (void)user; *now = fixed_clock_value; return 0; }

static int allowed_at(const RatifyV2Released *d, int64_t t) {
    fixed_clock_value = t;
    RatifyV2ClockCallbacks clock = {NULL, fixed_clock};
    return ratify_v2_released_allowed(d, &clock);
}

static void run_verify(c_store *s, v2c_vector *v, int cancel, RatifyV2ClaimStoreCallbacks *claim,
                       RatifyV2VerifyOutcome *out, RatifyV2Committed **committed) {
    RatifyV2VerifyCallbacks cb;
    RatifyV2EvaluatorConfig eval;
    int has_eval;
    (void)s;
    v2c_vector_callbacks(v, claim, cancel, &cb, &eval, &has_eval);
    size_t blen, rlen;
    const uint8_t *bundle = v2c_vector_bundle(v, &blen);
    const char *req = v2c_vector_request(v, &rlen);
    int32_t rc = ratify_v2_verify_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, has_eval ? &eval : NULL, &cb,
                                               out, NULL, committed);
    v2c_check(rc == 0, "lifecycle verify call", ratify_v2_last_error_message());
}

static char *released_string(const RatifyV2Released *d, int32_t field) {
    char *out = NULL;
    v2c_check(ratify_v2_released_string(d, field, &out) == 0, "released string", ratify_v2_last_error_message());
    return out;
}

static int release(c_store *s, const RatifyV2Committed *c, const RatifyV2PublicKey *vk, const char *want_decision,
                   RatifyV2ReleaseStoreCallbacks *rs, RatifyV2CheckpointCallbacks *cp) {
    char *claim_id = NULL;
    ratify_v2_committed_claim_id(c, &claim_id);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int checks = 0;
    v2c_check(publish(s, claim_id, &wire, &wire_len), "publish", claim_id);
    RatifyV2Slice receipt = {wire, wire_len};
    int32_t status = 0;
    char *reason = NULL;
    RatifyV2Released *d = NULL;
    int32_t rc = ratify_v2_release_decision(c, receipt, vk, s->log_id, rs, cp, &status, &reason, &d);
    v2c_check(rc == 0 && status == RatifyV2ReleaseReleased && d != NULL, "release", reason ? reason : ratify_v2_last_error_message());
    checks++;
    if (d) {
        char *decision = released_string(d, RatifyV2ReleasedDecision);
        v2c_check(strcmp(decision, want_decision) == 0, "released decision", decision);
        int64_t release_time, expires, horizon;
        int32_t has_horizon;
        v2c_check(ratify_v2_released_times(d, &release_time, &expires, &has_horizon, &horizon) == 0, "released times", "");
        if (strcmp(want_decision, "allow") == 0) {
            int64_t deadline = horizon < expires ? horizon : expires;
            v2c_check(has_horizon && allowed_at(d, release_time) && allowed_at(d, deadline - 1) &&
                          !allowed_at(d, deadline) && !allowed_at(d, deadline + 1),
                      "allowed deadlines", "allowed does not end at the exclusive deadline");
        } else {
            v2c_check(!has_horizon && !allowed_at(d, release_time), "not allowed", "a released non-allow is allowed");
        }
        /* A clock failure is never allowed. */
        RatifyV2ClockCallbacks broken = {NULL, NULL};
        v2c_check(ratify_v2_released_allowed(d, &broken) == 0, "allowed broken clock", "allowed without a clock");
        v2c_check(ratify_v2_released_allowed(d, NULL) == 0, "allowed null clock", "allowed without a clock");
        checks += 4;
        ratify_v2_string_free(decision);
        ratify_v2_released_free(d);
    }
    /* A repeated release re-verifies the acknowledgement and is idempotent. */
    ratify_v2_string_free(reason);
    reason = NULL;
    d = NULL;
    rc = ratify_v2_release_decision(c, receipt, vk, s->log_id, rs, cp, &status, &reason, &d);
    v2c_check(rc == 0 && status == RatifyV2ReleaseReleased, "repeated release", reason ? reason : "");
    ratify_v2_released_free(d);
    ratify_v2_string_free(reason);
    /* Without a published receipt the decision is pending, never released. */
    RatifyV2Slice none = {NULL, 0};
    reason = NULL;
    d = NULL;
    rc = ratify_v2_release_decision(c, none, vk, s->log_id, rs, cp, &status, &reason, &d);
    v2c_check(rc == 0 && status != RatifyV2ReleaseReleased && d == NULL, "release without receipt",
              ratify_v2_release_status_str(status));
    ratify_v2_string_free(reason);
    ratify_v2_string_free(claim_id);
    return checks + 2;
}

/* SPEC-v2 §7.8 at the checkpoint callback, on two published entries:
 * acknowledgement in order only, a fork freezes the log, an identical retry
 * keeps its original timestamp, and every timestamp is in the §2.5 domain. */
static int checkpoint_rules(void) {
    static c_store t;
    memset(&t, 0, sizeof t);
    snprintf(t.log_id, sizeof t.log_id, "%s", "00112233445566778899aabbccddeeff");
    t.now = t.high_water = 1800000000;
    uint8_t wire = 1, zero[48] = {0}, other[48];
    memset(other, 9, sizeof other);
    for (int i = 0; i < 2; i++) {
        t.outbox[i].wire = &wire;
        memset(t.outbox[i].digest, i + 1, 48);
    }
    t.noutbox = 2;
    RatifyV2Slice z = {zero, 48}, d1 = {t.outbox[0].digest, 48}, d2 = {t.outbox[1].digest, 48}, o = {other, 48};
    RatifyV2Acknowledgement a;
    int32_t early = st_acknowledge(&t, t.log_id, 2, d1, d2, &a);
    int early_acked = t.outbox[1].acked;
    int32_t first = st_acknowledge(&t, t.log_id, 1, z, d1, &a);
    int64_t first_ts = a.timestamp;
    t.now += 5;
    int32_t fork = st_acknowledge(&t, t.log_id, 1, z, o, &a);
    int32_t retry = st_acknowledge(&t, t.log_id, 1, z, d1, &a);
    int64_t retry_ts = a.timestamp;
    int32_t next = st_acknowledge(&t, t.log_id, 2, d1, d2, &a);
    v2c_check(early != 0 && !early_acked && first == 0 && fork != 0 && t.checkpoint_frozen && retry == 0 &&
                  retry_ts == first_ts && next != 0 && !t.outbox[1].acked,
              "checkpoint order and fork", "an acknowledgement broke SPEC-v2 §7.8 ordering or the fork freeze");

    t.checkpoint_frozen = 0;
    t.outbox[0].acked = 0;
    t.now = t.high_water = 253402300800LL;
    int32_t beyond = st_acknowledge(&t, t.log_id, 1, z, d1, &a);
    v2c_check(beyond != 0 && !t.outbox[0].acked, "checkpoint timestamp domain",
              "an acknowledgement was timestamped beyond the timestamp domain");

    t.now = 1800000000;
    t.high_water = 1800000100;
    int32_t regressed = st_acknowledge(&t, t.log_id, 1, z, d1, &a);
    v2c_check(regressed == RatifyV2ClockRegressed && !t.outbox[0].acked, "checkpoint clock regression",
              "an acknowledgement used a regressed clock");
    return 3;
}

static void reset_store(c_store *s) {
    for (int i = 0; i < s->nclaims; i++) {
        claim_rec *r = &s->claims[i];
        free(r->record); free(r->progress); free(r->terminal_result); free(r->body);
    }
    for (int i = 0; i < s->noutbox; i++) free(s->outbox[i].wire);
    s->nclaims = s->noutbox = 0;
    s->checkpoint_frozen = 0;
}

static int release_status(c_store *s, const RatifyV2Committed *c, RatifyV2Slice receipt, const RatifyV2PublicKey *vk,
                          RatifyV2ReleaseStoreCallbacks *rs, RatifyV2CheckpointCallbacks *cp, const char *want_reason) {
    int32_t status = 0;
    char *reason = NULL;
    RatifyV2Released *d = NULL;
    int32_t rc = ratify_v2_release_decision(c, receipt, vk, s->log_id, rs, cp, &status, &reason, &d);
    int ok = rc == 0 && status == RatifyV2ReleaseWithheld && d == NULL && reason && strcmp(reason, want_reason) == 0;
    v2c_check(ok, "withheld release", reason ? reason : ratify_v2_last_error_message());
    ratify_v2_string_free(reason);
    ratify_v2_released_free(d);
    return 1;
}

static int withheld_is_permanent(c_store *s, const char *allow_dir, RatifyV2ClaimStoreCallbacks *claim,
                                 const RatifyV2PublicKey *vk, RatifyV2ReleaseStoreCallbacks *rs,
                                 RatifyV2CheckpointCallbacks *cp) {
    int checks = 0;
    reset_store(s);
    v2c_vector *a = v2c_vector_load(allow_dir);
    s->now = s->high_water = strtoll(v2c_vector_meta(a, "now"), NULL, 10);
    char ns[256];
    snprintf(ns, sizeof ns, "%s", v2c_vector_meta(a, "namespace"));
    int64_t epoch = strtoll(v2c_vector_meta(a, "replay_epoch"), NULL, 10);
    RatifyV2VerifyOutcome out;
    RatifyV2Committed *c = NULL;
    run_verify(s, a, 0, claim, &out, &c);
    v2c_vector_free(a);
    v2c_check(out.stage == RatifyV2StageCommitted && c != NULL, "withheld fixture committed", ratify_v2_last_error_message());
    checks++;
    if (!c) return checks;
    char *claim_id = NULL;
    ratify_v2_committed_claim_id(c, &claim_id);
    claim_rec *r = find(s, claim_id);

    /* The store's finalize binds the receipt body to the sealed claim. */
    v2c_check(r && ratify_v2_validate_finalization_payload(r->record, r->record_len, r->terminal_result, r->terminal_len,
                                                           r->body, r->body_len) == 0,
              "finalization payload", ratify_v2_last_error_message());
    const char deny[] = "{\"decision\":\"deny\",\"decision_reason\":\"authorized\"}";
    v2c_check(r && ratify_v2_validate_finalization_payload(r->record, r->record_len, (const uint8_t *)deny, strlen(deny),
                                                           r->body, r->body_len) == RatifyV2ConfigurationInvalid,
              "finalization other decision", "a terminal result naming another decision was accepted");
    v2c_check(r && ratify_v2_validate_finalization_payload(r->record, r->record_len, r->terminal_result, r->terminal_len,
                                                           (const uint8_t *)"{}", 2) == RatifyV2Malformed,
              "finalization malformed body", "a body that does not decode was accepted");
    v2c_check(ratify_v2_valid_release_record_outcome(RatifyV2ReleaseReleased, "") &&
                  ratify_v2_valid_release_record_outcome(RatifyV2ReleaseWithheld, "challenge_expired") &&
                  !ratify_v2_valid_release_record_outcome(RatifyV2ReleaseWithheld, "receipt_abandoned") &&
                  !ratify_v2_valid_release_record_outcome(RatifyV2ReleaseReleased, "clock_regressed") &&
                  !ratify_v2_valid_release_record_outcome(RatifyV2ReleaseNone, ""),
              "release record outcomes", "");
    checks += 4;
    if (r && r->terminal && !r->has_release) {
        /* SPEC-v2 §6.8: a store's finalize commits an allow only with a horizon
         * in the timestamp domain. The committed allow is made live again for
         * direct calls, then restored. */
        int outbox = s->noutbox;
        r->terminal = 0;
        int32_t committed = 0;
        RatifyV2Slice tok = {r->token, r->token_len};
        RatifyV2Slice term = {r->terminal_result, r->terminal_len}, body = {r->body, r->body_len};
        int32_t none = st_finalize(s, r->claim_id, tok, term, body, 0, &committed);
        int32_t beyond = st_finalize(s, r->claim_id, tok, term, body, 253402300800LL, &committed);
        v2c_check(none == RatifyV2ConfigurationInvalid && beyond == RatifyV2ConfigurationInvalid && committed == 0 &&
                      !r->terminal && s->noutbox == outbox,
                  "finalize allow horizon", "an allow without a horizon in the timestamp domain was committed");
        r->terminal = 1;
        /* A release record's entry hash is a 48-byte SHA-384 digest. */
        uint8_t short_hash[32] = {0};
        RatifyV2ReleaseRecord rec = {r->claim_id, {short_hash, sizeof short_hash}, s->now, RatifyV2ReleaseReleased, ""};
        v2c_check(st_record_release(s, &rec) == RatifyV2StoreReleaseStateMismatch && !r->has_release,
                  "release entry hash length", "a release record with a 32-byte entry hash was stored");
        /* An acknowledgement must extend the log head: a wrong predecessor
         * digest acknowledges nothing. */
        if (r->outbox_index >= 0) {
            int64_t seq = r->outbox_index + 1;
            outbox_entry *e = &s->outbox[r->outbox_index];
            /* The entry is not published yet: stand in a wire, then restore. */
            uint8_t *kept_wire = e->wire;
            int kept_acked = e->acked;
            int64_t kept_ts = e->ack_ts;
            uint8_t placeholder = 0, wrong[48], zero[48] = {0};
            if (!kept_wire) e->wire = &placeholder;
            memset(wrong, 0x5a, sizeof wrong);
            const uint8_t *head = seq > 1 ? s->outbox[seq - 2].digest : zero;
            RatifyV2Acknowledgement ack;
            RatifyV2Slice bad = {wrong, sizeof wrong}, good = {head, 48}, entry = {e->digest, sizeof e->digest};
            int32_t refused = st_acknowledge(s, s->log_id, seq, bad, entry, &ack);
            int acked_after_refusal = e->acked;
            e->acked = 0;
            int32_t accepted = st_acknowledge(s, s->log_id, seq, good, entry, &ack);
            e->wire = kept_wire;
            e->acked = kept_acked;
            e->ack_ts = kept_ts;
            v2c_check(refused == RatifyV2StoreUnavailable && !acked_after_refusal && accepted == 0,
                      "acknowledge log head", "an acknowledgement ignored the log head");
            checks++;
        }
        checks += 2;
    }
    if (r) {
        /* A direct store call cannot open a second claim for the sealed
         * challenge (SPEC-v2 §7.3): neither under a forged ID beside the
         * real record, nor with the forged ID written into the record. */
        char forged[65];
        memset(forged, 'a', 64);
        forged[64] = '\0';
        size_t len = r->record_len;
        uint8_t *rewritten = malloc(len);
        memcpy(rewritten, r->record, len);
        char *at = strstr((char *)rewritten, claim_id);
        if (at) memcpy(at, forged, 64);
        RatifyV2ClaimView v;
        memset(&v, 0, sizeof v);
        v.claim_id = claim_id;
        v.verifier_namespace = ns;
        v.replay_epoch = epoch;
        v.agent_id = r->agent_id;
        v.issued_at = r->issued_at;
        v.expires_at = r->expires_at;
        v.max_age_seconds = r->max_age_seconds;
        v.clock_skew_seconds = r->clock_skew_seconds;
        v.record.ptr = r->record;
        v.record.len = len;
        int keyed = ratify_v2_claim_id_matches_key(&v);
        int before = s->nclaims;
        RatifyV2ClaimResult res;
        v.claim_id = forged;
        int32_t beside = st_claim(s, &v, &res);
        v.record.ptr = rewritten;
        int32_t inside = st_claim(s, &v, &res);
        v2c_check(keyed && at && beside == RatifyV2ConfigurationInvalid && inside == RatifyV2ConfigurationInvalid &&
                      s->nclaims == before,
                  "forged claim id", "a claim ID not derived from its replay key was accepted");
        free(rewritten);
        checks += 1;

        /* SPEC-v2 §7.3: the store's freshness rule reads the view, so a view
         * whose expiry is later than the sealed claim's cannot create the
         * expired claim. The sealed claim is first made unknown to the store. */
        v.claim_id = claim_id;
        v.record.ptr = r->record;
        char kept_id[sizeof r->claim_id];
        memcpy(kept_id, r->claim_id, sizeof kept_id);
        r->claim_id[0] = '\0';
        int64_t kept_now = s->now, kept_high = s->high_water;
        s->now = s->high_water = r->expires_at + 1;
        int32_t current = st_claim(s, &v, &res);
        v.expires_at = s->now + 100;
        int32_t later = st_claim(s, &v, &res);
        s->now = kept_now;
        s->high_water = kept_high;
        memcpy(r->claim_id, kept_id, sizeof kept_id);
        v2c_check(current == RatifyV2ChallengeNotFresh && later == RatifyV2ConfigurationInvalid && s->nclaims == before,
                  "claim view expiry", "a view expiry later than the sealed claim's created an expired claim");
        checks += 1;
    }
    {
        static const char ok[] = "{\"context_assessment\":\"not_evaluated\",\"context_policy_digest\":null,"
                                 "\"status_assessment\":\"not_evaluated\",\"status_evidence_digests\":[],\"trust_assessment\":\"trusted\"}";
        static const char renamed[] = "{\"context_assessment\":\"not_evaluated\",\"context_policy_digest\":null,"
                                      "\"status_assessment\":\"not_evaluated\",\"status_evidence\":[],\"trust_assessment\":\"trusted\"}";
        v2c_check(ratify_v2_valid_evaluation_progress((const uint8_t *)ok, sizeof ok - 1) &&
                      !ratify_v2_valid_evaluation_progress((const uint8_t *)renamed, sizeof renamed - 1) &&
                      !ratify_v2_valid_evaluation_progress((const uint8_t *)"{}", 2) &&
                      !ratify_v2_valid_evaluation_progress(NULL, 2),
                  "progress record validity", "");
        checks += 1;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    v2c_check(publish(s, claim_id, &wire, &wire_len), "withheld publish", claim_id);
    RatifyV2Slice receipt = {wire, wire_len}, none = {NULL, 0};
    int64_t expires = 0;
    v2c_check(ratify_v2_committed_challenge_expires_at(c, &expires) == 0, "challenge expiry", ratify_v2_last_error_message());
    s->now = expires;
    checks += release_status(s, c, receipt, vk, rs, cp, "challenge_expired");
    v2c_check(r && r->has_release && r->release_outcome == RatifyV2ReleaseWithheld &&
                  strcmp(r->release_reason, "challenge_expired") == 0,
              "withheld recorded", "the withheld result was not recorded");
    checks++;
    checks += release_status(s, c, none, vk, rs, cp, "challenge_expired");
    checks += release_status(s, c, receipt, vk, rs, cp, "challenge_expired");
    ratify_v2_string_free(claim_id);
    ratify_v2_committed_free(c);
    return checks;
}

int v2c_run_lifecycle(void) {
    char *meta = (char *)v2c_read("lifecycle/meta.txt", NULL), *save = NULL;
    char seed_ed[256] = "", seed_ml[256] = "", allow_dir[256] = "", cancel_dir[256] = "", cancel_id[128] = "";
    c_store s;
    memset(&s, 0, sizeof s);
    for (char *l = strtok_r(meta, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        long long x;
        if (sscanf(l, "verifier_seeds %255s %255s", seed_ed, seed_ml) == 2) continue;
        if (sscanf(l, "log_id %63s", s.log_id) == 1) continue;
        if (sscanf(l, "lease %lld", &x) == 1) { s.lease = x; continue; }
        if (sscanf(l, "allow %255s", allow_dir) == 1) continue;
        if (sscanf(l, "cancel %255s", cancel_dir) == 1) continue;
    }
    free(meta);
    uint8_t *ed = v2c_read(seed_ed, NULL), *ml = v2c_read(seed_ml, NULL);
    v2c_check(ratify_v2_keypair_from_seeds(ed, ml, &s.verifier) == 0, "verifier key", ratify_v2_last_error_message());
    free(ed);
    free(ml);
    ratify_v2_keypair_key_id(s.verifier, s.verifier_id, sizeof s.verifier_id);
    RatifyV2PublicKey vk;
    ratify_v2_keypair_public_key(s.verifier, &vk);

    RatifyV2ClaimStoreCallbacks claim = {&s, 0, st_now, st_claim, st_finalize, st_progress, st_load, st_recover};
    RatifyV2ReleaseStoreCallbacks rs = {&s, st_now, st_load_terminal, st_record_release};
    RatifyV2CheckpointCallbacks cp = {&s, st_acknowledge, st_get_ack};
    int checks = 0;

    /* 1. An allow commits, publishes, releases, and is allowed only before
     *    its exclusive deadlines. */
    v2c_vector *a = v2c_vector_load(allow_dir);
    s.now = s.high_water = strtoll(v2c_vector_meta(a, "now"), NULL, 10);
    RatifyV2VerifyOutcome out;
    RatifyV2Committed *c = NULL;
    run_verify(&s, a, 0, &claim, &out, &c);
    v2c_check(out.stage == RatifyV2StageCommitted && c != NULL, "lifecycle allow committed", ratify_v2_last_error_message());
    checks++;
    if (c) {
        checks += release(&s, c, &vk, "allow", &rs, &cp);
        ratify_v2_committed_free(c);
    }
    /* 2. An exact retry is a terminal replay that discloses nothing. */
    v2c_vector_free(a);
    a = v2c_vector_load(allow_dir);
    c = NULL;
    run_verify(&s, a, 0, &claim, &out, &c);
    v2c_check(out.stage == RatifyV2StageReplay && out.disposition == RatifyV2DispositionTerminalReplay && c == NULL,
              "lifecycle replay", "exact retry was not a terminal replay");
    checks++;
    v2c_vector_free(a);

    /* 3. A provider cancels after the claim: nothing is committed, the claim
     *    stays in progress until its lease expires, and recovery commits the
     *    canonical interrupted result, which releases as indeterminate. */
    for (int i = 0; i < s.nclaims; i++) {
        claim_rec *r = &s.claims[i];
        free(r->record); free(r->progress); free(r->terminal_result); free(r->body);
    }
    for (int i = 0; i < s.noutbox; i++) free(s.outbox[i].wire);
    s.nclaims = s.noutbox = 0; /* a fresh store for the same request */
    v2c_vector *b = v2c_vector_load(cancel_dir);
    s.now = s.high_water = strtoll(v2c_vector_meta(b, "now"), NULL, 10);
    {
        size_t clen;
        uint8_t *challenge = v2c_read(v2c_vector_meta(b, "challenge_file"), &clen);
        const char *ns = v2c_vector_meta(b, "namespace");
        char *id = NULL;
        int32_t idrc = ratify_v2_claim_id((const uint8_t *)ns, strlen(ns), strtoll(v2c_vector_meta(b, "replay_epoch"), NULL, 10),
                                          challenge, clen, &id);
        v2c_check(idrc == 0, "claim id", ratify_v2_last_error_message());
        snprintf(cancel_id, sizeof cancel_id, "%s", id ? id : "");
        ratify_v2_string_free(id);
        free(challenge);
    }
    c = NULL;
    run_verify(&s, b, 1, &claim, &out, &c);
    v2c_check(out.stage == RatifyV2StageEvaluating && out.error_code == RatifyV2EvaluationCancelled && c == NULL,
              "lifecycle cancel", v2c_class(out.error_code));
    RatifyV2Committed *recovered = NULL;
    int32_t rc = ratify_v2_recover_interrupted_claim(&claim, cancel_id, &recovered);
    v2c_check(rc == RatifyV2ClaimLeaseLive && recovered == NULL, "recover during lease", v2c_class(rc));
    s.now += s.lease;
    {
        /* SPEC-v2 §7.5: recovery seals only a valid canonical progress record;
         * one a store returns without context_policy_digest is malformed. */
        claim_rec *r = find(&s, cancel_id);
        static const char partial[] = "{\"context_assessment\":\"not_evaluated\",\"status_assessment\":\"not_evaluated\","
                                      "\"status_evidence_digests\":[],\"trust_assessment\":\"not_evaluated\"}";
        uint8_t *kept = r ? r->progress : NULL;
        size_t kept_len = r ? r->progress_len : 0;
        if (r) {
            r->progress = (uint8_t *)partial;
            r->progress_len = sizeof partial - 1;
        }
        RatifyV2Committed *bad = NULL;
        int32_t brc = ratify_v2_recover_interrupted_claim(&claim, cancel_id, &bad);
        if (r) {
            r->progress = kept;
            r->progress_len = kept_len;
        }
        v2c_check(r && brc == RatifyV2Malformed && bad == NULL && !r->terminal, "recover malformed progress", v2c_class(brc));
        ratify_v2_committed_free(bad);
        checks++;

        /* A NULL slice with a non-zero length is no record at all, not an
         * empty one: recovery must not seal the initial progress for it. */
        if (r) {
            r->progress = NULL;
            r->progress_len = 5;
        }
        bad = NULL;
        brc = ratify_v2_recover_interrupted_claim(&claim, cancel_id, &bad);
        if (r) {
            r->progress = kept;
            r->progress_len = kept_len;
        }
        v2c_check(r && brc != 0 && bad == NULL && !r->terminal, "recover NULL progress slice", v2c_class(brc));
        ratify_v2_committed_free(bad);
        checks++;
    }
    {
        /* SPEC-v2 §7.3: a returned claim record whose challenge digest no
         * longer derives its claim ID was altered; recovery commits nothing. */
        claim_rec *r = find(&s, cancel_id);
        uint8_t *kept = r ? r->record : NULL;
        size_t kept_len = r ? r->record_len : 0;
        uint8_t *altered = r ? malloc(kept_len) : NULL;
        uint8_t *hex = NULL;
        if (altered) {
            memcpy(altered, kept, kept_len);
            static const char key[] = "\"challenge_digest\":\"sha384:";
            size_t n = sizeof key - 1;
            for (size_t i = 0; !hex && i + n < kept_len; i++)
                if (memcmp(altered + i, key, n) == 0) hex = altered + i + n;
        }
        if (hex) {
            *hex = *hex == '0' ? '1' : '0'; /* still canonical lowercase hex */
            r->record = altered;
        }
        RatifyV2Committed *bad = NULL;
        int32_t brc = ratify_v2_recover_interrupted_claim(&claim, cancel_id, &bad);
        if (r) r->record = kept;
        r = find(&s, cancel_id);
        v2c_check(hex && r && r->record_len == kept_len && brc == RatifyV2Malformed && bad == NULL && !r->terminal,
                  "recover altered claim key", v2c_class(brc));
        ratify_v2_committed_free(bad);
        free(altered);
        checks++;

        /* SPEC-v2 §7.5: the store's own recovery validates as finalization
         * does, so an invalid direct payload commits nothing. */
        static const char empty[] = "{}";
        RatifyV2Slice e = {(const uint8_t *)empty, sizeof empty - 1};
        int32_t committed = 0;
        int32_t drc = st_recover(&s, cancel_id, e, e, &committed);
        v2c_check(drc != 0 && committed == 0 && r && !r->terminal, "direct recover invalid payload", v2c_class(drc));
        checks++;
    }
    rc = ratify_v2_recover_interrupted_claim(&claim, cancel_id, &recovered);
    v2c_check(rc == 0 && recovered != NULL, "recover after lease", ratify_v2_last_error_message());
    checks += 3;
    if (recovered) {
        RatifyV2Buffer body = {0};
        ratify_v2_committed_receipt_body(recovered, &body);
        uint8_t *text = v2c_take(body, NULL);
        v2c_check(strstr((char *)text, "\"decision_reason\":\"evaluation_interrupted\"") != NULL, "interrupted body", (char *)text);
        free(text);
        checks += release(&s, recovered, &vk, "indeterminate", &rs, &cp);
        ratify_v2_committed_free(recovered);
    }
    v2c_vector_free(b);

    /* 4. Withheld is permanent (SPEC-v2 §6.9): a release at the challenge
     *    expiry records the withheld result through record_release, and a
     *    later call is withheld with the recorded reason right after the
     *    committed-state step, even without a receipt. */
    checks += withheld_is_permanent(&s, allow_dir, &claim, &vk, &rs, &cp);
    checks += checkpoint_rules();

    /* 5. A regressed clock fails closed at the store. */
    s.now -= 10;
    int64_t t;
    v2c_check(st_now(&s, &t) == RatifyV2ClockRegressed, "clock regression", "regressed clock accepted");
    checks++;

    for (int i = 0; i < s.nclaims; i++) {
        claim_rec *r = &s.claims[i];
        free(r->record); free(r->progress); free(r->terminal_result); free(r->body);
    }
    for (int i = 0; i < s.noutbox; i++) free(s.outbox[i].wire);
    ratify_v2_keypair_free(s.verifier);
    printf("lifecycle (C store): %d checks\n", checks);
    return checks;
}
