/*
 * verifier-ordering.json through the C ABI with every provider and store
 * implemented in C: a scripted claim store, trust, status evidence (with a
 * C in-memory anchored security journal and its scripted failure modes),
 * audience, rate, receiver binding, and C constraint evaluators (fault
 * modes, and the standard profiles through ratify_v2_evaluate_standard_profile).
 *
 * Manifest (one directory per vector, listed in ordering/index.txt):
 *   bundle.bin, request.json, expect_body.bin (committed only)
 *   meta.txt      key/value lines (claim store mode and times, trust, journal,
 *                 binding, rate, audience modes, expectations)
 *   status.txt    "<issuer> mode <ok|error|panic>" / "<issuer> obj <code> <file>"
 *   preload.txt   "policy <lifetime> <age> <skew>", "key <issuer> <epoch> <ed> <ml>",
 *                 "apply <issuer> <code> <file> <now>"
 *   audience.txt  "m <di> <ci> <receiver|-> <issued> <expires> <digest|-> <n> <domain>..."
 *   evaluators.txt "e <type> <profile> <implementation> <valid_until>"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "v2c.h"

#define MAX_ISSUERS 16
#define MAX_OBJECTS 80
#define MAX_MEMBERS 16
#define MAX_DOMAINS 8
#define MAX_EVAL 16
#define MAX_META 64

enum { C_BINDING, C_CLAIM, C_TRUST, C_STATUS, C_AUDIENCE, C_RATE, C_FINALIZE, C_PROGRESS, C_EVALUATOR, C_N };
static const char *COUNT_NAMES[C_N] = {"receiver_binding", "claim", "trust", "status", "audience",
                                       "rate", "finalize", "progress", "evaluator"};

typedef struct {
    char issuer[160];
    char mode[16];
    int count;
    RatifyV2StatusObject objects[MAX_OBJECTS];
    uint8_t *data[MAX_OBJECTS];
} status_script;

typedef struct {
    RatifyV2AudienceMembership m;
    char receiver[256];
    char digest[256];
    char domain_text[MAX_DOMAINS][256];
    const char *domains[MAX_DOMAINS];
} member;

typedef struct {
    char type[160];
    char profile[160];
    char implementation[64];
    int64_t valid_until;
    struct v2c_vector *vec;
} evaluator;

/* A C in-memory anchored security journal (the reference shape: canonical
 * snapshot bytes plus an anchored head, replaced together by compare-and-swap). */
typedef struct {
    uint8_t *snapshot;
    size_t len;
    uint64_t generation;
    char digest[160];
    char mode[32];
    int cas_calls;
    char bogus[100];
} c_journal;

struct v2c_vector {
    char dir[512];
    uint8_t *bundle;
    size_t bundle_len;
    char *request;
    size_t request_len;
    char meta_key[MAX_META][64];
    char meta_val[MAX_META][1024];
    int nmeta;
    /* scripted claim store */
    int64_t claimed_at, finalization_at, expires_at;
    uint8_t token[32];
    uint8_t *final_body;
    size_t final_body_len;
    /* providers */
    RatifyV2PublicKey root;
    int has_root;
    status_script status[MAX_ISSUERS];
    int nstatus;
    int cancel_status;
    member members[MAX_MEMBERS];
    int nmembers;
    RatifyV2AudienceMembership member_views[MAX_MEMBERS];
    evaluator evals[MAX_EVAL];
    int nevals;
    RatifyV2EvaluatorRegistration regs[MAX_EVAL];
    c_journal journal;
    RatifyV2Buffer rate_seen;
    char rate_batch_text[4096];
    int counts[C_N];
    /* callback structs handed to the library */
    RatifyV2ClaimStoreCallbacks claim_cb;
    RatifyV2TrustCallbacks trust_cb;
    RatifyV2StatusEvidenceCallbacks status_cb;
    RatifyV2JournalStoreCallbacks journal_cb;
    RatifyV2AudienceCallbacks audience_cb;
    RatifyV2RateCallbacks rate_cb;
    RatifyV2ReceiverBindingCallbacks binding_cb;
};

static void bump(v2c_vector *v, int which) { __atomic_fetch_add(&v->counts[which], 1, __ATOMIC_SEQ_CST); }

const char *v2c_vector_meta(const v2c_vector *v, const char *key) {
    for (int i = 0; i < v->nmeta; i++)
        if (strcmp(v->meta_key[i], key) == 0) return v->meta_val[i];
    return "";
}

static int64_t meta_i(const v2c_vector *v, const char *key) { return strtoll(v2c_vector_meta(v, key), NULL, 10); }

const uint8_t *v2c_vector_bundle(const v2c_vector *v, size_t *len) { *len = v->bundle_len; return v->bundle; }
const char *v2c_vector_request(const v2c_vector *v, size_t *len) { *len = v->request_len; return v->request; }

/* <vector dir>/<name>; rotates through four buffers so two paths can be
 * passed to one call. */
static char *path(const v2c_vector *v, const char *name) {
    static char p[4][1024];
    static int next = 0;
    char *out = p[next++ % 4];
    snprintf(out, sizeof p[0], "%s/%s", v->dir, name);
    return out;
}

/* ---- scripted claim store ---------------------------------------------- */

static int32_t sc_now(void *user, int64_t *now) {
    *now = ((v2c_vector *)user)->finalization_at;
    return 0;
}

static int32_t sc_claim(void *user, const RatifyV2ClaimView *view, RatifyV2ClaimResult *out) {
    v2c_vector *v = user;
    bump(v, C_CLAIM);
    v->expires_at = view->expires_at;
    const char *mode = v2c_vector_meta(v, "claim_store");
    RatifyV2Slice none = {NULL, 0}, token = {v->token, sizeof v->token};
    out->claimed_at = v->claimed_at;
    if (strcmp(mode, "create") == 0) { out->disposition = RatifyV2DispositionCreated; out->owner_token = token; return 0; }
    if (strcmp(mode, "in_progress") == 0) { out->disposition = RatifyV2DispositionInProgress; out->owner_token = none; return 0; }
    if (strcmp(mode, "terminal_replay") == 0) { out->disposition = RatifyV2DispositionTerminalReplay; out->owner_token = none; return 0; }
    if (strcmp(mode, "proof_conflict") == 0) return RatifyV2StoreClaimProofConflict;
    return RatifyV2StoreUnavailable;
}

static int32_t sc_finalize(void *user, const char *claim_id, RatifyV2Slice token, RatifyV2Slice terminal,
                           RatifyV2Slice body, int64_t allow_valid_until, int32_t *committed) {
    (void)claim_id; (void)token; (void)terminal;
    v2c_vector *v = user;
    bump(v, C_FINALIZE);
    if (v->finalization_at < v->claimed_at) return RatifyV2ClockRegressed;
    if (allow_valid_until > 0 && (v->finalization_at >= allow_valid_until || v->finalization_at >= v->expires_at))
        return RatifyV2AllowHorizonPassed;
    free(v->final_body);
    v->final_body = malloc(body.len + 1);
    memcpy(v->final_body, body.ptr, body.len);
    v->final_body_len = body.len;
    *committed = 1;
    return 0;
}

static int32_t sc_progress(void *user, const char *claim_id, RatifyV2Slice token, RatifyV2Slice progress) {
    (void)claim_id; (void)token; (void)progress;
    bump(user, C_PROGRESS);
    return 0;
}

static int32_t sc_load(void *user, const char *claim_id, RatifyV2InterruptedClaim *out) {
    (void)user; (void)claim_id; (void)out;
    return RatifyV2StoreUnavailable;
}

static int32_t sc_recover(void *user, const char *claim_id, RatifyV2Slice t, RatifyV2Slice b, int32_t *c) {
    (void)user; (void)claim_id; (void)t; (void)b; (void)c;
    return RatifyV2StoreUnavailable;
}

/* ---- providers ---------------------------------------------------------- */

static int32_t trust_cb(void *user, const RatifyV2CertView *chain, size_t len, int32_t *outcome, RatifyV2PublicKey *root) {
    (void)chain; (void)len;
    v2c_vector *v = user;
    bump(v, C_TRUST);
    const char *mode = v2c_vector_meta(v, "trust_mode");
    if (strcmp(v2c_vector_meta(v, "trust"), "none") == 0) { *outcome = RatifyV2TrustUnavailable; return 0; }
    if (strcmp(mode, "error") == 0) return RatifyV2StoreUnavailable;
    if (strcmp(mode, "panic") == 0) return RatifyV2ErrInternal;
    const char *o = v2c_vector_meta(v, "trust_outcome");
    *outcome = strcmp(o, "trusted") == 0 ? RatifyV2TrustTrusted
             : strcmp(o, "untrusted") == 0 ? RatifyV2TrustUntrusted
             : strcmp(o, "ambiguous") == 0 ? RatifyV2TrustAmbiguous : RatifyV2TrustUnavailable;
    if (v->has_root) *root = v->root;
    return 0;
}

static int32_t status_cb(void *user, const RatifyV2StatusRequest *req, RatifyV2StatusBatch *out) {
    v2c_vector *v = user;
    bump(v, C_STATUS);
    out->objects = NULL;
    out->count = 0;
    for (int i = 0; i < v->nstatus; i++) {
        status_script *s = &v->status[i];
        if (strcmp(s->issuer, req->issuer_id) != 0) continue;
        if (strcmp(s->mode, "error") == 0) return RatifyV2StoreUnavailable;
        if (strcmp(s->mode, "panic") == 0) return RatifyV2ErrInternal;
        out->objects = s->objects;
        out->count = (size_t)s->count;
    }
    /* A caller may cancel the operation from a callback (SPEC-v2 §6.11). */
    return v->cancel_status ? RatifyV2ErrCancelled : 0;
}

static int32_t audience_cb(void *user, const RatifyV2DeferredConstraint *d, size_t n, const char *receiver,
                           RatifyV2AudienceResult *out) {
    (void)d; (void)n; (void)receiver;
    v2c_vector *v = user;
    bump(v, C_AUDIENCE);
    const char *mode = v2c_vector_meta(v, "audience_mode");
    if (strcmp(mode, "error") == 0) return RatifyV2StoreUnavailable;
    if (strcmp(mode, "panic") == 0) return RatifyV2ErrInternal;
    for (int i = 0; i < v->nmembers; i++) v->member_views[i] = v->members[i].m;
    out->memberships = v->nmembers ? v->member_views : NULL;
    out->count = (size_t)v->nmembers;
    return 0;
}

static int32_t rate_cb(void *user, const char *claim_id, RatifyV2Slice token, const char *bundle_hash,
                       const RatifyV2RateReservation *batch, size_t n) {
    (void)claim_id; (void)token; (void)bundle_hash;
    v2c_vector *v = user;
    bump(v, C_RATE);
    v->rate_batch_text[0] = 0;
    for (size_t i = 0; i < n; i++) {
        char item[600];
        snprintf(item, sizeof item, "%s %s %lld %lld;", batch[i].issuer_id, batch[i].cert_id,
                 (long long)batch[i].window_s, (long long)batch[i].limit);
        strncat(v->rate_batch_text, item, sizeof v->rate_batch_text - strlen(v->rate_batch_text) - 1);
    }
    const char *mode = v2c_vector_meta(v, "rate");
    if (strcmp(mode, "reserve") == 0) return 0;
    if (strcmp(mode, "exceeded") == 0) return RatifyV2StoreRateLimitExceeded;
    if (strcmp(mode, "panic") == 0) return RatifyV2ErrInternal;
    return RatifyV2StoreUnavailable;
}

static int32_t binding_cb(void *user, RatifyV2Slice bundle, RatifyV2Slice expected) {
    (void)bundle; (void)expected;
    v2c_vector *v = user;
    bump(v, C_BINDING);
    return strcmp(v2c_vector_meta(v, "binding"), "reject") == 0 ? 1 : 0;
}

/* ---- C journal store ---------------------------------------------------- */

static int32_t journal_load(void *user, RatifyV2JournalSnapshot *out) {
    c_journal *j = user;
    if (strcmp(j->mode, "load_error") == 0) return RatifyV2StatusObjectRejected;
    out->snapshot.ptr = j->snapshot;
    out->snapshot.len = j->len;
    out->generation = j->generation;
    out->digest = j->digest;
    if (strcmp(j->mode, "unanchored") == 0) out->digest = j->bogus;
    return 0;
}

static int32_t journal_cas(void *user, uint64_t generation, const char *digest, const RatifyV2JournalSnapshot *next) {
    c_journal *j = user;
    j->cas_calls++;
    if (strcmp(j->mode, "cas_conflict") == 0 || (strcmp(j->mode, "cas_conflict_once") == 0 && j->cas_calls % 2 == 1))
        return RatifyV2StoreJournalConflict;
    if (generation != j->generation || strcmp(digest, j->digest) != 0) return RatifyV2StoreJournalConflict;
    free(j->snapshot);
    j->snapshot = malloc(next->snapshot.len + 1);
    memcpy(j->snapshot, next->snapshot.ptr, next->snapshot.len);
    j->len = next->snapshot.len;
    j->generation = next->generation;
    snprintf(j->digest, sizeof j->digest, "%s", next->digest);
    return 0;
}

static void journal_init(c_journal *j) {
    RatifyV2Buffer snap = {0};
    char *digest = NULL;
    if (ratify_v2_journal_genesis(&snap, &j->generation, &digest) != 0) { fprintf(stderr, "genesis failed\n"); exit(1); }
    j->snapshot = v2c_take(snap, &j->len);
    snprintf(j->digest, sizeof j->digest, "%s", digest);
    ratify_v2_string_free(digest);
    memset(j->bogus, 'e', 96);
    j->bogus[96] = 0;
}

/* ---- evaluators --------------------------------------------------------- */

static int32_t evaluate_cb(void *user, const RatifyV2EvaluatorCall *call, const RatifyV2EvaluationInput *in,
                           RatifyV2EvaluationResult *out) {
    evaluator *e = user;
    bump(e->vec, C_EVALUATOR);
    out->detail = NULL;
    out->valid_until = 0;
    const char *impl = e->implementation;
    if (strcmp(impl, "fault:error") == 0) return RatifyV2StoreUnavailable;
    if (strcmp(impl, "fault:panic") == 0) return RatifyV2ErrInternal;
    if (strcmp(impl, "fault:timeout") == 0) {
        struct timespec ts = {0, 5000000};
        while (!ratify_v2_evaluator_call_expired(call)) nanosleep(&ts, NULL);
        out->outcome = RatifyV2OutcomePass;
        return 0;
    }
    if (strcmp(impl, "fault:invalid_outcome") == 0) { out->outcome = 99; return 0; }
    if (strcmp(impl, "fault:pass_until") == 0) { out->outcome = RatifyV2OutcomePass; out->valid_until = e->valid_until; return 0; }
    /* A standard profile: rebuild the evaluator input JSON and run it
     * through the ABI. */
    size_t cap = in->params_json.len + in->request_context_json.len + 2048;
    char *json = malloc(cap);
    int n = snprintf(json, cap, "{\"type\":\"%s\",\"delegation_index\":%zu,\"constraint_index\":%zu,"
                     "\"issuer_id\":\"%s\",\"cert_id\":\"%s\",\"evaluation_time\":%lld,\"context\":",
                     in->constraint_type, in->delegation_index, in->constraint_index, in->issuer_id, in->cert_id,
                     (long long)in->evaluation_time);
    memcpy(json + n, in->request_context_json.ptr, in->request_context_json.len);
    n += (int)in->request_context_json.len;
    if (in->has_params) {
        n += snprintf(json + n, cap - (size_t)n, ",\"params\":");
        memcpy(json + n, in->params_json.ptr, in->params_json.len);
        n += (int)in->params_json.len;
    }
    json[n++] = '}';
    int64_t until = 0;
    int32_t outcome = 0;
    int32_t rc = ratify_v2_evaluate_standard_profile(impl, (const uint8_t *)json, (size_t)n, &outcome, &until, NULL);
    free(json);
    if (rc != 0) return rc;
    out->outcome = outcome;
    out->valid_until = until;
    return 0;
}

/* ---- loading ------------------------------------------------------------ */

v2c_vector *v2c_vector_load(const char *subdir) {
    v2c_vector *v = calloc(1, sizeof *v);
    snprintf(v->dir, sizeof v->dir, "%s", subdir);
    v->bundle = v2c_read(path(v, "bundle.bin"), &v->bundle_len);
    v->request = (char *)v2c_read(path(v, "request.json"), &v->request_len);
    char *meta = (char *)v2c_read(path(v, "meta.txt"), NULL), *save = NULL;
    for (char *l = strtok_r(meta, "\n", &save); l && v->nmeta < MAX_META; l = strtok_r(NULL, "\n", &save)) {
        char *sp = strchr(l, ' ');
        if (!sp) continue;
        *sp = 0;
        snprintf(v->meta_key[v->nmeta], sizeof v->meta_key[0], "%s", l);
        snprintf(v->meta_val[v->nmeta], sizeof v->meta_val[0], "%s", sp + 1);
        v->nmeta++;
    }
    free(meta);
    v->claimed_at = meta_i(v, "claimed_at");
    v->finalization_at = meta_i(v, "finalization_at");
    memset(v->token, 7, sizeof v->token);
    if (strcmp(v2c_vector_meta(v, "root"), "yes") == 0) {
        v2c_load_key(path(v, "root.ed"), path(v, "root.ml"), &v->root);
        v->has_root = 1;
    }
    char a[256], b[256], c[256], d[256], e[256];
    /* status scripts */
    char *st = (char *)v2c_read(path(v, "status.txt"), NULL);
    save = NULL;
    for (char *l = strtok_r(st, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        if (sscanf(l, "%255s %255s %255s %255s", a, b, c, d) < 3) continue;
        status_script *s = NULL;
        for (int i = 0; i < v->nstatus; i++) if (strcmp(v->status[i].issuer, a) == 0) s = &v->status[i];
        if (!s) { s = &v->status[v->nstatus++]; snprintf(s->issuer, sizeof s->issuer, "%s", a); snprintf(s->mode, sizeof s->mode, "ok"); }
        if (strcmp(b, "mode") == 0) snprintf(s->mode, sizeof s->mode, "%s", c);
        else {
            size_t len;
            s->data[s->count] = v2c_read(path(v, d), &len);
            s->objects[s->count].object_type = (uint16_t)atoi(c);
            s->objects[s->count].wire.ptr = s->data[s->count];
            s->objects[s->count].wire.len = len;
            s->count++;
        }
    }
    free(st);
    /* audience */
    char *au = (char *)v2c_read(path(v, "audience.txt"), NULL);
    save = NULL;
    for (char *l = strtok_r(au, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        member *m = &v->members[v->nmembers];
        long long issued, expires;
        int nd, off = 0;
        size_t di, ci;
        if (sscanf(l, "m %zu %zu %255s %lld %lld %255s %d%n", &di, &ci, m->receiver, &issued, &expires, m->digest, &nd, &off) < 7) continue;
        for (int k = 0; k < nd && k < MAX_DOMAINS; k++) {
            int used = 0;
            sscanf(l + off, " %255s%n", m->domain_text[k], &used);
            off += used;
            m->domains[k] = m->domain_text[k];
        }
        if (strcmp(m->receiver, "-") == 0) m->receiver[0] = 0;
        if (strcmp(m->digest, "-") == 0) m->digest[0] = 0;
        m->m.delegation_index = di;
        m->m.constraint_index = ci;
        m->m.receiver_id = m->receiver;
        m->m.trust_domain_ids = nd ? m->domains : NULL;
        m->m.trust_domain_ids_len = (size_t)nd;
        m->m.issued_at = issued;
        m->m.expires_at = expires;
        m->m.evidence_digest = m->digest;
        v->nmembers++;
    }
    free(au);
    /* evaluators */
    char *ev = (char *)v2c_read(path(v, "evaluators.txt"), NULL);
    save = NULL;
    for (char *l = strtok_r(ev, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        evaluator *x = &v->evals[v->nevals];
        long long until;
        if (sscanf(l, "e %159s %159s %63s %lld", x->type, x->profile, x->implementation, &until) != 4) continue;
        x->valid_until = until;
        x->vec = v;
        v->regs[v->nevals].constraint_type = x->type;
        v->regs[v->nevals].profile = x->profile;
        v->regs[v->nevals].implementation = RatifyV2EvaluatorCustom;
        v->regs[v->nevals].evaluate = evaluate_cb;
        v->regs[v->nevals].user = x;
        v->nevals++;
    }
    free(ev);
    /* journal */
    snprintf(v->journal.mode, sizeof v->journal.mode, "%s", v2c_vector_meta(v, "journal"));
    if (strcmp(v->journal.mode, "absent") != 0) {
        journal_init(&v->journal);
        /* Configure and preload through the anchored journal callbacks (with
         * the plain anchored mode while preloading). */
        char saved[32];
        snprintf(saved, sizeof saved, "%s", v->journal.mode);
        snprintf(v->journal.mode, sizeof v->journal.mode, "anchored");
        RatifyV2JournalStoreCallbacks jc = {&v->journal, journal_load, journal_cas};
        RatifyV2StatusPolicy policy = {0, 0, 0};
        char *pl = (char *)v2c_read(path(v, "preload.txt"), NULL);
        save = NULL;
        for (char *l = strtok_r(pl, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
            long long x, y, z;
            if (sscanf(l, "policy %lld %lld %lld", &x, &y, &z) == 3) {
                policy.max_list_lifetime_seconds = x;
                policy.max_status_age_seconds = y;
                policy.clock_skew_seconds = z;
            } else if (sscanf(l, "key %255s %lld %255s %255s", a, &x, b, c) == 4) {
                RatifyV2PublicKey k;
                v2c_load_key(path(v, b), path(v, c), &k);
                int32_t rc = ratify_v2_journal_configure_status_key(&jc, a, (uint64_t)x, &k);
                v2c_check(rc == 0, "configure status key", ratify_v2_last_error_message());
            } else if (sscanf(l, "apply %255s %lld %255s %lld %255s %255s", a, &x, b, &y, c, e) == 6) {
                /* apply <issuer> <code> <file> <now> <ed> <ml> with the issuer's key */
                size_t len;
                uint8_t *w = v2c_read(path(v, b), &len);
                RatifyV2PublicKey k;
                v2c_load_key(path(v, c), path(v, e), &k);
                long long epoch = 0;
                char key_line[64];
                snprintf(key_line, sizeof key_line, "epoch_%s", a);
                epoch = strtoll(v2c_vector_meta(v, key_line), NULL, 10);
                int32_t rc = ratify_v2_journal_apply(&jc, (int32_t)x, w, len, a, (uint64_t)epoch, &k, &policy, y);
                v2c_check(rc == 0, "journal preload", ratify_v2_last_error_message());
                free(w);
            }
        }
        free(pl);
        snprintf(v->journal.mode, sizeof v->journal.mode, "%s", saved);
    }
    return v;
}

void v2c_vector_free(v2c_vector *v) {
    for (int i = 0; i < v->nstatus; i++)
        for (int k = 0; k < v->status[i].count; k++) free(v->status[i].data[k]);
    free(v->journal.snapshot);
    free(v->final_body);
    free(v->bundle);
    free(v->request);
    free(v);
}

void v2c_vector_callbacks(v2c_vector *v, const RatifyV2ClaimStoreCallbacks *claim, int cancel_status,
                          RatifyV2VerifyCallbacks *cb, RatifyV2EvaluatorConfig *eval, int *has_eval) {
    RatifyV2ClaimStoreCallbacks scripted = {v, 0, sc_now, sc_claim, sc_finalize, sc_progress, sc_load, sc_recover};
    v->claim_cb = claim ? *claim : scripted;
    v->cancel_status = cancel_status;
    v->trust_cb.user = v;
    v->trust_cb.resolve = trust_cb;
    v->status_cb.user = v;
    v->status_cb.fetch = status_cb;
    v->journal_cb.user = &v->journal;
    v->journal_cb.load = journal_load;
    v->journal_cb.compare_and_swap = journal_cas;
    v->audience_cb.user = v;
    v->audience_cb.lookup = audience_cb;
    v->rate_cb.user = v;
    v->rate_cb.rate_at_finalization = 0;
    v->rate_cb.reserve = rate_cb;
    v->binding_cb.user = v;
    v->binding_cb.check = binding_cb;
    const char *binding = v2c_vector_meta(v, "binding");
    const char *rate = v2c_vector_meta(v, "rate");
    cb->claim_store = &v->claim_cb;
    cb->trust = &v->trust_cb;
    cb->status_evidence = &v->status_cb;
    cb->status_journal = strcmp(v->journal.mode, "absent") == 0 ? NULL : &v->journal_cb;
    cb->audience = &v->audience_cb;
    cb->rate = (strcmp(rate, "absent") == 0 || rate[0] == 0) ? NULL : &v->rate_cb;
    cb->receiver_binding = (strcmp(binding, "accept") == 0 || strcmp(binding, "reject") == 0) ? &v->binding_cb : NULL;
    eval->timeout_ms = 1000;
    eval->registrations = v->nevals ? v->regs : NULL;
    eval->count = (size_t)v->nevals;
    *has_eval = v->nevals > 0;
}

/* ---- the ordering run ---------------------------------------------------- */

static const char *stage_name(int32_t s) {
    switch (s) {
    case RatifyV2StagePreflight: return "preflight";
    case RatifyV2StageReplay: return "replay";
    case RatifyV2StageEvaluating: return "evaluating";
    case RatifyV2StageCommitted: return "committed";
    default: return "-";
    }
}

static const char *disposition_name(int32_t d) {
    switch (d) {
    case RatifyV2DispositionCreated: return "created";
    case RatifyV2DispositionInProgress: return "in_progress";
    case RatifyV2DispositionTerminalReplay: return "terminal_replay";
    default: return "-";
    }
}

static int run_vector(const char *subdir) {
    v2c_vector *v = v2c_vector_load(subdir);
    const char *name = v2c_vector_meta(v, "name");
    RatifyV2VerifyCallbacks cb;
    RatifyV2EvaluatorConfig eval;
    int has_eval;
    v2c_vector_callbacks(v, NULL, 0, &cb, &eval, &has_eval);
    RatifyV2VerifyOutcome out;
    RatifyV2Committed *committed = NULL;
    int32_t rc = ratify_v2_verify_proof_bundle(v->bundle, v->bundle_len, (const uint8_t *)v->request, v->request_len,
                                               has_eval ? &eval : NULL, &cb, &out, NULL, &committed);
    char detail[4096];
    int before = v2c_failures;
    snprintf(detail, sizeof detail, "%s: rc %s (%s)", name, v2c_class(rc), ratify_v2_last_error_message());
    v2c_check(rc == 0, "ordering call", detail);
    const char *want_stage = v2c_vector_meta(v, "expect_stage");
    snprintf(detail, sizeof detail, "%s: stage %s class %s, want %s %s (%s)", name, stage_name(out.stage),
             out.error_code ? v2c_class(out.error_code) : "-", want_stage, v2c_vector_meta(v, "expect_class"),
             ratify_v2_last_error_message());
    v2c_check(strcmp(stage_name(out.stage), want_stage) == 0, "ordering stage", detail);
    v2c_check(strcmp(out.error_code ? v2c_class(out.error_code) : "-", v2c_vector_meta(v, "expect_class")) == 0,
              "ordering class", detail);
    const char *want_disp = v2c_vector_meta(v, "expect_disposition");
    if (strcmp(want_disp, "-") != 0)
        v2c_check(strcmp(disposition_name(out.disposition), want_disp) == 0, "ordering disposition", detail);
    char counts[256] = "";
    for (int i = 0; i < C_N; i++) {
        char c[32];
        snprintf(c, sizeof c, "%d ", v->counts[i]);
        strcat(counts, c);
    }
    snprintf(detail, sizeof detail, "%s: counts %s want %s (%s)", name, counts, v2c_vector_meta(v, "expect_counts"),
             COUNT_NAMES[0]);
    v2c_check(strcmp(counts, v2c_vector_meta(v, "expect_counts")) == 0, "ordering callback counts", detail);
    if (strcmp(want_stage, "committed") == 0) {
        v2c_check(committed != NULL, "ordering committed", name);
        if (committed) {
            RatifyV2Buffer body = {0};
            v2c_check(ratify_v2_committed_receipt_body(committed, &body) == 0, "committed body", name);
            size_t blen, wlen;
            uint8_t *got = v2c_take(body, &blen);
            uint8_t *want = v2c_read(path(v, "expect_body.bin"), &wlen);
            v2c_check(blen == wlen && memcmp(got, want, blen) == 0, "ordering receipt body", name);
            v2c_check(v->final_body_len == blen && memcmp(v->final_body, got, blen) == 0, "finalized body", name);
            int32_t has = 0;
            int64_t horizon = 0;
            v2c_check(ratify_v2_committed_allow_horizon(committed, &has, &horizon) == 0, "allow horizon", name);
            snprintf(detail, sizeof detail, "%s: horizon %d %lld want %s", name, (int)has, (long long)horizon,
                     v2c_vector_meta(v, "expect_allow"));
            char hz[64];
            snprintf(hz, sizeof hz, "%d %lld", (int)has, (long long)horizon);
            v2c_check(strcmp(hz, v2c_vector_meta(v, "expect_allow")) == 0, "ordering allow horizon", detail);
            const char *want_batch = v2c_vector_meta(v, "expect_rate_batch");
            if (want_batch[0]) v2c_check(strcmp(v->rate_batch_text, want_batch) == 0, "ordering rate batch", name);
            free(got);
            free(want);
            ratify_v2_committed_free(committed);
        }
    } else {
        v2c_check(committed == NULL, "ordering non-committed", name);
    }
    v2c_vector_free(v);
    return v2c_failures == before;
}

int v2c_run_ordering(void) {
    char *index = (char *)v2c_read("ordering/index.txt", NULL), *save = NULL;
    int n = 0, pass = 0;
    for (char *l = strtok_r(index, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        if (!l[0]) continue;
        pass += run_vector(l);
        n++;
    }
    free(index);
    printf("verifier-ordering: %d/%d vectors\n", pass, n);
    if (n == 0) { fprintf(stderr, "empty ordering manifest\n"); exit(1); }
    return n;
}
