/*
 * Multi-threaded stress program for the Protocol v2 C ABI, compiled with a
 * plain C compiler and pthreads against include/ratify.h and the built
 * ratify-c library (scripts/test-v2-c-stress.sh builds and runs it).
 *
 * Usage: v2_stress [-t threads] [-r rounds] [-d seconds]
 *                  [-o ops-per-thread-per-round] [-c challenges] [-s seed]
 *                  <manifest-dir>
 *
 * <manifest-dir> is produced by scripts/test-v2-c-abi.sh (PREPARE_ONLY=1)
 * from testvectors/v2: lifecycle/meta.txt and every lifecycle request in
 * lifereq/. The run stops after `rounds` rounds or `seconds` seconds,
 * whichever comes first (0 disables a bound; the default is 40 seconds).
 *
 * The store is the C-implemented in-memory store of tests/c/v2_lifecycle.c
 * (claim store, release store, receipt outbox, checkpoint), included here
 * unchanged and made thread-safe by one mutex around every callback. The
 * scripted providers are those of tests/c/v2_ordering.c, one instance per
 * thread and request. TEST ONLY: nothing here is durable.
 *
 * Each round resets the store and picks distinct challenges from the
 * lifecycle requests that commit in a fresh store. Every thread then runs a
 * randomized mix against those shared challenges through the ratify_v2_*
 * exports with C callbacks: full verifications of the same challenge
 * (exact retries), claim-only calls, conflicting bundles for one challenge,
 * cancellation from a provider, slow owners whose lease expires inside
 * finalize, lease-expiry recovery, direct non-owner finalize attempts,
 * ordered publication and acknowledgement (with retries, out-of-order
 * submissions and, in some rounds, a fork), release decisions on shared
 * committed handles, clock advances, and handle create/free churn.
 *
 * Invariants are checked in the callbacks, after every call, and at the end
 * of each round; any failure makes the exit status nonzero:
 *   - exactly one claimer of a challenge sees `created`; the others see an
 *     in-progress or terminal replay, or claim_replay for another bundle;
 *   - at most one terminal result per claim, and it never changes; every
 *     committed handle carries the stored body;
 *   - a finalize at or after lease expiry, or by a non-owner, never commits;
 *   - recovery after lease expiry commits evaluation_interrupted;
 *   - release yields released only with a released record for an
 *     acknowledged receipt, an allow only for a finalized allow, and a
 *     released claim has one decision;
 *   - acknowledgements extend the log in sequence with no gap, never change
 *     on retry, and nothing new is acknowledged after a fork froze the log.
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* The C store of the single-threaded lifecycle section, reused unchanged. */
#include "../c/v2_lifecycle.c"

#define MAX_REQ 64
#define MAX_CH 8
#define MAX_HANDLES 8
#define MAX_THREADS 64
#define MAX_FAIL_PRINT 40

/* ---- shared helpers (as in tests/c/v2_abi_main.c, thread-safe) --------- */

int v2c_failures = 0;
const char *v2c_dir = NULL;
static pthread_mutex_t print_mu = PTHREAD_MUTEX_INITIALIZER;
static int round_no; /* written by thread 0 between barriers */

static void fail(const char *fmt, ...) {
    int n = __atomic_add_fetch(&v2c_failures, 1, __ATOMIC_SEQ_CST);
    if (n > MAX_FAIL_PRINT) return;
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&print_mu);
    fprintf(stderr, "FAIL round %d: %s\n", round_no, msg);
    pthread_mutex_unlock(&print_mu);
}

unsigned char *v2c_read(const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", v2c_dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short read %s\n", path); exit(2); }
    buf[n] = 0;
    fclose(f);
    if (len) *len = (size_t)n;
    return buf;
}

unsigned char *v2c_read_opt(const char *name, size_t *len) {
    if (strcmp(name, "-") == 0) { if (len) *len = 0; return NULL; }
    return v2c_read(name, len);
}

void v2c_check(int ok, const char *what, const char *detail) {
    if (!ok) fail("%s: %s", what, detail);
}

char *v2c_b64(const uint8_t *data, size_t len) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *out = malloc(4 * ((len + 2) / 3) + 1);
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = i + 1 < len ? t[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? t[v & 63] : '=';
    }
    out[o] = 0;
    return out;
}

void v2c_load_key(const char *ed_file, const char *ml_file, RatifyV2PublicKey *out) {
    size_t a, b;
    unsigned char *ed = v2c_read(ed_file, &a);
    unsigned char *ml = v2c_read(ml_file, &b);
    if (a != sizeof out->ed25519 || b != sizeof out->ml_dsa_65) { fprintf(stderr, "bad key %s\n", ed_file); exit(2); }
    memcpy(out->ed25519, ed, a);
    memcpy(out->ml_dsa_65, ml, b);
    free(ed);
    free(ml);
}

const char *v2c_class(int32_t code) { return ratify_v2_error_class_str(code); }

uint8_t *v2c_take(RatifyV2Buffer b, size_t *len) {
    uint8_t *out = malloc(b.len + 1);
    if (b.len) memcpy(out, b.ptr, b.len);
    out[b.len] = 0;
    if (len) *len = b.len;
    ratify_v2_buffer_free(b);
    return out;
}

/* ---- barrier (macOS has no pthread_barrier_t) ---------------------------- */

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int n, waiting, phase;
} barrier_t;

static void barrier_wait(barrier_t *b) {
    pthread_mutex_lock(&b->mu);
    int phase = b->phase;
    if (++b->waiting == b->n) {
        b->waiting = 0;
        b->phase++;
        pthread_cond_broadcast(&b->cv);
    } else {
        while (phase == b->phase) pthread_cond_wait(&b->cv, &b->mu);
    }
    pthread_mutex_unlock(&b->mu);
}

/* ---- requests, groups, statistics ---------------------------------------- */

typedef struct {
    char name[32], dir[64], claim_id[80];
    int allow, claim_only, group;
    int64_t now, expires, horizon;
} req_info;

typedef struct {
    int req[4];
    int n;
} group_info;

static req_info reqs[MAX_REQ];
static int nreq;
static group_info groups[MAX_REQ];
static int ngroups;
/* The calibrated outcome of a second bundle for a claimed challenge. */
static int32_t conflict_stage, conflict_class, conflict_claim_rc;

enum {
    S_VERIFY, S_COMMITTED, S_REPLAY_PROGRESS, S_REPLAY_TERMINAL, S_CONFLICT, S_CANCELLED, S_LEASE_LOST,
    S_ALREADY_TERMINAL, S_HORIZON, S_CLAIM_ONLY, S_CLAIM_ONLY_CREATED, S_RECOVER, S_RECOVERED, S_LEASE_LIVE, S_NOT_FOUND,
    S_SLOW, S_LATE_FENCED, S_NONOWNER_REFUSED, S_PUBLISH, S_ACK, S_ACK_RETRY, S_ACK_ORDER_REFUSED, S_FORK,
    S_RELEASE, S_RELEASED_ALLOW, S_RELEASED_OTHER, S_WITHHELD, S_WITHHELD_AFTER_RELEASED, S_PENDING, S_REJECTED,
    S_RECORD_REFUSED,
    S_ADVANCE, S_CHURN, S_N
};
static const char *STAT_NAMES[S_N] = {
    "verify", "committed", "replay_in_progress", "replay_terminal", "claim_replay", "cancelled", "lease_lost",
    "already_terminal", "allow_horizon_passed", "claim_only", "claim_only_created", "recover", "recovered", "lease_live", "not_found",
    "slow_owner", "late_finalize_fenced", "nonowner_refused", "publish", "ack", "ack_retry", "ack_order_refused",
    "fork", "release", "released_allow", "released_other", "withheld", "withheld_after_released", "pending",
    "rejected", "second_record_refused", "advance", "churn"};
static long stats[S_N];
static void bump_stat(int which) { __atomic_add_fetch(&stats[which], 1, __ATOMIC_RELAXED); }

/* ---- the shared store ------------------------------------------------------ */

static c_store S;
static RatifyV2PublicKey vk;
static uint8_t *seed_ed, *seed_ml;
static int64_t clock_cap;
static pthread_mutex_t store_mu = PTHREAD_MUTEX_INITIALIZER;
static void store_lock(void) { pthread_mutex_lock(&store_mu); }
static void store_unlock(void) { pthread_mutex_unlock(&store_mu); }

/* Per round challenge bookkeeping. */
typedef struct {
    int primary, alt; /* request indexes; alt is -1 without a second bundle */
    char claim_id[80];
    int created_lib; /* atomic: `created` dispositions the library reported */
    /* guarded by store_mu */
    int store_created, commits, source; /* source 1 finalize, 2 recover */
    uint8_t *snapshot;
    size_t snapshot_len;
    uint8_t *seen_terminal, *seen_body; /* what the owner submitted to finalize */
    size_t seen_terminal_len, seen_body_len;
    int64_t seen_allow;
    int has_seen;
    int thief_tried, recover_tried; /* atomic */
    /* guarded by obs_mu */
    char released_decision[32];
    /* guarded by pool_mu[i]; each handle by handle_mu[i][k] */
    RatifyV2Committed *h[MAX_HANDLES];
    int nh;
} claim_book;

static claim_book book[MAX_CH];
static int nch;
static int round_fork;
static int slow_open, slow_claim; /* atomic: stalled slow owners, and the last one's book */
static pthread_mutex_t pool_mu[MAX_CH], handle_mu[MAX_CH][MAX_HANDLES];
static pthread_mutex_t obs_mu = PTHREAD_MUTEX_INITIALIZER;
/* The first acknowledgement of each sequence (guarded by store_mu). */
static int ack_known[MAX_CLAIMS];
static uint8_t ack_digest[MAX_CLAIMS][48];
static int64_t ack_ts[MAX_CLAIMS];

static int book_of(const char *id) {
    for (int i = 0; i < nch; i++)
        if (strcmp(book[i].claim_id, id) == 0) return i;
    return -1;
}

static uint8_t *copy_slice(RatifyV2Slice s, size_t *len) {
    uint8_t *p = malloc(s.len + 1);
    if (s.len) memcpy(p, s.ptr, s.len);
    *len = s.len;
    return p;
}

/* ---- workers --------------------------------------------------------------- */

typedef struct {
    int id;
    uint64_t rng;
    pthread_t th;
    v2c_vector *vec[MAX_REQ];
    RatifyV2ClaimStoreCallbacks claim_cb;
    RatifyV2ReleaseStoreCallbacks rs;
    RatifyV2CheckpointCallbacks cp;
    RatifyV2ClockCallbacks clock;
    int slow;
    int rec_called, rec_rc;
    int32_t rec_outcome;
} worker;

static uint32_t rnd(worker *w) {
    w->rng ^= w->rng >> 12;
    w->rng ^= w->rng << 25;
    w->rng ^= w->rng >> 27;
    return (uint32_t)((w->rng * 2685821657736338717ULL) >> 32);
}

static void pause_us(long us) {
    struct timespec ts = {0, us * 1000};
    nanosleep(&ts, NULL);
}

/* Wait until another thread sets `flag`, at most about `max_us`. */
static void wait_flag(int *flag, long max_us) {
    for (long t = 0; t < max_us && !__atomic_load_n(flag, __ATOMIC_SEQ_CST); t += 50) pause_us(50);
}

/* ---- thread-safe store callbacks (one mutex around the C store) ---------- */

/* A commit the C store just made (store_mu held). */
static void note_commit(claim_book *k, claim_rec *r, int source) {
    if (++k->commits > 1) fail("claim %s committed a second terminal result", k->claim_id);
    if (!k->snapshot) {
        k->snapshot = copy_slice((RatifyV2Slice){r->body, r->body_len}, &k->snapshot_len);
        k->source = source;
    }
}

static int32_t w_now(void *user, int64_t *out) {
    (void)user;
    store_lock();
    int32_t rc = st_now(&S, out);
    store_unlock();
    return rc;
}

static int32_t w_claim(void *user, const RatifyV2ClaimView *view, RatifyV2ClaimResult *out) {
    (void)user;
    store_lock();
    int32_t rc = st_claim(&S, view, out);
    if (rc == 0 && out->disposition == RatifyV2DispositionCreated) {
        int b = book_of(view->claim_id);
        if (b < 0) fail("created a claim for an unknown claim ID %s", view->claim_id);
        else if (++book[b].store_created > 1) fail("the store created claim %s twice", view->claim_id);
    }
    store_unlock();
    return rc;
}

static int32_t w_finalize(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice terminal, RatifyV2Slice body,
                          int64_t allow_valid_until, int32_t *committed) {
    worker *w = user;
    int b = book_of(id);
    if (b < 0) { fail("finalize of an unknown claim ID %s", id); return RatifyV2StoreUnavailable; }
    claim_book *k = &book[b];
    store_lock();
    /* What the owner submits, for the non-owner attempts of op_nonowner. */
    free(k->seen_terminal);
    free(k->seen_body);
    k->seen_terminal = copy_slice(terminal, &k->seen_terminal_len);
    k->seen_body = copy_slice(body, &k->seen_body_len);
    k->seen_allow = allow_valid_until;
    k->has_seen = 1;
    claim_rec *r = find(&S, id);
    int64_t lease_end = r ? r->lease_expires_at : 0;
    store_unlock();
    if (w->slow) {
        /* A slow owner: let a non-owner try first, then stall past the lease
         * so recovery can race the late finalize. */
        bump_stat(S_SLOW);
        __atomic_store_n(&slow_claim, b, __ATOMIC_SEQ_CST);
        __atomic_add_fetch(&slow_open, 1, __ATOMIC_SEQ_CST);
        wait_flag(&k->thief_tried, 3000);
        store_lock();
        if (S.now < lease_end && lease_end <= clock_cap) S.now = lease_end;
        store_unlock();
        wait_flag(&k->recover_tried, 3000);
        __atomic_sub_fetch(&slow_open, 1, __ATOMIC_SEQ_CST);
    }
    store_lock();
    int expired = r && S.now >= lease_end;
    int32_t rc = st_finalize(&S, id, token, terminal, body, allow_valid_until, committed);
    int did = rc == 0 && *committed;
    if (did) note_commit(k, r, 1);
    if (did && expired) fail("a finalize at or after lease expiry committed claim %s", id);
    if (expired && !did) bump_stat(S_LATE_FENCED);
    store_unlock();
    return rc;
}

static int32_t w_progress(void *user, const char *id, RatifyV2Slice token, RatifyV2Slice progress) {
    (void)user;
    store_lock();
    int32_t rc = st_progress(&S, id, token, progress);
    store_unlock();
    return rc;
}

static int32_t w_load(void *user, const char *id, RatifyV2InterruptedClaim *out) {
    (void)user;
    store_lock();
    int32_t rc = st_load(&S, id, out);
    store_unlock();
    return rc;
}

static int32_t w_recover(void *user, const char *id, RatifyV2Slice terminal, RatifyV2Slice body, int32_t *committed) {
    (void)user;
    int b = book_of(id);
    if (b < 0) { fail("recovery of an unknown claim ID %s", id); return RatifyV2StoreUnavailable; }
    store_lock();
    claim_rec *r = find(&S, id);
    int live = r && !r->terminal && S.now < r->lease_expires_at;
    int32_t rc = st_recover(&S, id, terminal, body, committed);
    if (rc == 0 && *committed) {
        note_commit(&book[b], r, 2);
        if (live) fail("recovery committed claim %s inside its live lease", id);
    }
    store_unlock();
    return rc;
}

static int32_t w_load_terminal(void *user, const char *id, RatifyV2TerminalClaim *out) {
    (void)user;
    store_lock();
    int32_t rc = st_load_terminal(&S, id, out);
    store_unlock();
    return rc;
}

static int32_t w_record_release(void *user, const RatifyV2ReleaseRecord *rec) {
    worker *w = user;
    store_lock();
    claim_rec *r = find(&S, rec->claim_id);
    int had = r && r->has_release;
    int32_t rc = st_record_release(&S, rec);
    if (rc == 0 && !had && rec->outcome == RatifyV2ReleaseReleased) {
        outbox_entry *e = r && r->terminal && r->outbox_index >= 0 ? &S.outbox[r->outbox_index] : NULL;
        if (!e || !e->wire || !e->acked)
            fail("a release was recorded for %s without an acknowledged receipt", rec->claim_id);
        else if (!same(e->digest, 48, rec->entry_hash) || e->ack_ts != rec->ack_timestamp)
            fail("a release was recorded for %s with another entry or acknowledgement time", rec->claim_id);
    }
    w->rec_called++;
    w->rec_rc = rc;
    w->rec_outcome = rec->outcome;
    store_unlock();
    return rc;
}

static int32_t w_get_ack(void *user, const char *log_id, int64_t sequence, RatifyV2Acknowledgement *out) {
    store_lock();
    int32_t rc = st_get_ack(&S, log_id, sequence, out);
    (void)user;
    store_unlock();
    return rc;
}

/* The checkpoint's Acknowledge with the §7.8 checks (store_mu held). */
static int32_t ack_checked(int64_t seq, RatifyV2Slice previous, RatifyV2Slice entry, RatifyV2Acknowledgement *out) {
    int idx = (int)seq - 1;
    int valid = idx >= 0 && idx < S.noutbox;
    int was = valid && S.outbox[idx].acked, frozen = S.checkpoint_frozen;
    int32_t rc = st_acknowledge(&S, S.log_id, seq, previous, entry, out);
    if (rc != 0) return rc;
    if (!valid || out->sequence != seq || entry.len != 48) {
        fail("acknowledgement of sequence %lld answered another entry", (long long)seq);
    } else if (!was) {
        if (frozen) fail("sequence %lld was acknowledged after a fork froze the log", (long long)seq);
        if (idx > 0 && !S.outbox[idx - 1].acked) fail("sequence %lld was acknowledged before its predecessor", (long long)seq);
        if (idx > 0 && out->timestamp < ack_ts[idx - 1]) fail("sequence %lld acknowledged before its predecessor's time", (long long)seq);
        ack_known[idx] = 1;
        memcpy(ack_digest[idx], entry.ptr, 48);
        ack_ts[idx] = out->timestamp;
    } else if (!ack_known[idx] || out->entry_hash.len != 48 || memcmp(ack_digest[idx], out->entry_hash.ptr, 48) != 0 ||
               out->timestamp != ack_ts[idx]) {
        fail("the acknowledgement of sequence %lld changed", (long long)seq);
    }
    return rc;
}

static int32_t w_acknowledge(void *user, const char *log_id, int64_t sequence, RatifyV2Slice previous, RatifyV2Slice entry,
                             RatifyV2Acknowledgement *out) {
    (void)user;
    store_lock();
    int32_t rc = strcmp(log_id, S.log_id) == 0 ? ack_checked(sequence, previous, entry, out) : RatifyV2StoreUnavailable;
    store_unlock();
    return rc;
}

static void worker_init(worker *w, int id, uint64_t seed) {
    memset(w, 0, sizeof *w);
    w->id = id;
    w->rng = seed * 0x9E3779B97F4A7C15ULL + (uint64_t)id * 0xD1B54A32D192ED03ULL + 1;
    RatifyV2ClaimStoreCallbacks c = {w, 0, w_now, w_claim, w_finalize, w_progress, w_load, w_recover};
    RatifyV2ReleaseStoreCallbacks rs = {w, w_now, w_load_terminal, w_record_release};
    RatifyV2CheckpointCallbacks cp = {w, w_acknowledge, w_get_ack};
    RatifyV2ClockCallbacks clock = {w, w_now};
    w->claim_cb = c;
    w->rs = rs;
    w->cp = cp;
    w->clock = clock;
    for (int i = 0; i < nreq; i++) w->vec[i] = v2c_vector_load(reqs[i].dir);
}

/* ---- operations -------------------------------------------------------------- */

static void pool_add(int b, RatifyV2Committed *c) {
    pthread_mutex_lock(&pool_mu[b]);
    if (book[b].nh < MAX_HANDLES) {
        book[b].h[book[b].nh++] = c;
        c = NULL;
    }
    pthread_mutex_unlock(&pool_mu[b]);
    ratify_v2_committed_free(c); /* churn: a full pool frees at once */
}

/* A pooled handle, locked for this thread's exclusive use, or -1. */
static int pool_take(worker *w, int b) {
    pthread_mutex_lock(&pool_mu[b]);
    int n = book[b].nh;
    pthread_mutex_unlock(&pool_mu[b]);
    if (n == 0) return -1;
    int k = (int)(rnd(w) % (uint32_t)n);
    pthread_mutex_lock(&handle_mu[b][k]);
    return k;
}

static void op_verify(worker *w, int b, int use_alt) {
    claim_book *k = &book[b];
    int ri = use_alt && k->alt >= 0 ? k->alt : k->primary;
    uint32_t mode = rnd(w) % 24;
    int cancel = mode < 3, slow = mode >= 3 && mode < 6;
    v2c_vector *v = w->vec[ri];
    RatifyV2VerifyCallbacks cb;
    RatifyV2EvaluatorConfig eval;
    int has_eval;
    v2c_vector_callbacks(v, &w->claim_cb, cancel, &cb, &eval, &has_eval);
    size_t blen, rlen;
    const uint8_t *bundle = v2c_vector_bundle(v, &blen);
    const char *req = v2c_vector_request(v, &rlen);
    RatifyV2VerifyOutcome out = {0, 0, 0};
    RatifyV2Committed *c = NULL;
    w->slow = slow;
    int32_t rc = ratify_v2_verify_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, has_eval ? &eval : NULL, &cb, &out,
                                               NULL, &c);
    w->slow = 0;
    bump_stat(S_VERIFY);
    if (rc != 0) { fail("verify %s: call failed %s", reqs[ri].name, v2c_class(rc)); return; }
    if (out.disposition == RatifyV2DispositionCreated) __atomic_add_fetch(&k->created_lib, 1, __ATOMIC_SEQ_CST);
    if ((out.stage == RatifyV2StageCommitted) != (c != NULL))
        fail("verify %s: stage %d with committed handle %p", reqs[ri].name, (int)out.stage, (void *)c);
    switch (out.stage) {
    case RatifyV2StageCommitted:
        bump_stat(S_COMMITTED);
        if (out.disposition != RatifyV2DispositionCreated) fail("verify %s: committed without creating the claim", reqs[ri].name);
        if (c) {
            char *id = NULL;
            ratify_v2_committed_claim_id(c, &id);
            if (!id || strcmp(id, k->claim_id) != 0) fail("verify %s: committed another claim", reqs[ri].name);
            ratify_v2_string_free(id);
            pool_add(b, c);
        }
        break;
    case RatifyV2StageReplay:
        if (out.disposition == RatifyV2DispositionInProgress) bump_stat(S_REPLAY_PROGRESS);
        else if (out.disposition == RatifyV2DispositionTerminalReplay) bump_stat(S_REPLAY_TERMINAL);
        else if (out.stage == conflict_stage && out.error_code == conflict_class) bump_stat(S_CONFLICT);
        else fail("verify %s: replay with disposition %d (%s)", reqs[ri].name, (int)out.disposition, v2c_class(out.error_code));
        break;
    case RatifyV2StageEvaluating:
        if (out.disposition != RatifyV2DispositionCreated)
            fail("verify %s: evaluating without creating the claim", reqs[ri].name);
        if (cancel && out.error_code == RatifyV2EvaluationCancelled) bump_stat(S_CANCELLED);
        else if (out.error_code == RatifyV2ClaimLeaseLost) bump_stat(S_LEASE_LOST);
        else if (out.error_code == RatifyV2ClaimAlreadyTerminal) bump_stat(S_ALREADY_TERMINAL);
        /* The store refuses an allow at or past its horizon; the claim stays
         * evaluating for recovery (SPEC-v2 §7.5). */
        else if (out.error_code == RatifyV2AllowHorizonPassed && reqs[ri].allow) bump_stat(S_HORIZON);
        else fail("verify %s: evaluating outcome %s (cancel %d, slow %d)", reqs[ri].name, v2c_class(out.error_code), cancel, slow);
        break;
    default:
        if (out.stage == conflict_stage && out.error_code == conflict_class) bump_stat(S_CONFLICT);
        else fail("verify %s: stage %d class %s", reqs[ri].name, (int)out.stage, v2c_class(out.error_code));
    }
}

static void op_claim_only(worker *w, int b, int use_alt) {
    claim_book *k = &book[b];
    int ri = use_alt && k->alt >= 0 ? k->alt : k->primary;
    if (!reqs[ri].claim_only) return;
    v2c_vector *v = w->vec[ri];
    size_t blen, rlen;
    const uint8_t *bundle = v2c_vector_bundle(v, &blen);
    const char *req = v2c_vector_request(v, &rlen);
    int32_t disposition = 0;
    char *id = NULL;
    int32_t rc = ratify_v2_claim_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, &w->claim_cb, &disposition, &id);
    bump_stat(S_CLAIM_ONLY);
    if (rc == 0) {
        if (!id || strcmp(id, k->claim_id) != 0) fail("claim-only %s: another claim ID", reqs[ri].name);
        if (disposition == RatifyV2DispositionCreated) {
            __atomic_add_fetch(&k->created_lib, 1, __ATOMIC_SEQ_CST);
            bump_stat(S_CLAIM_ONLY_CREATED);
        } else if (disposition != RatifyV2DispositionInProgress && disposition != RatifyV2DispositionTerminalReplay) {
            fail("claim-only %s: disposition %d", reqs[ri].name, (int)disposition);
        }
    } else if (rc == conflict_claim_rc) {
        bump_stat(S_CONFLICT);
    } else {
        fail("claim-only %s: %s (%s)", reqs[ri].name, v2c_class(rc), ratify_v2_last_error_message());
    }
    ratify_v2_string_free(id);
}

static void op_recover(worker *w, int b) {
    claim_book *k = &book[b];
    RatifyV2Committed *c = NULL;
    int32_t rc = ratify_v2_recover_interrupted_claim(&w->claim_cb, k->claim_id, &c);
    __atomic_store_n(&k->recover_tried, 1, __ATOMIC_SEQ_CST);
    bump_stat(S_RECOVER);
    if (rc == 0) {
        bump_stat(S_RECOVERED);
        if (!c) { fail("recovery of %s returned no handle", k->claim_id); return; }
        RatifyV2Buffer body = {0};
        ratify_v2_committed_receipt_body(c, &body);
        uint8_t *text = v2c_take(body, NULL);
        if (!strstr((char *)text, "\"decision_reason\":\"evaluation_interrupted\""))
            fail("recovery of %s committed another result", k->claim_id);
        free(text);
        store_lock();
        int source = k->source;
        store_unlock();
        if (source != 2) fail("recovery of %s returned a handle for a finalized claim", k->claim_id);
        pool_add(b, c);
        return;
    }
    if (c) fail("recovery of %s failed with a handle", k->claim_id);
    if (rc == RatifyV2ClaimLeaseLive) bump_stat(S_LEASE_LIVE);
    else if (rc == RatifyV2ClaimNotFound) bump_stat(S_NOT_FOUND);
    else if (rc == RatifyV2ClaimAlreadyTerminal) bump_stat(S_ALREADY_TERMINAL);
    else fail("recovery of %s: %s (%s)", k->claim_id, v2c_class(rc), ratify_v2_last_error_message());
}

static void op_nonowner(worker *w, int b) {
    claim_book *k = &book[b];
    uint8_t token[32];
    for (size_t i = 0; i < sizeof token; i++) token[i] = (uint8_t)rnd(w);
    store_lock();
    if (k->has_seen) {
        RatifyV2Slice t = {token, sizeof token}, term = {k->seen_terminal, k->seen_terminal_len},
                      body = {k->seen_body, k->seen_body_len};
        int32_t committed = 0;
        int32_t rc = st_finalize(&S, k->claim_id, t, term, body, k->seen_allow, &committed);
        if (rc == 0 && committed) fail("a non-owner finalize committed claim %s", k->claim_id);
        else bump_stat(S_NONOWNER_REFUSED);
    }
    store_unlock();
    __atomic_store_n(&k->thief_tried, 1, __ATOMIC_SEQ_CST);
}

/* Sign the outbox entry at index i at its log position, as publish() of
 * v2_lifecycle.c does, without acknowledging it (store_mu held). */
static void sign_entry(int i) {
    outbox_entry *e = &S.outbox[i];
    claim_rec *r = &S.claims[e->claim];
    char head[8192], acc[6000] = "";
    for (int j = 0; j < i; j++) {
        char *d = v2c_b64(S.outbox[j].digest, 48);
        char item[256];
        snprintf(item, sizeof item, "%s\"%d\":\"%s\"", j ? "," : "", j + 1, d);
        strcat(acc, item);
        free(d);
    }
    uint8_t zero[48] = {0};
    char *prev = v2c_b64(i ? S.outbox[i - 1].digest : zero, 48);
    snprintf(head, sizeof head,
             "{\"log_id\":\"%s\",\"verifier_id\":\"%s\",\"sequence\":%d,\"head_hash_b64\":\"%s\","
             "\"accepted_digests_b64\":{%s},\"frozen\":false}",
             S.log_id, S.verifier_id, i, prev, acc);
    free(prev);
    RatifyV2Buffer out = {0};
    int32_t rc = ratify_v2_sign_prepared_verification_receipt(r->body, r->body_len, (const uint8_t *)head, strlen(head),
                                                               S.verifier, NULL, &out);
    if (rc != 0) { fail("publish sign: %s", ratify_v2_last_error_message()); ratify_v2_buffer_free(out); return; }
    e->wire = v2c_take(out, &e->wire_len);
    RatifyV2Buffer d = {0};
    rc = ratify_v2_object_body_digest(RatifyV2KindVerificationReceipt, e->wire, e->wire_len, &d);
    size_t dl;
    uint8_t *digest = v2c_take(d, &dl);
    if (rc != 0 || dl != 48) fail("publish digest: %s", ratify_v2_last_error_message());
    else memcpy(e->digest, digest, 48);
    free(digest);
}

static void op_publish(void) {
    store_lock();
    int i = 0;
    while (i < S.noutbox && S.outbox[i].wire) i++;
    if (i < S.noutbox) {
        sign_entry(i);
        bump_stat(S_PUBLISH);
    }
    store_unlock();
}

static void op_ack(worker *w) {
    store_lock();
    int i = 0;
    while (i < S.noutbox && S.outbox[i].acked) i++;
    if (i < S.noutbox && S.outbox[i].wire) {
        static const uint8_t zero[48] = {0};
        RatifyV2Acknowledgement ack;
        int frozen = S.checkpoint_frozen;
        if (rnd(w) % 6 == 0 && i + 1 < S.noutbox && S.outbox[i + 1].wire) {
            /* Out of order: the next entry before this one is refused, and a
             * refusal that is not a fork does not freeze the log. */
            RatifyV2Slice prev = {S.outbox[i].digest, 48}, entry = {S.outbox[i + 1].digest, 48};
            int32_t rc = ack_checked(i + 2, prev, entry, &ack);
            if (rc == 0 || S.outbox[i + 1].acked) fail("sequence %d was acknowledged out of order", i + 2);
            else if (S.checkpoint_frozen != frozen) fail("an out-of-order refusal froze the log");
            else bump_stat(S_ACK_ORDER_REFUSED);
        }
        RatifyV2Slice prev = {i ? S.outbox[i - 1].digest : zero, 48}, entry = {S.outbox[i].digest, 48};
        int32_t rc = ack_checked(i + 1, prev, entry, &ack);
        if (rc == 0) bump_stat(S_ACK);
        else if (!S.checkpoint_frozen) fail("the next sequence %d was refused: %s", i + 1, v2c_class(rc));
    }
    store_unlock();
}

static void op_ack_retry(worker *w, int fork) {
    store_lock();
    int n = 0;
    while (n < S.noutbox && S.outbox[n].acked) n++;
    if (n > 0) {
        static const uint8_t zero[48] = {0};
        int i = (int)(rnd(w) % (uint32_t)n);
        RatifyV2Acknowledgement ack;
        RatifyV2Slice prev = {i ? S.outbox[i - 1].digest : zero, 48}, entry = {S.outbox[i].digest, 48};
        if (fork) {
            /* A different entry at an acknowledged sequence is a fork: refused,
             * and the log acknowledges nothing new afterwards. */
            uint8_t other[48];
            memcpy(other, S.outbox[i].digest, 48);
            other[0] ^= 1;
            RatifyV2Slice forked = {other, 48};
            int32_t rc = ack_checked(i + 1, prev, forked, &ack);
            if (rc == 0 || !S.checkpoint_frozen) fail("a fork at sequence %d was not refused and frozen", i + 1);
            else bump_stat(S_FORK);
        } else {
            int32_t rc = ack_checked(i + 1, prev, entry, &ack);
            if (rc != 0) fail("an identical acknowledgement retry of sequence %d was refused", i + 1);
            else bump_stat(S_ACK_RETRY);
        }
    }
    store_unlock();
}

static void op_advance(worker *w) {
    store_lock();
    int64_t t = S.now + 1 + (int64_t)(rnd(w) % (uint32_t)S.lease);
    if (t > clock_cap) t = clock_cap;
    if (t > S.now) S.now = t;
    store_unlock();
    bump_stat(S_ADVANCE);
}

/* A direct record_release with the other outcome for a claim that already
 * has a release record: the first record wins, so it is refused and the
 * stored record does not change (SPEC-v2 §6.9). */
static void conflicting_record(claim_book *k) {
    store_lock();
    claim_rec *r = find(&S, k->claim_id);
    if (r && r->has_release) {
        int32_t outcome = r->release_outcome;
        char reason[64];
        snprintf(reason, sizeof reason, "%s", r->release_reason);
        int64_t ts = r->release_ts;
        uint8_t hash[64];
        memcpy(hash, r->release_hash, sizeof hash);
        int released = outcome == RatifyV2ReleaseReleased;
        RatifyV2ReleaseRecord other = {r->claim_id, {hash, r->release_hash_len}, ts,
                                       released ? RatifyV2ReleaseWithheld : RatifyV2ReleaseReleased,
                                       released ? "allow_horizon_passed" : ""};
        int32_t rc = st_record_release(&S, &other);
        if (rc != RatifyV2StoreReleaseStateMismatch || r->release_outcome != outcome ||
            strcmp(r->release_reason, reason) != 0 || r->release_ts != ts)
            fail("a second, different release record for %s was not refused", k->claim_id);
        else bump_stat(S_RECORD_REFUSED);
    }
    store_unlock();
}

static void op_release(worker *w, int b) {
    claim_book *k = &book[b];
    int h = pool_take(w, b);
    if (h < 0) return;
    RatifyV2Committed *c = k->h[h];
    store_lock();
    claim_rec *r = find(&S, k->claim_id);
    const uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (r && r->terminal && r->outbox_index >= 0) {
        wire = S.outbox[r->outbox_index].wire;
        wire_len = S.outbox[r->outbox_index].wire_len;
    }
    store_unlock();
    if (rnd(w) % 5 == 0) { wire = NULL; wire_len = 0; }
    int32_t status = 0;
    char *reason = NULL;
    RatifyV2Released *d = NULL;
    w->rec_called = 0;
    int32_t rc = ratify_v2_release_decision(c, (RatifyV2Slice){wire, wire_len}, &vk, S.log_id, &w->rs, &w->cp, &status,
                                            &reason, &d);
    bump_stat(S_RELEASE);
    if (rc != 0) fail("release of %s: call failed %s", k->claim_id, v2c_class(rc));
    if ((status == RatifyV2ReleaseReleased) != (d != NULL)) fail("release of %s: status %d with handle %p", k->claim_id, (int)status, (void *)d);
    store_lock();
    int recorded = r && r->has_release ? r->release_outcome : 0;
    char recorded_reason[64];
    snprintf(recorded_reason, sizeof recorded_reason, "%s", r && r->has_release ? r->release_reason : "");
    int acked = r && r->terminal && r->outbox_index >= 0 && S.outbox[r->outbox_index].acked;
    int allow_body = r && r->terminal && body_has((RatifyV2Slice){r->body, r->body_len}, "\"decision\":\"allow\"");
    int source = k->source;
    store_unlock();
    if (status == RatifyV2ReleaseReleased && d) {
        char *decision = NULL;
        ratify_v2_released_string(d, RatifyV2ReleasedDecision, &decision);
        int allow = decision && strcmp(decision, "allow") == 0;
        bump_stat(allow ? S_RELEASED_ALLOW : S_RELEASED_OTHER);
        if (recorded != RatifyV2ReleaseReleased) fail("released %s without a released record (%d)", k->claim_id, recorded);
        if (w->rec_called && (w->rec_rc != 0 || w->rec_outcome != RatifyV2ReleaseReleased))
            fail("released %s although recording the release failed", k->claim_id);
        if (!wire) fail("released %s without a signed receipt", k->claim_id);
        if (!acked) fail("released %s before its receipt was acknowledged", k->claim_id);
        if (allow && (!allow_body || source != 1)) fail("released an allow for %s, which is not a finalized allow", k->claim_id);
        RatifyV2Buffer rb = {0};
        ratify_v2_released_receipt(d, &rb);
        size_t rlen;
        uint8_t *receipt = v2c_take(rb, &rlen);
        if (!wire || rlen != wire_len || memcmp(receipt, wire, rlen) != 0) fail("released %s with another receipt", k->claim_id);
        free(receipt);
        if (ratify_v2_released_allowed(d, &w->clock) && !allow) fail("a released non-allow for %s is allowed", k->claim_id);
        pthread_mutex_lock(&obs_mu);
        if (!k->released_decision[0]) snprintf(k->released_decision, sizeof k->released_decision, "%s", decision ? decision : "?");
        else if (!decision || strcmp(k->released_decision, decision) != 0) fail("claim %s released two decisions", k->claim_id);
        pthread_mutex_unlock(&obs_mu);
        ratify_v2_string_free(decision);
    } else if (status == RatifyV2ReleaseWithheld) {
        bump_stat(S_WITHHELD);
        /* With a monotonic clock capped before challenge expiry, the only
         * reason to withhold is a passed allow horizon. */
        if (!reason || strcmp(reason, "allow_horizon_passed") != 0 || !allow_body)
            fail("release of %s withheld: %s", k->claim_id, reason ? reason : "(null)");
        if (recorded == RatifyV2ReleaseWithheld && strcmp(recorded_reason, reason ? reason : "") != 0)
            fail("release of %s withheld with %s, recorded %s", k->claim_id, reason ? reason : "", recorded_reason);
        if (recorded == RatifyV2ReleaseReleased) bump_stat(S_WITHHELD_AFTER_RELEASED);
    } else if (status == RatifyV2ReleasePending) {
        bump_stat(S_PENDING);
    } else {
        bump_stat(S_REJECTED);
        fail("release of %s: %s %s", k->claim_id, ratify_v2_release_status_str(status), reason ? reason : "");
    }
    ratify_v2_string_free(reason);
    ratify_v2_released_free(d);
    pthread_mutex_unlock(&handle_mu[b][h]);
    conflicting_record(k);
}

/* Handle create/free churn: accessor copies of a shared committed handle,
 * reducer and key pair handles, and allocated strings. */
static void op_churn(worker *w, int b) {
    bump_stat(S_CHURN);
    switch (rnd(w) % 4) {
    case 0: {
        int h = pool_take(w, b);
        if (h < 0) return;
        RatifyV2Committed *c = book[b].h[h];
        char *id = NULL, *digest = NULL;
        RatifyV2Buffer body = {0};
        int64_t expires = 0, horizon = 0;
        int32_t has = 0;
        int ok = ratify_v2_committed_claim_id(c, &id) == 0 && ratify_v2_committed_receipt_body(c, &body) == 0 &&
                 ratify_v2_committed_receipt_body_digest(c, &digest) == 0 &&
                 ratify_v2_committed_challenge_expires_at(c, &expires) == 0 &&
                 ratify_v2_committed_allow_horizon(c, &has, &horizon) == 0;
        if (!ok || strcmp(id, book[b].claim_id) != 0) fail("committed accessors of %s", book[b].claim_id);
        ratify_v2_string_free(id);
        ratify_v2_string_free(digest);
        ratify_v2_buffer_free(body);
        pthread_mutex_unlock(&handle_mu[b][h]);
        break;
    }
    case 1: {
        RatifyV2StatusState *st = NULL;
        if (ratify_v2_status_state_new(&st) != 0) fail("status_state_new");
        RatifyV2Buffer json = {0};
        if (st && ratify_v2_status_state_json(st, &json) != 0) fail("status_state_json");
        ratify_v2_buffer_free(json);
        ratify_v2_status_state_free(st);
        break;
    }
    case 2: {
        RatifyV2KeyPair *kp = NULL;
        char id[RATIFY_V2_KEY_ID_BUF_LEN];
        if (ratify_v2_keypair_from_seeds(seed_ed, seed_ml, &kp) != 0 || ratify_v2_keypair_key_id(kp, id, sizeof id) != 0 ||
            strcmp(id, S.verifier_id) != 0)
            fail("keypair churn");
        ratify_v2_keypair_free(kp);
        break;
    }
    default: {
        char *json = NULL;
        if (ratify_v2_public_key_to_json(&vk, &json) != 0) fail("public_key_to_json");
        ratify_v2_string_free(json);
        break;
    }
    }
}

/* ---- rounds -------------------------------------------------------------------- */

static int opt_threads = 8, opt_ops = 12, opt_ch = 4;
static long opt_rounds = 0, opt_seconds = 40;
static uint64_t opt_seed = 1;
static int stop;
static barrier_t bar;
static worker workers[MAX_THREADS];
static uint64_t round_rng;
static struct timespec t_start;

static double elapsed(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)(t.tv_sec - t_start.tv_sec) + (double)(t.tv_nsec - t_start.tv_nsec) / 1e9;
}

static void reset_round(int64_t now) {
    reset_store(&S);
    S.now = S.high_water = now;
    memset(ack_known, 0, sizeof ack_known);
    memset(ack_ts, 0, sizeof ack_ts);
}

static void setup_round(long r) {
    round_no = (int)r;
    worker tmp;
    tmp.rng = round_rng;
    int chosen[MAX_REQ] = {0};
    nch = opt_ch < ngroups ? opt_ch : ngroups;
    for (int i = 0; i < nch; i++) {
        int g;
        do g = (int)(rnd(&tmp) % (uint32_t)ngroups); while (chosen[g]);
        chosen[g] = 1;
        claim_book *k = &book[i];
        memset(k, 0, sizeof *k);
        k->primary = groups[g].req[rnd(&tmp) % (uint32_t)groups[g].n];
        k->alt = -1;
        for (int j = 0; j < groups[g].n; j++)
            if (groups[g].req[j] != k->primary) k->alt = groups[g].req[j];
        snprintf(k->claim_id, sizeof k->claim_id, "%s", reqs[k->primary].claim_id);
    }
    round_fork = rnd(&tmp) % 16 == 0;
    round_rng = tmp.rng;
    reset_round(reqs[0].now);
}

/* End-of-round invariants, single-threaded. */
static void check_round(void) {
    for (int b = 0; b < nch; b++) {
        claim_book *k = &book[b];
        claim_rec *r = find(&S, k->claim_id);
        int exists = r != NULL;
        if (k->store_created != exists || k->created_lib != exists)
            fail("claim %s: %d store creations, %d created dispositions, exists %d", k->claim_id, k->store_created,
                 k->created_lib, exists);
        if (k->commits > 1 || (r && r->terminal != (k->commits == 1)))
            fail("claim %s: %d commits, terminal %d", k->claim_id, k->commits, r ? r->terminal : -1);
        if (r && r->terminal && (!k->snapshot || !same(k->snapshot, k->snapshot_len, (RatifyV2Slice){r->body, r->body_len})))
            fail("claim %s: the terminal body changed after commit", k->claim_id);
        if (r && r->has_release && r->release_outcome == RatifyV2ReleaseReleased &&
            (!r->terminal || !S.outbox[r->outbox_index].acked))
            fail("claim %s: a release record without an acknowledged receipt", k->claim_id);
        for (int h = 0; h < k->nh; h++) {
            RatifyV2Buffer body = {0};
            ratify_v2_committed_receipt_body(k->h[h], &body);
            size_t n;
            uint8_t *got = v2c_take(body, &n);
            if (!r || !r->terminal || !same(got, n, (RatifyV2Slice){r->body, r->body_len}))
                fail("claim %s: a committed handle differs from the stored result", k->claim_id);
            free(got);
            ratify_v2_committed_free(k->h[h]);
            k->h[h] = NULL;
        }
        k->nh = 0;
        free(k->snapshot);
        free(k->seen_terminal);
        free(k->seen_body);
        k->snapshot = k->seen_terminal = k->seen_body = NULL;
    }
    /* The acknowledged entries are a prefix of the log, each the entry the
     * publisher signed, unchanged, in time order. */
    int prefix = 1;
    for (int i = 0; i < S.noutbox; i++) {
        outbox_entry *e = &S.outbox[i];
        if (e->acked && !prefix) fail("sequence %d acknowledged after a gap", i + 1);
        if (!e->acked) { prefix = 0; continue; }
        if (!e->wire || !ack_known[i] || memcmp(ack_digest[i], e->digest, 48) != 0 || ack_ts[i] != e->ack_ts)
            fail("sequence %d: the acknowledgement differs from the first one", i + 1);
        if (i > 0 && e->ack_ts < S.outbox[i - 1].ack_ts) fail("sequence %d acknowledged before its predecessor", i + 1);
        RatifyV2Acknowledgement a;
        if (st_get_ack(&S, S.log_id, i + 1, &a) != 0 || a.timestamp != ack_ts[i] || !same(ack_digest[i], 48, a.entry_hash))
            fail("sequence %d: GetAcknowledgement differs", i + 1);
    }
}

static void *run_worker(void *arg) {
    worker *w = arg;
    for (;;) {
        if (w->id == 0) {
            long r = round_no + 1;
            if ((opt_rounds && r > opt_rounds) || (opt_seconds && elapsed() >= (double)opt_seconds)) stop = 1;
            else setup_round(r);
        }
        barrier_wait(&bar);
        if (stop) break;
        for (int n = 0; n < opt_ops; n++) {
            int b = (int)(rnd(w) % (uint32_t)nch);
            uint32_t op = rnd(w) % 100;
            if (__atomic_load_n(&slow_open, __ATOMIC_SEQ_CST) > 0 && rnd(w) % 2) {
                /* A slow owner is stalled: race it. */
                b = __atomic_load_n(&slow_claim, __ATOMIC_SEQ_CST);
                if (op % 2) op_nonowner(w, b);
                else op_recover(w, b);
                continue;
            }
            if (op < 24) op_verify(w, b, 0);
            else if (op < 28) op_claim_only(w, b, 0);
            else if (op < 32) op_verify(w, b, 1);
            else if (op < 34) op_claim_only(w, b, 1);
            else if (op < 44) op_recover(w, b);
            else if (op < 49) op_advance(w);
            else if (op < 58) op_publish();
            else if (op < 67) op_ack(w);
            else if (op < 70) op_ack_retry(w, round_fork && rnd(w) % 4 == 0);
            else if (op < 89) op_release(w, b);
            else if (op < 93) op_nonowner(w, b);
            else op_churn(w, b);
        }
        barrier_wait(&bar);
        if (w->id == 0) check_round();
    }
    return NULL;
}

/* ---- calibration ----------------------------------------------------------------- */

static void single_book(const char *claim_id, int ri) {
    nch = 1;
    memset(&book[0], 0, sizeof book[0]);
    book[0].primary = ri;
    book[0].alt = -1;
    snprintf(book[0].claim_id, sizeof book[0].claim_id, "%s", claim_id);
}

static void drop_book(void) {
    for (int h = 0; h < book[0].nh; h++) ratify_v2_committed_free(book[0].h[h]);
    free(book[0].snapshot);
    free(book[0].seen_terminal);
    free(book[0].seen_body);
    memset(&book[0], 0, sizeof book[0]);
}

static int calibrate_verify(worker *w, int ri, RatifyV2VerifyOutcome *out, RatifyV2Committed **c) {
    RatifyV2VerifyCallbacks cb;
    RatifyV2EvaluatorConfig eval;
    int has_eval;
    v2c_vector *v = w->vec[ri];
    v2c_vector_callbacks(v, &w->claim_cb, 0, &cb, &eval, &has_eval);
    size_t blen, rlen;
    const uint8_t *bundle = v2c_vector_bundle(v, &blen);
    const char *req = v2c_vector_request(v, &rlen);
    *c = NULL;
    return ratify_v2_verify_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, has_eval ? &eval : NULL, &cb, out, NULL, c);
}

/* Keep the lifecycle requests that commit in a fresh store, repeatably, and
 * group them by claim ID (requests sharing a challenge with another bundle
 * are the conflicting proofs of one challenge). */
static void calibrate(worker *w) {
    int keep[MAX_REQ], nkeep = 0;
    for (int i = 0; i < nreq; i++) {
        req_info *q = &reqs[i];
        v2c_vector *v = w->vec[i];
        q->now = strtoll(v2c_vector_meta(v, "now"), NULL, 10);
        const char *cf = v2c_vector_meta(v, "challenge_file");
        if (!cf[0]) continue;
        size_t clen;
        uint8_t *challenge = v2c_read(cf, &clen);
        const char *ns = v2c_vector_meta(v, "namespace");
        char *id = NULL;
        ratify_v2_claim_id((const uint8_t *)ns, strlen(ns), strtoll(v2c_vector_meta(v, "replay_epoch"), NULL, 10), challenge,
                           clen, &id);
        free(challenge);
        snprintf(q->claim_id, sizeof q->claim_id, "%s", id ? id : "");
        ratify_v2_string_free(id);
        int ok = 1;
        for (int rep = 0; rep < 3 && ok; rep++) {
            single_book(q->claim_id, i);
            reset_round(q->now);
            RatifyV2VerifyOutcome out;
            RatifyV2Committed *c = NULL;
            int32_t rc = calibrate_verify(w, i, &out, &c);
            ok = rc == 0 && out.stage == RatifyV2StageCommitted && c;
            if (ok && rep == 0) {
                RatifyV2Buffer body = {0};
                ratify_v2_committed_receipt_body(c, &body);
                q->allow = body_has((RatifyV2Slice){body.ptr, body.len}, "\"decision\":\"allow\"");
                ratify_v2_buffer_free(body);
                int32_t has = 0;
                ratify_v2_committed_challenge_expires_at(c, &q->expires);
                ratify_v2_committed_allow_horizon(c, &has, &q->horizon);
            }
            ratify_v2_committed_free(c);
            drop_book();
        }
        if (!ok || q->now != reqs[0].now) continue;
        /* Claim-only on a fresh store. */
        single_book(q->claim_id, i);
        reset_round(q->now);
        size_t blen, rlen;
        const uint8_t *bundle = v2c_vector_bundle(v, &blen);
        const char *req = v2c_vector_request(v, &rlen);
        int32_t disposition = 0;
        char *cid = NULL;
        q->claim_only = ratify_v2_claim_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, &w->claim_cb, &disposition,
                                                     &cid) == 0 &&
                        disposition == RatifyV2DispositionCreated;
        ratify_v2_string_free(cid);
        drop_book();
        keep[nkeep++] = i;
    }
    /* Compact to the kept requests and group them. */
    req_info kept[MAX_REQ];
    for (int i = 0; i < nkeep; i++) kept[i] = reqs[keep[i]];
    v2c_vector *vecs[MAX_THREADS][MAX_REQ];
    for (int t = 0; t < opt_threads; t++) {
        for (int i = 0; i < nreq; i++) vecs[t][i] = workers[t].vec[i];
        for (int i = 0; i < nreq; i++) {
            int used = 0;
            for (int j = 0; j < nkeep; j++) used |= keep[j] == i;
            if (!used) v2c_vector_free(vecs[t][i]);
        }
        for (int i = 0; i < nkeep; i++) workers[t].vec[i] = vecs[t][keep[i]];
    }
    nreq = nkeep;
    for (int i = 0; i < nreq; i++) reqs[i] = kept[i];
    ngroups = 0;
    clock_cap = INT64_MAX;
    for (int i = 0; i < nreq; i++) {
        int g = 0;
        while (g < ngroups && strcmp(reqs[groups[g].req[0]].claim_id, reqs[i].claim_id) != 0) g++;
        if (g == ngroups) groups[ngroups++].n = 0;
        if (groups[g].n < 4) groups[g].req[groups[g].n++] = i;
        reqs[i].group = g;
        if (reqs[i].expires - 1 < clock_cap) clock_cap = reqs[i].expires - 1;
    }
    /* A second bundle for a claimed challenge. */
    conflict_stage = conflict_class = conflict_claim_rc = -100;
    for (int g = 0; g < ngroups && conflict_stage == -100; g++) {
        if (groups[g].n < 2) continue;
        int a = groups[g].req[0], o = groups[g].req[1];
        single_book(reqs[a].claim_id, a);
        reset_round(reqs[a].now);
        RatifyV2VerifyOutcome out;
        RatifyV2Committed *c = NULL;
        calibrate_verify(w, a, &out, &c);
        ratify_v2_committed_free(c);
        RatifyV2Committed *c2 = NULL;
        int32_t rc = calibrate_verify(w, o, &out, &c2);
        if (rc == 0 && !c2 && out.error_code != 0) {
            conflict_stage = out.stage;
            conflict_class = out.error_code;
        }
        ratify_v2_committed_free(c2);
        if (reqs[o].claim_only) {
            size_t blen, rlen;
            const uint8_t *bundle = v2c_vector_bundle(w->vec[o], &blen);
            const char *req = v2c_vector_request(w->vec[o], &rlen);
            int32_t disposition = 0;
            char *cid = NULL;
            conflict_claim_rc = ratify_v2_claim_proof_bundle(bundle, blen, (const uint8_t *)req, rlen, &w->claim_cb,
                                                             &disposition, &cid);
            ratify_v2_string_free(cid);
        }
        drop_book();
    }
    nch = 0;
    printf("requests: %d committing (%d groups):", nreq, ngroups);
    for (int i = 0; i < nreq; i++)
        if (reqs[i].allow) printf(" %s(allow, horizon now+%lld)", reqs[i].name, (long long)(reqs[i].horizon - reqs[i].now));
        else printf(" %s", reqs[i].name);
    printf("\nsecond bundle for a claimed challenge: stage %d %s, claim-only %s; clock cap now+%lld, lease %lld\n",
           (int)conflict_stage, conflict_class == -100 ? "-" : v2c_class(conflict_class),
           conflict_claim_rc == -100 ? "-" : v2c_class(conflict_claim_rc), (long long)(clock_cap - reqs[0].now),
           (long long)S.lease);
    if (nreq == 0 || ngroups < 2) { fprintf(stderr, "too few committing lifecycle requests\n"); exit(1); }
}

/* ---- main ---------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    int ch;
    while ((ch = getopt(argc, argv, "t:r:d:o:c:s:")) != -1) {
        switch (ch) {
        case 't': opt_threads = atoi(optarg); break;
        case 'r': opt_rounds = atol(optarg); break;
        case 'd': opt_seconds = atol(optarg); break;
        case 'o': opt_ops = atoi(optarg); break;
        case 'c': opt_ch = atoi(optarg); break;
        case 's': opt_seed = strtoull(optarg, NULL, 10); break;
        default: fprintf(stderr, "usage: %s [-t threads] [-r rounds] [-d seconds] [-o ops] [-c challenges] [-s seed] <manifest-dir>\n", argv[0]); return 2;
        }
    }
    if (optind + 1 != argc || opt_threads < 1 || opt_threads > MAX_THREADS || opt_ops < 1 || opt_ch < 1 || opt_ch > MAX_CH) {
        fprintf(stderr, "usage: %s [-t threads] [-r rounds] [-d seconds] [-o ops] [-c challenges] [-s seed] <manifest-dir>\n", argv[0]);
        return 2;
    }
    v2c_dir = argv[optind];
    for (int i = 0; i < MAX_CH; i++) {
        pthread_mutex_init(&pool_mu[i], NULL);
        for (int h = 0; h < MAX_HANDLES; h++) pthread_mutex_init(&handle_mu[i][h], NULL);
    }
    pthread_mutex_init(&bar.mu, NULL);
    pthread_cond_init(&bar.cv, NULL);
    bar.n = opt_threads;

    /* The lifecycle store configuration, as v2c_run_lifecycle reads it. */
    char *meta = (char *)v2c_read("lifecycle/meta.txt", NULL), *save = NULL;
    char sed[256] = "", sml[256] = "";
    for (char *l = strtok_r(meta, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
        long long x;
        if (sscanf(l, "verifier_seeds %255s %255s", sed, sml) == 2) continue;
        if (sscanf(l, "log_id %63s", S.log_id) == 1) continue;
        if (sscanf(l, "lease %lld", &x) == 1) S.lease = x;
    }
    free(meta);
    seed_ed = v2c_read(sed, NULL);
    seed_ml = v2c_read(sml, NULL);
    if (ratify_v2_keypair_from_seeds(seed_ed, seed_ml, &S.verifier) != 0) { fprintf(stderr, "verifier key\n"); return 1; }
    ratify_v2_keypair_key_id(S.verifier, S.verifier_id, sizeof S.verifier_id);
    ratify_v2_keypair_public_key(S.verifier, &vk);
    if (S.lease <= 0) { fprintf(stderr, "no lease\n"); return 1; }

    char *index = (char *)v2c_read("lifereq/index.txt", NULL);
    save = NULL;
    for (char *l = strtok_r(index, "\n", &save); l && nreq < MAX_REQ; l = strtok_r(NULL, "\n", &save))
        if (sscanf(l, "%31s %63s", reqs[nreq].name, reqs[nreq].dir) == 2) nreq++;
    free(index);
    if (nreq == 0) { fprintf(stderr, "empty lifereq/index.txt\n"); return 1; }

    for (int t = 0; t < opt_threads; t++) worker_init(&workers[t], t, opt_seed);
    calibrate(&workers[0]);
    if (v2c_failures) { fprintf(stderr, "calibration failed\n"); return 1; }
    round_rng = opt_seed * 0xA0761D6478BD642FULL + 7;
    round_no = 0;

    printf("threads %d, ops per thread per round %d, challenges per round %d, rounds %ld, seconds %ld, seed %llu\n",
           opt_threads, opt_ops, nch == 0 ? (opt_ch < ngroups ? opt_ch : ngroups) : nch, opt_rounds, opt_seconds,
           (unsigned long long)opt_seed);
    fflush(stdout);
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    for (int t = 1; t < opt_threads; t++) pthread_create(&workers[t].th, NULL, run_worker, &workers[t]);
    run_worker(&workers[0]);
    for (int t = 1; t < opt_threads; t++) pthread_join(workers[t].th, NULL);
    double secs = elapsed();

    long calls = 0;
    for (int i = 0; i < S_N; i++) {
        printf("%s %ld%s", STAT_NAMES[i], stats[i], i + 1 < S_N ? ", " : "\n");
        calls += stats[i];
    }
    printf("rounds %d in %.1f s\n", round_no, secs);
    /* Every operation kind must have run, or the mix did not test it. */
    static const int required[] = {S_COMMITTED, S_REPLAY_PROGRESS, S_REPLAY_TERMINAL, S_CONFLICT, S_CANCELLED,
                                   S_LATE_FENCED, S_NONOWNER_REFUSED, S_RECOVERED, S_LEASE_LIVE, S_ACK, S_ACK_RETRY,
                                   S_ACK_ORDER_REFUSED, S_RECORD_REFUSED, S_RELEASED_ALLOW, S_RELEASED_OTHER, S_PENDING, S_CHURN};
    for (size_t i = 0; i < sizeof required / sizeof required[0]; i++)
        if (stats[required[i]] == 0) fail("operation outcome %s never occurred; run longer", STAT_NAMES[required[i]]);

    reset_store(&S);
    for (int t = 0; t < opt_threads; t++)
        for (int i = 0; i < nreq; i++) v2c_vector_free(workers[t].vec[i]);
    ratify_v2_keypair_free(S.verifier);
    free(seed_ed);
    free(seed_ml);
    printf("checks: %ld calls, failures: %d\n", calls, v2c_failures);
    return v2c_failures ? 1 : 0;
}
