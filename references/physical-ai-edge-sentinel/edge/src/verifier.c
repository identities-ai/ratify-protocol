/*
 * The v2 decision path: challenge issuance through the library's issuance
 * helper, the stateful live verifier over this receiver's C stores, receipt
 * publication and checkpoint acknowledgement, release, local policy, and the
 * release gate in front of the actuator.
 *
 * Ordering is deliberate. See sentinel_decide.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <time.h>

#include "clock.h"
#include "sentinel.h"
#include "store.h"
#include "trust.h"
#include "util.h"

#define STATUS_SKEW_S 5
#define FUTURE_SKEW_S 5
#define EVALUATOR_TIMEOUT_MS 1000
#define STATUS_MAX_BYTES (1u << 20)

struct sentinel_ctx {
    char state_dir[512];
    trust_config trust;
    ckpt_client ckpt;
    store *st;
    RatifyV2ClaimStoreCallbacks claim_cb;
    RatifyV2ReleaseStoreCallbacks release_cb;
    RatifyV2CheckpointCallbacks ckpt_cb;
    RatifyV2ClockCallbacks clock_cb;
    RatifyV2IssuanceStoreCallbacks issuance_cb;
    RatifyV2JournalStoreCallbacks journal_cb;
    RatifyV2StatusPolicy status_policy;
    uint64_t actuator_token;
    struct timespec started_monotonic;
    int quarantine_override;
    int64_t serial;
};

/* ---- Providers ----------------------------------------------------------- */

/* Trust is the complete pinned root key: the chain's terminal issuer key
 * must equal it byte for byte. A key ID match alone is not trust. */
static int32_t resolve_trust(void *user, const RatifyV2CertView *chain, uintptr_t chain_len, int32_t *outcome,
                             RatifyV2PublicKey *root_key)
{
    const sentinel_ctx *ctx = user;
    const RatifyV2PublicKey *issuer = chain_len ? chain[chain_len - 1].issuer_public_key : NULL;
    if (issuer && memcmp(issuer, &ctx->trust.root_key, sizeof *issuer) == 0) {
        *outcome = RatifyV2TrustTrusted;
        *root_key = ctx->trust.root_key;
    } else {
        *outcome = RatifyV2TrustUntrusted;
    }
    return 0;
}

typedef struct {
    RatifyV2StatusObject objects[2];
    uint8_t *wires[2];
    uintptr_t count;
} status_batch;

/* Signed status objects staged on the device, never a status result. */
static int32_t fetch_status(void *user, const RatifyV2StatusRequest *request, RatifyV2StatusBatch *out)
{
    status_batch *b = user;
    out->objects = b->objects;
    out->count = b->count;
    (void)request;
    return 0;
}

static void load_status_batch(const sentinel_ctx *ctx, status_batch *b)
{
    memset(b, 0, sizeof *b);
    const char *names[2] = {"status-list.json", "status-push.json"};
    const uint16_t kinds[2] = {RatifyV2KindRevocationList, RatifyV2KindRevocationPush};
    for (int i = 0; i < 2; i++) {
        char path[600];
        size_t len = 0;
        snprintf(path, sizeof path, "%s/%s", ctx->state_dir, names[i]);
        char *wire = read_file(path, STATUS_MAX_BYTES, &len);
        if (!wire) continue;
        b->wires[b->count] = (uint8_t *)wire;
        b->objects[b->count] = (RatifyV2StatusObject){kinds[i], {(const uint8_t *)wire, len}};
        b->count++;
    }
}

static void free_status_batch(status_batch *b)
{
    for (uintptr_t i = 0; i < b->count; i++) free(b->wires[i]);
}

/* ---- Lifecycle ----------------------------------------------------------- */

static int open_common(const char *trust_dir, const char *checkpoint_socket, sentinel_ctx *ctx)
{
    if (ratify_v2_abi_version() != RATIFY_V2_ABI_VERSION) {
        fprintf(stderr, "sentinel: Ratify v2 ABI %u, header %d\n", ratify_v2_abi_version(), RATIFY_V2_ABI_VERSION);
        return -1;
    }
    struct sockaddr_un probe;
    if (strlen(checkpoint_socket) >= sizeof probe.sun_path) {
        fprintf(stderr, "sentinel: checkpoint socket path longer than %zu bytes\n", sizeof probe.sun_path - 1);
        return -1;
    }
    if (trust_load(trust_dir, &ctx->trust) != 0) return -1;
    snprintf(ctx->ckpt.socket_path, sizeof ctx->ckpt.socket_path, "%s", checkpoint_socket);
    ctx->ckpt.key = ctx->trust.checkpoint_key;
    ctx->status_policy = (RatifyV2StatusPolicy){ctx->trust.status_max_age_s, ctx->trust.status_max_age_s, STATUS_SKEW_S};
    return 0;
}

static void bind_callbacks(sentinel_ctx *ctx)
{
    store_callbacks(ctx->st, &ctx->claim_cb, &ctx->release_cb, &ctx->ckpt_cb, &ctx->clock_cb, &ctx->issuance_cb,
                    &ctx->journal_cb);
}

int sentinel_initialize(const char *state_dir, const char *trust_dir, const char *checkpoint_socket)
{
    sentinel_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    snprintf(ctx.state_dir, sizeof ctx.state_dir, "%s", state_dir);
    if (open_common(trust_dir, checkpoint_socket, &ctx) != 0) return -1;
    if (store_create(state_dir, 1) != 0) {
        trust_unload(&ctx.trust);
        return -1;
    }
    char why[128];
    ctx.st = store_open(state_dir, &ctx.ckpt, 1, why);
    if (!ctx.st) {
        trust_unload(&ctx.trust);
        return -1;
    }
    bind_callbacks(&ctx);

    /* Key roles are bound once, permanently, in the anchored journal. The
     * journal itself refuses a key bound to a second role. */
    int rc = 0;
    int32_t c;
#define STEP(call, what)                                                                         \
    if (rc == 0 && (c = (call)) != 0) {                                                          \
        fprintf(stderr, "sentinel: %s: %s (%s)\n", what, ratify_v2_error_class_str(c),           \
                ratify_v2_last_error_message());                                                 \
        rc = -1;                                                                                 \
    }
    STEP(ratify_v2_journal_record_key_role(&ctx.journal_cb, "issuer", &ctx.trust.root_key), "issuer role");
    STEP(ratify_v2_journal_record_key_role(&ctx.journal_cb, "delegation", &ctx.trust.agent_key), "delegation role");
    STEP(ratify_v2_journal_record_key_role(&ctx.journal_cb, "verifier", store_verifier_key(ctx.st)), "verifier role");
    STEP(ratify_v2_journal_record_key_role(&ctx.journal_cb, "witness", &ctx.trust.checkpoint_key), "checkpoint role");
    STEP(ratify_v2_journal_configure_status_key(&ctx.journal_cb, ctx.trust.root_id, ctx.trust.status_epoch,
                                                &ctx.trust.status_key),
         "status key");

    /* Stage the signed status list into the anchored journal. */
    char path[600];
    size_t len = 0;
    snprintf(path, sizeof path, "%s/status-list.json", trust_dir);
    char *list = read_file(path, STATUS_MAX_BYTES, &len);
    int64_t now = 0;
    if (rc == 0 && (!list || store_now(ctx.st, &now) != 0)) {
        fprintf(stderr, "sentinel: no signed status list or no clock\n");
        rc = -1;
    }
    STEP(ratify_v2_journal_apply(&ctx.journal_cb, RatifyV2KindRevocationList, (const uint8_t *)list, len,
                                 ctx.trust.root_id, ctx.trust.status_epoch, &ctx.trust.status_key, &ctx.status_policy,
                                 now),
         "stage status list");
#undef STEP
    if (rc == 0) {
        snprintf(path, sizeof path, "%s/status-list.json", state_dir);
        rc = write_file_durable(path, list, len, 0600);
    }
    free(list);
    if (rc == 0) rc = store_provision(ctx.st);
    if (rc == 0)
        printf("INITIALIZED verifier=%s log=%s digest=%s\n", store_verifier_id(ctx.st), store_log_id(ctx.st),
               store_digest(ctx.st));
    store_free(ctx.st);
    trust_unload(&ctx.trust);
    return rc;
}

int sentinel_open(const char *state_dir, const char *trust_dir, const char *checkpoint_socket, sentinel_ctx **out)
{
    sentinel_ctx *ctx = calloc(1, sizeof *ctx);
    snprintf(ctx->state_dir, sizeof ctx->state_dir, "%s", state_dir);
    if (open_common(trust_dir, checkpoint_socket, ctx) != 0) {
        free(ctx);
        return -1;
    }
    char why[128];
    ctx->st = store_open(state_dir, &ctx->ckpt, 0, why);
    if (!ctx->st) {
        fprintf(stderr, "sentinel: %s\n", why);
        trust_unload(&ctx->trust);
        free(ctx);
        return -1;
    }
    if (why[0]) fprintf(stderr, "sentinel: RECOVERING: %s\n", why);
    bind_callbacks(ctx);
    if (store_status(ctx->st, NULL) == STORE_READY && store_drain(ctx->st) != 0)
        fprintf(stderr, "sentinel: outbox drain incomplete; pending entries stay unreleased\n");

    /* The actuator token is process-random and never leaves this process. */
    uint8_t seed[8];
    if (random_bytes(seed, sizeof seed) != 0) {
        sentinel_free(ctx);
        return -1;
    }
    memcpy(&ctx->actuator_token, seed, sizeof ctx->actuator_token);
    if (ctx->actuator_token == 0) ctx->actuator_token = 1;
    clock_gettime(CLOCK_MONOTONIC, &ctx->started_monotonic);
#ifdef SENTINEL_TEST_BUILD
    /* Test builds only; never compiled into the edge binary. */
    const char *q = getenv("SENTINEL_TEST_QUARANTINE_OVERRIDE");
    ctx->quarantine_override = q && strcmp(q, "1") == 0;
#endif
    *out = ctx;
    return 0;
}

void sentinel_free(sentinel_ctx *ctx)
{
    if (!ctx) return;
    store_free(ctx->st);
    trust_unload(&ctx->trust);
    free(ctx);
}

int64_t sentinel_quarantine_remaining(const sentinel_ctx *ctx)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int64_t elapsed = (int64_t)(now.tv_sec - ctx->started_monotonic.tv_sec);
    return elapsed >= SENTINEL_QUARANTINE_S ? 0 : SENTINEL_QUARANTINE_S - elapsed;
}

uint64_t sentinel_actuator_token(const sentinel_ctx *ctx) { return ctx->actuator_token; }

const char *sentinel_health(const sentinel_ctx *ctx)
{
    const char *why = NULL;
    return store_status(ctx->st, &why) == STORE_READY ? "ready" : "recovering";
}

/* ---- Challenge ----------------------------------------------------------- */

static int session_context_b64(const sentinel_ctx *ctx, const actx_action *a, char out[64])
{
    uint8_t sc[32];
    if (actx_session_context(a, store_verifier_id(ctx->st), ctx->trust.workspace_id, ctx->trust.agent_id, sc) != 0)
        return -1;
    char *b = b64_encode(sc, 32);
    snprintf(out, 64, "%s", b);
    free(b);
    return 0;
}

int sentinel_issue_challenge(sentinel_ctx *ctx, const actx_action *action, sentinel_challenge *out,
                             char reason[SENTINEL_TEXT_MAX])
{
    memset(out, 0, sizeof *out);
    snprintf(reason, SENTINEL_TEXT_MAX, "%s", "");
    if (store_status(ctx->st, NULL) != STORE_READY) {
        snprintf(reason, SENTINEL_TEXT_MAX, SENTINEL_REASON_RECOVERING);
        return -1;
    }
    if (!actx_valid(action) || session_context_b64(ctx, action, out->session_context_b64) != 0) {
        snprintf(reason, SENTINEL_TEXT_MAX, SENTINEL_REASON_REQUEST);
        return -1;
    }
    char *req = xformat("{\"verifier_namespace\":\"%s\",\"replay_epoch\":%lld,\"verifier_id\":\"%s\","
                        "\"lifetime_seconds\":%lld,\"expected_agent_id\":\"%s\",\"expected_agent_public_key\":%s,"
                        "\"expected_session_context_b64\":\"%s\"}",
                        TRUST_NAMESPACE, (long long)store_replay_epoch(ctx->st), store_verifier_id(ctx->st),
                        (long long)ctx->trust.challenge_lifetime_s, ctx->trust.agent_id, ctx->trust.agent_json,
                        out->session_context_b64);
    RatifyV2Buffer expected = {0};
    int32_t rc = ratify_v2_issue_challenge((const uint8_t *)req, strlen(req), &ctx->clock_cb, &ctx->issuance_cb, NULL,
                                           &expected);
    free(req);
    if (rc != 0) {
        snprintf(reason, SENTINEL_TEXT_MAX, "%s", ratify_v2_error_class_str(rc));
        return -1;
    }
    char *text = take_buffer(expected, NULL);
    int ok = json_get_str(text, "value_b64", out->challenge_b64, sizeof out->challenge_b64) &&
             json_get_int(text, "issued_at", &out->issued_at) && json_get_int(text, "expires_at", &out->expires_at);
    free(text);
    snprintf(out->verifier_id, sizeof out->verifier_id, "%s", store_verifier_id(ctx->st));
    if (!ok) snprintf(reason, SENTINEL_TEXT_MAX, "challenge_unavailable");
    return ok ? 0 : -1;
}

/* ---- Decision ------------------------------------------------------------ */

static void set(char *dst, const char *src) { snprintf(dst, SENTINEL_TEXT_MAX, "%s", src ? src : ""); }

static void device_deny(sentinel_decision *out, const char *reason)
{
    snprintf(out->stage, sizeof out->stage, "device");
    set(out->status, reason);
}

static int is_actuate(const char *scope) { return strcmp(scope, "physical:actuate") == 0; }

void sentinel_decide(sentinel_ctx *ctx, const char *bundle, size_t bundle_len, const actx_action *action,
                     sentinel_decision *out)
{
    memset(out, 0, sizeof *out);
    out->serial = ++ctx->serial;
    out->quarantine_override = ctx->quarantine_override;

    /* 1. Bound the input before touching it. */
    if (!bundle || bundle_len == 0 || bundle_len > SENTINEL_MAX_BUNDLE_BYTES) {
        device_deny(out, SENTINEL_REASON_OVERSIZE);
        return;
    }
    /* 2. A clock this build accepts, or no decision. */
    int64_t now;
    int trusted;
    if (clock_read(&now, &trusted) != 0) {
        device_deny(out, SENTINEL_REASON_NO_CLOCK);
        return;
    }
    out->decided_at = now;
    out->clock_trusted = trusted;
    /* 3. A receiver whose state does not match the checkpoint claims and
     *    releases nothing. */
    if (store_status(ctx->st, NULL) != STORE_READY) {
        device_deny(out, SENTINEL_REASON_RECOVERING);
        return;
    }
    if (!actx_valid(action)) {
        device_deny(out, SENTINEL_REASON_REQUEST);
        return;
    }
    /* 4. Post-boot quarantine for actuation. The claim store is durable, so
     *    a restart no longer forgets consumed challenges; the quarantine is
     *    kept as a settling period for the RTC after a power event. */
    if (is_actuate(action->scope) && !ctx->quarantine_override && sentinel_quarantine_remaining(ctx) > 0) {
        device_deny(out, SENTINEL_REASON_QUARANTINE);
        return;
    }
    store_drain(ctx->st);

    /* 5. Strict decode, then load the authenticated issuance record for the
     *    presented challenge. */
    RatifyV2Buffer canonical = {0};
    int32_t rc = ratify_v2_object_decode(RatifyV2KindProofBundle, (const uint8_t *)bundle, bundle_len, &canonical);
    if (rc != 0) {
        snprintf(out->stage, sizeof out->stage, "preflight");
        set(out->status, ratify_v2_error_class_str(rc));
        return;
    }
    char *text = take_buffer(canonical, NULL);
    char challenge_b64[64] = "";
    uint8_t challenge[32];
    int have = json_get_str(text, "challenge", challenge_b64, sizeof challenge_b64) &&
               b64_decode(challenge_b64, challenge, sizeof challenge) == 32;
    free(text);
    RatifyV2Buffer expected_buf = {0};
    if (!have || (rc = ratify_v2_load_expected_challenge(&ctx->issuance_cb, TRUST_NAMESPACE,
                                                         store_replay_epoch(ctx->st), challenge, 32,
                                                         &expected_buf)) != 0) {
        snprintf(out->stage, sizeof out->stage, "preflight");
        set(out->status, have ? ratify_v2_error_class_str(rc) : "malformed");
        return;
    }
    char *expected = take_buffer(expected_buf, NULL);

    /* 6. The expected session context comes from this request's action and
     *    the device's own configuration, never from the proof. */
    char sc_b64[64];
    session_context_b64(ctx, action, sc_b64);
    char *request = xformat(
        "{\"required_scope\":\"%s\",\"verifier_namespace\":\"%s\",\"replay_epoch\":%lld,\"now\":%lld,"
        "\"max_challenge_age_seconds\":%lld,\"future_skew_seconds\":%d,\"tzdb_version\":\"%s\","
        "\"status_keys\":{\"%s\":{\"epoch\":%llu,\"public_key\":%s}},"
        "\"status_policy\":{\"max_list_lifetime_seconds\":%lld,\"max_status_age_seconds\":%lld,"
        "\"clock_skew_seconds\":%d},"
        "\"expected_challenge\":%s,"
        "\"context_policy\":{\"profile\":\"%s\",\"require_bound\":true,\"required_fields\":[\"verifier_id\","
        "\"workspace_id\",\"agent_id\",\"session_id\",\"invocation_id\",\"request_hash\"],"
        "\"expected_session_context_b64\":\"%s\"},"
        "\"context\":{\"has_resource\":true,\"requested_resource_id\":\"%s\",\"requested_path\":\"/%s\","
        "\"extension_counts\":{\"%s\":%d}}}",
        action->scope, TRUST_NAMESPACE, (long long)store_replay_epoch(ctx->st), (long long)now,
        (long long)ctx->trust.max_challenge_age_s, FUTURE_SKEW_S, ratify_v2_tzdb_version(), ctx->trust.root_id,
        (unsigned long long)ctx->trust.status_epoch, ctx->trust.status_json, (long long)ctx->status_policy.max_list_lifetime_seconds,
        (long long)ctx->status_policy.max_status_age_seconds, STATUS_SKEW_S, expected, ACTX_CONTEXT_PROFILE, sc_b64,
        action->zone, action->resource, ACTX_DURATION_COUNTER, action->duration_ms);
    free(expected);

    /* 7. The live verifier over the durable stores. The certificate's
     *    duration ceiling is a signed max_count constraint evaluated by the
     *    standard profile. */
    RatifyV2EvaluatorRegistration reg = {ACTX_MAX_COUNT_TYPE, ACTX_MAX_COUNT_PROFILE,
                                         RatifyV2EvaluatorStandardMaxCount, NULL, NULL};
    RatifyV2EvaluatorConfig evaluators = {EVALUATOR_TIMEOUT_MS, &reg, 1};
    RatifyV2TrustCallbacks trust_cb = {ctx, resolve_trust};
    status_batch batch;
    load_status_batch(ctx, &batch);
    RatifyV2StatusEvidenceCallbacks evidence_cb = {&batch, fetch_status};
    RatifyV2VerifyCallbacks callbacks = {&ctx->claim_cb, &trust_cb, &evidence_cb, &ctx->journal_cb, NULL, NULL, NULL};
    RatifyV2VerifyOutcome outcome;
    memset(&outcome, 0, sizeof outcome);
    RatifyV2Committed *committed = NULL;
    rc = ratify_v2_verify_proof_bundle((const uint8_t *)bundle, bundle_len, (const uint8_t *)request, strlen(request),
                                       &evaluators, &callbacks, &outcome, NULL, &committed);
    free(request);
    free_status_batch(&batch);
    if (rc != 0) {
        device_deny(out, ratify_v2_error_class_str(rc));
        ratify_v2_committed_free(committed);
        return;
    }
    switch (outcome.stage) {
    case RatifyV2StagePreflight:
        snprintf(out->stage, sizeof out->stage, "preflight");
        set(out->status, ratify_v2_error_class_str(outcome.error_code));
        return;
    case RatifyV2StageReplay:
        snprintf(out->stage, sizeof out->stage, "replay");
        set(out->status, outcome.disposition == RatifyV2DispositionTerminalReplay ? "terminal_replay" : "in_progress");
        return;
    case RatifyV2StageEvaluating:
        snprintf(out->stage, sizeof out->stage, "evaluating");
        set(out->status, ratify_v2_error_class_str(outcome.error_code));
        return;
    case RatifyV2StageCommitted:
        break;
    default:
        device_deny(out, "internal");
        return;
    }
    snprintf(out->stage, sizeof out->stage, "committed");

    /* 8. Publish the signed receipt and obtain the checkpoint's
     *    acknowledgement, then release. Nothing is actionable before. */
    char *claim_id = NULL;
    ratify_v2_committed_claim_id(committed, &claim_id);
    snprintf(out->claim_id, sizeof out->claim_id, "%s", claim_id ? claim_id : "");
    uint8_t *receipt = NULL;
    size_t receipt_len = 0;
    char why[64];
    store_publish(ctx->st, out->claim_id, &receipt, &receipt_len, why);
    ratify_v2_string_free(claim_id);
    int32_t release_status = 0;
    char *release_reason = NULL;
    RatifyV2Slice receipt_slice = {receipt, receipt_len};
    rc = ratify_v2_release_decision(committed, receipt_slice, store_verifier_key(ctx->st), store_log_id(ctx->st),
                                    &ctx->release_cb, &ctx->ckpt_cb, &release_status, &release_reason,
                                    &out->released);
    free(receipt);
    ratify_v2_committed_free(committed);
    snprintf(out->release, sizeof out->release, "%s", ratify_v2_release_status_str(release_status));
    if (rc != 0 || release_status != RatifyV2ReleaseReleased || !out->released) {
        set(out->status, release_reason && release_reason[0] ? release_reason : ratify_v2_error_class_str(rc));
        ratify_v2_string_free(release_reason);
        return;
    }
    ratify_v2_string_free(release_reason);
    char *s1 = NULL, *s2 = NULL, *s3 = NULL;
    ratify_v2_released_string(out->released, RatifyV2ReleasedDecision, &s1);
    ratify_v2_released_string(out->released, RatifyV2ReleasedReason, &s2);
    ratify_v2_released_string(out->released, RatifyV2ReleasedIdentityStatus, &s3);
    snprintf(out->decision, sizeof out->decision, "%s", s1 ? s1 : "");
    set(out->reason, s2);
    set(out->identity_status, s3);
    set(out->status, "released");
    ratify_v2_string_free(s1);
    ratify_v2_string_free(s2);
    ratify_v2_string_free(s3);

    /* 9. Local policy narrows a released allow; it never widens one. It is
     *    evaluated after authority so unauthenticated callers cannot probe
     *    it. */
    if (strcmp(out->decision, "allow") != 0 || !is_actuate(action->scope)) return;
    if (!trust_zone_allowed(&ctx->trust, action->zone))
        set(out->local_policy, SENTINEL_REASON_ZONE);
    else if (action->duration_ms > ctx->trust.max_activation_ms)
        set(out->local_policy, SENTINEL_REASON_DURATION);
    else
        out->actionable = 1;
}

void sentinel_decision_free(sentinel_decision *d)
{
    ratify_v2_released_free(d->released);
    d->released = NULL;
}

int sentinel_release_gate(sentinel_ctx *ctx, const sentinel_decision *d, uint64_t *token)
{
    *token = 0;
    if (!d->actionable || !d->released) return 0;
    if (ratify_v2_released_allowed(d->released, &ctx->clock_cb) != 1) return 0;
    *token = ctx->actuator_token;
    return 1;
}

int sentinel_stage_status(sentinel_ctx *ctx, int kind, const uint8_t *wire, size_t len, char reason[SENTINEL_TEXT_MAX])
{
    snprintf(reason, SENTINEL_TEXT_MAX, "%s", "");
    if (store_status(ctx->st, NULL) != STORE_READY) {
        snprintf(reason, SENTINEL_TEXT_MAX, SENTINEL_REASON_RECOVERING);
        return -1;
    }
    if (kind != RatifyV2KindRevocationList && kind != RatifyV2KindRevocationPush) return -1;
    int64_t now;
    if (store_now(ctx->st, &now) != 0) {
        snprintf(reason, SENTINEL_TEXT_MAX, SENTINEL_REASON_NO_CLOCK);
        return -1;
    }
    int32_t rc = ratify_v2_journal_apply(&ctx->journal_cb, kind, wire, len, ctx->trust.root_id, ctx->trust.status_epoch,
                                         &ctx->trust.status_key, &ctx->status_policy, now);
    if (rc != 0) {
        snprintf(reason, SENTINEL_TEXT_MAX, "%s", ratify_v2_error_class_str(rc));
        return -1;
    }
    char path[600];
    snprintf(path, sizeof path, "%s/%s", ctx->state_dir,
             kind == RatifyV2KindRevocationList ? "status-list.json" : "status-push.json");
    return write_file_durable(path, wire, len, 0600);
}
