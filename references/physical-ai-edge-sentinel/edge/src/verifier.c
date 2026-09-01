/*
 * The verifier: challenge issuance, Ratify verification, trust-anchor check,
 * local policy, and the allow token that gates the actuator.
 *
 * Ordering matters and is deliberate. See sentinel_decide.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ratify.h"
#include "sentinel.h"
#include "trust.h"

#define CHALLENGE_STORE_CAPACITY 64

struct sentinel_ctx {
    trust_ctx             trust;
    RatifyChallengeStore *store;
    uint64_t              actuator_token;
    struct timespec       started_monotonic;
    int                   quarantine_override;
};

static void hex_encode(const unsigned char *in, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static void deny(sentinel_decision *out, const char *reason)
{
    out->allow = 0;
    out->actuator_token = 0;
    snprintf(out->status, sizeof(out->status), "%s", reason);
    snprintf(out->reason, sizeof(out->reason), "%s", reason);
}

static int build_invocation(const char *scope, const char *zone, int duration,
                            const char *invocation_id, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s|%s|%d|%s", scope ? scope : "",
                     zone ? zone : "", duration,
                     invocation_id ? invocation_id : "manual");
    return n >= 0 && (size_t)n < cap ? 0 : -1;
}

int sentinel_init(const char *trust_dir, sentinel_ctx **out)
{
    sentinel_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -1;

    if (trust_load(trust_dir, &ctx->trust) != 0) {
        free(ctx);
        return -1;
    }

    ctx->store = ratify_challenge_store_new(CHALLENGE_STORE_CAPACITY);
    if (!ctx->store) {
        fprintf(stderr, "sentinel: challenge store allocation failed\n");
        free(ctx);
        return -1;
    }

    /* The actuator token is process-random and never leaves this process. It
     * is what makes "the actuator has no independent path" structural rather
     * than a convention. */
    unsigned char seed[32];
    if (ratify_challenge_generate(seed, sizeof(seed)) != RatifyOk) {
        fprintf(stderr, "sentinel: entropy unavailable at startup\n");
        ratify_challenge_store_free(ctx->store);
        free(ctx);
        return -1;
    }
    memcpy(&ctx->actuator_token, seed, sizeof(ctx->actuator_token));
    if (ctx->actuator_token == 0) ctx->actuator_token = 1;  /* 0 means unbound */

    clock_gettime(CLOCK_MONOTONIC, &ctx->started_monotonic);

#ifdef SENTINEL_TEST_BUILD
    /* FR13. Test builds only. Never compiled into the edge binary, so the
     * normal build cannot enable it however the environment is set. */
    ctx->quarantine_override = getenv("SENTINEL_TEST_QUARANTINE_OVERRIDE") &&
        strcmp(getenv("SENTINEL_TEST_QUARANTINE_OVERRIDE"), "1") == 0;
#endif

    *out = ctx;
    return 0;
}

void sentinel_free(sentinel_ctx *ctx)
{
    if (!ctx) return;
    ratify_challenge_store_free(ctx->store);
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

int sentinel_issue_challenge(sentinel_ctx *ctx, const sentinel_request *req,
                             char *out_hex, char *out_context_hex,
                             int64_t *out_expires_at)
{
    int64_t now; int trusted;
    if (trust_now(&ctx->trust, &now, &trusted) != 0)
        return -1;

    unsigned char challenge[SENTINEL_CHALLENGE_BYTES];
    unsigned char op_hash[32], context[32];
    char invocation[512];
    char *err = NULL;
    const char *scope = req && req->scope ? req->scope : "";
    const char *zone = req && req->zone ? req->zone : "";
    int duration = req ? req->duration_ms : 0;
    const char *resource = req && req->resource_id ? req->resource_id : zone;
    const char *invocation_id = req && req->invocation_id ? req->invocation_id : "manual";
    if (build_invocation(scope, zone, duration, invocation_id,
                         invocation, sizeof(invocation)) != 0)
        return -1;
    if (ratify_operation_context_hash(scope, "physical-actuate", resource, invocation,
                                      NULL, 0, op_hash, &err) != RatifyOk ||
        ratify_session_context_build("ratify-edge", zone, NULL, "edge-session",
                                     invocation, op_hash, 32, context, &err) != RatifyOk) {
        ratify_error_free(err);
        return -1;
    }
    if (ratify_challenge_store_issue(ctx->store, context, 32,
                                     SENTINEL_CHALLENGE_TTL_S,
                                     challenge, out_expires_at,
                                     &err) != RatifyOk) {
        fprintf(stderr, "sentinel: challenge issue failed: %s\n",
                err ? err : "unknown");
        ratify_error_free(err);
        return -1;
    }
    hex_encode(challenge, sizeof(challenge), out_hex);
    hex_encode(context, sizeof(context), out_context_hex);
    return 0;
}

/* SDK revocation callback. 1 revoked, 0 clean, -1 unavailable (fail closed). */
static int revocation_cb(const char *cert_id, void *userdata)
{
    return trust_is_revoked((const trust_ctx *)userdata, cert_id);
}

void sentinel_decide(sentinel_ctx *ctx, const char *bundle_json,
                     size_t bundle_len, const sentinel_request *req,
                     sentinel_decision *out)
{
    const char *required_scope = req ? req->scope : NULL;
    memset(out, 0, sizeof(*out));
    out->quarantine_override = ctx->quarantine_override;

    /* 1. Bound the input before touching it. A 32-bit device with 921 MiB and
     *    an unauthenticated listener must refuse oversize bodies by size, not
     *    by parsing them. */
    if (!bundle_json || bundle_len == 0 ||
        bundle_len > SENTINEL_MAX_BUNDLE_BYTES) {
        deny(out, SENTINEL_REASON_OVERSIZE);
        return;
    }

    /* 2. Establish a clock we can justify. Without one, expiry and freshness
     *    are unfalsifiable, so there is nothing to decide. */
    int64_t now; int trusted;
    if (trust_now(&ctx->trust, &now, &trusted) != 0) {
        deny(out, SENTINEL_REASON_NO_CLOCK);
        return;
    }
    out->decided_at    = now;
    out->clock_trusted = trusted;

    int sensitive = required_scope && ratify_scope_is_sensitive(required_scope);

    /* 3. Quarantine, before any crypto. A restart cleared the in-memory
     *    challenge store, so a bundle captured before the restart is still
     *    inside its freshness window with its consumed record gone. */
    if (sensitive && !ctx->quarantine_override &&
        sentinel_quarantine_remaining(ctx) > 0) {
        deny(out, SENTINEL_REASON_QUARANTINE);
        return;
    }

    /* 4. Revocation state must be justifiable before a sensitive action.
     *    Absent state is not the same as "not revoked" (SPEC §15.5). */
    if (sensitive && !trust_revocation_ok(&ctx->trust)) {
        deny(out, SENTINEL_REASON_REVOCATION);
        return;
    }

    /* 5. Ratify verification with single-use challenge enforcement. The store
     *    rejects a challenge we did not issue before any signature work, which
     *    is what keeps a flood cheap at ~24 ms per real verification. */
    unsigned char op_hash[32], context[32];
    char invocation[512];
    char *context_err = NULL;
    const char *resource = req && req->resource_id ? req->resource_id :
        (req && req->zone ? req->zone : "");
    const char *invocation_id = req && req->invocation_id ? req->invocation_id : "manual";
    if (build_invocation(required_scope, req && req->zone ? req->zone : "",
                         req ? req->duration_ms : 0, invocation_id,
                         invocation, sizeof(invocation)) != 0) {
        deny(out, "operation_context_too_large");
        return;
    }
    if (ratify_operation_context_hash(required_scope, "physical-actuate",
                                      resource, invocation,
                                      NULL, 0, op_hash, &context_err) != RatifyOk ||
        ratify_session_context_build("ratify-edge", req && req->zone ? req->zone : "",
                                     NULL, "edge-session", invocation, op_hash, 32,
                                     context, &context_err) != RatifyOk) {
        deny(out, "operation_context_invalid");
        ratify_error_free(context_err);
        return;
    }
    RatifyVerifyOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.required_scope     = required_scope;
    opts.now_unix           = now;      /* never 0: 0 means "system clock" */
    opts.revocation_fn      = revocation_cb;
    opts.revocation_userdata = &ctx->trust;
    opts.session_context = context;
    opts.session_context_len = 32;

    RatifyVerifyResult *result = NULL;
    char *err = NULL;
    RatifyStatus st = ratify_verify_bundle_opts_with_challenge_store(
        bundle_json, &opts, ctx->store, &result, &err);

    if (st != RatifyOk || !result) {
        snprintf(out->status, sizeof(out->status), "verify_error");
        snprintf(out->reason, sizeof(out->reason), "%s", err ? err : "unknown");
        ratify_error_free(err);
        if (result) ratify_verify_result_free(result);
        out->allow = 0;
        return;
    }
    ratify_error_free(err);

    char *status   = ratify_verify_result_identity_status(result);
    char *reason   = ratify_verify_result_error_reason(result);
    char *human_id = ratify_verify_result_human_id(result);
    char *agent_id = ratify_verify_result_agent_id(result);
    int   valid    = ratify_verify_result_is_valid(result);

    if (human_id) snprintf(out->human_id, sizeof(out->human_id), "%s", human_id);
    if (agent_id) snprintf(out->agent_id, sizeof(out->agent_id), "%s", agent_id);

    if (!valid) {
        /* Record both. The status is the closed enum and is what policy and
         * fixtures key on; the reason is operator-facing detail whose shape
         * is not uniform across statuses. */
        snprintf(out->status, sizeof(out->status), "%s",
                 status ? status : "invalid");
        snprintf(out->reason, sizeof(out->reason), "%s",
                 (reason && reason[0]) ? reason : "");
        out->allow = 0;
    } else if (strcmp(out->human_id, ctx->trust.pinned_human_id) != 0) {
        /* 6. The anchor check. The SDK just told us this chain is internally
         *    valid and correctly signed. It cannot tell us whose chain it is,
         *    because it does not know which principal we trust. This is the
         *    step an implementer skips. */
        deny(out, SENTINEL_REASON_ANCHOR_MISMATCH);
    } else if (sensitive &&
               !trust_zone_allowed(&ctx->trust, req ? req->zone : NULL)) {
        /* 7. Local policy, evaluated only once the authority itself checks out.
         *    Deliberately after verification, not before: zone names and the
         *    duration cap are deployment configuration, and evaluating them
         *    first would let any unauthenticated caller probe them. An attacker
         *    without a live challenge never reaches this point, so the ordering
         *    costs nothing in the attack case. Policy may only narrow the
         *    delegation, never widen it. */
        deny(out, SENTINEL_REASON_ZONE);
    } else if (sensitive && req && req->duration_ms > ctx->trust.max_activation_ms) {
        deny(out, SENTINEL_REASON_DURATION);
    } else {
        out->allow = 1;
        out->actuator_token = ctx->actuator_token;
        snprintf(out->status, sizeof(out->status), "%s",
                 status ? status : "authorized_agent");
    }

    ratify_string_free(status);
    ratify_string_free(reason);
    ratify_string_free(human_id);
    ratify_string_free(agent_id);
    ratify_verify_result_free(result);
}

uint64_t sentinel_actuator_token(const sentinel_ctx *ctx)
{
    return ctx->actuator_token;
}
