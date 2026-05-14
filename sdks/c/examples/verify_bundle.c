/*
 * Ratify Protocol — C example: Delegate → Present → Verify
 *
 * Demonstrates the complete agent authorization flow using the C SDK.
 * All API entry/exit conditions are explicitly handled.
 *
 * Build (macOS):
 *   cargo build --release
 *   cc verify_bundle.c -I ../include -L ../target/release \
 *       -lratify_c -lpthread -framework Security -framework CoreFoundation \
 *       -o verify_bundle && ./verify_bundle
 *
 * Build (Linux):
 *   cc verify_bundle.c -I ../include -L ../target/release \
 *       -lratify_c -lpthread -ldl -lm -o verify_bundle && ./verify_bundle
 *
 * AddressSanitizer (Linux):
 *   cc verify_bundle.c -I ../include -L ../target/release \
 *       -lratify_c -lpthread -ldl -lm -fsanitize=address -g \
 *       -o verify_bundle_asan && ASAN_OPTIONS=detect_leaks=0 ./verify_bundle_asan
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/ratify.h"

/* Fixed timestamp for deterministic output. In production use time(NULL). */
static const int64_t FIXED_NOW = 1800000000LL; /* ~2027-01-15 */

/* Fail-fast helper: print error and return 1. */
static int fail(const char *step, char *err)
{
    fprintf(stderr, "FAIL: %s — %s\n", step, err ? err : "unknown error");
    ratify_error_free(err);
    return 1;
}

/* Check verify result and print one line. Returns 0 on expected outcome. */
static int check(const char *label, int want_valid, const char *want_status,
                 RatifyVerifyResult *result)
{
    int got_valid  = ratify_verify_result_is_valid(result);
    char *got_status = ratify_verify_result_identity_status(result);
    char *got_reason = ratify_verify_result_error_reason(result);

    int ok = (got_valid == want_valid) &&
             (got_status != NULL) &&
             (strcmp(got_status, want_status) == 0);

    printf("%-44s %s (valid=%d status=%s%s%s)\n",
           label,
           ok ? "PASS" : "FAIL",
           got_valid,
           got_status ? got_status : "(null)",
           (got_reason && got_reason[0]) ? " reason=" : "",
           (got_reason && got_reason[0]) ? got_reason : "");

    ratify_string_free(got_status);
    ratify_string_free(got_reason);
    return ok ? 0 : 1;
}

int main(void)
{
    printf("Ratify %s — C SDK example\n\n", ratify_version());

    int failures = 0;
    char *err = NULL;

    /* ------------------------------------------------------------------ */
    /* 1. Generate identities                                              */
    /* ------------------------------------------------------------------ */

    RatifyHumanRoot *root = NULL;
    if (ratify_human_root_generate(&root) != RatifyOk)
        return fail("ratify_human_root_generate", NULL);

    RatifyAgent *agent = NULL;
    if (ratify_agent_generate("MyDroneBot", "drone", &agent) != RatifyOk) {
        ratify_human_root_free(root);
        return fail("ratify_agent_generate", NULL);
    }

    char *root_id  = ratify_human_root_id(root);
    char *agent_id = ratify_agent_id(agent);
    printf("HumanRoot ID:  %s\n", root_id  ? root_id  : "(null)");
    printf("Agent ID:      %s\n\n", agent_id ? agent_id : "(null)");
    ratify_string_free(root_id);
    ratify_string_free(agent_id);

    /* ------------------------------------------------------------------ */
    /* 2. Issue a DelegationCert                                           */
    /* ------------------------------------------------------------------ */

    RatifyDelegationCert *cert = NULL;
    /* issued_at=FIXED_NOW, expires_at=FIXED_NOW+3600 (one hour) */
    if (ratify_delegation_issue(root, agent,
                                "[\"physical:enter\"]",
                                FIXED_NOW,
                                FIXED_NOW + 3600LL,
                                &cert, &err) != RatifyOk)
        return fail("ratify_delegation_issue", err);

    char *cert_json = ratify_delegation_cert_to_json(cert, &err);
    if (!cert_json)
        return fail("ratify_delegation_cert_to_json", err);

    /* ------------------------------------------------------------------ */
    /* 3. Generate challenge and build ProofBundle                         */
    /*    Always supply the exact byte count for fixed-size fields.        */
    /* ------------------------------------------------------------------ */

    uint8_t challenge[32];
    if (ratify_challenge_generate(challenge, 32 /* must be 32 */) != RatifyOk) {
        ratify_string_free(cert_json);
        return fail("ratify_challenge_generate", NULL);
    }

    RatifyProofBundle *bundle = NULL;
    if (ratify_proof_bundle_create(agent, cert_json,
                                   challenge, 32 /* challenge_len */,
                                   FIXED_NOW,
                                   &bundle, &err) != RatifyOk)
        return fail("ratify_proof_bundle_create", err);
    ratify_string_free(cert_json);

    char *bundle_json = ratify_proof_bundle_to_json(bundle, &err);
    if (!bundle_json)
        return fail("ratify_proof_bundle_to_json", err);

    /* ------------------------------------------------------------------ */
    /* 4. Verify — several scenarios                                        */
    /* ------------------------------------------------------------------ */

    RatifyVerifyResult *result = NULL;

    /* Happy path: scope present and cert not expired */
    ratify_verify_bundle(bundle_json, "physical:enter", FIXED_NOW, &result, &err);
    failures += check("verify physical:enter (expect pass)", 1, "authorized_agent", result);
    ratify_verify_result_free(result); result = NULL;

    /* Wrong scope */
    ratify_verify_bundle(bundle_json, "meeting:record", FIXED_NOW, &result, &err);
    failures += check("verify meeting:record (expect scope_denied)", 0, "scope_denied", result);
    ratify_verify_result_free(result); result = NULL;

    /* No scope requirement */
    ratify_verify_bundle(bundle_json, NULL, FIXED_NOW, &result, &err);
    failures += check("verify no scope (expect pass)", 1, "authorized_agent", result);
    ratify_verify_result_free(result); result = NULL;

    /* After expiry (2 hours past expiry) */
    ratify_verify_bundle(bundle_json, "physical:enter", FIXED_NOW + 7200LL, &result, &err);
    failures += check("verify after expiry (expect expired)", 0, "expired", result);
    ratify_verify_result_free(result); result = NULL;

    /* Full opts path: with a geo context (cert has no geo constraint — still passes) */
    {
        RatifyVerifierContext ctx = {0};
        ctx.current_lat  = 47.6062;
        ctx.current_lon  = -122.3321;
        ctx.has_location = 1;

        RatifyVerifyOptions opts = {0};
        opts.required_scope     = "physical:enter";
        opts.now_unix           = FIXED_NOW;
        opts.context            = &ctx;

        ratify_verify_bundle_opts(bundle_json, &opts, &result, &err);
        failures += check("verify with geo context (expect pass)", 1, "authorized_agent", result);
        ratify_verify_result_free(result); result = NULL;
    }

    /* ------------------------------------------------------------------ */
    /* 5. Validate bad-argument detection                                   */
    /* ------------------------------------------------------------------ */

    uint8_t small_buf[16];
    RatifyStatus s = ratify_challenge_generate(small_buf, 16 /* wrong size */);
    printf("%-44s %s (got status=%d)\n",
           "buf_len=16 returns RatifyErrBadArgument",
           (s == RatifyErrBadArgument) ? "PASS" : "FAIL",
           (int)s);
    if (s != RatifyErrBadArgument) failures++;

    /* ------------------------------------------------------------------ */
    /* 6. Cleanup                                                           */
    /* ------------------------------------------------------------------ */

    ratify_string_free(bundle_json);
    ratify_proof_bundle_free(bundle);
    ratify_delegation_cert_free(cert);
    ratify_agent_free(agent);
    ratify_human_root_free(root);

    printf("\n%s (%d/%d checks passed)\n",
           failures == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED",
           6 - failures, 6);
    return failures > 0 ? 1 : 0;
}
