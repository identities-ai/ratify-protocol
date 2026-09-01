/*
 * Ratify Edge Sentinel — Raspberry Pi 2 hardware smoke test.
 *
 * Satisfies the PRD non-functional requirement to measure and publish depth-1
 * hybrid verification latency and peak memory use on the actual Pi 2, and
 * demonstrates on-device that the trust-anchor check (FR5) is an application
 * duty the SDK cannot perform for you.
 *
 * This is a measurement and assumption-check tool, not the edge verifier. It
 * has no listener, no actuator path, no challenge store, and no policy.
 *
 *   make && ./smoke [iterations]
 */

/* glibc hides clock_gettime, CLOCK_MONOTONIC and getrusage under strict
   -std=c99. macOS headers expose them regardless, so this must come
   before any include or the Pi build fails and the Mac build does not. */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

#include "ratify.h"

#define WARMUP_ITERATIONS 5
#define DEFAULT_ITERATIONS 200

/* ru_maxrss is kilobytes on Linux and bytes on macOS/BSD. The Pi is the
   target; the divisor keeps a controller-side run on a Mac from recording a
   number three orders of magnitude wrong. */
#ifdef __APPLE__
#define RU_MAXRSS_PER_KIB 1024
#else
#define RU_MAXRSS_PER_KIB 1
#endif

/* Fixed clock for the measured path. The real verifier reads the DS3231 and
   passes an explicit now_unix; it never passes 0, which means "system clock". */
static const int64_t FIXED_NOW = 1800000000LL; /* ~2027-01-15 */

static int fail(const char *step, char *err)
{
    fprintf(stderr, "FAIL: %s — %s\n", step, err ? err : "unknown error");
    ratify_error_free(err);
    return 1;
}

static double elapsed_us(const struct timespec *a, const struct timespec *b)
{
    return (double)(b->tv_sec - a->tv_sec) * 1e6 +
           (double)(b->tv_nsec - a->tv_nsec) / 1e3;
}

static int cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Build a depth-1 bundle for `root`/`agent` granting physical:actuate.
   Returns bundle JSON (caller frees) or NULL. */
static char *build_bundle(RatifyHumanRoot *root, RatifyAgent *agent, char **err)
{
    RatifyDelegationCert *cert = NULL;
    if (ratify_delegation_issue(root, agent, "[\"physical:actuate\"]",
                                FIXED_NOW, FIXED_NOW + 3600LL,
                                &cert, err) != RatifyOk)
        return NULL;

    char *cert_json = ratify_delegation_cert_to_json(cert, err);
    ratify_delegation_cert_free(cert);
    if (!cert_json)
        return NULL;

    uint8_t challenge[32];
    if (ratify_challenge_generate(challenge, 32) != RatifyOk) {
        ratify_string_free(cert_json);
        return NULL;
    }

    RatifyProofBundle *bundle = NULL;
    RatifyStatus s = ratify_proof_bundle_create(agent, cert_json, challenge, 32,
                                                FIXED_NOW, &bundle, err);
    ratify_string_free(cert_json);
    if (s != RatifyOk)
        return NULL;

    char *bundle_json = ratify_proof_bundle_to_json(bundle, err);
    ratify_proof_bundle_free(bundle);
    return bundle_json;
}

int main(int argc, char **argv)
{
    int iterations = DEFAULT_ITERATIONS;
    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations < 1) {
            fprintf(stderr, "iterations must be >= 1\n");
            return 2;
        }
    }

    char *err = NULL;
    int failures = 0;

    printf("Ratify %s — Edge Sentinel Pi 2 smoke test\n", ratify_version());
    printf("sizeof(void*) = %zu bytes\n\n", sizeof(void *));

    /* ---------------------------------------------------------------- */
    /* Setup: the operator's root, the controller agent, and one bundle   */
    /* ---------------------------------------------------------------- */

    RatifyHumanRoot *root = NULL;
    if (ratify_human_root_generate(&root) != RatifyOk)
        return fail("ratify_human_root_generate", NULL);

    RatifyAgent *agent = NULL;
    if (ratify_agent_generate("EdgeSentinelController", "controller",
                              &agent) != RatifyOk)
        return fail("ratify_agent_generate", NULL);

    /* The pinned trust anchor. On the real device this is provisioned out of
       band and read from trust/, not generated at startup. */
    char *pinned_human_id = ratify_human_root_id(root);
    if (!pinned_human_id || !pinned_human_id[0])
        return fail("ratify_human_root_id", NULL);
    printf("pinned human_id: %s\n", pinned_human_id);

    char *bundle_json = build_bundle(root, agent, &err);
    if (!bundle_json)
        return fail("build_bundle", err);
    printf("bundle size:     %zu bytes (MAX_PROOF_BUNDLE_BYTES = 131072)\n\n",
           strlen(bundle_json));

    /* ---------------------------------------------------------------- */
    /* Check 1: depth-1 verify succeeds, and the root matches the pin     */
    /* ---------------------------------------------------------------- */

    RatifyVerifyOptions opts = {0};
    opts.required_scope = "physical:actuate";
    opts.now_unix       = FIXED_NOW;

    RatifyVerifyResult *result = NULL;
    if (ratify_verify_bundle_opts(bundle_json, &opts, &result, &err) != RatifyOk)
        return fail("ratify_verify_bundle_opts", err);

    {
        char *status    = ratify_verify_result_identity_status(result);
        char *human_id  = ratify_verify_result_human_id(result);
        int   valid     = ratify_verify_result_is_valid(result);
        int   anchor_ok = human_id && strcmp(human_id, pinned_human_id) == 0;

        printf("%-46s %s (valid=%d status=%s anchor=%s)\n",
               "depth-1 verify, pinned root",
               (valid && anchor_ok) ? "PASS" : "FAIL",
               valid, status ? status : "(null)",
               anchor_ok ? "match" : "MISMATCH");
        if (!valid || !anchor_ok) failures++;

        ratify_string_free(status);
        ratify_string_free(human_id);
    }
    ratify_verify_result_free(result);
    result = NULL;

    /* ---------------------------------------------------------------- */
    /* Check 2: an attacker's own root verifies. The anchor check is the  */
    /* only thing that stops it. This is FR5's reason for existing, and   */
    /* it is confirmed here on the target rather than assumed.            */
    /* ---------------------------------------------------------------- */

    {
        RatifyHumanRoot *rogue_root = NULL;
        RatifyAgent *rogue_agent = NULL;
        if (ratify_human_root_generate(&rogue_root) != RatifyOk ||
            ratify_agent_generate("RogueController", "controller",
                                  &rogue_agent) != RatifyOk)
            return fail("rogue identity generation", NULL);

        char *rogue_bundle = build_bundle(rogue_root, rogue_agent, &err);
        if (!rogue_bundle)
            return fail("build_bundle (rogue)", err);

        if (ratify_verify_bundle_opts(rogue_bundle, &opts, &result,
                                      &err) != RatifyOk)
            return fail("ratify_verify_bundle_opts (rogue)", err);

        char *status   = ratify_verify_result_identity_status(result);
        char *human_id = ratify_verify_result_human_id(result);
        int   valid    = ratify_verify_result_is_valid(result);
        int   anchor_mismatch = human_id &&
                                strcmp(human_id, pinned_human_id) != 0;

        /* Expected: the SDK accepts it (valid=1, authorized_agent) and only
           the anchor comparison rejects it. If valid were 0 here, the
           assumption behind FR5 would be wrong and the PRD would need a look. */
        printf("%-46s %s (valid=%d status=%s anchor=%s)\n",
               "attacker root: SDK accepts, anchor rejects",
               (valid && anchor_mismatch) ? "PASS" : "FAIL",
               valid, status ? status : "(null)",
               anchor_mismatch ? "anchor_mismatch" : "MATCHED (unexpected)");
        if (!valid || !anchor_mismatch) failures++;

        ratify_string_free(status);
        ratify_string_free(human_id);
        ratify_verify_result_free(result);
        result = NULL;
        ratify_string_free(rogue_bundle);
        ratify_agent_free(rogue_agent);
        ratify_human_root_free(rogue_root);
    }

    /* ---------------------------------------------------------------- */
    /* Measurement: depth-1 hybrid verify latency                         */
    /* ---------------------------------------------------------------- */

    double *samples = calloc((size_t)iterations, sizeof(double));
    if (!samples)
        return fail("calloc samples", NULL);

    /* Discard warm-up: the first verify in a process pays lattice-crypto
       init. BENCHMARKS.md measures Go settling by the third call. */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        ratify_verify_bundle_opts(bundle_json, &opts, &result, &err);
        ratify_verify_result_free(result);
        result = NULL;
    }

    for (int i = 0; i < iterations; i++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        RatifyStatus s = ratify_verify_bundle_opts(bundle_json, &opts,
                                                   &result, &err);
        clock_gettime(CLOCK_MONOTONIC, &t1);

        if (s != RatifyOk || !ratify_verify_result_is_valid(result)) {
            ratify_verify_result_free(result);
            free(samples);
            return fail("verify during measurement loop", err);
        }
        ratify_verify_result_free(result);
        result = NULL;
        samples[i] = elapsed_us(&t0, &t1);
    }

    double total = 0.0;
    for (int i = 0; i < iterations; i++)
        total += samples[i];
    qsort(samples, (size_t)iterations, sizeof(double), cmp_double);

    double median = (iterations % 2)
        ? samples[iterations / 2]
        : (samples[iterations / 2 - 1] + samples[iterations / 2]) / 2.0;
    double p95 = samples[(int)((double)(iterations - 1) * 0.95)];

    printf("\ndepth-1 hybrid verify, %d iterations after %d warm-up:\n",
           iterations, WARMUP_ITERATIONS);
    printf("  min    %8.1f us\n", samples[0]);
    printf("  median %8.1f us\n", median);
    printf("  mean   %8.1f us\n", total / iterations);
    printf("  p95    %8.1f us\n", p95);
    printf("  max    %8.1f us\n", samples[iterations - 1]);

    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        printf("\npeak RSS: %ld KiB\n", (long)(ru.ru_maxrss / RU_MAXRSS_PER_KIB));

    free(samples);
    ratify_string_free(bundle_json);
    ratify_string_free(pinned_human_id);
    ratify_agent_free(agent);
    ratify_human_root_free(root);

    printf("\n%s\n", failures == 0 ? "SMOKE TEST PASSED" : "SMOKE TEST FAILED");
    return failures > 0 ? 1 : 0;
}
