/*
 * Checkpoint A fixture harness.
 *
 * Covers the evidence-matrix rows that need no transport and no GPIO. Every
 * row asserts BOTH a specific decision reason and the actuator invocation
 * counter, because a zero count alone can be produced by the quarantine, by a
 * crash, or by a verifier that never ran.
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ratify.h"
#include "sentinel.h"
#include "actuator.h"

#define ACTUATE_SCOPE "physical:actuate"
#define TRUST_DIR "/tmp/sentinel-test-trust"
#define TEST_ZONE "north-paddock"

static const sentinel_request REQ_ACTUATE = { ACTUATE_SCOPE, TEST_ZONE, 500 };

static int failures = 0;
static int checks   = 0;

static void hex_decode(const char *hex, unsigned char *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

/* A row passes only if the status matches EXACTLY and the actuator counter
 * moved by exactly the expected amount.
 *
 * Exact, not prefix: an earlier version asserted the prefix "invalid" and a
 * tamper row passed on "invalid_scope", which is a different failure entirely.
 * Status is also the right field — SPEC §5.9 says audit layers should prefer
 * the enum over parsing the detail text, and `expired` and `revoked` do not
 * carry the status prefix in their error_reason at all. */
static void row(const char *label, const sentinel_decision *d,
                const char *want_status, unsigned long want_calls,
                unsigned long calls_before)
{
    unsigned long delta = actuator_invocations() - calls_before;
    int status_ok = strcmp(d->status, want_status) == 0;
    int calls_ok  = (delta == want_calls);
    checks++;
    if (!status_ok || !calls_ok) failures++;

    printf("%-40s %s  status=%-28s calls=%lu\n",
           label, (status_ok && calls_ok) ? "PASS" : "FAIL", d->status, delta);
    if (!status_ok)
        printf("%-40s      wanted status=%s, detail=\"%s\"\n",
               "", want_status, d->reason);
}

static void write_file(const char *name, const char *contents)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", TRUST_DIR, name);
    FILE *f = fopen(path, "w");
    fputs(contents, f);
    fclose(f);
}

static void unlink_trust(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", TRUST_DIR, name);
    unlink(path);
}

/* Provision the device the way an operator would: pinned anchor, operator
 * public key, local policy, and a signed revocation list. */
static void provision(RatifyHumanRoot *root, const char *human_id,
                      const char *revoked_certs_json, int64_t updated_at)
{
    mkdir(TRUST_DIR, 0700);
    char id_line[64];
    snprintf(id_line, sizeof(id_line), "%s\n", human_id);
    write_file("pinned_human_id", id_line);

    char *err = NULL;
    char *pub = ratify_human_root_pub_key_json(root, &err);
    write_file("operator_pub_key.json", pub);
    ratify_string_free(pub);

    write_file("policy.conf",
               "zone = " TEST_ZONE "\n"
               "max_activation_ms = 1000\n"
               "revocation_max_age_s = 86400\n");

    RatifyRevocationList *list = NULL;
    if (ratify_revocation_list_issue(root, revoked_certs_json, updated_at,
                                     &list, &err) != RatifyOk) {
        fprintf(stderr, "provision: revocation issue failed: %s\n",
                err ? err : "?");
        ratify_error_free(err);
        return;
    }
    char *json = ratify_revocation_list_to_json(list, &err);
    write_file("revocation.json", json);
    ratify_string_free(json);
    ratify_revocation_list_free(list);
}

/* Pull cert_id out of a bundle so a fixture can revoke exactly that cert. */
static void bundle_cert_id(const char *bundle_json, char *out, size_t cap)
{
    out[0] = '\0';
    const char *p = strstr(bundle_json, "\"cert_id\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    p = strchr(p, '"');
    if (!p) return;
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n < cap - 1) out[n++] = *p++;
    out[n] = '\0';
}

/* Build a bundle against a challenge this verifier issued. */
static char *issue_cert(RatifyHumanRoot *root, RatifyAgent *agent,
                        const char *scopes_json, int64_t issued_at,
                        int64_t expires_at)
{
    char *err = NULL;
    RatifyDelegationCert *cert = NULL;
    if (ratify_delegation_issue(root, agent, scopes_json, issued_at,
                                expires_at, &cert, &err) != RatifyOk) {
        fprintf(stderr, "delegation_issue: %s\n", err ? err : "?");
        return NULL;
    }
    char *json = ratify_delegation_cert_to_json(cert, &err);
    ratify_delegation_cert_free(cert);
    return json;
}

/* Present an already-issued cert against a challenge from `ctx`. Keeping cert
 * issuance separate matters for the revocation row: the cert_id must be known
 * BEFORE the verifier is provisioned with a list that revokes it. */
static char *present_cert(sentinel_ctx *ctx, RatifyAgent *agent,
                          const char *cert_json, int64_t challenge_at)
{
    char *err = NULL;
    char challenge_hex[SENTINEL_CHALLENGE_HEX + 1];
    int64_t expires;
    if (sentinel_issue_challenge(ctx, challenge_hex, &expires) != 0)
        return NULL;
    unsigned char challenge[SENTINEL_CHALLENGE_BYTES];
    hex_decode(challenge_hex, challenge, sizeof(challenge));

    RatifyProofBundle *bundle = NULL;
    RatifyStatus st = ratify_proof_bundle_create(agent, cert_json, challenge,
                                                 sizeof(challenge),
                                                 challenge_at, &bundle, &err);
    if (st != RatifyOk) {
        fprintf(stderr, "proof_bundle_create: %s\n", err ? err : "?");
        return NULL;
    }
    char *json = ratify_proof_bundle_to_json(bundle, &err);
    ratify_proof_bundle_free(bundle);
    return json;
}

/* Convenience for rows that do not care about the cert_id. */
static char *present(sentinel_ctx *ctx, RatifyHumanRoot *root,
                     RatifyAgent *agent, const char *scopes_json,
                     int64_t issued_at, int64_t expires_at, int64_t challenge_at)
{
    char *cert = issue_cert(root, agent, scopes_json, issued_at, expires_at);
    if (!cert) return NULL;
    char *b = present_cert(ctx, agent, cert, challenge_at);
    ratify_string_free(cert);
    return b;
}

int main(void)
{
    printf("Ratify %s — Edge Sentinel checkpoint A fixtures\n\n", ratify_version());

    /* The development overrides are explicit and would be absent on a real
     * device. The clock override stands in for the DS3231 that is not yet
     * fitted; the revocation override for the signed list checkpoint C adds. */
    setenv("SENTINEL_ALLOW_UNTRUSTED_CLOCK", "1", 1);
    /* No SENTINEL_ALLOW_NO_REVOCATION: from checkpoint C the fixtures run
     * against a real signed revocation list bound to the pinned anchor. */
    unsetenv("SENTINEL_ALLOW_NO_REVOCATION");

    char *err = NULL;
    RatifyHumanRoot *root = NULL;
    RatifyAgent *agent = NULL;
    if (ratify_human_root_generate(&root) != RatifyOk ||
        ratify_agent_generate("EdgeSentinelController", "controller",
                              &agent) != RatifyOk) {
        fprintf(stderr, "identity generation failed\n");
        return 1;
    }
    char *root_id = ratify_human_root_id(root);
    int64_t now0 = (int64_t)time(NULL);
    provision(root, root_id, "[]", now0);
    printf("pinned human_id: %s\n\n", root_id);

    int64_t now = (int64_t)time(NULL);
    unsigned long before;

    /* ---------------------------------------------------------------- */
    /* Row: quarantine is real. No override, fresh process, sensitive     */
    /* scope. This is the row that keeps the override honest.             */
    /* ---------------------------------------------------------------- */
    {
        unsetenv("SENTINEL_TEST_QUARANTINE_OVERRIDE");
        sentinel_ctx *q = NULL;
        if (sentinel_init(TRUST_DIR, &q) != 0) return 1;
        actuator_bind(sentinel_actuator_token(q));

        char *b = present(q, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(q, b, strlen(b), &REQ_ACTUATE, &d);
        row("fresh process, no override: quarantined", &d,
            SENTINEL_REASON_QUARANTINE, 0, before);
        ratify_string_free(b);
        sentinel_free(q);
    }

    /* Remaining rows run against a test build with the override enabled, and
     * every one asserts its own specific reason so a quarantine denial can
     * never masquerade as the intended cause. */
    setenv("SENTINEL_TEST_QUARANTINE_OVERRIDE", "1", 1);
    sentinel_ctx *ctx = NULL;
    if (sentinel_init(TRUST_DIR, &ctx) != 0) return 1;
    actuator_bind(sentinel_actuator_token(ctx));

    /* Row: authorized, pinned root. The only row that fires the actuator. */
    sentinel_decision allow_d;
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &allow_d);
        if (allow_d.allow) actuator_fire(&allow_d, 200);
        row("authorized, pinned root", &allow_d, "authorized_agent", 1, before);
        ratify_string_free(b);
    }

    /* Row: attacker's own root. Verifies cryptographically; only the anchor
     * check stops it. */
    {
        RatifyHumanRoot *rogue_root = NULL;
        RatifyAgent *rogue_agent = NULL;
        ratify_human_root_generate(&rogue_root);
        ratify_agent_generate("RogueController", "controller", &rogue_agent);

        char *b = present(ctx, rogue_root, rogue_agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 200);
        row("attacker root: anchor rejects", &d,
            SENTINEL_REASON_ANCHOR_MISMATCH, 0, before);
        ratify_string_free(b);
        ratify_agent_free(rogue_agent);
        ratify_human_root_free(rogue_root);
    }

    /* Row: monitor scope presented for actuation. */
    {
        char *b = present(ctx, root, agent, "[\"infrastructure:monitor\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 200);
        row("monitor scope for actuation", &d, "scope_denied", 0, before);
        ratify_string_free(b);
    }

    /* Row: physical:* wildcard. SPEC §9 never expands a wildcard into a
     * sensitive scope, so this must not authorize actuation. */
    {
        char *b = present(ctx, root, agent, "[\"physical:*\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 200);
        row("physical:* wildcard for actuation", &d, "scope_denied", 0, before);
        ratify_string_free(b);
    }

    /* Row: expired cert. expires_at is in the past; note 0 would mean
     * NO EXPIRY, not "expired". */
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now - 7200, now - 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 200);
        row("expired delegation", &d, "expired", 0, before);
        ratify_string_free(b);
    }

    /* Row: replay. The same bundle a second time. Its challenge was consumed
     * by the first presentation, so the store rejects it uniformly. */
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_decision first, second;
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &first);
        if (first.allow) actuator_fire(&first, 200);

        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &second);
        if (second.allow) actuator_fire(&second, 200);
        /* unknown_challenge is NOT in the identity_status enum: the SDK reports
         * status=invalid with the canonical detail. Assert both. */
        int detail_ok = strncmp(second.reason, "unknown_challenge:", 18) == 0;
        row("replay of a consumed challenge", &second, "invalid", 0, before);
        checks++;
        if (!detail_ok) failures++;
        printf("%-40s %s  detail begins \"unknown_challenge:\"\n",
               "  replay detail string", detail_ok ? "PASS" : "FAIL");
        ratify_string_free(b);
    }

    /* Row: tampered bundle. Rewriting the granted scope breaks the signature
     * the cert was issued over. */
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        /* Corrupt the longest base64 run, which is a hybrid signature. Editing
         * a scope string instead would fail vocabulary validation before any
         * signature check and prove nothing about tamper detection. */
        size_t best_start = 0, best_len = 0, cur_start = 0, cur_len = 0;
        for (size_t i = 0; b[i]; i++) {
            char c = b[i];
            int b64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            if (b64) {
                if (cur_len++ == 0) cur_start = i;
                if (cur_len > best_len) { best_len = cur_len; best_start = cur_start; }
            } else {
                cur_len = 0;
            }
        }
        sentinel_decision d;
        before = actuator_invocations();
        if (best_len > 64) {
            char *p = b + best_start + best_len / 2;
            *p = (*p == 'A') ? 'B' : 'A';
        }
        sentinel_decide(ctx, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 200);
        row("tampered signature", &d, "invalid", 0, before);
        ratify_string_free(b);
    }

    /* Row: oversize body, refused by size before parsing. */
    {
        size_t n = SENTINEL_MAX_BUNDLE_BYTES + 1;
        char *big = malloc(n + 1);
        memset(big, 'x', n);
        big[n] = '\0';
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, big, n, &REQ_ACTUATE, &d);
        row("oversize request body", &d, SENTINEL_REASON_OVERSIZE, 0, before);
        free(big);
    }

    /* ---------------------------------------------------------------- */
    /* Checkpoint C rows: revocation state and local policy.              */
    /* ---------------------------------------------------------------- */

    /* Row: local policy rejects a zone the device does not serve. */
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_request req = { ACTUATE_SCOPE, "south-paddock", 500 };
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &req, &d);
        if (d.allow) actuator_fire(&d, 500);
        row("zone outside local policy", &d, SENTINEL_REASON_ZONE, 0, before);
        ratify_string_free(b);
    }

    /* Row: local policy caps activation duration. Ratify has no duration
     * constraint; this is device policy narrowing the delegation. */
    {
        char *b = present(ctx, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_request req = { ACTUATE_SCOPE, TEST_ZONE, 60000 };
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(ctx, b, strlen(b), &req, &d);
        if (d.allow) actuator_fire(&d, 60000);
        row("activation longer than policy allows", &d,
            SENTINEL_REASON_DURATION, 0, before);
        ratify_string_free(b);
    }

    /* Row: the presented cert is on the signed revocation list. */
    {
        /* Issue the cert first so its id is known, revoke exactly that id,
         * then start a verifier that loads the list and present that same
         * cert to it. */
        char *cert = issue_cert(root, agent, "[\"" ACTUATE_SCOPE "\"]",
                                now, now + 3600);
        char cert_id[128];
        bundle_cert_id(cert, cert_id, sizeof(cert_id));

        char revoked[192];
        snprintf(revoked, sizeof(revoked), "[\"%s\"]", cert_id);
        provision(root, root_id, revoked, now);

        sentinel_ctx *rc = NULL;
        if (sentinel_init(TRUST_DIR, &rc) != 0) return 1;
        actuator_bind(sentinel_actuator_token(rc));

        char *b = present_cert(rc, agent, cert, now);
        ratify_string_free(cert);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(rc, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 500);
        row("cert on signed revocation list", &d, "revoked", 0, before);
        ratify_string_free(b);
        sentinel_free(rc);
        actuator_bind(sentinel_actuator_token(ctx));
    }

    /* Row: the revocation list is older than the freshness budget. Stale
     * state is not evidence of anything (SPEC §15.5). */
    {
        provision(root, root_id, "[]", now - 90000);   /* budget is 86400 s */
        sentinel_ctx *sc = NULL;
        if (sentinel_init(TRUST_DIR, &sc) != 0) return 1;
        actuator_bind(sentinel_actuator_token(sc));

        char *b = present(sc, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(sc, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 500);
        row("revocation list past freshness budget", &d,
            SENTINEL_REASON_REVOCATION, 0, before);
        ratify_string_free(b);
        sentinel_free(sc);
        actuator_bind(sentinel_actuator_token(ctx));
    }

    /* Row: no revocation list at all. Absence is not "nothing revoked". */
    {
        unlink_trust("revocation.json");
        sentinel_ctx *nc = NULL;
        if (sentinel_init(TRUST_DIR, &nc) != 0) return 1;
        actuator_bind(sentinel_actuator_token(nc));

        char *b = present(nc, root, agent, "[\"" ACTUATE_SCOPE "\"]",
                          now, now + 3600, now);
        sentinel_decision d;
        before = actuator_invocations();
        sentinel_decide(nc, b, strlen(b), &REQ_ACTUATE, &d);
        if (d.allow) actuator_fire(&d, 500);
        row("no revocation list present", &d,
            SENTINEL_REASON_REVOCATION, 0, before);
        ratify_string_free(b);
        sentinel_free(nc);
        provision(root, root_id, "[]", now);
        actuator_bind(sentinel_actuator_token(ctx));
    }

    /* Row: negative control. A genuine allow decision with a forged token must
     * not reach the actuator. This is what proves the actuator has no path of
     * its own rather than merely not having been called. */
    {
        sentinel_decision forged = allow_d;
        forged.actuator_token ^= 0xdeadbeefULL;
        before = actuator_invocations();
        int rc = actuator_fire(&forged, 200);
        checks++;
        int ok = (rc == -1) && (actuator_invocations() == before);
        if (!ok) failures++;
        printf("%-46s %s  reason=%-42s calls=%lu\n",
               "negative control: forged allow token",
               ok ? "PASS" : "FAIL", "actuator refused", actuator_invocations() - before);
    }

    printf("\n%s (%d/%d)\n", failures == 0 ? "ALL ROWS PASSED" : "ROWS FAILED",
           checks - failures, checks);

    ratify_string_free(root_id);
    sentinel_free(ctx);
    ratify_agent_free(agent);
    ratify_human_root_free(root);
    (void)err;
    return failures ? 1 : 0;
}
