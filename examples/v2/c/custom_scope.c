/*
 * Ratify Protocol v2 custom scope and the standard max_count evaluator
 * profile (com.ratifyprotocol.max_count/v1).
 *
 * DEVELOPMENT ONLY. This program uses the in-memory reference stores
 * (ratify_v2_ref_*), compiled only into a test-reference build. A production
 * verifier supplies durable Part B stores and an independent checkpoint
 * through the callback structs (SPEC-v2 §7).
 *
 * Build and run: examples/v2/c/test.sh
 */
#include "example_util.h"

#define START 1800000000LL
#define NAMESPACE "custom-scope"
#define EPOCH 1
#define LOG_ID "00000000000000000000000000000003"
#define CUSTOM_SCOPE "custom:acme:deploy"
#define MAX_COUNT_TYPE "com.ratifyprotocol.max_count"
#define MAX_COUNT_PROFILE "com.ratifyprotocol.max_count/v1"
#define TZDB_VERSION "2025c"

typedef struct {
    const char *root_id;
    const RatifyV2PublicKey *root_key;
} trust_config;

static int32_t resolve_trust(void *user, const RatifyV2CertView *chain, uintptr_t chain_len,
                             int32_t *outcome, RatifyV2PublicKey *root_key) {
    const trust_config *t = user;
    if (strcmp(chain[chain_len - 1].issuer_id, t->root_id) == 0) {
        *outcome = RatifyV2TrustTrusted;
        *root_key = *t->root_key;
    } else {
        *outcome = RatifyV2TrustUntrusted;
    }
    return 0;
}

static int32_t fetch_status(void *user, const RatifyV2StatusRequest *request, RatifyV2StatusBatch *out) {
    (void)request;
    out->objects = user;
    out->count = 1;
    return 0;
}

typedef struct {
    RatifyV2RefStore *store;
    RatifyV2KeyPair *agent;
    const RatifyV2IssuanceStoreCallbacks *issuance;
    const RatifyV2VerifyCallbacks *callbacks;
    const RatifyV2ReleaseStoreCallbacks *release;
    const RatifyV2CheckpointCallbacks *checkpoint;
    const RatifyV2ClockCallbacks *clock;
    const RatifyV2PublicKey *verifier_pub;
    const char *root_id, *agent_id, *verifier_id, *agent_json, *status_json, *cert;
} deployment;

/* Verifies one request for `nodes` nodes and releases the result. */
static void attempt(const deployment *d, const char *label, int nodes, const RatifyV2EvaluatorConfig *evaluators) {
    int64_t now;
    CHECK(ratify_v2_ref_store_time(d->store, &now));
    CHECK(ratify_v2_ref_store_control(d->store, 1, now + 1));
    now += 1;
    char *issue_req = format(
        "{\"verifier_namespace\":\"%s\",\"replay_epoch\":%d,\"verifier_id\":\"%s\",\"lifetime_seconds\":120,"
        "\"expected_agent_id\":\"%s\",\"expected_agent_public_key\":%s}",
        NAMESPACE, EPOCH, d->verifier_id, d->agent_id, d->agent_json);
    RatifyV2ClockCallbacks clock = *d->clock;
    RatifyV2Buffer challenge_buf;
    CHECK(ratify_v2_issue_challenge((const uint8_t *)issue_req, strlen(issue_req), &clock, d->issuance, NULL,
                                    &challenge_buf));
    char *challenge = take_string(challenge_buf);
    char challenge_b64[64];
    json_str(challenge, "value_b64", challenge_b64, sizeof challenge_b64);
    char *bundle_in = format(
        "{\"agent_id\":\"%s\",\"agent_pub_key\":%s,\"challenge\":\"%s\",\"challenge_at\":%lld,\"delegations\":[%s],"
        "\"session_context\":null,\"stream_id\":null,\"stream_seq\":null,\"verifier_id\":\"%s\",\"version\":2}",
        d->agent_id, d->agent_json, challenge_b64, (long long)json_int(challenge, "issued_at"), d->cert, d->verifier_id);
    RatifyV2Buffer bundle;
    CHECK(ratify_v2_sign_proof_bundle((const uint8_t *)bundle_in, strlen(bundle_in), d->agent, NULL, &bundle));

    uint8_t challenge_bytes[32];
    b64_decode(challenge_b64, challenge_bytes, sizeof challenge_bytes);
    RatifyV2Buffer expected_buf;
    CHECK(ratify_v2_load_expected_challenge(d->issuance, NAMESPACE, EPOCH, challenge_bytes, 32, &expected_buf));
    char *expected = take_string(expected_buf);
    /* The requested quantity comes from the authenticated request, never
     * from the proof. */
    char *request = format(
        "{\"required_scope\":\"%s\",\"verifier_namespace\":\"%s\",\"replay_epoch\":%d,\"now\":%lld,"
        "\"max_challenge_age_seconds\":300,\"future_skew_seconds\":5,\"tzdb_version\":\"%s\","
        "\"status_keys\":{\"%s\":{\"epoch\":1,\"public_key\":%s}},"
        "\"status_policy\":{\"max_list_lifetime_seconds\":3600,\"max_status_age_seconds\":3600,\"clock_skew_seconds\":5},"
        "\"expected_challenge\":%s,"
        "\"context_policy\":{\"profile\":\"example.custom-scope/v1\",\"require_bound\":false,\"required_fields\":[],"
        "\"expected_session_context_b64\":null},"
        "\"context\":{\"extension_counts\":{\"nodes\":%d}}}",
        CUSTOM_SCOPE, NAMESPACE, EPOCH, (long long)now, TZDB_VERSION, d->root_id, d->status_json, expected, nodes);
    RatifyV2VerifyOutcome outcome;
    RatifyV2Committed *committed = NULL;
    CHECK(ratify_v2_verify_proof_bundle(bundle.ptr, bundle.len, (const uint8_t *)request, strlen(request), evaluators,
                                        d->callbacks, &outcome, NULL, &committed));
    if (outcome.stage != RatifyV2StageCommitted) fail("verify did not commit");

    char *claim_id;
    RatifyV2Buffer body, receipt_buf;
    const char *refusal = NULL;
    CHECK(ratify_v2_committed_claim_id(committed, &claim_id));
    CHECK(ratify_v2_committed_receipt_body(committed, &body));
    CHECK(ratify_v2_ref_store_publish(d->store, claim_id, body.ptr, body.len, &receipt_buf, &refusal));
    int32_t release_status;
    char *release_reason = NULL;
    RatifyV2Released *decision = NULL;
    RatifyV2Slice receipt_wire = {receipt_buf.ptr, receipt_buf.len};
    CHECK(ratify_v2_release_decision(committed, receipt_wire, d->verifier_pub, LOG_ID, d->release, d->checkpoint,
                                     &release_status, &release_reason, &decision));
    if (release_status != RatifyV2ReleaseReleased) fail("release did not release");
    char *verdict, *reason;
    CHECK(ratify_v2_released_string(decision, RatifyV2ReleasedDecision, &verdict));
    CHECK(ratify_v2_released_string(decision, RatifyV2ReleasedReason, &reason));
    printf("%s: decision=%s reason=%s allowed=%s\n", label, verdict, reason,
           ratify_v2_released_allowed(decision, &clock) ? "true" : "false");

    /* The signed receipt names every evaluator profile the claim sealed. */
    RatifyV2Buffer released_receipt;
    CHECK(ratify_v2_released_receipt(decision, &released_receipt));
    char *receipt = take_string(released_receipt);
    const char *refs = strstr(receipt, "\"constraint_evaluators\":[");
    if (refs) {
        const char *end = strchr(refs, ']');
        for (const char *p = strstr(refs, "{"); p && p < end; p = strstr(p + 1, "{")) {
            char digest[128], type[160];
            json_str(p, "profile_digest", digest, sizeof digest);
            json_str(p, "type", type, sizeof type);
            printf("  receipt constraint_evaluators: %s %s\n", type, digest);
        }
    }

    free(receipt);
    ratify_v2_string_free(reason);
    ratify_v2_string_free(verdict);
    ratify_v2_string_free(release_reason);
    ratify_v2_released_free(decision);
    ratify_v2_buffer_free(receipt_buf);
    ratify_v2_buffer_free(body);
    ratify_v2_string_free(claim_id);
    ratify_v2_committed_free(committed);
    free(request);
    free(expected);
    ratify_v2_buffer_free(bundle);
    free(bundle_in);
    free(challenge);
    free(issue_req);
}

int main(void) {
    printf("Ratify Protocol v2 custom scope and max_count profile\n");
    printf("development only: in-memory reference stores\n");

    RatifyV2KeyPair *root, *agent, *status, *verifier;
    CHECK(ratify_v2_keypair_generate(&root, NULL, NULL));
    CHECK(ratify_v2_keypair_generate(&agent, NULL, NULL));
    CHECK(ratify_v2_keypair_generate(&status, NULL, NULL));
    CHECK(ratify_v2_keypair_generate(&verifier, NULL, NULL));
    static RatifyV2PublicKey root_pub, agent_pub, status_pub, verifier_pub;
    CHECK(ratify_v2_keypair_public_key(root, &root_pub));
    CHECK(ratify_v2_keypair_public_key(agent, &agent_pub));
    CHECK(ratify_v2_keypair_public_key(status, &status_pub));
    CHECK(ratify_v2_keypair_public_key(verifier, &verifier_pub));
    char root_id[RATIFY_V2_KEY_ID_BUF_LEN], agent_id[RATIFY_V2_KEY_ID_BUF_LEN], verifier_id[RATIFY_V2_KEY_ID_BUF_LEN];
    CHECK(ratify_v2_keypair_key_id(root, root_id, sizeof root_id));
    CHECK(ratify_v2_keypair_key_id(agent, agent_id, sizeof agent_id));
    CHECK(ratify_v2_keypair_key_id(verifier, verifier_id, sizeof verifier_id));
    char *root_json = key_json(&root_pub), *agent_json = key_json(&agent_pub), *status_json = key_json(&status_pub);

    /* A custom scope is one exact name. Wildcards are invalid. */
    char *wildcard = format(
        "{\"cert_id\":\"custom-scope-cert-1\",\"constraints\":[],\"expires_at\":%lld,\"issued_at\":%lld,"
        "\"issuer_id\":\"%s\",\"issuer_pub_key\":%s,\"scope\":[\"custom:*\"],\"subject_id\":\"%s\","
        "\"subject_pub_key\":%s,\"version\":2}",
        START + 86400, START, root_id, root_json, agent_id, agent_json);
    RatifyV2Buffer refused_buf = {0};
    int32_t refused = ratify_v2_sign_delegation_certificate((const uint8_t *)wildcard, strlen(wildcard), root, NULL,
                                                            &refused_buf);
    printf("issue scope custom:*: refused (%s)\n", ratify_v2_error_class_str(refused));

    /* The certificate carries an extension constraint. Only a verifier that
     * registered the max_count/v1 profile for this type can evaluate it. */
    char *cert_in = format(
        "{\"cert_id\":\"custom-scope-cert-1\",\"constraints\":[{\"params\":{\"counter\":\"nodes\",\"max\":5},"
        "\"type\":\"%s\"}],\"expires_at\":%lld,\"issued_at\":%lld,\"issuer_id\":\"%s\",\"issuer_pub_key\":%s,"
        "\"scope\":[\"%s\"],\"subject_id\":\"%s\",\"subject_pub_key\":%s,\"version\":2}",
        MAX_COUNT_TYPE, START + 86400, START, root_id, root_json, CUSTOM_SCOPE, agent_id, agent_json);
    RatifyV2Buffer cert_buf;
    CHECK(ratify_v2_sign_delegation_certificate((const uint8_t *)cert_in, strlen(cert_in), root, NULL, &cert_buf));
    char *cert = take_string(cert_buf);
    printf("delegation: scope=%s constraint=%s(counter=nodes, max=5)\n", CUSTOM_SCOPE, MAX_COUNT_TYPE);

    char *digest;
    CHECK(ratify_v2_constraint_profile_digest(MAX_COUNT_PROFILE, MAX_COUNT_TYPE, &digest));
    printf("profile: %s digest=%s\n", MAX_COUNT_PROFILE, digest);
    RatifyV2EvaluatorRegistration max_count = {MAX_COUNT_TYPE, MAX_COUNT_PROFILE, RatifyV2EvaluatorStandardMaxCount,
                                               NULL, NULL};
    RatifyV2EvaluatorConfig registry = {1000, &max_count, 1};

    RatifyV2RefJournal *journal_store;
    RatifyV2JournalStoreCallbacks journal;
    CHECK(ratify_v2_ref_journal_new(&journal_store));
    CHECK(ratify_v2_ref_journal_callbacks(journal_store, &journal, NULL, NULL));
    CHECK(ratify_v2_journal_record_key_role(&journal, "issuer", &root_pub));
    CHECK(ratify_v2_journal_configure_status_key(&journal, root_id, 1, &status_pub));
    RatifyV2Buffer list_buf, push_buf, state_buf;
    CHECK(ratify_v2_status_publish(RatifyV2PublishGenesis, &journal, &root_pub, status, NULL, 3600, NULL, 0, NULL, 0,
                                   START, &list_buf, &push_buf, &state_buf));
    ratify_v2_buffer_free(push_buf);
    ratify_v2_buffer_free(state_buf);
    RatifyV2StatusObject status_object = {RatifyV2KindRevocationList, {list_buf.ptr, list_buf.len}};

    RatifyV2RefStore *store;
    CHECK(ratify_v2_ref_store_new(START, 30, LOG_ID, verifier, &store));
    RatifyV2ClaimStoreCallbacks claim_cb;
    RatifyV2ReleaseStoreCallbacks release_cb;
    RatifyV2CheckpointCallbacks checkpoint_cb;
    RatifyV2ClockCallbacks clock_cb;
    CHECK(ratify_v2_ref_store_callbacks(store, 0, &claim_cb, NULL, &release_cb, &checkpoint_cb, &clock_cb));
    RatifyV2RefIssuance *issuance_store;
    RatifyV2IssuanceStoreCallbacks issuance;
    CHECK(ratify_v2_ref_issuance_new(&issuance_store));
    CHECK(ratify_v2_ref_issuance_control(issuance_store, -1, &issuance, NULL));

    trust_config trust_user = {root_id, &root_pub};
    RatifyV2TrustCallbacks trust = {&trust_user, resolve_trust};
    RatifyV2StatusEvidenceCallbacks evidence = {&status_object, fetch_status};
    RatifyV2VerifyCallbacks callbacks = {&claim_cb, &trust, &evidence, &journal, NULL, NULL, NULL};
    deployment d = {store, agent, &issuance, &callbacks, &release_cb, &checkpoint_cb, &clock_cb, &verifier_pub,
                    root_id, agent_id, verifier_id, agent_json, status_json, cert};

    attempt(&d, "request nodes=3", 3, &registry);
    attempt(&d, "request nodes=8", 8, &registry);
    attempt(&d, "request nodes=3 without the profile registered", 3, NULL);

    ratify_v2_ref_issuance_free(issuance_store);
    ratify_v2_ref_store_free(store);
    ratify_v2_buffer_free(list_buf);
    ratify_v2_ref_journal_free(journal_store);
    ratify_v2_string_free(digest);
    free(cert);
    free(cert_in);
    ratify_v2_buffer_free(refused_buf);
    free(wildcard);
    free(root_json);
    free(agent_json);
    free(status_json);
    ratify_v2_keypair_free(root);
    ratify_v2_keypair_free(agent);
    ratify_v2_keypair_free(status);
    ratify_v2_keypair_free(verifier);
    return 0;
}
