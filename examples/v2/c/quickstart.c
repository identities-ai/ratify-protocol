/*
 * Ratify Protocol v2 quickstart: delegate, present, verify, publish, release.
 *
 * DEVELOPMENT ONLY. This program uses the in-memory reference stores
 * (ratify_v2_ref_*: claim store, receipt log, checkpoint, journal and
 * challenge issuance store). They exist for tests and examples and are
 * compiled only into a test-reference build. A production verifier supplies
 * durable Part B stores and an independent checkpoint through the callback
 * structs (SPEC-v2 §7).
 *
 * Build and run: examples/v2/c/test.sh
 */
#include "example_util.h"

#define START 1800000000LL /* fixed clock so the output is reproducible */
#define NAMESPACE "quickstart"
#define EPOCH 1
#define LOG_ID "00000000000000000000000000000001"
#define TZDB_VERSION "2025c" /* the pinned tzdata release (SPEC-v2 §5.2) */

/* Trust is pinned to the complete root public key, never a key ID. */
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

/* The status provider returns signed objects only. */
static int32_t fetch_status(void *user, const RatifyV2StatusRequest *request, RatifyV2StatusBatch *out) {
    (void)request;
    out->objects = user;
    out->count = 1;
    return 0;
}

/* Everything one verification needs. */
typedef struct {
    RatifyV2RefStore *store;
    const RatifyV2IssuanceStoreCallbacks *issuance;
    const RatifyV2VerifyCallbacks *callbacks;
    const char *root_id;
    const char *verifier_id;
    const char *status_json;
    RatifyV2Slice bundle;
    const uint8_t *challenge;
} verifier_config;

/* Loads the issuance record for the presented challenge, then runs the full
 * v2 decision path at the store's current time. */
static RatifyV2VerifyOutcome verify(const verifier_config *v, RatifyV2Committed **committed) {
    RatifyV2Buffer expected_buf;
    CHECK(ratify_v2_load_expected_challenge(v->issuance, NAMESPACE, EPOCH, v->challenge, 32, &expected_buf));
    char *expected = take_string(expected_buf);
    int64_t now;
    CHECK(ratify_v2_ref_store_time(v->store, &now));
    char *request = format(
        "{\"required_scope\":\"payments:send\",\"verifier_namespace\":\"%s\",\"replay_epoch\":%d,\"verifier_id\":\"%s\",\"now\":%lld,"
        "\"max_challenge_age_seconds\":300,\"future_skew_seconds\":5,\"tzdb_version\":\"%s\","
        "\"status_keys\":{\"%s\":{\"epoch\":1,\"public_key\":%s}},"
        "\"status_policy\":{\"max_list_lifetime_seconds\":3600,\"max_status_age_seconds\":3600,\"clock_skew_seconds\":5},"
        "\"expected_challenge\":%s,"
        "\"context_policy\":{\"profile\":\"example.quickstart/v1\",\"require_bound\":false,\"required_fields\":[],"
        "\"expected_session_context_b64\":null},"
        "\"context\":{\"has_amount\":true,\"requested_amount_micros\":12500000,\"requested_currency\":\"USD\"}}",
        NAMESPACE, EPOCH, v->verifier_id, (long long)now, TZDB_VERSION, v->root_id, v->status_json, expected);
    RatifyV2VerifyOutcome outcome;
    *committed = NULL;
    CHECK(ratify_v2_verify_proof_bundle(v->bundle.ptr, v->bundle.len, (const uint8_t *)request, strlen(request), NULL,
                                        v->callbacks, &outcome, NULL, committed));
    free(expected);
    free(request);
    return outcome;
}

int main(void) {
    printf("Ratify Protocol v2 quickstart\n");
    printf("development only: in-memory reference stores\n");

    /* 1. Keys. Every party holds a hybrid Ed25519 + ML-DSA-65 key. The status
     * key is separate from the root key that issues delegations. */
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
    printf("keys: root, agent, status and verifier generated (key IDs are %zu hex characters)\n", strlen(root_id));

    /* 2. The root delegates payments:send to the agent, capped at 50.00 USD
     * per action (amounts are integer micro-units in v2). */
    char *cert_in = format(
        "{\"cert_id\":\"quickstart-cert-1\",\"constraints\":[{\"currency\":\"USD\",\"max_amount_micros\":50000000,"
        "\"type\":\"max_amount\"}],\"expires_at\":%lld,\"issued_at\":%lld,\"issuer_id\":\"%s\",\"issuer_pub_key\":%s,"
        "\"scope\":[\"payments:send\"],\"subject_id\":\"%s\",\"subject_pub_key\":%s,\"version\":2}",
        START + 86400, START, root_id, root_json, agent_id, agent_json);
    RatifyV2Buffer cert_buf;
    CHECK(ratify_v2_sign_delegation_certificate((const uint8_t *)cert_in, strlen(cert_in), root, NULL, &cert_buf));
    char *cert = take_string(cert_buf);
    printf("delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s\n");

    /* 3. Verifier state: the reference store is the claim store, receipt log,
     * checkpoint and authoritative clock. The journal records key roles and
     * the root's status key. */
    RatifyV2RefStore *store;
    CHECK(ratify_v2_ref_store_new(START, 30, LOG_ID, verifier, &store));
    RatifyV2ClaimStoreCallbacks claim_cb;
    RatifyV2ReleaseStoreCallbacks release_cb;
    RatifyV2CheckpointCallbacks checkpoint_cb;
    RatifyV2ClockCallbacks clock_cb;
    CHECK(ratify_v2_ref_store_callbacks(store, 0, &claim_cb, NULL, &release_cb, &checkpoint_cb, &clock_cb));
    RatifyV2RefJournal *journal_store;
    RatifyV2JournalStoreCallbacks journal;
    CHECK(ratify_v2_ref_journal_new(&journal_store));
    CHECK(ratify_v2_ref_journal_callbacks(journal_store, &journal, NULL, NULL));
    CHECK(ratify_v2_journal_record_key_role(&journal, "issuer", &root_pub));
    CHECK(ratify_v2_journal_record_key_role(&journal, "delegation", &agent_pub));
    CHECK(ratify_v2_journal_record_key_role(&journal, "verifier", &verifier_pub));
    CHECK(ratify_v2_journal_configure_status_key(&journal, root_id, 1, &status_pub));

    /* 4. The root's status publisher signs a genesis revocation list (no
     * revocations) under the separate status key. The caller persists the
     * returned state before publishing the list. */
    RatifyV2Buffer list_buf, push_buf, state_buf;
    CHECK(ratify_v2_status_publish(RatifyV2PublishGenesis, &journal, &root_pub, status, NULL, 3600, NULL, 0, NULL, 0,
                                   START, &list_buf, &push_buf, &state_buf));
    ratify_v2_buffer_free(push_buf);
    char *state = take_string(state_buf);
    RatifyV2StatusObject status_object = {RatifyV2KindRevocationList, {list_buf.ptr, list_buf.len}};
    printf("status: genesis list signed by the status key (sequence %lld, %d revoked)\n",
           (long long)json_int(state, "sequence"), strstr(state, "\"revoked\":[]") ? 0 : 1);

    /* 5. The verifier issues a challenge. The helper persists the record
     * before it returns the challenge. */
    RatifyV2RefIssuance *issuance_store;
    RatifyV2IssuanceStoreCallbacks issuance;
    CHECK(ratify_v2_ref_issuance_new(&issuance_store));
    CHECK(ratify_v2_ref_issuance_control(issuance_store, -1, &issuance, NULL));
    char *issue_req = format(
        "{\"verifier_namespace\":\"%s\",\"replay_epoch\":%d,\"verifier_id\":\"%s\",\"lifetime_seconds\":120,"
        "\"expected_agent_id\":\"%s\",\"expected_agent_public_key\":%s}",
        NAMESPACE, EPOCH, verifier_id, agent_id, agent_json);
    RatifyV2Buffer challenge_buf;
    CHECK(ratify_v2_issue_challenge((const uint8_t *)issue_req, strlen(issue_req), &clock_cb, &issuance, NULL,
                                    &challenge_buf));
    char *challenge = take_string(challenge_buf);
    char challenge_b64[64];
    json_str(challenge, "value_b64", challenge_b64, sizeof challenge_b64);
    int64_t issued_at = json_int(challenge, "issued_at"), expires_at = json_int(challenge, "expires_at");
    printf("challenge: issued and persisted, expires in %llds\n", (long long)(expires_at - issued_at));

    /* 6. The agent signs a proof bundle over the challenge. */
    CHECK(ratify_v2_ref_store_control(store, 1, START + 2));
    char *bundle_in = format(
        "{\"agent_id\":\"%s\",\"agent_pub_key\":%s,\"challenge\":\"%s\",\"challenge_at\":%lld,\"delegations\":[%s],"
        "\"session_context\":null,\"stream_id\":null,\"stream_seq\":null,\"verifier_id\":\"%s\",\"version\":2}",
        agent_id, agent_json, challenge_b64, (long long)issued_at, cert, verifier_id);
    RatifyV2Buffer bundle;
    CHECK(ratify_v2_sign_proof_bundle((const uint8_t *)bundle_in, strlen(bundle_in), agent, NULL, &bundle));
    printf("proof: agent signed the presentation (1 delegation)\n");

    /* 7. Verify. */
    uint8_t challenge_bytes[32];
    b64_decode(challenge_b64, challenge_bytes, sizeof challenge_bytes);
    trust_config trust_user = {root_id, &root_pub};
    RatifyV2TrustCallbacks trust = {&trust_user, resolve_trust};
    RatifyV2StatusEvidenceCallbacks evidence = {&status_object, fetch_status};
    RatifyV2VerifyCallbacks callbacks = {&claim_cb, &trust, &evidence, &journal, NULL, NULL, NULL};
    verifier_config v = {store, &issuance, &callbacks, root_id, verifier_id, status_json, {bundle.ptr, bundle.len}, challenge_bytes};
    RatifyV2Committed *committed;
    RatifyV2VerifyOutcome outcome = verify(&v, &committed);
    if (outcome.stage != RatifyV2StageCommitted) fail("verify did not commit");
    printf("verify: stage=committed (not actionable until released)\n");

    /* 8. Publish the signed receipt to the log; the checkpoint acknowledges it. */
    char *claim_id;
    RatifyV2Buffer body, receipt_buf;
    const char *refusal = NULL;
    CHECK(ratify_v2_committed_claim_id(committed, &claim_id));
    CHECK(ratify_v2_committed_receipt_body(committed, &body));
    CHECK(ratify_v2_ref_store_publish(store, claim_id, body.ptr, body.len, &receipt_buf, &refusal));
    ratify_v2_buffer_free(body);
    char *receipt = format("%.*s", (int)receipt_buf.len, (const char *)receipt_buf.ptr);
    int64_t sequence = json_int(receipt, "sequence");
    printf("receipt: published at log sequence %lld\n", (long long)sequence);
    RatifyV2Acknowledgement ack;
    CHECK(checkpoint_cb.get(checkpoint_cb.user, LOG_ID, sequence, &ack));
    printf("checkpoint: acknowledged sequence %lld\n", (long long)ack.sequence);

    /* 9. Release. Only a released decision is actionable. */
    int32_t release_status;
    char *release_reason = NULL;
    RatifyV2Released *decision = NULL;
    RatifyV2Slice receipt_wire = {receipt_buf.ptr, receipt_buf.len};
    CHECK(ratify_v2_release_decision(committed, receipt_wire, &verifier_pub, LOG_ID, &release_cb, &checkpoint_cb,
                                     &release_status, &release_reason, &decision));
    if (release_status != RatifyV2ReleaseReleased) fail("release did not release");
    char *verdict, *reason;
    CHECK(ratify_v2_released_string(decision, RatifyV2ReleasedDecision, &verdict));
    CHECK(ratify_v2_released_string(decision, RatifyV2ReleasedReason, &reason));
    printf("release: status=%s decision=%s reason=%s\n", ratify_v2_release_status_str(release_status), verdict, reason);
    RatifyV2Buffer scope_buf;
    CHECK(ratify_v2_released_granted_scope(decision, &scope_buf));
    char *scope = take_string(scope_buf); /* JSON array of one scope: ["payments:send"] */
    printf("granted scope: %.*s\n", (int)(strlen(scope) - 4), scope + 2);

    /* 10. Gate the side effect on Allowed at the receiver's authoritative time. */
    printf("allowed now: %s\n", ratify_v2_released_allowed(decision, &clock_cb) ? "true" : "false");

    /* 11. Presenting the same proof again is a replay and is never evaluated. */
    CHECK(ratify_v2_ref_store_control(store, 1, START + 3));
    RatifyV2Committed *replay_committed;
    RatifyV2VerifyOutcome replay = verify(&v, &replay_committed);
    printf("replay: stage=%s disposition=%s\n", stage_name(replay.stage), disposition_name(replay.disposition));

    /* 12. The released allow ends at the challenge expiry (an exclusive deadline). */
    CHECK(ratify_v2_ref_store_control(store, 1, expires_at));
    printf("allowed at challenge expiry: %s\n", ratify_v2_released_allowed(decision, &clock_cb) ? "true" : "false");

    ratify_v2_committed_free(replay_committed);
    free(scope);
    ratify_v2_string_free(reason);
    ratify_v2_string_free(verdict);
    ratify_v2_string_free(release_reason);
    ratify_v2_released_free(decision);
    free(receipt);
    ratify_v2_buffer_free(receipt_buf);
    ratify_v2_string_free(claim_id);
    ratify_v2_committed_free(committed);
    ratify_v2_buffer_free(bundle);
    free(bundle_in);
    free(challenge);
    free(issue_req);
    ratify_v2_ref_issuance_free(issuance_store);
    free(state);
    ratify_v2_buffer_free(list_buf);
    ratify_v2_ref_journal_free(journal_store);
    ratify_v2_ref_store_free(store);
    free(cert);
    free(cert_in);
    free(root_json);
    free(agent_json);
    free(status_json);
    ratify_v2_keypair_free(root);
    ratify_v2_keypair_free(agent);
    ratify_v2_keypair_free(status);
    ratify_v2_keypair_free(verifier);
    return 0;
}
