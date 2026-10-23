//! SPEC-v2 §2.7: every error a public v2 API returns carries exactly one
//! class from the closed list. Mirrors Go `TestV2PublicAPIErrorsAreClassified`
//! (errors_v2_public_test.go): each public entry point is called with an
//! input it must reject, and the class is asserted exactly wherever the Go
//! reference fixes it, so the Rust class matches the reference class for the
//! same input.
//!
//! Rust errors always carry a class, so "unclassified" cannot occur; the
//! check that matters is equality with the reference. Signing APIs return
//! [`V2SignError`], whose class is [`V2SignError::class`]; the claim store's
//! finalization returns [`V2StoreError`], whose class must be present.
//!
//! Go entries that Rust's types make unrepresentable are listed in
//! `NOT_REPRESENTABLE` with the reason, so the row count stays exact.

mod v2_status_common;
mod v2_verify_common;

use std::sync::Arc;
use std::time::Duration;

use ratify_protocol::v2::reference::{JournalStore, Store, TestOnlyChallengeIssuanceStore};
use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridPrivateKey, HybridPublicKey, HybridSignature};
use v2_verify_common::*;

use V2ErrorClass::*;

/// Go entries with no Rust counterpart, and why.
const NOT_REPRESENTABLE: &[(&str, &str)] = &[
    (
        "V2ReleasedDecision.Receipt",
        "a V2ReleasedDecision is only constructed by a successful release, so an invalid one cannot exist",
    ),
];

fn empty_key() -> HybridPublicKey {
    HybridPublicKey { ed25519: vec![], ml_dsa_65: vec![] }
}

fn empty_sig() -> HybridSignature {
    HybridSignature { ed25519: vec![], ml_dsa_65: vec![] }
}

fn empty_private() -> HybridPrivateKey {
    HybridPrivateKey::from_components(vec![], vec![])
}

fn zero_cert() -> DelegationCertV2 {
    DelegationCertV2 {
        version: 0,
        cert_id: String::new(),
        issuer_id: String::new(),
        issuer_pub_key: empty_key(),
        subject_id: String::new(),
        subject_pub_key: empty_key(),
        scope: vec![],
        constraints: vec![],
        issued_at: 0,
        expires_at: 0,
        signature: empty_sig(),
    }
}

fn zero_bundle() -> ProofBundleV2 {
    ProofBundleV2 {
        version: 0,
        verifier_id: String::new(),
        agent_id: String::new(),
        agent_pub_key: empty_key(),
        delegations: vec![],
        delegation_digest: vec![],
        challenge: vec![],
        challenge_at: 0,
        challenge_sig: empty_sig(),
        session_context: None,
        stream_id: None,
        stream_seq: None,
    }
}

fn zero_list() -> RevocationListV2 {
    RevocationListV2 {
        version: 0,
        issuer_id: String::new(),
        updated_at: 0,
        next_update: 0,
        sequence: 0,
        revoked: vec![],
        signature: empty_sig(),
    }
}

fn zero_push() -> RevocationPushV2 {
    RevocationPushV2 { version: 0, issuer_id: String::new(), sequence: 0, pushed_at: 0, revoked: vec![], signature: empty_sig() }
}

fn zero_rotation() -> KeyRotationStatementV2 {
    KeyRotationStatementV2 {
        version: 0,
        authority_id: String::new(),
        recovery_epoch: 0,
        role: String::new(),
        sequence: 0,
        previous_statement_hash: vec![],
        old_key: empty_key(),
        new_key: empty_key(),
        old_key_id: String::new(),
        new_key_id: String::new(),
        issued_at: 0,
        not_before: 0,
        old_signature: empty_sig(),
        new_signature: empty_sig(),
    }
}

fn zero_rotation_state() -> KeyRotationV2State {
    KeyRotationV2State {
        authority_id: String::new(),
        recovery_epoch: 0,
        role: String::new(),
        sequence: 0,
        head_hash: vec![],
        current_key: empty_key(),
        used_key_ids: vec![],
    }
}

fn zero_witness() -> WitnessEntryV2 {
    WitnessEntryV2 {
        version: 0,
        log_id: String::new(),
        sequence: 0,
        prev_hash: vec![],
        entry_data: vec![],
        timestamp: 0,
        witness_id: String::new(),
        signature: empty_sig(),
    }
}

fn zero_transaction() -> TransactionReceiptV2 {
    TransactionReceiptV2 {
        version: 0,
        transaction_id: String::new(),
        created_at: 0,
        terms_schema_uri: String::new(),
        terms_canonical_json: vec![],
        parties: vec![],
        party_signatures: vec![],
    }
}

fn zero_receipt() -> VerificationReceiptV2 {
    VerificationReceiptV2 {
        version: 0,
        log_id: String::new(),
        sequence: 0,
        verifier_id: String::new(),
        agent_id: String::new(),
        human_id: String::new(),
        bundle_hash: String::new(),
        issuer_ids: vec![],
        decision: String::new(),
        decision_reason: String::new(),
        identity_status: String::new(),
        trust_assessment: String::new(),
        status_assessment: String::new(),
        challenge_assessment: String::new(),
        constraint_evaluators: vec![],
        context_assessment: String::new(),
        context_policy_digest: None,
        verified_at: 0,
        required_scope: String::new(),
        granted_scope: vec![],
        status_evidence: vec![],
        previous_receipt_hash: vec![],
        signature: empty_sig(),
    }
}

fn zero_progress() -> V2EvaluationProgress {
    V2EvaluationProgress {
        trust_assessment: String::new(),
        status_assessment: String::new(),
        context_assessment: String::new(),
        context_policy_digest: None,
        status_evidence: vec![],
    }
}

/// Go `failingJournalStoreV2`. A Rust store error always carries a class; a
/// journal that cannot be loaded or committed is `status_object_rejected`
/// (§2.7), so that is the class this store reports.
struct FailingJournalStore;

impl SecurityJournalStoreV2 for FailingJournalStore {
    fn load(&self, _: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)> {
        Err(V2Error::new(StatusObjectRejected, "journal backend down"))
    }
    fn compare_and_swap(
        &self,
        _: &V2Context,
        _: &SecurityJournalHeadV2,
        _: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        Err(SecurityJournalStoreErrorV2::Failed(V2Error::new(StatusObjectRejected, "journal backend down")))
    }
}

/// Go `failingSignerV2`: reports a key and fails every signing request.
struct FailingSigner(HybridPublicKey);

impl SignerV2 for FailingSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.0.clone()
    }
    fn mode_v2(&self) -> SignerModeV2 {
        SignerModeV2::Direct
    }
    fn sign_v2(&self, _: &V2Context, _: &SignRequestV2) -> V2SignResult<HybridSignature> {
        Err(V2SignError::Provider("hardware signer unavailable".into()))
    }
}

struct FixedClock(i64);

impl V2AuthoritativeClock for FixedClock {
    fn authoritative_time_v2(&self, _: &V2Context) -> Result<i64, V2StoreError> {
        Ok(self.0)
    }
}

fn class<T>(r: V2Result<T>) -> Option<V2ErrorClass> {
    r.err().map(|e| e.class)
}

fn sign_class<T>(r: V2SignResult<T>) -> Option<V2ErrorClass> {
    r.err().map(|e| e.class())
}

/// A preflight and claim of a verifier-ordering vector, for the APIs that
/// take the evaluator capability.
fn claimed_token(store: &Store) -> (ProofBundleV2, V2PreflightResult, V2VerifyRequest, V2EvaluationToken) {
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"]).into_iter().find(|v| s(&v["name"]) == "allow_context_not_required").expect("vector");
    let wire = unb64(&f["bundles_b64"][s(&v["bundle"])]);
    let counts = Arc::new(Counts::default());
    let (req, _, _) = build_verify_request(&v, wire.clone(), &counts);
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    let preflight = preflight_proof_bundle_v2(
        &bundle,
        req.expected.as_ref(),
        req.context_policy.as_ref(),
        &req.required_scope,
        &req.verifier_namespace,
        req.replay_epoch,
        req.now,
        req.max_challenge_age_seconds,
        req.future_skew_seconds,
    )
    .expect("preflight");
    let (_, _, token) = claim_proof_bundle_v2(
        &V2Context::background(),
        store,
        &bundle,
        &preflight,
        &req.verifier_namespace,
        req.replay_epoch,
        req.now,
    )
    .expect("claim");
    (bundle, preflight, req, token.expect("token"))
}

#[test]
fn v2_public_api_errors_are_classified() {
    let (public, private) = generate_hybrid_keypair();
    let (other, _) = generate_hybrid_keypair();
    let key_id = key_id_v2(&public).unwrap();
    let ctx = V2Context::background();
    let (cancelled, handle) = ctx.with_cancel();
    handle.cancel();
    let garbage: &[u8] = br#"{"version":2}"#;
    let bad_key = HybridPublicKey { ed25519: vec![0; 3], ml_dsa_65: vec![] };
    let policy = RevocationStatusPolicyV2 { max_list_lifetime_seconds: 3600, max_status_age_seconds: 3600, clock_skew_seconds: 5 };
    let list = RevocationListV2 {
        version: 2,
        issuer_id: key_id.clone(),
        updated_at: 100,
        next_update: 200,
        sequence: 1,
        revoked: vec![],
        signature: empty_sig(),
    };
    let push = RevocationPushV2 {
        version: 2,
        issuer_id: key_id.clone(),
        sequence: 1,
        pushed_at: 100,
        revoked: vec![RevokedCertV2 { cert_id: "c1".into() }],
        signature: empty_sig(),
    };
    let state = RevocationStatusStateV2 {
        issuer_id: key_id.clone(),
        status_key_epoch: 1,
        status_key_id: key_id.clone(),
        ..Default::default()
    };
    let failing_signer = FailingSigner(public.clone());

    // A publisher over a journal that records the issuer under a non-status
    // role and the status key for its epoch.
    let journal = JournalStore::new().unwrap();
    let (status_public, status_private) = generate_hybrid_keypair();
    record_security_key_role_v2(&ctx, &journal, "issuer", &public).unwrap();
    configure_status_key_epoch_v2(&ctx, &journal, &key_id, 1, &status_public).unwrap();
    let publisher =
        new_v2_status_publisher_with_key(&ctx, &journal, &public, &status_private, 3600)
            .expect("publisher");

    let store = Store::new(1_800_000_000, 30, "0123456789abcdef0123456789abcdef", &private).unwrap();
    let (bundle, preflight, req, token) = claimed_token(&store);
    let mut altered = bundle.clone();
    altered.challenge_at -= 1;

    let rows: Vec<(&str, Option<V2ErrorClass>, Option<V2ErrorClass>)> = vec![
        // Decoders and archival verification.
        ("DecodeDelegationCertV2", Some(Malformed), class(decode_delegation_cert_v2(garbage))),
        ("DecodeProofBundleV2", Some(Malformed), class(decode_proof_bundle_v2(garbage))),
        ("DecodeRevocationListV2", Some(Malformed), class(decode_revocation_list_v2(garbage))),
        ("DecodeRevocationPushV2", Some(Malformed), class(decode_revocation_push_v2(garbage))),
        ("DecodeKeyRotationStatementV2", Some(Malformed), class(decode_key_rotation_statement_v2(garbage))),
        ("DecodeWitnessEntryV2", Some(Malformed), class(decode_witness_entry_v2(garbage))),
        ("DecodeTransactionReceiptV2", Some(Malformed), class(decode_transaction_receipt_v2(garbage))),
        ("DecodeVerificationReceiptV2", Some(Malformed), class(decode_verification_receipt_v2(garbage))),
        ("DecodeVerificationReceiptBodyV2", Some(Malformed), class(decode_verification_receipt_body_v2(garbage))),
        ("DecodeV2CheckpointAcknowledgement", Some(Malformed), class(decode_v2_checkpoint_acknowledgement(garbage))),
        ("DecodeV2StatusEvidenceBatch", Some(Malformed), class(decode_v2_status_evidence_batch(garbage))),
        (
            "ImportSecurityJournalSnapshotV2",
            Some(Malformed),
            class(import_security_journal_snapshot_v2(garbage, &SecurityJournalHeadV2::default())),
        ),
        ("ConstraintV2.UnmarshalJSON", Some(Malformed), class(ConstraintV2::decode(br#"{"type":"time_window"}"#))),
        (
            "ConstraintV2.MarshalJSON",
            Some(Malformed),
            class(ConstraintV2 { kind: CONSTRAINT_TIME_WINDOW.into(), ..Default::default() }.canonical_json()),
        ),
        ("VerifyArchivalDelegationCertV2", Some(Malformed), class(verify_archival_delegation_cert_v2(garbage))),
        (
            "VerifyArchivalRevocationListV2",
            Some(Malformed),
            class(verify_archival_revocation_list_v2(garbage, &key_id, &public)),
        ),
        (
            "VerifyArchivalRevocationPushV2",
            Some(Malformed),
            class(verify_archival_revocation_push_v2(garbage, &key_id, &public)),
        ),
        (
            "VerifyArchivalKeyRotationStatementV2",
            Some(Malformed),
            class(verify_archival_key_rotation_statement_v2(garbage)),
        ),
        ("VerifyArchivalWitnessEntryV2", Some(Malformed), class(verify_archival_witness_entry_v2(garbage, &public))),
        (
            "VerifyArchivalVerificationReceiptV2",
            Some(Malformed),
            class(verify_archival_verification_receipt_v2(garbage, &public)),
        ),
        (
            "VerifyArchivalTransactionReceiptV2",
            Some(Malformed),
            class(verify_archival_transaction_receipt_v2(garbage)),
        ),
        // Encoders, digests and identifiers.
        ("KeyIDV2", Some(Malformed), class(key_id_v2(&bad_key))),
        ("BundleHashV2", Some(Malformed), class(bundle_hash_v2(&zero_bundle()))),
        ("EncodeDelegationCertV2", Some(Malformed), class(encode_delegation_cert_v2(&zero_cert()))),
        ("EncodeProofBundleV2", Some(Malformed), class(encode_proof_bundle_v2(&zero_bundle()))),
        ("EncodeRevocationListV2", Some(Malformed), class(encode_revocation_list_v2(&zero_list()))),
        ("EncodeRevocationPushV2", Some(Malformed), class(encode_revocation_push_v2(&zero_push()))),
        ("EncodeKeyRotationStatementV2", Some(Malformed), class(encode_key_rotation_statement_v2(&zero_rotation()))),
        ("EncodeWitnessEntryV2", Some(Malformed), class(encode_witness_entry_v2(&zero_witness()))),
        ("EncodeTransactionReceiptV2", None, class(encode_transaction_receipt_v2(&zero_transaction()))),
        ("EncodeVerificationReceiptV2", Some(Malformed), class(encode_verification_receipt_v2(&zero_receipt()))),
        (
            "EncodeV2CheckpointAcknowledgement",
            Some(Malformed),
            class(encode_v2_checkpoint_acknowledgement(&V2CheckpointAcknowledgement::default())),
        ),
        (
            "EncodeV2StatusEvidenceBatch",
            Some(Malformed),
            class(encode_v2_status_evidence_batch(&V2StatusEvidenceBatch {
                objects: vec![V2StatusEvidenceObject { object_type: 9, wire: vec![] }],
            })),
        ),
        ("VerificationReceiptV2Body", Some(Malformed), class(verification_receipt_v2_body(&zero_receipt()))),
        ("VerificationReceiptV2Digest", Some(Malformed), class(verification_receipt_v2_digest(&zero_receipt()))),
        ("WitnessEntryV2Digest", Some(Malformed), class(witness_entry_v2_digest(&zero_witness()))),
        ("KeyRotationStatementV2Digest", Some(Malformed), class(key_rotation_statement_v2_digest(&zero_rotation()))),
        (
            "TransactionReceiptV2SignBytes",
            Some(Malformed),
            class(transaction_receipt_v2_sign_bytes(&zero_transaction())),
        ),
        (
            "StatementBodyDigestV2 unregistered code",
            Some(UnsupportedObjectType),
            class(statement_body_digest_v2(0x0001, b"{}")),
        ),
        ("StatementBodyDigestV2 bad body", Some(Malformed), class(statement_body_digest_v2(0x0006, b"{}"))),
        (
            "StatusEvidenceDigest unregistered code",
            Some(UnsupportedObjectType),
            class(status_evidence_digest_v2(0x0001, StatusEvidenceObjectV2::List(&zero_list()))),
        ),
        (
            "StatusEvidenceDigest wrong value",
            Some(Malformed),
            class(status_evidence_digest_v2(0x0003, StatusEvidenceObjectV2::Push(&zero_push()))),
        ),
        ("ChallengeClaimDigestV2", Some(Malformed), class(challenge_claim_digest_v2(b"short"))),
        ("ProtocolClaimIDV2 namespace", Some(ConfigurationInvalid), class(protocol_claim_id_v2("", 0, &[0; 32]))),
        ("ProtocolClaimIDV2 challenge", Some(Malformed), class(protocol_claim_id_v2("ns", 0, b"short"))),
        ("ProtocolClaimIDFromDigestV2", Some(Malformed), class(protocol_claim_id_from_digest_v2("ns", 0, b"short"))),
        ("DecodePayloadDigest", Some(Malformed), class(decode_payload_digest_v2(Some("!")))),
        ("BuildOperationContextV2", Some(InvalidRequiredScope), class(operation_context_v2_bytes(&OperationContextV2::default()))),
        (
            "BuildSessionContextV2",
            Some(ConfigurationInvalid),
            class(build_session_context_v2(&SessionContextV2Inputs::default())),
        ),
        (
            "BuildV2RateReservationBatch",
            Some(Malformed),
            class(build_v2_rate_reservation_batch(&[V2DeferredConstraint {
                kind: CONSTRAINT_MAX_RATE.into(),
                canonical_json: garbage.to_vec(),
                ..Default::default()
            }])),
        ),
        // Signing.
        (
            "NewV2StatusPublisherWithKey",
            Some(ConfigurationInvalid),
            class(new_v2_status_publisher_with_key(&ctx, &journal, &public, &empty_private(), 3600)),
        ),
        ("SignDelegationCertV2", Some(Malformed), sign_class(sign_delegation_cert_v2(&zero_cert(), &private))),
        (
            "SignDelegationCertV2WithSigner failing signer",
            None,
            sign_class(sign_delegation_cert_v2_with_signer(&ctx, &zero_cert(), &failing_signer)),
        ),
        (
            "SignProofBundleV2 agent key binding",
            Some(KeyIdMismatch),
            sign_class(sign_proof_bundle_v2(&zero_bundle(), &private)),
        ),
        (
            "SignProofBundleV2",
            Some(Malformed),
            sign_class(sign_proof_bundle_v2(
                &ProofBundleV2 { agent_id: key_id.clone(), agent_pub_key: public.clone(), ..zero_bundle() },
                &private,
            )),
        ),
        (
            "SignRevocationListV2 issuer binding",
            Some(StatusKeyBindingMismatch),
            sign_class(sign_revocation_list_v2(&list, "other", &public, &private)),
        ),
        (
            "SignRevocationListV2 status key binding",
            Some(StatusKeyBindingMismatch),
            sign_class(sign_revocation_list_v2(&list, &key_id, &other, &private)),
        ),
        (
            "SignRevocationListV2WithSigner failing signer",
            Some(ConfigurationInvalid),
            sign_class(sign_revocation_list_v2_with_signer(&ctx, &list, &key_id, &public, &failing_signer)),
        ),
        (
            "SignRevocationListV2WithSigner cancelled",
            Some(EvaluationCancelled),
            sign_class(sign_revocation_list_v2_with_signer(&cancelled, &list, &key_id, &public, &failing_signer)),
        ),
        (
            "SignRevocationPushV2 issuer binding",
            Some(StatusKeyBindingMismatch),
            sign_class(sign_revocation_push_v2(&push, "other", &public, &private)),
        ),
        (
            "SignKeyRotationStatementV2",
            Some(Malformed),
            sign_class(sign_key_rotation_statement_v2(&zero_rotation(), &private, &private)),
        ),
        ("SignWitnessEntryV2", Some(Malformed), sign_class(sign_witness_entry_v2(&zero_witness(), &private))),
        (
            "SignVerificationReceiptV2",
            Some(Malformed),
            sign_class(sign_verification_receipt_v2(&zero_receipt(), &private)),
        ),
        (
            "SignPreparedVerificationReceiptV2",
            Some(ConfigurationInvalid),
            sign_class(sign_prepared_verification_receipt_v2(garbage, &ReceiptV2Head::default(), &private)),
        ),
        (
            "BindVerificationReceiptBodyV2",
            Some(ConfigurationInvalid),
            class(bind_verification_receipt_body_v2(garbage, &ReceiptV2Head::default())),
        ),
        (
            "SignTransactionReceiptPartyV2",
            None,
            sign_class(sign_transaction_receipt_party_v2(&zero_transaction(), "p", &private)),
        ),
        // Signature and object verification.
        (
            "VerifyDelegationCertV2Signature",
            Some(Malformed),
            class(verify_delegation_cert_v2_signature(&zero_cert())),
        ),
        (
            "VerifyProofBundleV2Signatures",
            Some(Malformed),
            class(verify_proof_bundle_v2_signatures(&zero_bundle())),
        ),
        (
            "VerifyRevocationListV2Signature",
            Some(Malformed),
            class(verify_revocation_list_v2_signature(&zero_list(), &key_id, &public)),
        ),
        (
            "VerifyRevocationPushV2Signature",
            Some(StatusKeyBindingMismatch),
            class(verify_revocation_push_v2_signature(&push, "other", &public)),
        ),
        (
            "VerifyKeyRotationStatementV2",
            None,
            class(verify_key_rotation_statement_v2(&zero_rotation(), &zero_rotation_state(), 0, 0)),
        ),
        (
            "VerifyWitnessEntryV2",
            Some(Malformed),
            class(verify_witness_entry_v2(&zero_witness(), &WitnessV2Head::default(), &public)),
        ),
        (
            "VerifyVerificationReceiptV2",
            Some(Malformed),
            class(verify_verification_receipt_v2(&zero_receipt(), &public, &ReceiptV2Head::default())),
        ),
        (
            "VerifyTransactionReceiptV2Signatures",
            None,
            class(verify_transaction_receipt_v2_signatures(&zero_transaction())),
        ),
        (
            "CheckVerificationReceiptV2BundleBinding",
            None,
            class(check_verification_receipt_v2_bundle_binding(&zero_receipt(), &zero_bundle())),
        ),
        // Key rotation journal.
        ("NewKeyRotationV2Journal", Some(ConfigurationInvalid), class(new_key_rotation_v2_journal("", -1, "", &bad_key))),
        (
            "AcceptKeyRotationStatementV2",
            None,
            class(
                accept_key_rotation_statement_v2(
                    &zero_rotation(),
                    &KeyRotationV2Journal { state: zero_rotation_state(), accepted: vec![], frozen: false },
                    0,
                    0,
                )
                .1,
            ),
        ),
        (
            "RecoverKeyRotationV2",
            None,
            class(recover_key_rotation_v2(
                &KeyRotationV2Journal { state: zero_rotation_state(), accepted: vec![], frozen: false },
                0,
                &bad_key,
            )),
        ),
        // Status reducer and SecurityJournalV2 operations (§5.4, §6.6).
        (
            "TransitionRevocationStatusEpochV2",
            Some(StatusObjectRejected),
            class(transition_revocation_status_epoch_v2(&state, &key_id, 3, &other)),
        ),
        (
            "TransitionRevocationStatusEpochV2 reused key",
            Some(StatusObjectRejected),
            class(transition_revocation_status_epoch_v2(&state, &key_id, 2, &public)),
        ),
        (
            "ApplyRevocationListV2 unsigned",
            Some(InvalidSignature),
            class(apply_revocation_list_v2(&state, &list, &key_id, 1, &public, &policy, 150)),
        ),
        (
            "ApplyRevocationPushV2 unsigned",
            Some(InvalidSignature),
            class(apply_revocation_push_v2(&state, &push, &key_id, 1, &public, &policy, 150)),
        ),
        (
            "RevocationStatusForCertV2",
            None,
            class(revocation_status_for_cert_v2(&state, &key_id, "", 1, &public, &policy, 150)),
        ),
        (
            "RecordSecurityKeyRoleV2",
            Some(StatusObjectRejected),
            class(record_security_key_role_v2(&ctx, &FailingJournalStore, "verifier", &public)),
        ),
        (
            "RecordSecurityKeyRoleV2 status role",
            Some(StatusObjectRejected),
            class(record_security_key_role_v2(&ctx, &FailingJournalStore, "status", &public)),
        ),
        (
            "ConfigureStatusKeyEpochV2",
            Some(StatusObjectRejected),
            class(configure_status_key_epoch_v2(&ctx, &FailingJournalStore, &key_id, 1, &public)),
        ),
        (
            "ApplyRevocationListToJournalV2",
            Some(StatusObjectRejected),
            class(apply_revocation_list_to_journal_v2(&ctx, &FailingJournalStore, &list, &key_id, 1, &public, &policy, 150)),
        ),
        (
            "ApplyRevocationPushToJournalV2",
            Some(StatusObjectRejected),
            class(apply_revocation_push_to_journal_v2(&ctx, &FailingJournalStore, &push, &key_id, 1, &public, &policy, 150)),
        ),
        (
            "RevocationStatusFromJournalV2",
            Some(StatusObjectRejected),
            class(revocation_status_from_journal_v2(&ctx, &FailingJournalStore, &key_id, "c1", 1, &public, &policy, 150)),
        ),
        ("RegisterKeyRoleV2", Some(StatusObjectRejected), {
            let mut j = empty_security_journal_v2();
            class(register_key_role_v2(&mut j, "nonsense", &public))
        }),
        ("RegisterStatusKeyEpochV2", Some(StatusObjectRejected), {
            let mut j = empty_security_journal_v2();
            class(register_status_key_epoch_v2(&mut j, &key_id, 0, &public))
        }),
        (
            "ValidateSecurityJournalV2",
            Some(Malformed),
            class(validate_security_journal_v2(&SecurityJournalV2::default())),
        ),
        (
            "ValidateSecurityJournalTransitionV2",
            None,
            class(validate_security_journal_transition_v2(&empty_security_journal_v2(), &SecurityJournalV2::default())),
        ),
        (
            "ExportSecurityJournalSnapshotV2",
            Some(ConfigurationInvalid),
            class(export_security_journal_snapshot_v2(&SecurityJournalV2::default())),
        ),
        (
            "MigrateSecurityJournalV2",
            Some(ConfigurationInvalid),
            class(migrate_security_journal_v2(&SecurityJournalV2::default())),
        ),
        (
            "NewV2StatusPublisher",
            Some(ConfigurationInvalid),
            class(new_v2_status_publisher(&ctx, &FailingJournalStore, &public, Arc::new(failing_signer), 0)),
        ),
        (
            "V2StatusPublisher.Heartbeat",
            Some(ConfigurationInvalid),
            sign_class(publisher.heartbeat(&ctx, &V2StatusPublisherState::default(), 1)),
        ),
        (
            "V2StatusPublisher.Revoke",
            Some(ConfigurationInvalid),
            sign_class(publisher.revoke(&ctx, &V2StatusPublisherState::default(), &[], 1)),
        ),
        ("V2StatusPublisher.Genesis", Some(ConfigurationInvalid), sign_class(publisher.genesis(&ctx, -1))),
        // Verifier configuration, preflight, claim and evaluation (§6, §7).
        ("NewV2ContextPolicy", Some(ConfigurationInvalid), class(V2ContextPolicy::new("", true, &[], &[]))),
        (
            "NewConstraintEvaluatorRegistryV2",
            Some(ConfigurationInvalid),
            class(ConstraintEvaluatorRegistryV2::new(Duration::ZERO, vec![])),
        ),
        (
            "ConstraintProfileDigestV2",
            Some(ConfigurationInvalid),
            class(constraint_profile_digest_v2(&ConstraintProfileDescriptorV2 { profile: String::new(), kind: String::new() })),
        ),
        (
            "EvaluateReceiverAudienceV2",
            Some(ConfigurationInvalid),
            class(evaluate_receiver_audience_v2(&[], "", &[], -1, 0)),
        ),
        (
            "PreflightProofBundleV2",
            None,
            class(preflight_proof_bundle_v2(&zero_bundle(), None, None, "data:read", "ns", 0, 0, 0, 0)),
        ),
        (
            "ValidateProofBundleV2Preflight",
            None,
            class(validate_proof_bundle_v2_preflight(
                &zero_bundle(),
                &ExpectedChallengeV2::default(),
                "data:read",
                "ns",
                0,
                0,
                0,
                0,
            )),
        ),
        (
            "ClaimProofBundleV2",
            Some(ConfigurationInvalid),
            class(claim_proof_bundle_v2(
                &ctx,
                &store,
                &altered,
                &preflight,
                &req.verifier_namespace,
                req.replay_epoch,
                req.now,
            )),
        ),
        (
            "FinalizeClaimProofBundleV2",
            Some(ConfigurationInvalid),
            finalize_claim_proof_bundle_v2(&ctx, &store, &token, b"{}", b"{}").err().map(|e| {
                e.class().expect("finalization errors carry a class")
            }),
        ),
        (
            "ResolveClaimProofBundleV2AfterAudience",
            Some(ConfigurationInvalid),
            class(resolve_claim_proof_bundle_v2_after_audience(&token, &[])),
        ),
        (
            "ResolveClaimProofBundleV2AfterRate",
            Some(ConfigurationInvalid),
            class(resolve_claim_proof_bundle_v2_after_rate(&ctx, None, &token)),
        ),
        ("ValidateV2EvaluationProgress", Some(Malformed), class(validate_v2_evaluation_progress(&zero_progress()))),
        (
            "V2EvaluationInterruptedResult",
            Some(ConfigurationInvalid),
            class(v2_evaluation_interrupted_result(&V2ChallengeClaim::default(), -1, &zero_progress())),
        ),
        ("RecoverInterruptedClaimV2", Some(ConfigurationInvalid), class(recover_interrupted_claim_v2(&ctx, &store, ""))),
        (
            "IssueChallengeV2",
            Some(ConfigurationInvalid),
            class(
                V2ChallengeIssuer {
                    clock: Arc::new(FixedClock(1_800_000_000)),
                    store: Arc::new(TestOnlyChallengeIssuanceStore::new()),
                    random: None,
                }
                .issue_challenge_v2(&ctx, &V2ChallengeIssueRequest::default()),
            ),
        ),
        // Go passes a nil store (configuration_invalid), which Rust's
        // reference type rules out; a presented challenge that is not 32
        // bytes is expected_challenge_unavailable in both.
        (
            "LoadExpectedChallengeV2",
            Some(ExpectedChallengeUnavailable),
            class(load_expected_challenge_v2(&ctx, &TestOnlyChallengeIssuanceStore::new(), "ns", 0, &[])),
        ),
        ("CheckV2StreamSequence", Some(StreamSequenceMismatch), class(check_v2_stream_sequence(true, 5, 5))),
        (
            "VerifyTransactionReceiptV2",
            Some(ConfigurationInvalid),
            class(verify_transaction_receipt_v2(
                &ctx,
                &TransactionVerifyRequestV2 { now: -1, ..Default::default() },
                &TransactionVerifySourcesV2::default(),
            )),
        ),
    ];

    let mut failures = Vec::new();
    for (name, want, got) in &rows {
        match (want, got) {
            (_, None) => failures.push(format!("{name}: bad input was accepted")),
            (Some(w), Some(g)) if w != g => failures.push(format!("{name}: class {g}, want {w}")),
            _ => {}
        }
    }
    assert!(failures.is_empty(), "{} misclassified:\n{}", failures.len(), failures.join("\n"));
    // Every Go entry point is either exercised here or has no Rust
    // counterpart (errors_v2_public_test.go lists 117).
    assert_eq!(rows.len() + NOT_REPRESENTABLE.len(), 117);

    // The live verifier reports a listed class in its outcome as well.
    // Bounded decode precedes the claim-store check (SPEC-v2 §6.2), so an
    // undecodable bundle without a claim store is malformed.
    let outcome = verify_proof_bundle_v2(
        &ctx,
        &V2VerifyRequest { bundle: garbage.to_vec(), ..Default::default() },
        &V2VerifyCallbacks::default(),
    );
    assert_eq!(outcome.stage, V2VerifyStage::Preflight);
    assert_eq!(outcome.error_class, Some(Malformed));
}
