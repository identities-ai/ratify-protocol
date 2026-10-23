//! Panic containment for every `ratify_v2_*` export (SPEC-v2 §1.3): arm the
//! test-only panic hook and call each export; each must return its
//! documented internal-failure or fail-closed value instead of unwinding.
//! The list is checked against the header, so a new export must be added.

#![allow(clippy::unit_arg, unused_unsafe)]

use std::collections::BTreeSet;
use std::ffi::CStr;

use ratify_c::test_hook::arm_before_body;
use ratify_c::*;

/// A zero value for any argument (NULL pointers, zero integers, `None`
/// callbacks, empty structs); the injected panic fires before the body
/// reads it.
fn z<T>() -> T {
    // SAFETY: every ABI argument type is valid when zeroed.
    unsafe { std::mem::zeroed() }
}

/// The armed panic was consumed by the export just called (an export that
/// skipped the guard would leave it armed for this probe).
fn fired() {
    assert_eq!(
        ratify_v2_abi_version(),
        RATIFY_V2_ABI_VERSION,
        "the previous export did not run its guard"
    );
}

const SWEPT: &[&str] = &[
    "ratify_v2_abi_version",
    "ratify_v2_protocol_version",
    "ratify_v2_library_version",
    "ratify_v2_tzdb_version",
    "ratify_v2_error_class_str",
    "ratify_v2_last_error_message",
    "ratify_v2_buffer_free",
    "ratify_v2_string_free",
    "ratify_v2_evaluator_call_expired",
    "ratify_v2_object_decode",
    "ratify_v2_signable_bytes",
    "ratify_v2_signing_message",
    "ratify_v2_mldsa_context",
    "ratify_v2_external_mu",
    "ratify_v2_verify_statement",
    "ratify_v2_delegation_digest",
    "ratify_v2_bundle_hash",
    "ratify_v2_challenge_claim_digest",
    "ratify_v2_claim_id",
    "ratify_v2_claim_id_from_digest",
    "ratify_v2_status_evidence_digest",
    "ratify_v2_statement_body_digest",
    "ratify_v2_object_body_digest",
    "ratify_v2_revoked_set_digest",
    "ratify_v2_receipt_outbox_digest",
    "ratify_v2_security_journal_digest",
    "ratify_v2_verification_receipt_body",
    "ratify_v2_transaction_context_hash",
    "ratify_v2_transaction_party_request_hash",
    "ratify_v2_operation_context_hash",
    "ratify_v2_session_context",
    "ratify_v2_payload_digest_decode",
    "ratify_v2_context_policy_digest",
    "ratify_v2_constraint_profile_digest",
    "ratify_v2_canonical_json",
    "ratify_v2_validate_scopes",
    "ratify_v2_validate_required_scope",
    "ratify_v2_validate_request_context",
    "ratify_v2_evaluate_standard_profile",
    "ratify_v2_challenge_time_current",
    "ratify_v2_check_stream_sequence",
    "ratify_v2_validate_finalization_payload",
    "ratify_v2_valid_release_record_outcome",
    "ratify_v2_cross_sdk_fixture_verify",
    "ratify_v2_keypair_from_seeds",
    "ratify_v2_keypair_generate",
    "ratify_v2_keypair_free",
    "ratify_v2_keypair_public_key",
    "ratify_v2_keypair_key_id",
    "ratify_v2_public_key_id",
    "ratify_v2_public_key_to_json",
    "ratify_v2_key_id",
    "ratify_v2_key_id_check",
    "ratify_v2_verify_object",
    "ratify_v2_proof_bundle_verify_signatures",
    "ratify_v2_verification_receipt_verify",
    "ratify_v2_receipt_bundle_binding_check",
    "ratify_v2_ref_store_new",
    "ratify_v2_ref_store_free",
    "ratify_v2_ref_store_clone",
    "ratify_v2_ref_store_control",
    "ratify_v2_ref_store_time",
    "ratify_v2_ref_store_tamper",
    "ratify_v2_ref_store_abandon",
    "ratify_v2_ref_store_publish",
    "ratify_v2_ref_store_callbacks",
    "ratify_v2_ref_journal_new",
    "ratify_v2_ref_journal_free",
    "ratify_v2_ref_journal_callbacks",
    "ratify_v2_ref_trust_registry_new",
    "ratify_v2_ref_trust_registry_free",
    "ratify_v2_ref_trust_registry_callbacks",
    "ratify_v2_ref_issuance_new",
    "ratify_v2_ref_issuance_free",
    "ratify_v2_ref_issuance_control",
    "ratify_v2_ref_device_new",
    "ratify_v2_ref_device_free",
    "ratify_v2_ref_primary_free",
    "ratify_v2_ref_device_callbacks",
    "ratify_v2_ref_device_op",
    "ratify_v2_ref_device_snapshot",
    "ratify_v2_ref_device_restore",
    "ratify_v2_ref_device_state_projection",
    "ratify_v2_ref_ledger_new",
    "ratify_v2_ref_ledger_free",
    "ratify_v2_ref_ledger_open",
    "ratify_v2_ref_ledger_record",
    "ratify_v2_ref_ledger_execute",
    "ratify_v2_sign_delegation_certificate",
    "ratify_v2_sign_proof_bundle",
    "ratify_v2_sign_revocation_list",
    "ratify_v2_sign_revocation_push",
    "ratify_v2_sign_key_rotation_statement",
    "ratify_v2_sign_witness_entry",
    "ratify_v2_sign_verification_receipt",
    "ratify_v2_sign_prepared_verification_receipt",
    "ratify_v2_sign_transaction_receipt_party",
    "ratify_v2_status_state_new",
    "ratify_v2_status_state_free",
    "ratify_v2_status_state_apply",
    "ratify_v2_status_state_transition_epoch",
    "ratify_v2_status_state_query",
    "ratify_v2_status_state_json",
    "ratify_v2_journal_record_key_role",
    "ratify_v2_journal_configure_status_key",
    "ratify_v2_journal_apply",
    "ratify_v2_journal_status",
    "ratify_v2_journal_genesis",
    "ratify_v2_journal_import",
    "ratify_v2_journal_validate_transition",
    "ratify_v2_journal_migrate",
    "ratify_v2_journal_legacy_encode",
    "ratify_v2_status_publish",
    "ratify_v2_rotation_journal_new",
    "ratify_v2_rotation_journal_free",
    "ratify_v2_rotation_journal_accept",
    "ratify_v2_rotation_journal_recover",
    "ratify_v2_rotation_journal_state",
    "ratify_v2_witness_entry_append",
    "ratify_v2_verification_receipt_append",
    "ratify_v2_archival_verify",
    "ratify_v2_verify_proof_bundle",
    "ratify_v2_claim_proof_bundle",
    "ratify_v2_recover_interrupted_claim",
    "ratify_v2_committed_free",
    "ratify_v2_committed_claim_id",
    "ratify_v2_committed_receipt_body",
    "ratify_v2_committed_receipt_body_digest",
    "ratify_v2_committed_challenge_expires_at",
    "ratify_v2_committed_allow_horizon",
    "ratify_v2_release_decision",
    "ratify_v2_release_status_str",
    "ratify_v2_released_free",
    "ratify_v2_released_string",
    "ratify_v2_released_granted_scope",
    "ratify_v2_released_receipt",
    "ratify_v2_released_times",
    "ratify_v2_released_allowed",
    "ratify_v2_issue_challenge",
    "ratify_v2_load_expected_challenge",
    "ratify_v2_verify_transaction_receipt",
];

#[test]
fn every_v2_export_contains_a_panic() {
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_abi_version() },
        0,
        "ratify_v2_abi_version"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_protocol_version() },
        0,
        "ratify_v2_protocol_version"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { CStr::from_ptr(ratify_v2_library_version()) }
            .to_str()
            .unwrap(),
        "",
        "ratify_v2_library_version"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { CStr::from_ptr(ratify_v2_tzdb_version()) }
            .to_str()
            .unwrap(),
        "",
        "ratify_v2_tzdb_version"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { CStr::from_ptr(ratify_v2_error_class_str(z())) }
            .to_str()
            .unwrap(),
        "internal",
        "ratify_v2_error_class_str"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { CStr::from_ptr(ratify_v2_last_error_message()) }
            .to_str()
            .unwrap(),
        "internal: a panic was caught at the C ABI boundary",
        "ratify_v2_last_error_message"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_buffer_free(z()) };
    fired();
    arm_before_body();
    unsafe { ratify_v2_string_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_evaluator_call_expired(z()) },
        1,
        "ratify_v2_evaluator_call_expired"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_object_decode(z(), z(), z(), z()) },
        -3,
        "ratify_v2_object_decode"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_signable_bytes(z(), z(), z(), z()) },
        -3,
        "ratify_v2_signable_bytes"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_signing_message(z(), z(), z(), z()) },
        -3,
        "ratify_v2_signing_message"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_mldsa_context(z(), z()) },
        -3,
        "ratify_v2_mldsa_context"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_external_mu(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_external_mu"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verify_statement(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_verify_statement"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_delegation_digest(z(), z(), z()) },
        -3,
        "ratify_v2_delegation_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_bundle_hash(z(), z(), z()) },
        -3,
        "ratify_v2_bundle_hash"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_challenge_claim_digest(z(), z(), z()) },
        -3,
        "ratify_v2_challenge_claim_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_claim_id(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_claim_id"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_claim_id_from_digest(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_claim_id_from_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_evidence_digest(z(), z(), z(), z()) },
        -3,
        "ratify_v2_status_evidence_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_statement_body_digest(z(), z(), z(), z()) },
        -3,
        "ratify_v2_statement_body_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_object_body_digest(z(), z(), z(), z()) },
        -3,
        "ratify_v2_object_body_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_revoked_set_digest(z(), z(), z()) },
        -3,
        "ratify_v2_revoked_set_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_receipt_outbox_digest(z(), z(), z()) },
        -3,
        "ratify_v2_receipt_outbox_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_security_journal_digest(z(), z(), z()) },
        -3,
        "ratify_v2_security_journal_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verification_receipt_body(z(), z(), z()) },
        -3,
        "ratify_v2_verification_receipt_body"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_transaction_context_hash(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_transaction_context_hash"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_transaction_party_request_hash(z(), z(), z(), z()) },
        -3,
        "ratify_v2_transaction_party_request_hash"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_operation_context_hash(z(), z(), z()) },
        -3,
        "ratify_v2_operation_context_hash"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_session_context(z(), z(), z()) },
        -3,
        "ratify_v2_session_context"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_payload_digest_decode(z(), z(), z()) },
        -3,
        "ratify_v2_payload_digest_decode"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_context_policy_digest(z(), z(), z()) },
        -3,
        "ratify_v2_context_policy_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_constraint_profile_digest(z(), z(), z()) },
        -3,
        "ratify_v2_constraint_profile_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_canonical_json(z(), z(), z()) },
        -3,
        "ratify_v2_canonical_json"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_validate_scopes(z(), z()) },
        -3,
        "ratify_v2_validate_scopes"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_validate_required_scope(z()) },
        -3,
        "ratify_v2_validate_required_scope"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_validate_request_context(z(), z()) },
        -3,
        "ratify_v2_validate_request_context"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_evaluate_standard_profile(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_evaluate_standard_profile"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_challenge_time_current(z(), z(), z(), z(), z()) },
        0,
        "ratify_v2_challenge_time_current"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_check_stream_sequence(z(), z(), z()) },
        -3,
        "ratify_v2_check_stream_sequence"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_validate_finalization_payload(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_validate_finalization_payload"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_valid_release_record_outcome(z(), z()) },
        0,
        "ratify_v2_valid_release_record_outcome"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_cross_sdk_fixture_verify(z(), z(), z()) },
        -3,
        "ratify_v2_cross_sdk_fixture_verify"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_keypair_from_seeds(z(), z(), z()) },
        -3,
        "ratify_v2_keypair_from_seeds"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_keypair_generate(z(), z(), z()) },
        -3,
        "ratify_v2_keypair_generate"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_keypair_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_keypair_public_key(z(), z()) },
        -3,
        "ratify_v2_keypair_public_key"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_keypair_key_id(z(), z(), z()) },
        -3,
        "ratify_v2_keypair_key_id"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_public_key_id(z(), z(), z()) },
        -3,
        "ratify_v2_public_key_id"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_public_key_to_json(z(), z()) },
        -3,
        "ratify_v2_public_key_to_json"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_key_id(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_key_id"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_key_id_check(z(), z()) },
        -3,
        "ratify_v2_key_id_check"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verify_object(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_verify_object"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_proof_bundle_verify_signatures(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_proof_bundle_verify_signatures"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verification_receipt_verify(z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_verification_receipt_verify"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_receipt_bundle_binding_check(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_receipt_bundle_binding_check"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_new(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_store_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_store_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_clone(z(), z()) },
        -3,
        "ratify_v2_ref_store_clone"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_control(z(), z(), z()) },
        -3,
        "ratify_v2_ref_store_control"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_time(z(), z()) },
        -3,
        "ratify_v2_ref_store_time"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_tamper(z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_store_tamper"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_abandon(z(), z()) },
        -3,
        "ratify_v2_ref_store_abandon"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_publish(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_store_publish"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_store_callbacks(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_store_callbacks"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_journal_new(z()) },
        -3,
        "ratify_v2_ref_journal_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_journal_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_journal_callbacks(z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_journal_callbacks"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_trust_registry_new(z(), z(), z()) },
        -3,
        "ratify_v2_ref_trust_registry_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_trust_registry_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_trust_registry_callbacks(z(), z()) },
        -3,
        "ratify_v2_ref_trust_registry_callbacks"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_issuance_new(z()) },
        -3,
        "ratify_v2_ref_issuance_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_issuance_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_issuance_control(z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_issuance_control"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_new(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_device_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_device_free(z()) };
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_primary_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_callbacks(z(), z(), z()) },
        -3,
        "ratify_v2_ref_device_callbacks"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_op(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_device_op"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_snapshot(z(), z()) },
        -3,
        "ratify_v2_ref_device_snapshot"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_restore(z(), z(), z()) },
        -3,
        "ratify_v2_ref_device_restore"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_device_state_projection(z(), z(), z()) },
        -3,
        "ratify_v2_ref_device_state_projection"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_ledger_new(z()) },
        -3,
        "ratify_v2_ref_ledger_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_ref_ledger_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_ledger_open(z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_ledger_open"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_ledger_record(z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_ledger_record"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_ref_ledger_execute(z(), z(), z(), z()) },
        -3,
        "ratify_v2_ref_ledger_execute"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_delegation_certificate(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_delegation_certificate"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_proof_bundle(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_proof_bundle"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_revocation_list(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_revocation_list"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_revocation_push(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_revocation_push"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_key_rotation_statement(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_key_rotation_statement"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_witness_entry(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_witness_entry"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_verification_receipt(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_verification_receipt"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_prepared_verification_receipt(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_prepared_verification_receipt"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_sign_transaction_receipt_party(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_sign_transaction_receipt_party"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_state_new(z()) },
        -3,
        "ratify_v2_status_state_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_status_state_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_state_apply(z(), z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_status_state_apply"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_state_transition_epoch(z(), z(), z(), z()) },
        -3,
        "ratify_v2_status_state_transition_epoch"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_state_query(z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_status_state_query"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_status_state_json(z(), z()) },
        -3,
        "ratify_v2_status_state_json"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_record_key_role(z(), z(), z()) },
        -3,
        "ratify_v2_journal_record_key_role"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_configure_status_key(z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_configure_status_key"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_apply(z(), z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_apply"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_status(z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_status"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_genesis(z(), z(), z()) },
        -3,
        "ratify_v2_journal_genesis"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_import(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_import"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_validate_transition(z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_validate_transition"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_migrate(z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_migrate"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_journal_legacy_encode(z(), z(), z(), z()) },
        -3,
        "ratify_v2_journal_legacy_encode"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe {
            ratify_v2_status_publish(
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
                z(),
            )
        },
        -3,
        "ratify_v2_status_publish"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_rotation_journal_new(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_rotation_journal_new"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_rotation_journal_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_rotation_journal_accept(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_rotation_journal_accept"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_rotation_journal_recover(z(), z(), z()) },
        -3,
        "ratify_v2_rotation_journal_recover"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_rotation_journal_state(z(), z()) },
        -3,
        "ratify_v2_rotation_journal_state"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_witness_entry_append(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_witness_entry_append"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verification_receipt_append(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_verification_receipt_append"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_archival_verify(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_archival_verify"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_verify_proof_bundle(z(), z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_verify_proof_bundle"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_claim_proof_bundle(z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_claim_proof_bundle"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_recover_interrupted_claim(z(), z(), z()) },
        -3,
        "ratify_v2_recover_interrupted_claim"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_committed_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_committed_claim_id(z(), z()) },
        -3,
        "ratify_v2_committed_claim_id"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_committed_receipt_body(z(), z()) },
        -3,
        "ratify_v2_committed_receipt_body"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_committed_receipt_body_digest(z(), z()) },
        -3,
        "ratify_v2_committed_receipt_body_digest"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_committed_challenge_expires_at(z(), z()) },
        -3,
        "ratify_v2_committed_challenge_expires_at"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_committed_allow_horizon(z(), z(), z()) },
        -3,
        "ratify_v2_committed_allow_horizon"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_release_decision(z(), z(), z(), z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_release_decision"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { CStr::from_ptr(ratify_v2_release_status_str(z())) }
            .to_str()
            .unwrap(),
        "unknown",
        "ratify_v2_release_status_str"
    );
    fired();
    arm_before_body();
    unsafe { ratify_v2_released_free(z()) };
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_released_string(z(), z(), z()) },
        -3,
        "ratify_v2_released_string"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_released_granted_scope(z(), z()) },
        -3,
        "ratify_v2_released_granted_scope"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_released_receipt(z(), z()) },
        -3,
        "ratify_v2_released_receipt"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_released_times(z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_released_times"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_released_allowed(z(), z()) },
        0,
        "ratify_v2_released_allowed"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_issue_challenge(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_issue_challenge"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe { ratify_v2_load_expected_challenge(z(), z(), z(), z(), z(), z()) },
        -3,
        "ratify_v2_load_expected_challenge"
    );
    fired();
    arm_before_body();
    assert_eq!(
        unsafe {
            ratify_v2_verify_transaction_receipt(z(), z(), z(), z(), z(), z(), z(), z(), z(), z())
        },
        -3,
        "ratify_v2_verify_transaction_receipt"
    );
    fired();
}

#[test]
fn the_sweep_covers_every_v2_export_in_the_header() {
    let header = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("include/ratify.h"),
    )
    .unwrap();
    let mut declared = BTreeSet::new();
    for line in header.lines() {
        if line.starts_with(' ') || line.starts_with('/') || line.starts_with('#') {
            continue;
        }
        if let Some(open) = line.find("ratify_v2_") {
            let name: String = line[open..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if line[open + name.len()..].starts_with('(') {
                declared.insert(name);
            }
        }
    }
    let swept: BTreeSet<String> = SWEPT.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        declared, swept,
        "every ratify_v2_* export must be in the panic sweep"
    );
}
