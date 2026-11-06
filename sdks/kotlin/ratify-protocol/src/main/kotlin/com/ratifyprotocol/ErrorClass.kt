package com.ratifyprotocol

/**
 * A SPEC-v2 §2.7 error class. Every v2 failure carries exactly one;
 * [spelling] is the text shared by every SDK and the conformance corpus.
 * Conformance compares classes, never messages.
 */
public enum class ErrorClass(public val spelling: String) {
    MALFORMED("malformed"),
    UNSUPPORTED_OBJECT_TYPE("unsupported_object_type"),
    KEY_ID_MISMATCH("key_id_mismatch"),
    DELEGATION_DIGEST_MISMATCH("delegation_digest_mismatch"),
    CHAIN_LINKAGE_MISMATCH("chain_linkage_mismatch"),
    DUPLICATE_CERTIFICATE_REF("duplicate_certificate_ref"),
    INVALID_SIGNATURE("invalid_signature"),
    INVALID_REQUIRED_SCOPE("invalid_required_scope"),
    CONFIGURATION_INVALID("configuration_invalid"),
    EXPECTED_CHALLENGE_UNAVAILABLE("expected_challenge_unavailable"),
    NAMESPACE_MISMATCH("namespace_mismatch"),
    STALE_REPLAY_EPOCH("stale_replay_epoch"),
    VERIFIER_ID_MISMATCH("verifier_id_mismatch"),
    CHALLENGE_MISMATCH("challenge_mismatch"),
    CHALLENGE_NOT_FRESH("challenge_not_fresh"),
    EXPECTED_AGENT_MISMATCH("expected_agent_mismatch"),
    SESSION_CONTEXT_MISMATCH("session_context_mismatch"),
    RECEIVER_AUDIENCE_REQUIRED("receiver_audience_required"),
    RECEIVER_AUDIENCE_MISMATCH("receiver_audience_mismatch"),
    RECEIVER_BINDING_REJECTED("receiver_binding_rejected"),
    CLAIM_REPLAY("claim_replay"),
    STREAM_SEQUENCE_MISMATCH("stream_sequence_mismatch"),
    CLAIM_STORE_UNAVAILABLE("claim_store_unavailable"),
    RECEIPT_ABANDONED("receipt_abandoned"),
    EVALUATION_CANCELLED("evaluation_cancelled"),
    CLOCK_REGRESSED("clock_regressed"),
    ALLOW_HORIZON_PASSED("allow_horizon_passed"),
    CLAIM_LEASE_LIVE("claim_lease_live"),
    CLAIM_LEASE_LOST("claim_lease_lost"),
    CLAIM_ALREADY_TERMINAL("claim_already_terminal"),
    CLAIM_NOT_FOUND("claim_not_found"),
    STATUS_KEY_BINDING_MISMATCH("status_key_binding_mismatch"),
    STATUS_OBJECT_REJECTED("status_object_rejected"),
    RECEIPT_BUNDLE_MISMATCH("receipt_bundle_mismatch"),
    BUNDLE_HASH_MISMATCH("bundle_hash_mismatch"),
    TRANSACTION_PARTY_MISMATCH("transaction_party_mismatch"),
    TRANSACTION_CONTEXT_MISMATCH("transaction_context_mismatch"),
    TRANSACTION_SIGNATURE_SET_INVALID("transaction_signature_set_invalid"),
    ROTATION_STATE_MISMATCH("rotation_state_mismatch"),
    ROTATION_KEY_REUSED("rotation_key_reused"),
    ROTATION_FUTURE_DATED("rotation_future_dated"),
    ROTATION_FORK("rotation_fork"),
    ROTATION_FROZEN("rotation_frozen"),
    ROTATION_RECOVERY_INVALID("rotation_recovery_invalid"),
    LOG_STATE_MISMATCH("log_state_mismatch"),
    LOG_GAP("log_gap"),
    LOG_ORPHAN("log_orphan"),
    LOG_FORK("log_fork"),
    LOG_FROZEN("log_frozen");

    public companion object {
        /** The class with this spelling, or null for anything outside §2.7. */
        public fun fromSpelling(spelling: String): ErrorClass? = entries.firstOrNull { it.spelling == spelling }
    }
}
