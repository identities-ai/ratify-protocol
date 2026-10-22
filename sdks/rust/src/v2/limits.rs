//! Protocol v2 wire limits (SPEC-v2 §2.6, Go `limits_v2.go`) and
//! configuration and clock bounds (SPEC-v2 §2.5, Go `clock_bounds_v2.go`).
//!
//! Every time value is integer Unix seconds and every deadline is exclusive.

use super::errors::{err, plain, V2ErrorClass, V2Result};

pub const MAX_DELEGATION_CERT_BYTES_V2: usize = 32 << 10;
pub const MAX_PROOF_BUNDLE_BYTES_V2: usize = 128 << 10;
pub const MAX_KEY_ROTATION_STATEMENT_BYTES_V2: usize = 32 << 10;
pub const MAX_REVOCATION_PUSH_BYTES_V2: usize = 256 << 10;
pub const MAX_REVOCATION_PUSH_REFS_V2: usize = 512;
pub const MAX_REVOCATION_LIST_BYTES_V2: usize = 4 << 20;
pub const MAX_REVOCATION_LIST_REFS_V2: usize = 10000;
pub const MAX_WITNESS_ENTRY_BYTES_V2: usize = 64 << 10;
pub const MAX_WITNESS_ENTRY_DATA_BYTES_V2: usize = 16 << 10;
pub const MAX_VERIFICATION_RECEIPT_BYTES_V2: usize = 64 << 10;
pub const MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2: usize = 64 << 10;
pub const MAX_STATUS_EVIDENCE_BATCH_BYTES_V2: usize = 8 << 20;
pub const MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2: usize = 64;
pub const MAX_TRANSACTION_RECEIPT_BYTES_V2: usize = 5 << 20;
pub const MAX_TRANSACTION_PARTIES_V2: usize = 32;
pub const MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2: usize = 1024;

/// 9999-12-31T23:59:59Z. Timestamps are 0..=this.
pub const V2_MAX_TIMESTAMP_SECONDS: i64 = 253402300799;
pub const V2_MAX_FUTURE_SKEW_SECONDS: i64 = 300;
pub const V2_MAX_CHALLENGE_AGE_SECONDS: i64 = 300;
pub const V2_MAX_STATUS_LIFETIME_SECONDS: i64 = 86400;
pub const V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS: i64 = 86400;
pub const V2_MAX_RATE_WINDOW_SECONDS: i64 = 86400;
pub const V2_MAX_DELEGATION_LIFETIME_SECONDS: i64 = 315360000;
/// 2^53 - 1.
pub const V2_MAX_SAFE_INTEGER: i64 = 9007199254740991;

/// The pre-parse size gate shared by every v2 decoder.
pub(crate) fn check_v2_wire_size(data: &[u8], object: &str, limit_name: &str, limit: usize) -> V2Result<()> {
    if data.len() > limit {
        return plain(format!(
            "wire v2: {object} exceeds {limit_name} ({limit} bytes); rejected before parsing"
        ));
    }
    Ok(())
}

/// Whether `t` is inside the v2 timestamp domain.
pub fn valid_v2_timestamp(t: i64) -> bool {
    (0..=V2_MAX_TIMESTAMP_SECONDS).contains(&t)
}

/// Add two second counts inside the v2 timestamp domain; `None` if either
/// operand is outside it.
pub(crate) fn checked_add_v2(a: i64, b: i64) -> Option<i64> {
    if !(0..=V2_MAX_TIMESTAMP_SECONDS).contains(&a) || !(0..=V2_MAX_TIMESTAMP_SECONDS).contains(&b) {
        return None;
    }
    a.checked_add(b)
}

/// Exclusive challenge deadlines (Go `v2ChallengeTimeCurrent`).
pub(crate) fn v2_challenge_time_current(
    now: i64,
    issued_at: i64,
    expires_at: i64,
    max_age: i64,
    future_skew: i64,
) -> bool {
    if !valid_v2_timestamp(now) || !valid_v2_timestamp(issued_at) || !valid_v2_timestamp(expires_at) {
        return false;
    }
    if issued_at > now && issued_at - now > future_skew {
        return false;
    }
    match checked_add_v2(issued_at, max_age) {
        Some(age_deadline) => now < expires_at && now < age_deadline,
        None => false,
    }
}

/// Request-level clock bounds (Go `validateV2FreshnessConfiguration`).
pub(crate) fn validate_v2_freshness_configuration(
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<()> {
    if !valid_v2_timestamp(now) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("v2 verifier time is outside 0..{V2_MAX_TIMESTAMP_SECONDS}"),
        );
    }
    if !(1..=V2_MAX_CHALLENGE_AGE_SECONDS).contains(&max_age_seconds) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("v2 challenge maximum age must be 1..{V2_MAX_CHALLENGE_AGE_SECONDS} seconds"),
        );
    }
    if !(0..=V2_MAX_FUTURE_SKEW_SECONDS).contains(&future_skew_seconds) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("v2 future skew must be 0..{V2_MAX_FUTURE_SKEW_SECONDS} seconds"),
        );
    }
    Ok(())
}
