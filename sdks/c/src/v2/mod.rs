//! Protocol v2 C ABI (`ratify_v2_*`).
//!
//! This surface is separate from the v1 ABI: every symbol carries the
//! `ratify_v2_` prefix and no v1 function changes behaviour. It is an ABI
//! over the Rust `ratify-protocol` v2 implementation (SPEC-v2 §1.3), not an
//! independent implementation. Callers check `ratify_v2_abi_version()`
//! against `RATIFY_V2_ABI_VERSION` before use.
//!
//! ## Result codes
//!
//! Every fallible `ratify_v2_*` function returns an `int32_t`:
//!
//! - `0` (`RatifyV2Ok`) on success;
//! - a positive `RatifyV2Code` naming exactly one of the 49 SPEC-v2 §2.7
//!   failure classes, numbered in the order of the §2.7 table;
//! - a negative `RatifyV2Code` for an ABI condition (NULL pointer, bad
//!   argument, internal failure, cancellation), a Part B store sentinel, or a
//!   typed-signing refusal (SPEC-v2 §3.2). None of these is a Protocol
//!   failure class.
//!
//! `ratify_v2_error_class_str(code)` returns the stable spelling of a code.
//! The diagnostic text of the last call on the calling thread is available
//! from `ratify_v2_last_error_message()`; functions that also take an
//! `err_out` parameter write the same text there. Error text is diagnostic
//! only; the code is authoritative.
//!
//! ## Ownership, callbacks, threads, panics
//!
//! See the C README. In short: inputs are borrowed for the duration of the
//! call; library outputs are owned by the caller and released only through the
//! matching `ratify_v2_*_free` function; callbacks run on the calling thread
//! (constraint evaluators excepted, see `RatifyV2EvaluatorRegistration`) and
//! are never retained after the call returns; a panic is caught at every
//! export and poisons any handle in use.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

use ratify_protocol::v2::{V2Error, V2ErrorClass, V2SignError, V2StoreError};
use ratify_protocol::{HybridPublicKey, HybridSignature};

pub mod callbacks;
pub mod codec;
pub mod keys;
pub(crate) mod marshal;
pub mod objects;
#[cfg(feature = "test-reference")]
pub mod reference;
pub mod sign;
pub mod state;
pub mod verifier;

pub use callbacks::*;
pub use codec::*;
pub use keys::*;
pub use objects::*;
#[cfg(feature = "test-reference")]
pub use reference::*;
pub use sign::*;
pub use state::*;
pub use verifier::*;

/// Version of the `ratify_v2_*` C ABI. Bumped on any incompatible change to a
/// `ratify_v2_*` signature, struct, or code value.
pub const RATIFY_V2_ABI_VERSION: u32 = 2;

/// Protocol major version implemented by the `ratify_v2_*` surface.
pub const RATIFY_V2_PROTOCOL_VERSION: u32 = 2;

/// Buffer size (including the trailing NUL) for a v2 key ID written by
/// `ratify_v2_key_id`: 64 lowercase hex characters + NUL.
pub const RATIFY_V2_KEY_ID_BUF_LEN: usize = 65;

/// Raw Ed25519 public key length.
pub const RATIFY_V2_ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Raw ML-DSA-65 public key length (FIPS 204).
pub const RATIFY_V2_ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
/// Ed25519 signature length.
pub const RATIFY_V2_ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-65 signature length (FIPS 204).
pub const RATIFY_V2_ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Length of a key seed accepted by `ratify_v2_keypair_from_seeds`.
pub const RATIFY_V2_SEED_LEN: usize = 32;
/// Number of SPEC-v2 §2.7 failure classes (positive codes 1..=49).
pub const RATIFY_V2_ERROR_CLASS_COUNT: u32 = 49;

/// Result codes for `ratify_v2_*` functions and callback returns.
///
/// Positive values are the SPEC-v2 §2.7 failure classes in table order.
/// Negative values are not Protocol failure classes: `-1..=-4` are ABI
/// conditions; `-10..=-17` are Part B store sentinels a callback returns
/// (and that a few store-facing functions report). A signing refusal
/// reports its SPEC-v2 §2.7 class like every other failure. Values are
/// stable within one `RATIFY_V2_ABI_VERSION`; a C `switch` must include a
/// `default` case.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2Code {
    RatifyV2Ok = 0,
    RatifyV2Malformed = 1,
    RatifyV2UnsupportedObjectType = 2,
    RatifyV2KeyIdMismatch = 3,
    RatifyV2DelegationDigestMismatch = 4,
    RatifyV2ChainLinkageMismatch = 5,
    RatifyV2DuplicateCertificateRef = 6,
    RatifyV2InvalidSignature = 7,
    RatifyV2InvalidRequiredScope = 8,
    RatifyV2ConfigurationInvalid = 9,
    RatifyV2ExpectedChallengeUnavailable = 10,
    RatifyV2NamespaceMismatch = 11,
    RatifyV2StaleReplayEpoch = 12,
    RatifyV2VerifierIdMismatch = 13,
    RatifyV2ChallengeMismatch = 14,
    RatifyV2ChallengeNotFresh = 15,
    RatifyV2ExpectedAgentMismatch = 16,
    RatifyV2SessionContextMismatch = 17,
    RatifyV2ReceiverAudienceRequired = 18,
    RatifyV2ReceiverAudienceMismatch = 19,
    RatifyV2ReceiverBindingRejected = 20,
    RatifyV2ClaimReplay = 21,
    RatifyV2StreamSequenceMismatch = 22,
    RatifyV2ClaimStoreUnavailable = 23,
    RatifyV2ReceiptAbandoned = 24,
    RatifyV2EvaluationCancelled = 25,
    RatifyV2ClockRegressed = 26,
    RatifyV2AllowHorizonPassed = 27,
    RatifyV2ClaimLeaseLive = 28,
    RatifyV2ClaimLeaseLost = 29,
    RatifyV2ClaimAlreadyTerminal = 30,
    RatifyV2ClaimNotFound = 31,
    RatifyV2StatusKeyBindingMismatch = 32,
    RatifyV2StatusObjectRejected = 33,
    RatifyV2ReceiptBundleMismatch = 34,
    RatifyV2BundleHashMismatch = 35,
    RatifyV2TransactionPartyMismatch = 36,
    RatifyV2TransactionContextMismatch = 37,
    RatifyV2TransactionSignatureSetInvalid = 38,
    RatifyV2RotationStateMismatch = 39,
    RatifyV2RotationKeyReused = 40,
    RatifyV2RotationFutureDated = 41,
    RatifyV2RotationFork = 42,
    RatifyV2RotationFrozen = 43,
    RatifyV2RotationRecoveryInvalid = 44,
    RatifyV2LogStateMismatch = 45,
    RatifyV2LogGap = 46,
    RatifyV2LogOrphan = 47,
    RatifyV2LogFork = 48,
    RatifyV2LogFrozen = 49,
    /// A required pointer argument was NULL.
    RatifyV2ErrNullPointer = -1,
    /// A caller-supplied argument (length, UTF-8, JSON shape, enum value) was
    /// invalid at the ABI layer.
    RatifyV2ErrBadArgument = -2,
    /// An internal failure (a caught panic, or a poisoned handle).
    RatifyV2ErrInternal = -3,
    /// Cancellation. A callback returns it to cancel the operation (SPEC-v2
    /// §6.11); the operation then reports `RatifyV2EvaluationCancelled`.
    RatifyV2ErrCancelled = -4,
    /// Store sentinel: an unclassified store, provider, or clock failure. The
    /// verifier assigns the class SPEC-v2 names for that step.
    RatifyV2StoreUnavailable = -10,
    /// Store sentinel: the challenge was already claimed by a different proof.
    RatifyV2StoreClaimProofConflict = -11,
    /// Store sentinel: a complete atomic rate batch had no capacity.
    RatifyV2StoreRateLimitExceeded = -12,
    /// Store sentinel: a different release record exists for the claim.
    RatifyV2StoreReleaseStateMismatch = -13,
    /// Store sentinel: no checkpoint acknowledgement exists.
    RatifyV2StoreAcknowledgementNotFound = -14,
    /// Store sentinel: an issuance record already exists for that key.
    RatifyV2StoreIssuanceConflict = -15,
    /// Store sentinel: no issuance record exists for that key.
    RatifyV2StoreIssuanceNotFound = -16,
    /// Store sentinel: a security-journal compare-and-swap lost to another
    /// writer.
    RatifyV2StoreJournalConflict = -17,
}

/// Object kinds used by `ratify_v2_verify_object`, `ratify_v2_object_*`, and
/// signing. Values 1..=8 are the SPEC-v2 signed object type codes
/// (`kind_object_type_codes` in `objects.json`); 0x0009 shares the rotation
/// statement. Values from 100 name decodable objects that carry no signature
/// code of their own.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2ObjectKind {
    RatifyV2KindDelegationCertificate = 1,
    RatifyV2KindProofBundle = 2,
    RatifyV2KindRevocationList = 3,
    RatifyV2KindKeyRotationStatement = 4,
    RatifyV2KindRevocationPush = 5,
    RatifyV2KindWitnessEntry = 6,
    RatifyV2KindTransactionReceipt = 7,
    RatifyV2KindVerificationReceipt = 8,
    /// The sealed receipt outbox body (SPEC-v2 §7.7).
    RatifyV2KindVerificationReceiptBody = 100,
    /// A status evidence batch (SPEC-v2 §6.5).
    RatifyV2KindStatusEvidenceBatch = 101,
    /// A checkpoint acknowledgement (SPEC-v2 §7.8).
    RatifyV2KindCheckpointAcknowledgement = 102,
}

pub(crate) const CLASS_TABLE: &[(V2ErrorClass, RatifyV2Code, &CStr)] = {
    use RatifyV2Code::*;
    use V2ErrorClass::*;
    &[
        (Malformed, RatifyV2Malformed, c"malformed"),
        (
            UnsupportedObjectType,
            RatifyV2UnsupportedObjectType,
            c"unsupported_object_type",
        ),
        (KeyIdMismatch, RatifyV2KeyIdMismatch, c"key_id_mismatch"),
        (
            DelegationDigestMismatch,
            RatifyV2DelegationDigestMismatch,
            c"delegation_digest_mismatch",
        ),
        (
            ChainLinkageMismatch,
            RatifyV2ChainLinkageMismatch,
            c"chain_linkage_mismatch",
        ),
        (
            DuplicateCertificateRef,
            RatifyV2DuplicateCertificateRef,
            c"duplicate_certificate_ref",
        ),
        (
            InvalidSignature,
            RatifyV2InvalidSignature,
            c"invalid_signature",
        ),
        (
            InvalidRequiredScope,
            RatifyV2InvalidRequiredScope,
            c"invalid_required_scope",
        ),
        (
            ConfigurationInvalid,
            RatifyV2ConfigurationInvalid,
            c"configuration_invalid",
        ),
        (
            ExpectedChallengeUnavailable,
            RatifyV2ExpectedChallengeUnavailable,
            c"expected_challenge_unavailable",
        ),
        (
            NamespaceMismatch,
            RatifyV2NamespaceMismatch,
            c"namespace_mismatch",
        ),
        (
            StaleReplayEpoch,
            RatifyV2StaleReplayEpoch,
            c"stale_replay_epoch",
        ),
        (
            VerifierIdMismatch,
            RatifyV2VerifierIdMismatch,
            c"verifier_id_mismatch",
        ),
        (
            ChallengeMismatch,
            RatifyV2ChallengeMismatch,
            c"challenge_mismatch",
        ),
        (
            ChallengeNotFresh,
            RatifyV2ChallengeNotFresh,
            c"challenge_not_fresh",
        ),
        (
            ExpectedAgentMismatch,
            RatifyV2ExpectedAgentMismatch,
            c"expected_agent_mismatch",
        ),
        (
            SessionContextMismatch,
            RatifyV2SessionContextMismatch,
            c"session_context_mismatch",
        ),
        (
            ReceiverAudienceRequired,
            RatifyV2ReceiverAudienceRequired,
            c"receiver_audience_required",
        ),
        (
            ReceiverAudienceMismatch,
            RatifyV2ReceiverAudienceMismatch,
            c"receiver_audience_mismatch",
        ),
        (
            ReceiverBindingRejected,
            RatifyV2ReceiverBindingRejected,
            c"receiver_binding_rejected",
        ),
        (ClaimReplay, RatifyV2ClaimReplay, c"claim_replay"),
        (
            StreamSequenceMismatch,
            RatifyV2StreamSequenceMismatch,
            c"stream_sequence_mismatch",
        ),
        (
            ClaimStoreUnavailable,
            RatifyV2ClaimStoreUnavailable,
            c"claim_store_unavailable",
        ),
        (
            ReceiptAbandoned,
            RatifyV2ReceiptAbandoned,
            c"receipt_abandoned",
        ),
        (
            EvaluationCancelled,
            RatifyV2EvaluationCancelled,
            c"evaluation_cancelled",
        ),
        (ClockRegressed, RatifyV2ClockRegressed, c"clock_regressed"),
        (
            AllowHorizonPassed,
            RatifyV2AllowHorizonPassed,
            c"allow_horizon_passed",
        ),
        (ClaimLeaseLive, RatifyV2ClaimLeaseLive, c"claim_lease_live"),
        (ClaimLeaseLost, RatifyV2ClaimLeaseLost, c"claim_lease_lost"),
        (
            ClaimAlreadyTerminal,
            RatifyV2ClaimAlreadyTerminal,
            c"claim_already_terminal",
        ),
        (ClaimNotFound, RatifyV2ClaimNotFound, c"claim_not_found"),
        (
            StatusKeyBindingMismatch,
            RatifyV2StatusKeyBindingMismatch,
            c"status_key_binding_mismatch",
        ),
        (
            StatusObjectRejected,
            RatifyV2StatusObjectRejected,
            c"status_object_rejected",
        ),
        (
            ReceiptBundleMismatch,
            RatifyV2ReceiptBundleMismatch,
            c"receipt_bundle_mismatch",
        ),
        (
            BundleHashMismatch,
            RatifyV2BundleHashMismatch,
            c"bundle_hash_mismatch",
        ),
        (
            TransactionPartyMismatch,
            RatifyV2TransactionPartyMismatch,
            c"transaction_party_mismatch",
        ),
        (
            TransactionContextMismatch,
            RatifyV2TransactionContextMismatch,
            c"transaction_context_mismatch",
        ),
        (
            TransactionSignatureSetInvalid,
            RatifyV2TransactionSignatureSetInvalid,
            c"transaction_signature_set_invalid",
        ),
        (
            RotationStateMismatch,
            RatifyV2RotationStateMismatch,
            c"rotation_state_mismatch",
        ),
        (
            RotationKeyReused,
            RatifyV2RotationKeyReused,
            c"rotation_key_reused",
        ),
        (
            RotationFutureDated,
            RatifyV2RotationFutureDated,
            c"rotation_future_dated",
        ),
        (RotationFork, RatifyV2RotationFork, c"rotation_fork"),
        (RotationFrozen, RatifyV2RotationFrozen, c"rotation_frozen"),
        (
            RotationRecoveryInvalid,
            RatifyV2RotationRecoveryInvalid,
            c"rotation_recovery_invalid",
        ),
        (
            LogStateMismatch,
            RatifyV2LogStateMismatch,
            c"log_state_mismatch",
        ),
        (LogGap, RatifyV2LogGap, c"log_gap"),
        (LogOrphan, RatifyV2LogOrphan, c"log_orphan"),
        (LogFork, RatifyV2LogFork, c"log_fork"),
        (LogFrozen, RatifyV2LogFrozen, c"log_frozen"),
    ]
};

const OTHER_CODES: &[(RatifyV2Code, &CStr)] = {
    use RatifyV2Code::*;
    &[
        (RatifyV2Ok, c"ok"),
        (RatifyV2ErrNullPointer, c"null_pointer"),
        (RatifyV2ErrBadArgument, c"bad_argument"),
        (RatifyV2ErrInternal, c"internal"),
        (RatifyV2ErrCancelled, c"cancelled"),
        (RatifyV2StoreUnavailable, c"store_unavailable"),
        (RatifyV2StoreClaimProofConflict, c"claim_proof_conflict"),
        (RatifyV2StoreRateLimitExceeded, c"rate_limit_exceeded"),
        (RatifyV2StoreReleaseStateMismatch, c"release_state_mismatch"),
        (
            RatifyV2StoreAcknowledgementNotFound,
            c"acknowledgement_not_found",
        ),
        (
            RatifyV2StoreIssuanceConflict,
            c"challenge_issuance_conflict",
        ),
        (
            RatifyV2StoreIssuanceNotFound,
            c"challenge_issuance_not_found",
        ),
        (RatifyV2StoreJournalConflict, c"journal_conflict"),
    ]
};

/// The positive code of a SPEC-v2 §2.7 class.
pub(crate) fn class_code(class: V2ErrorClass) -> RatifyV2Code {
    CLASS_TABLE
        .iter()
        .find(|(c, _, _)| *c == class)
        .map(|(_, code, _)| *code)
        .unwrap_or(RatifyV2Code::RatifyV2ErrInternal)
}

/// The class of a positive code, if any.
pub(crate) fn code_class(code: i32) -> Option<V2ErrorClass> {
    CLASS_TABLE
        .iter()
        .find(|(_, k, _)| *k as i32 == code)
        .map(|(c, _, _)| *c)
}

pub(crate) fn code_cstr(code: i32) -> &'static CStr {
    if let Some((_, _, name)) = CLASS_TABLE.iter().find(|(_, k, _)| *k as i32 == code) {
        return name;
    }
    OTHER_CODES
        .iter()
        .find(|(k, _)| *k as i32 == code)
        .map(|(_, name)| *name)
        .unwrap_or(c"unknown")
}

pub(crate) fn code_str(code: i32) -> &'static str {
    code_cstr(code).to_str().unwrap_or("unknown")
}

// ---------------------------------------------------------------------------
// Failures

/// An ABI-layer failure: a Protocol class, an ABI condition, a store
/// sentinel, or a signing refusal, with its diagnostic message.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    pub code: RatifyV2Code,
    pub message: String,
}

impl Failure {
    pub fn new(code: RatifyV2Code, message: impl Into<String>) -> Self {
        Failure {
            code,
            message: message.into(),
        }
    }
}

impl From<V2Error> for Failure {
    fn from(e: V2Error) -> Self {
        Failure {
            code: class_code(e.class),
            message: e.message,
        }
    }
}

impl From<V2SignError> for Failure {
    /// A signing refusal reports the SPEC-v2 §2.7 class the Rust
    /// implementation assigns it ([`V2SignError::class`]).
    fn from(e: V2SignError) -> Self {
        Failure {
            code: class_code(e.class()),
            message: e.to_string(),
        }
    }
}

/// A store error as the code a store-facing export reports.
#[cfg_attr(not(feature = "test-reference"), allow(dead_code))]
pub(crate) fn store_failure(e: V2StoreError) -> Failure {
    use RatifyV2Code::*;
    let message = e.to_string();
    let code = match e {
        V2StoreError::Classified(inner) => class_code(inner.class),
        V2StoreError::Unavailable(_) => RatifyV2StoreUnavailable,
        V2StoreError::ClaimProofConflict => RatifyV2StoreClaimProofConflict,
        V2StoreError::RateLimitExceeded => RatifyV2StoreRateLimitExceeded,
        V2StoreError::ReleaseStateMismatch => RatifyV2StoreReleaseStateMismatch,
        V2StoreError::AcknowledgementNotFound => RatifyV2StoreAcknowledgementNotFound,
        V2StoreError::ChallengeIssuanceConflict => RatifyV2StoreIssuanceConflict,
        V2StoreError::ChallengeIssuanceNotFound => RatifyV2StoreIssuanceNotFound,
    };
    Failure { code, message }
}

pub(crate) fn bad_arg(message: impl Into<String>) -> Failure {
    Failure::new(RatifyV2Code::RatifyV2ErrBadArgument, message)
}

pub(crate) fn null_arg(name: &str) -> Failure {
    Failure::new(
        RatifyV2Code::RatifyV2ErrNullPointer,
        format!("{name} is null"),
    )
}

pub(crate) type AbiResult<T> = Result<T, Failure>;

// ---------------------------------------------------------------------------
// Thread-local diagnostics

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

thread_local! {
    static NOTE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// A diagnostic for a call that succeeds at the ABI level but reports a
/// Protocol outcome (for example a preflight verification failure).
pub(crate) fn set_success_note(message: &str) {
    NOTE.with(|n| *n.borrow_mut() = Some(message.to_string()));
}

pub(crate) fn set_last_error(message: &str) {
    let safe = CString::new(message.replace('\0', "<NUL>")).unwrap_or_default();
    LAST_ERROR.with(|l| *l.borrow_mut() = safe);
}

// ---------------------------------------------------------------------------
// Guards

/// Run `f` under the C ABI panic guard, map its outcome to an `int32_t` code,
/// and record the diagnostic (thread-local, and in `err_out` when non-NULL).
/// A caught panic runs `reset` (which puts every output parameter in a
/// defined state) and returns `RatifyV2ErrInternal` rather than unwinding
/// into C.
pub(crate) fn run(
    err_out: *mut *mut c_char,
    reset: impl FnOnce(),
    f: impl FnOnce() -> AbiResult<()>,
) -> i32 {
    run_h(err_out, &[], reset, f)
}

/// [`run`] for a function that uses opaque handles. `flags` are the poison
/// flags of every handle in use (NULL entries are ignored): a poisoned handle
/// fails with `RatifyV2ErrInternal` before the body runs, and a panic caught
/// while the body runs poisons every listed handle (SPEC-v2 §1.3).
pub(crate) fn run_h(
    err_out: *mut *mut c_char,
    flags: &[*const AtomicBool],
    reset: impl FnOnce(),
    f: impl FnOnce() -> AbiResult<()>,
) -> i32 {
    crate::guard::ffi_guard(
        || {
            for flag in flags.iter().filter(|f| !f.is_null()) {
                // SAFETY: a non-NULL flag points into a live handle the
                // caller passed to this call.
                unsafe { (**flag).store(true, Ordering::SeqCst) };
            }
            reset();
            let message = format!("internal: {}", crate::guard::PANIC_MESSAGE);
            set_last_error(&message);
            crate::set_err(err_out, &message);
            RatifyV2Code::RatifyV2ErrInternal as i32
        },
        || {
            let poisoned = flags
                .iter()
                .filter(|f| !f.is_null())
                // SAFETY: as above.
                .any(|f| unsafe { (**f).load(Ordering::SeqCst) });
            NOTE.with(|n| n.borrow_mut().take());
            let outcome = if poisoned {
                Err(Failure::new(
                    RatifyV2Code::RatifyV2ErrInternal,
                    "a handle in use is poisoned by an earlier caught panic",
                ))
            } else {
                f()
            };
            match outcome {
                Ok(()) => {
                    set_last_error(&NOTE.with(|n| n.borrow_mut().take()).unwrap_or_default());
                    RatifyV2Code::RatifyV2Ok as i32
                }
                Err(failure) => {
                    let message = format!("{}: {}", code_str(failure.code as i32), failure.message);
                    set_last_error(&message);
                    crate::set_err(err_out, &message);
                    failure.code as i32
                }
            }
        },
    )
}

/// Run a value-returning body under the panic guard (`on_panic` is the
/// fail-closed value). Used by accessors that return a plain value.
pub(crate) fn run_value<R>(flags: &[*const AtomicBool], on_panic: R, f: impl FnOnce() -> R) -> R
where
    R: Copy,
{
    crate::guard::ffi_guard(
        || {
            for flag in flags.iter().filter(|f| !f.is_null()) {
                // SAFETY: see run_h.
                unsafe { (**flag).store(true, Ordering::SeqCst) };
            }
            set_last_error(&format!("internal: {}", crate::guard::PANIC_MESSAGE));
            on_panic
        },
        || {
            // SAFETY: see run_h.
            if flags
                .iter()
                .filter(|f| !f.is_null())
                .any(|f| unsafe { (**f).load(Ordering::SeqCst) })
            {
                set_last_error("internal: a handle in use is poisoned by an earlier caught panic");
                return on_panic;
            }
            f()
        },
    )
}

/// Implemented by every opaque handle: the address of its poison flag.
pub(crate) trait Poisonable {
    fn poison_flag(&self) -> &AtomicBool;
}

/// The poison flag of a handle pointer, or NULL. Does not dereference a NULL
/// pointer and cannot panic.
pub(crate) fn flag<T: Poisonable>(p: *const T) -> *const AtomicBool {
    if p.is_null() {
        std::ptr::null()
    } else {
        // SAFETY: a non-NULL handle pointer comes from the library.
        unsafe { (*p).poison_flag() as *const AtomicBool }
    }
}

macro_rules! poisonable {
    ($($t:ty),* $(,)?) => {
        $(impl crate::v2::Poisonable for $t {
            fn poison_flag(&self) -> &std::sync::atomic::AtomicBool {
                &self.poisoned
            }
        })*
    };
}
pub(crate) use poisonable;

/// Borrow a handle, failing with `null_pointer` for NULL.
pub(crate) unsafe fn handle<'a, T>(p: *const T, name: &str) -> AbiResult<&'a T> {
    p.as_ref().ok_or_else(|| null_arg(name))
}

// ---------------------------------------------------------------------------
// Plain data shared with C

/// A borrowed byte range. `ptr` may be NULL only when `len` is 0.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RatifyV2Slice {
    pub ptr: *const u8,
    pub len: usize,
}

impl RatifyV2Slice {
    pub(crate) fn of(b: &[u8]) -> Self {
        RatifyV2Slice {
            ptr: if b.is_empty() {
                std::ptr::null()
            } else {
                b.as_ptr()
            },
            len: b.len(),
        }
    }

    pub(crate) fn empty() -> Self {
        RatifyV2Slice {
            ptr: std::ptr::null(),
            len: 0,
        }
    }

    /// The bytes, or `bad_argument` for a NULL pointer with a non-zero length.
    pub(crate) unsafe fn bytes<'a>(&self, name: &str) -> AbiResult<&'a [u8]> {
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.ptr.is_null() {
            return Err(bad_arg(format!("{name} is NULL with a non-zero length")));
        }
        Ok(std::slice::from_raw_parts(self.ptr, self.len))
    }
}

/// A library-allocated byte buffer owned by the caller. Release it with
/// `ratify_v2_buffer_free`. An empty buffer has `ptr == NULL` and `len == 0`.
#[repr(C)]
#[derive(Debug)]
pub struct RatifyV2Buffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// A complete hybrid public key with the fixed SPEC-v2 component lengths.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2PublicKey {
    pub ed25519: [u8; 32],
    pub ml_dsa_65: [u8; 1952],
}

impl RatifyV2PublicKey {
    pub(crate) fn as_hybrid(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519.to_vec(),
            ml_dsa_65: self.ml_dsa_65.to_vec(),
        }
    }

    pub(crate) fn write(out: *mut RatifyV2PublicKey, key: &HybridPublicKey) -> AbiResult<()> {
        if out.is_null() {
            return Err(null_arg("public key output"));
        }
        if key.ed25519.len() != 32 || key.ml_dsa_65.len() != 1952 {
            return Err(Failure::new(
                RatifyV2Code::RatifyV2Malformed,
                "public key components do not have the SPEC-v2 lengths",
            ));
        }
        // SAFETY: out is non-NULL and points to caller storage.
        unsafe {
            (*out).ed25519.copy_from_slice(&key.ed25519);
            (*out).ml_dsa_65.copy_from_slice(&key.ml_dsa_65);
        }
        Ok(())
    }
}

/// A hybrid signature. An external signer sets each `*_len` to the number of
/// bytes it wrote (64 and 3309 for a well-formed signature); any other length
/// is a missing or malformed component and fails signing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2Signature {
    pub ed25519: [u8; 64],
    pub ed25519_len: usize,
    pub ml_dsa_65: [u8; 3309],
    pub ml_dsa_65_len: usize,
}

impl RatifyV2Signature {
    pub(crate) fn zeroed() -> Self {
        RatifyV2Signature {
            ed25519: [0; 64],
            ed25519_len: 0,
            ml_dsa_65: [0; 3309],
            ml_dsa_65_len: 0,
        }
    }

    pub(crate) fn as_hybrid(&self) -> HybridSignature {
        HybridSignature {
            ed25519: self.ed25519[..self.ed25519_len.min(64)].to_vec(),
            ml_dsa_65: self.ml_dsa_65[..self.ml_dsa_65_len.min(3309)].to_vec(),
        }
    }
}

pub(crate) unsafe fn write_buffer(out: *mut RatifyV2Buffer, data: Vec<u8>) -> AbiResult<()> {
    if out.is_null() {
        return Err(null_arg("output buffer"));
    }
    if data.is_empty() {
        *out = RatifyV2Buffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
        return Ok(());
    }
    let boxed = data.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    *out = RatifyV2Buffer { ptr, len };
    Ok(())
}

/// Write an optional output buffer (a NULL `out` skips it).
pub(crate) unsafe fn write_opt_buffer(out: *mut RatifyV2Buffer, data: Vec<u8>) -> AbiResult<()> {
    if out.is_null() {
        return Ok(());
    }
    write_buffer(out, data)
}

pub(crate) unsafe fn clear_buffer(out: *mut RatifyV2Buffer) {
    if !out.is_null() {
        *out = RatifyV2Buffer {
            ptr: std::ptr::null_mut(),
            len: 0,
        };
    }
}

pub(crate) unsafe fn write_string(out: *mut *mut c_char, s: &str) -> AbiResult<()> {
    if out.is_null() {
        return Err(null_arg("output string"));
    }
    let c = CString::new(s).map_err(|_| bad_arg("output contains NUL"))?;
    *out = c.into_raw();
    Ok(())
}

pub(crate) unsafe fn write_opt_string(out: *mut *mut c_char, s: &str) -> AbiResult<()> {
    if out.is_null() {
        return Ok(());
    }
    write_string(out, s)
}

pub(crate) unsafe fn write_val<T>(out: *mut T, v: T) -> AbiResult<()> {
    if out.is_null() {
        return Err(null_arg("output value"));
    }
    *out = v;
    Ok(())
}

pub(crate) unsafe fn write_opt_val<T>(out: *mut T, v: T) {
    if !out.is_null() {
        *out = v;
    }
}

/// A required NUL-terminated UTF-8 string argument.
pub(crate) unsafe fn cstr<'a>(p: *const c_char, name: &str) -> AbiResult<&'a str> {
    if p.is_null() {
        return Err(null_arg(name));
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| bad_arg(format!("{name} is not valid UTF-8")))
}

/// A required byte argument: NULL is `null_pointer` even with a zero
/// length (pass any non-NULL pointer for empty input).
pub(crate) unsafe fn bytes<'a>(ptr: *const u8, len: usize, name: &str) -> AbiResult<&'a [u8]> {
    if ptr.is_null() {
        return Err(null_arg(name));
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

/// A strictly parsed JSON argument (bytes, not NUL-terminated).
pub(crate) unsafe fn json_bytes(
    ptr: *const u8,
    len: usize,
    name: &str,
) -> AbiResult<serde_json::Value> {
    let data = bytes(ptr, len, name)?;
    serde_json::from_slice(data).map_err(|e| bad_arg(format!("{name}: {e}")))
}

/// A NUL-terminated JSON argument.
pub(crate) unsafe fn json_cstr(ptr: *const c_char, name: &str) -> AbiResult<serde_json::Value> {
    let s = cstr(ptr, name)?;
    serde_json::from_str(s).map_err(|e| bad_arg(format!("{name}: {e}")))
}

// ---------------------------------------------------------------------------
// Version and error exports

/// Returns `RATIFY_V2_ABI_VERSION` as compiled into this library. A caller
/// built against a header with a different value must not use `ratify_v2_*`.
#[no_mangle]
pub extern "C" fn ratify_v2_abi_version() -> u32 {
    crate::guard::ffi_guard(
        // 0 matches no header's RATIFY_V2_ABI_VERSION, so a caller refuses the ABI.
        || 0,
        || RATIFY_V2_ABI_VERSION,
    )
}

/// Returns the Protocol major version implemented by `ratify_v2_*` (2).
#[no_mangle]
pub extern "C" fn ratify_v2_protocol_version() -> u32 {
    crate::guard::ffi_guard(|| 0, || RATIFY_V2_PROTOCOL_VERSION)
}

/// Returns the library package version (e.g. "2.0.0-alpha.1"). Statically
/// allocated — do NOT free. Same value as `ratify_version()`.
#[no_mangle]
pub extern "C" fn ratify_v2_library_version() -> *const c_char {
    crate::guard::ffi_guard(
        || c"".as_ptr(),
        || concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char,
    )
}

/// Returns the stable spelling for a `ratify_v2_*` result code: "ok", a
/// SPEC-v2 §2.7 failure class (e.g. "invalid_signature"), an ABI condition
/// ("null_pointer", "bad_argument", "internal", "cancelled"), a store
/// sentinel, a signing refusal, or "unknown". Statically allocated — do NOT
/// free.
#[no_mangle]
pub extern "C" fn ratify_v2_error_class_str(code: i32) -> *const c_char {
    crate::guard::ffi_guard(|| c"internal".as_ptr(), || code_cstr(code).as_ptr())
}

/// The diagnostic message of the most recent `ratify_v2_*` call on the
/// calling thread ("" after a success). The pointer is owned by the library
/// and valid until the next `ratify_v2_*` call on this thread — do NOT free.
#[no_mangle]
pub extern "C" fn ratify_v2_last_error_message() -> *const c_char {
    crate::guard::ffi_guard(
        || c"internal: a panic was caught at the C ABI boundary".as_ptr(),
        || LAST_ERROR.with(|l| l.borrow().as_ptr()),
    )
}

/// Release a buffer returned by the library. Safe to call with an empty
/// buffer. Each buffer must be freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_buffer_free(buffer: RatifyV2Buffer) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !buffer.ptr.is_null() && buffer.len > 0 {
                // SAFETY: ptr/len come from write_buffer's Box<[u8]>.
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    buffer.ptr, buffer.len,
                )));
            }
        },
    )
}

/// Release a string returned by a `ratify_v2_*` function. NULL is a no-op.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_string_free(s: *mut c_char) {
    crate::guard::ffi_guard(
        || (),
        || {
            if !s.is_null() {
                drop(CString::from_raw(s));
            }
        },
    )
}
