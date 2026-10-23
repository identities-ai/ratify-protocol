//! C callback interfaces for every Part A provider and Part B store, and the
//! adapters that present them to the Rust implementation.
//!
//! Every callback is a function pointer taking the caller's opaque `user`
//! pointer first. It runs on the calling thread before the ABI function
//! returns and is never retained afterwards, constraint evaluators included
//! (see `RatifyV2EvaluatorRegistration`). Buffers the
//! library passes in are valid only until the callback returns. Pointers a
//! callback writes into an output struct must stay valid until the callback
//! returns; the library copies them immediately after it returns.
//!
//! A callback returns 0 on success; a positive SPEC-v2 §2.7 code for a
//! classified failure (for example `RatifyV2ClockRegressed`); a store
//! sentinel (`RatifyV2Store*`); or `RatifyV2ErrCancelled`, which the library
//! treats as a provider cancellation under SPEC-v2 §6.11. Any other value is
//! an unclassified failure. A provider or store failure is always handled
//! fail-closed.

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::raw::{c_char, c_void};
use std::sync::Arc;
use std::time::Duration;

use ratify_protocol::v2::*;
use ratify_protocol::HybridPublicKey;

use super::marshal::{
    claim_from_json, claim_json, constraint_context_json, expected_challenge,
    expected_challenge_json, progress_from_json, progress_json, to_bytes,
};
use super::{
    code_class, code_str, AbiResult, Failure, RatifyV2Code, RatifyV2PublicKey, RatifyV2Slice,
};

/// Reads an authoritative clock (integer Unix seconds). A reading below the
/// greatest reading already returned must fail with `RatifyV2ClockRegressed`.
pub type RatifyV2NowFn = Option<unsafe extern "C" fn(user: *mut c_void, now_out: *mut i64) -> i32>;

/// An authoritative clock (SPEC-v2 §7.2).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2ClockCallbacks {
    pub user: *mut c_void,
    pub now: RatifyV2NowFn,
}

/// One sealed `max_rate` counter of a claim.
#[repr(C)]
pub struct RatifyV2RateReservation {
    pub issuer_id: *const c_char,
    pub cert_id: *const c_char,
    pub window_s: i64,
    pub limit: i64,
}

/// The claim a verifier asks a claim store to create (SPEC-v2 §7.3). The
/// scalar fields are the ones a store's rules read; `record` is a
/// deterministic encoding of every immutable claim field: an exact retry has
/// byte-identical `record`, and any difference for the same `claim_id` is a
/// different proof (`RatifyV2StoreClaimProofConflict`). Persist `record`
/// unchanged; `load_interrupted` returns it.
#[repr(C)]
pub struct RatifyV2ClaimView {
    pub claim_id: *const c_char,
    pub verifier_namespace: *const c_char,
    pub replay_epoch: i64,
    pub agent_id: *const c_char,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_age_seconds: i64,
    pub clock_skew_seconds: i64,
    pub has_stream_id: i32,
    pub stream_id: RatifyV2Slice,
    pub has_stream_seq: i32,
    pub stream_seq: i64,
    pub rate_batch: *const RatifyV2RateReservation,
    pub rate_batch_len: usize,
    pub record: RatifyV2Slice,
}

/// Claim dispositions.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2Disposition {
    RatifyV2DispositionNone = 0,
    RatifyV2DispositionCreated = 1,
    RatifyV2DispositionInProgress = 2,
    RatifyV2DispositionTerminalReplay = 3,
}

/// A claim store's answer. `owner_token` (32 random bytes) is set only for
/// `RatifyV2DispositionCreated`; store only its one-way hash.
#[repr(C)]
pub struct RatifyV2ClaimResult {
    pub disposition: i32,
    pub claimed_at: i64,
    pub owner_token: RatifyV2Slice,
}

/// What a claim store returns to lease-expiry recovery: the stored claim
/// `record`, the authoritative claim time, and the last stored `progress`
/// record (or an empty slice when none was recorded).
#[repr(C)]
pub struct RatifyV2InterruptedClaim {
    pub record: RatifyV2Slice,
    pub claimed_at: i64,
    pub progress: RatifyV2Slice,
}

/// Creates a claim atomically.
pub type RatifyV2ClaimFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim: *const RatifyV2ClaimView,
        out: *mut RatifyV2ClaimResult,
    ) -> i32,
>;
/// Commits a terminal result under the owner token and live lease, reading
/// T_final inside the compare-and-set. `*committed` is 1 when it commits, 0
/// for an identical repeat.
pub type RatifyV2FinalizeFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        owner_token: RatifyV2Slice,
        terminal_result: RatifyV2Slice,
        receipt_body: RatifyV2Slice,
        allow_valid_until: i64,
        committed: *mut i32,
    ) -> i32,
>;
/// Persists an evaluation progress record under the owner token.
pub type RatifyV2RecordProgressFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        owner_token: RatifyV2Slice,
        progress: RatifyV2Slice,
    ) -> i32,
>;
/// Loads an interrupted claim (fails with `RatifyV2ClaimLeaseLive` while the
/// lease is live).
pub type RatifyV2LoadInterruptedFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        out: *mut RatifyV2InterruptedClaim,
    ) -> i32,
>;
/// Commits only `indeterminate/evaluation_interrupted` after the lease
/// expired. `*committed` as for finalize.
pub type RatifyV2RecoverFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        terminal_result: RatifyV2Slice,
        receipt_body: RatifyV2Slice,
        committed: *mut i32,
    ) -> i32,
>;

/// The claim store (SPEC-v2 §7.2, §7.3, §7.5) with its authoritative clock.
/// Set `rate_at_finalization` to 1 when `finalize` admits the sealed rate
/// batch atomically (§7.6); it may then return
/// `RatifyV2StoreRateLimitExceeded` after a definitive rollback.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2ClaimStoreCallbacks {
    pub user: *mut c_void,
    pub rate_at_finalization: i32,
    pub now: RatifyV2NowFn,
    pub claim: RatifyV2ClaimFn,
    pub finalize: RatifyV2FinalizeFn,
    pub record_progress: RatifyV2RecordProgressFn,
    pub load_interrupted: RatifyV2LoadInterruptedFn,
    pub recover: RatifyV2RecoverFn,
}

/// Reserves a complete sealed rate batch. Return 0 (every counter held),
/// `RatifyV2StoreRateLimitExceeded` (definitive exhaustion), or another code
/// (unavailable; never authorizes).
pub type RatifyV2ReserveFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        owner_token: RatifyV2Slice,
        bundle_hash: *const c_char,
        batch: *const RatifyV2RateReservation,
        batch_len: usize,
    ) -> i32,
>;

/// The `max_rate` reservation store (SPEC-v2 §7.6). With
/// `rate_at_finalization` set, admission happens in the claim store's
/// finalize instead and `reserve` is not called.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2RateCallbacks {
    pub user: *mut c_void,
    pub rate_at_finalization: i32,
    pub reserve: RatifyV2ReserveFn,
}

/// What the claim store returns to release (§7.3, §6.9).
/// `receipt_outbox_digest` is `ReceiptOutboxDigest` of the committed body
/// (see `ratify_v2_receipt_outbox_digest`) or "" when not terminal.
#[repr(C)]
pub struct RatifyV2TerminalClaim {
    pub terminal: i32,
    pub receipt_outbox_digest: *const c_char,
    pub challenge_expires_at: i64,
    pub allow_horizon: i64,
    pub finalized_at: i64,
    pub receipt_abandoned: i32,
    pub has_release: i32,
    pub release_claim_id: *const c_char,
    pub release_entry_hash: RatifyV2Slice,
    pub release_ack_timestamp: i64,
}

/// The durable release record of §6.9 step 9.
#[repr(C)]
pub struct RatifyV2ReleaseRecord {
    pub claim_id: *const c_char,
    pub entry_hash: RatifyV2Slice,
    pub ack_timestamp: i64,
}

pub type RatifyV2LoadTerminalFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        claim_id: *const c_char,
        out: *mut RatifyV2TerminalClaim,
    ) -> i32,
>;
/// Records a release; an identical repeat is 0, a different existing record
/// is `RatifyV2StoreReleaseStateMismatch`.
pub type RatifyV2RecordReleaseFn =
    Option<unsafe extern "C" fn(user: *mut c_void, record: *const RatifyV2ReleaseRecord) -> i32>;

/// The claim-store view release needs, with its authoritative clock.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2ReleaseStoreCallbacks {
    pub user: *mut c_void,
    pub now: RatifyV2NowFn,
    pub load_terminal: RatifyV2LoadTerminalFn,
    pub record_release: RatifyV2RecordReleaseFn,
}

/// A checkpoint acknowledgement (§7.8).
#[repr(C)]
pub struct RatifyV2Acknowledgement {
    pub log_id: *const c_char,
    pub sequence: i64,
    pub entry_hash: RatifyV2Slice,
    pub timestamp: i64,
}

pub type RatifyV2AcknowledgeFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        log_id: *const c_char,
        sequence: i64,
        previous_entry_hash: RatifyV2Slice,
        entry_hash: RatifyV2Slice,
        out: *mut RatifyV2Acknowledgement,
    ) -> i32,
>;
/// Returns an acknowledgement, `RatifyV2StoreAcknowledgementNotFound`, or
/// another code for unavailability.
pub type RatifyV2GetAcknowledgementFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        log_id: *const c_char,
        sequence: i64,
        out: *mut RatifyV2Acknowledgement,
    ) -> i32,
>;

/// The caller-configured independent checkpoint (§7.8).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2CheckpointCallbacks {
    pub user: *mut c_void,
    pub acknowledge: RatifyV2AcknowledgeFn,
    pub get: RatifyV2GetAcknowledgementFn,
}

/// One anchored `SecurityJournalV2` state: its canonical snapshot bytes and
/// the independently anchored head (`generation`, `digest`).
#[repr(C)]
pub struct RatifyV2JournalSnapshot {
    pub snapshot: RatifyV2Slice,
    pub generation: u64,
    pub digest: *const c_char,
}

pub type RatifyV2JournalLoadFn =
    Option<unsafe extern "C" fn(user: *mut c_void, out: *mut RatifyV2JournalSnapshot) -> i32>;
/// Atomically replaces the stored state with `next` only while the anchored
/// head equals the expected head; otherwise `RatifyV2StoreJournalConflict`.
pub type RatifyV2JournalCasFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        expected_generation: u64,
        expected_digest: *const c_char,
        next: *const RatifyV2JournalSnapshot,
    ) -> i32,
>;

/// The rollback-protected, anchored security journal store (§6.6).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2JournalStoreCallbacks {
    pub user: *mut c_void,
    pub load: RatifyV2JournalLoadFn,
    pub compare_and_swap: RatifyV2JournalCasFn,
}

/// One delegation certificate of a verified chain, root-most last.
#[repr(C)]
pub struct RatifyV2CertView {
    pub cert_id: *const c_char,
    pub issuer_id: *const c_char,
    pub subject_id: *const c_char,
    pub issuer_public_key: *const RatifyV2PublicKey,
    pub subject_public_key: *const RatifyV2PublicKey,
    pub wire: RatifyV2Slice,
}

/// Trust provider outcomes (§6.1).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2TrustOutcome {
    RatifyV2TrustTrusted = 1,
    RatifyV2TrustUntrusted = 2,
    RatifyV2TrustUnavailable = 3,
    RatifyV2TrustAmbiguous = 4,
}

/// Resolves trust for a verified chain. For `RatifyV2TrustTrusted` write the
/// complete configured root key into `*root_key`; the verifier requires it
/// to equal the chain's terminal issuer.
pub type RatifyV2TrustFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        chain: *const RatifyV2CertView,
        chain_len: usize,
        outcome: *mut i32,
        root_key: *mut RatifyV2PublicKey,
    ) -> i32,
>;

/// The caller-authenticated trust provider.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2TrustCallbacks {
    pub user: *mut c_void,
    pub resolve: RatifyV2TrustFn,
}

/// An issuer-scoped certificate reference.
#[repr(C)]
pub struct RatifyV2CertRef {
    pub issuer_id: *const c_char,
    pub cert_id: *const c_char,
}

/// What the verifier asks a status provider for (§6.5).
#[repr(C)]
pub struct RatifyV2StatusRequest {
    pub issuer_id: *const c_char,
    pub status_key_epoch: u64,
    pub status_key_id: *const c_char,
    pub refs: *const RatifyV2CertRef,
    pub refs_len: usize,
}

/// One signed status object as received (0x0003 list or 0x0005 push).
#[repr(C)]
pub struct RatifyV2StatusObject {
    pub object_type: u16,
    pub wire: RatifyV2Slice,
}

/// A provider's bounded batch for one issuer (empty is valid).
#[repr(C)]
pub struct RatifyV2StatusBatch {
    pub objects: *const RatifyV2StatusObject,
    pub count: usize,
}

pub type RatifyV2StatusFetchFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        request: *const RatifyV2StatusRequest,
        out: *mut RatifyV2StatusBatch,
    ) -> i32,
>;

/// The status evidence provider: signed objects only, never a status result.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2StatusEvidenceCallbacks {
    pub user: *mut c_void,
    pub fetch: RatifyV2StatusFetchFn,
}

/// One deferred receiver-audience constraint.
#[repr(C)]
pub struct RatifyV2DeferredConstraint {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub issuer_id: *const c_char,
    pub cert_id: *const c_char,
    pub constraint_type: *const c_char,
    pub canonical_json: RatifyV2Slice,
}

/// One audience membership answer. Never copy these fields from a proof.
#[repr(C)]
pub struct RatifyV2AudienceMembership {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub receiver_id: *const c_char,
    pub trust_domain_ids: *const *const c_char,
    pub trust_domain_ids_len: usize,
    pub issued_at: i64,
    pub expires_at: i64,
    pub evidence_digest: *const c_char,
}

/// The memberships an audience provider returns.
#[repr(C)]
pub struct RatifyV2AudienceResult {
    pub memberships: *const RatifyV2AudienceMembership,
    pub count: usize,
}

pub type RatifyV2AudienceFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        deferred: *const RatifyV2DeferredConstraint,
        deferred_len: usize,
        receiver_id: *const c_char,
        out: *mut RatifyV2AudienceResult,
    ) -> i32,
>;

/// The receiver-audience membership provider.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2AudienceCallbacks {
    pub user: *mut c_void,
    pub lookup: RatifyV2AudienceFn,
}

/// The application's pure pre-claim receiver-binding hook. `bundle` is the
/// canonical proof bundle; `expected_challenge` is the ExpectedChallenge JSON.
/// Return 0 to accept; `RatifyV2ErrCancelled` cancels the operation before
/// the claim (`evaluation_cancelled`, nothing consumed, SPEC-v2 §6.11);
/// anything else rejects (`receiver_binding_rejected`).
pub type RatifyV2ReceiverBindingFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        bundle: RatifyV2Slice,
        expected_challenge: RatifyV2Slice,
    ) -> i32,
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2ReceiverBindingCallbacks {
    pub user: *mut c_void,
    pub check: RatifyV2ReceiverBindingFn,
}

/// Every verifier dependency; a NULL member is absent (a missing claim store
/// fails before claim; other absences are unavailable, fail-closed).
#[repr(C)]
pub struct RatifyV2VerifyCallbacks {
    pub claim_store: *const RatifyV2ClaimStoreCallbacks,
    pub trust: *const RatifyV2TrustCallbacks,
    pub status_evidence: *const RatifyV2StatusEvidenceCallbacks,
    pub status_journal: *const RatifyV2JournalStoreCallbacks,
    pub audience: *const RatifyV2AudienceCallbacks,
    pub rate: *const RatifyV2RateCallbacks,
    pub receiver_binding: *const RatifyV2ReceiverBindingCallbacks,
}

/// Persists a complete issuance record keyed by (namespace, replay epoch,
/// `ChallengeClaimDigest`); an existing key is `RatifyV2StoreIssuanceConflict`
/// and is never overwritten. `record` is the ExpectedChallenge JSON.
pub type RatifyV2IssuancePersistFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        verifier_namespace: *const c_char,
        replay_epoch: i64,
        claim_digest: RatifyV2Slice,
        record: RatifyV2Slice,
    ) -> i32,
>;
/// Loads a record into `*record` or returns `RatifyV2StoreIssuanceNotFound`.
pub type RatifyV2IssuanceLoadFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        verifier_namespace: *const c_char,
        replay_epoch: i64,
        claim_digest: RatifyV2Slice,
        record: *mut RatifyV2Slice,
    ) -> i32,
>;

/// The challenge issuance store (§7.3).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2IssuanceStoreCallbacks {
    pub user: *mut c_void,
    pub persist: RatifyV2IssuancePersistFn,
    pub load: RatifyV2IssuanceLoadFn,
}

/// Fills `len` bytes of `buf` with random bytes; non-zero fails.
pub type RatifyV2RandomFn =
    Option<unsafe extern "C" fn(user: *mut c_void, buf: *mut u8, len: usize) -> i32>;

/// An alternative random source for challenge issuance.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2RandomCallbacks {
    pub user: *mut c_void,
    pub fill: RatifyV2RandomFn,
}

// ---------------------------------------------------------------------------
// Evaluators

/// The control handle of one evaluator call. Poll
/// `ratify_v2_evaluator_call_expired` and return once it reports 1.
pub struct RatifyV2EvaluatorCall {
    pub(crate) ctx: V2Context,
}

/// Everything an evaluator may read (a copy). `params_json` is the canonical
/// params object when `has_params`; `request_context_json` uses the request
/// `"context"` schema; `evaluation_time` is the authoritative claim time.
#[repr(C)]
pub struct RatifyV2EvaluationInput {
    pub constraint_type: *const c_char,
    pub has_params: i32,
    pub params_json: RatifyV2Slice,
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub issuer_id: *const c_char,
    pub cert_id: *const c_char,
    pub request_context_json: RatifyV2Slice,
    pub evaluation_time: i64,
}

/// An evaluator verdict: `outcome` is a `RatifyV2EvaluatorOutcome`;
/// `valid_until` is an exclusive pass horizon (0 = none); `detail` is
/// diagnostic text (may be NULL).
#[repr(C)]
pub struct RatifyV2EvaluationResult {
    pub outcome: i32,
    pub valid_until: i64,
    pub detail: *const c_char,
}

/// A pure evaluator: no I/O, clock, or randomness. It runs on the calling
/// thread. A non-zero return, an invalid result, or an answer at or after
/// the registry deadline is unverifiable.
pub type RatifyV2EvaluateFn = Option<
    unsafe extern "C" fn(
        user: *mut c_void,
        call: *const RatifyV2EvaluatorCall,
        input: *const RatifyV2EvaluationInput,
        out: *mut RatifyV2EvaluationResult,
    ) -> i32,
>;

/// How a registered profile is implemented.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2EvaluatorImplementation {
    /// `evaluate` is called.
    RatifyV2EvaluatorCustom = 0,
    /// The built-in `com.ratifyprotocol.max_count/v1` implementation.
    RatifyV2EvaluatorStandardMaxCount = 1,
    /// The built-in `com.ratifyprotocol.allowed_values/v1` implementation.
    RatifyV2EvaluatorStandardAllowedValues = 2,
}

/// One extension evaluator: the `{profile, type}` descriptor sealed into
/// claims and receipts, and its implementation. A custom evaluator runs
/// synchronously on the calling thread (SPEC-v2 §1.3) and `user` is never
/// used after the call. The registry timeout is enforced by elapsed time:
/// the call is not interrupted, so an answer at or after the deadline is
/// discarded as `constraint_unverifiable`, and an evaluator that never
/// returns blocks the ABI call. Poll `ratify_v2_evaluator_call_expired` to
/// return promptly once the deadline has passed.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatifyV2EvaluatorRegistration {
    pub constraint_type: *const c_char,
    pub profile: *const c_char,
    pub implementation: i32,
    pub evaluate: RatifyV2EvaluateFn,
    pub user: *mut c_void,
}

/// The caller-authenticated evaluator registry for one call: at most 32
/// registrations, one per type, `timeout_ms` in 1..=10000.
#[repr(C)]
pub struct RatifyV2EvaluatorConfig {
    pub timeout_ms: u32,
    pub registrations: *const RatifyV2EvaluatorRegistration,
    pub count: usize,
}

/// 1 when the evaluator call's deadline has passed (return now), else 0.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_evaluator_call_expired(
    call: *const RatifyV2EvaluatorCall,
) -> i32 {
    crate::guard::ffi_guard(
        || 1,
        || call.as_ref().map_or(1, |c| i32::from(c.ctx.is_done())),
    )
}

// ---------------------------------------------------------------------------
// Adapters

/// Copy a C string the callback returned ("" for NULL).
pub(crate) unsafe fn owned(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

pub(crate) unsafe fn slice_vec(s: RatifyV2Slice) -> Vec<u8> {
    if s.ptr.is_null() || s.len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(s.ptr, s.len).to_vec()
    }
}

/// `s` as a C string for a callback. An identifier containing U+0000 cannot
/// cross into a C string unchanged, and stripping the NUL would merge
/// distinct identifiers, so it is refused; each caller reports the refusal
/// as its own provider or store failure, which fails closed.
pub(crate) fn cs(s: &str, what: &str) -> Result<CString, String> {
    CString::new(s)
        .map_err(|_| format!("{what} contains U+0000 and cannot be passed to a C callback"))
}

/// The operation's cancellation: a callback returning `RatifyV2ErrCancelled`
/// cancels the operation context.
#[derive(Clone)]
pub(crate) struct Cancel(pub V2CancelHandle);

impl Cancel {
    fn note(&self, code: i32) {
        if code == RatifyV2Code::RatifyV2ErrCancelled as i32 {
            self.0.cancel();
        }
    }
}

fn missing(what: &str) -> V2StoreError {
    V2StoreError::Unavailable(format!("{what} callback is not set"))
}

/// Map a callback status to a store error.
pub(crate) fn store_error(code: i32, cancel: &Cancel, what: &str) -> V2StoreError {
    use RatifyV2Code::*;
    cancel.note(code);
    let message = format!("{what} callback returned {}", code_str(code));
    if let Some(class) = code_class(code) {
        return V2StoreError::Classified(V2Error::new(class, message));
    }
    match code {
        c if c == RatifyV2StoreClaimProofConflict as i32 => V2StoreError::ClaimProofConflict,
        c if c == RatifyV2StoreRateLimitExceeded as i32 => V2StoreError::RateLimitExceeded,
        c if c == RatifyV2StoreReleaseStateMismatch as i32 => V2StoreError::ReleaseStateMismatch,
        c if c == RatifyV2StoreAcknowledgementNotFound as i32 => {
            V2StoreError::AcknowledgementNotFound
        }
        c if c == RatifyV2StoreIssuanceConflict as i32 => V2StoreError::ChallengeIssuanceConflict,
        c if c == RatifyV2StoreIssuanceNotFound as i32 => V2StoreError::ChallengeIssuanceNotFound,
        _ => V2StoreError::Unavailable(message),
    }
}

fn call_now(
    f: RatifyV2NowFn,
    user: *mut c_void,
    cancel: &Cancel,
    what: &str,
) -> Result<i64, V2StoreError> {
    let f = f.ok_or_else(|| missing(what))?;
    let mut now = 0i64;
    // SAFETY: caller-supplied callback and user pointer.
    let code = unsafe { f(user, &mut now) };
    if code != 0 {
        return Err(store_error(code, cancel, what));
    }
    Ok(now)
}

/// A C clock as a Rust authoritative clock.
pub(crate) struct CClock {
    pub cb: RatifyV2ClockCallbacks,
    pub cancel: Cancel,
}

// SAFETY: every adapter is used only on the thread of the ABI call that
// created it (evaluators excepted, which hold no adapter); the C side
// guarantees its user pointer is valid for that call.
unsafe impl Send for CClock {}
unsafe impl Sync for CClock {}

impl V2AuthoritativeClock for CClock {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        call_now(self.cb.now, self.cb.user, &self.cancel, "clock")
    }
}

/// A C claim store.
pub(crate) struct CClaimStore {
    pub cb: RatifyV2ClaimStoreCallbacks,
    pub cancel: Cancel,
}

unsafe impl Send for CClaimStore {}
unsafe impl Sync for CClaimStore {}

fn committed_result(
    code: i32,
    committed: i32,
    cancel: &Cancel,
    what: &str,
) -> Result<bool, V2StoreError> {
    if code != 0 {
        return Err(store_error(code, cancel, what));
    }
    Ok(committed != 0)
}

impl V2AuthoritativeClock for CClaimStore {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        call_now(self.cb.now, self.cb.user, &self.cancel, "claim store clock")
    }
}

impl ClaimStoreV2 for CClaimStore {
    fn claim_v2(
        &self,
        _ctx: &V2Context,
        claim: V2ChallengeClaim,
    ) -> Result<V2ClaimResult, V2StoreError> {
        let f = self.cb.claim.ok_or_else(|| missing("claim"))?;
        let record = claim_json(&claim);
        let (id, ns, agent) = (
            cs(&claim.claim_id, "claim_id").map_err(V2StoreError::Unavailable)?,
            cs(&claim.namespace, "verifier_namespace").map_err(V2StoreError::Unavailable)?,
            cs(&claim.agent_id, "agent_id").map_err(V2StoreError::Unavailable)?,
        );
        let rate_strings: Vec<(CString, CString)> = claim
            .rate_batch
            .iter()
            .map(|r| Ok((cs(&r.issuer_id, "issuer_id")?, cs(&r.cert_id, "cert_id")?)))
            .collect::<Result<_, String>>()
            .map_err(V2StoreError::Unavailable)?;
        let rate: Vec<RatifyV2RateReservation> = claim
            .rate_batch
            .iter()
            .zip(&rate_strings)
            .map(|(r, (i, c))| RatifyV2RateReservation {
                issuer_id: i.as_ptr(),
                cert_id: c.as_ptr(),
                window_s: r.window_s,
                limit: r.limit,
            })
            .collect();
        let stream_id = claim.stream_id.clone().unwrap_or_default();
        let view = RatifyV2ClaimView {
            claim_id: id.as_ptr(),
            verifier_namespace: ns.as_ptr(),
            replay_epoch: claim.replay_epoch,
            agent_id: agent.as_ptr(),
            issued_at: claim.issued_at,
            expires_at: claim.expires_at,
            max_age_seconds: claim.max_age_seconds,
            clock_skew_seconds: claim.clock_skew_seconds,
            has_stream_id: i32::from(claim.stream_id.is_some()),
            stream_id: RatifyV2Slice::of(&stream_id),
            has_stream_seq: i32::from(claim.stream_seq.is_some()),
            stream_seq: claim.stream_seq.unwrap_or(0),
            rate_batch: if rate.is_empty() {
                std::ptr::null()
            } else {
                rate.as_ptr()
            },
            rate_batch_len: rate.len(),
            record: RatifyV2Slice::of(&record),
        };
        let mut out = RatifyV2ClaimResult {
            disposition: 0,
            claimed_at: 0,
            owner_token: RatifyV2Slice::empty(),
        };
        // SAFETY: caller-supplied callback; view buffers outlive the call.
        let code = unsafe { f(self.cb.user, &view, &mut out) };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "claim"));
        }
        let disposition = match out.disposition {
            1 => V2ClaimDisposition::Created,
            2 => V2ClaimDisposition::InProgress,
            3 => V2ClaimDisposition::TerminalReplay,
            other => {
                return Err(V2StoreError::Unavailable(format!(
                    "claim callback returned disposition {other}"
                )))
            }
        };
        Ok(V2ClaimResult {
            disposition,
            claimed_at: out.claimed_at,
            // SAFETY: the callback's output pointer is valid until we copy it.
            owner_token: unsafe { slice_vec(out.owner_token) },
        })
    }

    fn finalize_v2_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        let f = self.cb.finalize.ok_or_else(|| missing("finalize"))?;
        let id = cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let mut committed = 0i32;
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                id.as_ptr(),
                RatifyV2Slice::of(owner_token),
                RatifyV2Slice::of(terminal_result),
                RatifyV2Slice::of(receipt_body),
                allow_valid_until,
                &mut committed,
            )
        };
        committed_result(code, committed, &self.cancel, "finalize")
    }

    fn record_v2_evaluation_progress(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        let f = self
            .cb
            .record_progress
            .ok_or_else(|| missing("record_progress"))?;
        let id = cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let record = progress_json(&progress);
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                id.as_ptr(),
                RatifyV2Slice::of(owner_token),
                RatifyV2Slice::of(&record),
            )
        };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "record_progress"));
        }
        Ok(())
    }

    fn load_v2_interrupted_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
    ) -> Result<V2InterruptedClaim, V2StoreError> {
        let f = self
            .cb
            .load_interrupted
            .ok_or_else(|| missing("load_interrupted"))?;
        let id = cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let mut out = RatifyV2InterruptedClaim {
            record: RatifyV2Slice::empty(),
            claimed_at: 0,
            progress: RatifyV2Slice::empty(),
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(self.cb.user, id.as_ptr(), &mut out) };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "load_interrupted"));
        }
        // SAFETY: output pointers valid until copied.
        let (record, progress) = unsafe { (slice_vec(out.record), slice_vec(out.progress)) };
        let claim = claim_from_json(&record).map_err(|f| {
            V2StoreError::Classified(V2Error::new(V2ErrorClass::Malformed, f.message))
        })?;
        let progress = if progress.is_empty() {
            initial_v2_evaluation_progress()
        } else {
            progress_from_json(&progress).map_err(|f| {
                V2StoreError::Classified(V2Error::new(V2ErrorClass::Malformed, f.message))
            })?
        };
        Ok(V2InterruptedClaim {
            claim,
            claimed_at: out.claimed_at,
            progress,
        })
    }

    fn recover_interrupted_v2_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        let f = self.cb.recover.ok_or_else(|| missing("recover"))?;
        let id = cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let mut committed = 0i32;
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                id.as_ptr(),
                RatifyV2Slice::of(terminal_result),
                RatifyV2Slice::of(receipt_body),
                &mut committed,
            )
        };
        committed_result(code, committed, &self.cancel, "recover")
    }

    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        (self.cb.rate_at_finalization != 0).then_some(self as &dyn V2RateAtFinalizationStore)
    }
}

impl V2RateReservationStore for CClaimStore {
    fn reserve_v2_rate_batch(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _owner_token: &[u8],
        _bundle_hash: &str,
        _batch: &[V2RateReservation],
    ) -> Result<(), V2StoreError> {
        Err(V2StoreError::Unavailable(
            "provisional rate reservation is not used with admission at finalization".into(),
        ))
    }

    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        (self.cb.rate_at_finalization != 0).then_some(self as &dyn V2RateAtFinalizationStore)
    }
}

impl V2RateAtFinalizationStore for CClaimStore {
    fn admits_v2_rate_at_finalization(&self) {}
}

/// A C rate store. With `rate_at_finalization`, it presents the claim store's
/// atomic admission view (the C callbacks then describe the same store).
pub(crate) struct CRate {
    pub cb: RatifyV2RateCallbacks,
    pub claim_store: Option<Arc<CClaimStore>>,
    pub fallback: CClaimStore,
    pub cancel: Cancel,
}

unsafe impl Send for CRate {}
unsafe impl Sync for CRate {}

impl V2RateReservationStore for CRate {
    fn reserve_v2_rate_batch(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        bundle_hash: &str,
        batch: &[V2RateReservation],
    ) -> Result<(), V2StoreError> {
        let f = self.cb.reserve.ok_or_else(|| missing("reserve"))?;
        let (id, hash) = (
            cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?,
            cs(bundle_hash, "bundle_hash").map_err(V2StoreError::Unavailable)?,
        );
        let strings: Vec<(CString, CString)> = batch
            .iter()
            .map(|r| Ok((cs(&r.issuer_id, "issuer_id")?, cs(&r.cert_id, "cert_id")?)))
            .collect::<Result<_, String>>()
            .map_err(V2StoreError::Unavailable)?;
        let items: Vec<RatifyV2RateReservation> = batch
            .iter()
            .zip(&strings)
            .map(|(r, (i, c))| RatifyV2RateReservation {
                issuer_id: i.as_ptr(),
                cert_id: c.as_ptr(),
                window_s: r.window_s,
                limit: r.limit,
            })
            .collect();
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                id.as_ptr(),
                RatifyV2Slice::of(owner_token),
                hash.as_ptr(),
                if items.is_empty() {
                    std::ptr::null()
                } else {
                    items.as_ptr()
                },
                items.len(),
            )
        };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "reserve"));
        }
        Ok(())
    }

    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        if self.cb.rate_at_finalization == 0 {
            return None;
        }
        Some(match &self.claim_store {
            Some(c) => c.as_ref() as &dyn V2RateAtFinalizationStore,
            None => &self.fallback as &dyn V2RateAtFinalizationStore,
        })
    }
}

/// A C release store.
pub(crate) struct CReleaseStore {
    pub cb: RatifyV2ReleaseStoreCallbacks,
    pub cancel: Cancel,
}

unsafe impl Send for CReleaseStore {}
unsafe impl Sync for CReleaseStore {}

impl V2AuthoritativeClock for CReleaseStore {
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        call_now(
            self.cb.now,
            self.cb.user,
            &self.cancel,
            "release store clock",
        )
    }
}

impl V2ReleaseClaimStore for CReleaseStore {
    fn load_v2_terminal_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
    ) -> Result<V2TerminalClaimRecord, V2StoreError> {
        let f = self
            .cb
            .load_terminal
            .ok_or_else(|| missing("load_terminal"))?;
        let id = cs(claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let mut out = RatifyV2TerminalClaim {
            terminal: 0,
            receipt_outbox_digest: std::ptr::null(),
            challenge_expires_at: 0,
            allow_horizon: 0,
            finalized_at: 0,
            receipt_abandoned: 0,
            has_release: 0,
            release_claim_id: std::ptr::null(),
            release_entry_hash: RatifyV2Slice::empty(),
            release_ack_timestamp: 0,
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(self.cb.user, id.as_ptr(), &mut out) };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "load_terminal"));
        }
        // SAFETY: output pointers valid until copied.
        unsafe {
            Ok(V2TerminalClaimRecord {
                terminal: out.terminal != 0,
                receipt_outbox_digest: owned(out.receipt_outbox_digest),
                challenge_expires_at: out.challenge_expires_at,
                allow_horizon: out.allow_horizon,
                finalized_at: out.finalized_at,
                receipt_abandoned: out.receipt_abandoned != 0,
                release: (out.has_release != 0).then(|| V2ReleaseRecord {
                    claim_id: owned(out.release_claim_id),
                    entry_hash: slice_vec(out.release_entry_hash),
                    ack_timestamp: out.release_ack_timestamp,
                }),
            })
        }
    }

    fn record_v2_release(
        &self,
        _ctx: &V2Context,
        record: V2ReleaseRecord,
    ) -> Result<(), V2StoreError> {
        let f = self
            .cb
            .record_release
            .ok_or_else(|| missing("record_release"))?;
        let id = cs(&record.claim_id, "claim_id").map_err(V2StoreError::Unavailable)?;
        let view = RatifyV2ReleaseRecord {
            claim_id: id.as_ptr(),
            entry_hash: RatifyV2Slice::of(&record.entry_hash),
            ack_timestamp: record.ack_timestamp,
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(self.cb.user, &view) };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "record_release"));
        }
        Ok(())
    }
}

/// A C checkpoint.
pub(crate) struct CCheckpoint {
    pub cb: RatifyV2CheckpointCallbacks,
    pub cancel: Cancel,
}

unsafe impl Send for CCheckpoint {}
unsafe impl Sync for CCheckpoint {}

fn empty_ack() -> RatifyV2Acknowledgement {
    RatifyV2Acknowledgement {
        log_id: std::ptr::null(),
        sequence: 0,
        entry_hash: RatifyV2Slice::empty(),
        timestamp: 0,
    }
}

unsafe fn ack_of(a: &RatifyV2Acknowledgement) -> V2CheckpointAcknowledgement {
    V2CheckpointAcknowledgement {
        log_id: owned(a.log_id),
        sequence: a.sequence,
        entry_hash: slice_vec(a.entry_hash),
        timestamp: a.timestamp,
    }
}

impl V2ReceiptCheckpoint for CCheckpoint {
    fn acknowledge_v2_receipt(
        &self,
        _ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let f = self.cb.acknowledge.ok_or_else(|| missing("acknowledge"))?;
        let id = cs(log_id, "log_id").map_err(V2StoreError::Unavailable)?;
        let mut out = empty_ack();
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                id.as_ptr(),
                sequence,
                RatifyV2Slice::of(previous_entry_hash),
                RatifyV2Slice::of(entry_hash),
                &mut out,
            )
        };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "acknowledge"));
        }
        // SAFETY: output pointers valid until copied.
        Ok(unsafe { ack_of(&out) })
    }

    fn get_v2_acknowledgement(
        &self,
        _ctx: &V2Context,
        log_id: &str,
        sequence: i64,
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let f = self.cb.get.ok_or_else(|| missing("get acknowledgement"))?;
        let id = cs(log_id, "log_id").map_err(V2StoreError::Unavailable)?;
        let mut out = empty_ack();
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(self.cb.user, id.as_ptr(), sequence, &mut out) };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "get acknowledgement"));
        }
        // SAFETY: output pointers valid until copied.
        Ok(unsafe { ack_of(&out) })
    }
}

/// A C security journal store.
pub(crate) struct CJournal {
    pub cb: RatifyV2JournalStoreCallbacks,
    pub cancel: Cancel,
}

unsafe impl Send for CJournal {}
unsafe impl Sync for CJournal {}

fn journal_error(code: i32, cancel: &Cancel, what: &str) -> V2Error {
    cancel.note(code);
    let message = format!("journal {what} callback returned {}", code_str(code));
    V2Error::new(
        code_class(code).unwrap_or(V2ErrorClass::StatusObjectRejected),
        message,
    )
}

impl SecurityJournalStoreV2 for CJournal {
    /// The stored snapshot is imported against the reported generation and
    /// the snapshot's own digest; the reported head is returned unchanged, so
    /// the verifier's own head check applies exactly as for any store.
    fn load(&self, _ctx: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)> {
        let f = self.cb.load.ok_or_else(|| {
            V2Error::new(
                V2ErrorClass::StatusObjectRejected,
                "journal load callback is not set",
            )
        })?;
        let mut out = RatifyV2JournalSnapshot {
            snapshot: RatifyV2Slice::empty(),
            generation: 0,
            digest: std::ptr::null(),
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(self.cb.user, &mut out) };
        if code != 0 {
            return Err(journal_error(code, &self.cancel, "load"));
        }
        // SAFETY: output pointers valid until copied.
        let (snapshot, digest) = unsafe { (slice_vec(out.snapshot), owned(out.digest)) };
        let own = SecurityJournalHeadV2 {
            generation: out.generation,
            digest: security_journal_snapshot_digest_v2(&snapshot),
        };
        let journal = import_security_journal_snapshot_v2(&snapshot, &own)?;
        Ok((
            journal,
            SecurityJournalHeadV2 {
                generation: out.generation,
                digest,
            },
        ))
    }

    fn compare_and_swap(
        &self,
        _ctx: &V2Context,
        expected: &SecurityJournalHeadV2,
        next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        let f = self.cb.compare_and_swap.ok_or_else(|| {
            SecurityJournalStoreErrorV2::Failed(V2Error::new(
                V2ErrorClass::StatusObjectRejected,
                "journal compare_and_swap callback is not set",
            ))
        })?;
        let snapshot = export_security_journal_snapshot_v2(next)?;
        let journal_digest = |d: &str| {
            cs(d, "journal digest").map_err(|m| {
                SecurityJournalStoreErrorV2::Failed(V2Error::new(
                    V2ErrorClass::StatusObjectRejected,
                    m,
                ))
            })
        };
        let (expected_digest, next_digest) =
            (journal_digest(&expected.digest)?, journal_digest(&next.digest)?);
        let view = RatifyV2JournalSnapshot {
            snapshot: RatifyV2Slice::of(&snapshot),
            generation: next.generation,
            digest: next_digest.as_ptr(),
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                expected.generation,
                expected_digest.as_ptr(),
                &view,
            )
        };
        match code {
            0 => Ok(()),
            c if c == RatifyV2Code::RatifyV2StoreJournalConflict as i32 => {
                Err(SecurityJournalStoreErrorV2::Conflict)
            }
            c => Err(SecurityJournalStoreErrorV2::Failed(journal_error(
                c,
                &self.cancel,
                "compare_and_swap",
            ))),
        }
    }
}

fn key_struct(k: &HybridPublicKey) -> RatifyV2PublicKey {
    let mut out = RatifyV2PublicKey {
        ed25519: [0; 32],
        ml_dsa_65: [0; 1952],
    };
    if k.ed25519.len() == 32 && k.ml_dsa_65.len() == 1952 {
        out.ed25519.copy_from_slice(&k.ed25519);
        out.ml_dsa_65.copy_from_slice(&k.ml_dsa_65);
    }
    out
}

/// Wraps a copied callback struct so a closure captures it whole (closures
/// otherwise capture the raw-pointer fields individually).
struct Raw<T>(T);

impl<T> Raw<T> {
    fn get(&self) -> &T {
        &self.0
    }
}
// SAFETY: see CClock.
unsafe impl<T> Send for Raw<T> {}
unsafe impl<T> Sync for Raw<T> {}

pub(crate) fn trust_provider(cb: RatifyV2TrustCallbacks, cancel: Cancel) -> V2TrustProvider {
    let cb = Raw(cb);
    Arc::new(move |_ctx: &V2Context, chain: &[DelegationCertV2]| {
        let cb = cb.get();
        let f = cb
            .resolve
            .ok_or_else(|| V2ProviderError::new("trust resolve callback is not set"))?;
        let mut strings = Vec::new();
        let mut keys = Vec::new();
        let mut wires = Vec::new();
        for c in chain {
            strings.push((
                cs(&c.cert_id, "cert_id").map_err(V2ProviderError::new)?,
                cs(&c.issuer_id, "issuer_id").map_err(V2ProviderError::new)?,
                cs(&c.subject_id, "subject_id").map_err(V2ProviderError::new)?,
            ));
            keys.push((
                key_struct(&c.issuer_pub_key),
                key_struct(&c.subject_pub_key),
            ));
            wires.push(encode_delegation_cert_v2(c).unwrap_or_default());
        }
        let views: Vec<RatifyV2CertView> = (0..chain.len())
            .map(|i| RatifyV2CertView {
                cert_id: strings[i].0.as_ptr(),
                issuer_id: strings[i].1.as_ptr(),
                subject_id: strings[i].2.as_ptr(),
                issuer_public_key: &keys[i].0,
                subject_public_key: &keys[i].1,
                wire: RatifyV2Slice::of(&wires[i]),
            })
            .collect();
        let mut outcome = 0i32;
        let mut root = key_struct(&HybridPublicKey {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        });
        // SAFETY: caller-supplied callback; views outlive the call.
        let code = unsafe {
            f(
                cb.user,
                views.as_ptr(),
                views.len(),
                &mut outcome,
                &mut root,
            )
        };
        if code != 0 {
            cancel.note(code);
            return Err(V2ProviderError::new(format!(
                "trust callback returned {}",
                code_str(code)
            )));
        }
        let outcome = match outcome {
            1 => V2TrustOutcome::Trusted,
            2 => V2TrustOutcome::Untrusted,
            3 => V2TrustOutcome::Unavailable,
            4 => V2TrustOutcome::Ambiguous,
            other => {
                return Err(V2ProviderError::new(format!(
                    "trust callback returned outcome {other}"
                )))
            }
        };
        Ok(V2TrustResolution {
            outcome,
            root_key: if outcome == V2TrustOutcome::Trusted {
                root.as_hybrid()
            } else {
                HybridPublicKey {
                    ed25519: Vec::new(),
                    ml_dsa_65: Vec::new(),
                }
            },
        })
    })
}

pub(crate) fn status_provider(
    cb: RatifyV2StatusEvidenceCallbacks,
    cancel: Cancel,
) -> V2StatusEvidenceProvider {
    let cb = Raw(cb);
    Arc::new(move |_ctx: &V2Context, r: &V2StatusEvidenceRequest| {
        let cb = cb.get();
        let f = cb
            .fetch
            .ok_or_else(|| V2StatusProviderError::new("status fetch callback is not set"))?;
        let (issuer, key_id) = (
            cs(&r.issuer_id, "issuer_id").map_err(V2StatusProviderError::new)?,
            cs(&r.status_key_id, "status_key_id").map_err(V2StatusProviderError::new)?,
        );
        let ref_strings: Vec<(CString, CString)> = r
            .refs
            .iter()
            .map(|x| Ok((cs(&x.issuer_id, "issuer_id")?, cs(&x.cert_id, "cert_id")?)))
            .collect::<Result<_, String>>()
            .map_err(V2StatusProviderError::new)?;
        let refs: Vec<RatifyV2CertRef> = ref_strings
            .iter()
            .map(|(i, c)| RatifyV2CertRef {
                issuer_id: i.as_ptr(),
                cert_id: c.as_ptr(),
            })
            .collect();
        let req = RatifyV2StatusRequest {
            issuer_id: issuer.as_ptr(),
            status_key_epoch: r.status_key_epoch,
            status_key_id: key_id.as_ptr(),
            refs: if refs.is_empty() {
                std::ptr::null()
            } else {
                refs.as_ptr()
            },
            refs_len: refs.len(),
        };
        let mut out = RatifyV2StatusBatch {
            objects: std::ptr::null(),
            count: 0,
        };
        // SAFETY: caller-supplied callback.
        let code = unsafe { f(cb.user, &req, &mut out) };
        if code != 0 {
            cancel.note(code);
            return Err(V2StatusProviderError::new(format!(
                "status callback returned {}",
                code_str(code)
            )));
        }
        let mut objects = Vec::new();
        if out.count > 0 {
            if out.objects.is_null() {
                return Err(V2StatusProviderError::new(
                    "status callback returned a NULL batch",
                ));
            }
            // SAFETY: the callback reported `count` readable entries.
            for o in unsafe { std::slice::from_raw_parts(out.objects, out.count) } {
                objects.push(V2StatusEvidenceObject {
                    object_type: o.object_type,
                    // SAFETY: as above.
                    wire: unsafe { slice_vec(o.wire) },
                });
            }
        }
        Ok(V2StatusEvidenceBatch { objects })
    })
}

pub(crate) fn audience_provider(
    cb: RatifyV2AudienceCallbacks,
    cancel: Cancel,
) -> V2AudienceProvider {
    let cb = Raw(cb);
    Arc::new(
        move |_ctx: &V2Context, deferred: &[V2DeferredConstraint], receiver_id: &str| {
            let cb = cb.get();
            let f = cb
                .lookup
                .ok_or_else(|| V2ProviderError::new("audience lookup callback is not set"))?;
            let strings: Vec<(CString, CString, CString)> = deferred
                .iter()
                .map(|d| {
                    Ok((
                        cs(&d.issuer_id, "issuer_id")?,
                        cs(&d.cert_id, "cert_id")?,
                        cs(&d.kind, "constraint type")?,
                    ))
                })
                .collect::<Result<_, String>>()
                .map_err(V2ProviderError::new)?;
            let views: Vec<RatifyV2DeferredConstraint> = deferred
                .iter()
                .zip(&strings)
                .map(|(d, (i, c, k))| RatifyV2DeferredConstraint {
                    delegation_index: d.delegation_index,
                    constraint_index: d.constraint_index,
                    issuer_id: i.as_ptr(),
                    cert_id: c.as_ptr(),
                    constraint_type: k.as_ptr(),
                    canonical_json: RatifyV2Slice::of(&d.canonical_json),
                })
                .collect();
            let receiver = cs(receiver_id, "receiver_id").map_err(V2ProviderError::new)?;
            let mut out = RatifyV2AudienceResult {
                memberships: std::ptr::null(),
                count: 0,
            };
            // SAFETY: caller-supplied callback.
            let code = unsafe {
                f(
                    cb.user,
                    views.as_ptr(),
                    views.len(),
                    receiver.as_ptr(),
                    &mut out,
                )
            };
            if code != 0 {
                cancel.note(code);
                return Err(V2ProviderError::new(format!(
                    "audience callback returned {}",
                    code_str(code)
                )));
            }
            let mut memberships = Vec::new();
            if out.count > 0 {
                if out.memberships.is_null() {
                    return Err(V2ProviderError::new(
                        "audience callback returned NULL memberships",
                    ));
                }
                // SAFETY: the callback reported `count` readable entries.
                for m in unsafe { std::slice::from_raw_parts(out.memberships, out.count) } {
                    let mut domains = Vec::new();
                    if m.trust_domain_ids_len > 0 && !m.trust_domain_ids.is_null() {
                        // SAFETY: as above.
                        for d in unsafe {
                            std::slice::from_raw_parts(m.trust_domain_ids, m.trust_domain_ids_len)
                        } {
                            // SAFETY: as above.
                            domains.push(unsafe { owned(*d) });
                        }
                    }
                    memberships.push(V2AudienceMembership {
                        delegation_index: m.delegation_index,
                        constraint_index: m.constraint_index,
                        // SAFETY: as above.
                        receiver_id: unsafe { owned(m.receiver_id) },
                        trust_domain_ids: domains,
                        issued_at: m.issued_at,
                        expires_at: m.expires_at,
                        // SAFETY: as above.
                        evidence_digest: unsafe { owned(m.evidence_digest) },
                    });
                }
            }
            Ok(memberships)
        },
    )
}

pub(crate) fn receiver_binding_hook(
    cb: RatifyV2ReceiverBindingCallbacks,
    cancel: Cancel,
) -> V2ReceiverBindingHook {
    let cb = Raw(cb);
    Arc::new(
        move |bundle: &ProofBundleV2, expected: &ExpectedChallengeV2| {
            let cb = cb.get();
            let f = cb
                .check
                .ok_or_else(|| V2ProviderError::new("receiver binding callback is not set"))?;
            let wire =
                encode_proof_bundle_v2(bundle).map_err(|e| V2ProviderError::new(e.message))?;
            let exp = to_bytes(&expected_challenge_json(expected));
            // SAFETY: caller-supplied callback.
            let code = unsafe { f(cb.user, RatifyV2Slice::of(&wire), RatifyV2Slice::of(&exp)) };
            if code != 0 {
                cancel.note(code);
                return Err(V2ProviderError::new(format!(
                    "receiver binding callback returned {}",
                    code_str(code)
                )));
            }
            Ok(())
        },
    )
}

/// A C challenge issuance store.
pub(crate) struct CIssuance {
    pub cb: RatifyV2IssuanceStoreCallbacks,
    pub cancel: Cancel,
}

unsafe impl Send for CIssuance {}
unsafe impl Sync for CIssuance {}

impl V2ChallengeIssuanceStore for CIssuance {
    fn persist_v2_challenge(
        &self,
        _ctx: &V2Context,
        record: ExpectedChallengeV2,
    ) -> Result<(), V2StoreError> {
        let f = self.cb.persist.ok_or_else(|| missing("issuance persist"))?;
        let digest = challenge_claim_digest_v2(&record.value).map_err(V2StoreError::Classified)?;
        let ns = cs(&record.verifier_namespace, "verifier_namespace").map_err(V2StoreError::Unavailable)?;
        let json = to_bytes(&expected_challenge_json(&record));
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                ns.as_ptr(),
                record.replay_epoch,
                RatifyV2Slice::of(&digest),
                RatifyV2Slice::of(&json),
            )
        };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "issuance persist"));
        }
        Ok(())
    }

    fn load_v2_challenge(
        &self,
        _ctx: &V2Context,
        namespace: &str,
        replay_epoch: i64,
        claim_digest: &[u8],
    ) -> Result<ExpectedChallengeV2, V2StoreError> {
        let f = self.cb.load.ok_or_else(|| missing("issuance load"))?;
        let ns = cs(namespace, "verifier_namespace").map_err(V2StoreError::Unavailable)?;
        let mut out = RatifyV2Slice::empty();
        // SAFETY: caller-supplied callback.
        let code = unsafe {
            f(
                self.cb.user,
                ns.as_ptr(),
                replay_epoch,
                RatifyV2Slice::of(claim_digest),
                &mut out,
            )
        };
        if code != 0 {
            return Err(store_error(code, &self.cancel, "issuance load"));
        }
        // SAFETY: output pointer valid until copied.
        let data = unsafe { slice_vec(out) };
        let v: serde_json::Value = super::strict_json(&data)
            .map_err(|e| V2StoreError::Unavailable(format!("issuance record is not JSON: {e}")))?;
        expected_challenge(&v)
            .map_err(|f| V2StoreError::Unavailable(format!("issuance record: {}", f.message)))
    }
}

/// A C random source as `Read`.
pub(crate) struct CRandom(pub RatifyV2RandomCallbacks);

unsafe impl Send for CRandom {}

impl Read for CRandom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(f) = self.0.fill else {
            return Err(std::io::Error::other("random fill callback is not set"));
        };
        // SAFETY: caller-supplied callback filling our buffer.
        let code = unsafe { f(self.0.user, buf.as_mut_ptr(), buf.len()) };
        if code != 0 {
            return Err(std::io::Error::other(format!(
                "random source returned {}",
                code_str(code)
            )));
        }
        Ok(buf.len())
    }
}

// ---------------------------------------------------------------------------
// Evaluator registry for one call

fn custom_evaluator(reg: RatifyV2EvaluatorRegistration) -> ConstraintEvaluatorFnV2 {
    let reg = Raw(reg);
    Arc::new(
        move |ctx: &V2Context, input: &ConstraintEvaluationInputV2| {
            let reg = reg.get();
            let f = reg.evaluate.ok_or_else(|| {
                ConstraintEvaluatorError("custom evaluator has no evaluate callback".into())
            })?;
            let (kind, issuer, cert) = (
                cs(&input.kind, "constraint type").map_err(ConstraintEvaluatorError)?,
                cs(&input.issuer_id, "issuer_id").map_err(ConstraintEvaluatorError)?,
                cs(&input.cert_id, "cert_id").map_err(ConstraintEvaluatorError)?,
            );
            let context = to_bytes(&constraint_context_json(&input.context));
            let params = input.params_json.clone().unwrap_or_default();
            let view = RatifyV2EvaluationInput {
                constraint_type: kind.as_ptr(),
                has_params: i32::from(input.params_json.is_some()),
                params_json: RatifyV2Slice::of(&params),
                delegation_index: input.delegation_index,
                constraint_index: input.constraint_index,
                issuer_id: issuer.as_ptr(),
                cert_id: cert.as_ptr(),
                request_context_json: RatifyV2Slice::of(&context),
                evaluation_time: input.evaluation_time,
            };
            let call = RatifyV2EvaluatorCall { ctx: ctx.clone() };
            let mut out = RatifyV2EvaluationResult {
                outcome: 0,
                valid_until: 0,
                detail: std::ptr::null(),
            };
            // SAFETY: caller-supplied callback, invoked on the calling thread
            // during the ABI call.
            let code = unsafe { f(reg.user, &call, &view, &mut out) };
            if code != 0 {
                return Err(ConstraintEvaluatorError(format!(
                    "evaluator returned {}",
                    code_str(code)
                )));
            }
            let outcome = match out.outcome {
                1 => ConstraintOutcomeV2::Pass,
                2 => ConstraintOutcomeV2::Denied,
                3 => ConstraintOutcomeV2::Unverifiable,
                _ => ConstraintOutcomeV2::Invalid,
            };
            Ok(ConstraintEvaluationResultV2 {
                outcome,
                valid_until: out.valid_until,
                // SAFETY: output pointer valid until copied.
                detail: unsafe { owned(out.detail) },
            })
        },
    )
}

/// Build the Rust registry for one call. A NULL config registers none.
/// Evaluators run on the calling thread (SPEC-v2 §1.3); the timeout is
/// enforced by elapsed time, so an answer at or after the deadline is
/// `constraint_unverifiable`.
pub(crate) unsafe fn evaluator_registry(
    config: *const RatifyV2EvaluatorConfig,
) -> AbiResult<Option<ConstraintEvaluatorRegistryV2>> {
    let Some(config) = config.as_ref() else {
        return Ok(None);
    };
    let regs: &[RatifyV2EvaluatorRegistration] = if config.count == 0 {
        &[]
    } else if config.registrations.is_null() {
        return Err(super::null_arg("evaluator registrations"));
    } else {
        std::slice::from_raw_parts(config.registrations, config.count)
    };
    let mut registrations = Vec::new();
    for r in regs {
        let descriptor = ConstraintProfileDescriptorV2 {
            profile: super::cstr(r.profile, "evaluator profile")?.to_string(),
            kind: super::cstr(r.constraint_type, "evaluator constraint_type")?.to_string(),
        };
        let evaluate = match r.implementation {
            0 => custom_evaluator(*r),
            1 => standard_max_count_evaluator_v2().evaluate,
            2 => standard_allowed_values_evaluator_v2().evaluate,
            other => {
                return Err(super::bad_arg(format!(
                    "evaluator implementation {other} is not defined"
                )))
            }
        };
        registrations.push(ConstraintEvaluatorRegistrationV2 {
            descriptor,
            evaluate,
        });
    }
    let registry = ConstraintEvaluatorRegistryV2::new_with_invocation(
        Duration::from_millis(u64::from(config.timeout_ms)),
        registrations,
        ConstraintEvaluatorInvocationV2::CallingThread,
    )
    .map_err(Failure::from)?;
    Ok(Some(registry))
}

/// Everything a verification-shaped call needs from `RatifyV2VerifyCallbacks`.
pub(crate) struct VerifyDeps {
    pub callbacks: V2VerifyCallbacks,
}

/// Build the Rust callbacks from the C struct for one call.
pub(crate) unsafe fn build_callbacks(
    cb: *const RatifyV2VerifyCallbacks,
    cancel: &Cancel,
) -> VerifyDeps {
    let mut out = V2VerifyCallbacks::default();
    let Some(cb) = cb.as_ref() else {
        return VerifyDeps { callbacks: out };
    };
    let claim = cb.claim_store.as_ref().map(|c| {
        Arc::new(CClaimStore {
            cb: *c,
            cancel: cancel.clone(),
        })
    });
    if let Some(c) = &claim {
        out.claim_store = Some(c.clone());
    }
    if let Some(t) = cb.trust.as_ref() {
        out.trust = Some(trust_provider(*t, cancel.clone()));
    }
    if let Some(s) = cb.status_evidence.as_ref() {
        out.status_evidence = Some(status_provider(*s, cancel.clone()));
    }
    if let Some(j) = cb.status_journal.as_ref() {
        out.status_journal = Some(Arc::new(CJournal {
            cb: *j,
            cancel: cancel.clone(),
        }));
    }
    if let Some(a) = cb.audience.as_ref() {
        out.audience = Some(audience_provider(*a, cancel.clone()));
    }
    if let Some(r) = cb.rate.as_ref() {
        out.rate = Some(Arc::new(CRate {
            cb: *r,
            claim_store: claim.clone(),
            fallback: CClaimStore {
                cb: RatifyV2ClaimStoreCallbacks {
                    user: std::ptr::null_mut(),
                    rate_at_finalization: 0,
                    now: None,
                    claim: None,
                    finalize: None,
                    record_progress: None,
                    load_interrupted: None,
                    recover: None,
                },
                cancel: cancel.clone(),
            },
            cancel: cancel.clone(),
        }));
    }
    if let Some(h) = cb.receiver_binding.as_ref() {
        out.receiver_binding = Some(receiver_binding_hook(*h, cancel.clone()));
    }
    VerifyDeps { callbacks: out }
}

#[cfg(test)]
mod nul_identifier_tests {
    //! An identifier containing U+0000 cannot reach a C callback unchanged.
    //! Each adapter must refuse it (fail closed, as that provider or store
    //! being unavailable) and must never call the callback with the NUL
    //! stripped, which would merge distinct identifiers.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    // The tests share CALLS, so they run one at a time.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn called() -> usize {
        CALLS.swap(0, Ordering::SeqCst)
    }

    fn cancel() -> Cancel {
        Cancel(V2Context::background().with_cancel().1)
    }

    unsafe extern "C" fn claim(
        _: *mut c_void,
        _: *const RatifyV2ClaimView,
        out: *mut RatifyV2ClaimResult,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        (*out).disposition = 1;
        0
    }

    unsafe extern "C" fn reserve(
        _: *mut c_void,
        _: *const c_char,
        _: RatifyV2Slice,
        _: *const c_char,
        _: *const RatifyV2RateReservation,
        _: usize,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn persist(
        _: *mut c_void,
        _: *const c_char,
        _: i64,
        _: RatifyV2Slice,
        _: RatifyV2Slice,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn load(
        _: *mut c_void,
        _: *const c_char,
        _: i64,
        _: RatifyV2Slice,
        _: *mut RatifyV2Slice,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        RatifyV2Code::RatifyV2StoreIssuanceNotFound as i32
    }

    unsafe extern "C" fn trust(
        _: *mut c_void,
        _: *const RatifyV2CertView,
        _: usize,
        _: *mut i32,
        _: *mut RatifyV2PublicKey,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn fetch(
        _: *mut c_void,
        _: *const RatifyV2StatusRequest,
        _: *mut RatifyV2StatusBatch,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn lookup(
        _: *mut c_void,
        _: *const RatifyV2DeferredConstraint,
        _: usize,
        _: *const c_char,
        _: *mut RatifyV2AudienceResult,
    ) -> i32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }

    fn claim_store() -> CClaimStore {
        CClaimStore {
            cb: RatifyV2ClaimStoreCallbacks {
                user: std::ptr::null_mut(),
                rate_at_finalization: 0,
                now: None,
                claim: Some(claim),
                finalize: None,
                record_progress: None,
                load_interrupted: None,
                recover: None,
            },
            cancel: cancel(),
        }
    }

    fn rate(cert_id: &str) -> V2RateReservation {
        V2RateReservation {
            issuer_id: "issuer".into(),
            cert_id: cert_id.into(),
            window_s: 60,
            limit: 1,
        }
    }

    fn unavailable<T: std::fmt::Debug>(r: Result<T, V2StoreError>) {
        match r {
            Err(V2StoreError::Unavailable(m)) => assert!(m.contains("U+0000"), "{m}"),
            other => panic!("expected an unavailable store, got {other:?}"),
        }
    }

    #[test]
    fn claim_store_refuses_nul_identifiers() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = V2Context::background();
        let store = claim_store();
        let ok = V2ChallengeClaim {
            namespace: "lab".into(),
            rate_batch: vec![rate("xy")],
            ..Default::default()
        };
        store.claim_v2(&ctx, ok.clone()).expect("control claim");
        assert_eq!(called(), 1);
        for claim in [
            V2ChallengeClaim {
                namespace: "lab\0x".into(),
                ..ok.clone()
            },
            V2ChallengeClaim {
                rate_batch: vec![rate("x\0y")],
                ..ok.clone()
            },
        ] {
            unavailable(store.claim_v2(&ctx, claim));
            assert_eq!(called(), 0);
        }
    }

    #[test]
    fn rate_store_refuses_nul_cert_id() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = V2Context::background();
        let store = CRate {
            cb: RatifyV2RateCallbacks {
                user: std::ptr::null_mut(),
                rate_at_finalization: 0,
                reserve: Some(reserve),
            },
            claim_store: None,
            fallback: claim_store(),
            cancel: cancel(),
        };
        store
            .reserve_v2_rate_batch(&ctx, "id", b"t", "h", &[rate("xy")])
            .expect("control reservation");
        assert_eq!(called(), 1);
        unavailable(store.reserve_v2_rate_batch(&ctx, "id", b"t", "h", &[rate("x\0y")]));
        assert_eq!(called(), 0);
    }

    #[test]
    fn issuance_store_refuses_nul_namespace() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = V2Context::background();
        let store = CIssuance {
            cb: RatifyV2IssuanceStoreCallbacks {
                user: std::ptr::null_mut(),
                persist: Some(persist),
                load: Some(load),
            },
            cancel: cancel(),
        };
        let record = |ns: &str| ExpectedChallengeV2 {
            value: vec![7; 32],
            verifier_namespace: ns.into(),
            ..Default::default()
        };
        store
            .persist_v2_challenge(&ctx, record("labx"))
            .expect("control persist");
        assert_eq!(called(), 1);
        unavailable(store.persist_v2_challenge(&ctx, record("lab\0x")));
        unavailable(store.load_v2_challenge(&ctx, "lab\0x", 1, &[0; 32]));
        assert_eq!(called(), 0);
    }

    #[test]
    fn providers_refuse_nul_identifiers() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = V2Context::background();

        let objects: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testvectors/v2/objects.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let wire = objects["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["kind"] == "delegation_certificate")
            .and_then(|o| o["wire_b64"].as_str())
            .map(|w| ratify_protocol::base64_std_decode(w).unwrap())
            .unwrap();
        let mut cert = decode_delegation_cert_v2(&wire).unwrap();
        let trust_cb = trust_provider(
            RatifyV2TrustCallbacks {
                user: std::ptr::null_mut(),
                resolve: Some(trust),
            },
            cancel(),
        );
        let _ = trust_cb(&ctx, std::slice::from_ref(&cert));
        assert_eq!(called(), 1, "control trust call");
        cert.cert_id = "x\0y".into();
        assert!(trust_cb(&ctx, std::slice::from_ref(&cert)).is_err());
        assert_eq!(called(), 0);

        let status_cb = status_provider(
            RatifyV2StatusEvidenceCallbacks {
                user: std::ptr::null_mut(),
                fetch: Some(fetch),
            },
            cancel(),
        );
        let request = |cert_id: &str| V2StatusEvidenceRequest {
            issuer_id: "issuer".into(),
            status_key_epoch: 1,
            status_key_id: "key".into(),
            refs: vec![CertificateRefV2 {
                issuer_id: "issuer".into(),
                cert_id: cert_id.into(),
            }],
        };
        let _ = status_cb(&ctx, &request("xy"));
        assert_eq!(called(), 1, "control status call");
        assert!(status_cb(&ctx, &request("x\0y")).is_err());
        assert_eq!(called(), 0);

        let audience_cb = audience_provider(
            RatifyV2AudienceCallbacks {
                user: std::ptr::null_mut(),
                lookup: Some(lookup),
            },
            cancel(),
        );
        let deferred = |cert_id: &str| {
            vec![V2DeferredConstraint {
                issuer_id: "issuer".into(),
                cert_id: cert_id.into(),
                kind: "ratify.receiver_audience".into(),
                ..Default::default()
            }]
        };
        let _ = audience_cb(&ctx, &deferred("xy"), "receiver");
        assert_eq!(called(), 1, "control audience call");
        assert!(audience_cb(&ctx, &deferred("x\0y"), "receiver").is_err());
        assert!(audience_cb(&ctx, &deferred("xy"), "recei\0ver").is_err());
        assert_eq!(called(), 0);
    }
}
