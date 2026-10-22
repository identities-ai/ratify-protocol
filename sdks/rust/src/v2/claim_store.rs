//! The atomic challenge claim, the single-use evaluator capability, and
//! terminal finalization (SPEC-v2 §6.2, §7.2, §7.3, §7.5). Mirrors Go
//! `claim_store_v2.go`.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use sha2::{Digest, Sha256};

use super::authorization::V2LocalAuthorizationAssessment;
use super::context::V2Context;
use super::errors::{err, plain, V2Error, V2ErrorClass, V2Result};
use super::evaluation_progress::{V2EvaluationProgress, V2InterruptedClaim};
use super::evaluator::ConstraintEvaluatorRefV2;
use super::json::{parse_json, JV};
use super::limits::v2_challenge_time_current;
use super::operation_context::{challenge_claim_digest_v2, protocol_claim_id_v2};
use super::preflight::{validate_proof_bundle_v2_preflight, ExpectedChallengeStateV2, ExpectedChallengeV2, V2PreflightResult};
use super::rate_reservation::{signed_v2_rate_reservation_batch, V2RateReservation};
use super::wire::{bundle_hash_v2, ProofBundleV2};

// ---------------------------------------------------------------------------
// Store errors

/// A Part B store, clock, or checkpoint failure.
///
/// Go stores return an `error` that is either classified (`*V2Error`), one
/// of a few exact sentinel values, or a plain (unclassified) error to which
/// the verifier assigns the class SPEC-v2 names for that step. This enum
/// carries exactly those three kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2StoreError {
    /// A failure whose class the store fixed deliberately; the verifier keeps
    /// it (for example `clock_regressed`, `claim_lease_lost`).
    Classified(V2Error),
    /// An unclassified failure (Go: a plain error). The verifier assigns the
    /// class Go assigns at that step (usually `claim_store_unavailable`).
    Unavailable(String),
    /// Go `ErrV2ClaimProofConflict`: the challenge was already claimed by a
    /// different proof (class `claim_replay`).
    ClaimProofConflict,
    /// Go `ErrV2RateLimitExceeded`: a complete atomic batch had no capacity.
    RateLimitExceeded,
    /// Go `ErrV2ReleaseStateMismatch`: a different release record exists.
    ReleaseStateMismatch,
    /// Go `ErrV2AcknowledgementNotFound`.
    AcknowledgementNotFound,
    /// Go `ErrV2ChallengeIssuanceConflict`: a record already exists for the
    /// issuance key; the store never overwrites it.
    ChallengeIssuanceConflict,
    /// Go `ErrV2ChallengeIssuanceNotFound`.
    ChallengeIssuanceNotFound,
}

impl V2StoreError {
    /// Go `V2ErrorClassOf` for this error: `None` means unclassified.
    ///
    /// `RateLimitExceeded` reaches a caller only from
    /// [`finalize_claim_proof_bundle_v2`], which Go classifies as
    /// `claim_store_unavailable` while the sentinel stays matchable; this
    /// variant reports that class so the two agree.
    pub fn class(&self) -> Option<V2ErrorClass> {
        match self {
            V2StoreError::Classified(e) => Some(e.class),
            V2StoreError::ClaimProofConflict => Some(V2ErrorClass::ClaimReplay),
            V2StoreError::RateLimitExceeded => Some(V2ErrorClass::ClaimStoreUnavailable),
            _ => None,
        }
    }

    /// The Go error value this store error stands for: classified when Go's
    /// would be, provisional (unclassified) otherwise.
    pub(crate) fn into_v2(self) -> V2Error {
        match self {
            V2StoreError::Classified(e) => e,
            V2StoreError::ClaimProofConflict => {
                V2Error::new(V2ErrorClass::ClaimReplay, self_message(&V2StoreError::ClaimProofConflict))
            }
            other => V2Error::plain(self_message(&other)),
        }
    }

    /// The error with every unclassified kind given `class`.
    pub(crate) fn classified_or(self, class: V2ErrorClass) -> V2Error {
        self.into_v2().classify(class)
    }
}

fn self_message(e: &V2StoreError) -> String {
    match e {
        V2StoreError::Classified(e) => e.message.clone(),
        V2StoreError::Unavailable(m) => m.clone(),
        V2StoreError::ClaimProofConflict => "v2 challenge was already claimed by a different proof".into(),
        V2StoreError::RateLimitExceeded => "v2 signed rate limit has no remaining capacity".into(),
        V2StoreError::ReleaseStateMismatch => "v2 claim already records a different release".into(),
        V2StoreError::AcknowledgementNotFound => "v2 checkpoint acknowledgement not found".into(),
        V2StoreError::ChallengeIssuanceConflict => "v2 challenge issuance record already exists".into(),
        V2StoreError::ChallengeIssuanceNotFound => "v2 challenge issuance record not found".into(),
    }
}

impl fmt::Display for V2StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            V2StoreError::Classified(e) => write!(f, "{e}"),
            other => f.write_str(&self_message(other)),
        }
    }
}

impl std::error::Error for V2StoreError {}

impl From<V2Error> for V2StoreError {
    fn from(e: V2Error) -> Self {
        V2StoreError::Classified(e)
    }
}

// ---------------------------------------------------------------------------
// Claim

/// The immutable identity a verifier persists when it consumes a fresh
/// challenge. A [`ClaimStoreV2`] must atomically enforce uniqueness on
/// (namespace, replay_epoch, challenge_digest), store proof_digest and every
/// other field as immutable claim values, and return the existing state only
/// for an exact retry without starting another evaluation. A changed scope or
/// context policy is not an exact retry even when the signed proof bytes are
/// identical.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2ChallengeClaim {
    pub claim_id: String,
    pub namespace: String,
    pub replay_epoch: i64,
    pub challenge_digest: String,
    pub proof_digest: String,
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub required_scope: String,
    pub context_policy_digest: String,
    pub verifier_id: String,
    pub agent_id: String,
    pub requires_rate: bool,
    pub rate_batch: Vec<V2RateReservation>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub max_age_seconds: i64,
    pub clock_skew_seconds: i64,
    pub stream_id: Option<Vec<u8>>,
    pub stream_seq: Option<i64>,
    /// The sealed extension evaluator snapshot for the chain (SPEC-v2 §5.2,
    /// §6.3), sorted by type; every terminal receipt for the claim, including
    /// evaluation_interrupted, carries it.
    pub constraint_evaluators: Vec<ConstraintEvaluatorRefV2>,
}

/// The atomic claim outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2ClaimDisposition {
    Created,
    InProgress,
    TerminalReplay,
}

impl V2ClaimDisposition {
    /// The spelling shared by every SDK (`created`, `in_progress`,
    /// `terminal_replay`).
    pub fn as_str(self) -> &'static str {
        match self {
            V2ClaimDisposition::Created => "created",
            V2ClaimDisposition::InProgress => "in_progress",
            V2ClaimDisposition::TerminalReplay => "terminal_replay",
        }
    }
}

impl fmt::Display for V2ClaimDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The claim transaction's result, including its authoritative timestamp.
/// The store, not the caller, chooses `claimed_at` from its configured
/// security clock. `owner_token` is returned only to the process that
/// atomically created the claim; stores persist only a one-way hash of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ClaimResult {
    pub disposition: V2ClaimDisposition,
    pub claimed_at: i64,
    pub owner_token: Vec<u8>,
}

/// A Part B authoritative security clock in integer seconds
/// (0..V2_MAX_TIMESTAMP_SECONDS). A reading below the greatest reading the
/// clock has returned is a regression and fails with a
/// [`V2StoreError::Classified`] `clock_regressed` error.
pub trait V2AuthoritativeClock: Send + Sync {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError>;
}

/// The storage boundary for challenge consumption (Go `ClaimStoreV2`; see
/// SPEC-v2 §7.3 and the Go documentation for the full contract).
///
/// `claim_v2` must be atomic across processes and durable across restart,
/// advance any stream sequence in the same transaction, and recheck expiry
/// and maximum age with the authoritative clock inside it. A different
/// proof_digest or any other immutable field for the same replay key returns
/// [`V2StoreError::ClaimProofConflict`] without disclosing the existing
/// result. A created result includes a random 32-byte owner token.
///
/// `finalize_v2_claim` compares the token against the stored digest without
/// an early exit and performs a state-and-live-lease compare-and-set, reading
/// its authoritative clock as T_final inside it: a regressed reading fails
/// with `clock_regressed`; a non-zero `allow_valid_until` commits only while
/// T_final < allow_valid_until and T_final < the challenge expiry, else
/// `allow_horizon_passed`. It returns `true` when it commits, `false` when the
/// same owner already committed the identical result and receipt body.
///
/// `record_v2_evaluation_progress` persists progress under the owner token
/// and live lease (`claim_lease_lost` or `claim_already_terminal`
/// otherwise). `load_v2_interrupted_claim` fails with `claim_lease_live`
/// while an evaluating claim's lease is live. `recover_interrupted_v2_claim`
/// commits only indeterminate/evaluation_interrupted after the lease expired.
///
/// This trait does not make a memory-only implementation safe for
/// production.
pub trait ClaimStoreV2: V2AuthoritativeClock {
    fn claim_v2(&self, ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError>;
    fn finalize_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError>;
    fn record_v2_evaluation_progress(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError>;
    fn load_v2_interrupted_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2InterruptedClaim, V2StoreError>;
    fn recover_interrupted_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError>;
    /// Go's `store.(V2RateAtFinalizationStore)` type assertion: a store that
    /// implements [`V2RateAtFinalizationStore`] returns `Some(self)`.
    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        None
    }
}

/// Atomically reserves the complete claim-sealed rate batch. An exact live
/// retry is idempotent. Implementations must not call back into the token.
/// `Ok` means every counter remains provisionally held;
/// [`V2StoreError::RateLimitExceeded`] means definitive capacity exhaustion;
/// any other error is unavailable or ambiguous and never authorizes.
pub trait V2RateReservationStore: Send + Sync {
    fn reserve_v2_rate_batch(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        bundle_hash: &str,
        batch: &[V2RateReservation],
    ) -> Result<(), V2StoreError>;
    /// Go's `store.(V2RateAtFinalizationStore)` type assertion: a store that
    /// implements [`V2RateAtFinalizationStore`] returns `Some(self)`.
    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        None
    }
}

/// Admits the sealed rate batch atomically during finalization (external
/// barrier preparation). The capability must remain active for the claim's
/// lifetime and must reject a claim with a legacy reservation. Its
/// `finalize_v2_claim` may return the exact [`V2StoreError::RateLimitExceeded`]
/// only after definitive rollback. Implementors also return `Some(self)` from
/// both `rate_at_finalization_view` methods.
pub trait V2RateAtFinalizationStore: ClaimStoreV2 + V2RateReservationStore {
    fn admits_v2_rate_at_finalization(&self);
}

/// Go `ChallengeClaimTimeCurrentV2`: whether an authoritative time is inside
/// the claim's sealed challenge bounds using exclusive deadlines.
pub fn challenge_claim_time_current_v2(claim: &V2ChallengeClaim, now: i64) -> bool {
    v2_challenge_time_current(
        now,
        claim.issued_at,
        claim.expires_at,
        claim.max_age_seconds,
        claim.clock_skew_seconds,
    )
}

// ---------------------------------------------------------------------------
// Evaluator capability

/// Grants one local evaluation attempt for a newly created claim. It is
/// single-use and is never returned for an exact retry. Cloning shares the
/// same capability (Go passes the pointer).
#[derive(Clone)]
pub struct V2EvaluationToken {
    pub(crate) state: Arc<TokenState>,
}

impl fmt::Debug for V2EvaluationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2EvaluationToken")
            .field("claim_id", &self.state.claim_id)
            .finish_non_exhaustive()
    }
}

pub(crate) struct TokenState {
    pub claim_id: String,
    pub proof_digest: String,
    pub required_scope: String,
    pub future_skew: i64,
    pub expected: Arc<ExpectedChallengeStateV2>,
    pub used: AtomicBool,
    pub evaluation_complete: AtomicBool,
    pub claim_time_valid: bool,
    pub claimed_at: i64,
    pub rate_batch: Vec<V2RateReservation>,
    pub owner_token: Vec<u8>,
    pub m: Mutex<TokenMut>,
}

#[derive(Default)]
pub(crate) struct TokenMut {
    pub finalization_digest: [u8; 32],
    pub finalization_started: bool,
    pub evaluated_at: i64,
    pub rate_at_finalization: bool,
    pub allow_valid_until: i64,
    pub evaluation_status: String,
    pub evaluation_reason: String,
    pub pending_assessment: Option<V2LocalAuthorizationAssessment>,
}

impl TokenState {
    pub(crate) fn lock(&self) -> MutexGuard<'_, TokenMut> {
        self.m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Go `allowHorizon`: the exclusive allow deadline sealed for this claim
    /// (0 unless the evaluation reached allow).
    pub(crate) fn allow_horizon(&self) -> i64 {
        self.lock().allow_valid_until
    }
}

// ---------------------------------------------------------------------------
// ClaimProofBundleV2

/// Go `ClaimProofBundleV2`: repeat the security-relevant freshness and
/// binding checks immediately before invoking the atomic claim store. No
/// trust, status, or policy callback runs before this succeeds. An
/// unclassified failure is reported as `claim_store_unavailable`, as the live
/// verifier reports it; a missing or different successful preflight is
/// `configuration_invalid`; a different proof is `claim_replay`.
pub fn claim_proof_bundle_v2(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    bundle: &ProofBundleV2,
    preflight: &V2PreflightResult,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
) -> V2Result<(V2ChallengeClaim, V2ClaimDisposition, Option<V2EvaluationToken>)> {
    claim_proof_bundle_v2_inner(ctx, store, bundle, preflight, configured_namespace, configured_replay_epoch, now)
        .map_err(|e| e.classify(V2ErrorClass::ClaimStoreUnavailable))
}

pub(crate) fn claim_proof_bundle_v2_inner(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    bundle: &ProofBundleV2,
    preflight: &V2PreflightResult,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
) -> V2Result<(V2ChallengeClaim, V2ClaimDisposition, Option<V2EvaluationToken>)> {
    let sealed = &preflight.state;
    if sealed.context_policy.is_none() && !sealed.no_context_policy {
        return err(V2ErrorClass::ConfigurationInvalid, "v2 successful preflight state is required before claim");
    }
    let bundle_hash = match bundle_hash_v2(bundle) {
        Ok(h) if h == sealed.bundle_hash => h,
        _ => return err(V2ErrorClass::ConfigurationInvalid, "v2 proof bundle differs from successful preflight"),
    };
    let expected = ExpectedChallengeV2 {
        value: sealed.value.clone(),
        issued_at: sealed.issued_at,
        expires_at: sealed.expires_at,
        verifier_namespace: sealed.verifier_namespace.clone(),
        replay_epoch: sealed.replay_epoch,
        verifier_id: sealed.verifier_id.clone(),
        expected_agent_id: sealed.expected_agent_id.clone(),
        expected_agent_public_key: sealed.expected_agent_public_key.clone(),
        expected_receiver_id: sealed.expected_receiver_id.clone(),
        expected_session_context: sealed.expected_session_context.clone(),
        context_policy: sealed.context_policy.clone(),
    };
    validate_proof_bundle_v2_preflight(
        bundle,
        &expected,
        &sealed.required_scope,
        configured_namespace,
        configured_replay_epoch,
        now,
        sealed.max_age,
        sealed.future_skew,
    )
    .map_err(|e| e.context("v2 claim-time preflight"))?;
    let challenge_digest = challenge_claim_digest_v2(&sealed.value)?;
    let claim_id = protocol_claim_id_v2(&sealed.verifier_namespace, sealed.replay_epoch, &sealed.value)?;
    let rate_batch = signed_v2_rate_reservation_batch(bundle)
        .map_err(|e| e.context("v2 signed rate batch").classify(V2ErrorClass::Malformed))?;
    let claim = V2ChallengeClaim {
        claim_id,
        namespace: sealed.verifier_namespace.clone(),
        replay_epoch: sealed.replay_epoch,
        challenge_digest: format!("sha384:{}", hex::encode(&challenge_digest)),
        proof_digest: bundle_hash.clone(),
        bundle_hash: sealed.bundle_hash.clone(),
        issuer_ids: sealed.issuer_ids.clone(),
        required_scope: sealed.required_scope.clone(),
        context_policy_digest: sealed.context_policy_digest.clone(),
        verifier_id: sealed.verifier_id.clone(),
        agent_id: bundle.agent_id.clone(),
        requires_rate: !rate_batch.is_empty(),
        rate_batch,
        issued_at: sealed.issued_at,
        expires_at: sealed.expires_at,
        max_age_seconds: sealed.max_age,
        clock_skew_seconds: sealed.future_skew,
        stream_id: bundle.stream_id.clone(),
        stream_seq: bundle.stream_seq,
        constraint_evaluators: sealed.evaluator_refs.clone(),
    };
    // SPEC-v2 §6.11: cancellation before the claim consumes nothing, so a
    // caller that has already cancelled never reaches the store.
    if ctx.is_done() {
        return err(
            V2ErrorClass::EvaluationCancelled,
            "v2 claim cancelled before the store was called: context done",
        );
    }
    let result = store.claim_v2(ctx, claim.clone()).map_err(V2StoreError::into_v2)?;
    match result.disposition {
        V2ClaimDisposition::Created => {
            if result.owner_token.len() != 32 {
                return plain("v2 claim store returned an invalid evaluator owner token");
            }
            // The store's authoritative claim time must itself satisfy the
            // exclusive challenge deadlines; otherwise evaluation is
            // interrupted.
            let claim_time_valid = v2_challenge_time_current(
                result.claimed_at,
                sealed.issued_at,
                sealed.expires_at,
                sealed.max_age,
                sealed.future_skew,
            );
            let token = V2EvaluationToken {
                state: Arc::new(TokenState {
                    claim_id: claim.claim_id.clone(),
                    proof_digest: claim.proof_digest.clone(),
                    required_scope: sealed.required_scope.clone(),
                    future_skew: sealed.future_skew,
                    expected: Arc::clone(sealed),
                    used: AtomicBool::new(false),
                    evaluation_complete: AtomicBool::new(false),
                    claim_time_valid,
                    claimed_at: result.claimed_at,
                    rate_batch: claim.rate_batch.clone(),
                    owner_token: result.owner_token.clone(),
                    m: Mutex::new(TokenMut::default()),
                }),
            };
            Ok((claim, result.disposition, Some(token)))
        }
        V2ClaimDisposition::InProgress | V2ClaimDisposition::TerminalReplay => {
            if !result.owner_token.is_empty() {
                return plain("v2 exact retry must not receive evaluator ownership");
            }
            Ok((claim, result.disposition, None))
        }
    }
}

// ---------------------------------------------------------------------------
// FinalizeClaimProofBundleV2

/// Why the finalization helper did not commit: its own refusal (Go: a plain
/// error from the helper) or the store's error.
#[derive(Debug, Clone)]
pub(crate) enum FinalizeFailure {
    Own(V2Error),
    Store(V2StoreError),
}

/// Go `FinalizeClaimProofBundleV2`: commit a terminal local evaluation
/// through the same opaque capability that won the atomic claim. Results that
/// still need status or rate checks cannot be finalized. An ambiguous store
/// failure can be retried only with the identical result and receipt. A
/// barrier store's exact [`V2StoreError::RateLimitExceeded`] proves rollback,
/// changes the token to constraint_denied, and requires a new deny result and
/// receipt.
///
/// Classes (Go returns its own refusals unclassified): a helper refusal is
/// `configuration_invalid`, a cancelled context is `evaluation_cancelled`, an
/// unclassified store failure is `claim_store_unavailable`; classified store
/// errors are returned as the store reported them. `RateLimitExceeded` is
/// returned as that variant, so callers can still match it, and its
/// [`V2StoreError::class`] is `claim_store_unavailable`, as in Go.
pub fn finalize_claim_proof_bundle_v2(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    token: &V2EvaluationToken,
    terminal_result: &[u8],
    receipt_body: &[u8],
) -> Result<bool, V2StoreError> {
    if ctx.is_done() {
        return Err(V2StoreError::Classified(V2Error::new(
            V2ErrorClass::EvaluationCancelled,
            "v2 finalization context is done",
        )));
    }
    match finalize_claim_proof_bundle_v2_inner(ctx, store, token, terminal_result, receipt_body) {
        Ok(finalized) => Ok(finalized),
        Err(FinalizeFailure::Own(e)) => Err(V2StoreError::Classified(e.classify(V2ErrorClass::ConfigurationInvalid))),
        Err(FinalizeFailure::Store(V2StoreError::Unavailable(m))) => Err(V2StoreError::Classified(V2Error::new(
            V2ErrorClass::ClaimStoreUnavailable,
            m,
        ))),
        Err(FinalizeFailure::Store(e)) => Err(e),
    }
}

pub(crate) fn finalize_claim_proof_bundle_v2_inner(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    token: &V2EvaluationToken,
    terminal_result: &[u8],
    receipt_body: &[u8],
) -> Result<bool, FinalizeFailure> {
    let own = |m: &str| Err(FinalizeFailure::Own(V2Error::plain(m)));
    let state = &token.state;
    if state.owner_token.len() != 32 || state.claim_id.is_empty() {
        return own("v2 claim store and valid evaluator capability are required");
    }
    if ctx.is_done() {
        return own("v2 finalization context is done");
    }
    let mut m = state.lock();
    if !state.evaluation_complete.load(Ordering::SeqCst) {
        return own("v2 proof evaluation has not completed");
    }
    let Some(decision) = terminal_decision_for_v2_evaluation(&m.evaluation_status, &m.evaluation_reason) else {
        return own("v2 proof evaluation has not reached a terminal local result");
    };
    if !terminal_payload_matches_v2(terminal_result, receipt_body, decision, &m.evaluation_reason) {
        return own("v2 terminal result does not match the completed local evaluation");
    }
    if (decision == "allow" && m.allow_valid_until <= 0) || (decision != "allow" && m.allow_valid_until != 0) {
        return own("v2 terminal result lacks a valid allow freshness horizon");
    }
    if m.rate_at_finalization && store.rate_at_finalization_view().is_none() {
        return own("v2 rate-at-finalization requires an atomic rate store");
    }
    let payload_digest = v2_finalization_payload_digest(terminal_result, receipt_body);
    if m.finalization_started && m.finalization_digest != payload_digest {
        return own("v2 evaluator capability cannot change its terminal result or receipt body");
    }
    m.finalization_started = true;
    m.finalization_digest = payload_digest;
    let result = store.finalize_v2_claim(
        ctx,
        &state.claim_id,
        &state.owner_token,
        terminal_result,
        receipt_body,
        m.allow_valid_until,
    );
    if let Err(V2StoreError::RateLimitExceeded) = &result {
        if m.rate_at_finalization && decision == "allow" && store.rate_at_finalization_view().is_some() {
            m.evaluation_status = "constraint_denied".into();
            m.evaluation_reason = "constraint_denied".into();
            m.allow_valid_until = 0;
            m.rate_at_finalization = false;
            m.finalization_started = false;
            m.finalization_digest = [0; 32];
        }
    }
    result.map_err(FinalizeFailure::Store)
}

/// Go `terminalDecisionForV2Evaluation`.
pub(crate) fn terminal_decision_for_v2_evaluation(status: &str, reason: &str) -> Option<&'static str> {
    if reason == "evaluation_interrupted" {
        return (status == "authorization_unverified").then_some("indeterminate");
    }
    let (decision, ok) = match status {
        "authorization_unverified" => (
            "indeterminate",
            matches!(reason, "trust_unavailable" | "action_context_unverified" | "status_unavailable" | "status_stale"),
        ),
        "authorized_agent" => ("allow", reason == "authorized"),
        "constraint_denied" | "constraint_unverifiable" | "constraint_unknown" | "unauthorized" | "invalid_scope"
        | "scope_denied" => ("deny", reason == status),
        "revoked" => ("deny", reason == "delegation_revoked"),
        "invalid" => ("deny", reason == "proof_invalid"),
        "delegation_not_authorized" => ("deny", reason == "not_delegated" || reason == "delegation_not_authorized"),
        "expired" => ("deny", reason == "delegation_expired"),
        _ => return None,
    };
    ok.then_some(decision)
}

/// Go `terminalPayloadMatchesV2`: both objects are JSON objects without
/// duplicate keys at any level whose `decision` and `decision_reason` are
/// strings equal to the expected values.
pub(crate) fn terminal_payload_matches_v2(
    terminal_result: &[u8],
    receipt_body: &[u8],
    want_decision: &str,
    want_reason: &str,
) -> bool {
    fn read(value: &[u8]) -> Option<(String, String)> {
        let root = parse_json(value).ok()?;
        let JV::Obj(fields) = &root.v else {
            return None;
        };
        let field = |name: &str| -> Option<String> {
            match fields.iter().find(|(k, _)| k == name).map(|(_, v)| &v.v) {
                Some(JV::Str(s)) => Some(s.clone()),
                // Go json.Unmarshal of null into a string leaves "".
                Some(JV::Null) => Some(String::new()),
                _ => None,
            }
        };
        Some((field("decision")?, field("decision_reason")?))
    }
    match (read(terminal_result), read(receipt_body)) {
        (Some((rd, rr)), Some((bd, br))) => {
            rd == want_decision && bd == want_decision && rr == want_reason && br == want_reason
        }
        _ => false,
    }
}

/// Go `v2FinalizationPayloadDigest`.
pub(crate) fn v2_finalization_payload_digest(terminal_result: &[u8], receipt_body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((terminal_result.len() as u64).to_be_bytes());
    h.update(terminal_result);
    h.update((receipt_body.len() as u64).to_be_bytes());
    h.update(receipt_body);
    h.finalize().into()
}
