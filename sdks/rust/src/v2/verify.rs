//! The live Protocol v2 decision path (SPEC-v2 §6). Mirrors Go
//! `verify_v2.go`.

use std::collections::BTreeMap;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use super::audience::V2AudienceMembership;
use super::authorization::{
    evaluate_proof_bundle_v2_local_authorization, interrupt_v2_evaluation, resolve_after_audience_inner,
    resolve_after_rate_inner, resolve_claim_proof_bundle_v2_after_status, v2_interrupted_assessment,
    V2DeferredConstraint, V2LocalAuthorizationAssessment, V2LocalAuthorizationOptions,
};
use super::claim_store::{
    claim_proof_bundle_v2_inner, finalize_claim_proof_bundle_v2_inner, terminal_decision_for_v2_evaluation,
    ClaimStoreV2, FinalizeFailure, V2ChallengeClaim, V2ClaimDisposition,
    V2RateReservationStore, V2StoreError,
};
use super::constraints::{ConstraintContextV2, CONSTRAINT_RECEIVER_AUDIENCE};
use super::context::V2Context;
use super::context_policy::V2ContextPolicy;
use super::crypto::{equal_keys, key_id_v2, valid_v2_id};
use super::errors::{err, V2Error, V2ErrorClass, V2Result};
use super::evaluation_progress::{
    initial_v2_evaluation_progress, receipt_skeleton, record_v2_progress_safely, terminal_result_json,
    V2EvaluationProgress,
};
use super::evaluator::{validate_v2_request_context, ConstraintEvaluatorRegistryV2};
use super::journal::SecurityJournalStoreV2;
use super::limits::{validate_v2_freshness_configuration, V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_STATUS_LIFETIME_SECONDS};
use super::preflight::{preflight_proof_bundle_v2_inner, ExpectedChallengeV2};
use super::receipt::verification_receipt_v2_body;
use super::release::CommittedV2Outcome;
use super::status::RevocationStatusPolicyV2;
use super::status_provenance::{run_v2_status_stage, V2StatusEvidenceProvider, V2StatusKeyConfig, V2StatusStageInputs};
use super::wire::{decode_proof_bundle_v2, DelegationCertV2, ProofBundleV2, MAX_SAFE};
use crate::types::HybridPublicKey;

/// A provider or hook failure (trust, audience, receiver binding). The
/// message is diagnostic only; the verifier handles every failure fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ProviderError {
    pub message: String,
}

impl V2ProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        V2ProviderError {
            message: message.into(),
        }
    }
}

impl fmt::Display for V2ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for V2ProviderError {}

/// A trust provider's answer for one verified chain (SPEC-v2 §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2TrustOutcome {
    /// The chain terminates at the returned configured root.
    Trusted,
    /// Trust configuration is available and the chain does not terminate at
    /// any configured root.
    Untrusted,
    /// No trust configuration, or the source is unavailable.
    Unavailable,
    /// More than one configured candidate matches, or the resolver cannot
    /// decide uniquely. Never becomes trusted.
    Ambiguous,
}

impl V2TrustOutcome {
    /// `trusted`, `untrusted`, `unavailable`, or `ambiguous`.
    pub fn as_str(self) -> &'static str {
        match self {
            V2TrustOutcome::Trusted => "trusted",
            V2TrustOutcome::Untrusted => "untrusted",
            V2TrustOutcome::Unavailable => "unavailable",
            V2TrustOutcome::Ambiguous => "ambiguous",
        }
    }

    /// Parse one of the four spellings.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "trusted" => V2TrustOutcome::Trusted,
            "untrusted" => V2TrustOutcome::Untrusted,
            "unavailable" => V2TrustOutcome::Unavailable,
            "ambiguous" => V2TrustOutcome::Ambiguous,
            _ => return None,
        })
    }
}

/// The caller-authenticated trust provider result. `root_key` is the
/// complete root public key for `Trusted`; the verifier recomputes its key
/// ID and requires it and the key to equal the chain's terminal issuer,
/// treating a mismatch as ambiguous. Unavailable, ambiguous, an error, or a
/// panic yields indeterminate/trust_unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2TrustResolution {
    pub outcome: V2TrustOutcome,
    pub root_key: HybridPublicKey,
}

impl V2TrustResolution {
    fn unavailable() -> Self {
        V2TrustResolution {
            outcome: V2TrustOutcome::Unavailable,
            root_key: HybridPublicKey {
                ed25519: Vec::new(),
                ml_dsa_65: Vec::new(),
            },
        }
    }
}

/// The application's pure pre-consumption hook. It runs after the built-in
/// expected-agent, session-context and exact-audience checks and before the
/// claim. It must not perform I/O or have side effects.
pub type V2ReceiverBindingHook =
    Arc<dyn Fn(&ProofBundleV2, &ExpectedChallengeV2) -> Result<(), V2ProviderError> + Send + Sync>;

/// The trust provider, selected by authenticated configuration; it never
/// follows a location or identifier taken from the proof.
pub type V2TrustProvider =
    Arc<dyn Fn(&V2Context, &[DelegationCertV2]) -> Result<V2TrustResolution, V2ProviderError> + Send + Sync>;

/// The receiver-audience membership provider.
pub type V2AudienceProvider = Arc<
    dyn Fn(&V2Context, &[V2DeferredConstraint], &str) -> Result<Vec<V2AudienceMembership>, V2ProviderError>
        + Send
        + Sync,
>;

/// The verifier-owned dependencies of the live v2 decision path.
/// `claim_store` is required. A callback that returns an error or panics is
/// handled fail-closed: trust -> trust_unavailable, status -> unavailable
/// for that issuer, audience -> constraint_unverifiable, rate ->
/// constraint_unverifiable. If the caller's context has ended when a
/// callback fails, nothing is committed (evaluation_cancelled) and the claim
/// remains in progress for lease-expiry recovery.
#[derive(Clone, Default)]
pub struct V2VerifyCallbacks {
    pub receiver_binding: Option<V2ReceiverBindingHook>,
    pub claim_store: Option<Arc<dyn ClaimStoreV2>>,
    pub trust: Option<V2TrustProvider>,
    /// A bounded batch of signed status objects for one issuer; never a
    /// status result.
    pub status_evidence: Option<V2StatusEvidenceProvider>,
    /// The rollback-protected, anchored security journal the evidence is
    /// applied to. Without it every status is unavailable.
    pub status_journal: Option<Arc<dyn SecurityJournalStoreV2>>,
    pub audience: Option<V2AudienceProvider>,
    pub rate: Option<Arc<dyn V2RateReservationStore>>,
}

impl fmt::Debug for V2VerifyCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2VerifyCallbacks")
            .field("receiver_binding", &self.receiver_binding.is_some())
            .field("claim_store", &self.claim_store.is_some())
            .field("trust", &self.trust.is_some())
            .field("status_evidence", &self.status_evidence.is_some())
            .field("status_journal", &self.status_journal.is_some())
            .field("audience", &self.audience.is_some())
            .field("rate", &self.rate.is_some())
            .finish()
    }
}

/// One live verification. `context_policy: None` means the verifier
/// explicitly configured no context policy; the terminal result can then
/// never be allow (SPEC-v2 §6.7). `now` is the caller's clock and is used
/// only for the pre-claim freshness check; every post-claim time-sensitive
/// check uses the claim store's authoritative time.
#[derive(Debug, Clone, Default)]
pub struct V2VerifyRequest {
    pub bundle: Vec<u8>,
    pub expected: Option<ExpectedChallengeV2>,
    pub context_policy: Option<V2ContextPolicy>,
    pub required_scope: String,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub now: i64,
    pub max_challenge_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub context: ConstraintContextV2,
    /// The configured IANA tzdata release for `time_window`; it must equal
    /// [`super::TZDB_VERSION_V2`].
    pub tzdb_version: String,
    pub status_keys: BTreeMap<String, V2StatusKeyConfig>,
    pub status_policy: RevocationStatusPolicyV2,
    /// The caller-authenticated extension evaluator registry; `None`
    /// registers none, so every extension type is constraint_unknown.
    pub constraint_evaluators: Option<ConstraintEvaluatorRegistryV2>,
}

/// Where a verification stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2VerifyStage {
    /// A pre-claim failure. No challenge was consumed, no
    /// trust/status/policy callback ran, and no Protocol receipt exists.
    Preflight,
    /// Preflight passed but the claim already existed. The result is not
    /// disclosed and no evaluation callback ran.
    Replay,
    /// The claim was created but nothing was committed. The claim stays in
    /// progress for lease-expiry recovery.
    Evaluating,
    /// A terminal Protocol result and its receipt outbox body were
    /// committed. A committed outcome is NOT actionable; only
    /// [`super::release_v2_decision`] produces an actionable decision.
    Committed,
}

impl V2VerifyStage {
    /// `preflight`, `replay`, `evaluating`, or `committed`.
    pub fn as_str(self) -> &'static str {
        match self {
            V2VerifyStage::Preflight => "preflight",
            V2VerifyStage::Replay => "replay",
            V2VerifyStage::Evaluating => "evaluating",
            V2VerifyStage::Committed => "committed",
        }
    }
}

/// The result of [`verify_proof_bundle_v2`]. It deliberately has no
/// decision field: for `Committed`, `committed` is the opaque handoff to
/// [`super::release_v2_decision`]. `error` (and `error_class`) is present
/// exactly for `Preflight` and `Evaluating` (Go returns the error itself only
/// for `Evaluating`).
#[derive(Debug)]
pub struct V2VerifyOutcome {
    pub stage: V2VerifyStage,
    pub error: Option<V2Error>,
    pub error_class: Option<V2ErrorClass>,
    pub disposition: Option<V2ClaimDisposition>,
    pub claim: V2ChallengeClaim,
    pub committed: Option<CommittedV2Outcome>,
}

/// The evaluator's progress: `persisted` is exactly what was last recorded
/// in the claim store; `trust_completed` notes that trust resolution ran.
struct EvaluationProgress {
    persisted: V2EvaluationProgress,
    trust_completed: bool,
}

/// Go `VerifyProofBundleV2`: the live decision path in the SPEC-v2 §6
/// order. A pre-claim failure returns `Preflight` with a classified error
/// and invokes no claim, trust, status, audience, or rate callback. A
/// committed outcome is never an authorization.
pub fn verify_proof_bundle_v2(ctx: &V2Context, req: &V2VerifyRequest, cb: &V2VerifyCallbacks) -> V2VerifyOutcome {
    let preflight_failure = |e: V2Error| V2VerifyOutcome {
        stage: V2VerifyStage::Preflight,
        error_class: Some(e.class),
        error: Some(e),
        disposition: None,
        claim: V2ChallengeClaim::default(),
        committed: None,
    };
    // SPEC-v2 §6.2 step 1 (bounded strict decode), then step 2
    // (configuration, including the claim store). No callback runs before
    // both pass.
    let bundle = match decode_proof_bundle_v2(&req.bundle) {
        Ok(b) => b,
        Err(e) => return preflight_failure(e),
    };
    let Some(store) = cb.claim_store.as_deref() else {
        return preflight_failure(V2Error::new(
            V2ErrorClass::ConfigurationInvalid,
            "v2 verification requires a context and claim store",
        ));
    };
    if let Err(e) = validate_v2_verify_configuration(req) {
        return preflight_failure(e);
    }
    let preflight = match preflight_proof_bundle_v2_inner(
        &bundle,
        req.expected.as_ref(),
        req.context_policy.as_ref(),
        true,
        cb.receiver_binding.as_ref(),
        req.constraint_evaluators.as_ref(),
        &req.required_scope,
        &req.verifier_namespace,
        req.replay_epoch,
        req.now,
        req.max_challenge_age_seconds,
        req.future_skew_seconds,
    ) {
        Ok(p) => p,
        Err(e) => return preflight_failure(e),
    };
    let claimed = catch_unwind(AssertUnwindSafe(|| {
        claim_proof_bundle_v2_inner(ctx, store, &bundle, &preflight, &req.verifier_namespace, req.replay_epoch, req.now)
    }))
    .unwrap_or_else(|_| Err(V2Error::new(V2ErrorClass::ClaimStoreUnavailable, "claim store panicked")));
    let (claim, disposition, token) = match claimed {
        Ok(c) => c,
        Err(e) => return preflight_failure(e.classify(V2ErrorClass::ClaimStoreUnavailable)),
    };
    let token = match (disposition, token) {
        (V2ClaimDisposition::Created, Some(token)) => token,
        (V2ClaimDisposition::Created, None) => {
            return preflight_failure(V2Error::new(
                V2ErrorClass::ClaimStoreUnavailable,
                "v2 claim store created a claim without an evaluator capability",
            ))
        }
        _ => {
            return V2VerifyOutcome {
                stage: V2VerifyStage::Replay,
                error: None,
                error_class: None,
                disposition: Some(disposition),
                claim,
                committed: None,
            }
        }
    };
    let evaluating = |claim: &V2ChallengeClaim, e: V2Error| V2VerifyOutcome {
        stage: V2VerifyStage::Evaluating,
        error_class: Some(e.class),
        error: Some(e),
        disposition: Some(disposition),
        claim: claim.clone(),
        committed: None,
    };
    let cancelled = |claim: &V2ChallengeClaim| {
        evaluating(
            claim,
            V2Error::new(
                V2ErrorClass::EvaluationCancelled,
                "v2 evaluation cancelled before commit: context done",
            ),
        )
    };

    let mut progress = EvaluationProgress {
        persisted: initial_v2_evaluation_progress(),
        trust_completed: false,
    };
    // Persist progress before an external lookup starts and after it
    // completes (SPEC-v2 §7.5). A failed write stops evaluation before the
    // next provider call.
    let record = |p: &V2EvaluationProgress| -> V2Result<()> {
        record_v2_progress_safely(ctx, store, &token, p).map_err(|e| {
            if ctx.is_done() {
                V2Error::new(
                    V2ErrorClass::EvaluationCancelled,
                    "v2 evaluation cancelled before commit: context done",
                )
            } else {
                e
            }
        })
    };
    let mut opts = V2LocalAuthorizationOptions {
        future_skew_seconds: req.future_skew_seconds,
        required_scope: req.required_scope.clone(),
        context: req.context.clone(),
        tzdb_version: req.tzdb_version.clone(),
        context_policy: req.context_policy.clone(),
        expected_challenge: req.expected.clone(),
        claim_token: Some(token.clone()),
        ..Default::default()
    };
    // The claim's own consistency is checked before trust; an inconsistent
    // claim is interrupted with every assessment not_evaluated.
    if token.state.claim_time_valid {
        if let Some(root) = bundle.delegations.last() {
            progress.persisted.trust_assessment = "unavailable".into(); // resolution started
            if let Err(e) = record(&progress.persisted) {
                return evaluating(&claim, e);
            }
            let resolution = call_v2_trust_safely(ctx, cb.trust.as_ref(), &bundle.delegations);
            if resolution.is_err() && ctx.is_done() {
                return cancelled(&claim);
            }
            let mut trust = "unavailable";
            if let Ok(resolution) = resolution {
                match resolution.outcome {
                    V2TrustOutcome::Trusted => {
                        if let Ok(root_id) = key_id_v2(&resolution.root_key) {
                            if root_id == root.issuer_id && equal_keys(&resolution.root_key, &root.issuer_pub_key) {
                                trust = "trusted";
                                opts.trusted_root_id = root_id;
                                opts.trusted_root_key = resolution.root_key.clone();
                            }
                        }
                    }
                    // Configured trust that excludes this chain: the local
                    // evaluation compares against an empty root and denies.
                    V2TrustOutcome::Untrusted => trust = "untrusted",
                    V2TrustOutcome::Unavailable | V2TrustOutcome::Ambiguous => {}
                }
            }
            opts.trust_configured = trust != "unavailable";
            progress.trust_completed = true;
            progress.persisted.trust_assessment = trust.into();
        }
    }
    let mut assessment = evaluate_proof_bundle_v2_local_authorization(&bundle, &opts);
    let claimed_at = token.state.claimed_at;
    if progress.trust_completed {
        if progress.persisted.trust_assessment == "trusted"
            && (assessment.context_assessment == "bound" || assessment.context_assessment == "not_required")
        {
            if let Some(digest) = &assessment.context_policy_digest {
                progress.persisted.context_assessment = assessment.context_assessment.clone();
                progress.persisted.context_policy_digest = Some(digest.clone());
            }
        }
        if assessment.status == "pending_external_checks" {
            progress.persisted.status_assessment = "unavailable".into(); // status started
        }
        if let Err(e) = record(&progress.persisted) {
            return evaluating(&claim, e);
        }
    }

    if assessment.status == "pending_external_checks" {
        let inputs = V2StatusStageInputs {
            status_evidence: cb.status_evidence.as_ref(),
            status_journal: cb.status_journal.as_deref(),
            status_keys: &req.status_keys,
            status_policy: &req.status_policy,
        };
        let stage = run_v2_status_stage(ctx, &bundle, &assessment.status_checks, &inputs, claimed_at);
        if stage.cancelled {
            return cancelled(&claim);
        }
        progress.persisted.status_assessment = stage.assessment.assessment.clone();
        progress.persisted.status_evidence = stage.assessment.evidence.clone();
        if let Err(e) = record(&progress.persisted) {
            return evaluating(&claim, e);
        }
        let status_assessment = stage.assessment;
        match resolve_claim_proof_bundle_v2_after_status(&token, |_| Ok(status_assessment)) {
            Ok(resolved) => assessment = resolved,
            Err(_) => {
                interrupt_v2_evaluation(&token);
                assessment = v2_interrupted_assessment("evaluation interrupted after status");
            }
        }
    }
    if assessment.status == "pending_external_checks"
        && assessment.deferred.iter().any(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
    {
        let audience_deferred: Vec<V2DeferredConstraint> = assessment
            .deferred
            .iter()
            .filter(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
            .cloned()
            .collect();
        let receiver_id = req
            .expected
            .as_ref()
            .map(|e| e.expected_receiver_id.clone())
            .unwrap_or_default();
        let memberships = match call_v2_audience_safely(ctx, cb.audience.as_ref(), &audience_deferred, &receiver_id) {
            Ok(m) => m,
            Err(_) => {
                if ctx.is_done() {
                    return cancelled(&claim);
                }
                Vec::new()
            }
        };
        match resolve_after_audience_inner(&token, &memberships) {
            Ok(resolved) => assessment = resolved,
            Err(_) => {
                interrupt_v2_evaluation(&token);
                assessment = v2_interrupted_assessment("evaluation interrupted after audience");
            }
        }
    }
    if assessment.status == "pending_external_checks" {
        if ctx.is_done() {
            return cancelled(&claim);
        }
        match resolve_after_rate_inner(ctx, cb.rate.as_deref(), &token) {
            Ok(resolved) => assessment = resolved,
            Err(_) => {
                if ctx.is_done() {
                    return cancelled(&claim);
                }
                interrupt_v2_evaluation(&token);
                assessment = v2_interrupted_assessment("evaluation interrupted after rate");
            }
        }
    }

    // The claim store reads T_final inside the finalization compare-and-set
    // and rejects a regressed clock or an allow at or beyond its horizon or
    // the challenge expiry; nothing is then committed (SPEC-v2 §7.2, §7.5).
    for attempt in 0..2 {
        let (decision, terminal, body) = match build_v2_terminal_result(&bundle, &assessment, &progress, &claim, claimed_at) {
            Ok(t) => t,
            Err(e) => return evaluating(&claim, e),
        };
        let finalized = catch_unwind(AssertUnwindSafe(|| {
            finalize_claim_proof_bundle_v2_inner(ctx, store, &token, &terminal, &body)
        }))
        .unwrap_or_else(|_| Err(FinalizeFailure::Own(V2Error::plain("claim store finalization panicked"))));
        let (rate_limited, finalize_err) = match finalized {
            Ok(_) => {
                let horizon = if decision == "allow" { token.state.allow_horizon() } else { 0 };
                return V2VerifyOutcome {
                    stage: V2VerifyStage::Committed,
                    error: None,
                    error_class: None,
                    disposition: Some(disposition),
                    claim: claim.clone(),
                    committed: Some(CommittedV2Outcome::new(&claim, &body, horizon)),
                };
            }
            Err(FinalizeFailure::Own(e)) => (false, e),
            Err(FinalizeFailure::Store(e)) => (matches!(e, V2StoreError::RateLimitExceeded), e.into_v2()),
        };
        let finalize_err = finalize_err.classify(V2ErrorClass::ClaimStoreUnavailable);
        if ctx.is_done() {
            return cancelled(&claim);
        }
        if !rate_limited || attempt > 0 {
            return evaluating(&claim, finalize_err);
        }
        // A barrier store proved definitive capacity exhaustion and rolled
        // back; the same claim finalizes once as constraint_denied.
        assessment.status = "constraint_denied".into();
        assessment.reason = "constraint_denied".into();
        assessment.detail = "signed rate limit has no remaining capacity".into();
    }
    evaluating(
        &claim,
        V2Error::new(V2ErrorClass::ClaimStoreUnavailable, "v2 terminal finalization did not complete"),
    )
}

/// Go `validateV2VerifyConfiguration`: out-of-bounds configuration and an
/// invalid supplied request context are rejected before claim.
fn validate_v2_verify_configuration(req: &V2VerifyRequest) -> V2Result<()> {
    validate_v2_freshness_configuration(req.now, req.max_challenge_age_seconds, req.future_skew_seconds)?;
    if !(0..=MAX_SAFE).contains(&req.replay_epoch) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("v2 configured replay epoch must be 0..{MAX_SAFE}"),
        );
    }
    // The live verifier has one future skew (SPEC-v2 §6.1): status freshness
    // uses future_skew_seconds, so a status policy carrying another skew is a
    // configuration error rather than a second, silently different bound.
    if req.status_policy.clock_skew_seconds != req.future_skew_seconds {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 status policy skew must equal future_skew_seconds",
        );
    }
    validate_v2_request_context(&req.context)?;
    validate_v2_status_configuration(&req.status_keys, &req.status_policy)
}

/// Go `validateV2StatusConfiguration`: the caller-authenticated status
/// policy bounds and status-key configuration (SPEC-v2 §2.5, §6.5).
pub(crate) fn validate_v2_status_configuration(
    keys: &BTreeMap<String, V2StatusKeyConfig>,
    policy: &RevocationStatusPolicyV2,
) -> V2Result<()> {
    if !(1..=V2_MAX_STATUS_LIFETIME_SECONDS).contains(&policy.max_list_lifetime_seconds)
        || !(1..=V2_MAX_STATUS_LIFETIME_SECONDS).contains(&policy.max_status_age_seconds)
        || !(0..=V2_MAX_FUTURE_SKEW_SECONDS).contains(&policy.clock_skew_seconds)
    {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!(
                "v2 status policy must bound list lifetime and status age to 1..{V2_MAX_STATUS_LIFETIME_SECONDS} seconds and skew to 0..{V2_MAX_FUTURE_SKEW_SECONDS}"
            ),
        );
    }
    for (issuer_id, config) in keys {
        if !valid_v2_id(issuer_id) || config.epoch == 0 || config.epoch > MAX_SAFE as u64 {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "v2 status-key configuration has an invalid issuer or epoch",
            );
        }
        if let Err(e) = key_id_v2(&config.key) {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                format!("v2 status-key configuration has an invalid key: {}", e.message),
            );
        }
    }
    Ok(())
}

/// Go `buildV2TerminalResult`: map a terminal assessment to the receipt
/// tuple of SPEC-v2 §5.8 and the §6.7 table and validate it by preparing the
/// exact receipt outbox body. `verified_at` is the authoritative claim time.
/// Returns `(decision, terminal_result, receipt_body)`.
fn build_v2_terminal_result(
    bundle: &ProofBundleV2,
    assessment: &V2LocalAuthorizationAssessment,
    progress: &EvaluationProgress,
    claim: &V2ChallengeClaim,
    verified_at: i64,
) -> V2Result<(&'static str, Vec<u8>, Vec<u8>)> {
    let Some(decision) = terminal_decision_for_v2_evaluation(&assessment.status, &assessment.reason) else {
        return Err(V2Error::plain(format!(
            "v2 evaluation did not reach a terminal result: {}/{}",
            assessment.status, assessment.reason
        )));
    };
    let mut trust = progress.persisted.trust_assessment.clone();
    let mut status_assessment = if assessment.status_assessment.is_empty() {
        "not_evaluated".to_string()
    } else {
        assessment.status_assessment.clone()
    };
    let mut context_assessment = if assessment.context_assessment.is_empty() {
        "not_evaluated".to_string()
    } else {
        assessment.context_assessment.clone()
    };
    let mut evidence = assessment.status_evidence.clone();
    if assessment.reason == "not_delegated" {
        trust = "not_evaluated".into();
    }
    if status_assessment == "not_evaluated" {
        evidence = Vec::new();
    }
    let mut policy_digest = if context_assessment != "not_evaluated" && context_assessment != "unbound" {
        assessment.context_policy_digest.clone()
    } else {
        None
    };
    if assessment.reason == "evaluation_interrupted" {
        // Per-dimension progress, exactly as lease-expiry recovery reports it.
        let p = progress.persisted.clone();
        trust = p.trust_assessment;
        status_assessment = p.status_assessment;
        context_assessment = p.context_assessment;
        policy_digest = p.context_policy_digest;
        evidence = p.status_evidence;
    }
    let mut granted = Vec::new();
    if decision == "allow" {
        granted = assessment.effective_scope.clone();
        granted.sort();
        granted.dedup();
    }
    let mut receipt = receipt_skeleton();
    receipt.verifier_id = bundle.verifier_id.clone();
    receipt.agent_id = bundle.agent_id.clone();
    receipt.bundle_hash = claim.bundle_hash.clone();
    receipt.issuer_ids = claim.issuer_ids.clone();
    receipt.decision = decision.into();
    receipt.decision_reason = assessment.reason.clone();
    receipt.identity_status = assessment.status.clone();
    receipt.trust_assessment = trust;
    receipt.status_assessment = status_assessment;
    receipt.challenge_assessment = "current".into();
    receipt.context_assessment = context_assessment;
    receipt.context_policy_digest = policy_digest;
    receipt.verified_at = verified_at;
    receipt.required_scope = claim.required_scope.clone();
    receipt.granted_scope = granted;
    receipt.status_evidence = evidence;
    receipt.constraint_evaluators = claim.constraint_evaluators.clone();
    let body = verification_receipt_v2_body(&receipt)
        .map_err(|e| e.context("v2 terminal receipt body is inconsistent with the evaluated result"))?;
    let terminal = terminal_result_json(decision, &assessment.reason, &assessment.status)?;
    Ok((decision, terminal, body))
}

// ---------------------------------------------------------------------------
// Fail-closed callback adapters. A panic is treated exactly like an error.

/// Go `callV2TrustSafely`: a missing provider answers unavailable.
pub(crate) fn call_v2_trust_safely(
    ctx: &V2Context,
    trust: Option<&V2TrustProvider>,
    chain: &[DelegationCertV2],
) -> Result<V2TrustResolution, V2ProviderError> {
    let Some(trust) = trust else {
        return Ok(V2TrustResolution::unavailable());
    };
    let chain = chain.to_vec();
    catch_unwind(AssertUnwindSafe(|| trust(ctx, &chain)))
        .unwrap_or_else(|_| Err(V2ProviderError::new("trust resolver panicked")))
}

fn call_v2_audience_safely(
    ctx: &V2Context,
    audience: Option<&V2AudienceProvider>,
    deferred: &[V2DeferredConstraint],
    receiver_id: &str,
) -> Result<Vec<V2AudienceMembership>, V2ProviderError> {
    let Some(audience) = audience else {
        return Ok(Vec::new());
    };
    catch_unwind(AssertUnwindSafe(|| audience(ctx, deferred, receiver_id)))
        .unwrap_or_else(|_| Err(V2ProviderError::new("audience provider panicked")))
}
