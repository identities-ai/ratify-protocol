//! Persisted evaluation progress and lease-expiry recovery (SPEC-v2 §6.7,
//! §7.5). Mirrors Go `evaluation_progress_v2.go`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use super::claim_store::{
    claim_id_matches_key, validate_v2_finalization_payload, ClaimStoreV2, V2ChallengeClaim, V2EvaluationToken,
    V2StoreError,
};
use super::context::V2Context;
use super::crypto::valid_prefixed_digest;
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, CJ};
use super::limits::{valid_v2_timestamp, V2_MAX_TIMESTAMP_SECONDS};
use super::receipt::{
    decode_verification_receipt_body_v2, verification_receipt_v2_body, StatusEvidenceEntryV2, VerificationReceiptV2,
};
use super::release::CommittedV2Outcome;
use crate::types::HybridSignature;

/// The per-dimension progress of one claimed evaluation (SPEC-v2 §6.7,
/// §7.5). The evaluator persists it in the claim store under its evaluator
/// capability before every external lookup starts and after it completes.
///
/// - `trust_assessment`: not_evaluated, unavailable (started, not
///   completed), trusted, or untrusted.
/// - `status_assessment`: not_evaluated, unavailable, current, revoked, or
///   stale.
/// - `context_assessment`: not_evaluated, bound, or not_required.
/// - `context_policy_digest` is present exactly when `context_assessment` is
///   bound or not_required.
/// - `status_evidence` is empty while `status_assessment` is not_evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2EvaluationProgress {
    pub trust_assessment: String,
    pub status_assessment: String,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub status_evidence: Vec<StatusEvidenceEntryV2>,
}

impl Default for V2EvaluationProgress {
    fn default() -> Self {
        initial_v2_evaluation_progress()
    }
}

/// What a claim store returns to lease-expiry recovery: the sealed claim,
/// its authoritative claim time T_claim, and the last persisted progress.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2InterruptedClaim {
    pub claim: V2ChallengeClaim,
    pub claimed_at: i64,
    pub progress: V2EvaluationProgress,
}

/// Go `InitialV2EvaluationProgress`: no post-claim check has started.
pub fn initial_v2_evaluation_progress() -> V2EvaluationProgress {
    V2EvaluationProgress {
        trust_assessment: "not_evaluated".into(),
        status_assessment: "not_evaluated".into(),
        context_assessment: "not_evaluated".into(),
        context_policy_digest: None,
        status_evidence: Vec::new(),
    }
}

/// Go `ValidateV2EvaluationProgress` (class `malformed`; Go returns an
/// unclassified error). A claim store rejects an invalid record, and
/// recovery refuses to build a receipt from one. (Go's additional "nil
/// evidence slice" rejection has no Rust counterpart: a `Vec` is never nil.)
pub fn validate_v2_evaluation_progress(p: &V2EvaluationProgress) -> V2Result<()> {
    validate_v2_evaluation_progress_inner(p).classify(V2ErrorClass::Malformed)
}

pub(crate) fn validate_v2_evaluation_progress_inner(p: &V2EvaluationProgress) -> V2Result<()> {
    if !matches!(p.trust_assessment.as_str(), "not_evaluated" | "unavailable" | "trusted" | "untrusted") {
        return plain("v2 evaluation progress trust_assessment is invalid");
    }
    if !matches!(
        p.status_assessment.as_str(),
        "not_evaluated" | "unavailable" | "current" | "revoked" | "stale"
    ) {
        return plain("v2 evaluation progress status_assessment is invalid");
    }
    if !matches!(p.context_assessment.as_str(), "not_evaluated" | "bound" | "not_required") {
        return plain("v2 evaluation progress context_assessment is invalid");
    }
    if (p.context_assessment == "not_evaluated") != p.context_policy_digest.is_none()
        || p.context_policy_digest.as_deref().is_some_and(|d| !valid_prefixed_digest(d))
    {
        return plain("v2 evaluation progress context_policy_digest does not match context_assessment");
    }
    if p.trust_assessment != "trusted"
        && (p.status_assessment != "not_evaluated" || p.context_assessment != "not_evaluated")
    {
        return plain("v2 evaluation progress records status or context without a trusted root");
    }
    if p.status_assessment == "not_evaluated" && !p.status_evidence.is_empty() {
        return plain("v2 evaluation progress status evidence is inconsistent with status_assessment");
    }
    Ok(())
}

/// The canonical terminal-result object `{"decision","decision_reason",
/// "identity_status"}`.
pub(crate) fn terminal_result_json(decision: &str, reason: &str, identity_status: &str) -> V2Result<Vec<u8>> {
    canonical(&CJ::obj(vec![
        ("decision", CJ::s(decision)),
        ("decision_reason", CJ::s(reason)),
        ("identity_status", CJ::s(identity_status)),
    ]))
}

/// An empty receipt with the fields every receipt shares; callers fill the
/// rest (the log position, previous hash and signature are not part of a
/// receipt body).
pub(crate) fn receipt_skeleton() -> VerificationReceiptV2 {
    VerificationReceiptV2 {
        version: 2,
        log_id: String::new(),
        sequence: 0,
        verifier_id: String::new(),
        agent_id: String::new(),
        human_id: String::new(),
        bundle_hash: String::new(),
        issuer_ids: Vec::new(),
        decision: String::new(),
        decision_reason: String::new(),
        identity_status: String::new(),
        trust_assessment: String::new(),
        status_assessment: String::new(),
        challenge_assessment: String::new(),
        constraint_evaluators: Vec::new(),
        context_assessment: String::new(),
        context_policy_digest: None,
        verified_at: 0,
        required_scope: String::new(),
        granted_scope: Vec::new(),
        status_evidence: Vec::new(),
        previous_receipt_hash: Vec::new(),
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    }
}

/// Go `V2EvaluationInterruptedResult`: the canonical terminal result object
/// and receipt outbox body for indeterminate/evaluation_interrupted from the
/// claim's sealed values and its evaluation progress. `verified_at` is the
/// claim's authoritative claim time T_claim. Returns `(terminal_result,
/// receipt_body)`.
pub fn v2_evaluation_interrupted_result(
    claim: &V2ChallengeClaim,
    verified_at: i64,
    progress: &V2EvaluationProgress,
) -> V2Result<(Vec<u8>, Vec<u8>)> {
    if !valid_v2_timestamp(verified_at) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 recovery time is outside the timestamp domain",
        );
    }
    validate_v2_evaluation_progress_inner(progress).classify(V2ErrorClass::Malformed)?;
    let mut issuers = claim.issuer_ids.clone();
    issuers.sort();
    issuers.dedup();
    let mut receipt = receipt_skeleton();
    receipt.verifier_id = claim.verifier_id.clone();
    receipt.agent_id = claim.agent_id.clone();
    receipt.bundle_hash = claim.bundle_hash.clone();
    receipt.issuer_ids = issuers;
    receipt.decision = "indeterminate".into();
    receipt.decision_reason = "evaluation_interrupted".into();
    receipt.identity_status = "authorization_unverified".into();
    receipt.trust_assessment = progress.trust_assessment.clone();
    receipt.status_assessment = progress.status_assessment.clone();
    receipt.challenge_assessment = "current".into();
    receipt.context_assessment = progress.context_assessment.clone();
    receipt.context_policy_digest = progress.context_policy_digest.clone();
    receipt.verified_at = verified_at;
    receipt.required_scope = claim.required_scope.clone();
    receipt.status_evidence = progress.status_evidence.clone();
    receipt.constraint_evaluators = claim.constraint_evaluators.clone();
    let receipt_body = verification_receipt_v2_body(&receipt).classify(V2ErrorClass::Malformed)?;
    let terminal = terminal_result_json("indeterminate", "evaluation_interrupted", "authorization_unverified")
        .classify(V2ErrorClass::Malformed)?;
    Ok((terminal, receipt_body))
}

/// Go `RecoverInterruptedClaimV2`: lease-expiry recovery. Loads the claim's
/// sealed values, T_claim and persisted progress from the store (which
/// refuses while the evaluator lease is live), commits the
/// evaluation_interrupted result built from them, and returns the committed,
/// non-actionable outcome for publication and release. An identical repeat
/// returns the same outcome.
pub fn recover_interrupted_claim_v2(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    claim_id: &str,
) -> V2Result<CommittedV2Outcome> {
    if claim_id.is_empty() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 recovery requires a context, claim store and claim ID",
        );
    }
    let classify = |e: V2StoreError| e.classified_or(V2ErrorClass::ClaimStoreUnavailable);
    let interrupted = match catch_unwind(AssertUnwindSafe(|| store.load_v2_interrupted_claim(ctx, claim_id))) {
        Ok(r) => r.map_err(classify)?,
        Err(_) => {
            return err(
                V2ErrorClass::ClaimStoreUnavailable,
                "claim store recovery load panicked",
            )
        }
    };
    if interrupted.claim.claim_id != claim_id {
        return err(
            V2ErrorClass::ClaimStoreUnavailable,
            "v2 claim store returned a different claim for recovery",
        );
    }
    let (terminal, body) =
        v2_evaluation_interrupted_result(&interrupted.claim, interrupted.claimed_at, &interrupted.progress)?;
    match catch_unwind(AssertUnwindSafe(|| {
        store.recover_interrupted_v2_claim(ctx, claim_id, &terminal, &body)
    })) {
        Ok(r) => {
            r.map_err(classify)?;
        }
        Err(_) => return err(V2ErrorClass::ClaimStoreUnavailable, "claim store recovery panicked"),
    }
    Ok(CommittedV2Outcome::new(&interrupted.claim, &body, 0))
}

/// Go `V2CommittedClaim`: a terminal claim as the claim store's terminal
/// compare-and-set persisted it: the sealed claim values, the terminal
/// result, the sealed receipt outbox body, and the allow horizon (0 unless
/// the result is an allow).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2CommittedClaim {
    pub claim: V2ChallengeClaim,
    pub terminal_result: Vec<u8>,
    pub receipt_body: Vec<u8>,
    pub allow_horizon: i64,
}

/// Go `V2CommittedClaimStore`: loads a terminal claim's persisted record for
/// resumption (SPEC-v2 §7.11). `load_v2_committed_claim` answers
/// `claim_not_found` for a claim the store does not hold, `claim_lease_live`
/// for a claim still evaluating under a live lease, and `claim_lease_lost`
/// for a claim still evaluating after its lease expired (lease-expiry
/// recovery runs first).
pub trait V2CommittedClaimStore {
    fn load_v2_committed_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2CommittedClaim, V2StoreError>;
}

/// Go `ResumeCommittedClaimV2`: returns the handoff of a claim's committed
/// result from the claim store's persisted record (SPEC-v2 §7.11), for a
/// service whose handoff was lost after the terminal commit, for example by
/// a crash before the verifier returned. It checks the record as the
/// terminal compare-and-set does and never builds or replaces a result; a
/// record that fails a check is `claim_store_unavailable`. Publication,
/// checkpoint submission and release then proceed as for a returned handoff.
pub fn resume_committed_claim_v2(
    ctx: &V2Context,
    store: &dyn V2CommittedClaimStore,
    claim_id: &str,
) -> V2Result<CommittedV2Outcome> {
    if claim_id.is_empty() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 resumption requires a context, claim store and claim ID",
        );
    }
    let committed = match catch_unwind(AssertUnwindSafe(|| store.load_v2_committed_claim(ctx, claim_id))) {
        Ok(r) => r.map_err(|e| e.classified_or(V2ErrorClass::ClaimStoreUnavailable))?,
        Err(_) => {
            return err(
                V2ErrorClass::ClaimStoreUnavailable,
                "claim store committed-claim load panicked",
            )
        }
    };
    if let Err(e) = validate_v2_committed_claim(&committed, claim_id) {
        return err(
            V2ErrorClass::ClaimStoreUnavailable,
            format!("v2 claim store returned a committed record that fails its checks: {}", e.message),
        );
    }
    Ok(CommittedV2Outcome::new(&committed.claim, &committed.receipt_body, committed.allow_horizon))
}

/// Go `validateV2CommittedClaim`: the terminal compare-and-set's checks on a
/// persisted record: the claim ID (§7.3), the finalization payload (§7.5),
/// and the allow horizon (§6.8).
fn validate_v2_committed_claim(committed: &V2CommittedClaim, claim_id: &str) -> V2Result<()> {
    let claim = &committed.claim;
    if claim.claim_id != claim_id {
        return plain("the record is for a different claim");
    }
    if !claim_id_matches_key(claim) {
        return plain("the claim ID does not derive from the claim's replay key");
    }
    validate_v2_finalization_payload(claim, &committed.terminal_result, &committed.receipt_body)?;
    let body = decode_verification_receipt_body_v2(&committed.receipt_body)?;
    if body.decision == "allow" {
        if committed.allow_horizon <= 0 || committed.allow_horizon > V2_MAX_TIMESTAMP_SECONDS {
            return plain("an allow has no allow horizon in the timestamp domain");
        }
    } else if committed.allow_horizon != 0 {
        return plain("a result that is not an allow has an allow horizon");
    }
    Ok(())
}

/// Go `recordV2ProgressSafely`: persist progress under the evaluator
/// capability. Any failure stops the evaluation before the next provider
/// call.
pub(crate) fn record_v2_progress_safely(
    ctx: &V2Context,
    store: &dyn ClaimStoreV2,
    token: &V2EvaluationToken,
    progress: &V2EvaluationProgress,
) -> V2Result<()> {
    validate_v2_evaluation_progress_inner(progress)?;
    let state = &token.state;
    match catch_unwind(AssertUnwindSafe(|| {
        store.record_v2_evaluation_progress(ctx, &state.claim_id, &state.owner_token, progress.clone())
    })) {
        Ok(r) => r.map_err(|e| e.classified_or(V2ErrorClass::ClaimStoreUnavailable)),
        Err(_) => Err(V2Error::new(
            V2ErrorClass::ClaimStoreUnavailable,
            "claim store progress write panicked",
        )),
    }
}
