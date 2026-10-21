//! Ordered live verifier (SPEC-v2 §6): preflight, atomic claim, local
//! authorization, status, audience, rate, and terminal finalization.
//! Mirrors Go `verify_v2_preflight.go`, `claim_store_v2.go`,
//! `authorization_v2.go`, and `verify_v2.go`.

use std::sync::Mutex;

use super::crypto::{equal_keys, key_id_v2, sha256, valid_v2_id};
use super::errors::{err, plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, CJ};
use super::policy::{
    build_v2_rate_reservation_batch, decision_fields, evaluate_proof_bundle_v2_context_policy,
    evaluate_receiver_audience_v2, signed_rate_batch, V2AudienceMembership, V2ContextPolicy,
    V2DeferredConstraint, V2RateReservation,
};
use super::receipt::{verification_receipt_v2_body, StatusEvidenceEntryV2, VerificationReceiptV2};
use super::status::{
    aggregate_certificate_status_v2, RevocationStatusResultV2, V2CertificateStatusCheck,
    V2StatusRoleBindings,
};
use super::wire::{
    audience_params, bundle_hash_v2, decode_proof_bundle_v2, encode_constraint_v2,
    validate_required_scope_v2, validate_scopes_v2, verify_proof_bundle_v2_signatures,
    DelegationCertV2, ProofBundleV2, CONSTRAINT_RECEIVER_AUDIENCE, MAX_SAFE,
};
use crate::types::{HybridPublicKey, HybridSignature, VerifierContext};

// ---------------------------------------------------------------------------
// Expected challenge and preflight

/// Verifier-authenticated issuance state for one challenge.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExpectedChallengeV2 {
    pub value: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    /// Empty means not configured (must be paired with the public key).
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<HybridPublicKey>,
    /// Empty means not configured.
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
    pub context_policy: Option<V2ContextPolicy>,
}

#[derive(Debug, Clone)]
struct SealedState {
    expected: ExpectedChallengeV2,
    required_scope: String,
    bundle_hash: String,
    issuer_ids: Vec<String>,
    future_skew: i64,
    max_age: i64,
    context_policy_digest: String,
    context_policy: Option<V2ContextPolicy>,
    no_context_policy: bool,
}

/// Sealed result of a successful preflight; its state is never exposed.
#[derive(Debug, Clone)]
pub struct V2PreflightResult {
    state: SealedState,
}

fn matches_sealed(expected: &ExpectedChallengeV2, sealed: &SealedState) -> bool {
    let s = &sealed.expected;
    expected.value == s.value
        && expected.issued_at == s.issued_at
        && expected.expires_at == s.expires_at
        && expected.verifier_namespace == s.verifier_namespace
        && expected.replay_epoch == s.replay_epoch
        && expected.verifier_id == s.verifier_id
        && expected.expected_agent_id == s.expected_agent_id
        && expected.expected_receiver_id == s.expected_receiver_id
        && expected.expected_session_context == s.expected_session_context
        && (expected.context_policy.is_none() || expected.context_policy == sealed.context_policy)
        && expected.expected_agent_public_key == s.expected_agent_public_key
}

/// Pure pre-claim checks (scope, proof, challenge binding, freshness,
/// expected agent, session context, exact receiver audience).
#[allow(clippy::too_many_arguments)]
pub fn validate_proof_bundle_v2_preflight(
    bundle: &ProofBundleV2,
    expected: &ExpectedChallengeV2,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<()> {
    use V2ErrorClass::*;
    if let Some(p) = &expected.context_policy {
        if !p.valid() {
            return err(
                ConfigurationInvalid,
                "v2 expected context policy is invalid",
            );
        }
        if p.require_bound()
            && (expected.expected_session_context.as_deref() != Some(p.expected_session_context())
                || p.expected_session_context().len() != 32)
        {
            return err(
                ConfigurationInvalid,
                "v2 expected context does not match its policy",
            );
        }
        if !p.require_bound() && expected.expected_session_context.is_some() {
            return err(
                ConfigurationInvalid,
                "unbound v2 context policy cannot have an expected session context",
            );
        }
    }
    validate_required_scope_v2(required_scope).map_err(|e| {
        V2Error::new(
            InvalidRequiredScope,
            format!("v2 request scope: {}", e.message),
        )
    })?;
    verify_proof_bundle_v2_signatures(bundle)
        .map_err(|e| e.context("v2 cryptographic preflight"))?;
    if configured_namespace.is_empty() || expected.verifier_namespace != configured_namespace {
        return err(
            NamespaceMismatch,
            "v2 challenge verifier namespace mismatch",
        );
    }
    let in_range = |v: i64| (0..=MAX_SAFE).contains(&v);
    if !in_range(configured_replay_epoch)
        || !in_range(expected.replay_epoch)
        || expected.replay_epoch != configured_replay_epoch
    {
        return err(StaleReplayEpoch, "v2 challenge replay epoch is stale");
    }
    if expected.verifier_id.is_empty()
        || expected.verifier_id != bundle.verifier_id
        || !valid_v2_id(&expected.verifier_id)
    {
        return err(VerifierIdMismatch, "v2 challenge verifier ID mismatch");
    }
    if expected.value.len() != 32
        || bundle.challenge != expected.value
        || bundle.challenge_at != expected.issued_at
    {
        return err(
            ChallengeMismatch,
            "v2 proof does not match authenticated challenge issuance",
        );
    }
    let safe = |v: i64| (-MAX_SAFE..=MAX_SAFE).contains(&v);
    if !safe(expected.issued_at)
        || !safe(expected.expires_at)
        || expected.expires_at <= expected.issued_at
    {
        return err(
            ConfigurationInvalid,
            "v2 authenticated challenge time bounds are invalid",
        );
    }
    if !safe(now)
        || max_age_seconds <= 0
        || max_age_seconds > MAX_SAFE
        || !in_range(future_skew_seconds)
    {
        return err(ConfigurationInvalid, "v2 freshness policy is invalid");
    }
    if expected.issued_at > now && expected.issued_at - now > future_skew_seconds {
        return err(
            ChallengeNotFresh,
            "v2 challenge issuance is too far in the future",
        );
    }
    if now >= expected.expires_at {
        return err(ChallengeNotFresh, "v2 challenge is expired");
    }
    if now - expected.issued_at > max_age_seconds {
        return err(ChallengeNotFresh, "v2 challenge exceeds maximum age");
    }
    if expected.expected_agent_id.is_empty() != expected.expected_agent_public_key.is_none() {
        return err(
            ConfigurationInvalid,
            "v2 expected agent ID and public key must be configured together",
        );
    }
    if let Some(key) = &expected.expected_agent_public_key {
        let id = key_id_v2(key).map_err(|e| {
            V2Error::new(
                ConfigurationInvalid,
                format!("v2 expected agent key: {}", e.message),
            )
        })?;
        if id != expected.expected_agent_id
            || bundle.agent_id != id
            || !equal_keys(&bundle.agent_pub_key, key)
        {
            return err(
                ExpectedAgentMismatch,
                "v2 presentation does not match authenticated expected agent",
            );
        }
    }
    if let Some(ctx) = &expected.expected_session_context {
        if ctx.len() != 32 || bundle.session_context.as_ref() != Some(ctx) {
            return err(
                SessionContextMismatch,
                "v2 presentation does not match expected session context",
            );
        }
    }
    check_exact_receiver_audience(bundle, &expected.expected_receiver_id)
}

fn check_exact_receiver_audience(bundle: &ProofBundleV2, receiver_id: &str) -> V2Result<()> {
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for c in cert
            .constraints
            .iter()
            .filter(|c| c.kind == CONSTRAINT_RECEIVER_AUDIENCE)
        {
            if receiver_id.is_empty() {
                return err(
                    V2ErrorClass::ReceiverAudienceRequired,
                    "v2 receiver audience requires an authenticated expected receiver ID",
                );
            }
            let (exact, domains, _) = audience_params(c);
            if domains.is_empty() && !exact.iter().any(|e| e == receiver_id) {
                return err(
                    V2ErrorClass::ReceiverAudienceMismatch,
                    format!("v2 receiver does not match exact-only audience at delegation {i}"),
                );
            }
        }
    }
    Ok(())
}

/// Pure application receiver-binding hook; runs after every built-in
/// pre-claim check and before the claim. Must not perform I/O.
pub trait V2ReceiverBinding {
    fn check(
        &mut self,
        bundle: &ProofBundleV2,
        expected: &ExpectedChallengeV2,
    ) -> Result<(), String>;
}

/// Bind the expected challenge to the immutable context policy and run the
/// ordered pre-claim pipeline. A policy is required here.
#[allow(clippy::too_many_arguments)]
pub fn preflight_proof_bundle_v2(
    bundle: &ProofBundleV2,
    expected: Option<&ExpectedChallengeV2>,
    policy: Option<&V2ContextPolicy>,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<V2PreflightResult> {
    preflight(
        bundle,
        expected,
        policy,
        false,
        None,
        required_scope,
        configured_namespace,
        configured_replay_epoch,
        now,
        max_age_seconds,
        future_skew_seconds,
    )
}

#[allow(clippy::too_many_arguments)]
fn preflight(
    bundle: &ProofBundleV2,
    expected: Option<&ExpectedChallengeV2>,
    policy: Option<&V2ContextPolicy>,
    allow_no_policy: bool,
    hook: Option<&mut dyn V2ReceiverBinding>,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<V2PreflightResult> {
    use V2ErrorClass::*;
    let Some(expected) = expected else {
        return err(
            ExpectedChallengeUnavailable,
            "v2 expected challenge is unavailable",
        );
    };
    if (policy.is_none() && !allow_no_policy) || policy.is_some_and(|p| !p.valid()) {
        return err(
            ConfigurationInvalid,
            "v2 context policy is missing or invalid",
        );
    }
    match policy {
        None if expected.context_policy.is_some() => {
            return err(
                ConfigurationInvalid,
                "v2 challenge context policy does not match the issued policy",
            );
        }
        Some(p) => {
            if expected.context_policy.as_ref().is_some_and(|e| e != p) {
                return err(
                    ConfigurationInvalid,
                    "v2 challenge context policy does not match the issued policy",
                );
            }
            if p.require_bound() {
                if expected.expected_session_context.as_deref()
                    != Some(p.expected_session_context())
                    || p.expected_session_context().len() != 32
                {
                    return err(
                        ConfigurationInvalid,
                        "v2 challenge context does not match the configured context policy",
                    );
                }
            } else if expected.expected_session_context.is_some() {
                return err(
                    ConfigurationInvalid,
                    "unbound v2 context policy cannot have an expected session context",
                );
            }
        }
        None => {}
    }
    let mut checked = expected.clone();
    checked.context_policy = policy.cloned();
    validate_proof_bundle_v2_preflight(
        bundle,
        &checked,
        required_scope,
        configured_namespace,
        configured_replay_epoch,
        now,
        max_age_seconds,
        future_skew_seconds,
    )?;
    if let Some(hook) = hook {
        hook.check(bundle, &checked).map_err(|e| {
            V2Error::new(
                ReceiverBindingRejected,
                format!("v2 receiver-binding hook rejected the presentation: {e}"),
            )
        })?;
    }
    let bundle_hash = bundle_hash_v2(bundle)
        .map_err(|e| e.context("v2 validated bundle hash"))
        .classify(Malformed)?;
    let mut issuer_ids: Vec<String> = bundle
        .delegations
        .iter()
        .map(|c| c.issuer_id.clone())
        .collect();
    issuer_ids.sort();
    issuer_ids.dedup();
    Ok(V2PreflightResult {
        state: SealedState {
            expected: expected.clone(),
            required_scope: required_scope.to_string(),
            bundle_hash,
            issuer_ids,
            future_skew: future_skew_seconds,
            max_age: max_age_seconds,
            context_policy_digest: policy.map(|p| p.digest().to_string()).unwrap_or_default(),
            context_policy: policy.cloned(),
            no_context_policy: policy.is_none(),
        },
    })
}

// ---------------------------------------------------------------------------
// Claim store and evaluation token

/// Immutable identity persisted when a verifier consumes a fresh challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ClaimDisposition {
    Created,
    InProgress,
    TerminalReplay,
}

impl V2ClaimDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            V2ClaimDisposition::Created => "created",
            V2ClaimDisposition::InProgress => "in_progress",
            V2ClaimDisposition::TerminalReplay => "terminal_replay",
        }
    }
}

/// Claim transaction result with the store's authoritative timestamp.
#[derive(Debug, Clone)]
pub struct V2ClaimResult {
    pub disposition: V2ClaimDisposition,
    pub claimed_at: i64,
    /// Returned only to the creator: 32 unpredictable bytes.
    pub owner_token: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2ClaimStoreError {
    /// The challenge was already claimed by a different proof (`claim_replay`).
    ProofConflict,
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2FinalizeError {
    /// Definitive capacity exhaustion after rollback (rate-at-finalization stores only).
    RateLimitExceeded,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2RateError {
    LimitExceeded,
    Unavailable(String),
}

/// Storage boundary for challenge consumption (see Go `ClaimStoreV2` for the
/// atomicity, durability, owner-token, and lease contract).
pub trait ClaimStoreV2 {
    fn claim_v2(&mut self, claim: &V2ChallengeClaim) -> Result<V2ClaimResult, V2ClaimStoreError>;
    fn finalize_v2_claim(
        &mut self,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2FinalizeError>;
    fn recover_interrupted_v2_claim(
        &mut self,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, String>;
    /// True for a store that admits the sealed rate batch atomically at finalization.
    fn admits_rate_at_finalization(&self) -> bool {
        false
    }
}

/// Atomic reservation of the complete claim-sealed rate batch.
pub trait V2RateReservationStore {
    fn reserve_v2_rate_batch(
        &mut self,
        claim_id: &str,
        owner_token: &[u8],
        bundle_hash: &str,
        batch: &[V2RateReservation],
    ) -> Result<(), V2RateError>;
    /// True when reservation is deferred to an atomic barrier at finalization.
    fn admits_rate_at_finalization(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct TokenState {
    claim_id: String,
    proof_digest: String,
    required_scope: String,
    future_skew: i64,
    sealed: SealedState,
    used: bool,
    evaluation_complete: bool,
    finalization_digest: Option<Vec<u8>>,
    claim_time_valid: bool,
    claimed_at: i64,
    evaluated_at: i64,
    rate_batch: Vec<V2RateReservation>,
    rate_at_finalization: bool,
    allow_valid_until: i64,
    owner_token: Vec<u8>,
    evaluation_status: String,
    evaluation_reason: String,
    pending: Option<V2LocalAuthorizationAssessment>,
}

/// Single-use capability for one evaluation of a newly created claim.
#[derive(Debug)]
pub struct V2EvaluationToken {
    state: Mutex<TokenState>,
}

impl V2EvaluationToken {
    fn lock(&self) -> std::sync::MutexGuard<'_, TokenState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The allow freshness horizon sealed for a terminal allow (0 otherwise).
    pub fn allow_valid_until(&self) -> i64 {
        self.lock().allow_valid_until
    }
}

/// Repeat the security-relevant checks and atomically claim the challenge.
/// Returns the token only for a newly created claim.
pub fn claim_proof_bundle_v2(
    store: &mut dyn ClaimStoreV2,
    bundle: &ProofBundleV2,
    preflight: &V2PreflightResult,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    now: i64,
) -> V2Result<(
    V2ChallengeClaim,
    V2ClaimDisposition,
    Option<V2EvaluationToken>,
)> {
    let sealed = preflight.state.clone();
    if sealed.context_policy.is_none() && !sealed.no_context_policy {
        return plain("v2 successful preflight state is required before claim");
    }
    if bundle_hash_v2(bundle).ok().as_deref() != Some(sealed.bundle_hash.as_str()) {
        return plain("v2 proof bundle differs from successful preflight");
    }
    let mut expected = sealed.expected.clone();
    expected.context_policy = sealed.context_policy.clone();
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
    let e = &sealed.expected;
    if !(0..=MAX_SAFE).contains(&e.replay_epoch) {
        return plain("v2 replay epoch is outside the safe integer range");
    }
    let challenge_digest =
        crate::challenge_claim_v2::challenge_claim_digest_v2(&e.value).map_err(V2Error::plain)?;
    let claim_id = crate::challenge_claim_v2::protocol_claim_id_v2(
        &e.verifier_namespace,
        e.replay_epoch as u64,
        &e.value,
    )
    .map_err(V2Error::plain)?;
    let rate_batch = signed_rate_batch(bundle).map_err(|x| x.context("v2 signed rate batch"))?;
    let claim = V2ChallengeClaim {
        claim_id,
        namespace: e.verifier_namespace.clone(),
        replay_epoch: e.replay_epoch,
        challenge_digest: format!("sha384:{}", hex::encode(challenge_digest)),
        proof_digest: sealed.bundle_hash.clone(),
        bundle_hash: sealed.bundle_hash.clone(),
        issuer_ids: sealed.issuer_ids.clone(),
        required_scope: sealed.required_scope.clone(),
        context_policy_digest: sealed.context_policy_digest.clone(),
        verifier_id: e.verifier_id.clone(),
        agent_id: bundle.agent_id.clone(),
        requires_rate: !rate_batch.is_empty(),
        rate_batch,
        issued_at: e.issued_at,
        expires_at: e.expires_at,
        max_age_seconds: sealed.max_age,
        clock_skew_seconds: sealed.future_skew,
        stream_id: bundle.stream_id.clone(),
        stream_seq: bundle.stream_seq,
    };
    let result = store.claim_v2(&claim).map_err(|x| match x {
        V2ClaimStoreError::ProofConflict => V2Error::new(
            V2ErrorClass::ClaimReplay,
            "v2 challenge was already claimed by a different proof",
        ),
        V2ClaimStoreError::Unavailable(m) => V2Error::plain(m),
    })?;
    match result.disposition {
        V2ClaimDisposition::Created => {
            if result.owner_token.len() != 32 {
                return plain("v2 claim store returned an invalid evaluator owner token");
            }
            let at = result.claimed_at;
            let claim_time_valid = (-MAX_SAFE..=MAX_SAFE).contains(&at)
                && !(at < e.issued_at && e.issued_at - at > sealed.future_skew)
                && at < e.expires_at
                && !(at > e.issued_at && at - e.issued_at > sealed.max_age);
            let token = V2EvaluationToken {
                state: Mutex::new(TokenState {
                    claim_id: claim.claim_id.clone(),
                    proof_digest: claim.proof_digest.clone(),
                    required_scope: sealed.required_scope.clone(),
                    future_skew: sealed.future_skew,
                    rate_batch: claim.rate_batch.clone(),
                    sealed,
                    used: false,
                    evaluation_complete: false,
                    finalization_digest: None,
                    claim_time_valid,
                    claimed_at: at,
                    evaluated_at: 0,
                    rate_at_finalization: false,
                    allow_valid_until: 0,
                    owner_token: result.owner_token,
                    evaluation_status: String::new(),
                    evaluation_reason: String::new(),
                    pending: None,
                }),
            };
            Ok((claim, V2ClaimDisposition::Created, Some(token)))
        }
        d => {
            if !result.owner_token.is_empty() {
                return plain("v2 exact retry must not receive evaluator ownership");
            }
            Ok((claim, d, None))
        }
    }
}

fn terminal_decision(status: &str, reason: &str) -> Option<&'static str> {
    if reason == "evaluation_interrupted" {
        return (status == "authorization_unverified").then_some("indeterminate");
    }
    let (decision, ok) = match status {
        "authorization_unverified" => (
            "indeterminate",
            matches!(
                reason,
                "trust_unavailable"
                    | "action_context_unverified"
                    | "status_unavailable"
                    | "status_stale"
            ),
        ),
        "authorized_agent" => ("allow", reason == "authorized"),
        "constraint_denied"
        | "constraint_unverifiable"
        | "constraint_unknown"
        | "unauthorized"
        | "invalid_scope"
        | "scope_denied" => ("deny", reason == status),
        "revoked" => ("deny", reason == "delegation_revoked"),
        "invalid" => ("deny", reason == "proof_invalid"),
        "delegation_not_authorized" => (
            "deny",
            reason == "not_delegated" || reason == "delegation_not_authorized",
        ),
        "expired" => ("deny", reason == "delegation_expired"),
        _ => return None,
    };
    ok.then_some(decision)
}

/// Commit a terminal local evaluation through the capability that won the claim.
pub fn finalize_claim_proof_bundle_v2(
    store: &mut dyn ClaimStoreV2,
    token: &V2EvaluationToken,
    terminal_result: &[u8],
    receipt_body: &[u8],
) -> Result<bool, V2FinalizeError> {
    let fail = |m: &str| Err(V2FinalizeError::Failed(m.to_string()));
    let mut st = token.lock();
    if st.owner_token.len() != 32 || st.claim_id.is_empty() {
        return fail("v2 claim store and valid evaluator capability are required");
    }
    if !st.evaluation_complete {
        return fail("v2 proof evaluation has not completed");
    }
    let Some(decision) = terminal_decision(&st.evaluation_status, &st.evaluation_reason) else {
        return fail("v2 proof evaluation has not reached a terminal local result");
    };
    let matches = |v: &[u8]| {
        decision_fields(v).is_some_and(|(d, r)| d == decision && r == st.evaluation_reason)
    };
    if !matches(terminal_result) || !matches(receipt_body) {
        return fail("v2 terminal result does not match the completed local evaluation");
    }
    if (decision == "allow" && st.allow_valid_until <= 0)
        || (decision != "allow" && st.allow_valid_until != 0)
    {
        return fail("v2 terminal result lacks a valid allow freshness horizon");
    }
    if st.rate_at_finalization && !store.admits_rate_at_finalization() {
        return fail("v2 rate-at-finalization requires an atomic rate store");
    }
    let digest = sha256(&[
        &(terminal_result.len() as u64).to_be_bytes(),
        terminal_result,
        &(receipt_body.len() as u64).to_be_bytes(),
        receipt_body,
    ]);
    if st
        .finalization_digest
        .as_ref()
        .is_some_and(|d| *d != digest)
    {
        return fail("v2 evaluator capability cannot change its terminal result or receipt body");
    }
    st.finalization_digest = Some(digest);
    let result = store.finalize_v2_claim(
        &st.claim_id,
        &st.owner_token,
        terminal_result,
        receipt_body,
        st.allow_valid_until,
    );
    if matches!(result, Err(V2FinalizeError::RateLimitExceeded))
        && st.rate_at_finalization
        && decision == "allow"
        && store.admits_rate_at_finalization()
    {
        st.evaluation_status = "constraint_denied".into();
        st.evaluation_reason = "constraint_denied".into();
        st.allow_valid_until = 0;
        st.rate_at_finalization = false;
        st.finalization_digest = None;
    }
    result
}

// ---------------------------------------------------------------------------
// Local authorization and post-claim stages

/// Trust configuration resolved for one verified chain.
#[derive(Debug, Clone, Default)]
pub struct V2TrustResolution {
    pub available: bool,
    pub root_id: String,
    pub root_key: Option<HybridPublicKey>,
}

/// Issuer-scoped certificate reference passed to status providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRefV2 {
    pub issuer_id: String,
    pub cert_id: String,
}

/// A local verdict held until every status is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2LocalPolicyFailure {
    pub status: String,
    pub reason: String,
    pub detail: String,
}

/// Intermediate (non-terminal unless `status` is terminal) assessment.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct V2LocalAuthorizationAssessment {
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub agent_id: String,
    pub root_id: String,
    pub required_scope: String,
    pub delegation_digest: Vec<u8>,
    pub effective_scope: Vec<String>,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub status_assessment: String,
    pub delegation_valid_until: i64,
    pub local_time_valid_until: i64,
    pub status_fresh_until: i64,
    pub audience_fresh_until: i64,
    pub status_evidence: Vec<StatusEvidenceEntryV2>,
    pub audience_evidence_digests: Vec<String>,
    pub rate_store_unavailable: bool,
    pub rate_admission_deferred: bool,
    pub status_checks: Vec<V2CertificateStatusCheck>,
    pub deferred: Vec<V2DeferredConstraint>,
    pub local_policy_failure: Option<V2LocalPolicyFailure>,
    pub status: String,
    pub reason: String,
    pub detail: String,
}

/// Verifier-owned inputs for post-claim local authorization.
pub struct V2LocalAuthorizationOptions<'a, 'c> {
    pub now: i64,
    pub future_skew: i64,
    pub required_scope: String,
    pub trusted_root_id: String,
    pub trusted_root_key: Option<HybridPublicKey>,
    pub trust_configured: bool,
    pub context: &'a VerifierContext<'c>,
    pub context_policy: Option<&'a V2ContextPolicy>,
    pub expected_challenge: Option<&'a ExpectedChallengeV2>,
    pub claim_token: Option<&'a V2EvaluationToken>,
}

fn local(
    status: &str,
    reason: &str,
    scope: Vec<String>,
    detail: String,
) -> V2LocalAuthorizationAssessment {
    V2LocalAuthorizationAssessment {
        effective_scope: scope,
        context_assessment: "not_evaluated".into(),
        status: status.into(),
        reason: reason.into(),
        detail,
        ..Default::default()
    }
}

fn interrupted(detail: &str) -> V2LocalAuthorizationAssessment {
    local(
        "authorization_unverified",
        "evaluation_interrupted",
        Vec::new(),
        detail.into(),
    )
}

fn precedence(status: &str) -> u8 {
    match status {
        "constraint_denied" => 3,
        "constraint_unknown" => 2,
        "constraint_unverifiable" => 1,
        _ => 0,
    }
}

fn combinable_with_audience(
    f: &Option<V2LocalPolicyFailure>,
    deferred: &[V2DeferredConstraint],
) -> bool {
    f.as_ref().is_some_and(|f| {
        (f.status == "constraint_unknown" || f.status == "constraint_unverifiable")
            && deferred
                .iter()
                .any(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
    })
}

fn allow_horizon(a: &V2LocalAuthorizationAssessment) -> i64 {
    let mut h = a.delegation_valid_until.min(a.status_fresh_until);
    if a.audience_fresh_until > 0 {
        h = h.min(a.audience_fresh_until);
    }
    if a.local_time_valid_until > 0 {
        h = h.min(a.local_time_valid_until);
    }
    h
}

/// End of the current accepted local minute or the next UTC offset change.
fn local_time_window_valid_until(bundle: &ProofBundleV2, now: i64) -> Result<i64, String> {
    use chrono::{Datelike, Duration, NaiveDate, Offset, TimeZone, Timelike};
    let mut horizon = 0i64;
    for cert in &bundle.delegations {
        for c in cert.constraints.iter().filter(|c| c.kind == "time_window") {
            let tz: chrono_tz::Tz =
                c.tz.parse()
                    .map_err(|_| format!("unknown timezone {:?}", c.tz))?;
            let start = crate::constraints::parse_hhmm(&c.start).ok_or("bad start time")?;
            let end = crate::constraints::parse_hhmm(&c.end).ok_or("bad end time")?;
            let utc = chrono::DateTime::from_timestamp(now, 0).ok_or("invalid time")?;
            let local = utc.with_timezone(&tz);
            let minute = (local.hour() * 60 + local.minute()) as i32;
            let outside = if start <= end {
                minute < start || minute > end
            } else {
                minute < start && minute > end
            };
            if outside {
                return Err("time window is no longer current".into());
            }
            let offset = local.offset().fix().local_minus_utc() as i64;
            let day_offset = if start > end && minute >= start { 1 } else { 0 };
            let date = NaiveDate::from_ymd_opt(local.year(), local.month(), local.day())
                .ok_or("invalid date")?
                + Duration::days(day_offset);
            let naive = date.and_hms_opt(0, 0, 0).ok_or("invalid date")?
                + Duration::minutes(end as i64 + 1);
            let mut until = naive.and_utc().timestamp() - offset;
            // Next UTC-offset transition (Go ZoneBounds): first second in
            // (now, until] whose offset differs from the current one.
            let offset_at = |t: i64| {
                tz.timestamp_opt(t, 0)
                    .single()
                    .map(|d| d.offset().fix().local_minus_utc() as i64)
            };
            if until > now && offset_at(until) != Some(offset) {
                let (mut lo, mut hi) = (now, until);
                while hi - lo > 1 {
                    let mid = lo + (hi - lo) / 2;
                    if offset_at(mid) == Some(offset) {
                        lo = mid;
                    } else {
                        hi = mid;
                    }
                }
                until = until.min(hi);
            }
            if until <= now || until <= 0 || until > MAX_SAFE {
                return Err("time window has no valid terminal horizon".into());
            }
            if horizon == 0 || until < horizon {
                horizon = until;
            }
        }
    }
    Ok(horizon)
}

fn evaluate_local_constraints(
    bundle: &ProofBundleV2,
    ctx: &VerifierContext<'_>,
    now: i64,
) -> (Vec<V2DeferredConstraint>, String, Vec<String>) {
    let mut deferred = Vec::new();
    let mut status = String::new();
    let mut failures = Vec::new();
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for (j, c) in cert.constraints.iter().enumerate() {
            if c.kind == "max_rate" || c.kind == CONSTRAINT_RECEIVER_AUDIENCE {
                match encode_constraint_v2(c) {
                    Ok(enc) => deferred.push(V2DeferredConstraint {
                        delegation_index: i,
                        constraint_index: j,
                        issuer_id: cert.issuer_id.clone(),
                        cert_id: cert.cert_id.clone(),
                        kind: c.kind.clone(),
                        canonical_json: enc.into_bytes(),
                    }),
                    Err(e) => {
                        if precedence("constraint_unverifiable") > precedence(&status) {
                            status = "constraint_unverifiable".into();
                        }
                        failures.push(format!(
                            "delegation {i} constraint {j} cannot be encoded: {}",
                            e.message
                        ));
                    }
                }
                continue;
            }
            if let Err(e) = crate::constraints::evaluate_constraint(c, &cert.cert_id, ctx, now) {
                let s = if e.starts_with("constraint_unverifiable") {
                    "constraint_unverifiable"
                } else if e.starts_with("constraint_unknown") {
                    "constraint_unknown"
                } else {
                    "constraint_denied"
                };
                if status.is_empty() || precedence(s) > precedence(&status) {
                    status = s.into();
                }
                failures.push(format!("delegation {i} constraint {j}: {e}"));
            }
        }
    }
    (deferred, status, failures)
}

/// Post-claim local authorization: trust-root binding, delegation times,
/// effective scope, context policy, and deterministic constraints. No
/// external call is made. Requires the claim's single-use token.
pub fn evaluate_proof_bundle_v2_local_authorization(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions<'_, '_>,
) -> V2LocalAuthorizationAssessment {
    let Some(token) = opts.claim_token else {
        return local(
            "preflight_binding_mismatch",
            "claim_required",
            Vec::new(),
            "local authorization requires a successful atomic challenge claim".into(),
        );
    };
    let mut st = token.lock();
    let (mut assessment, started) = evaluate_local(bundle, opts, &mut st);
    assessment.bundle_hash = st.sealed.bundle_hash.clone();
    assessment.issuer_ids = st.sealed.issuer_ids.clone();
    if started && !assessment.status.is_empty() {
        st.evaluation_status = assessment.status.clone();
        st.evaluation_reason = assessment.reason.clone();
        if assessment.status == "pending_external_checks" {
            st.pending = Some(assessment.clone());
        }
        st.evaluation_complete = true;
    }
    assessment
}

fn evaluate_local(
    bundle: &ProofBundleV2,
    opts: &V2LocalAuthorizationOptions<'_, '_>,
    st: &mut TokenState,
) -> (V2LocalAuthorizationAssessment, bool) {
    let e = &st.sealed.expected;
    let claim_id = crate::challenge_claim_v2::protocol_claim_id_v2(
        &e.verifier_namespace,
        e.replay_epoch.max(0) as u64,
        &e.value,
    )
    .ok();
    if claim_id.as_deref() != Some(st.claim_id.as_str())
        || st.proof_digest != st.sealed.bundle_hash
        || st.owner_token.len() != 32
    {
        return (
            interrupted(
                "local authorization state differs from successful preflight or atomic claim",
            ),
            false,
        );
    }
    if st.used {
        return (
            local(
                "evaluation_in_progress",
                "claim_in_progress",
                Vec::new(),
                "the claim's single evaluation token has already been used".into(),
            ),
            false,
        );
    }
    st.used = true;
    let r = (|| {
        if !st.claim_time_valid {
            return interrupted("claim store returned an authoritative claim time outside the authenticated freshness bounds");
        }
        if opts
            .expected_challenge
            .is_some_and(|x| !matches_sealed(x, &st.sealed))
        {
            return interrupted("local authorization challenge state differs from successful preflight or atomic claim");
        }
        let now = opts.now.max(st.claimed_at);
        st.evaluated_at = now;
        if opts.required_scope != st.required_scope
            || opts.future_skew < 0
            || opts.future_skew != st.future_skew
        {
            return interrupted(
                "local authorization state differs from successful preflight or atomic claim",
            );
        }
        if opts.required_scope != st.sealed.required_scope {
            return interrupted("required scope differs from the scope validated during preflight");
        }
        if bundle_hash_v2(bundle).ok().as_deref() != Some(st.proof_digest.as_str()) {
            return interrupted("proof bundle differs from the bundle validated during preflight");
        }
        let e = &st.sealed.expected;
        if bundle.challenge != e.value
            || bundle.challenge_at != e.issued_at
            || bundle.verifier_id != e.verifier_id
        {
            return interrupted(
                "proof challenge differs from the challenge validated during preflight",
            );
        }
        if validate_required_scope_v2(&opts.required_scope).is_err() {
            return interrupted("required scope changed after successful preflight");
        }
        if verify_proof_bundle_v2_signatures(bundle).is_err() {
            return interrupted("proof signature changed after successful preflight");
        }
        if bundle.delegations.is_empty() {
            return local(
                "delegation_not_authorized",
                "not_delegated",
                Vec::new(),
                "proof has no delegation certificates".into(),
            );
        }
        if !opts.trust_configured {
            return local(
                "authorization_unverified",
                "trust_unavailable",
                Vec::new(),
                "caller-authenticated trust configuration is unavailable".into(),
            );
        }
        let root = bundle.delegations.last().expect("non-empty");
        if opts.trusted_root_id != root.issuer_id
            || opts
                .trusted_root_key
                .as_ref()
                .is_none_or(|k| !equal_keys(k, &root.issuer_pub_key))
        {
            return local(
                "unauthorized",
                "unauthorized",
                Vec::new(),
                "delegation chain does not terminate at the configured trust root".into(),
            );
        }
        for (i, c) in bundle.delegations.iter().enumerate() {
            if c.issued_at >= c.expires_at || c.issued_at > now + opts.future_skew {
                return local(
                    "invalid",
                    "proof_invalid",
                    Vec::new(),
                    format!("delegation {i} has invalid time bounds"),
                );
            }
        }
        for (i, c) in bundle.delegations.iter().enumerate() {
            if now >= c.expires_at {
                return local(
                    "expired",
                    "delegation_expired",
                    Vec::new(),
                    format!("delegation {i} has expired"),
                );
            }
        }
        for (i, c) in bundle.delegations.iter().enumerate() {
            if let Err(err) = validate_scopes_v2(&c.scope) {
                return local(
                    "invalid_scope",
                    "invalid_scope",
                    Vec::new(),
                    format!("delegation {i}: {}", err.message),
                );
            }
        }
        for i in 0..bundle.delegations.len() {
            if let Some(parent) = bundle.delegations.get(i + 1) {
                if !parent
                    .scope
                    .iter()
                    .any(|s| s == crate::scope::SCOPE_IDENTITY_DELEGATE)
                {
                    return local(
                        "delegation_not_authorized",
                        "delegation_not_authorized",
                        Vec::new(),
                        format!(
                            "parent delegation {} does not grant identity:delegate",
                            i + 1
                        ),
                    );
                }
            }
        }
        let lists: Vec<&[String]> = bundle
            .delegations
            .iter()
            .map(|c| c.scope.as_slice())
            .collect();
        let effective = crate::scope::intersect_scopes(&lists);
        let mut failure = None;
        if !effective.contains(&opts.required_scope) {
            failure = Some(V2LocalPolicyFailure {
                status: "scope_denied".into(),
                reason: "scope_denied".into(),
                detail: format!(
                    "required scope {:?} is not in the effective delegation scope",
                    opts.required_scope
                ),
            });
        }
        if opts
            .context_policy
            .is_some_and(|p| Some(p) != st.sealed.context_policy.as_ref())
        {
            return interrupted(
                "context policy differs from the policy sealed during successful preflight",
            );
        }
        let ctx =
            evaluate_proof_bundle_v2_context_policy(bundle, st.sealed.context_policy.as_ref());
        if ctx.status != "passed" && failure.is_none() {
            failure = Some(V2LocalPolicyFailure {
                status: ctx.status.clone(),
                reason: ctx.reason.clone(),
                detail: ctx.detail.clone(),
            });
        }
        let (deferred, cstatus, mut cfail) = evaluate_local_constraints(bundle, opts.context, now);
        if !cstatus.is_empty() {
            cfail.sort();
            if failure.is_none() {
                failure = Some(V2LocalPolicyFailure {
                    status: cstatus.clone(),
                    reason: cstatus,
                    detail: cfail.join("; "),
                });
            }
        }
        let mut a = local(
            "pending_external_checks",
            "external_checks_required",
            effective,
            "local checks recorded; status and deferred authorization checks remain".into(),
        );
        a.agent_id = bundle.agent_id.clone();
        a.root_id = opts.trusted_root_id.clone();
        a.required_scope = opts.required_scope.clone();
        a.delegation_digest = bundle.delegation_digest.clone();
        a.status_checks = bundle
            .delegations
            .iter()
            .enumerate()
            .map(|(i, c)| V2CertificateStatusCheck {
                delegation_index: i,
                issuer_id: c.issuer_id.clone(),
                subject_id: c.subject_id.clone(),
                cert_id: c.cert_id.clone(),
            })
            .collect();
        a.deferred = deferred;
        a.delegation_valid_until = bundle
            .delegations
            .iter()
            .map(|c| c.expires_at)
            .min()
            .unwrap_or(0);
        if failure.is_none() {
            match local_time_window_valid_until(bundle, now) {
                Ok(h) => a.local_time_valid_until = h,
                Err(e) => {
                    failure = Some(V2LocalPolicyFailure {
                        status: "constraint_unverifiable".into(),
                        reason: "constraint_unverifiable".into(),
                        detail: e,
                    })
                }
            }
        }
        a.local_policy_failure = failure;
        a.context_assessment = ctx.assessment;
        a.context_policy_digest = ctx.policy_digest;
        a
    })();
    (r, true)
}

fn pending_of(st: &TokenState, what: &str) -> V2Result<V2LocalAuthorizationAssessment> {
    if !st.evaluation_complete || st.evaluation_status != "pending_external_checks" {
        return plain(format!(
            "v2 claim does not have a pending {what} assessment"
        ));
    }
    st.pending.clone().ok_or_else(|| {
        V2Error::plain(format!(
            "v2 claim does not have a pending {what} assessment"
        ))
    })
}

/// Ordered post-claim status stage: one authenticated result per CertificateRef.
pub fn resolve_claim_proof_bundle_v2_after_status(
    token: &V2EvaluationToken,
    results: &[RevocationStatusResultV2],
    roles: &V2StatusRoleBindings,
) -> V2Result<V2LocalAuthorizationAssessment> {
    let mut st = token.lock();
    let mut a = pending_of(&st, "status")?;
    if a.bundle_hash != st.sealed.bundle_hash || a.required_scope != st.sealed.required_scope {
        return plain("pending status assessment differs from its claimed proof");
    }
    let agg = aggregate_certificate_status_v2(&a.status_checks, results, roles)?;
    a.status_assessment = agg.assessment.clone();
    a.status_fresh_until = agg.fresh_until;
    a.status_evidence = agg.evidence;
    let set = |a: &mut V2LocalAuthorizationAssessment, s: &str, r: &str, d: &str| {
        a.status = s.into();
        a.reason = r.into();
        a.detail = d.into();
    };
    match agg.assessment.as_str() {
        "revoked" => set(
            &mut a,
            "revoked",
            "delegation_revoked",
            "at least one delegation certificate is revoked",
        ),
        "unavailable" => set(
            &mut a,
            "authorization_unverified",
            "status_unavailable",
            "one or more delegation certificate statuses are unavailable",
        ),
        "stale" => set(
            &mut a,
            "authorization_unverified",
            "status_stale",
            "one or more delegation certificate statuses are stale",
        ),
        "current" => {
            if combinable_with_audience(&a.local_policy_failure, &a.deferred) {
                a.deferred
                    .retain(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE);
                set(&mut a, "pending_external_checks", "deferred_policy_checks_required", "status is current; audience must be aggregated with a pending local constraint result");
                st.pending = Some(a.clone());
                st.evaluation_status = a.status.clone();
                st.evaluation_reason = a.reason.clone();
                return Ok(a);
            } else if let Some(f) = a.local_policy_failure.clone() {
                set(&mut a, &f.status, &f.reason, &f.detail);
            } else if !a.deferred.is_empty() {
                set(
                    &mut a,
                    "pending_external_checks",
                    "deferred_policy_checks_required",
                    "status is current; deferred audience or rate checks remain",
                );
                st.pending = Some(a.clone());
                st.evaluation_status = a.status.clone();
                st.evaluation_reason = a.reason.clone();
                return Ok(a);
            } else {
                set(
                    &mut a,
                    "authorized_agent",
                    "authorized",
                    "proof, status, and local authorization checks passed",
                );
                st.allow_valid_until = allow_horizon(&a);
            }
        }
        _ => return plain("v2 status aggregator returned an unknown assessment"),
    }
    st.evaluation_status = a.status.clone();
    st.evaluation_reason = a.reason.clone();
    st.pending = None;
    Ok(a)
}

/// Consume caller-authenticated membership results after current status.
pub fn resolve_claim_proof_bundle_v2_after_audience(
    token: &V2EvaluationToken,
    memberships: &[V2AudienceMembership],
    now: i64,
) -> V2Result<V2LocalAuthorizationAssessment> {
    let mut st = token.lock();
    let mut a = pending_of(&st, "audience")?;
    if a.status_assessment != "current"
        || (a.local_policy_failure.is_some()
            && !combinable_with_audience(&a.local_policy_failure, &a.deferred))
    {
        return plain("v2 claim does not have current status and pending audience checks");
    }
    let interrupt = |st: &mut TokenState| {
        st.evaluation_status = "authorization_unverified".into();
        st.evaluation_reason = "evaluation_interrupted".into();
        st.pending = None;
    };
    if a.bundle_hash != st.sealed.bundle_hash || a.required_scope != st.sealed.required_scope {
        interrupt(&mut st);
        return plain("pending audience assessment differs from its claimed proof");
    }
    let now = now.max(st.evaluated_at);
    let result = match evaluate_receiver_audience_v2(
        &a.deferred,
        &st.sealed.expected.expected_receiver_id,
        memberships,
        now,
        st.future_skew,
    ) {
        Ok(r) => r,
        Err(e) => {
            interrupt(&mut st);
            return Err(e);
        }
    };
    a.audience_evidence_digests = result.evidence_digests.clone();
    a.audience_fresh_until = result.fresh_until;
    if let Some(f) = a.local_policy_failure.clone() {
        if result.status == "passed" || precedence(&f.status) > precedence(&result.status) {
            a.status = f.status;
            a.reason = f.reason;
            a.detail = f.detail;
        } else {
            a.status = result.status.clone();
            a.reason = result.status.clone();
            a.detail = "receiver audience did not authorize this receiver".into();
        }
        a.deferred.clear();
        st.pending = None;
    } else if result.status != "passed" {
        a.status = result.status.clone();
        a.reason = result.status.clone();
        a.detail = "receiver audience did not authorize this receiver".into();
        st.pending = None;
    } else {
        a.deferred
            .retain(|d| d.kind != CONSTRAINT_RECEIVER_AUDIENCE);
        if a.deferred.is_empty() {
            a.status = "authorized_agent".into();
            a.reason = "authorized".into();
            a.detail = "proof, status, audience, and local authorization checks passed".into();
            st.allow_valid_until = allow_horizon(&a);
            st.pending = None;
        } else {
            a.status = "pending_external_checks".into();
            a.reason = "rate_reservation_required".into();
            a.detail = "audience passed; rate reservation remains".into();
            st.pending = Some(a.clone());
        }
    }
    st.evaluation_status = a.status.clone();
    st.evaluation_reason = a.reason.clone();
    Ok(a)
}

/// Final external constraint stage: reserve the sealed rate batch.
pub fn resolve_claim_proof_bundle_v2_after_rate(
    store: Option<&mut dyn V2RateReservationStore>,
    token: &V2EvaluationToken,
) -> V2Result<V2LocalAuthorizationAssessment> {
    let mut st = token.lock();
    let mut a = pending_of(&st, "rate")?;
    if a.status_assessment != "current" || a.local_policy_failure.is_some() {
        return plain("v2 claim does not have current status and pending rate checks");
    }
    let interrupt = |st: &mut TokenState| {
        st.evaluation_status = "authorization_unverified".into();
        st.evaluation_reason = "evaluation_interrupted".into();
        st.pending = None;
    };
    if a.bundle_hash != st.sealed.bundle_hash
        || a.required_scope != st.sealed.required_scope
        || st.rate_batch.is_empty()
    {
        interrupt(&mut st);
        return plain("pending rate assessment differs from its claimed proof");
    }
    if a.deferred.iter().any(|d| d.kind != "max_rate") {
        return plain("audience or unknown checks remain before rate reservation");
    }
    let batch = build_v2_rate_reservation_batch(&a.deferred);
    let batch = match batch {
        Ok(b) if b == st.rate_batch => b,
        _ => {
            interrupt(&mut st);
            return plain("pending rate checks differ from sealed signed batch");
        }
    };
    let result = match store {
        None => Err(V2RateError::Unavailable(
            "v2 rate reservation store is unavailable".into(),
        )),
        Some(s) if s.admits_rate_at_finalization() => {
            st.rate_at_finalization = true;
            a.rate_admission_deferred = true;
            Ok(())
        }
        Some(s) => s.reserve_v2_rate_batch(
            &st.claim_id,
            &st.owner_token.clone(),
            &a.bundle_hash,
            &batch,
        ),
    };
    match result {
        Ok(()) => {
            a.status = "authorized_agent".into();
            a.reason = "authorized".into();
            a.detail = if st.rate_at_finalization {
                "proof, status, and audience passed; rate admission is deferred to durable finalization".into()
            } else {
                "proof, status, audience, and rate checks passed".into()
            };
            st.allow_valid_until = allow_horizon(&a);
        }
        Err(V2RateError::LimitExceeded) => {
            a.status = "constraint_denied".into();
            a.reason = "constraint_denied".into();
            a.detail = "signed rate limit has no remaining capacity".into();
        }
        Err(V2RateError::Unavailable(_)) => {
            a.status = "constraint_unverifiable".into();
            a.reason = "constraint_unverifiable".into();
            a.detail = "rate reservation could not be verified".into();
            a.rate_store_unavailable = true;
        }
    }
    a.deferred.clear();
    st.pending = None;
    st.evaluation_status = a.status.clone();
    st.evaluation_reason = a.reason.clone();
    Ok(a)
}

// ---------------------------------------------------------------------------
// End-to-end live verifier

/// Resolves caller-authenticated trust for one verified chain.
pub trait V2TrustResolver {
    fn resolve(&mut self, chain: &[DelegationCertV2]) -> Result<V2TrustResolution, String>;
}

/// Returns one authenticated status result for a CertificateRef.
pub trait V2StatusProvider {
    fn status(&mut self, reference: &CertificateRefV2) -> RevocationStatusResultV2;
}

/// Returns caller-authenticated audience memberships.
pub trait V2AudienceProvider {
    fn memberships(
        &mut self,
        deferred: &[V2DeferredConstraint],
        receiver_id: &str,
    ) -> Result<Vec<V2AudienceMembership>, String>;
}

/// Verifier-owned dependencies of the live decision path. `claim_store` is
/// required; absent trust/status/audience providers are unavailable.
#[derive(Default)]
pub struct V2VerifyCallbacks<'a> {
    pub receiver_binding: Option<&'a mut dyn V2ReceiverBinding>,
    pub claim_store: Option<&'a mut dyn ClaimStoreV2>,
    pub trust: Option<&'a mut dyn V2TrustResolver>,
    pub status: Option<&'a mut dyn V2StatusProvider>,
    pub audience: Option<&'a mut dyn V2AudienceProvider>,
    pub rate: Option<&'a mut dyn V2RateReservationStore>,
}

/// One live verification. `context_policy: None` means the verifier
/// explicitly has no context policy; the result can then never be allow.
#[derive(Default)]
pub struct V2VerifyRequest<'a> {
    pub bundle: Vec<u8>,
    pub expected: Option<ExpectedChallengeV2>,
    pub context_policy: Option<V2ContextPolicy>,
    pub required_scope: String,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub now: i64,
    pub max_challenge_age_seconds: i64,
    pub future_skew_seconds: i64,
    pub context: VerifierContext<'a>,
    pub status_roles: V2StatusRoleBindings,
}

/// Where a verification stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2VerifyStage {
    /// Pre-claim failure: nothing consumed, no evaluation callback ran.
    Preflight,
    /// The claim already existed: no result disclosed, no evaluation.
    Replay,
    /// Claimed but no terminal commit; the claim awaits lease recovery.
    Evaluating,
    /// A terminal Protocol result was committed.
    Terminal,
}

impl V2VerifyStage {
    pub fn as_str(self) -> &'static str {
        match self {
            V2VerifyStage::Preflight => "preflight",
            V2VerifyStage::Replay => "replay",
            V2VerifyStage::Evaluating => "evaluating",
            V2VerifyStage::Terminal => "terminal",
        }
    }
}

/// Result of [`verify_proof_bundle_v2`].
#[derive(Debug, Clone)]
pub struct V2VerifyOutcome {
    pub stage: V2VerifyStage,
    pub error: Option<V2Error>,
    pub disposition: Option<V2ClaimDisposition>,
    pub claim: Option<V2ChallengeClaim>,
    pub decision: String,
    pub reason: String,
    pub identity_status: String,
    /// Receipt body fields (log position, previous hash, signature unset).
    pub receipt: Option<VerificationReceiptV2>,
    /// Exact sealed outbox body finalized with the claim.
    pub receipt_body: Vec<u8>,
    pub allow_valid_until: i64,
}

impl V2VerifyOutcome {
    fn stage(stage: V2VerifyStage) -> Self {
        V2VerifyOutcome {
            stage,
            error: None,
            disposition: None,
            claim: None,
            decision: String::new(),
            reason: String::new(),
            identity_status: String::new(),
            receipt: None,
            receipt_body: Vec::new(),
            allow_valid_until: 0,
        }
    }

    pub fn error_class(&self) -> Option<V2ErrorClass> {
        self.error.as_ref().map(|e| e.class)
    }
}

fn evaluating(claim: &V2ChallengeClaim, e: V2Error) -> Box<(V2VerifyOutcome, V2Error)> {
    let mut o = V2VerifyOutcome::stage(V2VerifyStage::Evaluating);
    o.claim = Some(claim.clone());
    o.disposition = Some(V2ClaimDisposition::Created);
    Box::new((o, e))
}

/// Run the complete live Protocol v2 decision path in SPEC-v2 §6 order:
/// strict decode and structure, required scope, key IDs/digest/linkage/
/// duplicates, every signature, expected challenge and freshness, the pure
/// receiver-binding hook, the atomic claim, and only then trust, local
/// authorization, status for every CertificateRef, audience, and rate,
/// followed by terminal finalization through the claim store.
///
/// A pre-claim failure returns `Ok` with stage `Preflight` and invokes no
/// claim, trust, status, audience, or rate callback. `Err` is returned only
/// when a claimed evaluation could not reach a terminal commit; the outcome
/// in the boxed error tuple then has stage `Evaluating`.
pub fn verify_proof_bundle_v2(
    req: &V2VerifyRequest<'_>,
    cb: V2VerifyCallbacks<'_>,
) -> Result<V2VerifyOutcome, Box<(V2VerifyOutcome, V2Error)>> {
    let preflight_failure = |e: V2Error| {
        let mut o = V2VerifyOutcome::stage(V2VerifyStage::Preflight);
        o.error = Some(e);
        Ok(o)
    };
    let V2VerifyCallbacks {
        receiver_binding,
        claim_store,
        trust,
        mut status,
        audience,
        rate,
    } = cb;
    let Some(store) = claim_store else {
        return preflight_failure(V2Error::new(
            V2ErrorClass::ConfigurationInvalid,
            "v2 verification requires a claim store",
        ));
    };
    let bundle = match decode_proof_bundle_v2(&req.bundle) {
        Ok(b) => b,
        Err(e) => return preflight_failure(e),
    };
    let pre = match preflight(
        &bundle,
        req.expected.as_ref(),
        req.context_policy.as_ref(),
        true,
        receiver_binding,
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
    let (claim, disposition, token) = match claim_proof_bundle_v2(
        store,
        &bundle,
        &pre,
        &req.verifier_namespace,
        req.replay_epoch,
        req.now,
    ) {
        Ok(r) => r,
        Err(e) => return preflight_failure(e.classify(V2ErrorClass::ClaimStoreUnavailable)),
    };
    let Some(token) = token else {
        let mut o = V2VerifyOutcome::stage(V2VerifyStage::Replay);
        o.disposition = Some(disposition);
        o.claim = Some(claim);
        return Ok(o);
    };
    let expected = req
        .expected
        .as_ref()
        .expect("preflight requires an expected challenge");

    let mut trust_assessment = "not_evaluated";
    let mut resolution = V2TrustResolution::default();
    if !bundle.delegations.is_empty() {
        if let Some(t) = trust {
            if let Ok(r) = t.resolve(&bundle.delegations) {
                resolution = r;
            }
        }
        let root = bundle.delegations.last().expect("non-empty");
        trust_assessment = if !resolution.available {
            "unavailable"
        } else if resolution.root_id != root.issuer_id
            || resolution
                .root_key
                .as_ref()
                .is_none_or(|k| !equal_keys(k, &root.issuer_pub_key))
        {
            "untrusted"
        } else {
            "trusted"
        };
    }
    let opts = V2LocalAuthorizationOptions {
        now: req.now,
        future_skew: req.future_skew_seconds,
        required_scope: req.required_scope.clone(),
        trusted_root_id: resolution.root_id.clone(),
        trusted_root_key: resolution.root_key.clone(),
        trust_configured: resolution.available,
        context: &req.context,
        context_policy: req.context_policy.as_ref(),
        expected_challenge: Some(expected),
        claim_token: Some(&token),
    };
    let mut assessment = evaluate_proof_bundle_v2_local_authorization(&bundle, &opts);

    if assessment.status == "pending_external_checks" {
        let results: Vec<RevocationStatusResultV2> = assessment
            .status_checks
            .iter()
            .map(|c| match status.as_deref_mut() {
                Some(p) => p.status(&CertificateRefV2 {
                    issuer_id: c.issuer_id.clone(),
                    cert_id: c.cert_id.clone(),
                }),
                None => RevocationStatusResultV2::unavailable(),
            })
            .collect();
        assessment =
            match resolve_claim_proof_bundle_v2_after_status(&token, &results, &req.status_roles) {
                Ok(a) => a,
                Err(e) => {
                    return Err(evaluating(
                        &claim,
                        e.classify(V2ErrorClass::ConfigurationInvalid),
                    ))
                }
            };
    }
    if assessment.status == "pending_external_checks"
        && assessment
            .deferred
            .iter()
            .any(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
    {
        let mut memberships = Vec::new();
        if let Some(p) = audience {
            let audience_deferred: Vec<V2DeferredConstraint> = assessment
                .deferred
                .iter()
                .filter(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
                .cloned()
                .collect();
            if let Ok(m) = p.memberships(&audience_deferred, &expected.expected_receiver_id) {
                memberships = m;
            }
        }
        assessment =
            match resolve_claim_proof_bundle_v2_after_audience(&token, &memberships, req.now) {
                Ok(a) => a,
                Err(e) => {
                    return Err(evaluating(
                        &claim,
                        e.classify(V2ErrorClass::ConfigurationInvalid),
                    ))
                }
            };
    }
    if assessment.status == "pending_external_checks" {
        assessment = match resolve_claim_proof_bundle_v2_after_rate(rate, &token) {
            Ok(a) => a,
            Err(e) => {
                return Err(evaluating(
                    &claim,
                    e.classify(V2ErrorClass::ConfigurationInvalid),
                ))
            }
        };
    }

    for attempt in 0..2 {
        let mut outcome =
            match terminal_outcome(&bundle, &assessment, trust_assessment, req, &claim) {
                Ok(o) => o,
                Err(e) => return Err(evaluating(&claim, e)),
            };
        let terminal = match canonical(&CJ::obj(vec![
            ("decision", CJ::s(&outcome.decision)),
            ("decision_reason", CJ::s(&outcome.reason)),
            ("identity_status", CJ::s(&outcome.identity_status)),
        ])) {
            Ok(t) => t,
            Err(e) => return Err(evaluating(&claim, e)),
        };
        match finalize_claim_proof_bundle_v2(store, &token, &terminal, &outcome.receipt_body) {
            Ok(_) => {
                outcome.disposition = Some(disposition);
                outcome.allow_valid_until = token.allow_valid_until();
                return Ok(outcome);
            }
            Err(V2FinalizeError::RateLimitExceeded) if attempt == 0 => {
                assessment.status = "constraint_denied".into();
                assessment.reason = "constraint_denied".into();
                assessment.detail = "signed rate limit has no remaining capacity".into();
            }
            Err(V2FinalizeError::RateLimitExceeded) => {
                return Err(evaluating(
                    &claim,
                    V2Error::plain("v2 signed rate limit has no remaining capacity"),
                ))
            }
            Err(V2FinalizeError::Failed(m)) => return Err(evaluating(&claim, V2Error::plain(m))),
        }
    }
    Err(evaluating(
        &claim,
        V2Error::plain("v2 terminal finalization did not complete"),
    ))
}

fn terminal_outcome(
    bundle: &ProofBundleV2,
    a: &V2LocalAuthorizationAssessment,
    trust: &str,
    req: &V2VerifyRequest<'_>,
    claim: &V2ChallengeClaim,
) -> V2Result<V2VerifyOutcome> {
    let Some(decision) = terminal_decision(&a.status, &a.reason) else {
        return plain(format!(
            "v2 evaluation did not reach a terminal result: {}/{}",
            a.status, a.reason
        ));
    };
    let mut trust = trust.to_string();
    let mut status_assessment = if a.status_assessment.is_empty() {
        "not_evaluated".to_string()
    } else {
        a.status_assessment.clone()
    };
    let mut context = if a.context_assessment.is_empty() {
        "not_evaluated".to_string()
    } else {
        a.context_assessment.clone()
    };
    match a.reason.as_str() {
        "not_delegated" => trust = "not_evaluated".into(),
        "evaluation_interrupted" => {
            if trust != "trusted" {
                trust = "not_evaluated".into();
                status_assessment = "not_evaluated".into();
            }
            if context != "bound" && context != "not_required" {
                context = "not_evaluated".into();
            }
            if context == "not_evaluated" {
                status_assessment = "not_evaluated".into();
            }
        }
        _ => {}
    }
    let policy_digest = if context != "not_evaluated" && context != "unbound" {
        a.context_policy_digest.clone()
    } else {
        None
    };
    let evidence = if status_assessment == "not_evaluated" {
        Vec::new()
    } else {
        a.status_evidence.clone()
    };
    let mut granted = Vec::new();
    if decision == "allow" {
        granted = a.effective_scope.clone();
        granted.sort();
        granted.dedup();
    }
    let receipt = VerificationReceiptV2 {
        version: 2,
        log_id: String::new(),
        sequence: 0,
        verifier_id: bundle.verifier_id.clone(),
        agent_id: bundle.agent_id.clone(),
        human_id: String::new(),
        bundle_hash: claim.bundle_hash.clone(),
        issuer_ids: claim.issuer_ids.clone(),
        decision: decision.into(),
        decision_reason: a.reason.clone(),
        identity_status: a.status.clone(),
        trust_assessment: trust,
        status_assessment,
        challenge_assessment: "current".into(),
        context_assessment: context,
        context_policy_digest: policy_digest,
        verified_at: req.now,
        required_scope: claim.required_scope.clone(),
        granted_scope: granted,
        status_evidence: evidence,
        previous_receipt_hash: Vec::new(),
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    let body = verification_receipt_v2_body(&receipt).map_err(|e| {
        e.context("v2 terminal receipt body is inconsistent with the evaluated result")
    })?;
    let mut o = V2VerifyOutcome::stage(V2VerifyStage::Terminal);
    o.claim = Some(claim.clone());
    o.decision = decision.into();
    o.reason = a.reason.clone();
    o.identity_status = a.status.clone();
    o.receipt = Some(receipt);
    o.receipt_body = body;
    Ok(o)
}
