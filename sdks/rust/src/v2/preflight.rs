//! Pre-claim checks (SPEC-v2 §6.2). Mirrors Go `verify_v2_preflight.go`.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

use super::constraints::CONSTRAINT_RECEIVER_AUDIENCE;
use super::context_policy::{same_v2_context_policy, V2ContextPolicy};
use super::crypto::{equal_keys, key_id_v2, valid_v2_id};
use super::errors::{err, Classify, V2ErrorClass, V2Result};
use super::evaluator::{
    snapshot_constraint_evaluators_v2, ConstraintEvaluatorRefV2, ConstraintEvaluatorRegistryV2,
    RegisteredEvaluator,
};
use super::limits::{v2_challenge_time_current, valid_v2_timestamp, validate_v2_freshness_configuration};
use super::verify::V2ReceiverBindingHook;
use super::wire::{
    bundle_hash_v2, validate_required_scope_v2, verify_proof_bundle_v2_signatures, ProofBundleV2,
    MAX_SAFE,
};
use crate::types::{HybridPublicKey, ParamsValue};

/// Verifier-authenticated issuance state. Values must come from the local
/// issuer or an independently authenticated issuer.
/// `expected_session_context: None` means no expected context (Go nil).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedChallengeV2 {
    pub value: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<HybridPublicKey>,
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
    pub context_policy: Option<V2ContextPolicy>,
}

/// Seals the authenticated issuance, policy, and proof identity for one
/// request. Its state is never exposed or mutated after construction; only
/// [`preflight_proof_bundle_v2`] (or the live verifier) builds one.
#[derive(Debug, Clone)]
pub struct V2PreflightResult {
    pub(crate) state: Arc<ExpectedChallengeStateV2>,
}

/// Go `expectedChallengeStateV2`.
#[derive(Clone)]
pub(crate) struct ExpectedChallengeStateV2 {
    pub value: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<HybridPublicKey>,
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
    pub required_scope: String,
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub future_skew: i64,
    pub max_age: i64,
    pub context_policy_digest: String,
    pub context_policy: Option<V2ContextPolicy>,
    /// An explicit generic-Protocol evaluation with no configured context
    /// policy (only the internal end-to-end verifier sets it).
    pub no_context_policy: bool,
    pub evaluator_refs: Vec<ConstraintEvaluatorRefV2>,
    pub evaluators: BTreeMap<String, RegisteredEvaluator>,
    pub evaluator_timeout: Duration,
}

impl std::fmt::Debug for ExpectedChallengeStateV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpectedChallengeStateV2")
            .field("bundle_hash", &self.bundle_hash)
            .field("required_scope", &self.required_scope)
            .finish_non_exhaustive()
    }
}

fn snapshot_expected_challenge_v2(
    expected: &ExpectedChallengeV2,
    policy: Option<&V2ContextPolicy>,
    required_scope: &str,
    bundle_hash: String,
    issuer_ids: Vec<String>,
    max_age: i64,
    future_skew: i64,
) -> ExpectedChallengeStateV2 {
    ExpectedChallengeStateV2 {
        value: expected.value.clone(),
        issued_at: expected.issued_at,
        expires_at: expected.expires_at,
        verifier_namespace: expected.verifier_namespace.clone(),
        replay_epoch: expected.replay_epoch,
        verifier_id: expected.verifier_id.clone(),
        expected_agent_id: expected.expected_agent_id.clone(),
        expected_agent_public_key: expected.expected_agent_public_key.clone(),
        expected_receiver_id: expected.expected_receiver_id.clone(),
        expected_session_context: expected.expected_session_context.clone(),
        required_scope: required_scope.to_string(),
        bundle_hash,
        issuer_ids,
        future_skew,
        max_age,
        context_policy_digest: policy.map(|p| p.digest().to_string()).unwrap_or_default(),
        context_policy: policy.cloned(),
        no_context_policy: policy.is_none(),
        evaluator_refs: Vec::new(),
        evaluators: BTreeMap::new(),
        evaluator_timeout: Duration::ZERO,
    }
}

fn bytes_equal(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
    a.as_deref().unwrap_or(&[]) == b.as_deref().unwrap_or(&[])
}

/// Go `matchesExpectedChallengeV2`.
pub(crate) fn matches_expected_challenge_v2(
    expected: &ExpectedChallengeV2,
    state: &ExpectedChallengeStateV2,
) -> bool {
    if expected.value != state.value
        || expected.issued_at != state.issued_at
        || expected.expires_at != state.expires_at
        || expected.verifier_namespace != state.verifier_namespace
        || expected.replay_epoch != state.replay_epoch
        || expected.verifier_id != state.verifier_id
        || expected.expected_agent_id != state.expected_agent_id
        || expected.expected_receiver_id != state.expected_receiver_id
        || !bytes_equal(&expected.expected_session_context, &state.expected_session_context)
        || (expected.context_policy.is_some()
            && !same_v2_context_policy(expected.context_policy.as_ref(), state.context_policy.as_ref()))
    {
        return false;
    }
    match (&expected.expected_agent_public_key, &state.expected_agent_public_key) {
        (None, None) => true,
        (Some(a), Some(b)) => equal_keys(a, b),
        _ => false,
    }
}

/// Go `PreflightProofBundleV2`: bind the challenge's expected context to the
/// same immutable policy used by terminal evaluation. It seals no extension
/// evaluator profile, so a staged evaluation that starts here treats every
/// extension constraint type as `constraint_unknown`; only
/// [`super::verify_proof_bundle_v2`] accepts a registry.
#[allow(clippy::too_many_arguments)]
pub fn preflight_proof_bundle_v2(
    bundle: &ProofBundleV2,
    expected: Option<&ExpectedChallengeV2>,
    policy: Option<&V2ContextPolicy>,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    configured_verifier_id: &str,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<V2PreflightResult> {
    preflight_proof_bundle_v2_inner(
        bundle,
        expected,
        policy,
        false,
        None,
        None,
        required_scope,
        configured_namespace,
        configured_replay_epoch,
        configured_verifier_id,
        now,
        max_age_seconds,
        future_skew_seconds,
    )
}

/// Go `preflightProofBundleV2`: the ordered pre-claim pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) fn preflight_proof_bundle_v2_inner(
    bundle: &ProofBundleV2,
    expected: Option<&ExpectedChallengeV2>,
    policy: Option<&V2ContextPolicy>,
    allow_no_policy: bool,
    hook: Option<&V2ReceiverBindingHook>,
    evaluators: Option<&ConstraintEvaluatorRegistryV2>,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    configured_verifier_id: &str,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<V2PreflightResult> {
    let Some(expected) = expected else {
        return err(
            V2ErrorClass::ExpectedChallengeUnavailable,
            "v2 expected challenge is unavailable",
        );
    };
    if (policy.is_none() && !allow_no_policy) || policy.is_some_and(|p| !p.is_valid()) {
        return err(V2ErrorClass::ConfigurationInvalid, "v2 context policy is missing or invalid");
    }
    if policy.is_none() && expected.context_policy.is_some() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 challenge context policy does not match the issued policy",
        );
    }
    if let Some(policy) = policy {
        if expected.context_policy.is_some()
            && !same_v2_context_policy(expected.context_policy.as_ref(), Some(policy))
        {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "v2 challenge context policy does not match the issued policy",
            );
        }
        if policy.require_bound() {
            // SPEC-v2 §6.7: an ExpectedChallenge without an expected session
            // context is accepted; the policy's own expected context is then
            // compared after claim and a mismatch is a post-claim deny.
            if let Some(ctx) = &expected.expected_session_context {
                if ctx.as_slice() != policy.expected_session_context_ref() {
                    return err(
                        V2ErrorClass::ConfigurationInvalid,
                        "v2 challenge context does not match the configured context policy",
                    );
                }
            }
        } else if expected.expected_session_context.is_some() {
            return err(
                V2ErrorClass::ConfigurationInvalid,
                "unbound v2 context policy cannot have an expected session context",
            );
        }
    }
    let mut checked = expected.clone();
    checked.context_policy = policy.cloned();
    validate_proof_bundle_v2_preflight(
        bundle,
        &checked,
        required_scope,
        configured_namespace,
        configured_replay_epoch,
        configured_verifier_id,
        now,
        max_age_seconds,
        future_skew_seconds,
    )?;
    if let Some(hook) = hook {
        let answer = catch_unwind(AssertUnwindSafe(|| hook(bundle, &checked)));
        let failure = match answer {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(_) => Some("receiver-binding hook panicked".to_string()),
        };
        if let Some(message) = failure {
            return err(
                V2ErrorClass::ReceiverBindingRejected,
                format!("v2 receiver-binding hook rejected the presentation: {message}"),
            );
        }
    }
    let bundle_hash = bundle_hash_v2(bundle)
        .map_err(|e| e.context("v2 validated bundle hash"))
        .classify(V2ErrorClass::Malformed)?;
    let issuer_ids: Vec<String> = bundle
        .delegations
        .iter()
        .map(|c| c.issuer_id.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let mut state = snapshot_expected_challenge_v2(
        expected,
        policy,
        required_scope,
        bundle_hash,
        issuer_ids,
        max_age_seconds,
        future_skew_seconds,
    );
    let (sealed, refs, timeout) = snapshot_constraint_evaluators_v2(evaluators, bundle);
    state.evaluators = sealed;
    state.evaluator_refs = refs;
    state.evaluator_timeout = timeout;
    Ok(V2PreflightResult {
        state: Arc::new(state),
    })
}

/// Go `ValidateProofBundleV2Preflight`: the pure pre-claim checks required
/// before a caller may atomically consume challenge/stream state. It
/// performs no trust, status, policy, billing, or other external call and
/// issues no authorization decision.
#[allow(clippy::too_many_arguments)]
pub fn validate_proof_bundle_v2_preflight(
    bundle: &ProofBundleV2,
    expected: &ExpectedChallengeV2,
    required_scope: &str,
    configured_namespace: &str,
    configured_replay_epoch: i64,
    configured_verifier_id: &str,
    now: i64,
    max_age_seconds: i64,
    future_skew_seconds: i64,
) -> V2Result<()> {
    use V2ErrorClass::*;
    validate_v2_verifier_identity_configuration(configured_namespace, configured_replay_epoch, configured_verifier_id)?;
    if expected.expected_session_context.as_ref().is_some_and(|c| c.len() != 32) {
        return err(
            ConfigurationInvalid,
            "v2 expected session context must be absent or exactly 32 bytes",
        );
    }
    if let Some(policy) = &expected.context_policy {
        if !policy.is_valid() {
            return err(ConfigurationInvalid, "v2 expected context policy is invalid");
        }
        if policy.require_bound() {
            if let Some(ctx) = &expected.expected_session_context {
                if ctx.as_slice() != policy.expected_session_context_ref() {
                    return err(ConfigurationInvalid, "v2 expected context does not match its policy");
                }
            }
        }
        if !policy.require_bound() && expected.expected_session_context.is_some() {
            return err(
                ConfigurationInvalid,
                "unbound v2 context policy cannot have an expected session context",
            );
        }
    }
    if let Err(e) = validate_required_scope_v2(required_scope) {
        return err(InvalidRequiredScope, format!("v2 request scope: {}", e.message));
    }
    verify_proof_bundle_v2_signatures(bundle).map_err(|e| e.context("v2 cryptographic preflight"))?;
    if expected.verifier_namespace != configured_namespace {
        return err(NamespaceMismatch, "v2 challenge verifier namespace mismatch");
    }
    if !(0..=MAX_SAFE).contains(&configured_replay_epoch)
        || !(0..=MAX_SAFE).contains(&expected.replay_epoch)
        || expected.replay_epoch != configured_replay_epoch
    {
        return err(StaleReplayEpoch, "v2 challenge replay epoch is stale");
    }
    if expected.verifier_id != configured_verifier_id || bundle.verifier_id != configured_verifier_id {
        return err(
            VerifierIdMismatch,
            "v2 challenge or proof verifier ID differs from the configured verifier key ID",
        );
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
    if !valid_v2_timestamp(expected.issued_at)
        || !valid_v2_timestamp(expected.expires_at)
        || expected.expires_at <= expected.issued_at
    {
        return err(ConfigurationInvalid, "v2 authenticated challenge time bounds are invalid");
    }
    validate_v2_freshness_configuration(now, max_age_seconds, future_skew_seconds)?;
    if !v2_challenge_time_current(
        now,
        expected.issued_at,
        expected.expires_at,
        max_age_seconds,
        future_skew_seconds,
    ) {
        return err(
            ChallengeNotFresh,
            "v2 challenge is not fresh (future-dated, expired, or beyond maximum age)",
        );
    }
    if expected.expected_agent_id.is_empty() != expected.expected_agent_public_key.is_none() {
        return err(
            ConfigurationInvalid,
            "v2 expected agent ID and public key must be configured together",
        );
    }
    if let Some(key) = &expected.expected_agent_public_key {
        let id = match key_id_v2(key) {
            Ok(id) => id,
            Err(e) => {
                return err(ConfigurationInvalid, format!("v2 expected agent key: {}", e.message))
            }
        };
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
        if bundle.session_context.as_ref() != Some(ctx) {
            return err(
                SessionContextMismatch,
                "v2 presentation does not match expected session context",
            );
        }
    }
    check_exact_receiver_audience_v2(bundle, &expected.expected_receiver_id)
}

/// Go `validateV2VerifierIdentityConfiguration`: the caller-authenticated
/// verifier identity of SPEC-v2 §6.1, checked at §6.2 step 2. A non-empty
/// namespace, a replay epoch of 0 through 2^53-1, and the verifier key ID as
/// a canonical v2 key ID; any violation is `configuration_invalid`.
pub(crate) fn validate_v2_verifier_identity_configuration(
    namespace: &str,
    replay_epoch: i64,
    verifier_id: &str,
) -> V2Result<()> {
    use V2ErrorClass::ConfigurationInvalid;
    if namespace.is_empty() {
        return err(ConfigurationInvalid, "v2 configured verifier namespace must not be empty");
    }
    if !(0..=MAX_SAFE).contains(&replay_epoch) {
        return err(
            ConfigurationInvalid,
            format!("v2 configured replay epoch must be 0..{MAX_SAFE}"),
        );
    }
    if !valid_v2_id(verifier_id) {
        return err(
            ConfigurationInvalid,
            "v2 configured verifier key ID must be a canonical v2 key ID",
        );
    }
    Ok(())
}

fn check_exact_receiver_audience_v2(bundle: &ProofBundleV2, receiver_id: &str) -> V2Result<()> {
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for constraint in &cert.constraints {
            if constraint.kind != CONSTRAINT_RECEIVER_AUDIENCE {
                continue;
            }
            if receiver_id.is_empty() {
                return err(
                    V2ErrorClass::ReceiverAudienceRequired,
                    "v2 receiver audience requires an authenticated expected receiver ID",
                );
            }
            let list = |key: &str| -> Vec<&ParamsValue> {
                match constraint.params.as_ref().and_then(|p| p.get(key)) {
                    Some(ParamsValue::Array(items)) => items.iter().collect(),
                    _ => Vec::new(),
                }
            };
            let matches = list("exact_receiver_ids")
                .iter()
                .any(|v| matches!(v, ParamsValue::Str(id) if id == receiver_id));
            // A domain audience is evaluated only after claim from
            // authenticated trust configuration. An exact mismatch cannot
            // pre-reject that case.
            if list("trust_domain_ids").is_empty() && !matches {
                return err(
                    V2ErrorClass::ReceiverAudienceMismatch,
                    format!("v2 receiver does not match exact-only audience at delegation {i}"),
                );
            }
        }
    }
    Ok(())
}
