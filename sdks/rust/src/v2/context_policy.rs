//! Verifier-owned context policy (SPEC-v2 §6.7). Mirrors Go
//! `context_policy_v2.go`.

use super::crypto::{sha384, valid_prefixed_digest};
use super::errors::{err, V2ErrorClass, V2Result};
use super::json::{canonical, CJ};
use super::wire::ProofBundleV2;

const VERIFY_SESSION_CONTEXT_PROFILE_V2: &str = "ratify.verify.session-context/v1";

const VERIFY_SESSION_CONTEXT_FIELDS_V2: &[&str] = &[
    "verifier_id",
    "workspace_id",
    "agent_id",
    "session_id",
    "invocation_id",
    "request_hash",
];

/// Validated verifier-owned context policy. Its receipt digest is derived
/// from the canonical policy fields, never supplied by callers; only
/// [`V2ContextPolicy::new`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ContextPolicy {
    profile: String,
    require_bound: bool,
    required_fields: Vec<String>,
    expected_session_context: Vec<u8>,
    digest: String,
}

/// An intermediate ordered-stage result. A caller stops on any status other
/// than `"passed"` before constraints or status.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2ContextPolicyAssessment {
    pub assessment: String,
    pub policy_digest: Option<String>,
    pub status: String,
    pub reason: String,
    pub detail: String,
}

impl V2ContextPolicy {
    /// Go `NewV2ContextPolicy`: validate and fingerprint a policy.
    /// `expected_session_context` is per-invocation authenticated state and
    /// is excluded from the policy digest (empty = none). Every failure is
    /// `configuration_invalid` (Go returns an unclassified error).
    pub fn new(
        profile: &str,
        require_bound: bool,
        required_fields: &[String],
        expected_session_context: &[u8],
    ) -> V2Result<Self> {
        let invalid = |m: String| err(V2ErrorClass::ConfigurationInvalid, m);
        if profile.is_empty() {
            return invalid("v2 context policy profile must be non-empty valid UTF-8".into());
        }
        let mut fields: Vec<String> = Vec::with_capacity(required_fields.len());
        for (i, field) in required_fields.iter().enumerate() {
            if field.is_empty() {
                return invalid(format!("v2 context policy field {i} is empty or invalid UTF-8"));
            }
            if fields.contains(field) {
                return invalid(format!("v2 context policy has duplicate field {field:?}"));
            }
            fields.push(field.clone());
        }
        if require_bound && (fields.is_empty() || expected_session_context.len() != 32) {
            return invalid(
                "bound v2 context policy requires fields and a 32-byte authenticated context".into(),
            );
        }
        if !require_bound && !expected_session_context.is_empty() {
            return invalid("unbound v2 context policy cannot carry an expected context".into());
        }
        if profile == VERIFY_SESSION_CONTEXT_PROFILE_V2
            && (!require_bound
                || fields
                    .iter()
                    .map(String::as_str)
                    .ne(VERIFY_SESSION_CONTEXT_FIELDS_V2.iter().copied()))
        {
            return invalid(
                "Ratify Verify session-context policy must require the canonical field set".into(),
            );
        }
        let encoded = canonical(&CJ::obj(vec![
            ("profile", CJ::s(profile)),
            ("require_bound", CJ::Bool(require_bound)),
            ("required_fields", CJ::strs(&fields)),
            ("version", CJ::Int(1)),
        ]))
        .map_err(|e| e.classify(V2ErrorClass::ConfigurationInvalid))?;
        Ok(V2ContextPolicy {
            profile: profile.to_string(),
            require_bound,
            required_fields: fields,
            expected_session_context: expected_session_context.to_vec(),
            digest: format!("sha384:{}", hex::encode(sha384(&[&encoded]))),
        })
    }

    /// The policy digest recorded in receipts.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Whether the policy requires a bound session context.
    pub fn require_bound(&self) -> bool {
        self.require_bound
    }

    /// The policy profile identifier.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// A copy of the required field names.
    pub fn required_fields(&self) -> Vec<String> {
        self.required_fields.clone()
    }

    /// A copy of the per-invocation expected session context (empty = none).
    pub fn expected_session_context(&self) -> Vec<u8> {
        self.expected_session_context.clone()
    }

    pub(crate) fn expected_session_context_ref(&self) -> &[u8] {
        &self.expected_session_context
    }

    /// Go `policy.valid && policy.digest != "" && validPrefixedDigestV2`.
    /// A policy can only be built by [`V2ContextPolicy::new`], so this holds
    /// for every value; it is kept for parity with the Go checks.
    pub(crate) fn is_valid(&self) -> bool {
        !self.digest.is_empty() && valid_prefixed_digest(&self.digest)
    }
}

/// Go `EvaluateProofBundleV2ContextPolicy`: apply a validated verifier
/// context policy after preflight and claim.
pub fn evaluate_proof_bundle_v2_context_policy(
    bundle: Option<&ProofBundleV2>,
    policy: Option<&V2ContextPolicy>,
) -> V2ContextPolicyAssessment {
    let Some(bundle) = bundle else {
        return context_policy_failure(
            "unverified",
            "authorization_unverified",
            "action_context_unverified",
            "proof bundle is unavailable",
        );
    };
    let has_context = bundle.session_context.is_some();
    let Some(policy) = policy else {
        return context_policy_failure(
            if has_context { "unverified" } else { "unbound" },
            "authorization_unverified",
            "action_context_unverified",
            "no caller-authenticated context policy is configured",
        );
    };
    if !policy.is_valid() {
        return context_policy_failure(
            if has_context { "unverified" } else { "unbound" },
            "authorization_unverified",
            "action_context_unverified",
            "no valid caller-authenticated context policy is configured",
        );
    }
    let digest = Some(policy.digest.clone());
    if !policy.require_bound {
        return V2ContextPolicyAssessment {
            assessment: "not_required".into(),
            policy_digest: digest,
            status: "passed".into(),
            ..Default::default()
        };
    }
    let Some(session_context) = &bundle.session_context else {
        return V2ContextPolicyAssessment {
            assessment: "unverified".into(),
            policy_digest: digest,
            status: "authorization_unverified".into(),
            reason: "action_context_unverified".into(),
            detail: "required session context is absent".into(),
        };
    };
    if *session_context != policy.expected_session_context {
        return V2ContextPolicyAssessment {
            assessment: "mismatch".into(),
            policy_digest: digest,
            status: "constraint_denied".into(),
            reason: "constraint_denied".into(),
            detail: "proof session context does not match the verifier's authenticated context"
                .into(),
        };
    }
    V2ContextPolicyAssessment {
        assessment: "bound".into(),
        policy_digest: digest,
        status: "passed".into(),
        ..Default::default()
    }
}

fn context_policy_failure(
    assessment: &str,
    status: &str,
    reason: &str,
    detail: &str,
) -> V2ContextPolicyAssessment {
    V2ContextPolicyAssessment {
        assessment: assessment.into(),
        policy_digest: None,
        status: status.into(),
        reason: reason.into(),
        detail: detail.into(),
    }
}

/// Go `sameV2ContextPolicy`.
pub(crate) fn same_v2_context_policy(a: Option<&V2ContextPolicy>, b: Option<&V2ContextPolicy>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.is_valid() && b.is_valid() && a == b,
        _ => false,
    }
}
