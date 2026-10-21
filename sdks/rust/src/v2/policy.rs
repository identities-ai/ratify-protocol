//! Verifier context policy, receiver-audience evaluation, and signed
//! `max_rate` reservation batches. Mirrors Go `context_policy_v2.go`,
//! `audience_v2.go`, and `rate_reservation_v2.go`.

use std::collections::BTreeMap;

use super::crypto::{sha384, valid_prefixed_digest, valid_v2_id};
use super::errors::{plain, V2Result};
use super::json::{canonical, obj, parse_json, CJ};
use super::wire::{
    audience_params, encode_constraint_v2, validate_v2_constraint_fields, ProofBundleV2,
    CONSTRAINT_RECEIVER_AUDIENCE, MAX_SAFE,
};
use crate::types::MAX_IDENTIFIER_LENGTH_BYTES;

const VERIFY_SESSION_PROFILE: &str = "ratify.verify.session-context/v1";
const VERIFY_SESSION_FIELDS: &[&str] = &[
    "verifier_id",
    "workspace_id",
    "agent_id",
    "session_id",
    "invocation_id",
    "request_hash",
];

/// Validated verifier-owned context policy. Its digest is derived from the
/// canonical policy fields and never supplied by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ContextPolicy {
    profile: String,
    require_bound: bool,
    required_fields: Vec<String>,
    expected_session_context: Vec<u8>,
    digest: String,
}

impl V2ContextPolicy {
    /// Validate and fingerprint a policy. `expected_session_context` is
    /// per-invocation authenticated state excluded from the digest.
    pub fn new(
        profile: &str,
        require_bound: bool,
        required_fields: &[String],
        expected_session_context: Option<&[u8]>,
    ) -> V2Result<Self> {
        if profile.is_empty() {
            return plain("v2 context policy profile must be non-empty valid UTF-8");
        }
        for (i, f) in required_fields.iter().enumerate() {
            if f.is_empty() {
                return plain(format!(
                    "v2 context policy field {i} is empty or invalid UTF-8"
                ));
            }
            if required_fields[..i].contains(f) {
                return plain(format!("v2 context policy has duplicate field {f:?}"));
            }
        }
        let ctx = expected_session_context.unwrap_or(&[]);
        if require_bound && (required_fields.is_empty() || ctx.len() != 32) {
            return plain(
                "bound v2 context policy requires fields and a 32-byte authenticated context",
            );
        }
        if !require_bound && !ctx.is_empty() {
            return plain("unbound v2 context policy cannot carry an expected context");
        }
        if profile == VERIFY_SESSION_PROFILE
            && (!require_bound
                || required_fields
                    .iter()
                    .map(String::as_str)
                    .ne(VERIFY_SESSION_FIELDS.iter().copied()))
        {
            return plain(
                "Ratify Verify session-context policy must require the canonical field set",
            );
        }
        let encoded = canonical(&CJ::obj(vec![
            ("profile", CJ::s(profile)),
            ("require_bound", CJ::Bool(require_bound)),
            ("required_fields", CJ::strs(required_fields)),
            ("version", CJ::Int(1)),
        ]))?;
        Ok(V2ContextPolicy {
            profile: profile.to_string(),
            require_bound,
            required_fields: required_fields.to_vec(),
            expected_session_context: ctx.to_vec(),
            digest: format!("sha384:{}", hex::encode(sha384(&[&encoded]))),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn require_bound(&self) -> bool {
        self.require_bound
    }

    pub fn expected_session_context(&self) -> &[u8] {
        &self.expected_session_context
    }

    pub(crate) fn valid(&self) -> bool {
        valid_prefixed_digest(&self.digest)
    }
}

/// Ordered-stage context outcome; `status` is "passed" or a failure status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ContextPolicyAssessment {
    pub assessment: String,
    pub policy_digest: Option<String>,
    pub status: String,
    pub reason: String,
    pub detail: String,
}

fn failure(
    assessment: &str,
    status: &str,
    reason: &str,
    detail: &str,
    digest: Option<String>,
) -> V2ContextPolicyAssessment {
    V2ContextPolicyAssessment {
        assessment: assessment.into(),
        policy_digest: digest,
        status: status.into(),
        reason: reason.into(),
        detail: detail.into(),
    }
}

/// Apply a validated verifier context policy after preflight and claim.
pub fn evaluate_proof_bundle_v2_context_policy(
    bundle: &ProofBundleV2,
    policy: Option<&V2ContextPolicy>,
) -> V2ContextPolicyAssessment {
    let bound_present = bundle.session_context.is_some();
    let Some(policy) = policy.filter(|p| p.valid()) else {
        let assessment = if bound_present {
            "unverified"
        } else {
            "unbound"
        };
        return failure(
            assessment,
            "authorization_unverified",
            "action_context_unverified",
            "no caller-authenticated context policy is configured",
            None,
        );
    };
    let digest = Some(policy.digest.clone());
    if !policy.require_bound {
        return failure("not_required", "passed", "", "", digest);
    }
    match &bundle.session_context {
        None => failure(
            "unverified",
            "authorization_unverified",
            "action_context_unverified",
            "required session context is absent",
            digest,
        ),
        Some(ctx) if *ctx != policy.expected_session_context => failure(
            "mismatch",
            "constraint_denied",
            "constraint_denied",
            "proof session context does not match the verifier's authenticated context",
            digest,
        ),
        Some(_) => failure("bound", "passed", "", "", digest),
    }
}

// ---------------------------------------------------------------------------
// Deferred constraints, audience, and rate

/// A constraint requiring the ordered status, membership, or rate stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2DeferredConstraint {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub issuer_id: String,
    pub cert_id: String,
    pub kind: String,
    pub canonical_json: Vec<u8>,
}

/// Caller-authenticated, complete membership result for one constrained link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2AudienceMembership {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub receiver_id: String,
    pub trust_domain_ids: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub evidence_digest: String,
}

/// Post-claim, post-status audience outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2AudienceAssessment {
    pub status: String,
    pub evidence_digests: Vec<String>,
    pub fresh_until: i64,
}

fn canonical_constraint(item: &V2DeferredConstraint) -> V2Result<crate::types::Constraint> {
    let c = validate_v2_constraint_fields(&item.canonical_json)?;
    if encode_constraint_v2(&c)?.as_bytes() != item.canonical_json.as_slice() {
        return plain("v2 deferred constraint is not canonical");
    }
    Ok(c)
}

/// Evaluate every deferred audience link. A valid nonmatching membership
/// outranks unavailable membership on another link.
pub fn evaluate_receiver_audience_v2(
    deferred: &[V2DeferredConstraint],
    receiver_id: &str,
    memberships: &[V2AudienceMembership],
    now: i64,
    future_skew: i64,
) -> V2Result<V2AudienceAssessment> {
    if receiver_id.is_empty()
        || !(-MAX_SAFE..=MAX_SAFE).contains(&now)
        || !(0..=MAX_SAFE).contains(&future_skew)
    {
        return plain("v2 audience requires a sealed receiver and valid security time");
    }
    let mut links = Vec::new();
    let mut seen = Vec::new();
    let mut max_age = MAX_SAFE;
    let mut fresh_until = MAX_SAFE;
    for item in deferred
        .iter()
        .filter(|d| d.kind == CONSTRAINT_RECEIVER_AUDIENCE)
    {
        let c = canonical_constraint(item)
            .map_err(|e| e.context("v2 sealed audience constraint is invalid"))?;
        let pos = (item.delegation_index, item.constraint_index);
        if seen.contains(&pos) {
            return plain("v2 audience constraint has duplicate or invalid position");
        }
        seen.push(pos);
        if c.kind != CONSTRAINT_RECEIVER_AUDIENCE {
            return plain("v2 sealed audience constraint has wrong type");
        }
        let (exact, domains, age) = audience_params(&c);
        if !domains.is_empty() && age <= 0 {
            return plain("v2 audience membership age must be positive");
        }
        if !domains.is_empty() && age < max_age {
            max_age = age;
        }
        links.push((exact, domains, pos));
    }
    if links.is_empty() {
        return plain("v2 audience stage has no audience constraints");
    }
    let (mut denied, mut unavailable) = (false, false);
    let mut evidence = Vec::new();
    for (exact, domains, pos) in &links {
        if exact.iter().any(|e| e == receiver_id) {
            continue;
        }
        if domains.is_empty() {
            return plain("v2 exact-only audience mismatch passed preflight");
        }
        let matching: Vec<&V2AudienceMembership> = memberships
            .iter()
            .filter(|m| (m.delegation_index, m.constraint_index) == *pos)
            .collect();
        if matching.len() != 1 {
            unavailable = true;
            continue;
        }
        let m = matching[0];
        let safe = |v: i64| (-MAX_SAFE..=MAX_SAFE).contains(&v);
        if m.receiver_id != receiver_id
            || !valid_prefixed_digest(&m.evidence_digest)
            || !safe(m.issued_at)
            || !safe(m.expires_at)
            || m.issued_at >= m.expires_at
            || now >= m.expires_at
            || (m.issued_at > now && m.issued_at - now > future_skew)
            || (now > m.issued_at && now - m.issued_at > max_age)
        {
            unavailable = true;
            continue;
        }
        let mut malformed = false;
        let mut matched = false;
        for (i, d) in m.trust_domain_ids.iter().enumerate() {
            if d.is_empty() || m.trust_domain_ids[..i].contains(d) {
                malformed = true;
                break;
            }
            matched = matched || domains.contains(d);
        }
        if malformed {
            unavailable = true;
            continue;
        }
        evidence.push(m.evidence_digest.clone());
        if !matched {
            denied = true;
        } else {
            fresh_until = fresh_until.min(m.expires_at).min(m.issued_at + max_age);
        }
    }
    evidence.sort();
    evidence.dedup();
    let (status, fresh) = if denied {
        ("constraint_denied", 0)
    } else if unavailable {
        ("constraint_unverifiable", 0)
    } else {
        ("passed", fresh_until)
    };
    Ok(V2AudienceAssessment {
        status: status.into(),
        evidence_digests: evidence,
        fresh_until: fresh,
    })
}

/// One issuer-scoped rolling-window counter (smallest signed limit wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2RateReservation {
    pub issuer_id: String,
    pub cert_id: String,
    pub window_s: i64,
    pub limit: i64,
}

/// Deterministic atomic reservation batch from signed `max_rate` constraints.
pub fn build_v2_rate_reservation_batch(
    deferred: &[V2DeferredConstraint],
) -> V2Result<Vec<V2RateReservation>> {
    let mut counters: BTreeMap<(String, String, i64), i64> = BTreeMap::new();
    let mut seen = Vec::new();
    for item in deferred {
        let pos = (item.delegation_index, item.constraint_index);
        if seen.contains(&pos)
            || !valid_v2_id(&item.issuer_id)
            || item.cert_id.is_empty()
            || item.cert_id.len() > MAX_IDENTIFIER_LENGTH_BYTES
        {
            return plain("v2 rate constraint has invalid identity or duplicate position");
        }
        seen.push(pos);
        let c =
            canonical_constraint(item).map_err(|e| e.context("v2 rate constraint is invalid"))?;
        if c.kind != item.kind {
            return plain("v2 rate constraint has wrong type");
        }
        if item.kind != "max_rate" && item.kind != CONSTRAINT_RECEIVER_AUDIENCE {
            return plain("v2 rate batch contains an unexpected deferred constraint type");
        }
        if item.kind == CONSTRAINT_RECEIVER_AUDIENCE {
            continue;
        }
        if c.count <= 0 || c.count > MAX_SAFE || c.window_s <= 0 || c.window_s > MAX_SAFE {
            return plain("v2 rate constraint has noncanonical or invalid limits");
        }
        let key = (item.issuer_id.clone(), item.cert_id.clone(), c.window_s);
        let entry = counters.entry(key).or_insert(c.count);
        if c.count < *entry {
            *entry = c.count;
        }
    }
    Ok(counters
        .into_iter()
        .map(
            |((issuer_id, cert_id, window_s), limit)| V2RateReservation {
                issuer_id,
                cert_id,
                window_s,
                limit,
            },
        )
        .collect())
}

/// Seal every rate counter of a preflight-verified proof into the claim.
pub(crate) fn signed_rate_batch(bundle: &ProofBundleV2) -> V2Result<Vec<V2RateReservation>> {
    let mut deferred = Vec::new();
    for (i, cert) in bundle.delegations.iter().enumerate() {
        for (j, c) in cert.constraints.iter().enumerate() {
            if c.kind == "max_rate" {
                deferred.push(V2DeferredConstraint {
                    delegation_index: i,
                    constraint_index: j,
                    issuer_id: cert.issuer_id.clone(),
                    cert_id: cert.cert_id.clone(),
                    kind: c.kind.clone(),
                    canonical_json: encode_constraint_v2(c)?.into_bytes(),
                });
            }
        }
    }
    build_v2_rate_reservation_batch(&deferred)
}

/// Read `decision` and `decision_reason` strings from a strict JSON object.
pub(crate) fn decision_fields(value: &[u8]) -> Option<(String, String)> {
    let root = parse_json(value).ok()?;
    let o = obj(&root).ok()?;
    let d = super::json::as_str(o.get("decision")?).ok()?;
    let r = super::json::as_str(o.get("decision_reason")?).ok()?;
    Some((d, r))
}
