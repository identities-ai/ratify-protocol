//! Receiver-audience evaluation (SPEC-v2 §5.2, §6.4). Mirrors Go
//! `audience_v2.go`.

use std::collections::BTreeSet;

use super::authorization::V2DeferredConstraint;
use super::constraints::{
    audience_params, validate_v2_constraint_fields, ConstraintV2, CONSTRAINT_RECEIVER_AUDIENCE,
};
use super::crypto::valid_prefixed_digest;
use super::errors::{plain, V2Result};
use super::json::parse_json;
use super::limits::{valid_v2_timestamp, V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS, V2_MAX_FUTURE_SKEW_SECONDS};
use super::wire::MAX_SAFE;

/// A caller-authenticated, complete membership result for one constrained
/// certificate link. Protocol does not authenticate this input: a live
/// adapter must verify the statement, signer, current version floor,
/// receiver ownership, source, and completeness before passing it here.
/// Absence of this result is unavailable, not proof of nonmembership. It must
/// never copy these fields from a proof.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2AudienceMembership {
    pub delegation_index: usize,
    pub constraint_index: usize,
    pub receiver_id: String,
    pub trust_domain_ids: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub evidence_digest: String,
}

/// A post-claim, post-status constraint outcome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct V2AudienceAssessment {
    pub status: String,
    pub evidence_digests: Vec<String>,
    pub fresh_until: i64,
}

struct AudienceLink {
    exact_receiver_ids: Vec<String>,
    trust_domain_ids: Vec<String>,
    delegation_index: usize,
    constraint_index: usize,
}

/// Go `EvaluateReceiverAudienceV2`: evaluate every deferred audience link. A
/// valid nonmatching membership takes precedence over unavailable membership
/// in another link. Only the verifier's authenticated expected receiver is
/// used. Errors are unclassified in Go; this public function reports them as
/// `configuration_invalid` (sealed inputs that are inconsistent).
pub fn evaluate_receiver_audience_v2(
    deferred: &[V2DeferredConstraint],
    receiver_id: &str,
    memberships: &[V2AudienceMembership],
    now: i64,
    future_skew: i64,
) -> V2Result<V2AudienceAssessment> {
    evaluate_receiver_audience_inner(deferred, receiver_id, memberships, now, future_skew)
        .map_err(|e| e.classify(super::errors::V2ErrorClass::ConfigurationInvalid))
}

pub(crate) fn evaluate_receiver_audience_inner(
    deferred: &[V2DeferredConstraint],
    receiver_id: &str,
    memberships: &[V2AudienceMembership],
    now: i64,
    future_skew: i64,
) -> V2Result<V2AudienceAssessment> {
    if receiver_id.is_empty()
        || !valid_v2_timestamp(now)
        || !(0..=V2_MAX_FUTURE_SKEW_SECONDS).contains(&future_skew)
    {
        return plain("v2 audience requires a sealed receiver and valid security time");
    }
    let mut links: Vec<AudienceLink> = Vec::new();
    let mut seen_links: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut max_age = MAX_SAFE;
    let mut fresh_until = MAX_SAFE;
    for item in deferred {
        if item.kind != CONSTRAINT_RECEIVER_AUDIENCE {
            continue;
        }
        let node = parse_json(&item.canonical_json)
            .map_err(|e| e.context("v2 sealed audience constraint is invalid"))?;
        validate_v2_constraint_fields(&node)
            .map_err(|e| e.context("v2 sealed audience constraint is invalid"))?;
        let link_key = (item.delegation_index, item.constraint_index);
        if seen_links.contains(&link_key) {
            return plain("v2 audience constraint has duplicate or invalid position");
        }
        seen_links.insert(link_key);
        let original = ConstraintV2::from_node(&node)
            .map_err(|e| e.context("v2 audience constraint cannot be decoded"))?;
        match original.canonical_json() {
            Ok(canonical) if canonical == item.canonical_json => {}
            _ => return plain("v2 audience constraint is not canonical"),
        }
        if original.kind != CONSTRAINT_RECEIVER_AUDIENCE {
            return plain("v2 sealed audience constraint has wrong type");
        }
        let (exact, domains, age) = audience_params(&original);
        if !domains.is_empty() && (age <= 0 || age > V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS) {
            return plain(format!(
                "v2 audience membership age must be 1..{V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS} seconds"
            ));
        }
        if !domains.is_empty() && age < max_age {
            max_age = age;
        }
        links.push(AudienceLink {
            exact_receiver_ids: exact,
            trust_domain_ids: domains,
            delegation_index: item.delegation_index,
            constraint_index: item.constraint_index,
        });
    }
    if links.is_empty() {
        return plain("v2 audience stage has no audience constraints");
    }
    let (mut denied, mut unavailable) = (false, false);
    let mut evidence: Vec<String> = Vec::new();
    for link in &links {
        if link.exact_receiver_ids.iter().any(|id| id == receiver_id) {
            continue;
        }
        if link.trust_domain_ids.is_empty() {
            return plain("v2 exact-only audience mismatch passed preflight");
        }
        let mut membership: Option<&V2AudienceMembership> = None;
        for candidate in memberships {
            if candidate.delegation_index == link.delegation_index
                && candidate.constraint_index == link.constraint_index
            {
                if membership.is_some() {
                    unavailable = true;
                    membership = None;
                    break;
                }
                membership = Some(candidate);
            }
        }
        let Some(m) = membership else {
            unavailable = true;
            continue;
        };
        if m.receiver_id != receiver_id
            || !valid_prefixed_digest(&m.evidence_digest)
            || !valid_v2_timestamp(m.issued_at)
            || !valid_v2_timestamp(m.expires_at)
            || m.issued_at >= m.expires_at
            || now >= m.expires_at
            || (m.issued_at > now && m.issued_at - now > future_skew)
            // Exclusive age deadline: current only while now < issued_at + max_age.
            || (now >= m.issued_at && now - m.issued_at >= max_age)
        {
            unavailable = true;
            continue;
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut matched = false;
        let mut malformed = false;
        for domain_id in &m.trust_domain_ids {
            if domain_id.is_empty() || seen.contains(domain_id.as_str()) {
                malformed = true;
                break;
            }
            seen.insert(domain_id);
            matched = matched || link.trust_domain_ids.iter().any(|d| d == domain_id);
        }
        if malformed {
            unavailable = true;
            continue;
        }
        evidence.push(m.evidence_digest.clone());
        if !matched {
            denied = true;
        } else {
            fresh_until = fresh_until.min(m.expires_at);
            fresh_until = fresh_until.min(m.issued_at + max_age);
        }
    }
    evidence.sort();
    evidence.dedup();
    Ok(if denied {
        V2AudienceAssessment {
            status: "constraint_denied".into(),
            evidence_digests: evidence,
            fresh_until: 0,
        }
    } else if unavailable {
        V2AudienceAssessment {
            status: "constraint_unverifiable".into(),
            evidence_digests: evidence,
            fresh_until: 0,
        }
    } else {
        V2AudienceAssessment {
            status: "passed".into(),
            evidence_digests: evidence,
            fresh_until,
        }
    })
}
