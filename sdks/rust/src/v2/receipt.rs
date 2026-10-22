//! Verification receipts (object code 0x0008), the prepared receipt body,
//! receipt-log verification, and receipt/bundle binding. Mirrors Go
//! `verification_receipt_v2.go` and `verification_receipt_body_v2.go`.

use std::collections::BTreeMap;

use super::context::V2Context;
use super::crypto::{key_id_v2, valid_prefixed_digest, valid_v2_id, verify_v2_statement, V2ObjectType};
use super::errors::{err, plain, Classify, V2ErrorClass, V2Result, V2SignError, V2SignResult};
use super::evaluator::{evaluator_refs_cj, valid_constraint_evaluator_refs_v2, ConstraintEvaluatorRefV2};
use super::limits::{
    check_v2_wire_size, valid_v2_timestamp, MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2,
    MAX_VERIFICATION_RECEIPT_BYTES_V2,
};
use super::signer::{sign_v2_statement_with_signer, signer_public_key_v2, LocalSignerV2, SignerV2};
use super::json::{canonical, obj, parse_wire, Obj, CJ};
use super::rotation::{statement_body_digest_v2, WitnessEntryV2Result};
use super::wire::{
    bundle_hash_v2, encode_proof_bundle_v2, is_wildcard_scope, placeholder_signature,
    required_scope_v2, validate_scopes_v2, ProofBundleV2, MAX_SAFE,
};
use super::witness::{log_position, validate_head};
use crate::types::{HybridPrivateKey, HybridPublicKey, HybridSignature};

/// Authenticated status evidence reference (issuer-scoped).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusEvidenceEntryV2 {
    pub issuer_id: String,
    pub status_key_id: String,
    pub sequence: i64,
    pub object_type: u16,
    pub digest: String,
}

/// Verifier-signed terminal assertion.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationReceiptV2 {
    pub version: i64,
    pub log_id: String,
    pub sequence: i64,
    pub verifier_id: String,
    /// Empty means absent (omitted on the wire).
    pub agent_id: String,
    /// Empty means absent (omitted on the wire).
    pub human_id: String,
    pub bundle_hash: String,
    pub issuer_ids: Vec<String>,
    pub decision: String,
    pub decision_reason: String,
    pub identity_status: String,
    pub trust_assessment: String,
    pub status_assessment: String,
    pub challenge_assessment: String,
    /// Present (non-empty) exactly when the claim sealed at least one
    /// extension evaluator profile (SPEC-v2 §5.2, §5.8).
    pub constraint_evaluators: Vec<ConstraintEvaluatorRefV2>,
    pub context_assessment: String,
    pub context_policy_digest: Option<String>,
    pub verified_at: i64,
    pub required_scope: String,
    pub granted_scope: Vec<String>,
    pub status_evidence: Vec<StatusEvidenceEntryV2>,
    pub previous_receipt_hash: Vec<u8>,
    pub signature: HybridSignature,
}

/// Caller-authenticated receipt-log state before a candidate receipt.
#[derive(Debug, Clone, Default)]
pub struct ReceiptV2Head {
    pub log_id: String,
    pub verifier_id: String,
    pub sequence: i64,
    pub head_hash: Vec<u8>,
    pub accepted_digests: BTreeMap<i64, Vec<u8>>,
    pub frozen: bool,
}

const FIELDS: &[&str] = &[
    "version",
    "log_id",
    "sequence",
    "verifier_id",
    "bundle_hash",
    "issuer_ids",
    "decision",
    "decision_reason",
    "identity_status",
    "trust_assessment",
    "status_assessment",
    "challenge_assessment",
    "context_assessment",
    "context_policy_digest",
    "verified_at",
    "required_scope",
    "granted_scope",
    "status_evidence_digests",
    "previous_receipt_hash",
    "signature",
];
const BODY_REQUIRED: &[&str] = &[
    "version",
    "verifier_id",
    "bundle_hash",
    "issuer_ids",
    "decision",
    "decision_reason",
    "identity_status",
    "trust_assessment",
    "status_assessment",
    "challenge_assessment",
    "context_assessment",
    "context_policy_digest",
    "verified_at",
    "required_scope",
    "granted_scope",
    "status_evidence_digests",
];

pub(crate) fn evidence_cj(values: &[StatusEvidenceEntryV2]) -> CJ {
    CJ::Arr(
        values
            .iter()
            .map(|e| {
                CJ::obj(vec![
                    ("digest", CJ::s(&e.digest)),
                    ("issuer_id", CJ::s(&e.issuer_id)),
                    ("object_type_code", CJ::Int(e.object_type as i64)),
                    ("sequence", CJ::Int(e.sequence)),
                    ("status_key_id", CJ::s(&e.status_key_id)),
                ])
            })
            .collect(),
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Body,
    Signable,
    Wire,
}

fn receipt_cj(r: &VerificationReceiptV2, shape: Shape) -> CJ {
    let mut f = vec![
        ("bundle_hash", CJ::s(&r.bundle_hash)),
        ("challenge_assessment", CJ::s(&r.challenge_assessment)),
        ("context_assessment", CJ::s(&r.context_assessment)),
        (
            "context_policy_digest",
            r.context_policy_digest.as_deref().map_or(CJ::Null, CJ::s),
        ),
        ("decision", CJ::s(&r.decision)),
        ("decision_reason", CJ::s(&r.decision_reason)),
        ("granted_scope", CJ::strs(&r.granted_scope)),
        ("identity_status", CJ::s(&r.identity_status)),
        ("issuer_ids", CJ::strs(&r.issuer_ids)),
        ("required_scope", CJ::s(&r.required_scope)),
        ("status_assessment", CJ::s(&r.status_assessment)),
        ("status_evidence_digests", evidence_cj(&r.status_evidence)),
        ("trust_assessment", CJ::s(&r.trust_assessment)),
        ("verified_at", CJ::Int(r.verified_at)),
        ("verifier_id", CJ::s(&r.verifier_id)),
        ("version", CJ::Int(r.version)),
    ];
    if !r.agent_id.is_empty() {
        f.push(("agent_id", CJ::s(&r.agent_id)));
    }
    if !r.human_id.is_empty() {
        f.push(("human_id", CJ::s(&r.human_id)));
    }
    if !r.constraint_evaluators.is_empty() {
        f.push(("constraint_evaluators", evaluator_refs_cj(&r.constraint_evaluators)));
    }
    if shape != Shape::Body {
        f.push(("log_id", CJ::s(&r.log_id)));
        f.push((
            "previous_receipt_hash",
            CJ::Bytes(r.previous_receipt_hash.clone()),
        ));
        f.push(("sequence", CJ::Int(r.sequence)));
    }
    if shape == Shape::Wire {
        f.push(("signature", CJ::sig(&r.signature)));
    }
    CJ::obj(f)
}

fn sorted_unique_ids(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(i, v)| valid_v2_id(v) && (i == 0 || values[i - 1] < *v))
}

fn sorted_granted(values: &[String]) -> bool {
    if values.is_empty() {
        return true;
    }
    if validate_scopes_v2(values).is_err() {
        return false;
    }
    values
        .iter()
        .enumerate()
        .all(|(i, v)| !is_wildcard_scope(v) && (i == 0 || values[i - 1] < *v))
}

fn sorted_evidence(
    values: &[StatusEvidenceEntryV2],
    issuer_ids: &[String],
    verifier_id: &str,
    agent_id: &str,
) -> bool {
    let mut key_issuers: BTreeMap<&str, &str> = BTreeMap::new();
    for (i, v) in values.iter().enumerate() {
        if let Some(prior) = key_issuers.get(v.status_key_id.as_str()) {
            if *prior != v.issuer_id {
                return false;
            }
        }
        key_issuers.insert(&v.status_key_id, &v.issuer_id);
        if !issuer_ids.contains(&v.issuer_id)
            || !valid_v2_id(&v.status_key_id)
            || issuer_ids.contains(&v.status_key_id)
            || v.status_key_id == verifier_id
            || (!agent_id.is_empty() && v.status_key_id == agent_id)
            || v.sequence <= 0
            || v.sequence > MAX_SAFE
            || (v.object_type != 3 && v.object_type != 5)
            || !valid_prefixed_digest(&v.digest)
        {
            return false;
        }
        if i > 0 && compare_evidence(&values[i - 1], v) != std::cmp::Ordering::Less {
            return false;
        }
    }
    true
}

pub(crate) fn compare_evidence(
    a: &StatusEvidenceEntryV2,
    b: &StatusEvidenceEntryV2,
) -> std::cmp::Ordering {
    (
        &a.issuer_id,
        &a.status_key_id,
        a.sequence,
        a.object_type,
        &a.digest,
    )
        .cmp(&(
            &b.issuer_id,
            &b.status_key_id,
            b.sequence,
            b.object_type,
            &b.digest,
        ))
}

pub(crate) fn has_accepted_status_history_per_issuer(
    evidence: &[StatusEvidenceEntryV2],
    issuer_ids: &[String],
) -> bool {
    for issuer in issuer_ids {
        let mut base = 0i64;
        let mut key = "";
        let mut pushes: Vec<i64> = Vec::new();
        for e in evidence.iter().filter(|e| &e.issuer_id == issuer) {
            if key.is_empty() {
                key = &e.status_key_id;
            } else if key != e.status_key_id {
                return false;
            }
            if e.object_type == 3 {
                if base != 0 {
                    return false;
                }
                base = e.sequence;
            } else {
                if pushes.contains(&e.sequence) {
                    return false;
                }
                pushes.push(e.sequence);
            }
        }
        if base == 0 || pushes.iter().any(|s| *s <= base) {
            return false;
        }
        for s in base + 1..=base + pushes.len() as i64 {
            if !pushes.contains(&s) {
                return false;
            }
        }
    }
    !issuer_ids.is_empty()
}

pub(crate) fn validate_receipt(r: &VerificationReceiptV2, signature: bool) -> V2Result<()> {
    if r.version != 2
        || r.log_id.len() != 32
        || !super::crypto::lower_hex(&r.log_id)
        || r.sequence <= 0
        || r.sequence > MAX_SAFE
        || !valid_v2_timestamp(r.verified_at)
    {
        return plain("wire v2: receipt version, log ID, sequence, or verified_at is invalid");
    }
    if !valid_v2_id(&r.verifier_id) || (!r.agent_id.is_empty() && !valid_v2_id(&r.agent_id)) {
        return plain("wire v2: receipt verifier_id and optional agent_id must be v2 key IDs");
    }
    if !valid_prefixed_digest(&r.bundle_hash) || r.previous_receipt_hash.len() != 48 {
        return plain("wire v2: receipt bundle hash or previous receipt hash is invalid");
    }
    if !sorted_unique_ids(&r.issuer_ids) {
        return plain("wire v2: receipt arrays must be present and canonical");
    }
    let reason = r.decision_reason.as_str();
    if reason != "not_delegated" && reason != "evaluation_interrupted" && r.issuer_ids.is_empty() {
        return plain(
            "wire v2: a receipt for a delegated decision must identify its certificate issuers",
        );
    }
    if reason == "evaluation_interrupted"
        && r.issuer_ids.is_empty()
        && (r.trust_assessment != "not_evaluated"
            || r.status_assessment != "not_evaluated"
            || r.context_assessment != "not_evaluated"
            || !r.status_evidence.is_empty())
    {
        return plain("wire v2: interrupted empty-chain receipt cannot claim completed trust, status, or context checks");
    }
    required_scope_v2(&r.required_scope).map_err(|e| e.context("wire v2"))?;
    let zero = r.previous_receipt_hash.iter().all(|b| *b == 0);
    if (r.sequence == 1 && !zero) || (r.sequence > 1 && zero) {
        return plain("wire v2: previous_receipt_hash is inconsistent with receipt sequence");
    }
    if !sorted_granted(&r.granted_scope) {
        return plain("wire v2: granted_scope must be sorted, unique canonical scopes");
    }
    if !sorted_evidence(
        &r.status_evidence,
        &r.issuer_ids,
        &r.verifier_id,
        &r.agent_id,
    ) {
        return plain("wire v2: status evidence is invalid, duplicated, or not canonically sorted");
    }
    let sa = r.status_assessment.as_str();
    let ca = r.context_assessment.as_str();
    if matches!(sa, "current" | "revoked" | "stale") && r.status_evidence.is_empty() {
        return plain("wire v2: evaluated status requires authenticated evidence");
    }
    if r.context_policy_digest
        .as_deref()
        .is_some_and(|d| !valid_prefixed_digest(d))
    {
        return plain("wire v2: context_policy_digest is invalid");
    }
    if !valid_constraint_evaluator_refs_v2(&r.constraint_evaluators)
        || (!r.constraint_evaluators.is_empty() && r.issuer_ids.is_empty())
    {
        return plain("wire v2: constraint_evaluators must be valid extension types with sha384 profile digests, sorted and unique by type, and only for a delegated chain");
    }
    if (matches!(ca, "not_evaluated" | "unbound") && r.context_policy_digest.is_some())
        || (matches!(ca, "bound" | "not_required" | "mismatch")
            && r.context_policy_digest.is_none())
    {
        return plain("wire v2: context_policy_digest does not match context_assessment");
    }
    if sa == "not_evaluated" && !r.status_evidence.is_empty() {
        return plain("wire v2: status evidence cannot be present when status was not evaluated");
    }
    if matches!(sa, "current" | "stale")
        && !has_accepted_status_history_per_issuer(&r.status_evidence, &r.issuer_ids)
    {
        return plain("wire v2: current or stale status requires one accepted full-list base and contiguous pushes for every issuer");
    }
    if r.challenge_assessment != "current" {
        return plain("wire v2: terminal receipt challenge_assessment must be current");
    }
    validate_decision(r)?;
    if signature && (r.signature.ed25519.len() != 64 || r.signature.ml_dsa_65.len() != 3309) {
        return plain(
            "wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components",
        );
    }
    Ok(())
}

fn valid_deny_pair(reason: &str, status: &str) -> bool {
    let expected = match reason {
        "not_delegated" | "delegation_not_authorized" => "delegation_not_authorized",
        "delegation_expired" => "expired",
        "delegation_revoked" => "revoked",
        "scope_denied" => "scope_denied",
        "invalid_scope" => "invalid_scope",
        "constraint_denied" => "constraint_denied",
        "constraint_unverifiable" => "constraint_unverifiable",
        "constraint_unknown" => "constraint_unknown",
        "proof_invalid" => "invalid",
        "unauthorized" => "unauthorized",
        _ => return false,
    };
    expected == status
}

fn validate_decision(r: &VerificationReceiptV2) -> V2Result<()> {
    const REASONS: &[&str] = &[
        "authorized",
        "not_delegated",
        "delegation_not_authorized",
        "delegation_expired",
        "delegation_revoked",
        "scope_denied",
        "constraint_denied",
        "constraint_unverifiable",
        "constraint_unknown",
        "invalid_scope",
        "proof_invalid",
        "unauthorized",
        "status_stale",
        "status_unavailable",
        "action_context_unverified",
        "trust_unavailable",
        "evaluation_interrupted",
    ];
    let reason = r.decision_reason.as_str();
    let ta = r.trust_assessment.as_str();
    let sa = r.status_assessment.as_str();
    let ca = r.context_assessment.as_str();
    if !REASONS.contains(&reason) {
        return plain("wire v2: receipt decision_reason is invalid");
    }
    if !matches!(
        ta,
        "trusted" | "untrusted" | "unavailable" | "not_evaluated"
    ) {
        return plain("wire v2: receipt trust_assessment is invalid");
    }
    if !matches!(
        sa,
        "current" | "revoked" | "stale" | "unavailable" | "not_evaluated"
    ) {
        return plain("wire v2: receipt status_assessment is invalid");
    }
    if !matches!(
        ca,
        "bound" | "not_required" | "unbound" | "unverified" | "mismatch" | "not_evaluated"
    ) {
        return plain("wire v2: receipt context_assessment is invalid");
    }
    let local = matches!(
        reason,
        "scope_denied" | "constraint_denied" | "constraint_unverifiable" | "constraint_unknown"
    );
    let constraint = matches!(
        reason,
        "constraint_denied" | "constraint_unverifiable" | "constraint_unknown"
    );
    if r.decision == "allow" {
        if reason != "authorized"
            || r.identity_status != "authorized_agent"
            || ta != "trusted"
            || sa != "current"
            || r.status_evidence.is_empty()
            || r.granted_scope.is_empty()
            || !r.granted_scope.contains(&r.required_scope)
            || (ca != "bound" && ca != "not_required")
            || r.context_policy_digest.is_none()
        {
            return plain("wire v2: allow receipt violates authorization, status, context, or scope requirements");
        }
        return Ok(());
    }
    if r.decision == "deny" {
        if !r.granted_scope.is_empty() || !valid_deny_pair(reason, &r.identity_status) {
            return plain(
                "wire v2: deny receipt has an invalid reason/status pair or granted scope",
            );
        }
        if reason == "not_delegated" && !r.issuer_ids.is_empty() {
            return plain("wire v2: not_delegated receipt cannot contain certificate issuers");
        }
        if local && sa != "current" {
            return plain("wire v2: post-status local policy denial requires current status");
        }
        if (reason == "unauthorized" && ta != "untrusted")
            || (reason == "not_delegated" && ta != "not_evaluated")
            || (reason != "unauthorized" && reason != "not_delegated" && ta != "trusted")
        {
            return plain("wire v2: deny receipt trust assessment is inconsistent");
        }
        if (reason == "delegation_revoked" && sa != "revoked")
            || (reason == "not_delegated" && sa != "not_evaluated")
            || (reason != "delegation_revoked"
                && reason != "not_delegated"
                && sa != "not_evaluated"
                && !(sa == "current" && local))
        {
            return plain("wire v2: deny receipt status assessment is inconsistent");
        }
        if (reason == "not_delegated" || reason == "unauthorized") && ca != "not_evaluated" {
            return plain("wire v2: deny receipt context assessment is inconsistent");
        }
        if reason == "delegation_revoked" && ca == "not_evaluated" {
            return plain(
                "wire v2: delegation_revoked receipt must retain its completed context assessment",
            );
        }
        if !matches!(
            reason,
            "delegation_revoked" | "not_delegated" | "unauthorized"
        ) && !local
            && ca != "not_evaluated"
        {
            return plain("wire v2: context assessment must be not_evaluated for this deny result");
        }
        if (reason == "scope_denied" && ca == "not_evaluated")
            || (constraint
                && ca != "bound"
                && ca != "not_required"
                && !(reason == "constraint_denied" && ca == "mismatch"))
        {
            return plain(
                "wire v2: constraint denial must retain its completed context assessment",
            );
        }
        if (reason == "not_delegated" || reason == "unauthorized") && !r.status_evidence.is_empty()
        {
            return plain("wire v2: status evidence is not evaluated for this deny result");
        }
        if reason == "constraint_denied"
            && ca == "mismatch"
            && r.identity_status != "constraint_denied"
        {
            return plain("wire v2: context mismatch must be a constraint denial");
        }
        return Ok(());
    }
    if r.decision != "indeterminate"
        || !r.granted_scope.is_empty()
        || r.identity_status != "authorization_unverified"
    {
        return plain("wire v2: receipt decision or indeterminate identity/scope is invalid");
    }
    let ok = match reason {
        "status_stale" => ta == "trusted" && sa == "stale" && ca != "not_evaluated",
        "status_unavailable" => ta == "trusted" && sa == "unavailable" && ca != "not_evaluated",
        "trust_unavailable" => {
            ta == "unavailable"
                && sa == "not_evaluated"
                && ca == "not_evaluated"
                && r.status_evidence.is_empty()
        }
        "action_context_unverified" => {
            ta == "trusted" && sa == "current" && (ca == "unbound" || ca == "unverified")
        }
        // Each dimension is independent (SPEC-v2 §6.7): trust keeps its last
        // state; status and context exist only under a trusted root; context
        // is recorded only when it completed as bound or not_required.
        "evaluation_interrupted" => {
            !((ca != "not_evaluated" && ca != "bound" && ca != "not_required")
                || (ta != "trusted" && (sa != "not_evaluated" || ca != "not_evaluated")))
        }
        _ => return plain("wire v2: indeterminate reason is invalid"),
    };
    if !ok {
        return plain(format!("wire v2: {reason} assessment tuple is invalid"));
    }
    Ok(())
}

fn evidence_from(o: &Obj<'_>) -> V2Result<Vec<StatusEvidenceEntryV2>> {
    o.array("status_evidence_digests")?
        .iter()
        .map(|n| {
            if n.is_null() {
                return Ok(StatusEvidenceEntryV2 {
                    issuer_id: String::new(),
                    status_key_id: String::new(),
                    sequence: 0,
                    object_type: 0,
                    digest: String::new(),
                });
            }
            let e = obj(n)?;
            e.only(&[
                "digest",
                "issuer_id",
                "object_type_code",
                "sequence",
                "status_key_id",
            ])?;
            Ok(StatusEvidenceEntryV2 {
                issuer_id: e.str("issuer_id")?,
                status_key_id: e.str("status_key_id")?,
                sequence: e.i64("sequence")?,
                object_type: e.u16("object_type_code")?,
                digest: e.str("digest")?,
            })
        })
        .collect()
}

fn receipt_from(o: &Obj<'_>) -> V2Result<VerificationReceiptV2> {
    Ok(VerificationReceiptV2 {
        version: o.i64("version")?,
        log_id: o.str("log_id")?,
        sequence: o.i64("sequence")?,
        verifier_id: o.str("verifier_id")?,
        agent_id: o.str("agent_id")?,
        human_id: o.str("human_id")?,
        bundle_hash: o.str("bundle_hash")?,
        issuer_ids: o.str_array("issuer_ids")?,
        decision: o.str("decision")?,
        decision_reason: o.str("decision_reason")?,
        identity_status: o.str("identity_status")?,
        trust_assessment: o.str("trust_assessment")?,
        status_assessment: o.str("status_assessment")?,
        challenge_assessment: o.str("challenge_assessment")?,
        constraint_evaluators: evaluators_from(o)?,
        context_assessment: o.str("context_assessment")?,
        context_policy_digest: o.opt_str("context_policy_digest")?,
        verified_at: o.i64("verified_at")?,
        required_scope: o.str("required_scope")?,
        granted_scope: o.str_array("granted_scope")?,
        status_evidence: evidence_from(o)?,
        previous_receipt_hash: o.bytes("previous_receipt_hash")?,
        signature: o.sig("signature")?,
    })
}

fn evaluators_from(o: &Obj<'_>) -> V2Result<Vec<ConstraintEvaluatorRefV2>> {
    o.array("constraint_evaluators")?
        .iter()
        .map(|n| {
            let e = obj(n)?;
            e.only(&["profile_digest", "type"])?;
            Ok(ConstraintEvaluatorRefV2 {
                kind: e.str("type")?,
                profile_digest: e.str("profile_digest")?,
            })
        })
        .collect()
}

fn with_optional(names: &[&'static str]) -> Vec<&'static str> {
    names
        .iter()
        .copied()
        .chain(["agent_id", "human_id", "constraint_evaluators"])
        .collect()
}

/// StatementBodyDigestV2(0x0008, signable body).
pub fn verification_receipt_v2_digest(r: &VerificationReceiptV2) -> V2Result<Vec<u8>> {
    validate_receipt(r, false)?;
    statement_body_digest_v2(0x0008, &canonical(&receipt_cj(r, Shape::Signable))?)
}

/// Canonical signable bytes (all fields but `signature`).
pub fn verification_receipt_v2_signable_bytes(r: &VerificationReceiptV2) -> V2Result<Vec<u8>> {
    canonical(&receipt_cj(r, Shape::Signable))
}

pub(crate) fn validate_receipt_signable_body(data: &[u8]) -> V2Result<()> {
    let root = parse_wire(data, &["previous_receipt_hash"], &["bundle_hash"])?;
    let o = obj(&root)?;
    o.require(&FIELDS[..FIELDS.len() - 1], &["context_policy_digest"])?;
    if o.get("signature").is_some() {
        return plain("signable body must exclude signature");
    }
    o.only(&with_optional(&FIELDS[..FIELDS.len() - 1]))?;
    let r = receipt_from(&o)?;
    validate_receipt(&r, false)?;
    if canonical(&receipt_cj(&r, Shape::Signable))? != data {
        return plain("signable body must use RatifyCanonicalJSON");
    }
    Ok(())
}

/// Canonical wire bytes.
pub fn encode_verification_receipt_v2(r: &VerificationReceiptV2) -> V2Result<Vec<u8>> {
    validate_receipt(r, true)?;
    let data = canonical(&receipt_cj(r, Shape::Wire))?;
    check_v2_wire_size(
        &data,
        "verification receipt",
        "MAX_VERIFICATION_RECEIPT_BYTES_V2",
        MAX_VERIFICATION_RECEIPT_BYTES_V2,
    )?;
    Ok(data)
}

/// Strictly decode a canonical v2 verification receipt.
pub fn decode_verification_receipt_v2(data: &[u8]) -> V2Result<VerificationReceiptV2> {
    (|| {
        check_v2_wire_size(
            data,
            "verification receipt",
            "MAX_VERIFICATION_RECEIPT_BYTES_V2",
            MAX_VERIFICATION_RECEIPT_BYTES_V2,
        )?;
        let root = parse_wire(data, &["previous_receipt_hash"], &["bundle_hash"])?;
        let o = obj(&root)?;
        o.require(FIELDS, &["context_policy_digest"])?;
        o.only(&with_optional(FIELDS))?;
        let r = receipt_from(&o)?;
        validate_receipt(&r, true)?;
        match encode_verification_receipt_v2(&r) {
            Ok(c) if c == data => Ok(r),
            _ => plain("wire v2: verification receipt is not canonical Ratify JSON"),
        }
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Sign a receipt under code 0x0008 with the verifier key.
pub fn sign_verification_receipt_v2(
    r: &VerificationReceiptV2,
    verifier_key: &HybridPrivateKey,
) -> V2SignResult<VerificationReceiptV2> {
    sign_verification_receipt_v2_with_signer(&V2Context::background(), r, &LocalSignerV2::new(verifier_key)?)
}

/// [`sign_verification_receipt_v2`] with an external signer whose key ID must
/// equal `verifier_id`.
pub fn sign_verification_receipt_v2_with_signer(
    ctx: &V2Context,
    r: &VerificationReceiptV2,
    signer: &dyn SignerV2,
) -> V2SignResult<VerificationReceiptV2> {
    validate_receipt(r, false).classify(V2ErrorClass::Malformed)?;
    let verifier_public = signer_public_key_v2(signer)?;
    if key_id_v2(&verifier_public).ok().as_deref() != Some(r.verifier_id.as_str()) {
        return Err(V2SignError::KeyBinding(
            "receipt verifier_id does not match signing key".into(),
        ));
    }
    let body = verification_receipt_v2_signable_bytes(r).classify(V2ErrorClass::Malformed)?;
    let mut out = r.clone();
    out.signature = sign_v2_statement_with_signer(
        ctx,
        V2ObjectType::VerificationReceipt,
        &body,
        signer,
        &verifier_public,
    )?;
    encode_verification_receipt_v2(&out).classify(V2ErrorClass::Malformed)?;
    Ok(out)
}

fn validate_receipt_head(head: &ReceiptV2Head) -> V2Result<()> {
    if !valid_v2_id(&head.verifier_id) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "caller receipt head is invalid",
        );
    }
    validate_head(
        &head.log_id,
        head.sequence,
        &head.head_hash,
        &head.accepted_digests,
    )
}

/// Verify a receipt with a caller-supplied verifier key and log head.
pub fn verify_verification_receipt_v2(
    r: &VerificationReceiptV2,
    verifier_key: &HybridPublicKey,
    head: &ReceiptV2Head,
) -> V2Result<WitnessEntryV2Result> {
    validate_receipt(r, true).classify(V2ErrorClass::Malformed)?;
    encode_verification_receipt_v2(r).classify(V2ErrorClass::Malformed)?;
    validate_receipt_head(head)?;
    if r.log_id != head.log_id || r.verifier_id != head.verifier_id {
        return err(
            V2ErrorClass::LogStateMismatch,
            "receipt log ID or verifier identity does not match caller-authenticated state",
        );
    }
    if r.verifier_id != key_id_v2(verifier_key)? {
        return err(
            V2ErrorClass::LogStateMismatch,
            "receipt verifier_id does not match caller-authenticated key",
        );
    }
    let body = verification_receipt_v2_signable_bytes(r)?;
    verify_v2_statement(
        V2ObjectType::VerificationReceipt,
        &body,
        &r.signature,
        verifier_key,
    )?;
    let digest = verification_receipt_v2_digest(r)?;
    log_position(
        r.sequence,
        &r.previous_receipt_hash,
        &digest,
        head.sequence,
        &head.head_hash,
        &head.accepted_digests,
        head.frozen,
        &head.log_id,
    )
}

/// The canonical outbox body prepared before terminal commit: every field
/// except log position, previous hash, and signature.
pub fn verification_receipt_v2_body(r: &VerificationReceiptV2) -> V2Result<Vec<u8>> {
    let mut candidate = r.clone();
    candidate.log_id = "0123456789abcdef0123456789abcdef".into();
    candidate.sequence = 1;
    candidate.previous_receipt_hash = vec![0; 48];
    candidate.signature = HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    };
    validate_receipt(&candidate, false)?;
    candidate.sequence = MAX_SAFE;
    candidate.previous_receipt_hash[0] = 1;
    candidate.signature = placeholder_signature();
    encode_verification_receipt_v2(&candidate)?;
    canonical(&receipt_cj(r, Shape::Body))
}

/// Reject a malformed or noncanonical prepared body.
pub fn decode_verification_receipt_body_v2(data: &[u8]) -> V2Result<VerificationReceiptV2> {
    (|| {
        check_v2_wire_size(
            data,
            "verification receipt body",
            "MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2",
            MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2,
        )?;
        let root = parse_wire(data, &[], &["bundle_hash"])?;
        let o = obj(&root)?;
        o.require(BODY_REQUIRED, &["context_policy_digest"])?;
        o.only(&with_optional(BODY_REQUIRED))?;
        let mut r = receipt_from(&o)?;
        r.signature = HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        };
        let body = verification_receipt_v2_body(&r).map_err(|e| {
            e.context("wire v2: verification receipt body is invalid or noncanonical")
        })?;
        if body != data {
            return plain("wire v2: verification receipt body is noncanonical");
        }
        Ok(r)
    })()
    .classify(V2ErrorClass::Malformed)
}

/// Assign the next position in a caller-authenticated receipt log.
pub fn bind_verification_receipt_body_v2(
    data: &[u8],
    head: &ReceiptV2Head,
) -> V2Result<VerificationReceiptV2> {
    validate_receipt_head(head)?;
    if head.frozen || head.sequence == MAX_SAFE {
        return plain("wire v2: receipt log cannot accept another entry");
    }
    let mut r = decode_verification_receipt_body_v2(data)?;
    if r.verifier_id != head.verifier_id {
        return plain("wire v2: prepared receipt verifier differs from authenticated log");
    }
    r.log_id = head.log_id.clone();
    r.sequence = head.sequence + 1;
    r.previous_receipt_hash = head.head_hash.clone();
    validate_receipt(&r, false)?;
    Ok(r)
}

/// Bind and sign an exact prepared body with a local verifier key.
pub fn sign_prepared_verification_receipt_v2(
    data: &[u8],
    head: &ReceiptV2Head,
    verifier_key: &HybridPrivateKey,
) -> V2SignResult<VerificationReceiptV2> {
    sign_prepared_verification_receipt_v2_with_signer(
        &V2Context::background(),
        data,
        head,
        &LocalSignerV2::new(verifier_key)?,
    )
}

/// [`sign_prepared_verification_receipt_v2`] with an external verifier signer.
pub fn sign_prepared_verification_receipt_v2_with_signer(
    ctx: &V2Context,
    data: &[u8],
    head: &ReceiptV2Head,
    signer: &dyn SignerV2,
) -> V2SignResult<VerificationReceiptV2> {
    let bound = bind_verification_receipt_body_v2(data, head)?;
    let signed = sign_verification_receipt_v2_with_signer(ctx, &bound, signer)?;
    match verification_receipt_v2_body(&signed) {
        Ok(b) if b == data => Ok(signed),
        _ => Err(V2SignError::InvalidObject(super::errors::V2Error::new(
            V2ErrorClass::Malformed,
            "wire v2: signed receipt differs from prepared body",
        ))),
    }
}

/// Compare a receipt with its proof bundle (hash, verifier, agent, issuers,
/// status-key role separation). Trust and status are not re-established.
pub fn check_verification_receipt_v2_bundle_binding(
    r: &VerificationReceiptV2,
    b: &ProofBundleV2,
) -> V2Result<()> {
    use V2ErrorClass::*;
    validate_receipt(r, false).classify(Malformed)?;
    encode_proof_bundle_v2(b).classify(Malformed)?;
    if r.verifier_id != b.verifier_id || (!r.agent_id.is_empty() && r.agent_id != b.agent_id) {
        return err(
            ReceiptBundleMismatch,
            "receipt verifier or agent ID does not match the proof bundle",
        );
    }
    let mut roles = vec![b.verifier_id.as_str(), b.agent_id.as_str()];
    for c in &b.delegations {
        roles.push(&c.issuer_id);
        roles.push(&c.subject_id);
    }
    if r.status_evidence
        .iter()
        .any(|e| roles.contains(&e.status_key_id.as_str()))
    {
        return err(
            ReceiptBundleMismatch,
            "receipt status key ID overlaps a proof or verifier key role",
        );
    }
    if r.bundle_hash != bundle_hash_v2(b)? {
        return err(
            ReceiptBundleMismatch,
            "receipt bundle_hash does not match the proof bundle",
        );
    }
    let mut issuers: Vec<String> = b.delegations.iter().map(|c| c.issuer_id.clone()).collect();
    issuers.sort();
    issuers.dedup();
    if issuers != r.issuer_ids {
        return err(
            ReceiptBundleMismatch,
            "receipt issuer_ids do not match the proof bundle chain",
        );
    }
    Ok(())
}
