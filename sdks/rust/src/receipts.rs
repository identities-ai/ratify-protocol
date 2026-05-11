//! Receipts and verdicts — SPEC §17.5–§17.6.
//!
//! Additive primitives that sit on top of `verify_bundle`:
//!   - `VerificationReceipt`: hybrid-signed attestation that a bundle was
//!     verified with a specific decision at a specific time. Chains by
//!     `prev_hash` so the chain is tamper-evident.
//!   - `PolicyVerdict`: HMAC-bound cached policy decision; lets a commercial
//!     policy backend skip live evaluation on subsequent calls.
//!
//! Wire format unchanged: these wrap output of the verifier rather than
//! adding fields to existing signed objects.

use crate::canonical::canonical_json;
use crate::crypto::{sign_both, verify_both};
use crate::types::{
    HybridPrivateKey, HybridPublicKey, HybridSignature, PolicyVerdict, ProofBundle,
    VerificationReceipt, VerifierContext, VerifyResult,
};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt — SPEC §17.5
// ---------------------------------------------------------------------------

/// SHA-256 of the canonical JSON of a ProofBundle. The stable identifier
/// of "what was verified" inside a VerificationReceipt.
pub fn bundle_hash(bundle: &ProofBundle) -> Result<Vec<u8>, String> {
    let v = serde_json::to_value(bundle).map_err(|e| format!("serialize bundle: {}", e))?;
    let bytes = canonical_json(&v);
    Ok(Sha256::digest(&bytes).to_vec())
}

fn verification_receipt_sign_bytes(r: &VerificationReceipt) -> Result<Vec<u8>, String> {
    // We need to base64-encode bytes for canonical JSON; canonical_json over
    // the typed struct produces b64 directly when fields use base64_bytes
    // serde, but here we build the signable as a flat json! for control.
    // Simpler: hand-canonicalize a serde_json::Value so the bytes match Go.
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut signable = serde_json::Map::new();
    if !r.agent_id.is_empty() {
        signable.insert("agent_id".into(), json!(r.agent_id));
    }
    signable.insert("bundle_hash".into(), json!(STANDARD.encode(&r.bundle_hash)));
    signable.insert("decision".into(), json!(r.decision));
    if !r.error_reason.is_empty() {
        signable.insert("error_reason".into(), json!(r.error_reason));
    }
    if !r.granted_scope.is_empty() {
        let mut scope = r.granted_scope.clone();
        scope.sort();
        signable.insert("granted_scope".into(), json!(scope));
    }
    if !r.human_id.is_empty() {
        signable.insert("human_id".into(), json!(r.human_id));
    }
    signable.insert("prev_hash".into(), json!(STANDARD.encode(&r.prev_hash)));
    signable.insert("verified_at".into(), json!(r.verified_at));
    signable.insert("verifier_id".into(), json!(r.verifier_id));
    signable.insert("verifier_pub".into(), serde_json::to_value(&r.verifier_pub).map_err(|e| e.to_string())?);
    signable.insert("version".into(), json!(r.version));
    Ok(canonical_json(&serde_json::Value::Object(signable)))
}

/// Construct and hybrid-sign a VerificationReceipt over a (bundle, result,
/// prev) triple. `prev_hash` is `None` for genesis (becomes 32 zero bytes).
pub fn issue_verification_receipt(
    bundle: &ProofBundle,
    result: &VerifyResult,
    verifier_id: &str,
    verifier_pub: &HybridPublicKey,
    verifier_priv: &HybridPrivateKey,
    prev_hash: Option<&[u8]>,
    verified_at: i64,
) -> Result<VerificationReceipt, String> {
    let prev = match prev_hash {
        Some(p) if p.len() == 32 => p.to_vec(),
        None => vec![0u8; 32],
        Some(p) => return Err(format!("prev_hash must be 32 bytes, got {}", p.len())),
    };
    let mut r = VerificationReceipt {
        version: 1,
        verifier_id: verifier_id.to_string(),
        verifier_pub: verifier_pub.clone(),
        bundle_hash: bundle_hash(bundle)?,
        decision: result.identity_status.as_str().to_string(),
        human_id: result.human_id.clone(),
        agent_id: result.agent_id.clone(),
        granted_scope: result.granted_scope.clone(),
        error_reason: result.error_reason.clone(),
        verified_at,
        prev_hash: prev,
        signature: HybridSignature {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        },
    };
    let signable = verification_receipt_sign_bytes(&r)?;
    r.signature = sign_both(&signable, verifier_priv);
    Ok(r)
}

/// Verify the hybrid signature on a VerificationReceipt against the
/// receipt's declared verifier_pub. Returns Ok(()) iff both component
/// signatures verify.
pub fn verify_verification_receipt(r: &VerificationReceipt) -> Result<(), String> {
    if r.version != 1 {
        return Err(format!("unsupported version {}", r.version));
    }
    if r.bundle_hash.len() != 32 {
        return Err(format!("bundle_hash must be 32 bytes, got {}", r.bundle_hash.len()));
    }
    if r.prev_hash.len() != 32 {
        return Err(format!("prev_hash must be 32 bytes, got {}", r.prev_hash.len()));
    }
    let signable = verification_receipt_sign_bytes(r)?;
    verify_both(&signable, &r.signature, &r.verifier_pub)
}

/// SHA-256 of a receipt's canonical signable bytes. Use as `prev_hash` for
/// the next receipt in the chain.
pub fn receipt_hash(r: &VerificationReceipt) -> Result<Vec<u8>, String> {
    let signable = verification_receipt_sign_bytes(r)?;
    Ok(Sha256::digest(&signable).to_vec())
}

// ---------------------------------------------------------------------------
// Lever 2: PolicyVerdict — SPEC §17.6
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct VerifierContextSignable {
    current_alt_m: f64,
    current_lat: f64,
    current_lon: f64,
    current_speed_mps: f64,
    has_amount: bool,
    has_location: bool,
    has_speed: bool,
    requested_amount: f64,
    requested_currency: String,
}

/// SHA-256 of the canonical-byte representation of the policy-relevant
/// subset of a VerifierContext. Used as `context_hash` on a PolicyVerdict.
/// `invocations_in_window` is excluded — closures don't serialize.
pub fn verifier_context_hash(ctx: &VerifierContext) -> Result<Vec<u8>, String> {
    // has_* booleans derived from field presence (Option::is_some) so the
    // canonical hash matches the Go reference's explicit Has* fields.
    let signable = VerifierContextSignable {
        current_alt_m: ctx.current_alt_m.unwrap_or(0.0),
        current_lat: ctx.current_lat.unwrap_or(0.0),
        current_lon: ctx.current_lon.unwrap_or(0.0),
        current_speed_mps: ctx.current_speed_mps.unwrap_or(0.0),
        has_amount: ctx.requested_amount.is_some(),
        has_location: ctx.current_lat.is_some() && ctx.current_lon.is_some(),
        has_speed: ctx.current_speed_mps.is_some(),
        requested_amount: ctx.requested_amount.unwrap_or(0.0),
        requested_currency: ctx.requested_currency.clone().unwrap_or_default(),
    };
    let v = serde_json::to_value(&signable).map_err(|e| format!("serialize ctx: {}", e))?;
    let bytes = canonical_json(&v);
    Ok(Sha256::digest(&bytes).to_vec())
}

#[derive(Serialize)]
struct PolicyVerdictSignable<'a> {
    agent_id: &'a str,
    allow: bool,
    context_hash: String,
    issued_at: i64,
    scope: &'a str,
    valid_until: i64,
    verdict_id: &'a str,
    version: i32,
}

fn policy_verdict_sign_bytes(v: &PolicyVerdict) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let signable = PolicyVerdictSignable {
        agent_id: &v.agent_id,
        allow: v.allow,
        context_hash: STANDARD.encode(&v.context_hash),
        issued_at: v.issued_at,
        scope: &v.scope,
        valid_until: v.valid_until,
        verdict_id: &v.verdict_id,
        version: v.version,
    };
    let v = serde_json::to_value(&signable).map_err(|e| format!("serialize signable: {}", e))?;
    Ok(canonical_json(&v))
}

/// Construct and HMAC-bind a PolicyVerdict.
pub fn issue_policy_verdict(
    verdict_id: &str,
    agent_id: &str,
    scope: &str,
    allow: bool,
    context_hash: &[u8],
    issued_at: i64,
    valid_until: i64,
    policy_secret: &[u8],
) -> Result<PolicyVerdict, String> {
    if policy_secret.is_empty() {
        return Err("policy_secret must not be empty".into());
    }
    if verdict_id.is_empty() {
        return Err("verdict_id must not be empty".into());
    }
    if agent_id.is_empty() {
        return Err("agent_id must not be empty".into());
    }
    if scope.is_empty() {
        return Err("scope must not be empty".into());
    }
    if context_hash.len() != 32 {
        return Err(format!("context_hash must be 32 bytes, got {}", context_hash.len()));
    }
    if valid_until <= issued_at {
        return Err("valid_until must be strictly after issued_at".into());
    }
    let mut v = PolicyVerdict {
        version: 1,
        verdict_id: verdict_id.to_string(),
        agent_id: agent_id.to_string(),
        scope: scope.to_string(),
        allow,
        context_hash: context_hash.to_vec(),
        issued_at,
        valid_until,
        mac: Vec::new(),
    };
    let signable = policy_verdict_sign_bytes(&v)?;
    let mut mac = HmacSha256::new_from_slice(policy_secret).map_err(|e| e.to_string())?;
    mac.update(&signable);
    v.mac = mac.finalize().into_bytes().to_vec();
    Ok(v)
}

/// Check a PolicyVerdict's HMAC and validity. Returns `Ok(())` on success
/// (cached allow); returns `Err("policy_verdict_denied: ...")` on cached
/// deny; any other `Err` indicates the verdict is unusable.
pub fn verify_policy_verdict(
    v: &PolicyVerdict,
    policy_secret: &[u8],
    expected_agent_id: &str,
    expected_scope: &str,
    expected_context_hash: &[u8],
    now: i64,
) -> Result<(), String> {
    if policy_secret.is_empty() {
        return Err("policy_secret must not be empty".into());
    }
    if v.version != 1 {
        return Err(format!("unsupported version {}", v.version));
    }
    if v.context_hash.len() != 32 {
        return Err(format!("context_hash must be 32 bytes, got {}", v.context_hash.len()));
    }
    if v.mac.len() != 32 {
        return Err(format!("mac must be 32 bytes, got {}", v.mac.len()));
    }
    let signable = policy_verdict_sign_bytes(v)?;
    let mut mac = HmacSha256::new_from_slice(policy_secret).map_err(|e| e.to_string())?;
    mac.update(&signable);
    mac.verify_slice(&v.mac)
        .map_err(|_| "policy_verdict MAC invalid".to_string())?;
    if now < v.issued_at {
        return Err("policy_verdict not yet valid".into());
    }
    if now > v.valid_until {
        return Err("policy_verdict expired".into());
    }
    if v.agent_id != expected_agent_id {
        return Err("policy_verdict agent_id mismatch".into());
    }
    if v.scope != expected_scope {
        return Err("policy_verdict scope mismatch".into());
    }
    if v.context_hash != expected_context_hash {
        return Err("policy_verdict context_hash mismatch".into());
    }
    if !v.allow {
        return Err(format!(
            "policy_verdict_denied: cached deny for scope \"{}\"",
            v.scope
        ));
    }
    Ok(())
}
