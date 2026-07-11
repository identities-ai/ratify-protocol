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

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use crate::canonical::{
    encode_bool, encode_bytes_b64, encode_f64, encode_hybrid_pub_key, encode_hybrid_sig, encode_i32,
    encode_i64, encode_str, encode_str_array,
};
use crate::crypto::{sign_both, verify_both};
use crate::types::{
    DelegationCert, HybridPrivateKey, HybridPublicKey, HybridSignature, PolicyVerdict, ProofBundle,
    VerificationReceipt, VerifierContext, VerifyResult,
};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt — SPEC §17.5
// ---------------------------------------------------------------------------

/// Canonical delegation object for the bundle hash (all fields present,
/// no skip, including signature). Keys in lex order.
fn encode_delegation_for_hash(d: &DelegationCert, out: &mut String) {
    use crate::canonical::encode_constraints;
    out.push('{');
    out.push_str("\"cert_id\":");        encode_str(&d.cert_id, out);
    out.push_str(",\"constraints\":");   encode_constraints(&d.constraints, out);
    out.push_str(",\"expires_at\":");    encode_i64(d.expires_at, out);
    out.push_str(",\"issued_at\":");     encode_i64(d.issued_at, out);
    out.push_str(",\"issuer_id\":");     encode_str(&d.issuer_id, out);
    out.push_str(",\"issuer_pub_key\":"); encode_hybrid_pub_key(&d.issuer_pub_key, out);
    out.push_str(",\"scope\":");         encode_str_array(&d.scope, out);
    out.push_str(",\"signature\":");     encode_hybrid_sig(&d.signature, out);
    out.push_str(",\"subject_id\":");    encode_str(&d.subject_id, out);
    out.push_str(",\"subject_pub_key\":"); encode_hybrid_pub_key(&d.subject_pub_key, out);
    out.push_str(",\"version\":");       encode_i32(d.version, out);
    out.push('}');
}

/// SHA-256 of a fixed-shape canonical form of a ProofBundle (SPEC §17.5).
///
/// Cross-SDK byte equivalence requires every field to be present (no skip),
/// keys alphabetical at every level, and empty bytes / empty lists / zero
/// ints serialized as `""` / `[]` / `0`. Every reference SDK (Go,
/// TypeScript, Python, Rust) produces the same 32-byte digest for the
/// same logical bundle. Verified against
/// `testvectors/v1/cross_sdk_vectors.json`.
pub fn bundle_hash(bundle: &ProofBundle) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    // Outer keys in lex order: agent_id, agent_pub_key, challenge,
    // challenge_at, challenge_sig, delegations, session_context, stream_id,
    // stream_seq.
    out.push('{');
    out.push_str("\"agent_id\":"); encode_str(&bundle.agent_id, &mut out);
    out.push_str(",\"agent_pub_key\":"); encode_hybrid_pub_key(&bundle.agent_pub_key, &mut out);
    // challenge and session_context/stream_id always b64 (empty slice → "")
    out.push_str(",\"challenge\":"); encode_bytes_b64(&bundle.challenge, &mut out);
    out.push_str(",\"challenge_at\":"); encode_i64(bundle.challenge_at, &mut out);
    out.push_str(",\"challenge_sig\":"); encode_hybrid_sig(&bundle.challenge_sig, &mut out);
    // delegations array (all fields present, including signature)
    out.push_str(",\"delegations\":[");
    for (i, d) in bundle.delegations.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        encode_delegation_for_hash(d, &mut out);
    }
    out.push(']');
    out.push_str(",\"session_context\":"); encode_bytes_b64(&bundle.session_context, &mut out);
    out.push_str(",\"stream_id\":"); encode_bytes_b64(&bundle.stream_id, &mut out);
    out.push_str(",\"stream_seq\":"); encode_i64(bundle.stream_seq, &mut out);
    out.push('}');
    let bytes = out.into_bytes();
    Ok(Sha256::digest(&bytes).to_vec())
}

/// Canonical signable bytes for a VerificationReceipt. Public so tests
/// (and any AuditProvider that wants to chain its own signatures) can
/// recompute the bytes.
pub fn verification_receipt_sign_bytes_buf(
    r: &VerificationReceipt,
) -> Result<Vec<u8>, String> {
    verification_receipt_sign_bytes(r)
}

fn verification_receipt_sign_bytes(r: &VerificationReceipt) -> Result<Vec<u8>, String> {
    // Keys in lex order. Optional fields (agent_id, error_reason, granted_scope,
    // human_id) are omitted when empty, matching Go's omitempty.
    // Sorted: agent_id < bundle_hash < decision < error_reason <
    // granted_scope < human_id < prev_hash < verified_at < verifier_id <
    // verifier_pub < version.
    let mut out = String::new();
    out.push('{');

    // Build a vec of (key, writer) pairs for present fields, then join with commas.
    // Simpler: just track separator manually.
    let mut sep = "";

    if !r.agent_id.is_empty() {
        out.push_str(sep); sep = ",";
        out.push_str("\"agent_id\":"); encode_str(&r.agent_id, &mut out);
    }
    out.push_str(sep); sep = ",";
    out.push_str("\"bundle_hash\":"); encode_bytes_b64(&r.bundle_hash, &mut out);
    out.push_str(sep);
    out.push_str("\"decision\":"); encode_str(&r.decision, &mut out);
    if !r.error_reason.is_empty() {
        out.push_str(sep);
        out.push_str("\"error_reason\":"); encode_str(&r.error_reason, &mut out);
    }
    if !r.granted_scope.is_empty() {
        let mut scope = r.granted_scope.clone();
        scope.sort();
        out.push_str(sep);
        out.push_str("\"granted_scope\":"); encode_str_array(&scope, &mut out);
    }
    if !r.human_id.is_empty() {
        out.push_str(sep);
        out.push_str("\"human_id\":"); encode_str(&r.human_id, &mut out);
    }
    out.push_str(sep);
    out.push_str("\"prev_hash\":"); encode_bytes_b64(&r.prev_hash, &mut out);
    out.push_str(sep);
    out.push_str("\"verified_at\":"); encode_i64(r.verified_at, &mut out);
    out.push_str(sep);
    out.push_str("\"verifier_id\":"); encode_str(&r.verifier_id, &mut out);
    out.push_str(sep);
    out.push_str("\"verifier_pub\":"); encode_hybrid_pub_key(&r.verifier_pub, &mut out);
    out.push_str(sep);
    out.push_str("\"version\":"); encode_i32(r.version, &mut out);
    out.push('}');
    Ok(out.into_bytes())
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

/// SHA-256 of the canonical-byte representation of the policy-relevant
/// subset of a VerifierContext. Used as `context_hash` on a PolicyVerdict.
/// `invocations_in_window` is excluded — closures don't serialize.
/// Keys in lex order: current_alt_m, current_lat, current_lon,
/// current_speed_mps, has_amount, has_location, has_speed,
/// requested_amount, requested_currency.
pub fn verifier_context_hash(ctx: &VerifierContext) -> Result<Vec<u8>, String> {
    let has_amount = ctx.requested_amount.is_some();
    let has_location = ctx.current_lat.is_some() && ctx.current_lon.is_some();
    let has_speed = ctx.current_speed_mps.is_some();
    let mut out = String::new();
    out.push('{');
    out.push_str("\"current_alt_m\":"); encode_f64(ctx.current_alt_m.unwrap_or(0.0), &mut out);
    out.push_str(",\"current_lat\":"); encode_f64(ctx.current_lat.unwrap_or(0.0), &mut out);
    out.push_str(",\"current_lon\":"); encode_f64(ctx.current_lon.unwrap_or(0.0), &mut out);
    out.push_str(",\"current_speed_mps\":"); encode_f64(ctx.current_speed_mps.unwrap_or(0.0), &mut out);
    out.push_str(",\"has_amount\":"); encode_bool(has_amount, &mut out);
    out.push_str(",\"has_location\":"); encode_bool(has_location, &mut out);
    out.push_str(",\"has_speed\":"); encode_bool(has_speed, &mut out);
    out.push_str(",\"requested_amount\":"); encode_f64(ctx.requested_amount.unwrap_or(0.0), &mut out);
    out.push_str(",\"requested_currency\":"); encode_str(ctx.requested_currency.as_deref().unwrap_or(""), &mut out);
    out.push('}');
    let bytes = out.into_bytes();
    Ok(Sha256::digest(&bytes).to_vec())
}

/// Canonical signable bytes for a PolicyVerdict. Public so tests and
/// alternative issuance backends can recompute the bytes.
/// Keys: agent_id, allow, context_hash, issued_at, scope, valid_until,
/// verdict_id, version.
pub fn policy_verdict_sign_bytes_buf(v: &PolicyVerdict) -> Result<Vec<u8>, String> {
    policy_verdict_sign_bytes(v)
}

fn policy_verdict_sign_bytes(v: &PolicyVerdict) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    out.push('{');
    out.push_str("\"agent_id\":"); encode_str(&v.agent_id, &mut out);
    out.push_str(",\"allow\":"); encode_bool(v.allow, &mut out);
    out.push_str(",\"context_hash\":"); encode_bytes_b64(&v.context_hash, &mut out);
    out.push_str(",\"issued_at\":"); encode_i64(v.issued_at, &mut out);
    out.push_str(",\"scope\":"); encode_str(&v.scope, &mut out);
    out.push_str(",\"valid_until\":"); encode_i64(v.valid_until, &mut out);
    out.push_str(",\"verdict_id\":"); encode_str(&v.verdict_id, &mut out);
    out.push_str(",\"version\":"); encode_i32(v.version, &mut out);
    out.push('}');
    Ok(out.into_bytes())
}

/// Construct and HMAC-bind a PolicyVerdict.
///
/// Eight explicit parameters is deliberate: this signature mirrors
/// issue_policy_verdict in the Go/TypeScript/Python SDKs, and cross-SDK
/// signature parity outranks the lint here.
#[allow(clippy::too_many_arguments)]
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
