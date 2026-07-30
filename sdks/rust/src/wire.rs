//! Wire decoders and the `VerificationReceipt` codec pair (SPEC §17.5, §5.1).
//!
//! Decoders are strict: unknown fields are rejected (serde `deny_unknown_fields`
//! on the wire types), the wire-integer domain and canonical base64 are
//! enforced by the field (de)serializers, and the input bounds of SPEC §5.1 are
//! enforced here — [`decode_proof_bundle`] rejects an oversized payload BEFORE
//! parsing, and JSON container nesting beyond [`MAX_JSON_NESTING_DEPTH`] is
//! rejected up front. Violations are structural failures — callers surface them
//! as the existing `invalid` status.
//!
//! JSON parsing (and therefore the `decode_*` functions) requires `serde_json`
//! and is only available with the `std` feature. [`encode_verification_receipt`]
//! and [`check_json_nesting_depth`] are `no_std`-compatible.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec::Vec};

use crate::types::{
    is_canonical_constraint_type, DelegationCert, IdentityStatus, VerificationReceipt,
    MAX_CONSTRAINTS_PER_CERT, MAX_IDENTIFIER_LENGTH_BYTES, MAX_JSON_NESTING_DEPTH,
    MAX_SCOPES_PER_CERT, MAX_SCOPE_LENGTH_BYTES,
};

use crate::canonical::{encode_bytes_b64, encode_hybrid_pub_key, encode_hybrid_sig, encode_i64, encode_str, encode_str_array};
use crate::resource_path::validate_constraint_params;

/// Reject JSON whose container nesting exceeds [`MAX_JSON_NESTING_DEPTH`],
/// scanning the raw bytes with string-literal awareness so brackets inside
/// strings do not count. Mirrors the depth rule of Go's `CheckWireJSON`.
pub fn check_json_nesting_depth(data: &[u8]) -> Result<(), String> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in data {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                if depth >= MAX_JSON_NESTING_DEPTH {
                    return Err(format!(
                        "wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH ({})",
                        MAX_JSON_NESTING_DEPTH
                    ));
                }
                depth += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Enforce the per-cert count and length limits of SPEC §5.1 during decode.
/// Does NOT enforce issuance hygiene (`validate_resource_constraints`) —
/// decoders accept what issuance rejects; verification fails unsatisfiable
/// sets closed.
pub fn check_cert_bounds(cert: &DelegationCert) -> Result<(), String> {
    if cert.scope.len() > MAX_SCOPES_PER_CERT {
        return Err(format!(
            "wire: {} scopes exceeds MAX_SCOPES_PER_CERT ({})",
            cert.scope.len(),
            MAX_SCOPES_PER_CERT
        ));
    }
    if cert.constraints.len() > MAX_CONSTRAINTS_PER_CERT {
        return Err(format!(
            "wire: {} constraints exceeds MAX_CONSTRAINTS_PER_CERT ({})",
            cert.constraints.len(),
            MAX_CONSTRAINTS_PER_CERT
        ));
    }
    for s in &cert.scope {
        if s.len() > MAX_SCOPE_LENGTH_BYTES {
            return Err(format!(
                "wire: scope of {} bytes exceeds MAX_SCOPE_LENGTH_BYTES ({})",
                s.len(),
                MAX_SCOPE_LENGTH_BYTES
            ));
        }
    }
    for c in &cert.constraints {
        if c.resource_id.len() > MAX_IDENTIFIER_LENGTH_BYTES {
            return Err(format!(
                "wire: resource_id of {} bytes exceeds MAX_IDENTIFIER_LENGTH_BYTES ({})",
                c.resource_id.len(),
                MAX_IDENTIFIER_LENGTH_BYTES
            ));
        }
        if c.params.is_some() {
            if is_canonical_constraint_type(&c.kind) {
                return Err(format!(
                    "wire: canonical constraint type \"{}\" must not carry params",
                    c.kind
                ));
            }
            validate_constraint_params(c).map_err(|e| format!("wire: constraint params: {}", e))?;
        }
    }
    Ok(())
}

/// Enforce the structural invariants of a wire [`VerificationReceipt`]
/// (SPEC §17.5) — shared by the encoder and decoder so the codec pair never
/// emits a document its counterpart rejects.
pub fn check_receipt_structure(r: &VerificationReceipt) -> Result<(), String> {
    if r.version != crate::types::PROTOCOL_VERSION {
        return Err(format!(
            "wire: receipt version {} is not PROTOCOL_VERSION ({})",
            r.version,
            crate::types::PROTOCOL_VERSION
        ));
    }
    if r.verifier_id.is_empty() {
        return Err("wire: receipt verifier_id must be non-empty".to_string());
    }
    if IdentityStatus::from_wire(&r.decision).is_none() {
        return Err(format!(
            "wire: receipt decision \"{}\" is not a known identity_status",
            r.decision
        ));
    }
    if r.bundle_hash.len() != 32 {
        return Err(format!(
            "wire: bundle_hash must be 32 bytes, got {}",
            r.bundle_hash.len()
        ));
    }
    if r.prev_hash.len() != 32 {
        return Err(format!(
            "wire: prev_hash must be 32 bytes, got {}",
            r.prev_hash.len()
        ));
    }
    if r.verifier_pub.ed25519.len() != 32 {
        return Err(format!(
            "wire: verifier_pub.ed25519 must be 32 bytes, got {}",
            r.verifier_pub.ed25519.len()
        ));
    }
    if r.verifier_pub.ml_dsa_65.len() != 1952 {
        return Err(format!(
            "wire: verifier_pub.ml_dsa_65 must be 1952 bytes, got {}",
            r.verifier_pub.ml_dsa_65.len()
        ));
    }
    if r.signature.ed25519.len() != 64 {
        return Err(format!(
            "wire: signature.ed25519 must be 64 bytes, got {}",
            r.signature.ed25519.len()
        ));
    }
    if r.signature.ml_dsa_65.len() != 3309 {
        return Err(format!(
            "wire: signature.ml_dsa_65 must be 3309 bytes, got {}",
            r.signature.ml_dsa_65.len()
        ));
    }
    Ok(())
}

/// Marshal a [`VerificationReceipt`] into its canonical wire JSON (SPEC §17.5):
/// lex-sorted keys, byte fields as base64-standard strings, optional fields
/// omitted when empty. A structurally invalid receipt is an error, never
/// emitted: the codec pair never produces a document its own decoder rejects.
pub fn encode_verification_receipt(r: &VerificationReceipt) -> Result<Vec<u8>, String> {
    check_receipt_structure(r)?;
    // Keys in lex order: agent_id, bundle_hash, decision, error_reason,
    // granted_scope, human_id, prev_hash, signature, verified_at,
    // verifier_id, verifier_pub, version.
    let mut out = String::new();
    out.push('{');
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
        out.push_str(sep);
        out.push_str("\"granted_scope\":"); encode_str_array(&r.granted_scope, &mut out);
    }
    if !r.human_id.is_empty() {
        out.push_str(sep);
        out.push_str("\"human_id\":"); encode_str(&r.human_id, &mut out);
    }
    out.push_str(sep);
    out.push_str("\"prev_hash\":"); encode_bytes_b64(&r.prev_hash, &mut out);
    out.push_str(sep);
    out.push_str("\"signature\":"); encode_hybrid_sig(&r.signature, &mut out);
    out.push_str(sep);
    out.push_str("\"verified_at\":"); encode_i64(r.verified_at, &mut out);
    out.push_str(sep);
    out.push_str("\"verifier_id\":"); encode_str(&r.verifier_id, &mut out);
    out.push_str(sep);
    out.push_str("\"verifier_pub\":"); encode_hybrid_pub_key(&r.verifier_pub, &mut out);
    out.push_str(sep);
    out.push_str("\"version\":"); out.push_str(&r.version.to_string());
    out.push('}');
    Ok(out.into_bytes())
}

// ------------------------------------------------------------------
// JSON decoders (require serde_json → std only).
// ------------------------------------------------------------------

/// Parse canonical wire JSON into a [`DelegationCert`] under strict wire
/// acceptance and the SPEC §5.1 input bounds.
#[cfg(feature = "std")]
pub fn decode_delegation_cert(data: &[u8]) -> Result<DelegationCert, String> {
    check_json_nesting_depth(data)?;
    let cert: DelegationCert =
        serde_json::from_slice(data).map_err(|e| format!("wire: {}", e))?;
    check_cert_bounds(&cert)?;
    Ok(cert)
}

/// Parse canonical wire JSON into a [`crate::types::ProofBundle`] under strict
/// wire acceptance and the SPEC §5.1 input bounds. The
/// [`MAX_PROOF_BUNDLE_BYTES`] check runs BEFORE any parsing: an oversized
/// payload is rejected without being parsed at all.
#[cfg(feature = "std")]
pub fn decode_proof_bundle(data: &[u8]) -> Result<crate::types::ProofBundle, String> {
    if data.len() > crate::types::MAX_PROOF_BUNDLE_BYTES {
        return Err(format!(
            "wire: proof bundle of {} bytes exceeds MAX_PROOF_BUNDLE_BYTES ({})",
            data.len(),
            crate::types::MAX_PROOF_BUNDLE_BYTES
        ));
    }
    check_json_nesting_depth(data)?;
    let bundle: crate::types::ProofBundle =
        serde_json::from_slice(data).map_err(|e| format!("wire: {}", e))?;
    // Chain depth is NOT enforced here: it is a verify-time semantic ceiling
    // (chain_too_deep), not a wire-structural bound. The byte limit above
    // already caps pre-parse work, and an over-deep chain must reach verify
    // to produce its documented identity_status. This keeps every SDK's
    // public decoder identical: decode succeeds, verify rejects.
    for cert in &bundle.delegations {
        check_cert_bounds(cert)?;
    }
    Ok(bundle)
}

// Strict wire mirror of VerificationReceipt: rejects unknown fields at decode
// so constraint-level strictness holds regardless of the public type's serde
// configuration.
#[cfg(feature = "std")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationReceiptWire {
    version: i32,
    verifier_id: String,
    verifier_pub: crate::types::HybridPublicKey,
    #[serde(with = "crate::canonical::base64_bytes")]
    bundle_hash: Vec<u8>,
    decision: String,
    #[serde(default)]
    human_id: String,
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    granted_scope: Vec<String>,
    #[serde(default)]
    error_reason: String,
    verified_at: i64,
    #[serde(with = "crate::canonical::base64_bytes")]
    prev_hash: Vec<u8>,
    signature: crate::types::HybridSignature,
}

/// Parse canonical wire JSON into a [`VerificationReceipt`] under strict wire
/// acceptance and the same structural invariants the encoder enforces (hash
/// and key-component lengths, known decision, protocol version). Signature
/// verification is the caller's job via `verify_verification_receipt`.
#[cfg(feature = "std")]
pub fn decode_verification_receipt(data: &[u8]) -> Result<VerificationReceipt, String> {
    check_json_nesting_depth(data)?;
    let w: VerificationReceiptWire =
        serde_json::from_slice(data).map_err(|e| format!("wire: {}", e))?;
    let r = VerificationReceipt {
        version: w.version,
        verifier_id: w.verifier_id,
        verifier_pub: w.verifier_pub,
        bundle_hash: w.bundle_hash,
        decision: w.decision,
        human_id: w.human_id,
        agent_id: w.agent_id,
        granted_scope: w.granted_scope,
        error_reason: w.error_reason,
        verified_at: w.verified_at,
        prev_hash: w.prev_hash,
        signature: w.signature,
    };
    check_receipt_structure(&r)?;
    Ok(r)
}
