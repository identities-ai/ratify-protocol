//! Object-level verification exports kept from the first `ratify_v2_*`
//! surface: key IDs, stateless object verification against a JSON context,
//! proof-bundle signature checks, and receipt checks.

use std::ffi::CStr;
use std::os::raw::c_char;

use ratify_protocol::v2::{
    bundle_hash_v2, check_verification_receipt_v2_bundle_binding, decode_delegation_cert_v2,
    decode_key_rotation_statement_v2, decode_proof_bundle_v2, decode_revocation_list_v2,
    decode_revocation_push_v2, decode_transaction_receipt_v2, decode_verification_receipt_v2,
    decode_witness_entry_v2, key_id_v2, valid_v2_id, verify_delegation_cert_v2_signature,
    verify_key_rotation_statement_v2, verify_proof_bundle_v2_signatures,
    verify_revocation_list_v2_signature, verify_revocation_push_v2_signature,
    verify_transaction_receipt_v2_signatures, verify_verification_receipt_v2,
    verify_witness_entry_v2, V2Error, V2ErrorClass,
};
use ratify_protocol::HybridPublicKey;
use serde_json::Value;

use super::marshal::{public_key, receipt_head, rotation_state, witness_head};
use super::{bad_arg, bytes, null_arg, run, AbiResult};

fn field<'a>(v: &'a Value, name: &str) -> AbiResult<&'a Value> {
    v.get(name)
        .filter(|x| !x.is_null())
        .ok_or_else(|| bad_arg(format!("context is missing \"{name}\"")))
}

fn str_field(v: &Value, name: &str) -> AbiResult<String> {
    field(v, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| bad_arg(format!("context \"{name}\" must be a string")))
}

fn int_field(v: &Value, name: &str) -> AbiResult<i64> {
    field(v, name)?
        .as_i64()
        .ok_or_else(|| bad_arg(format!("context \"{name}\" must be an integer")))
}

fn key_field(v: &Value, name: &str) -> AbiResult<HybridPublicKey> {
    public_key(field(v, name)?, name)
}

unsafe fn json_arg(ptr: *const c_char, name: &str) -> AbiResult<Value> {
    super::json_cstr(ptr, name)
}

fn verify_kind(kind: i32, wire: &[u8], ctx: Option<&Value>) -> AbiResult<()> {
    let need_ctx = || ctx.ok_or_else(|| null_arg("verify_context_json"));
    match kind {
        1 => verify_delegation_cert_v2_signature(&decode_delegation_cert_v2(wire)?)?,
        2 => verify_proof_bundle_v2_signatures(&decode_proof_bundle_v2(wire)?)?,
        3 => {
            let c = need_ctx()?;
            verify_revocation_list_v2_signature(
                &decode_revocation_list_v2(wire)?,
                &str_field(c, "bound_issuer_id")?,
                &key_field(c, "status_key")?,
            )?
        }
        4 => {
            let c = need_ctx()?;
            verify_key_rotation_statement_v2(
                &decode_key_rotation_statement_v2(wire)?,
                &rotation_state(field(c, "rotation_state")?)?,
                int_field(c, "now")?,
                int_field(c, "future_skew_seconds")?,
            )?
        }
        5 => {
            let c = need_ctx()?;
            verify_revocation_push_v2_signature(
                &decode_revocation_push_v2(wire)?,
                &str_field(c, "bound_issuer_id")?,
                &key_field(c, "status_key")?,
            )?
        }
        6 => {
            let c = need_ctx()?;
            verify_witness_entry_v2(
                &decode_witness_entry_v2(wire)?,
                &witness_head(field(c, "head")?)?,
                &key_field(c, "witness_key")?,
            )
            .map(|_| ())?
        }
        7 => verify_transaction_receipt_v2_signatures(&decode_transaction_receipt_v2(wire)?)?,
        8 => {
            let c = need_ctx()?;
            verify_verification_receipt_v2(
                &decode_verification_receipt_v2(wire)?,
                &key_field(c, "verifier_key")?,
                &receipt_head(field(c, "head")?)?,
            )
            .map(|_| ())?
        }
        other => {
            return Err(V2Error::new(
                V2ErrorClass::UnsupportedObjectType,
                format!("object kind {other} is not a standalone v2 signed object"),
            )
            .into())
        }
    }
    Ok(())
}

fn write_hex_out(out: *mut c_char, out_len: usize, hex: &str) -> AbiResult<()> {
    if out.is_null() {
        return Err(null_arg("out"));
    }
    if out_len < hex.len() + 1 {
        return Err(bad_arg(format!(
            "out_len {out_len} is too small; need {}",
            hex.len() + 1
        )));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(hex.as_ptr(), out as *mut u8, hex.len());
        *out.add(hex.len()) = 0;
    }
    Ok(())
}

// ============================================================================
// Exported functions
// ============================================================================

/// Derive the full 256-bit v2 key ID
/// (`hex(SHA-256("ratify-key-id-v2\0" || ed25519 || ml_dsa_65))`) and write it
/// as 64 lowercase hex characters plus NUL into `out` (`out_len` >= 65,
/// `RATIFY_V2_KEY_ID_BUF_LEN`). Wrong key lengths return `RatifyV2Malformed`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_key_id(
    ed25519: *const u8,
    ed25519_len: usize,
    ml_dsa_65: *const u8,
    ml_dsa_65_len: usize,
    out: *mut c_char,
    out_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || crate::guard::clear_cstr(out, out_len), || {
        let key = HybridPublicKey {
            ed25519: bytes(ed25519, ed25519_len, "ed25519")?.to_vec(),
            ml_dsa_65: bytes(ml_dsa_65, ml_dsa_65_len, "ml_dsa_65")?.to_vec(),
        };
        let id = key_id_v2(&key).map_err(|e| e.classify(V2ErrorClass::Malformed))?;
        write_hex_out(out, out_len, &id)
    })
}

/// Check that `key_id` is a well-formed v2 key ID (64 lowercase hex chars).
/// A 128-bit v1 ID, uppercase hex, or wrong length returns `RatifyV2Malformed`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_key_id_check(
    key_id: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || {}, || {
        if key_id.is_null() {
            return Err(null_arg("key_id"));
        }
        let ok = CStr::from_ptr(key_id)
            .to_str()
            .map(valid_v2_id)
            .unwrap_or(false);
        if ok {
            Ok(())
        } else {
            Err(V2Error::new(V2ErrorClass::Malformed, "not a 256-bit lowercase-hex v2 key ID").into())
        }
    })
}

/// Strictly decode a canonical v2 signed object of `kind`
/// (`RatifyV2ObjectKind`) from `wire` and verify it per the SPEC-v2 procedure
/// for that kind. Returns `RatifyV2Ok` or the failure class.
///
/// `verify_context_json` is required for kinds that verify against
/// caller-authenticated state and may be NULL otherwise:
///
/// - revocation_list / revocation_push:
///   `{"bound_issuer_id": "<v2 id>", "status_key": <HybridPublicKey>}`
/// - key_rotation_statement:
///   `{"rotation_state": {"authority_id", "recovery_epoch", "role", "sequence",
///   "head_hash_b64", "current_key": <HybridPublicKey>, "used_key_ids": [..]},
///   "now": <unix>, "future_skew_seconds": <int>}`
/// - witness_entry: `{"witness_key": <HybridPublicKey>, "head": <head>}`
/// - verification_receipt: `{"verifier_key": <HybridPublicKey>, "head": <head>}`
///
/// `<head>` is `{"log_id", "sequence", "head_hash_b64",
/// "accepted_digests_b64": {"<seq>": "<b64>"}, "frozen"}` plus `"verifier_id"`
/// for a verification receipt. `<HybridPublicKey>` is
/// `{"ed25519": "<b64>", "ml_dsa_65": "<b64>"}`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verify_object(
    kind: i32,
    wire: *const u8,
    wire_len: usize,
    verify_context_json: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || {}, || {
        let wire = bytes(wire, wire_len, "wire")?;
        let ctx = if verify_context_json.is_null() {
            None
        } else {
            Some(json_arg(verify_context_json, "verify_context_json")?)
        };
        verify_kind(kind, wire, ctx.as_ref())
    })
}

/// Strictly decode a v2 ProofBundle and run its structural checks (key IDs,
/// delegation digest, duplicate CertificateRef, chain linkage) and every
/// certificate and challenge signature. This is NOT a full live verification:
/// it performs no trust-anchor, challenge, replay, status, or policy checks.
///
/// When `bundle_hash_out` is non-NULL, the BundleHashV2 of a verified bundle is
/// written there as a NUL-terminated string (`bundle_hash_out_len` bytes
/// available; 128 is sufficient).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_proof_bundle_verify_signatures(
    wire: *const u8,
    wire_len: usize,
    bundle_hash_out: *mut c_char,
    bundle_hash_out_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || crate::guard::clear_cstr(bundle_hash_out, bundle_hash_out_len), || {
        let b = decode_proof_bundle_v2(bytes(wire, wire_len, "wire")?)?;
        verify_proof_bundle_v2_signatures(&b)?;
        if !bundle_hash_out.is_null() {
            write_hex_out(bundle_hash_out, bundle_hash_out_len, &bundle_hash_v2(&b)?)?;
        }
        Ok(())
    })
}

/// Verify a v2 VerificationReceipt against a caller-authenticated verifier key
/// and log head. `head_json` uses the `<head>` shape documented on
/// `ratify_v2_verify_object` (including `verifier_id`).
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_verification_receipt_verify(
    wire: *const u8,
    wire_len: usize,
    verifier_ed25519: *const u8,
    verifier_ed25519_len: usize,
    verifier_ml_dsa_65: *const u8,
    verifier_ml_dsa_65_len: usize,
    head_json: *const c_char,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || {}, || {
        let r = decode_verification_receipt_v2(bytes(wire, wire_len, "wire")?)?;
        let key = HybridPublicKey {
            ed25519: bytes(verifier_ed25519, verifier_ed25519_len, "verifier_ed25519")?.to_vec(),
            ml_dsa_65: bytes(verifier_ml_dsa_65, verifier_ml_dsa_65_len, "verifier_ml_dsa_65")?
                .to_vec(),
        };
        let head = receipt_head(&json_arg(head_json, "head_json")?)?;
        verify_verification_receipt_v2(&r, &key, &head)?;
        Ok(())
    })
}

/// Check that a v2 VerificationReceipt is bound to a v2 ProofBundle (bundle
/// hash, verifier ID, agent ID, issuer IDs). Mismatch returns
/// `RatifyV2ReceiptBundleMismatch`.
#[no_mangle]
pub unsafe extern "C" fn ratify_v2_receipt_bundle_binding_check(
    receipt_wire: *const u8,
    receipt_wire_len: usize,
    bundle_wire: *const u8,
    bundle_wire_len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    run(err_out, || {}, || {
        let r = decode_verification_receipt_v2(bytes(receipt_wire, receipt_wire_len, "receipt_wire")?)?;
        let b = decode_proof_bundle_v2(bytes(bundle_wire, bundle_wire_len, "bundle_wire")?)?;
        check_verification_receipt_v2_bundle_binding(&r, &b)?;
        Ok(())
    })
}
