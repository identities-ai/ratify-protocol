//! Protocol v2 C ABI (`ratify_v2_*`).
//!
//! This surface is separate from the v1 ABI: every symbol carries the
//! `ratify_v2_` prefix and no v1 function changes behaviour. Callers check
//! `ratify_v2_abi_version()` against `RATIFY_V2_ABI_VERSION` before use.
//!
//! ## Result codes
//!
//! Every fallible `ratify_v2_*` function returns an `int32_t`:
//!
//! - `0` (`RatifyV2Ok`) on success;
//! - a positive `RatifyV2Code` naming the Protocol v2 failure class
//!   (the language-neutral class used by `testvectors/v2` and Go `errors_v2.go`);
//! - a negative `RatifyV2Code` for a caller/ABI error (NULL pointer, bad
//!   argument, internal error). These are never Protocol failure classes.
//!
//! `ratify_v2_error_class_str(code)` returns the stable class spelling.
//! When `err_out` is non-NULL a diagnostic message is written on failure; free
//! it with `ratify_error_free`. The return code is authoritative.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;

use ratify_protocol::v2::{
    check_verification_receipt_v2_bundle_binding, decode_delegation_cert_v2,
    decode_key_rotation_statement_v2, decode_proof_bundle_v2, decode_revocation_list_v2,
    decode_revocation_push_v2, decode_transaction_receipt_v2, decode_verification_receipt_v2,
    decode_witness_entry_v2, key_id_v2, valid_v2_id, verify_delegation_cert_v2_signature,
    verify_key_rotation_statement_v2, verify_proof_bundle_v2_signatures,
    verify_revocation_list_v2_signature, verify_revocation_push_v2_signature,
    verify_transaction_receipt_v2_signatures, verify_verification_receipt_v2,
    verify_witness_entry_v2, bundle_hash_v2, KeyRotationV2State, ReceiptV2Head, V2Error,
    V2ErrorClass, WitnessV2Head,
};
use ratify_protocol::{base64_std_decode, HybridPublicKey};
use serde_json::Value;

/// Version of the `ratify_v2_*` C ABI. Bumped on any incompatible change to a
/// `ratify_v2_*` signature, struct, or code value.
pub const RATIFY_V2_ABI_VERSION: u32 = 1;

/// Protocol major version implemented by the `ratify_v2_*` surface.
pub const RATIFY_V2_PROTOCOL_VERSION: u32 = 2;

/// Buffer size (including the trailing NUL) for a v2 key ID written by
/// `ratify_v2_key_id`: 64 lowercase hex characters + NUL.
pub const RATIFY_V2_KEY_ID_BUF_LEN: usize = 65;

/// Result codes for `ratify_v2_*` functions. Positive values are Protocol v2
/// failure classes; negative values are ABI errors. Values are stable within
/// one `RATIFY_V2_ABI_VERSION`; a C `switch` must include a `default` case.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2Code {
    RatifyV2Ok = 0,
    RatifyV2Unclassified = 1,
    RatifyV2Malformed = 2,
    RatifyV2UnsupportedObjectType = 3,
    RatifyV2KeyIdMismatch = 4,
    RatifyV2DelegationDigestMismatch = 5,
    RatifyV2ChainLinkageMismatch = 6,
    RatifyV2DuplicateCertificateRef = 7,
    RatifyV2InvalidSignature = 8,
    RatifyV2InvalidRequiredScope = 9,
    RatifyV2ConfigurationInvalid = 10,
    RatifyV2ExpectedChallengeUnavailable = 11,
    RatifyV2NamespaceMismatch = 12,
    RatifyV2StaleReplayEpoch = 13,
    RatifyV2VerifierIdMismatch = 14,
    RatifyV2ChallengeMismatch = 15,
    RatifyV2ChallengeNotFresh = 16,
    RatifyV2ExpectedAgentMismatch = 17,
    RatifyV2SessionContextMismatch = 18,
    RatifyV2ReceiverAudienceRequired = 19,
    RatifyV2ReceiverAudienceMismatch = 20,
    RatifyV2ReceiverBindingRejected = 21,
    RatifyV2ClaimReplay = 22,
    RatifyV2ClaimStoreUnavailable = 23,
    RatifyV2StatusKeyBindingMismatch = 24,
    RatifyV2ReceiptBundleMismatch = 25,
    RatifyV2BundleHashMismatch = 26,
    RatifyV2TransactionPartyMismatch = 27,
    RatifyV2TransactionContextMismatch = 28,
    RatifyV2TransactionSignatureSetInvalid = 29,
    RatifyV2RotationStateMismatch = 30,
    RatifyV2RotationKeyReused = 31,
    RatifyV2RotationFutureDated = 32,
    RatifyV2RotationFork = 33,
    RatifyV2RotationFrozen = 34,
    RatifyV2RotationRecoveryInvalid = 35,
    RatifyV2LogStateMismatch = 36,
    RatifyV2LogGap = 37,
    RatifyV2LogOrphan = 38,
    RatifyV2LogFork = 39,
    RatifyV2LogFrozen = 40,
    RatifyV2StatusObjectRejected = 41,
    /// A required pointer argument was NULL.
    RatifyV2ErrNullPointer = -1,
    /// A caller-supplied argument (length, UTF-8, context JSON) was invalid.
    RatifyV2ErrBadArgument = -2,
    /// An internal error (caught panic). Should not occur.
    RatifyV2ErrInternal = -3,
}

/// Object kinds accepted by `ratify_v2_verify_object`. Values are the SPEC-v2
/// signed object type codes (`kind_object_type_codes` in `objects.json`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatifyV2ObjectKind {
    RatifyV2KindDelegationCertificate = 1,
    RatifyV2KindProofBundle = 2,
    RatifyV2KindRevocationList = 3,
    RatifyV2KindKeyRotationStatement = 4,
    RatifyV2KindRevocationPush = 5,
    RatifyV2KindWitnessEntry = 6,
    RatifyV2KindTransactionReceipt = 7,
    RatifyV2KindVerificationReceipt = 8,
}

const CLASS_TABLE: &[(V2ErrorClass, RatifyV2Code, &CStr)] = {
    use RatifyV2Code::*;
    use V2ErrorClass::*;
    &[
        (Unclassified, RatifyV2Unclassified, c"unclassified"),
        (Malformed, RatifyV2Malformed, c"malformed"),
        (UnsupportedObjectType, RatifyV2UnsupportedObjectType, c"unsupported_object_type"),
        (KeyIdMismatch, RatifyV2KeyIdMismatch, c"key_id_mismatch"),
        (DelegationDigestMismatch, RatifyV2DelegationDigestMismatch, c"delegation_digest_mismatch"),
        (ChainLinkageMismatch, RatifyV2ChainLinkageMismatch, c"chain_linkage_mismatch"),
        (DuplicateCertificateRef, RatifyV2DuplicateCertificateRef, c"duplicate_certificate_ref"),
        (InvalidSignature, RatifyV2InvalidSignature, c"invalid_signature"),
        (InvalidRequiredScope, RatifyV2InvalidRequiredScope, c"invalid_required_scope"),
        (ConfigurationInvalid, RatifyV2ConfigurationInvalid, c"configuration_invalid"),
        (ExpectedChallengeUnavailable, RatifyV2ExpectedChallengeUnavailable, c"expected_challenge_unavailable"),
        (NamespaceMismatch, RatifyV2NamespaceMismatch, c"namespace_mismatch"),
        (StaleReplayEpoch, RatifyV2StaleReplayEpoch, c"stale_replay_epoch"),
        (VerifierIdMismatch, RatifyV2VerifierIdMismatch, c"verifier_id_mismatch"),
        (ChallengeMismatch, RatifyV2ChallengeMismatch, c"challenge_mismatch"),
        (ChallengeNotFresh, RatifyV2ChallengeNotFresh, c"challenge_not_fresh"),
        (ExpectedAgentMismatch, RatifyV2ExpectedAgentMismatch, c"expected_agent_mismatch"),
        (SessionContextMismatch, RatifyV2SessionContextMismatch, c"session_context_mismatch"),
        (ReceiverAudienceRequired, RatifyV2ReceiverAudienceRequired, c"receiver_audience_required"),
        (ReceiverAudienceMismatch, RatifyV2ReceiverAudienceMismatch, c"receiver_audience_mismatch"),
        (ReceiverBindingRejected, RatifyV2ReceiverBindingRejected, c"receiver_binding_rejected"),
        (ClaimReplay, RatifyV2ClaimReplay, c"claim_replay"),
        (ClaimStoreUnavailable, RatifyV2ClaimStoreUnavailable, c"claim_store_unavailable"),
        (StatusKeyBindingMismatch, RatifyV2StatusKeyBindingMismatch, c"status_key_binding_mismatch"),
        (ReceiptBundleMismatch, RatifyV2ReceiptBundleMismatch, c"receipt_bundle_mismatch"),
        (BundleHashMismatch, RatifyV2BundleHashMismatch, c"bundle_hash_mismatch"),
        (TransactionPartyMismatch, RatifyV2TransactionPartyMismatch, c"transaction_party_mismatch"),
        (TransactionContextMismatch, RatifyV2TransactionContextMismatch, c"transaction_context_mismatch"),
        (TransactionSignatureSetInvalid, RatifyV2TransactionSignatureSetInvalid, c"transaction_signature_set_invalid"),
        (RotationStateMismatch, RatifyV2RotationStateMismatch, c"rotation_state_mismatch"),
        (RotationKeyReused, RatifyV2RotationKeyReused, c"rotation_key_reused"),
        (RotationFutureDated, RatifyV2RotationFutureDated, c"rotation_future_dated"),
        (RotationFork, RatifyV2RotationFork, c"rotation_fork"),
        (RotationFrozen, RatifyV2RotationFrozen, c"rotation_frozen"),
        (RotationRecoveryInvalid, RatifyV2RotationRecoveryInvalid, c"rotation_recovery_invalid"),
        (LogStateMismatch, RatifyV2LogStateMismatch, c"log_state_mismatch"),
        (LogGap, RatifyV2LogGap, c"log_gap"),
        (LogOrphan, RatifyV2LogOrphan, c"log_orphan"),
        (LogFork, RatifyV2LogFork, c"log_fork"),
        (LogFrozen, RatifyV2LogFrozen, c"log_frozen"),
        (StatusObjectRejected, RatifyV2StatusObjectRejected, c"status_object_rejected"),
    ]
};

fn class_code(class: V2ErrorClass) -> RatifyV2Code {
    CLASS_TABLE
        .iter()
        .find(|(c, _, _)| *c == class)
        .map(|(_, code, _)| *code)
        .unwrap_or(RatifyV2Code::RatifyV2Unclassified)
}

/// An ABI-layer failure: either a Protocol class or a caller error.
struct Failure {
    code: RatifyV2Code,
    message: String,
}

impl From<V2Error> for Failure {
    fn from(e: V2Error) -> Self {
        Failure {
            code: class_code(e.class),
            message: e.message,
        }
    }
}

fn bad_arg(message: impl Into<String>) -> Failure {
    Failure {
        code: RatifyV2Code::RatifyV2ErrBadArgument,
        message: message.into(),
    }
}

fn null_arg(name: &str) -> Failure {
    Failure {
        code: RatifyV2Code::RatifyV2ErrNullPointer,
        message: format!("{name} is null"),
    }
}

type AbiResult<T> = Result<T, Failure>;

/// Run `f` under the C ABI panic guard, map its outcome to an `int32_t` code,
/// and write any diagnostic. A caught panic runs `reset` (which puts every
/// output parameter in a defined state) and returns `RatifyV2ErrInternal`
/// rather than unwinding into C.
fn run(
    err_out: *mut *mut c_char,
    reset: impl FnOnce(),
    f: impl FnOnce() -> AbiResult<()>,
) -> i32 {
    crate::guard::ffi_guard(
        || {
            reset();
            crate::set_err(err_out, &format!("internal: {}", crate::guard::PANIC_MESSAGE));
            RatifyV2Code::RatifyV2ErrInternal as i32
        },
        || match f() {
            Ok(()) => RatifyV2Code::RatifyV2Ok as i32,
            Err(f) => {
                crate::set_err(
                    err_out,
                    &format!("{}: {}", class_str(f.code as i32), f.message),
                );
                f.code as i32
            }
        },
    )
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize, name: &str) -> AbiResult<&'a [u8]> {
    if ptr.is_null() {
        return Err(null_arg(name));
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn json_arg(ptr: *const c_char, name: &str) -> AbiResult<Value> {
    if ptr.is_null() {
        return Err(null_arg(name));
    }
    let s = CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| bad_arg(format!("{name} contains invalid UTF-8")))?;
    serde_json::from_str(s).map_err(|e| bad_arg(format!("{name}: {e}")))
}

fn field<'a>(v: &'a Value, name: &str) -> AbiResult<&'a Value> {
    v.get(name)
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

fn b64_value(v: &Value, name: &str) -> AbiResult<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| bad_arg(format!("context \"{name}\" must be a base64 string")))?;
    base64_std_decode(s).map_err(|e| bad_arg(format!("context \"{name}\": {e}")))
}

fn key_field(v: &Value, name: &str) -> AbiResult<HybridPublicKey> {
    serde_json::from_value(field(v, name)?.clone())
        .map_err(|e| bad_arg(format!("context \"{name}\" must be a hybrid public key: {e}")))
}

fn accepted_digests(h: &Value) -> AbiResult<std::collections::BTreeMap<i64, Vec<u8>>> {
    let mut out = std::collections::BTreeMap::new();
    match h.get("accepted_digests_b64") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                let seq = k
                    .parse::<i64>()
                    .map_err(|_| bad_arg(format!("accepted_digests_b64 key {k:?} is not an integer")))?;
                out.insert(seq, b64_value(v, "accepted_digests_b64")?);
            }
        }
        Some(_) => return Err(bad_arg("accepted_digests_b64 must be an object")),
    }
    Ok(out)
}

fn frozen(h: &Value) -> AbiResult<bool> {
    match h.get("frozen") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad_arg("context \"frozen\" must be a boolean")),
    }
}

fn witness_head(h: &Value) -> AbiResult<WitnessV2Head> {
    Ok(WitnessV2Head {
        log_id: str_field(h, "log_id")?,
        sequence: int_field(h, "sequence")?,
        head_hash: b64_value(field(h, "head_hash_b64")?, "head_hash_b64")?,
        accepted_digests: accepted_digests(h)?,
        frozen: frozen(h)?,
    })
}

fn receipt_head(h: &Value) -> AbiResult<ReceiptV2Head> {
    let w = witness_head(h)?;
    Ok(ReceiptV2Head {
        log_id: w.log_id,
        verifier_id: str_field(h, "verifier_id")?,
        sequence: w.sequence,
        head_hash: w.head_hash,
        accepted_digests: w.accepted_digests,
        frozen: w.frozen,
    })
}

fn rotation_state(v: &Value) -> AbiResult<KeyRotationV2State> {
    let used = field(v, "used_key_ids")?
        .as_array()
        .ok_or_else(|| bad_arg("context \"used_key_ids\" must be an array"))?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad_arg("context \"used_key_ids\" entries must be strings"))
        })
        .collect::<AbiResult<Vec<_>>>()?;
    Ok(KeyRotationV2State {
        authority_id: str_field(v, "authority_id")?,
        recovery_epoch: int_field(v, "recovery_epoch")?,
        role: str_field(v, "role")?,
        sequence: int_field(v, "sequence")?,
        head_hash: b64_value(field(v, "head_hash_b64")?, "head_hash_b64")?,
        current_key: key_field(v, "current_key")?,
        used_key_ids: used,
    })
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

fn class_cstr(code: i32) -> &'static CStr {
    match code {
        0 => c"ok",
        -1 => c"null_pointer",
        -2 => c"bad_argument",
        -3 => c"internal",
        c => CLASS_TABLE
            .iter()
            .find(|(_, k, _)| *k as i32 == c)
            .map(|(_, _, name)| *name)
            .unwrap_or(c"unknown"),
    }
}

fn class_str(code: i32) -> &'static str {
    class_cstr(code).to_str().unwrap_or("unknown")
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

/// Returns `RATIFY_V2_ABI_VERSION` as compiled into this library. A caller
/// built against a header with a different value must not use `ratify_v2_*`.
#[no_mangle]
pub extern "C" fn ratify_v2_abi_version() -> u32 {
    crate::guard::ffi_guard(
        // 0 matches no header's RATIFY_V2_ABI_VERSION, so a caller refuses the ABI.
        || 0,
        || RATIFY_V2_ABI_VERSION,
    )
}

/// Returns the Protocol major version implemented by `ratify_v2_*` (2).
#[no_mangle]
pub extern "C" fn ratify_v2_protocol_version() -> u32 {
    crate::guard::ffi_guard(|| 0, || RATIFY_V2_PROTOCOL_VERSION)
}

/// Returns the library package version (e.g. "2.0.0-alpha.1"). Statically
/// allocated — do NOT free. Same value as `ratify_version()`.
#[no_mangle]
pub extern "C" fn ratify_v2_library_version() -> *const c_char {
    crate::guard::ffi_guard(
        || c"".as_ptr(),
        || concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char,
    )
}

/// Returns the stable spelling for a `ratify_v2_*` result code: "ok", a
/// Protocol v2 failure class (e.g. "invalid_signature"), "null_pointer",
/// "bad_argument", "internal", or "unknown". Statically allocated — do NOT free.
#[no_mangle]
pub extern "C" fn ratify_v2_error_class_str(code: i32) -> *const c_char {
    crate::guard::ffi_guard(|| c"internal".as_ptr(), || class_cstr(code).as_ptr())
}

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
