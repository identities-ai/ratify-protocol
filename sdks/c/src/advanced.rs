//! Advanced Ratify Protocol C bindings — parity with Go/TS/Python/Rust SDKs.
//!
//! This module adds the remaining operations beyond basic verify/delegate:
//!
//! - Session tokens          — fast-path multi-turn verification (embedded streaming)
//! - Verification receipts   — tamper-evident on-device audit proofs
//! - Revocation lists        — offline signed revocation (no network callback needed)
//! - Revocation push         — real-time delta revocation notifications
//! - Witness entries         — hash-chain audit witness log
//! - Transaction receipts    — multi-party atomic transaction attestations
//! - Key rotation            — device and identity key lifecycle management
//! - Scope utilities         — scope intersection, expansion, sensitivity checks
//! - Policy verdicts         — HMAC-bound cached policy decisions
//! - Utility hashes          — bundle_hash, chain_hash, verifier_context_hash
//!
//! All functions follow the same conventions as `lib.rs`:
//! - Null pointers checked at entry; return `RatifyErrNullPointer`.
//! - Fixed-size buffers (`_len` params) validated to exact expected size.
//! - Non-UTF-8 strings return `RatifyErrEncoding`.
//! - Entropy failure panics (system failure).
//! - All heap allocations freed by the caller with the matching `_free` function.

#![allow(clippy::missing_safety_doc)]
#![allow(deprecated)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar};
use std::slice;

use ratify_protocol::{
    bundle_hash as sdk_bundle_hash, chain_hash as sdk_chain_hash,
    expand_scopes, has_scope, intersect_scopes, is_sensitive,
    issue_key_rotation_statement, issue_policy_verdict, issue_revocation_list,
    issue_revocation_push, issue_session_token, issue_verification_receipt,
    issue_witness_entry, sign_transaction_receipt_party,
    validate_scopes, verify_key_rotation_statement, verify_policy_verdict,
    verify_revocation_list, verify_revocation_push, verify_session_token_e,
    verify_transaction_receipt, verify_verification_receipt, verify_witness_entry,
    HybridPublicKey, HybridSignature,
    KeyRotationStatement, PolicyVerdict,
    RevocationList, RevocationPush, SessionToken,
    TransactionReceipt, VerificationReceipt,
    WitnessEntry,
};

use crate::{
    set_err, cstr_to_string, new_cstring,
    RatifyHumanRoot, RatifyAgent, RatifyProofBundle, RatifyVerifyResult,
    RatifyStatus, RatifyVerifierContext,
};

// ============================================================================
// Opaque handle types
// ============================================================================

pub struct RatifySessionToken(SessionToken);
pub struct RatifyReceipt(VerificationReceipt);
pub struct RatifyRevocationList(RevocationList);
pub struct RatifyRevocationPush(RevocationPush);
pub struct RatifyWitnessEntry(WitnessEntry);
pub struct RatifyTransactionReceipt(TransactionReceipt);
pub struct RatifyKeyRotation(KeyRotationStatement);
pub struct RatifyPolicyVerdict(PolicyVerdict);

// ============================================================================
// Helper: validate a secret/hash buffer and return a slice
// ============================================================================

unsafe fn validated_buf<'a>(
    ptr: *const c_uchar,
    len: usize,
    min_len: usize,
    name: &str,
    err_out: *mut *mut c_char,
) -> Option<&'a [u8]> {
    if ptr.is_null() {
        set_err(err_out, &format!("{name} is null"));
        return None;
    }
    if len < min_len {
        set_err(err_out, &format!("{name}_len must be >= {min_len}, got {len}"));
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

/// Validate a NULLABLE fixed-size buffer (NULL+0 = absent, returns `Some(&[])`).
/// Use only for truly optional fields like `prev_hash` (where absence means genesis/zeros).
/// For MANDATORY fields, call `mandatory_exact_buf` instead.
unsafe fn exact_buf<'a>(
    ptr: *const c_uchar,
    len: usize,
    exact: usize,
    name: &str,
    err_out: *mut *mut c_char,
) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 { return Some(&[]); } // NULL+0 = absent (caller uses genesis/zeros)
        set_err(err_out, &format!("{name} is null but {name}_len is {len}"));
        return None;
    }
    if len != exact {
        set_err(err_out, &format!("{name}_len must be exactly {exact}, got {len}"));
        return None;
    }
    Some(slice::from_raw_parts(ptr, exact))
}

/// Validate a MANDATORY fixed-size buffer, returning the appropriate error status.
///
/// Returns `Ok(&[u8])` on success.
/// Returns `Err(RatifyErrNullPointer)` if `ptr` is null.
/// Returns `Err(RatifyErrBadArgument)` if `len != exact`.
///
/// Use only for required fields (e.g. `context_hash` which must be exactly 32 bytes).
/// Use `exact_buf` for nullable optional fields (e.g. `prev_hash` where NULL+0 = genesis).
unsafe fn mandatory_exact_buf<'a>(
    ptr: *const c_uchar,
    len: usize,
    exact: usize,
    name: &str,
    err_out: *mut *mut c_char,
) -> Result<&'a [u8], RatifyStatus> {
    if ptr.is_null() {
        set_err(err_out, &format!("{name} is null"));
        return Err(RatifyStatus::RatifyErrNullPointer);
    }
    if len != exact {
        set_err(err_out, &format!("{name}_len must be exactly {exact}, got {len}"));
        return Err(RatifyStatus::RatifyErrBadArgument);
    }
    Ok(slice::from_raw_parts(ptr, exact))
}

fn map_sdk_err(err_out: *mut *mut c_char, e: String) -> RatifyStatus {
    set_err(err_out, &e);
    RatifyStatus::RatifyErrCrypto
}

fn json_err(err_out: *mut *mut c_char, label: &str, e: impl std::fmt::Display) -> RatifyStatus {
    set_err(err_out, &format!("{label}: {e}"));
    RatifyStatus::RatifyErrJson
}

/// Returns `RatifyErrNullPointer` if `ptr` is null, otherwise succeeds.
/// Use this as the first guard in pure-verify functions that require a JSON input.
fn check_not_null(ptr: *const c_char, name: &str, err_out: *mut *mut c_char) -> Option<()> {
    if ptr.is_null() {
        set_err(err_out, &format!("{name} is null"));
        None
    } else {
        Some(())
    }
}

// ============================================================================
// Session Tokens
// ============================================================================

/// Issue a SessionToken after a successful `ratify_verify_bundle` call.
///
/// Session tokens let subsequent turns skip full chain re-verification —
/// critical for embedded streaming and multi-turn Physical AI interactions.
/// The verifier HMAC-signs the cached result with `session_secret`.
///
/// - `bundle` — the ProofBundle that was verified.
/// - `result` — the VerifyResult from ratify_verify_bundle (must be valid).
/// - `session_id` — caller-assigned null-terminated session identifier.
/// - `issued_at_unix` / `valid_until_unix` — validity window.
/// - `session_secret` / `session_secret_len` — HMAC key, minimum 1 byte.
///   Use at least 32 bytes for security. Never share across verifier instances.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_issue(
    bundle: *const RatifyProofBundle,
    result: *const RatifyVerifyResult,
    session_id: *const c_char,
    issued_at_unix: i64,
    valid_until_unix: i64,
    session_secret: *const c_uchar,
    session_secret_len: usize,
    out: *mut *mut RatifySessionToken,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if bundle.is_null() || result.is_null() || out.is_null() {
        set_err(err_out, "bundle, result, and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let session_id_str = match cstr_to_string(session_id, "session_id", err_out) {
        Some(s) => s, None => return RatifyStatus::RatifyErrEncoding,
    };
    let secret = match validated_buf(session_secret, session_secret_len, 1, "session_secret", err_out) {
        Some(b) => b, None => return RatifyStatus::RatifyErrBadArgument,
    };

    match issue_session_token(
        &(*bundle).0,
        &(*result).0,
        &session_id_str,
        issued_at_unix,
        valid_until_unix,
        secret,
    ) {
        Ok(tok) => { *out = Box::into_raw(Box::new(RatifySessionToken(tok))); RatifyStatus::RatifyOk }
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Verify a SessionToken JSON string against the session secret and current time.
///
/// Returns `RatifyOk` if the token is cryptographically valid, within its
/// validity window, and the HMAC matches. Returns `RatifyErrCrypto` otherwise;
/// `*err_out` contains the specific rejection reason.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_verify(
    token_json: *const c_char,
    session_secret: *const c_uchar,
    session_secret_len: usize,
    now_unix: i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(token_json, "token_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let token_str = match cstr_to_string(token_json, "token_json", err_out) {
        Some(s) => s, None => return RatifyStatus::RatifyErrJson,
    };
    let token: SessionToken = match serde_json::from_str(&token_str) {
        Ok(t) => t,
        Err(e) => return json_err(err_out, "token_json", e),
    };
    let secret = match validated_buf(session_secret, session_secret_len, 1, "session_secret", err_out) {
        Some(b) => b, None => return RatifyStatus::RatifyErrBadArgument,
    };
    match verify_session_token_e(&token, secret, now_unix) {
        Ok(()) => RatifyStatus::RatifyOk,
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Serialise a SessionToken to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_to_json(
    handle: *const RatifySessionToken,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) {
        Ok(s) => new_cstring(&s),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Deserialise a SessionToken from JSON. Free with `ratify_session_token_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_from_json(
    json: *const c_char,
    out: *mut *mut RatifySessionToken,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<SessionToken>(&s) {
        Ok(t) => { *out = Box::into_raw(Box::new(RatifySessionToken(t))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "session_token_from_json", e),
    }
}

/// Free a `RatifySessionToken` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_free(handle: *mut RatifySessionToken) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Verification Receipts
// ============================================================================

/// Issue a signed VerificationReceipt for an agent verification event.
///
/// The receipt is hybrid-signed by `verifier`'s keypair and chains to
/// `prev_hash` (32 bytes, or NULL/0 for the genesis receipt). Receipts form
/// a tamper-evident chain: any missing or backdated entry is detectable by
/// computing SHA-256 over each receipt's signable bytes.
///
/// - `verifier` — the verifier's HumanRoot handle (provides ID + signing key).
/// - `prev_hash` / `prev_hash_len` — NULL + 0 = genesis (zeros filled automatically).
///   Non-NULL: must be exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_issue(
    bundle: *const RatifyProofBundle,
    result: *const RatifyVerifyResult,
    verifier: *const RatifyHumanRoot,
    prev_hash: *const c_uchar,
    prev_hash_len: usize,
    verified_at_unix: i64,
    out: *mut *mut RatifyReceipt,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if bundle.is_null() || result.is_null() || verifier.is_null() || out.is_null() {
        set_err(err_out, "bundle, result, verifier, and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let prev: Option<&[u8]> = if prev_hash.is_null() {
        None
    } else {
        match exact_buf(prev_hash, prev_hash_len, 32, "prev_hash", err_out) {
            Some(b) => Some(b), None => return RatifyStatus::RatifyErrBadArgument,
        }
    };

    let v = &*verifier;
    match issue_verification_receipt(
        &(*bundle).0,
        &(*result).0,
        &v.0.id,
        &v.0.public_key,
        &v.1,
        prev,
        verified_at_unix,
    ) {
        Ok(r) => { *out = Box::into_raw(Box::new(RatifyReceipt(r))); RatifyStatus::RatifyOk }
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Verify a VerificationReceipt JSON string's hybrid signature.
/// Returns `RatifyOk` if both Ed25519 and ML-DSA-65 components verify.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_verify(
    receipt_json: *const c_char,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(receipt_json, "receipt_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(receipt_json, "receipt_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let r: VerificationReceipt = match serde_json::from_str(&s) {
        Ok(r) => r, Err(e) => return json_err(err_out, "receipt_json", e),
    };
    match verify_verification_receipt(&r) {
        Ok(()) => RatifyStatus::RatifyOk,
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Compute the SHA-256 hash of a ProofBundle's canonical bytes.
/// Writes exactly 32 bytes to `out_32`. Use as `prev_hash` for the next receipt.
#[no_mangle]
pub unsafe extern "C" fn ratify_bundle_hash(
    bundle: *const RatifyProofBundle,
    out_32: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if bundle.is_null() || out_32.is_null() {
        set_err(err_out, "bundle and out_32 must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    match sdk_bundle_hash(&(*bundle).0) {
        Ok(h) => {
            if h.len() != 32 { set_err(err_out, "bundle_hash: unexpected hash length"); return RatifyStatus::RatifyErrInternal; }
            slice::from_raw_parts_mut(out_32, 32).copy_from_slice(&h);
            RatifyStatus::RatifyOk
        }
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Compute the SHA-256 hash of a VerificationReceipt's canonical bytes.
/// Writes exactly 32 bytes to `out_32`. Use as `prev_hash` for the next receipt.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_hash(
    handle: *const RatifyReceipt,
    out_32: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if handle.is_null() || out_32.is_null() {
        set_err(err_out, "handle and out_32 must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    match ratify_protocol::receipt_hash(&(*handle).0) {
        Ok(h) => {
            if h.len() != 32 { set_err(err_out, "receipt_hash: unexpected hash length"); return RatifyStatus::RatifyErrInternal; }
            slice::from_raw_parts_mut(out_32, 32).copy_from_slice(&h);
            RatifyStatus::RatifyOk
        }
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Serialise a VerificationReceipt to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_to_json(
    handle: *const RatifyReceipt,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) {
        Ok(s) => new_cstring(&s),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Deserialise a VerificationReceipt from JSON. Free with `ratify_receipt_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_from_json(
    json: *const c_char,
    out: *mut *mut RatifyReceipt,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<VerificationReceipt>(&s) {
        Ok(r) => { *out = Box::into_raw(Box::new(RatifyReceipt(r))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "receipt_from_json", e),
    }
}

/// Free a `RatifyReceipt` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_receipt_free(handle: *mut RatifyReceipt) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Revocation Lists
// ============================================================================

/// Create and sign a RevocationList from a JSON array of revoked cert IDs.
///
/// The list is signed with `issuer`'s private key. Verifiers can check
/// the signature offline without a network callback. Suitable for
/// air-gapped embedded deployments.
///
/// - `revoked_certs_json` — JSON array of cert_id hex strings.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_issue(
    issuer: *const RatifyHumanRoot,
    revoked_certs_json: *const c_char,
    updated_at_unix: i64,
    out: *mut *mut RatifyRevocationList,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if issuer.is_null() || out.is_null() {
        set_err(err_out, "issuer and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let certs_str = match cstr_to_string(revoked_certs_json, "revoked_certs_json", err_out) {
        Some(s) => s, None => return RatifyStatus::RatifyErrJson,
    };
    let revoked_certs: Vec<String> = match serde_json::from_str(&certs_str) {
        Ok(v) => v, Err(e) => return json_err(err_out, "revoked_certs_json", e),
    };

    let issuer_ref = &*issuer;
    let mut list = RevocationList {
        issuer_id: issuer_ref.0.id.clone(),
        updated_at: updated_at_unix,
        revoked_certs,
        signature: HybridSignature { ed25519: vec![0u8; 64], ml_dsa_65: vec![0u8; 3309] },
    };
    issue_revocation_list(&mut list, &issuer_ref.1);
    *out = Box::into_raw(Box::new(RatifyRevocationList(list)));
    RatifyStatus::RatifyOk
}

/// Verify a RevocationList's hybrid signature against `issuer_pub_json`.
///
/// `issuer_pub_json` — the issuer's public key JSON (`{"ed25519":"...","ml_dsa_65":"..."}`).
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_verify(
    list_json: *const c_char,
    issuer_pub_json: *const c_char,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(list_json, "list_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    if check_not_null(issuer_pub_json, "issuer_pub_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let list_str = match cstr_to_string(list_json, "list_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let pub_str  = match cstr_to_string(issuer_pub_json, "issuer_pub_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let list: RevocationList = match serde_json::from_str(&list_str) { Ok(l) => l, Err(e) => return json_err(err_out, "list_json", e) };
    let pub_key: HybridPublicKey = match serde_json::from_str(&pub_str) { Ok(k) => k, Err(e) => return json_err(err_out, "issuer_pub_json", e) };
    if verify_revocation_list(&list, &pub_key) { RatifyStatus::RatifyOk } else { set_err(err_out, "revocation_list signature invalid"); RatifyStatus::RatifyErrCrypto }
}

/// Returns 1 if `cert_id` appears in the revocation list, 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_contains(
    handle: *const RatifyRevocationList,
    cert_id: *const c_char,
) -> c_int {
    if handle.is_null() || cert_id.is_null() { return 0; }
    let id = match CStr::from_ptr(cert_id).to_str() { Ok(s) => s, Err(_) => return 0 };
    (*handle).0.revoked_certs.iter().any(|c| c == id) as c_int
}

/// Serialise a RevocationList to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_to_json(
    handle: *const RatifyRevocationList,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Deserialise a RevocationList from JSON. Free with `ratify_revocation_list_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_from_json(
    json: *const c_char, out: *mut *mut RatifyRevocationList, err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<RevocationList>(&s) {
        Ok(l) => { *out = Box::into_raw(Box::new(RatifyRevocationList(l))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "revocation_list_from_json", e),
    }
}

/// Free a `RatifyRevocationList` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_free(handle: *mut RatifyRevocationList) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Revocation Push
// ============================================================================

/// Issue a signed RevocationPush — a real-time delta notification of newly
/// revoked cert IDs. Used with push-subscription infrastructure; verifiers
/// apply deltas to their local revocation cache.
///
/// - `new_revoked_json` — JSON array of newly revoked cert_id strings.
/// - `seq_no` — monotonically increasing sequence number per issuer.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_issue(
    issuer: *const RatifyHumanRoot,
    new_revoked_json: *const c_char,
    seq_no: i64,
    pushed_at_unix: i64,
    out: *mut *mut RatifyRevocationPush,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if issuer.is_null() || out.is_null() { set_err(err_out, "issuer and out must be non-null"); return RatifyStatus::RatifyErrNullPointer; }
    let entries_str = match cstr_to_string(new_revoked_json, "new_revoked_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let entries: Vec<String> = match serde_json::from_str(&entries_str) { Ok(v) => v, Err(e) => return json_err(err_out, "new_revoked_json", e) };
    let issuer_ref = &*issuer;
    let mut push = RevocationPush {
        issuer_id: issuer_ref.0.id.clone(),
        seq_no,
        entries,
        pushed_at: pushed_at_unix,
        signature: HybridSignature { ed25519: vec![0u8; 64], ml_dsa_65: vec![0u8; 3309] },
    };
    issue_revocation_push(&mut push, &issuer_ref.1);
    *out = Box::into_raw(Box::new(RatifyRevocationPush(push)));
    RatifyStatus::RatifyOk
}

/// Verify a RevocationPush's signature against `issuer_pub_json`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_verify(
    push_json: *const c_char,
    issuer_pub_json: *const c_char,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(push_json, "push_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    if check_not_null(issuer_pub_json, "issuer_pub_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let push_str = match cstr_to_string(push_json, "push_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let pub_str  = match cstr_to_string(issuer_pub_json, "issuer_pub_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let push: RevocationPush = match serde_json::from_str(&push_str) { Ok(p) => p, Err(e) => return json_err(err_out, "push_json", e) };
    let pub_key: HybridPublicKey = match serde_json::from_str(&pub_str) { Ok(k) => k, Err(e) => return json_err(err_out, "issuer_pub_json", e) };
    if verify_revocation_push(&push, &pub_key) { RatifyStatus::RatifyOk } else { set_err(err_out, "revocation_push signature invalid"); RatifyStatus::RatifyErrCrypto }
}

/// Serialise a RevocationPush to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_to_json(handle: *const RatifyRevocationPush, err_out: *mut *mut c_char) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Deserialise a RevocationPush from JSON. Free with `ratify_revocation_push_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_from_json(json: *const c_char, out: *mut *mut RatifyRevocationPush, err_out: *mut *mut c_char) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<RevocationPush>(&s) {
        Ok(p) => { *out = Box::into_raw(Box::new(RatifyRevocationPush(p))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "revocation_push_from_json", e),
    }
}

/// Free a `RatifyRevocationPush` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_free(handle: *mut RatifyRevocationPush) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Witness Entries
// ============================================================================

/// Issue a signed WitnessEntry for a hash-chain audit log.
///
/// - `entry_data` / `entry_data_len` — raw bytes of the witnessed payload.
/// - `prev_hash` / `prev_hash_len` — NULL + 0 = genesis (zeros); otherwise 32 bytes.
/// - `witness` — the witness's HumanRoot handle (ID + signing key).
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_issue(
    witness: *const RatifyHumanRoot,
    entry_data: *const c_uchar,
    entry_data_len: usize,
    timestamp_unix: i64,
    prev_hash: *const c_uchar,
    prev_hash_len: usize,
    out: *mut *mut RatifyWitnessEntry,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if witness.is_null() || entry_data.is_null() || out.is_null() {
        set_err(err_out, "witness, entry_data, and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let data = slice::from_raw_parts(entry_data, entry_data_len).to_vec();
    let prev: Vec<u8> = if prev_hash.is_null() || prev_hash_len == 0 {
        vec![0u8; 32]
    } else {
        match exact_buf(prev_hash, prev_hash_len, 32, "prev_hash", err_out) {
            Some(b) => b.to_vec(), None => return RatifyStatus::RatifyErrBadArgument,
        }
    };
    let witness_ref = &*witness;
    let mut entry = WitnessEntry {
        prev_hash: prev,
        entry_data: data,
        timestamp: timestamp_unix,
        witness_id: witness_ref.0.id.clone(),
        signature: HybridSignature { ed25519: vec![0u8; 64], ml_dsa_65: vec![0u8; 3309] },
    };
    issue_witness_entry(&mut entry, &witness_ref.1);
    *out = Box::into_raw(Box::new(RatifyWitnessEntry(entry)));
    RatifyStatus::RatifyOk
}

/// Verify a WitnessEntry's signature against `witness_pub_json`.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_verify(
    entry_json: *const c_char,
    witness_pub_json: *const c_char,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(entry_json, "entry_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    if check_not_null(witness_pub_json, "witness_pub_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let entry_str = match cstr_to_string(entry_json, "entry_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let pub_str   = match cstr_to_string(witness_pub_json, "witness_pub_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let entry: WitnessEntry = match serde_json::from_str(&entry_str) { Ok(e) => e, Err(e) => return json_err(err_out, "entry_json", e) };
    let pub_key: HybridPublicKey = match serde_json::from_str(&pub_str) { Ok(k) => k, Err(e) => return json_err(err_out, "witness_pub_json", e) };
    if verify_witness_entry(&entry, &pub_key) { RatifyStatus::RatifyOk } else { set_err(err_out, "witness_entry signature invalid"); RatifyStatus::RatifyErrCrypto }
}

/// Serialise a WitnessEntry to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_to_json(handle: *const RatifyWitnessEntry, err_out: *mut *mut c_char) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Deserialise a WitnessEntry from JSON. Free with `ratify_witness_entry_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_from_json(json: *const c_char, out: *mut *mut RatifyWitnessEntry, err_out: *mut *mut c_char) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<WitnessEntry>(&s) {
        Ok(e) => { *out = Box::into_raw(Box::new(RatifyWitnessEntry(e))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "witness_entry_from_json", e),
    }
}

/// Free a `RatifyWitnessEntry` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_free(handle: *mut RatifyWitnessEntry) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Key Rotation Statements
// ============================================================================

/// Issue a KeyRotationStatement signed by BOTH the old and new root keys.
///
/// Use this when rotating a device's identity keypair (e.g., after key
/// compromise or scheduled rotation). The statement proves continuity:
/// the old key authorises the new key.
///
/// - `old_root` — the old HumanRoot handle (will sign).
/// - `new_root` — the new HumanRoot handle (will also sign).
/// - `reason` — null-terminated reason string (e.g., "scheduled_rotation").
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_issue(
    old_root: *const RatifyHumanRoot,
    new_root: *const RatifyHumanRoot,
    reason: *const c_char,
    rotated_at_unix: i64,
    out: *mut *mut RatifyKeyRotation,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if old_root.is_null() || new_root.is_null() || out.is_null() {
        set_err(err_out, "old_root, new_root, and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let reason_str = match cstr_to_string(reason, "reason", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let old_ref = &*old_root;
    let new_ref = &*new_root;
    let mut stmt = KeyRotationStatement {
        version: 1,
        old_id:    old_ref.0.id.clone(),
        old_pub_key: old_ref.0.public_key.clone(),
        new_id:    new_ref.0.id.clone(),
        new_pub_key: new_ref.0.public_key.clone(),
        rotated_at: rotated_at_unix,
        reason: reason_str,
        signature_old: HybridSignature { ed25519: vec![0u8; 64], ml_dsa_65: vec![0u8; 3309] },
        signature_new: HybridSignature { ed25519: vec![0u8; 64], ml_dsa_65: vec![0u8; 3309] },
    };
    // issue_key_rotation_statement is infallible in the Rust SDK
    issue_key_rotation_statement(&mut stmt, &old_ref.1, &new_ref.1);
    *out = Box::into_raw(Box::new(RatifyKeyRotation(stmt)));
    RatifyStatus::RatifyOk
}

/// Verify a KeyRotationStatement — checks both old and new key signatures.
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_verify(
    stmt_json: *const c_char,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(stmt_json, "stmt_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(stmt_json, "stmt_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let stmt: KeyRotationStatement = match serde_json::from_str(&s) { Ok(st) => st, Err(e) => return json_err(err_out, "stmt_json", e) };
    match verify_key_rotation_statement(&stmt) {
        Ok(()) => RatifyStatus::RatifyOk,
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Serialise a KeyRotationStatement to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_to_json(handle: *const RatifyKeyRotation, err_out: *mut *mut c_char) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Deserialise a KeyRotationStatement from JSON. Free with `ratify_key_rotation_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_from_json(json: *const c_char, out: *mut *mut RatifyKeyRotation, err_out: *mut *mut c_char) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<KeyRotationStatement>(&s) {
        Ok(st) => { *out = Box::into_raw(Box::new(RatifyKeyRotation(st))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "key_rotation_from_json", e),
    }
}

/// Free a `RatifyKeyRotation` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_free(handle: *mut RatifyKeyRotation) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Scope Utilities
// ============================================================================

/// Returns 1 if `required` appears in the JSON array of granted scopes.
/// Returns 0 if absent, if either pointer is null, or on parse error.
#[no_mangle]
pub unsafe extern "C" fn ratify_scope_has(
    granted_json: *const c_char,
    required: *const c_char,
) -> c_int {
    if granted_json.is_null() || required.is_null() { return 0; }
    let granted_str = match CStr::from_ptr(granted_json).to_str() { Ok(s) => s, Err(_) => return 0 };
    let req_str     = match CStr::from_ptr(required).to_str()     { Ok(s) => s, Err(_) => return 0 };
    let granted: Vec<String> = match serde_json::from_str(granted_str) { Ok(v) => v, Err(_) => return 0 };
    has_scope(&granted, req_str) as c_int
}

/// Returns 1 if `scope` is marked sensitive in the protocol vocabulary
/// (i.e., requires high-assurance verification), 0 otherwise.
/// NULL or non-UTF-8 input returns 0.
#[no_mangle]
pub unsafe extern "C" fn ratify_scope_is_sensitive(scope: *const c_char) -> c_int {
    if scope.is_null() { return 0; }
    match CStr::from_ptr(scope).to_str() {
        Ok(s) => is_sensitive(s) as c_int,
        Err(_) => 0,
    }
}

/// Expand wildcard scopes to their concrete members.
/// Input: JSON array e.g. `["meeting:*"]`.
/// Output: JSON array of expanded concrete scopes.
/// Free with `ratify_string_free`. Returns NULL on parse error (`*err_out` set).
#[no_mangle]
pub unsafe extern "C" fn ratify_scopes_expand(
    scopes_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(scopes_json, "scopes_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let scopes: Vec<String> = match serde_json::from_str(&s) {
        Ok(v) => v,
        Err(e) => { set_err(err_out, &format!("scopes_json: {e}")); return std::ptr::null_mut(); }
    };
    let expanded = expand_scopes(&scopes);
    match serde_json::to_string(&expanded) {
        Ok(out) => new_cstring(&out),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Compute the intersection of multiple scope arrays.
///
/// `scope_arrays_json` — pointer to `count` null-terminated JSON array strings.
/// Returns JSON array of scopes present in ALL arrays. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_scopes_intersect(
    scope_arrays_json: *const *const c_char,
    count: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if scope_arrays_json.is_null() {
        set_err(err_out, "scope_arrays_json is null");
        return std::ptr::null_mut();
    }
    let mut parsed: Vec<Vec<String>> = Vec::with_capacity(count);
    for i in 0..count {
        let ptr = *scope_arrays_json.add(i);
        if ptr.is_null() { set_err(err_out, &format!("scope_arrays_json[{i}] is null")); return std::ptr::null_mut(); }
        let s = match CStr::from_ptr(ptr).to_str() { Ok(s) => s, Err(_) => { set_err(err_out, &format!("scope_arrays_json[{i}] invalid UTF-8")); return std::ptr::null_mut(); } };
        match serde_json::from_str::<Vec<String>>(s) {
            Ok(v) => parsed.push(v),
            Err(e) => { set_err(err_out, &format!("scope_arrays_json[{i}]: {e}")); return std::ptr::null_mut(); }
        }
    }
    let refs: Vec<&[String]> = parsed.iter().map(|v| v.as_slice()).collect();
    let result = intersect_scopes(&refs);
    match serde_json::to_string(&result) {
        Ok(out) => new_cstring(&out),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Validate a JSON array of scope strings against the protocol vocabulary.
///
/// Returns NULL if all scopes are valid. Returns a heap-allocated error string
/// (free with `ratify_string_free`) if any scope is invalid. NULL input returns
/// a null-pointer error string.
#[no_mangle]
pub unsafe extern "C" fn ratify_scopes_validate(
    scopes_json: *const c_char,
) -> *mut c_char {
    if scopes_json.is_null() { return new_cstring("scopes_json is null"); }
    let s = match CStr::from_ptr(scopes_json).to_str() { Ok(s) => s, Err(_) => return new_cstring("scopes_json invalid UTF-8") };
    let scopes: Vec<String> = match serde_json::from_str(s) { Ok(v) => v, Err(e) => return new_cstring(&format!("scopes_json: {e}")) };
    match validate_scopes(&scopes) {
        None => std::ptr::null_mut(), // valid
        Some(err) => new_cstring(&err),
    }
}

// ============================================================================
// Policy Verdicts
// ============================================================================

/// Issue a HMAC-bound PolicyVerdict — a cached policy decision.
///
/// After a policy server evaluates a bundle, it can issue a short-lived verdict
/// that subsequent verifications can consume locally without re-running the
/// policy engine. The verdict is bound to (agent_id, scope, context_hash) so
/// it cannot be replayed across different agents or contexts.
///
/// - `context_hash` / `context_hash_len` — exactly 32 bytes. Compute with
///   `ratify_verifier_context_hash` to bind to a specific VerifierContext.
/// - `policy_secret` — HMAC key; minimum 1 byte, 32+ bytes recommended.
/// - `allow` — 1 for allow, 0 for deny.
#[no_mangle]
pub unsafe extern "C" fn ratify_policy_verdict_issue(
    verdict_id: *const c_char,
    agent_id: *const c_char,
    scope: *const c_char,
    allow: c_int,
    context_hash: *const c_uchar,
    context_hash_len: usize,
    issued_at_unix: i64,
    valid_until_unix: i64,
    policy_secret: *const c_uchar,
    policy_secret_len: usize,
    out: *mut *mut RatifyPolicyVerdict,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let vid   = match cstr_to_string(verdict_id, "verdict_id", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let aid   = match cstr_to_string(agent_id,   "agent_id",   err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let scp   = match cstr_to_string(scope,       "scope",      err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let ctx_h = match mandatory_exact_buf(context_hash, context_hash_len, 32, "context_hash", err_out) { Ok(b) => b, Err(e) => return e };
    let secret = match validated_buf(policy_secret, policy_secret_len, 1, "policy_secret", err_out) { Some(b) => b, None => return RatifyStatus::RatifyErrBadArgument };

    match issue_policy_verdict(&vid, &aid, &scp, allow != 0, ctx_h, issued_at_unix, valid_until_unix, secret) {
        Ok(v) => { *out = Box::into_raw(Box::new(RatifyPolicyVerdict(v))); RatifyStatus::RatifyOk }
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Verify a PolicyVerdict JSON string.
///
/// Returns `RatifyOk` if the verdict is valid (HMAC matches, not expired, agent/scope/context match, and allow=true).
/// Returns `RatifyErrCrypto` with a reason if invalid or if the verdict is a cached deny.
#[no_mangle]
pub unsafe extern "C" fn ratify_policy_verdict_verify(
    verdict_json: *const c_char,
    policy_secret: *const c_uchar,
    policy_secret_len: usize,
    expected_agent_id: *const c_char,
    expected_scope: *const c_char,
    expected_context_hash: *const c_uchar,
    expected_context_hash_len: usize,
    now_unix: i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    let s       = match cstr_to_string(verdict_json,     "verdict_json",     err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let aid     = match cstr_to_string(expected_agent_id,"expected_agent_id",err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let scp     = match cstr_to_string(expected_scope,   "expected_scope",   err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrEncoding };
    let verdict: PolicyVerdict = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => return json_err(err_out, "verdict_json", e) };
    let secret  = match validated_buf(policy_secret, policy_secret_len, 1, "policy_secret", err_out) { Some(b) => b, None => return RatifyStatus::RatifyErrBadArgument };
    let ctx_h   = match mandatory_exact_buf(expected_context_hash, expected_context_hash_len, 32, "expected_context_hash", err_out) { Ok(b) => b, Err(e) => return e };

    match verify_policy_verdict(&verdict, secret, &aid, &scp, ctx_h, now_unix) {
        Ok(()) => RatifyStatus::RatifyOk,
        Err(e) => map_sdk_err(err_out, e),
    }
}

/// Serialise a PolicyVerdict to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_policy_verdict_to_json(handle: *const RatifyPolicyVerdict, err_out: *mut *mut c_char) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Deserialise a PolicyVerdict from JSON. Free with `ratify_policy_verdict_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_policy_verdict_from_json(json: *const c_char, out: *mut *mut RatifyPolicyVerdict, err_out: *mut *mut c_char) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<PolicyVerdict>(&s) {
        Ok(v) => { *out = Box::into_raw(Box::new(RatifyPolicyVerdict(v))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "policy_verdict_from_json", e),
    }
}

/// Free a `RatifyPolicyVerdict` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_policy_verdict_free(handle: *mut RatifyPolicyVerdict) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Transaction Receipts
// ============================================================================

/// Verify a multi-party TransactionReceipt JSON string.
///
/// Verifies every party signature independently and returns `RatifyOk` only
/// if ALL party signatures verify.
///
/// - `now_unix` — Unix timestamp used for party proof bundle freshness checks.
///   Pass 0 to use the system clock. Embedded targets without a system clock
///   should pass an explicit timestamp from their best available time source.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_verify(
    receipt_json: *const c_char,
    now_unix: i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if check_not_null(receipt_json, "receipt_json", err_out).is_none() { return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(receipt_json, "receipt_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    let receipt: TransactionReceipt = match serde_json::from_str(&s) { Ok(r) => r, Err(e) => return json_err(err_out, "receipt_json", e) };
    // Use caller-supplied timestamp; fall back to system clock if 0.
    // This eliminates the SystemTime::now() dependency for embedded targets
    // that have no OS clock but can supply a timestamp from NTP or RTC.
    let now_ts = if now_unix != 0 {
        now_unix
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    };
    let result = verify_transaction_receipt(&receipt, now_ts);
    if result.valid { RatifyStatus::RatifyOk } else { set_err(err_out, &format!("transaction_receipt invalid: {}", result.error_reason)); RatifyStatus::RatifyErrCrypto }
}

/// Sign a TransactionReceipt as one party using an AgentIdentity.
///
/// Returns the party signature as a JSON string (`ReceiptPartySignature`).
/// Free with `ratify_string_free`. The caller collects all party signatures
/// and assembles the final receipt.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_sign_party(
    receipt_json: *const c_char,
    party_id: *const c_char,
    agent: *const RatifyAgent,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if agent.is_null() { set_err(err_out, "agent is null"); return std::ptr::null_mut(); }
    let receipt_str = match cstr_to_string(receipt_json, "receipt_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let pid_str     = match cstr_to_string(party_id,    "party_id",    err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let receipt: TransactionReceipt = match serde_json::from_str(&receipt_str) { Ok(r) => r, Err(e) => { set_err(err_out, &format!("receipt_json: {e}")); return std::ptr::null_mut(); } };
    let agent_ref = &*agent;
    // sign_transaction_receipt_party is infallible in the Rust SDK
    let sig = sign_transaction_receipt_party(&receipt, &pid_str, &agent_ref.1);
    match serde_json::to_string(&sig) {
        Ok(s) => new_cstring(&s),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Deserialise a TransactionReceipt from JSON. Free with `ratify_transaction_receipt_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_from_json(json: *const c_char, out: *mut *mut RatifyTransactionReceipt, err_out: *mut *mut c_char) -> RatifyStatus {
    if out.is_null() { set_err(err_out, "out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrJson };
    match serde_json::from_str::<TransactionReceipt>(&s) {
        Ok(r) => { *out = Box::into_raw(Box::new(RatifyTransactionReceipt(r))); RatifyStatus::RatifyOk }
        Err(e) => json_err(err_out, "transaction_receipt_from_json", e),
    }
}

/// Serialise a TransactionReceipt to JSON. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_to_json(handle: *const RatifyTransactionReceipt, err_out: *mut *mut c_char) -> *mut c_char {
    if handle.is_null() { set_err(err_out, "handle is null"); return std::ptr::null_mut(); }
    match serde_json::to_string(&(*handle).0) { Ok(s) => new_cstring(&s), Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() } }
}

/// Free a `RatifyTransactionReceipt` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_free(handle: *mut RatifyTransactionReceipt) {
    if !handle.is_null() { drop(Box::from_raw(handle)); }
}

// ============================================================================
// Utility Hashes
// ============================================================================

/// Compute the SHA-256 hash of a delegation cert chain.
///
/// Writes exactly 32 bytes to `out_32`. Used as `chain_hash` in SessionTokens
/// to bind a session to a specific delegation chain — if any cert in the chain
/// is replaced, the hash changes and the session token is invalidated.
#[no_mangle]
pub unsafe extern "C" fn ratify_chain_hash(
    bundle: *const RatifyProofBundle,
    out_32: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if bundle.is_null() || out_32.is_null() { set_err(err_out, "bundle and out_32 must be non-null"); return RatifyStatus::RatifyErrNullPointer; }
    let h = sdk_chain_hash(&(*bundle).0.delegations);
    if h.len() != 32 { set_err(err_out, "chain_hash: unexpected length"); return RatifyStatus::RatifyErrInternal; }
    slice::from_raw_parts_mut(out_32, 32).copy_from_slice(&h);
    RatifyStatus::RatifyOk
}

/// Compute the SHA-256 hash of a VerifierContext.
///
/// Writes exactly 32 bytes to `out_32`. Use this as the `context_hash` when
/// issuing a PolicyVerdict to bind the verdict to a specific constraint
/// evaluation context.
#[no_mangle]
pub unsafe extern "C" fn ratify_verifier_context_hash(
    ctx: *const RatifyVerifierContext,
    out_32: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if ctx.is_null() || out_32.is_null() { set_err(err_out, "ctx and out_32 must be non-null"); return RatifyStatus::RatifyErrNullPointer; }

    // Build the Rust VerifierContext from the C struct — reuse the same logic as build_opts.
    let ctx_ref = &*ctx;
    let currency = if ctx_ref.requested_currency.is_null() { None } else {
        CStr::from_ptr(ctx_ref.requested_currency).to_str().ok().map(|s| s.to_owned())
    };
    let rust_ctx = ratify_protocol::VerifierContext {
        current_lat:           if ctx_ref.has_location != 0 { Some(ctx_ref.current_lat) } else { None },
        current_lon:           if ctx_ref.has_location != 0 { Some(ctx_ref.current_lon) } else { None },
        current_alt_m:         if ctx_ref.has_location != 0 { Some(ctx_ref.current_alt_m) } else { None },
        current_speed_mps:     if ctx_ref.has_speed    != 0 { Some(ctx_ref.current_speed_mps) } else { None },
        requested_amount:      if ctx_ref.has_amount   != 0 { Some(ctx_ref.requested_amount) } else { None },
        requested_currency:    if ctx_ref.has_amount   != 0 { currency } else { None },
        invocations_in_window: None, // not needed for hashing
    };
    match ratify_protocol::verifier_context_hash(&rust_ctx) {
        Ok(h) => {
            if h.len() != 32 { set_err(err_out, "verifier_context_hash: unexpected length"); return RatifyStatus::RatifyErrInternal; }
            slice::from_raw_parts_mut(out_32, 32).copy_from_slice(&h);
            RatifyStatus::RatifyOk
        }
        Err(e) => map_sdk_err(err_out, e),
    }
}
