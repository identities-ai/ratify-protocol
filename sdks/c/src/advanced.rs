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

// The deprecated positional streamed verifier stays exported through the C
// ABI for compatibility; its wrapper below documents the deprecation.
#[allow(deprecated)]
use ratify_protocol::verify_streamed_turn;
use ratify_protocol::{
    bundle_hash as sdk_bundle_hash, chain_hash as sdk_chain_hash,
    expand_scopes, has_scope, hex_encode, intersect_scopes, is_sensitive,
    issue_key_rotation_statement, issue_policy_verdict, issue_revocation_list,
    issue_revocation_push, issue_session_token, issue_verification_receipt,
    issue_witness_entry, key_rotation_sign_bytes, revocation_push_sign_bytes,
    revocation_sign_bytes, session_token_sign_bytes, sign_transaction_receipt_party,
    transaction_receipt_sign_bytes, validate_scopes, verify_key_rotation_statement,
    verify_policy_verdict, verify_revocation_list, verify_revocation_push,
    verify_session_token_e, verify_streamed_turn_with_options, verify_transaction_receipt,
    verify_bundle, verify_verification_receipt, verify_witness_entry, vocabulary,
    build_session_context, operation_context_hash,
    canonical_json, challenge_sign_bytes_with_stream,
    operation_context_bytes, session_context_bytes, sign_challenge_with_stream,
    sign_challenge, sign_challenge_with_session_context,
    verify_challenge_signature, verify_challenge_signature_with_session_context,
    verify_challenge_signature_with_stream, verify_delegation_signature,
    delegation_sign_bytes, derive_id, hybrid_keypair_from_seeds,
    DelegationCert,
    witness_entry_sign_bytes, ChallengeStore, MemoryChallengeStore, OperationContext,
    ProofBundle, SessionContextInputs, StreamedTurn, StreamedVerifyOptions,
    HybridPublicKey, HybridSignature,
    KeyRotationStatement, PolicyVerdict,
    RevocationList, RevocationPush, SessionToken,
    TransactionReceipt, VerificationReceipt,
    WitnessEntry,
};

use crate::{
    set_err, cstr_to_string, new_cstring, checked_build_opts,
    RatifyHumanRoot, RatifyAgent, RatifyProofBundle, RatifyVerifyResult,
    RatifyStatus, RatifyVerifierContext, RatifyVerifyOptions,
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
pub struct RatifyChallengeStore(MemoryChallengeStore);

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

/// Structural invariants of a wire VerificationReceipt (SPEC §17.5),
/// shared by the encode (`to_json`) and decode (`from_json`) paths so the
/// codec pair never emits a document its counterpart rejects. Mirrors the
/// Go reference's `checkReceiptStructure`. Signature *validity* is a
/// separate concern (`ratify_receipt_verify`); this only checks shape.
fn check_receipt_structure(r: &VerificationReceipt) -> Result<(), String> {
    // The closed identity_status vocabulary a receipt may attest (SPEC §5.9).
    const VALID_DECISIONS: &[&str] = &[
        "authorized_agent", "verified_human", "expired", "revoked",
        "scope_denied", "constraint_denied", "constraint_unverifiable",
        "constraint_unknown", "invalid_scope", "delegation_not_authorized",
        "invalid", "unauthorized",
    ];
    if r.version != 1 {
        return Err(format!("wire: receipt version {} is not PROTOCOL_VERSION (1)", r.version));
    }
    if r.verifier_id.is_empty() {
        return Err("wire: receipt verifier_id must be non-empty".to_string());
    }
    if !VALID_DECISIONS.contains(&r.decision.as_str()) {
        return Err(format!("wire: receipt decision {:?} is not a known identity_status", r.decision));
    }
    if r.bundle_hash.len() != 32 {
        return Err(format!("wire: bundle_hash must be 32 bytes, got {}", r.bundle_hash.len()));
    }
    if r.prev_hash.len() != 32 {
        return Err(format!("wire: prev_hash must be 32 bytes, got {}", r.prev_hash.len()));
    }
    if r.verifier_pub.ed25519.len() != 32 {
        return Err(format!("wire: verifier_pub.ed25519 must be 32 bytes, got {}", r.verifier_pub.ed25519.len()));
    }
    if r.verifier_pub.ml_dsa_65.len() != 1952 {
        return Err(format!("wire: verifier_pub.ml_dsa_65 must be 1952 bytes, got {}", r.verifier_pub.ml_dsa_65.len()));
    }
    if r.signature.ed25519.len() != 64 {
        return Err(format!("wire: signature.ed25519 must be 64 bytes, got {}", r.signature.ed25519.len()));
    }
    if r.signature.ml_dsa_65.len() != 3309 {
        return Err(format!("wire: signature.ml_dsa_65 must be 3309 bytes, got {}", r.signature.ml_dsa_65.len()));
    }
    Ok(())
}

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
    // SPEC §17.5: never emit a document our own decoder rejects.
    if let Err(e) = check_receipt_structure(&(*handle).0) {
        set_err(err_out, &e);
        return std::ptr::null_mut();
    }
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
        Ok(r) => {
            // SPEC §17.5: reject a structurally-invalid wire receipt (wrong
            // hash/key lengths, unknown decision, wrong version) here — the
            // same invariants the encoder enforces.
            if let Err(e) = check_receipt_structure(&r) {
                set_err(err_out, &e);
                return RatifyStatus::RatifyErrJson;
            }
            *out = Box::into_raw(Box::new(RatifyReceipt(r))); RatifyStatus::RatifyOk
        }
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

/// Return the complete canonical scope vocabulary for v1 as a JSON array of
/// strings, sorted lexicographically.
///
/// Consumers that present scope choices to users (consoles, policy editors)
/// should derive their lists from this function rather than hardcoding scope
/// strings, so UI vocabularies cannot drift from the protocol.
///
/// Free with `ratify_string_free`. Returns NULL only on allocation failure.
#[no_mangle]
pub extern "C" fn ratify_scope_vocabulary() -> *mut c_char {
    match serde_json::to_string(&vocabulary()) {
        Ok(out) => new_cstring(&out),
        Err(_) => std::ptr::null_mut(),
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
        // The legacy RatifyVerifierContext carries no resource context
        // (SPEC §5.16); resource fields are supplied only through the
        // versioned verify path, not this hashing helper.
        requested_resource_id: None,
        requested_path:        None,
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

// ============================================================================
// Canonical sign-bytes helpers — for conformance testing and audit tooling.
// Each function deserialises the typed object from JSON, computes the
// canonical signing bytes defined in SPEC.md, and returns the bytes as a
// lowercase hex string. Free the result with `ratify_string_free`.
// ============================================================================

/// Return the canonical revocation-list signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_list_sign_bytes_hex(
    list_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(list_json, "list_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let list: RevocationList = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&revocation_sign_bytes(&list)))
}

/// Return the canonical revocation-push signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_sign_bytes_hex(
    push_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(push_json, "push_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let push: RevocationPush = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&revocation_push_sign_bytes(&push)))
}

/// Return the Ed25519 component of a RevocationPush signature as hex. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_sig_ed25519_hex(
    push_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(push_json, "push_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let push: RevocationPush = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&push.signature.ed25519))
}

/// Return the ML-DSA-65 component of a RevocationPush signature as hex. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_revocation_push_sig_ml_dsa_65_hex(
    push_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(push_json, "push_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let push: RevocationPush = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&push.signature.ml_dsa_65))
}

/// Return the canonical key-rotation signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_key_rotation_sign_bytes_hex(
    rotation_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(rotation_json, "rotation_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let stmt: KeyRotationStatement = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&key_rotation_sign_bytes(&stmt)))
}

/// Return the canonical session-token signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_sign_bytes_hex(
    token_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(token_json, "token_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let token: SessionToken = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&session_token_sign_bytes(&token)))
}

/// Return the session-token MAC bytes as a lowercase hex string. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_token_mac_hex(
    token_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(token_json, "token_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let token: SessionToken = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&token.mac))
}

/// Return the canonical transaction-receipt signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_sign_bytes_hex(
    receipt_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(receipt_json, "receipt_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let receipt: TransactionReceipt = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&transaction_receipt_sign_bytes(&receipt)))
}

/// Return the canonical witness-entry signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_sign_bytes_hex(
    entry_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(entry_json, "entry_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let entry: WitnessEntry = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&witness_entry_sign_bytes(&entry)))
}

/// Return the Ed25519 component of a WitnessEntry signature as hex. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_sig_ed25519_hex(
    entry_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(entry_json, "entry_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let entry: WitnessEntry = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&entry.signature.ed25519))
}

/// Return the ML-DSA-65 component of a WitnessEntry signature as hex. Free with `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_witness_entry_sig_ml_dsa_65_hex(
    entry_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(entry_json, "entry_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let entry: WitnessEntry = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&entry.signature.ml_dsa_65))
}

// ============================================================================
// Streamed-turn verification (session token fast path)
// ============================================================================

/// Verify a single streamed turn against an already-issued session token.
///
/// DEPRECATED: presentation checks only — this form cannot enforce a
/// required scope, single-use challenges, or verifier-side session/stream
/// checks, so a token holder passes it for any protected action. Use
/// `ratify_verify_streamed_turn_opts`. Retained for compatibility through
/// the v1.0.0-* releases.
///
/// This is the fast path for embedded streaming: after a full `verify_bundle`
/// that issued a session token, each subsequent turn is verified with this
/// function — no cert chain re-verification needed.
///
/// Returns a `RatifyVerifyResult*` (same type as `ratify_verify_bundle`).
/// Free with `ratify_verify_result_free`.
///
/// - `token_json`          — JSON of the `SessionToken` returned by `ratify_session_token_issue`.
/// - `session_secret`      — the HMAC secret used when the token was issued (raw bytes, ≥1 byte).
/// - `challenge` / `challenge_len` — the fresh challenge bytes for this turn.
/// - `challenge_at`        — Unix timestamp the challenge was issued.
/// - `challenge_sig_json`  — `HybridSignature` JSON produced by the agent.
/// - `session_context`     — optional 32-byte session context (NULL + 0 = none).
/// - `stream_id`           — optional 32-byte stream ID (NULL + 0 = none).
/// - `stream_seq`          — highest sequence number already accepted (0 = first turn).
/// - `now_unix`            — current clock; 0 = use system clock.
#[no_mangle]
pub unsafe extern "C" fn ratify_verify_streamed_turn(
    token_json:           *const c_char,
    session_secret:       *const c_uchar,
    session_secret_len:   usize,
    challenge:            *const c_uchar,
    challenge_len:        usize,
    challenge_at:         i64,
    challenge_sig_json:   *const c_char,
    session_context:      *const c_uchar,
    session_context_len:  usize,
    stream_id:            *const c_uchar,
    stream_id_len:        usize,
    stream_seq:           i64,
    now_unix:             i64,
    err_out:              *mut *mut c_char,
) -> *mut crate::RatifyVerifyResult {
    // Parse session token
    let token_str = match cstr_to_string(token_json, "token_json", err_out) {
        Some(s) => s, None => return std::ptr::null_mut(),
    };
    let token: SessionToken = match serde_json::from_str(&token_str) {
        Ok(t) => t,
        Err(e) => { set_err(err_out, &format!("token_json: {e}")); return std::ptr::null_mut(); }
    };

    // Session secret
    let secret = match validated_buf(session_secret, session_secret_len, 1, "session_secret", err_out) {
        Some(b) => b, None => return std::ptr::null_mut(),
    };

    // Challenge bytes
    let chall = match validated_buf(challenge, challenge_len, 1, "challenge", err_out) {
        Some(b) => b, None => return std::ptr::null_mut(),
    };

    // Challenge signature
    let sig_str = match cstr_to_string(challenge_sig_json, "challenge_sig_json", err_out) {
        Some(s) => s, None => return std::ptr::null_mut(),
    };
    let sig: HybridSignature = match serde_json::from_str(&sig_str) {
        Ok(s) => s,
        Err(e) => { set_err(err_out, &format!("challenge_sig_json: {e}")); return std::ptr::null_mut(); }
    };

    // Optional session context: NULL+0 = absent; non-NULL must be exactly 32 bytes.
    let sess_ctx: &[u8] = if session_context.is_null() {
        if session_context_len != 0 {
            set_err(err_out, "session_context is null but session_context_len is non-zero");
            return std::ptr::null_mut();
        }
        &[]
    } else if session_context_len == 0 {
        &[]
    } else if session_context_len != 32 {
        set_err(err_out, &format!("session_context_len must be 0 or 32, got {session_context_len}"));
        return std::ptr::null_mut();
    } else {
        slice::from_raw_parts(session_context, 32)
    };

    // Optional stream ID: NULL+0 = absent; non-NULL must be exactly 32 bytes.
    let sid: &[u8] = if stream_id.is_null() {
        if stream_id_len != 0 {
            set_err(err_out, "stream_id is null but stream_id_len is non-zero");
            return std::ptr::null_mut();
        }
        &[]
    } else if stream_id_len == 0 {
        &[]
    } else if stream_id_len != 32 {
        set_err(err_out, &format!("stream_id_len must be 0 or 32, got {stream_id_len}"));
        return std::ptr::null_mut();
    } else {
        slice::from_raw_parts(stream_id, 32)
    };

    #[allow(deprecated)]
    let result = verify_streamed_turn(
        &token, secret, chall, challenge_at, &sig,
        sess_ctx, sid, stream_seq,
        if now_unix == 0 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) } else { now_unix },
    );

    Box::into_raw(Box::new(crate::RatifyVerifyResult(result)))
}

// Validate and convert RatifyStreamedVerifyOptions -> StreamedVerifyOptions.
unsafe fn checked_build_streamed_opts<'a>(
    opts: *const crate::RatifyStreamedVerifyOptions,
    err_out: *mut *mut c_char,
) -> Result<StreamedVerifyOptions<'a>, RatifyStatus> {
    if opts.is_null() {
        return Ok(StreamedVerifyOptions::default());
    }
    let o = &*opts;

    if o.session_context_len != 0 && o.session_context_len != 32 {
        set_err(err_out, "session_context_len must be 0 or 32");
        return Err(RatifyStatus::RatifyErrBadArgument);
    }
    if o.session_context_len == 32 && o.session_context.is_null() {
        set_err(err_out, "session_context is null but session_context_len is 32");
        return Err(RatifyStatus::RatifyErrNullPointer);
    }
    if !o.stream.is_null() {
        let s = &*o.stream;
        if s.stream_id_len != 0 && s.stream_id_len != 32 {
            set_err(err_out, "stream_id_len must be 0 or 32");
            return Err(RatifyStatus::RatifyErrBadArgument);
        }
        if s.stream_id_len == 32 && s.stream_id.is_null() {
            set_err(err_out, "stream_id is null but stream_id_len is 32");
            return Err(RatifyStatus::RatifyErrNullPointer);
        }
    }
    if !o.required_scope.is_null()
        && std::ffi::CStr::from_ptr(o.required_scope).to_str().is_err()
    {
        set_err(err_out, "required_scope contains invalid UTF-8");
        return Err(RatifyStatus::RatifyErrEncoding);
    }

    let required_scope = if o.required_scope.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(o.required_scope)
            .to_str()
            .unwrap_or("")
            .to_owned()
    };
    let session_context = if o.session_context.is_null() || o.session_context_len == 0 {
        Vec::new()
    } else {
        slice::from_raw_parts(o.session_context, o.session_context_len).to_vec()
    };
    let stream = if o.stream.is_null() {
        None
    } else {
        let s = &*o.stream;
        if s.stream_id.is_null() || s.stream_id_len == 0 {
            None
        } else {
            Some(ratify_protocol::StreamContext {
                stream_id: slice::from_raw_parts(s.stream_id, s.stream_id_len).to_vec(),
                last_seen_seq: s.last_seen_seq,
            })
        }
    };

    Ok(StreamedVerifyOptions {
        required_scope,
        challenge_store: None,
        session_context,
        stream,
        now: if o.now_unix == 0 { None } else { Some(o.now_unix) },
    })
}

/// Options-object streamed-turn verification (SPEC §5.13).
///
/// Verifies one turn against a previously issued SessionToken and enforces
/// the verifier-side controls the positional `ratify_verify_streamed_turn`
/// cannot: `opts->required_scope` is checked against the token's cached
/// effective scope (`scope_denied` on miss), `opts->session_context` /
/// `opts->stream` are the verifier-side expectations checked against the
/// presented bindings with the same statuses as full verification, and a
/// non-NULL `store` makes the per-turn challenge single-use (consulted,
/// without consuming, after the session token's HMAC authenticates the
/// presentation and before the per-turn hybrid challenge signature is
/// verified; atomically consumed after that signature verifies — before
/// the scope check; store failures normalize to the canonical
/// unknown_challenge result).
///
/// `opts` is `RatifyStreamedVerifyOptions` — deliberately not the full
/// `RatifyVerifyOptions`, so revocation callbacks and constraint context
/// can never be passed and silently ignored. Callers who need fresh
/// revocation or policy semantics run full bundle verification instead.
///
/// - `session_context` / `stream_id` / `stream_seq` — the PRESENTED
///   bindings the agent signed (NULL + 0 = unbound), distinct from the
///   expectations in `opts`.
/// - `opts` may be NULL for default options; `now` comes from
///   `opts->now_unix` (0 = system clock).
/// - `store` may be NULL to skip single-use enforcement.
/// - `opts->stream` is a caller-owned snapshot — see its declaration for
///   the atomic-advance requirement.
#[no_mangle]
pub unsafe extern "C" fn ratify_verify_streamed_turn_opts(
    token_json: *const c_char,
    session_secret: *const c_uchar,
    session_secret_len: usize,
    challenge: *const c_uchar,
    challenge_len: usize,
    challenge_at: i64,
    challenge_sig_json: *const c_char,
    session_context: *const c_uchar,
    session_context_len: usize,
    stream_id: *const c_uchar,
    stream_id_len: usize,
    stream_seq: i64,
    opts: *const crate::RatifyStreamedVerifyOptions,
    store: *const RatifyChallengeStore,
    out: *mut *mut crate::RatifyVerifyResult,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if token_json.is_null() || out.is_null() {
        set_err(err_out, "token_json and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let token_str = match cstr_to_string(token_json, "token_json", err_out) {
        Some(s) => s,
        None => return RatifyStatus::RatifyErrJson,
    };
    let token: SessionToken = match serde_json::from_str(&token_str) {
        Ok(t) => t,
        Err(e) => {
            set_err(err_out, &format!("token_json: {e}"));
            return RatifyStatus::RatifyErrJson;
        }
    };
    let secret = match validated_buf(session_secret, session_secret_len, 1, "session_secret", err_out) {
        Some(b) => b,
        None => return RatifyStatus::RatifyErrBadArgument,
    };
    let chall = match validated_buf(challenge, challenge_len, 1, "challenge", err_out) {
        Some(b) => b,
        None => return RatifyStatus::RatifyErrBadArgument,
    };
    let sig_str = match cstr_to_string(challenge_sig_json, "challenge_sig_json", err_out) {
        Some(s) => s,
        None => return RatifyStatus::RatifyErrJson,
    };
    let sig: HybridSignature = match serde_json::from_str(&sig_str) {
        Ok(s) => s,
        Err(e) => {
            set_err(err_out, &format!("challenge_sig_json: {e}"));
            return RatifyStatus::RatifyErrJson;
        }
    };
    let sess_ctx = match validated_buf_opt(session_context, session_context_len, err_out) {
        Ok(b) => b,
        Err(status) => return status,
    };
    let sid = match validated_buf_opt(stream_id, stream_id_len, err_out) {
        Ok(b) => b,
        Err(status) => return status,
    };

    let mut rust_opts = match checked_build_streamed_opts(opts, err_out) {
        Ok(o) => o,
        Err(status) => return status,
    };
    if !store.is_null() {
        rust_opts.challenge_store = Some(Box::new(&(*store).0 as &dyn ChallengeStore));
    }

    let turn = StreamedTurn {
        challenge: chall.to_vec(),
        challenge_at,
        challenge_sig: sig,
        session_context: sess_ctx.to_vec(),
        stream_id: sid.to_vec(),
        stream_seq,
    };
    let result = verify_streamed_turn_with_options(&token, secret, &turn, &rust_opts);
    *out = Box::into_raw(Box::new(crate::RatifyVerifyResult(result)));
    RatifyStatus::RatifyOk
}

/// Full transaction-receipt verification with explicit valid/error_reason outputs.
///
/// Writes 1 to `*valid_out` on success, 0 on failure.
/// On failure, `*err_out` contains the error_reason string (free with `ratify_error_free`).
/// Returns `RatifyOk` on parse success (the receipt may still be invalid — check `*valid_out`).
#[no_mangle]
pub unsafe extern "C" fn ratify_transaction_receipt_verify_full(
    receipt_json: *const c_char,
    now_unix: i64,
    valid_out: *mut c_int,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if valid_out.is_null() { set_err(err_out, "valid_out is null"); return RatifyStatus::RatifyErrNullPointer; }
    let s = match cstr_to_string(receipt_json, "receipt_json", err_out) {
        Some(s) => s, None => return RatifyStatus::RatifyErrJson,
    };
    let receipt: TransactionReceipt = match serde_json::from_str(&s) {
        Ok(v) => v,
        Err(e) => return json_err(err_out, "receipt_json", e),
    };
    let ts = if now_unix == 0 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) } else { now_unix };
    let result = verify_transaction_receipt(&receipt, ts);
    *valid_out = result.valid as c_int;
    if !result.valid && !result.error_reason.is_empty() {
        set_err(err_out, &result.error_reason);
    }
    RatifyStatus::RatifyOk
}

// ============================================================================
// Operation-context / session-context constructions (SPEC §6.4.9)
// ============================================================================

// Read an optional null-terminated UTF-8 string: NULL = empty string.
unsafe fn opt_utf8(
    ptr: *const c_char,
    name: &str,
    err_out: *mut *mut c_char,
) -> Result<String, RatifyStatus> {
    if ptr.is_null() {
        return Ok(String::new());
    }
    match std::ffi::CStr::from_ptr(ptr).to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => {
            set_err(err_out, &format!("{name} contains invalid UTF-8"));
            Err(RatifyStatus::RatifyErrEncoding)
        }
    }
}

/// Compute the 32-byte request_hash over the SPEC §6.4.9 operation
/// context: the specific action a presentation authorizes. Every string
/// may be NULL (= empty); `payload_digest` is NULL + 0 (= none) or
/// exactly 32 bytes. Writes 32 bytes to `out_hash`.
///
/// Feed the result to `ratify_session_context_build` as `request_hash` —
/// binding the session but not the operation would let an intermediary
/// attach a valid proof to the wrong action inside the right session.
#[no_mangle]
pub unsafe extern "C" fn ratify_operation_context_hash(
    required_scope: *const c_char,
    operation: *const c_char,
    resource_id: *const c_char,
    requested_path: *const c_char,
    payload_digest: *const c_uchar,
    payload_digest_len: usize,
    out_hash: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out_hash.is_null() {
        set_err(err_out, "out_hash must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let digest = match validated_buf_opt(payload_digest, payload_digest_len, err_out) {
        Ok(b) => b,
        Err(status) => return status,
    };
    let ctx = OperationContext {
        required_scope: match opt_utf8(required_scope, "required_scope", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        operation: match opt_utf8(operation, "operation", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        resource_id: match opt_utf8(resource_id, "resource_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        requested_path: match opt_utf8(requested_path, "requested_path", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        payload_digest: digest.to_vec(),
    };
    match operation_context_hash(&ctx) {
        Ok(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash, 32);
            RatifyStatus::RatifyOk
        }
        Err(e) => {
            set_err(err_out, &e);
            RatifyStatus::RatifyErrBadArgument
        }
    }
}

/// Build the 32-byte session_context over the SPEC §6.4.9 session
/// context: the session a presentation belongs to plus (through
/// `request_hash`) the operation it authorizes. Every string may be NULL
/// (= empty); `request_hash` MUST be exactly 32 bytes — from
/// `ratify_operation_context_hash`, over an all-NULL operation context
/// when the deployment has no operation-specific inputs. Writes 32 bytes
/// to `out_context`, ready for `RatifyVerifyOptions.session_context` and
/// the challenge signing bytes. The Middleware Custody Profile (SPEC
/// §15.2.1) requires all fields populated.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_context_build(
    verifier_id: *const c_char,
    workspace_id: *const c_char,
    agent_id: *const c_char,
    session_id: *const c_char,
    invocation_id: *const c_char,
    request_hash: *const c_uchar,
    request_hash_len: usize,
    out_context: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out_context.is_null() {
        set_err(err_out, "out_context must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    if request_hash.is_null() || request_hash_len != 32 {
        set_err(err_out, "request_hash must point to exactly 32 bytes");
        return RatifyStatus::RatifyErrBadArgument;
    }
    let inputs = SessionContextInputs {
        verifier_id: match opt_utf8(verifier_id, "verifier_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        workspace_id: match opt_utf8(workspace_id, "workspace_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        agent_id: match opt_utf8(agent_id, "agent_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        session_id: match opt_utf8(session_id, "session_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        invocation_id: match opt_utf8(invocation_id, "invocation_id", err_out) {
            Ok(s) => s,
            Err(st) => return st,
        },
        request_hash: slice::from_raw_parts(request_hash, 32).to_vec(),
    };
    match build_session_context(&inputs) {
        Ok(ctx) => {
            std::ptr::copy_nonoverlapping(ctx.as_ptr(), out_context, 32);
            RatifyStatus::RatifyOk
        }
        Err(e) => {
            set_err(err_out, &e);
            RatifyStatus::RatifyErrBadArgument
        }
    }
}

// ============================================================================
// Challenge store (SPEC §10 single-use challenges)
// ============================================================================

/// Create an in-memory challenge store holding at most `max_size` pending
/// challenges. The store makes verifier-issued challenges single-use: each
/// is accepted at most once within its freshness window; consuming a
/// challenge removes its record, freeing the capacity slot immediately.
/// Single-process only — deployments spanning processes or hosts need a
/// store over shared storage with atomic consumption. Returns NULL when
/// `max_size` is 0. Free with `ratify_challenge_store_free`.
#[no_mangle]
pub extern "C" fn ratify_challenge_store_new(max_size: usize) -> *mut RatifyChallengeStore {
    if max_size == 0 {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(RatifyChallengeStore(MemoryChallengeStore::new(
        max_size,
    ))))
}

/// Free a `RatifyChallengeStore` handle. Safe to call with NULL.
#[no_mangle]
pub unsafe extern "C" fn ratify_challenge_store_free(store: *mut RatifyChallengeStore) {
    if !store.is_null() {
        drop(Box::from_raw(store));
    }
}

/// Issue a fresh 32-byte challenge bound to `session_context` (which must
/// be NULL/0 = unbound, or exactly 32 bytes), valid for `ttl_seconds`
/// (which must be positive). Invalid inputs return RatifyErrBadArgument.
///
/// - `out_challenge` — buffer of at least 32 bytes; receives the challenge.
/// - `out_expires_at` — optional; receives the expiry (unix seconds).
#[no_mangle]
pub unsafe extern "C" fn ratify_challenge_store_issue(
    store: *const RatifyChallengeStore,
    session_context: *const c_uchar,
    session_context_len: usize,
    ttl_seconds: i64,
    out_challenge: *mut c_uchar,
    out_expires_at: *mut i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if store.is_null() || out_challenge.is_null() {
        set_err(err_out, "store and out_challenge must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let ctx = match validated_buf_opt(session_context, session_context_len, err_out) {
        Ok(c) => c,
        Err(status) => return status,
    };
    match (*store).0.issue(ctx, ttl_seconds) {
        Ok((challenge, expires_at)) => {
            std::ptr::copy_nonoverlapping(challenge.as_ptr(), out_challenge, challenge.len());
            if !out_expires_at.is_null() {
                *out_expires_at = expires_at;
            }
            RatifyStatus::RatifyOk
        }
        Err(e) => {
            set_err(err_out, &e);
            RatifyStatus::RatifyErrBadArgument
        }
    }
}

/// Report whether `challenge` could be consumed right now — issued,
/// unexpired, unconsumed, and bound to `session_context` — WITHOUT
/// consuming it. Returns RatifyOk when consumable; otherwise an error
/// status with the documented unknown-challenge detail in `*err_out`.
/// `now_unix` 0 = system clock.
#[no_mangle]
pub unsafe extern "C" fn ratify_challenge_store_check(
    store: *const RatifyChallengeStore,
    challenge: *const c_uchar,
    challenge_len: usize,
    session_context: *const c_uchar,
    session_context_len: usize,
    now_unix: i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    challenge_store_op(
        store, challenge, challenge_len, session_context, session_context_len, now_unix,
        err_out, false,
    )
}

/// Atomically remove the challenge's issuance record. Exactly one consume
/// of a given challenge may ever succeed; later calls (and calls with a
/// mismatched `session_context`, which do NOT remove the record) return an
/// error status with the documented unknown-challenge detail in `*err_out`.
/// Removal frees the record's capacity slot immediately.
/// `now_unix` 0 = system clock.
#[no_mangle]
pub unsafe extern "C" fn ratify_challenge_store_consume(
    store: *const RatifyChallengeStore,
    challenge: *const c_uchar,
    challenge_len: usize,
    session_context: *const c_uchar,
    session_context_len: usize,
    now_unix: i64,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    challenge_store_op(
        store, challenge, challenge_len, session_context, session_context_len, now_unix,
        err_out, true,
    )
}

// Eight parameters mirror the two public wrappers' C ABI argument lists.
#[allow(clippy::too_many_arguments)]
unsafe fn challenge_store_op(
    store: *const RatifyChallengeStore,
    challenge: *const c_uchar,
    challenge_len: usize,
    session_context: *const c_uchar,
    session_context_len: usize,
    now_unix: i64,
    err_out: *mut *mut c_char,
    consume: bool,
) -> RatifyStatus {
    if store.is_null() || challenge.is_null() {
        set_err(err_out, "store and challenge must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let challenge = slice::from_raw_parts(challenge, challenge_len);
    let ctx = match validated_buf_opt(session_context, session_context_len, err_out) {
        Ok(c) => c,
        Err(status) => return status,
    };
    let now = if now_unix == 0 { unix_now() } else { now_unix };
    let result = if consume {
        (*store).0.consume(challenge, ctx, now)
    } else {
        (*store).0.validate(challenge, ctx, now)
    };
    match result {
        Ok(()) => RatifyStatus::RatifyOk,
        Err(e) => {
            set_err(err_out, &e);
            RatifyStatus::RatifyErrBadArgument
        }
    }
}

/// Verify a ProofBundle with single-use challenge enforcement (SPEC §10).
///
/// Identical to `ratify_verify_bundle_opts`, plus: the store is consulted
/// (without consuming) before any signature work, and the challenge is
/// atomically consumed after the structural, chain, and challenge-signature
/// checks pass — before authorization evaluation. A forged or malformed
/// presentation never consumes a challenge; a cryptographically valid
/// presentation does, even if authorization is subsequently denied.
///
/// The store's session binding is checked against `opts->session_context`.
/// `opts` may be NULL for default options.
#[no_mangle]
pub unsafe extern "C" fn ratify_verify_bundle_opts_with_challenge_store(
    bundle_json: *const c_char,
    opts: *const RatifyVerifyOptions,
    store: *const RatifyChallengeStore,
    out: *mut *mut RatifyVerifyResult,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if bundle_json.is_null() || store.is_null() || out.is_null() {
        set_err(err_out, "bundle_json, store, and out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let mut rust_opts = match checked_build_opts(opts, err_out) {
        Ok(o) => o,
        Err(status) => return status,
    };
    rust_opts.challenge_store = Some(Box::new(&(*store).0 as &dyn ChallengeStore));

    let bundle_str = match cstr_to_string(bundle_json, "bundle_json", err_out) {
        Some(s) => s,
        None => return RatifyStatus::RatifyErrJson,
    };
    let bundle: ProofBundle = match serde_json::from_str(&bundle_str) {
        Ok(b) => b,
        Err(e) => {
            set_err(err_out, &format!("bundle_json: {e}"));
            return RatifyStatus::RatifyErrJson;
        }
    };

    let result = verify_bundle(&bundle, &rust_opts);
    *out = Box::into_raw(Box::new(RatifyVerifyResult(result)));
    RatifyStatus::RatifyOk
}

// Validate an optional (ptr, len) byte buffer: NULL+0 = empty.
unsafe fn validated_buf_opt<'a>(
    ptr: *const c_uchar,
    len: usize,
    err_out: *mut *mut c_char,
) -> Result<&'a [u8], RatifyStatus> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        set_err(err_out, "session_context is null but session_context_len is non-zero");
        return Err(RatifyStatus::RatifyErrNullPointer);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ============================================================================
// Minimum-surface primitives (docs/SDKS.md §4)
//
// These complete the C ABI's coverage of the published minimum SDK surface.
// Without `ratify_delegation_sign_bytes_hex` and `ratify_challenge_sign_bytes_hex`
// in particular, the C conformance suite could not make the two assertions that
// §4 requires of every `Kind = verify` fixture.
// ============================================================================

/// Compute the 16-byte hex identity from a hybrid public key (SPEC §7).
///
/// `pub_json` is the public key JSON (`{"ed25519":"...","ml_dsa_65":"..."}`),
/// as returned by `ratify_human_root_pub_key_json`. Free the result with
/// `ratify_string_free`.
///
/// A verifier that pins an identity by id uses this to confirm that a public
/// key it has been given belongs to the principal it pinned (SPEC §15.4).
#[no_mangle]
pub unsafe extern "C" fn ratify_derive_id(
    pub_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(pub_json, "pub_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let pk: HybridPublicKey = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&derive_id(&pk))
}

/// Return the canonical delegation-cert signing bytes as a lowercase hex string.
#[no_mangle]
pub unsafe extern "C" fn ratify_delegation_sign_bytes_hex(
    cert_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(cert_json, "cert_json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let cert: DelegationCert = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    new_cstring(&hex_encode(&delegation_sign_bytes(&cert)))
}

/// Return the challenge signing bytes as a lowercase hex string.
///
/// One entry point covers all three challenge-bytes variants in
/// `docs/SDKS.md` §4, which explicitly permits optional arguments where that is
/// idiomatic:
///
/// - plain (`challenge || BE u64(ts)`): pass NULL for both optional pointers;
/// - session-bound (SPEC §5.8): pass a 32-byte `session_context`;
/// - stream-bound: additionally pass a 32-byte `stream_id` and `stream_seq`.
///
/// `challenge` must point to exactly `challenge_len` bytes. `session_context`
/// and `stream_id`, when non-NULL, MUST each be exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn ratify_challenge_sign_bytes_hex(
    challenge: *const c_uchar,
    challenge_len: usize,
    challenge_at_unix: i64,
    session_context: *const c_uchar,
    session_context_len: usize,
    stream_id: *const c_uchar,
    stream_id_len: usize,
    stream_seq: i64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if challenge.is_null() {
        set_err(err_out, "challenge is null");
        return std::ptr::null_mut();
    }
    let ch = slice::from_raw_parts(challenge, challenge_len);

    let sc: &[u8] = if session_context.is_null() {
        if session_context_len != 0 {
            set_err(err_out, "session_context is null but session_context_len is non-zero");
            return std::ptr::null_mut();
        }
        &[]
    } else {
        if session_context_len != 32 {
            set_err(err_out, "session_context_len must be 32");
            return std::ptr::null_mut();
        }
        slice::from_raw_parts(session_context, 32)
    };

    let sid: &[u8] = if stream_id.is_null() {
        if stream_id_len != 0 {
            set_err(err_out, "stream_id is null but stream_id_len is non-zero");
            return std::ptr::null_mut();
        }
        &[]
    } else {
        if stream_id_len != 32 {
            set_err(err_out, "stream_id_len must be 32");
            return std::ptr::null_mut();
        }
        slice::from_raw_parts(stream_id, 32)
    };

    new_cstring(&hex_encode(&challenge_sign_bytes_with_stream(
        ch,
        challenge_at_unix,
        sc,
        sid,
        stream_seq,
    )))
}

/// Canonicalise a JSON document (SPEC §6). Returns the canonical form as a
/// string; free with `ratify_string_free`. Provided for interop audit, which is
/// what §4 names it for.
#[no_mangle]
pub unsafe extern "C" fn ratify_canonical_json(
    json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let s = match cstr_to_string(json, "json", err_out) { Some(s) => s, None => return std::ptr::null_mut() };
    let value: serde_json::Value = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return std::ptr::null_mut(); } };
    match String::from_utf8(canonical_json(&value)) {
        Ok(text) => new_cstring(&text),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Rebuild a HumanRoot deterministically from two 32-byte seeds.
///
/// This is the supported way to persist an issuer identity in C: store the two
/// seeds as key material and reconstruct the identity after a restart. The
/// protocol deliberately specifies no private-key serialisation format, so
/// seeds are the portable unit.
///
/// `created_at_unix` is carried into the rebuilt identity so that a restored
/// root is byte-identical to the original rather than merely equivalent.
///
/// Both seeds MUST be 32 bytes and MUST come from a cryptographically secure
/// source. Anyone holding them holds the identity.
#[no_mangle]
pub unsafe extern "C" fn ratify_human_root_from_seeds(
    ed_seed: *const c_uchar,
    ed_seed_len: usize,
    ml_seed: *const c_uchar,
    ml_seed_len: usize,
    created_at_unix: i64,
    out: *mut *mut RatifyHumanRoot,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { return RatifyStatus::RatifyErrNullPointer; }
    let (ed, ml) = match seed_pair(ed_seed, ed_seed_len, ml_seed, ml_seed_len, err_out) {
        Some(v) => v,
        None => return RatifyStatus::RatifyErrBadArgument,
    };
    let (pub_key, priv_key) = hybrid_keypair_from_seeds(&ed, &ml);
    let root = ratify_protocol::HumanRoot {
        id: derive_id(&pub_key),
        public_key: pub_key,
        created_at: created_at_unix,
        // None, not Some(empty): matches what generate_human_root produces, so a
        // root rebuilt from seeds serialises byte-identically to the original.
        anchors: None,
    };
    *out = Box::into_raw(Box::new(RatifyHumanRoot(root, priv_key)));
    RatifyStatus::RatifyOk
}

/// Rebuild an AgentIdentity deterministically from two 32-byte seeds.
/// See `ratify_human_root_from_seeds` for the seed-custody warning.
#[no_mangle]
pub unsafe extern "C" fn ratify_agent_from_seeds(
    name_utf8: *const c_char,
    agent_type_utf8: *const c_char,
    ed_seed: *const c_uchar,
    ed_seed_len: usize,
    ml_seed: *const c_uchar,
    ml_seed_len: usize,
    created_at_unix: i64,
    out: *mut *mut RatifyAgent,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out.is_null() { return RatifyStatus::RatifyErrNullPointer; }
    let name = match cstr_to_string(name_utf8, "name_utf8", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrNullPointer };
    let agent_type = match cstr_to_string(agent_type_utf8, "agent_type_utf8", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrNullPointer };
    let (ed, ml) = match seed_pair(ed_seed, ed_seed_len, ml_seed, ml_seed_len, err_out) {
        Some(v) => v,
        None => return RatifyStatus::RatifyErrBadArgument,
    };
    let (pub_key, priv_key) = hybrid_keypair_from_seeds(&ed, &ml);
    let agent = ratify_protocol::AgentIdentity {
        id: derive_id(&pub_key),
        name,
        agent_type,
        public_key: pub_key,
        created_at: created_at_unix,
    };
    *out = Box::into_raw(Box::new(RatifyAgent(agent, priv_key)));
    RatifyStatus::RatifyOk
}

/// Validate and copy a pair of 32-byte seeds out of caller memory.
unsafe fn seed_pair(
    ed_seed: *const c_uchar,
    ed_seed_len: usize,
    ml_seed: *const c_uchar,
    ml_seed_len: usize,
    err_out: *mut *mut c_char,
) -> Option<([u8; 32], [u8; 32])> {
    if ed_seed.is_null() || ml_seed.is_null() {
        set_err(err_out, "seed pointer is null");
        return None;
    }
    if ed_seed_len != 32 || ml_seed_len != 32 {
        set_err(err_out, "both seeds must be exactly 32 bytes");
        return None;
    }
    let mut ed = [0u8; 32];
    let mut ml = [0u8; 32];
    ed.copy_from_slice(slice::from_raw_parts(ed_seed, 32));
    ml.copy_from_slice(slice::from_raw_parts(ml_seed, 32));
    Some((ed, ml))
}

// ============================================================================
// Remaining minimum-surface entries (docs/SDKS.md §4)
// ============================================================================

/// Verify a delegation cert's own hybrid signature. Writes 1 or 0 to
/// `valid_out`. This checks only the signature on this one cert; full chain
/// verification is `ratify_verify_bundle`.
#[no_mangle]
pub unsafe extern "C" fn ratify_verify_delegation_signature(
    cert_json: *const c_char,
    valid_out: *mut c_int,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if valid_out.is_null() {
        set_err(err_out, "valid_out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let s = match cstr_to_string(cert_json, "cert_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrNullPointer };
    let cert: DelegationCert = match serde_json::from_str(&s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return RatifyStatus::RatifyErrJson; } };
    *valid_out = if verify_delegation_signature(&cert) { 1 } else { 0 };
    RatifyStatus::RatifyOk
}

/// Sign a challenge with an agent's private key, returning the hybrid
/// signature as JSON. Free with `ratify_string_free`.
///
/// Optional bindings match `ratify_challenge_sign_bytes_hex`: pass NULL for
/// both to sign the plain preimage, a 32-byte `session_context` for the
/// session-bound form, and additionally a 32-byte `stream_id` plus
/// `stream_seq` for the stream-bound form.
#[no_mangle]
pub unsafe extern "C" fn ratify_agent_sign_challenge(
    agent: *const RatifyAgent,
    challenge: *const c_uchar,
    challenge_len: usize,
    challenge_at_unix: i64,
    session_context: *const c_uchar,
    session_context_len: usize,
    stream_id: *const c_uchar,
    stream_id_len: usize,
    stream_seq: i64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if agent.is_null() || challenge.is_null() {
        set_err(err_out, "agent and challenge must be non-null");
        return std::ptr::null_mut();
    }
    let ch = slice::from_raw_parts(challenge, challenge_len);
    let sc = match optional_32(session_context, session_context_len, "session_context", err_out) {
        Ok(v) => v, Err(()) => return std::ptr::null_mut(),
    };
    let sid = match optional_32(stream_id, stream_id_len, "stream_id", err_out) {
        Ok(v) => v, Err(()) => return std::ptr::null_mut(),
    };
    // Dispatch by which bindings are present. The stream variants assert a
    // 32-byte stream_id in the core, and an assertion reached through the FFI
    // would abort the caller's process rather than return an error, so an
    // absent binding must never be forwarded as an empty slice.
    let sig = if !sid.is_empty() {
        sign_challenge_with_stream(ch, challenge_at_unix, sc, sid, stream_seq, &(*agent).1)
    } else if !sc.is_empty() {
        sign_challenge_with_session_context(ch, challenge_at_unix, sc, &(*agent).1)
    } else {
        sign_challenge(ch, challenge_at_unix, &(*agent).1)
    };
    match serde_json::to_string(&sig) {
        Ok(j) => new_cstring(&j),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Verify a hybrid challenge signature against a public key. Writes 1 or 0 to
/// `valid_out`. Optional bindings match `ratify_agent_sign_challenge`; they
/// MUST match what was signed or verification fails.
#[no_mangle]
pub unsafe extern "C" fn ratify_verify_challenge_signature(
    challenge: *const c_uchar,
    challenge_len: usize,
    challenge_at_unix: i64,
    session_context: *const c_uchar,
    session_context_len: usize,
    stream_id: *const c_uchar,
    stream_id_len: usize,
    stream_seq: i64,
    sig_json: *const c_char,
    pub_json: *const c_char,
    valid_out: *mut c_int,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if valid_out.is_null() || challenge.is_null() {
        set_err(err_out, "challenge and valid_out must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    let sig_s = match cstr_to_string(sig_json, "sig_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrNullPointer };
    let pub_s = match cstr_to_string(pub_json, "pub_json", err_out) { Some(s) => s, None => return RatifyStatus::RatifyErrNullPointer };
    let sig: HybridSignature = match serde_json::from_str(&sig_s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return RatifyStatus::RatifyErrJson; } };
    let pk: HybridPublicKey = match serde_json::from_str(&pub_s) { Ok(v) => v, Err(e) => { set_err(err_out, &e.to_string()); return RatifyStatus::RatifyErrJson; } };

    let ch = slice::from_raw_parts(challenge, challenge_len);
    let sc = match optional_32(session_context, session_context_len, "session_context", err_out) {
        Ok(v) => v, Err(()) => return RatifyStatus::RatifyErrBadArgument,
    };
    let sid = match optional_32(stream_id, stream_id_len, "stream_id", err_out) {
        Ok(v) => v, Err(()) => return RatifyStatus::RatifyErrBadArgument,
    };
    let ok = if !sid.is_empty() {
        verify_challenge_signature_with_stream(
            ch, challenge_at_unix, sc, sid, stream_seq, &sig, &pk,
        )
        .is_ok()
    } else if !sc.is_empty() {
        verify_challenge_signature_with_session_context(ch, challenge_at_unix, sc, &sig, &pk)
            .is_ok()
    } else {
        verify_challenge_signature(ch, challenge_at_unix, &sig, &pk).is_ok()
    };
    *valid_out = if ok { 1 } else { 0 };
    RatifyStatus::RatifyOk
}

/// Generate a random hybrid keypair from the OS RNG.
///
/// The public half is returned as JSON. The private half is returned as the
/// two 32-byte seeds that reproduce it through `ratify_human_root_from_seeds`
/// or `ratify_agent_from_seeds`: the protocol specifies no private-key
/// serialisation format, so seeds are this SDK's portable unit of private key
/// material. Both output buffers MUST be at least 32 bytes. Treat them as key
/// material.
#[no_mangle]
pub unsafe extern "C" fn ratify_generate_hybrid_keypair(
    out_pub_json: *mut *mut c_char,
    out_ed_seed: *mut c_uchar,
    out_ml_seed: *mut c_uchar,
    err_out: *mut *mut c_char,
) -> RatifyStatus {
    if out_pub_json.is_null() || out_ed_seed.is_null() || out_ml_seed.is_null() {
        set_err(err_out, "all output pointers must be non-null");
        return RatifyStatus::RatifyErrNullPointer;
    }
    // Draw the seeds, then derive deterministically from them, so the returned
    // seeds always reproduce the returned public key.
    let mut ed = [0u8; 32];
    let mut ml = [0u8; 32];
    let (a, b) = (
        ratify_protocol::generate_challenge(),
        ratify_protocol::generate_challenge(),
    );
    if a.len() != 32 || b.len() != 32 {
        set_err(err_out, "entropy source returned an unexpected length");
        return RatifyStatus::RatifyErrCrypto;
    }
    ed.copy_from_slice(&a);
    ml.copy_from_slice(&b);
    let (pk, _priv) = ratify_protocol::hybrid_keypair_from_seeds(&ed, &ml);
    let json = match serde_json::to_string(&pk) {
        Ok(j) => j,
        Err(e) => { set_err(err_out, &e.to_string()); return RatifyStatus::RatifyErrJson; }
    };
    *out_pub_json = new_cstring(&json);
    std::ptr::copy_nonoverlapping(ed.as_ptr(), out_ed_seed, 32);
    std::ptr::copy_nonoverlapping(ml.as_ptr(), out_ml_seed, 32);
    RatifyStatus::RatifyOk
}

/// Return the operation-context preimage (SPEC §6.4.9) as a lowercase hex
/// string. `ratify_operation_context_hash` returns the digest over these bytes;
/// audit tooling needs the bytes themselves. Parameters match that function.
#[no_mangle]
pub unsafe extern "C" fn ratify_operation_context_bytes_hex(
    required_scope: *const c_char,
    operation: *const c_char,
    resource_id: *const c_char,
    requested_path: *const c_char,
    payload_digest: *const c_uchar,
    payload_digest_len: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let digest = match validated_buf_opt(payload_digest, payload_digest_len, err_out) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let ctx = OperationContext {
        required_scope: match opt_utf8(required_scope, "required_scope", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        operation: match opt_utf8(operation, "operation", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        resource_id: match opt_utf8(resource_id, "resource_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        requested_path: match opt_utf8(requested_path, "requested_path", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        payload_digest: digest.to_vec(),
    };
    match operation_context_bytes(&ctx) {
        Ok(bytes) => new_cstring(&hex_encode(&bytes)),
        Err(e) => { set_err(err_out, &e); std::ptr::null_mut() }
    }
}

/// Return the session-context preimage (SPEC §6.4.9) as a lowercase hex
/// string. Parameters match `ratify_session_context_build`, which returns the
/// digest over these bytes.
#[no_mangle]
pub unsafe extern "C" fn ratify_session_context_bytes_hex(
    verifier_id: *const c_char,
    workspace_id: *const c_char,
    agent_id: *const c_char,
    session_id: *const c_char,
    invocation_id: *const c_char,
    request_hash: *const c_uchar,
    request_hash_len: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if request_hash.is_null() || request_hash_len != 32 {
        set_err(err_out, "request_hash must be exactly 32 bytes");
        return std::ptr::null_mut();
    }
    let inputs = SessionContextInputs {
        verifier_id: match opt_utf8(verifier_id, "verifier_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        workspace_id: match opt_utf8(workspace_id, "workspace_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        agent_id: match opt_utf8(agent_id, "agent_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        session_id: match opt_utf8(session_id, "session_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        invocation_id: match opt_utf8(invocation_id, "invocation_id", err_out) { Ok(s) => s, Err(_) => return std::ptr::null_mut() },
        request_hash: slice::from_raw_parts(request_hash, 32).to_vec(),
    };
    match session_context_bytes(&inputs) {
        Ok(bytes) => new_cstring(&hex_encode(&bytes)),
        Err(e) => { set_err(err_out, &e); std::ptr::null_mut() }
    }
}

/// Serialise an agent's hybrid public key to JSON, for feeding to
/// `ratify_verify_challenge_signature` and `ratify_derive_id`. The symmetric
/// accessor for human roots already existed; without this one an agent's key
/// could not be handed to the verification primitives at all. Free with
/// `ratify_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratify_agent_pub_key_json(
    agent: *const RatifyAgent,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if agent.is_null() {
        set_err(err_out, "agent is null");
        return std::ptr::null_mut();
    }
    match serde_json::to_string(&(*agent).0.public_key) {
        Ok(j) => new_cstring(&j),
        Err(e) => { set_err(err_out, &e.to_string()); std::ptr::null_mut() }
    }
}

/// Validate an optional 32-byte binding, returning an empty slice when absent.
unsafe fn optional_32<'a>(
    ptr: *const c_uchar,
    len: usize,
    name: &str,
    err_out: *mut *mut c_char,
) -> Result<&'a [u8], ()> {
    if ptr.is_null() {
        if len != 0 {
            set_err(err_out, &format!("{name} is null but its length is non-zero"));
            return Err(());
        }
        return Ok(&[]);
    }
    if len != 32 {
        set_err(err_out, &format!("{name} length must be 32"));
        return Err(());
    }
    Ok(slice::from_raw_parts(ptr, 32))
}
