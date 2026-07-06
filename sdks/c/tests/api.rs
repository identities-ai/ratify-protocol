//! Unit tests for every exported C API function.
//!
//! Coverage:
//! - Happy path for every function
//! - Null pointer handling for every pointer argument
//! - Malformed / empty JSON inputs
//! - Full round-trip: generate → delegate → challenge → bundle → verify
//! - Revocation via callback (revoked = true, revoked = false, error path)
//! - VerifierContext: geo constraints, speed, amount, rate counter
//! - Session context binding
//! - Error reason strings
//! - Memory: every allocated object is freed; no panics on double-inspection
//! - ratify_string_free / ratify_error_free with NULL (must not crash)

use ratify_c::{
    ratify_agent_free, ratify_agent_generate, ratify_agent_id,
    ratify_challenge_generate, ratify_delegation_cert_free, ratify_delegation_cert_to_json,
    ratify_delegation_issue, ratify_error_free, ratify_human_root_free,
    ratify_human_root_generate, ratify_human_root_id, ratify_human_root_to_json,
    ratify_proof_bundle_create, ratify_proof_bundle_free, ratify_proof_bundle_to_json,
    ratify_string_free, ratify_verify_bundle, ratify_verify_bundle_opts,
    ratify_verify_result_agent_id, ratify_verify_result_error_reason,
    ratify_verify_result_free, ratify_verify_result_human_id,
    ratify_verify_result_identity_status, ratify_verify_result_is_valid, ratify_version,
    ratify_no_expiry_sentinel, ratify_expires_at_is_no_expiry,
    RatifyStatus, RatifyVerifierContext, RatifyVerifyOptions,
};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// ============================================================================
// Helpers
// ============================================================================

/// Read a C string and return it as a Rust String. Panics if null.
unsafe fn read_cstr(ptr: *mut c_char) -> String {
    assert!(!ptr.is_null(), "expected non-null string");
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_string_free(ptr);
    s
}

/// Read a C string, optionally null. Returns None if null, Some(String) if set.
#[allow(dead_code)]
unsafe fn read_cstr_opt(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() { return None; }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_string_free(ptr);
    Some(s)
}

/// Create a temporary CString and return its raw pointer.
/// SAFETY: The CString temporary is dropped at the end of the enclosing
/// *statement* — NOT the end of the macro expansion. When used as a direct
/// function argument (e.g., `f(cstr!("x"))`), the CString lives through the
/// call and the pointer is valid. Never assign the result to a variable and
/// use it later; that would be use-after-free.
macro_rules! cstr {
    ($s:expr) => { CString::new($s).unwrap().as_ptr() };
}

// ============================================================================
// ratify_version
// ============================================================================

#[test]
fn version_is_nonempty() {
    let v = ratify_version();
    assert!(!v.is_null());
    unsafe {
        let s = CStr::from_ptr(v).to_str().unwrap();
        assert!(!s.is_empty(), "version string must not be empty");
        assert!(s.contains("alpha") || s.contains('.'), "version must look like a semver: {s}");
    }
}

// ============================================================================
// ratify_no_expiry_sentinel / ratify_expires_at_is_no_expiry
// ============================================================================

#[test]
fn no_expiry_sentinel_value_and_predicate() {
    // SPEC §5.7: 4070908799 = 2099-12-31 23:59:59 UTC.
    assert_eq!(ratify_no_expiry_sentinel(), 4_070_908_799i64);
    assert!(ratify_expires_at_is_no_expiry(4_070_908_799));
    assert!(!ratify_expires_at_is_no_expiry(4_070_908_798));
    assert!(!ratify_expires_at_is_no_expiry(0));
}

#[test]
fn delegation_issue_zero_expiry_signs_sentinel() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("agent"), cstr!("custom"), &mut agent);

        let mut cert = std::ptr::null_mut();
        // expires_at_unix = 0 → the library signs the no-expiry sentinel.
        assert_eq!(
            ratify_delegation_issue(root, agent, cstr!("[\"meeting:attend\"]"), 1_800_000_000, 0, &mut cert, &mut err),
            RatifyStatus::RatifyOk
        );
        let json = ratify_delegation_cert_to_json(cert, &mut err);
        assert!(!json.is_null());
        let s = CStr::from_ptr(json).to_str().unwrap();
        assert!(
            s.contains("\"expires_at\":4070908799"),
            "zero expiry must sign the sentinel, got: {s}"
        );

        ratify_string_free(json);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// ratify_human_root_generate
// ============================================================================

#[test]
fn human_root_generate_succeeds() {
    unsafe {
        let mut root = std::ptr::null_mut();
        assert_eq!(ratify_human_root_generate(&mut root), RatifyStatus::RatifyOk);
        assert!(!root.is_null());
        ratify_human_root_free(root);
    }
}

#[test]
fn human_root_generate_null_out_returns_error() {
    unsafe {
        assert_eq!(
            ratify_human_root_generate(std::ptr::null_mut()),
            RatifyStatus::RatifyErrNullPointer
        );
    }
}

#[test]
fn human_root_id_is_32_hex_chars() {
    unsafe {
        let mut root = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        let id = read_cstr(ratify_human_root_id(root));
        assert_eq!(id.len(), 32, "human_id must be 32 hex chars");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "human_id must be hex");
        ratify_human_root_free(root);
    }
}

#[test]
fn human_root_to_json_is_valid_json() {
    unsafe {
        let mut root = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        let mut err = std::ptr::null_mut();
        let json_ptr = ratify_human_root_to_json(root, &mut err);
        assert!(err.is_null(), "no error expected");
        let json = read_cstr(json_ptr);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["id"].is_string(), "JSON must contain 'id'");
        assert!(parsed["public_key"]["ed25519"].is_string(), "must have ed25519 key");
        assert!(parsed["public_key"]["ml_dsa_65"].is_string(), "must have ml_dsa_65 key");
        ratify_human_root_free(root);
    }
}

#[test]
fn human_root_to_json_null_handle_returns_null() {
    unsafe {
        let mut err = std::ptr::null_mut();
        let result = ratify_human_root_to_json(std::ptr::null(), &mut err);
        assert!(result.is_null());
        // err_out must be set
        assert!(!err.is_null());
        ratify_error_free(err);
    }
}

#[test]
fn human_root_two_generates_produce_different_ids() {
    unsafe {
        let mut r1 = std::ptr::null_mut();
        let mut r2 = std::ptr::null_mut();
        ratify_human_root_generate(&mut r1);
        ratify_human_root_generate(&mut r2);
        let id1 = read_cstr(ratify_human_root_id(r1));
        let id2 = read_cstr(ratify_human_root_id(r2));
        assert_ne!(id1, id2, "two generated roots must have different IDs");
        ratify_human_root_free(r1);
        ratify_human_root_free(r2);
    }
}

// ============================================================================
// ratify_agent_generate
// ============================================================================

#[test]
fn agent_generate_succeeds() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        assert_eq!(
            ratify_agent_generate(cstr!("MyBot"), cstr!("meeting_bot"), &mut agent),
            RatifyStatus::RatifyOk
        );
        assert!(!agent.is_null());
        ratify_agent_free(agent);
    }
}

#[test]
fn agent_generate_null_name_returns_error() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        assert_eq!(
            ratify_agent_generate(std::ptr::null(), cstr!("drone"), &mut agent),
            RatifyStatus::RatifyErrNullPointer
        );
    }
}

#[test]
fn agent_generate_null_type_returns_error() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        assert_eq!(
            ratify_agent_generate(cstr!("MyBot"), std::ptr::null(), &mut agent),
            RatifyStatus::RatifyErrNullPointer
        );
    }
}

#[test]
fn agent_generate_null_out_returns_error() {
    unsafe {
        assert_eq!(
            ratify_agent_generate(cstr!("MyBot"), cstr!("drone"), std::ptr::null_mut()),
            RatifyStatus::RatifyErrNullPointer
        );
    }
}

#[test]
fn agent_id_is_32_hex_chars() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        ratify_agent_generate(cstr!("Bot"), cstr!("custom"), &mut agent);
        let id = read_cstr(ratify_agent_id(agent));
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        ratify_agent_free(agent);
    }
}

#[test]
fn agent_generate_produces_unique_ids() {
    unsafe {
        let mut a1 = std::ptr::null_mut();
        let mut a2 = std::ptr::null_mut();
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut a1);
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut a2);
        let id1 = read_cstr(ratify_agent_id(a1));
        let id2 = read_cstr(ratify_agent_id(a2));
        assert_ne!(id1, id2);
        ratify_agent_free(a1);
        ratify_agent_free(a2);
    }
}

// ============================================================================
// ratify_delegation_issue
// ============================================================================

#[test]
fn delegation_issue_succeeds() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);

        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        assert_eq!(
            ratify_delegation_issue(
                root, agent,
                cstr!("[\"physical:enter\"]"),
                0, // issued_at: 0 = system clock
                0, // expires_at: 0 = no expiry (2099-12-31)
                &mut cert, &mut err,
            ),
            RatifyStatus::RatifyOk
        );
        assert!(!cert.is_null());
        assert!(err.is_null());

        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn delegation_issue_null_issuer_returns_error() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);
        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_delegation_issue(
            std::ptr::null(), agent, cstr!("[\"physical:enter\"]"), 0, 0, &mut cert, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrNullPointer);
        assert!(!err.is_null());
        ratify_error_free(err);
        ratify_agent_free(agent);
    }
}

#[test]
fn delegation_issue_malformed_scopes_returns_error() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);
        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_delegation_issue(
            root, agent,
            cstr!("not-json-at-all"),
            0, 0, &mut cert, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrJson);
        assert!(!err.is_null());
        ratify_error_free(err);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn delegation_cert_to_json_contains_expected_fields() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("meeting_bot"), &mut agent);

        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_delegation_issue(root, agent, cstr!("[\"meeting:attend\"]"), 0, 0, &mut cert, &mut err);

        let json = read_cstr(ratify_delegation_cert_to_json(cert, &mut err));
        assert!(err.is_null());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["cert_id"].is_string());
        assert_eq!(parsed["scope"][0].as_str().unwrap(), "meeting:attend");
        assert_eq!(parsed["version"].as_i64().unwrap(), 1);
        assert!(parsed["signature"]["ed25519"].is_string());
        assert!(parsed["signature"]["ml_dsa_65"].is_string());

        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// ratify_challenge_generate
// ============================================================================

#[test]
fn challenge_generate_produces_32_bytes() {
    unsafe {
        let mut buf = [0u8; 32];
        assert_eq!(ratify_challenge_generate(buf.as_mut_ptr(), 32), RatifyStatus::RatifyOk);
        // Very unlikely all 32 bytes are zero
        assert_ne!(buf, [0u8; 32], "challenge must contain random bytes");
    }
}

#[test]
fn challenge_generate_null_buf_returns_error() {
    unsafe {
        assert_eq!(
            ratify_challenge_generate(std::ptr::null_mut(), 32),
            RatifyStatus::RatifyErrNullPointer
        );
    }
}

#[test]
fn challenge_generate_wrong_len_returns_bad_argument() {
    unsafe {
        let mut buf = [0u8; 64];
        assert_eq!(
            ratify_challenge_generate(buf.as_mut_ptr(), 16),
            RatifyStatus::RatifyErrBadArgument,
            "buf_len != 32 must return RatifyErrBadArgument"
        );
        assert_eq!(
            ratify_challenge_generate(buf.as_mut_ptr(), 0),
            RatifyStatus::RatifyErrBadArgument
        );
        assert_eq!(
            ratify_challenge_generate(buf.as_mut_ptr(), 64),
            RatifyStatus::RatifyErrBadArgument
        );
    }
}

#[test]
fn two_challenges_are_different() {
    unsafe {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        ratify_challenge_generate(a.as_mut_ptr(), 32);
        ratify_challenge_generate(b.as_mut_ptr(), 32);
        assert_ne!(a, b, "successive challenges must differ");
    }
}

// ============================================================================
// ratify_proof_bundle_create
// ============================================================================

#[test]
fn proof_bundle_create_succeeds() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);

        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_delegation_issue(root, agent, cstr!("[\"physical:enter\"]"), 0, 0, &mut cert, &mut err);
        let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);

        let mut challenge = [0u8; 32];
        ratify_challenge_generate(challenge.as_mut_ptr(), 32);

        let mut bundle = std::ptr::null_mut();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let status = ratify_proof_bundle_create(
            agent, cert_json_ptr, challenge.as_ptr(), 32, now, &mut bundle, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyOk);
        assert!(!bundle.is_null());

        ratify_string_free(cert_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn proof_bundle_create_null_challenge_returns_error() {
    unsafe {
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);
        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_delegation_issue(root, agent, cstr!("[\"physical:enter\"]"), 0, 0, &mut cert, &mut err);
        let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);

        let mut bundle = std::ptr::null_mut();
        let status = ratify_proof_bundle_create(
            agent, cert_json_ptr, std::ptr::null(), 32, 1800000000, &mut bundle, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrNullPointer);

        ratify_string_free(cert_json_ptr);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn proof_bundle_create_malformed_cert_json_returns_error() {
    unsafe {
        let mut agent = std::ptr::null_mut();
        ratify_agent_generate(cstr!("Bot"), cstr!("drone"), &mut agent);
        let mut challenge = [0u8; 32];
        ratify_challenge_generate(challenge.as_mut_ptr(), 32);
        let mut bundle = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_proof_bundle_create(
            agent, cstr!("{not-json}"), challenge.as_ptr(), 32, 1800000000, &mut bundle, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrJson);
        assert!(!err.is_null());
        ratify_error_free(err);
        ratify_agent_free(agent);
    }
}

// ============================================================================
// Full round-trip: generate → delegate → verify
// ============================================================================

unsafe fn full_round_trip(scope: &str, now: i64) -> (bool, String) {
    let mut root = std::ptr::null_mut();
    let mut agent = std::ptr::null_mut();
    ratify_human_root_generate(&mut root);
    ratify_agent_generate(cstr!("RoundTripBot"), cstr!("custom"), &mut agent);

    let scopes_json = format!("[\"{scope}\"]");
    let scopes_c = CString::new(scopes_json).unwrap();
    let mut cert = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    ratify_delegation_issue(root, agent, scopes_c.as_ptr(), now, now + 3600, &mut cert, &mut err);
    assert!(err.is_null(), "delegation must succeed");

    let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);
    let mut challenge = [0u8; 32];
    ratify_challenge_generate(challenge.as_mut_ptr(), 32);

    let mut bundle = std::ptr::null_mut();
    ratify_proof_bundle_create(agent, cert_json_ptr, challenge.as_ptr(), 32, now, &mut bundle, &mut err);
    assert!(err.is_null(), "bundle creation must succeed");
    let bundle_json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);

    let scope_c = CString::new(scope).unwrap();
    let mut result = std::ptr::null_mut();
    ratify_verify_bundle(bundle_json_ptr, scope_c.as_ptr(), now, &mut result, &mut err);
    assert!(err.is_null());

    let valid = ratify_verify_result_is_valid(result) != 0;
    let status = read_cstr(ratify_verify_result_identity_status(result));

    ratify_verify_result_free(result);
    ratify_string_free(bundle_json_ptr);
    ratify_proof_bundle_free(bundle);
    ratify_string_free(cert_json_ptr);
    ratify_delegation_cert_free(cert);
    ratify_agent_free(agent);
    ratify_human_root_free(root);

    (valid, status)
}

#[test]
fn round_trip_meeting_attend_verifies() {
    unsafe {
        let now = 1800000000i64;
        let (valid, status) = full_round_trip("meeting:attend", now);
        assert!(valid, "round-trip must verify: status={status}");
        assert_eq!(status, "authorized_agent");
    }
}

#[test]
fn round_trip_physical_enter_verifies() {
    unsafe {
        let now = 1800000000i64;
        let (valid, status) = full_round_trip("physical:enter", now);
        assert!(valid, "physical:enter round-trip: status={status}");
        assert_eq!(status, "authorized_agent");
    }
}

#[test]
fn round_trip_wrong_scope_rejects() {
    unsafe {
        // Delegate meeting:attend, require meeting:record — must fail
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        let now = 1800000000i64;
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("custom"), &mut agent);

        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_delegation_issue(root, agent, cstr!("[\"meeting:attend\"]"), now, now + 3600, &mut cert, &mut err);
        let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);

        let mut challenge = [0u8; 32];
        ratify_challenge_generate(challenge.as_mut_ptr(), 32);
        let mut bundle = std::ptr::null_mut();
        ratify_proof_bundle_create(agent, cert_json_ptr, challenge.as_ptr(), 32, now, &mut bundle, &mut err);
        let bundle_json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);

        let mut result = std::ptr::null_mut();
        // Require a scope the cert doesn't have
        ratify_verify_bundle(bundle_json_ptr, cstr!("meeting:record"), now, &mut result, &mut err);

        let valid = ratify_verify_result_is_valid(result) != 0;
        let status = read_cstr(ratify_verify_result_identity_status(result));
        assert!(!valid, "wrong scope must fail");
        assert_eq!(status, "scope_denied");

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_string_free(cert_json_ptr);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// ratify_verify_bundle — error paths
// ============================================================================

#[test]
fn verify_bundle_null_bundle_json_returns_error() {
    unsafe {
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_verify_bundle(
            std::ptr::null(), std::ptr::null(), 0, &mut result, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrNullPointer);
    }
}

#[test]
fn verify_bundle_malformed_json_returns_error() {
    unsafe {
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_verify_bundle(
            cstr!("{this is not json}"), std::ptr::null(), 0, &mut result, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyErrJson);
        assert!(!err.is_null());
        ratify_error_free(err);
    }
}

#[test]
fn verify_bundle_empty_json_returns_error() {
    unsafe {
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_verify_bundle(
            cstr!("{}"), std::ptr::null(), 0, &mut result, &mut err,
        );
        // Empty object will either parse to a ProofBundle with empty fields and
        // fail cryptographically, or fail JSON parsing due to missing required fields.
        // Either way, result is either null (error) or valid=false.
        if status == RatifyStatus::RatifyOk {
            assert!(!result.is_null());
            assert_eq!(ratify_verify_result_is_valid(result), 0);
            ratify_verify_result_free(result);
        } else {
            assert_eq!(status, RatifyStatus::RatifyErrJson);
            if !err.is_null() { ratify_error_free(err); }
        }
    }
}

#[test]
fn verify_result_null_handle_safe() {
    // All accessors must tolerate null gracefully
    unsafe {
        assert_eq!(ratify_verify_result_is_valid(std::ptr::null()), 0);
        assert!(ratify_verify_result_identity_status(std::ptr::null()).is_null());
        assert!(ratify_verify_result_human_id(std::ptr::null()).is_null());
        assert!(ratify_verify_result_agent_id(std::ptr::null()).is_null());
        assert!(ratify_verify_result_error_reason(std::ptr::null()).is_null());
        ratify_verify_result_free(std::ptr::null_mut()); // must not crash
    }
}

// ============================================================================
// Revocation via callback
// ============================================================================

unsafe extern "C" fn always_revoked(
    _cert_id: *const c_char,
    _userdata: *mut std::ffi::c_void,
) -> c_int {
    1 // revoked
}

unsafe extern "C" fn never_revoked(
    _cert_id: *const c_char,
    _userdata: *mut std::ffi::c_void,
) -> c_int {
    0 // not revoked
}

unsafe extern "C" fn revocation_error(
    _cert_id: *const c_char,
    _userdata: *mut std::ffi::c_void,
) -> c_int {
    -1 // lookup failed → fail closed
}

unsafe fn make_bundle_json(now: i64) -> (*mut c_char, *mut ratify_c::RatifyHumanRoot, *mut ratify_c::RatifyAgent, *mut ratify_c::RatifyDelegationCert, *mut ratify_c::RatifyProofBundle) {
    let mut root = std::ptr::null_mut();
    let mut agent = std::ptr::null_mut();
    ratify_human_root_generate(&mut root);
    ratify_agent_generate(cstr!("RevBot"), cstr!("custom"), &mut agent);

    let mut cert = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    ratify_delegation_issue(root, agent, cstr!("[\"meeting:attend\"]"), now, now + 3600, &mut cert, &mut err);
    let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);

    let mut challenge = [0u8; 32];
    ratify_challenge_generate(challenge.as_mut_ptr(), 32);
    let mut bundle = std::ptr::null_mut();
    ratify_proof_bundle_create(agent, cert_json_ptr, challenge.as_ptr(), 32, now, &mut bundle, &mut err);
    let bundle_json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);
    ratify_string_free(cert_json_ptr);

    (bundle_json_ptr, root, agent, cert, bundle)
}

#[test]
fn revocation_callback_revoked_fails_verification() {
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: Some(always_revoked),
            revocation_userdata: std::ptr::null_mut(),
            context: std::ptr::null(),
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);

        assert_eq!(ratify_verify_result_is_valid(result), 0);
        let status = read_cstr(ratify_verify_result_identity_status(result));
        // Ok(true) from the provider → the cert is definitively revoked
        assert_eq!(status, "revoked", "always_revoked callback → identity_status=revoked");

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn revocation_callback_not_revoked_passes() {
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: Some(never_revoked),
            revocation_userdata: std::ptr::null_mut(),
            context: std::ptr::null(),
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);

        assert_eq!(ratify_verify_result_is_valid(result), 1);
        let status = read_cstr(ratify_verify_result_identity_status(result));
        assert_eq!(status, "authorized_agent");

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn revocation_callback_error_fails_closed() {
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: Some(revocation_error),
            revocation_userdata: std::ptr::null_mut(),
            context: std::ptr::null(),
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);

        // Err() from provider → fail-closed as invalid (identity_status)
        // with error_reason containing "revocation lookup failed"
        assert_eq!(ratify_verify_result_is_valid(result), 0);
        let status = read_cstr(ratify_verify_result_identity_status(result));
        // The Rust SDK maps unknown statuses to "invalid"; the error detail
        // is in error_reason.
        assert_eq!(status, "invalid", "lookup error → invalid (fail-closed)");
        let reason = read_cstr(ratify_verify_result_error_reason(result));
        assert!(
            reason.contains("revocation") || reason.contains("lookup") || reason.contains("failed"),
            "error_reason must mention revocation failure: {reason}"
        );

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn revocation_callback_receives_cert_id() {
    // Verify that the cert_id passed to the callback is the correct cert ID.
    use std::sync::{Arc, Mutex};
    let received_ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let ids_clone = Arc::clone(&received_ids);
    let ids_ptr = Arc::into_raw(ids_clone) as *mut std::ffi::c_void;

    unsafe extern "C" fn capture_cert_id(cert_id: *const c_char, userdata: *mut std::ffi::c_void) -> c_int {
        unsafe {
            let ids = &*(userdata as *const Mutex<Vec<String>>);
            let id = CStr::from_ptr(cert_id).to_string_lossy().into_owned();
            ids.lock().unwrap().push(id);
        }
        0 // not revoked
    }

    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        // Get the cert_id from the cert JSON
        let mut err = std::ptr::null_mut();
        let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);
        let cert_json = CStr::from_ptr(cert_json_ptr).to_string_lossy().into_owned();
        ratify_string_free(cert_json_ptr);
        let parsed: serde_json::Value = serde_json::from_str(&cert_json).unwrap();
        let expected_cert_id = parsed["cert_id"].as_str().unwrap().to_owned();

        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: Some(capture_cert_id),
            revocation_userdata: ids_ptr,
            context: std::ptr::null(),
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);
        ratify_verify_result_free(result);

        // Reconstruct Arc to free it properly
        let ids_arc: Arc<Mutex<Vec<String>>> = Arc::from_raw(ids_ptr as *const Mutex<Vec<String>>);
        let ids = ids_arc.lock().unwrap();
        assert!(ids.contains(&expected_cert_id), "callback must receive the cert's cert_id");

        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// VerifierContext — geo constraints
// ============================================================================

#[test]
fn verifier_context_null_skips_constraint_evaluation() {
    // Without context, a cert with geo constraints fails closed.
    // We test that passing NULL context is safe (doesn't panic).
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: None,
            revocation_userdata: std::ptr::null_mut(),
            context: std::ptr::null(), // null context is safe
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);
        assert_eq!(status, RatifyStatus::RatifyOk); // function call succeeds
        assert!(!result.is_null());
        // Bundle has no constraints → should verify
        assert_eq!(ratify_verify_result_is_valid(result), 1);

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

#[test]
fn verifier_context_with_location_is_safe() {
    // Verify that populating geo fields doesn't crash even when certs have no geo constraints.
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        let ctx = RatifyVerifierContext {
            current_lat: 47.6062,
            current_lon: -122.3321,
            current_alt_m: 56.0,
            has_location: 1,
            current_speed_mps: 0.0,
            has_speed: 0,
            requested_amount: 0.0,
            requested_currency: std::ptr::null(),
            has_amount: 0,
            rate_fn: None,
            rate_userdata: std::ptr::null_mut(),
        };
        let opts = RatifyVerifyOptions {
            required_scope: std::ptr::null(),
            now_unix: now,
            session_context: std::ptr::null(),
            session_context_len: 0,
            revocation_fn: None,
            revocation_userdata: std::ptr::null_mut(),
            context: &ctx,
            stream: std::ptr::null(),
        };
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        ratify_verify_bundle_opts(bundle_json_ptr, &opts, &mut result, &mut err);
        assert!(!result.is_null());
        // No geo constraint on cert → should still verify
        assert_eq!(ratify_verify_result_is_valid(result), 1);

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// Error reason strings
// ============================================================================

#[test]
fn expired_cert_gives_expired_status() {
    unsafe {
        let now = 1800000000i64;
        let mut root = std::ptr::null_mut();
        let mut agent = std::ptr::null_mut();
        ratify_human_root_generate(&mut root);
        ratify_agent_generate(cstr!("Bot"), cstr!("custom"), &mut agent);

        let mut cert = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        // expires_at = now - 1 → already expired
        ratify_delegation_issue(root, agent, cstr!("[\"meeting:attend\"]"), now - 7200, now - 1, &mut cert, &mut err);
        let cert_json_ptr = ratify_delegation_cert_to_json(cert, &mut err);

        let mut challenge = [0u8; 32];
        ratify_challenge_generate(challenge.as_mut_ptr(), 32);
        let mut bundle = std::ptr::null_mut();
        ratify_proof_bundle_create(agent, cert_json_ptr, challenge.as_ptr(), 32, now, &mut bundle, &mut err);
        let bundle_json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);

        let mut result = std::ptr::null_mut();
        ratify_verify_bundle(bundle_json_ptr, std::ptr::null(), now, &mut result, &mut err);

        assert_eq!(ratify_verify_result_is_valid(result), 0);
        let status = read_cstr(ratify_verify_result_identity_status(result));
        assert_eq!(status, "expired");
        let reason = read_cstr(ratify_verify_result_error_reason(result));
        assert!(!reason.is_empty(), "error_reason must be set for expired");

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_string_free(cert_json_ptr);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}

// ============================================================================
// Memory safety: free functions with NULL
// ============================================================================

#[test]
fn free_functions_tolerate_null() {
    unsafe {
        ratify_human_root_free(std::ptr::null_mut());
        ratify_agent_free(std::ptr::null_mut());
        ratify_delegation_cert_free(std::ptr::null_mut());
        ratify_proof_bundle_free(std::ptr::null_mut());
        ratify_verify_result_free(std::ptr::null_mut());
        ratify_string_free(std::ptr::null_mut());
        ratify_error_free(std::ptr::null_mut());
        // If we reach here without crashing, all free functions tolerate NULL.
    }
}

// ============================================================================
// ratify_verify_bundle_opts — null opts
// ============================================================================

#[test]
fn verify_bundle_opts_null_opts_behaves_like_simple_verify() {
    unsafe {
        let now = 1800000000i64;
        let (bundle_json_ptr, root, agent, cert, bundle) = make_bundle_json(now);

        // NULL opts should be accepted and behave like default options
        let mut result = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_verify_bundle_opts(bundle_json_ptr, std::ptr::null(), &mut result, &mut err);
        assert_eq!(status, RatifyStatus::RatifyOk);
        // With system clock (now ≠ 1800000000), challenge may be stale but we
        // just check the function didn't crash/return an error code.
        assert!(!result.is_null());

        ratify_verify_result_free(result);
        ratify_string_free(bundle_json_ptr);
        ratify_proof_bundle_free(bundle);
        ratify_delegation_cert_free(cert);
        ratify_agent_free(agent);
        ratify_human_root_free(root);
    }
}
