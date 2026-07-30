//! Input-bound boundary tests (SPEC §5.1) exercised through the C ABI.
//!
//! This mirrors Go's `TestInputBoundBoundaries` (resource_path_test.go): every
//! §5.1 input bound is exercised at EXACTLY the limit (must be accepted — the
//! bound must not fire) and ONE PAST it (must be rejected — the bound must
//! fire). The at-limit accept cases matter as much as the rejects: an
//! off-by-one that rejected a legal maximum would be a silent availability
//! regression.
//!
//! How each bound surfaces through the C ABI (see sdks/c/src/lib.rs and
//! sdks/rust/src/verify.rs):
//!
//! - MAX_SCOPES_PER_CERT, MAX_CONSTRAINTS_PER_CERT, MAX_SCOPE_LENGTH_BYTES,
//!   MAX_IDENTIFIER_LENGTH_BYTES: re-enforced inside `verify_bundle` BEFORE
//!   signature verification. Over the limit -> RatifyOk + an `invalid`
//!   VerifyResult whose error_reason names the bound. At the limit the bound
//!   passes and verification proceeds; because these fixtures inject the
//!   payload into an already-signed bundle, at-limit then fails on the
//!   signature (a semantic failure), NOT on the bound. We assert the bound
//!   name is absent at the limit and present one past it. All exercised
//!   through `ratify_verify_bundle`.
//!
//! - MAX_JSON_NESTING_DEPTH: checked pre-parse in `ratify_verify_bundle_opts_v2`
//!   via the shared crate scanner. At depth 16 the gate passes and the parser
//!   is reached (the bare bracket string is not a ProofBundle, so parsing
//!   fails with RatifyErrJson — the nesting bound did NOT fire); at depth 17
//!   the gate fires -> RatifyOk + `invalid` naming MAX_JSON_NESTING_DEPTH.
//!   Exercised through `ratify_verify_bundle`, mirroring Go's use of the
//!   standalone `CheckWireJSON` decoder.
//!
//! - MAX_AGENT_NAME_LENGTH_BYTES: a construction bound with no bundle path.
//!   Exercised through its closest ABI entry, `ratify_agent_generate`, which
//!   returns RatifyErrBadArgument for an over-long name (mirrors Go's
//!   `GenerateAgentKeypair` name bound).

use ratify_c::{
    ratify_agent_free, ratify_agent_generate, ratify_challenge_generate,
    ratify_delegation_cert_free, ratify_delegation_cert_to_json, ratify_delegation_issue,
    ratify_error_free, ratify_human_root_free, ratify_human_root_generate,
    ratify_proof_bundle_create, ratify_proof_bundle_free, ratify_proof_bundle_to_json,
    ratify_string_free, ratify_verify_bundle, ratify_verify_result_error_reason,
    ratify_verify_result_free, ratify_verify_result_identity_status,
    ratify_verify_result_is_valid, RatifyStatus,
};
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// SPEC §5.1 numeric limits.
const MAX_SCOPES_PER_CERT: usize = 128;
const MAX_CONSTRAINTS_PER_CERT: usize = 32;
const MAX_SCOPE_LENGTH_BYTES: usize = 256;
const MAX_IDENTIFIER_LENGTH_BYTES: usize = 512;
const MAX_JSON_NESTING_DEPTH: usize = 16;
const MAX_AGENT_NAME_LENGTH_BYTES: usize = 256;

const NOW: i64 = 1_800_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a C string that may be null. Frees the pointer. Null -> empty string.
unsafe fn read_opt(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_string_free(ptr);
    s
}

/// Build a valid, signed ProofBundle JSON at `NOW`. The signature covers the
/// bundle exactly as issued; boundary fixtures mutate a copy of this JSON, so
/// at-limit cases parse and reach the verifier (where they fail on the
/// tampered signature, not on any bound).
unsafe fn valid_bundle_json() -> String {
    let mut root = std::ptr::null_mut();
    let mut agent = std::ptr::null_mut();
    ratify_human_root_generate(&mut root);
    let agent_type = CString::new("custom").unwrap();
    let agent_name = CString::new("BoundBot").unwrap();
    ratify_agent_generate(agent_name.as_ptr(), agent_type.as_ptr(), &mut agent);

    let scopes = CString::new("[\"meeting:attend\"]").unwrap();
    let mut cert = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    ratify_delegation_issue(root, agent, scopes.as_ptr(), NOW, NOW + 3600, &mut cert, &mut err);
    assert!(err.is_null(), "delegation must succeed");
    let cert_json = ratify_delegation_cert_to_json(cert, &mut err);
    assert!(!cert_json.is_null());

    let mut challenge = [0u8; 32];
    ratify_challenge_generate(challenge.as_mut_ptr(), 32);
    let mut bundle = std::ptr::null_mut();
    ratify_proof_bundle_create(agent, cert_json, challenge.as_ptr(), 32, NOW, &mut bundle, &mut err);
    assert!(err.is_null(), "bundle creation must succeed");
    let bundle_json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);
    let bundle_json = read_opt(bundle_json_ptr);

    ratify_string_free(cert_json);
    ratify_proof_bundle_free(bundle);
    ratify_delegation_cert_free(cert);
    ratify_agent_free(agent);
    ratify_human_root_free(root);
    assert!(!bundle_json.is_empty(), "bundle JSON must be produced");
    bundle_json
}

/// Deserialize `bundle_json`, apply `f` to the first delegation cert's object,
/// and re-serialize. Panics if the structure is not as expected.
fn mutate_first_cert(bundle_json: &str, f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let mut v: Value = serde_json::from_str(bundle_json).expect("bundle JSON parses");
    let cert = v["delegations"][0]
        .as_object_mut()
        .expect("delegations[0] is an object");
    f(cert);
    serde_json::to_string(&v).expect("re-serialize")
}

struct Outcome {
    status: RatifyStatus,
    has_result: bool,
    valid: bool,
    #[allow(dead_code)]
    identity_status: String,
    reason: String,
}

/// Verify `bundle_json` through the C ABI and capture the full outcome,
/// whether it surfaces as a status code (no result) or a VerifyResult.
unsafe fn verify(bundle_json: &str) -> Outcome {
    let c = CString::new(bundle_json).expect("no interior NUL");
    let mut result = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    let status = ratify_verify_bundle(c.as_ptr(), std::ptr::null(), NOW, &mut result, &mut err);

    if result.is_null() {
        let reason = if err.is_null() {
            String::new()
        } else {
            let s = CStr::from_ptr(err).to_string_lossy().into_owned();
            ratify_error_free(err);
            s
        };
        return Outcome { status, has_result: false, valid: false, identity_status: String::new(), reason };
    }

    let valid = ratify_verify_result_is_valid(result) != 0;
    let identity_status = read_opt(ratify_verify_result_identity_status(result));
    let reason = read_opt(ratify_verify_result_error_reason(result));
    ratify_verify_result_free(result);
    if !err.is_null() {
        ratify_error_free(err);
    }
    Outcome { status, has_result: true, valid, identity_status, reason }
}

/// N vocabulary-valid custom scopes.
fn scopes(n: usize) -> Value {
    let v: Vec<String> = (0..n).map(|i| format!("custom:com.example:s{i}")).collect();
    json!(v)
}

/// N identical whole-resource `resource_path` constraints (each with a short,
/// in-bound resource_id so only the count bound is under test).
fn constraints(n: usize) -> Value {
    let v: Vec<Value> = (0..n)
        .map(|_| json!({"type": "resource_path", "resource_id": "git:example.com/r"}))
        .collect();
    json!(v)
}

// ---------------------------------------------------------------------------
// Count and length bounds — through ratify_verify_bundle / verify_bundle
// ---------------------------------------------------------------------------

#[test]
fn max_scopes_per_cert_boundary() {
    unsafe {
        let base = valid_bundle_json();

        let at = mutate_first_cert(&base, |c| {
            c.insert("scope".into(), scopes(MAX_SCOPES_PER_CERT));
        });
        let o = verify(&at);
        assert_eq!(o.status, RatifyStatus::RatifyOk, "at-limit bundle must parse and verify");
        assert!(o.has_result, "at-limit must produce a VerifyResult");
        assert!(
            !o.reason.contains("MAX_SCOPES_PER_CERT"),
            "at limit ({MAX_SCOPES_PER_CERT}) the scope-count bound must NOT fire; reason={}",
            o.reason
        );

        let over = mutate_first_cert(&base, |c| {
            c.insert("scope".into(), scopes(MAX_SCOPES_PER_CERT + 1));
        });
        let o = verify(&over);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(!o.valid, "one past the limit must be invalid");
        assert!(
            o.reason.contains("MAX_SCOPES_PER_CERT"),
            "one past ({}) must surface the scope-count bound; reason={}",
            MAX_SCOPES_PER_CERT + 1,
            o.reason
        );
    }
}

#[test]
fn max_constraints_per_cert_boundary() {
    unsafe {
        let base = valid_bundle_json();

        let at = mutate_first_cert(&base, |c| {
            c.insert("constraints".into(), constraints(MAX_CONSTRAINTS_PER_CERT));
        });
        let o = verify(&at);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(o.has_result);
        assert!(
            !o.reason.contains("MAX_CONSTRAINTS_PER_CERT"),
            "at limit ({MAX_CONSTRAINTS_PER_CERT}) the constraint-count bound must NOT fire; reason={}",
            o.reason
        );

        let over = mutate_first_cert(&base, |c| {
            c.insert("constraints".into(), constraints(MAX_CONSTRAINTS_PER_CERT + 1));
        });
        let o = verify(&over);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(!o.valid);
        assert!(
            o.reason.contains("MAX_CONSTRAINTS_PER_CERT"),
            "one past ({}) must surface the constraint-count bound; reason={}",
            MAX_CONSTRAINTS_PER_CERT + 1,
            o.reason
        );
    }
}

#[test]
fn max_scope_length_bytes_boundary() {
    unsafe {
        let base = valid_bundle_json();
        // A vocabulary-valid `custom:` scope padded to an exact byte length.
        let scope_of_len = |n: usize| -> Value {
            let prefix = "custom:x:";
            json!([format!("{prefix}{}", "a".repeat(n - prefix.len()))])
        };

        let at = mutate_first_cert(&base, |c| {
            c.insert("scope".into(), scope_of_len(MAX_SCOPE_LENGTH_BYTES));
        });
        let o = verify(&at);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(o.has_result);
        assert!(
            !o.reason.contains("MAX_SCOPE_LENGTH_BYTES"),
            "at limit ({MAX_SCOPE_LENGTH_BYTES}) the scope-length bound must NOT fire; reason={}",
            o.reason
        );

        let over = mutate_first_cert(&base, |c| {
            c.insert("scope".into(), scope_of_len(MAX_SCOPE_LENGTH_BYTES + 1));
        });
        let o = verify(&over);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(!o.valid);
        assert!(
            o.reason.contains("MAX_SCOPE_LENGTH_BYTES"),
            "one past ({}) must surface the scope-length bound; reason={}",
            MAX_SCOPE_LENGTH_BYTES + 1,
            o.reason
        );
    }
}

#[test]
fn max_identifier_length_bytes_boundary() {
    unsafe {
        let base = valid_bundle_json();
        let rp_id = |n: usize| -> Value {
            json!([{"type": "resource_path", "resource_id": "r".repeat(n)}])
        };

        let at = mutate_first_cert(&base, |c| {
            c.insert("constraints".into(), rp_id(MAX_IDENTIFIER_LENGTH_BYTES));
        });
        let o = verify(&at);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(o.has_result);
        assert!(
            !o.reason.contains("MAX_IDENTIFIER_LENGTH_BYTES"),
            "at limit ({MAX_IDENTIFIER_LENGTH_BYTES}) the identifier-length bound must NOT fire; reason={}",
            o.reason
        );

        let over = mutate_first_cert(&base, |c| {
            c.insert("constraints".into(), rp_id(MAX_IDENTIFIER_LENGTH_BYTES + 1));
        });
        let o = verify(&over);
        assert_eq!(o.status, RatifyStatus::RatifyOk);
        assert!(!o.valid);
        assert!(
            o.reason.contains("MAX_IDENTIFIER_LENGTH_BYTES"),
            "one past ({}) must surface the identifier-length bound; reason={}",
            MAX_IDENTIFIER_LENGTH_BYTES + 1,
            o.reason
        );
    }
}

// ---------------------------------------------------------------------------
// Nesting bound — pre-parse gate in ratify_verify_bundle_opts_v2
// ---------------------------------------------------------------------------

#[test]
fn max_json_nesting_depth_boundary() {
    unsafe {
        // At the limit: the nesting gate passes and the parser is reached. The
        // bare bracket string is not a ProofBundle, so parsing fails with
        // RatifyErrJson — proving the nesting bound did NOT reject it.
        let at = format!(
            "{}{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH),
            "]".repeat(MAX_JSON_NESTING_DEPTH)
        );
        let o = verify(&at);
        assert_eq!(
            o.status,
            RatifyStatus::RatifyErrJson,
            "at limit ({MAX_JSON_NESTING_DEPTH}) nesting must pass the gate and reach the parser"
        );
        assert!(
            !o.reason.contains("MAX_JSON_NESTING_DEPTH"),
            "at the limit the nesting bound must NOT fire; reason={}",
            o.reason
        );

        // One past the limit: the pre-parse gate fires and surfaces as an
        // `invalid` VerifyResult naming the bound.
        let over = format!(
            "{}{}",
            "[".repeat(MAX_JSON_NESTING_DEPTH + 1),
            "]".repeat(MAX_JSON_NESTING_DEPTH + 1)
        );
        let o = verify(&over);
        assert_eq!(o.status, RatifyStatus::RatifyOk, "over-limit nesting surfaces as an invalid result");
        assert!(o.has_result);
        assert!(!o.valid);
        assert!(
            o.reason.contains("MAX_JSON_NESTING_DEPTH"),
            "one past ({}) must surface the nesting bound; reason={}",
            MAX_JSON_NESTING_DEPTH + 1,
            o.reason
        );
    }
}

// ---------------------------------------------------------------------------
// Agent-name bound — construction bound via ratify_agent_generate
// ---------------------------------------------------------------------------

#[test]
fn max_agent_name_length_bytes_boundary() {
    unsafe {
        let agent_type = CString::new("custom").unwrap();

        // At the limit: accepted.
        let name = CString::new("n".repeat(MAX_AGENT_NAME_LENGTH_BYTES)).unwrap();
        let mut agent = std::ptr::null_mut();
        assert_eq!(
            ratify_agent_generate(name.as_ptr(), agent_type.as_ptr(), &mut agent),
            RatifyStatus::RatifyOk,
            "name of exactly {MAX_AGENT_NAME_LENGTH_BYTES} bytes must be accepted"
        );
        assert!(!agent.is_null());
        ratify_agent_free(agent);

        // One past the limit: rejected as a bad argument.
        let name = CString::new("n".repeat(MAX_AGENT_NAME_LENGTH_BYTES + 1)).unwrap();
        let mut agent = std::ptr::null_mut();
        assert_eq!(
            ratify_agent_generate(name.as_ptr(), agent_type.as_ptr(), &mut agent),
            RatifyStatus::RatifyErrBadArgument,
            "name of {} bytes must be rejected",
            MAX_AGENT_NAME_LENGTH_BYTES + 1
        );
        assert!(agent.is_null());
    }
}
