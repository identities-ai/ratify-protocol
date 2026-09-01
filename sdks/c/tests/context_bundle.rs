//! Tests for `ratify_proof_bundle_create_with_context`.
//!
//! The C SDK was the only reference implementation without a way to build a
//! ProofBundle bound to a 32-byte session context; Go, Rust, Python and
//! TypeScript already expose one. This covers the addition to the same
//! standard the rest of the C surface is held to: happy path, null pointer
//! safety, size validation, and a round trip through JSON.
//!
//! The size assertions matter more than usual here. The context binding is a
//! security property, and an implementation that quietly accepted a short or
//! oversized context would weaken it without failing anything.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use ratify_c::{
    ratify_agent_free, ratify_agent_generate, ratify_challenge_generate,
    ratify_delegation_cert_free, ratify_delegation_cert_to_json, ratify_delegation_issue,
    ratify_human_root_free, ratify_human_root_generate, ratify_proof_bundle_create_with_context,
    ratify_proof_bundle_free, ratify_proof_bundle_to_json, ratify_string_free, RatifyStatus,
};

const NOW: i64 = 1_800_000_000;

struct Fixture {
    root: *mut ratify_c::RatifyHumanRoot,
    agent: *mut ratify_c::RatifyAgent,
    cert: *mut ratify_c::RatifyDelegationCert,
    cert_json: *mut c_char,
    challenge: [u8; 32],
    context: [u8; 32],
}

impl Drop for Fixture {
    fn drop(&mut self) {
        unsafe {
            ratify_string_free(self.cert_json);
            ratify_delegation_cert_free(self.cert);
            ratify_agent_free(self.agent);
            ratify_human_root_free(self.root);
        }
    }
}

unsafe fn fixture() -> Fixture {
    let mut root = std::ptr::null_mut();
    let mut agent = std::ptr::null_mut();
    ratify_human_root_generate(&mut root);
    let agent_type = CString::new("custom").unwrap();
    let agent_name = CString::new("ContextBot").unwrap();
    ratify_agent_generate(agent_name.as_ptr(), agent_type.as_ptr(), &mut agent);

    let scopes = CString::new("[\"physical:actuate\"]").unwrap();
    let mut cert = std::ptr::null_mut();
    let mut err = std::ptr::null_mut();
    ratify_delegation_issue(root, agent, scopes.as_ptr(), NOW, NOW + 3600, &mut cert, &mut err);
    assert!(err.is_null(), "delegation must succeed");
    let cert_json = ratify_delegation_cert_to_json(cert, &mut err);
    assert!(!cert_json.is_null(), "cert json must serialise");

    let mut challenge = [0u8; 32];
    ratify_challenge_generate(challenge.as_mut_ptr(), 32);
    let mut context = [0u8; 32];
    ratify_challenge_generate(context.as_mut_ptr(), 32);

    Fixture { root, agent, cert, cert_json, challenge, context }
}

#[test]
fn creates_a_bundle_bound_to_a_session_context() {
    unsafe {
        let f = fixture();
        let mut bundle = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let status = ratify_proof_bundle_create_with_context(
            f.agent, f.cert_json, f.challenge.as_ptr(), 32, NOW,
            f.context.as_ptr(), 32, &mut bundle, &mut err,
        );
        assert_eq!(status, RatifyStatus::RatifyOk, "creation must succeed");
        assert!(err.is_null());
        assert!(!bundle.is_null());

        // Round trip: the context must survive serialisation, otherwise a
        // verifier could never compare it.
        let json_ptr = ratify_proof_bundle_to_json(bundle, &mut err);
        assert!(!json_ptr.is_null());
        let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
        assert!(json.contains("session_context"), "bundle json must carry the context");
        ratify_string_free(json_ptr);
        ratify_proof_bundle_free(bundle);
    }
}

#[test]
fn differing_contexts_produce_differing_bundles() {
    unsafe {
        let f = fixture();
        let mut other = [0u8; 32];
        ratify_challenge_generate(other.as_mut_ptr(), 32);

        let render = |ctx: *const u8| -> String {
            let mut bundle = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let status = ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, f.challenge.as_ptr(), 32, NOW,
                ctx, 32, &mut bundle, &mut err,
            );
            assert_eq!(status, RatifyStatus::RatifyOk);
            let ptr = ratify_proof_bundle_to_json(bundle, &mut err);
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ratify_string_free(ptr);
            ratify_proof_bundle_free(bundle);
            s
        };

        // If these matched, the context would not be bound into the signature
        // and the whole mechanism would be decorative.
        assert_ne!(render(f.context.as_ptr()), render(other.as_ptr()));
    }
}

#[test]
fn rejects_a_context_that_is_not_exactly_32_bytes() {
    unsafe {
        let f = fixture();
        for len in [0usize, 1, 16, 31, 33, 64] {
            let mut bundle = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let status = ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, f.challenge.as_ptr(), 32, NOW,
                f.context.as_ptr(), len, &mut bundle, &mut err,
            );
            assert_eq!(
                status, RatifyStatus::RatifyErrBadArgument,
                "session_context_len {len} must be rejected"
            );
            assert!(bundle.is_null(), "no bundle on rejection");
            if !err.is_null() { ratify_string_free(err); }
        }
    }
}

#[test]
fn rejects_a_challenge_that_is_not_exactly_32_bytes() {
    unsafe {
        let f = fixture();
        for len in [0usize, 31, 33] {
            let mut bundle = std::ptr::null_mut();
            let mut err = std::ptr::null_mut();
            let status = ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, f.challenge.as_ptr(), len, NOW,
                f.context.as_ptr(), 32, &mut bundle, &mut err,
            );
            assert_eq!(
                status, RatifyStatus::RatifyErrBadArgument,
                "challenge_len {len} must be rejected"
            );
            assert!(bundle.is_null());
            if !err.is_null() { ratify_string_free(err); }
        }
    }
}

#[test]
fn rejects_null_arguments() {
    unsafe {
        let f = fixture();
        let mut bundle = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();

        let cases: [(&str, RatifyStatus); 5] = [
            ("agent", ratify_proof_bundle_create_with_context(
                std::ptr::null(), f.cert_json, f.challenge.as_ptr(), 32, NOW,
                f.context.as_ptr(), 32, &mut bundle, &mut err)),
            ("cert_json", ratify_proof_bundle_create_with_context(
                f.agent, std::ptr::null(), f.challenge.as_ptr(), 32, NOW,
                f.context.as_ptr(), 32, &mut bundle, &mut err)),
            ("challenge", ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, std::ptr::null(), 32, NOW,
                f.context.as_ptr(), 32, &mut bundle, &mut err)),
            ("session_context", ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, f.challenge.as_ptr(), 32, NOW,
                std::ptr::null(), 32, &mut bundle, &mut err)),
            ("out", ratify_proof_bundle_create_with_context(
                f.agent, f.cert_json, f.challenge.as_ptr(), 32, NOW,
                f.context.as_ptr(), 32, std::ptr::null_mut(), &mut err)),
        ];

        for (name, status) in cases {
            assert_eq!(
                status, RatifyStatus::RatifyErrNullPointer,
                "null {name} must be rejected"
            );
        }
        if !err.is_null() { ratify_string_free(err); }
    }
}
