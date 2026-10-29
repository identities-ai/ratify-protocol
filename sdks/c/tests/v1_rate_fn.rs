//! v1 `max_rate` through the C `rate_fn` adapter (SPEC §5.6).
//!
//! The adapter must never turn a rate lookup it cannot make into "no
//! invocations": a `cert_id` that cannot cross into a C string (it contains
//! U+0000) and a negative count from the callback both fail closed, and the C
//! result matches the Rust SDK for the same bundle and counter.

use ratify_c::{
    ratify_string_free, ratify_verify_bundle_opts, ratify_verify_result_free,
    ratify_verify_result_identity_status, ratify_verify_result_is_valid, RatifyStatus,
    RatifyVerifierContext, RatifyVerifyOptions,
};
use ratify_protocol::*;
use std::cell::Cell;
use std::ffi::{c_char, c_void, CStr, CString};

const NOW: i64 = 1_800_000_000;

struct Counter {
    count: i64,
    calls: Cell<u32>,
}

unsafe extern "C" fn rate_fn(_cert_id: *const c_char, _window_s: i64, ud: *mut c_void) -> i64 {
    let c = &*(ud as *const Counter);
    c.calls.set(c.calls.get() + 1);
    c.count
}

fn bundle(cert_id: &str) -> ProofBundle {
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("rate-agent", "custom").unwrap();
    let mut cert = DelegationCert {
        cert_id: cert_id.into(),
        version: 1,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec!["meeting:attend".into()],
        constraints: vec![Constraint {
            kind: "max_rate".into(),
            count: 1,
            window_s: 60,
            ..Default::default()
        }],
        issued_at: NOW - 10,
        expires_at: NOW + 3600,
        signature: HybridSignature {
            ed25519: vec![],
            ml_dsa_65: vec![],
        },
    };
    issue_delegation(&mut cert, &root_priv).unwrap();
    let challenge = vec![7u8; 32];
    let challenge_sig = sign_challenge(&challenge, NOW, &agent_priv);
    ProofBundle {
        agent_id: agent.id,
        agent_pub_key: agent.public_key,
        delegations: vec![cert],
        challenge,
        challenge_at: NOW,
        challenge_sig,
        session_context: vec![],
        stream_id: vec![],
        stream_seq: 0,
    }
}

/// Returns (valid, identity_status, callback calls) from the C ABI.
fn verify_c(b: &ProofBundle, count: i64) -> (bool, String, u32) {
    let json = CString::new(serde_json::to_string(b).unwrap()).unwrap();
    let counter = Counter {
        count,
        calls: Cell::new(0),
    };
    let ctx = RatifyVerifierContext {
        current_lat: 0.0,
        current_lon: 0.0,
        current_alt_m: 0.0,
        has_location: 0,
        current_speed_mps: 0.0,
        has_speed: 0,
        requested_amount: 0.0,
        requested_currency: std::ptr::null(),
        has_amount: 0,
        rate_fn: Some(rate_fn),
        rate_userdata: &counter as *const Counter as *mut c_void,
    };
    let scope = CString::new("meeting:attend").unwrap();
    let opts = RatifyVerifyOptions {
        required_scope: scope.as_ptr(),
        now_unix: NOW,
        session_context: std::ptr::null(),
        session_context_len: 0,
        revocation_fn: None,
        revocation_userdata: std::ptr::null_mut(),
        context: &ctx,
        stream: std::ptr::null(),
    };
    unsafe {
        let mut out = std::ptr::null_mut();
        let mut err = std::ptr::null_mut();
        let st = ratify_verify_bundle_opts(json.as_ptr(), &opts, &mut out, &mut err);
        assert_eq!(st, RatifyStatus::RatifyOk);
        assert!(!out.is_null());
        let valid = ratify_verify_result_is_valid(out) == 1;
        let p = ratify_verify_result_identity_status(out);
        let status = CStr::from_ptr(p).to_string_lossy().into_owned();
        ratify_string_free(p);
        ratify_verify_result_free(out);
        (valid, status, counter.calls.get())
    }
}

fn verify_rust(b: &ProofBundle, count: i64) -> (bool, String) {
    let opts = VerifyOptions {
        required_scope: "meeting:attend".into(),
        now: Some(NOW),
        context: VerifierContext {
            invocations_in_window: Some(Box::new(move |_: &str, _: i64| count)),
            ..Default::default()
        },
        ..Default::default()
    };
    let r = verify_bundle(b, &opts);
    (r.valid, r.identity_status.as_str().to_owned())
}

#[test]
fn rate_fn_exhausted_window_denies() {
    let b = bundle("rate-cert");
    let (valid, status, calls) = verify_c(&b, 5);
    assert!(!valid);
    assert_eq!(status, "constraint_denied");
    assert_eq!(calls, 1);
    assert_eq!(verify_rust(&b, 5), (valid, status));
}

#[test]
fn rate_fn_cert_id_with_nul_fails_closed() {
    // The counter would deny (5 >= 1), but it can never be asked about a
    // cert_id that contains U+0000. That must not read as "zero invocations".
    let b = bundle("rate\u{0}cert");
    let (valid, status, calls) = verify_c(&b, 5);
    assert!(!valid, "a cert_id the callback cannot see must not pass max_rate");
    assert_eq!(status, "constraint_unverifiable");
    assert_eq!(calls, 0, "the callback must not see a truncated cert_id");
    // Even a counter that would allow cannot rescue it.
    let (valid, status, _) = verify_c(&b, 0);
    assert!(!valid);
    assert_eq!(status, "constraint_unverifiable");
}

#[test]
fn rate_fn_negative_count_fails_closed() {
    let b = bundle("rate-cert");
    for count in [-1, i64::MIN] {
        let (valid, status, calls) = verify_c(&b, count);
        assert!(!valid, "count {count} must not allow");
        assert_eq!(status, "constraint_unverifiable");
        assert_eq!(calls, 1);
        assert_eq!(verify_rust(&b, count), (valid, status));
    }
}
