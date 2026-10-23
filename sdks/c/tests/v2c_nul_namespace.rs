//! A configured verifier namespace reaches the claim and issuance store
//! callbacks as a C string, which cannot carry U+0000. Stripping the NUL
//! would key `"lab\0x"` and `"labx"` to the same store records, so a
//! configured namespace containing U+0000 is `configuration_invalid` before
//! any callback runs.

mod v2c_common;

use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use ratify_c::*;
use serde_json::json;
use v2c_common::*;

static PERSISTS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn now(_: *mut c_void, out: *mut i64) -> i32 {
    *out = 1_800_000_000;
    0
}

unsafe extern "C" fn fill(_: *mut c_void, out: *mut u8, len: usize) -> i32 {
    ptr::write_bytes(out, 7, len);
    0
}

unsafe extern "C" fn persist(
    _: *mut c_void,
    _: *const c_char,
    _: i64,
    _: RatifyV2Slice,
    _: RatifyV2Slice,
) -> i32 {
    PERSISTS.fetch_add(1, Ordering::SeqCst);
    0
}

fn issue(namespace: &str) -> R<Vec<u8>> {
    let req = json_bytes(&json!({
        "verifier_namespace": namespace,
        "replay_epoch": 1,
        "verifier_id": "ab".repeat(32),
        "lifetime_seconds": 60,
    }));
    let clock = RatifyV2ClockCallbacks {
        user: ptr::null_mut(),
        now: Some(now),
    };
    let store = RatifyV2IssuanceStoreCallbacks {
        user: ptr::null_mut(),
        persist: Some(persist),
        load: None,
    };
    let random = RatifyV2RandomCallbacks {
        user: ptr::null_mut(),
        fill: Some(fill),
    };
    buf(|o| unsafe {
        ratify_v2_issue_challenge(req.as_ptr(), req.len(), &clock, &store, &random, o)
    })
}

#[test]
fn issue_challenge_refuses_nul_in_configured_namespace() {
    issue("labx").expect("control issuance");
    assert_eq!(PERSISTS.swap(0, Ordering::SeqCst), 1);
    let e = issue("lab\u{0}x").expect_err("a NUL namespace must not be issued");
    assert_eq!(e.class, "configuration_invalid", "{}", e.message);
    assert_eq!(
        PERSISTS.load(Ordering::SeqCst),
        0,
        "the store must never see the namespace"
    );
}

#[test]
fn verify_refuses_nul_in_configured_namespace() {
    let req = json_bytes(&json!({"verifier_namespace": "lab\u{0}x"}));
    let bundle = b"{}";
    // SAFETY: every member of the callback struct is a nullable pointer.
    let callbacks: RatifyV2VerifyCallbacks = unsafe { std::mem::zeroed() };
    let mut outcome = RatifyV2VerifyOutcome {
        stage: 0,
        error_code: 0,
        disposition: 0,
    };
    let mut committed = ptr::null_mut();
    let code = unsafe {
        ratify_v2_verify_proof_bundle(
            bundle.as_ptr(),
            bundle.len(),
            req.as_ptr(),
            req.len(),
            ptr::null(),
            &callbacks,
            &mut outcome,
            ptr::null_mut(),
            &mut committed,
        )
    };
    let message = last_error();
    assert_eq!(class(code), "configuration_invalid", "{message}");
    assert!(message.contains("U+0000"), "{message}");
    assert!(committed.is_null());
}
