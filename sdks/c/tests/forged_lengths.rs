//! Forged lengths and counts at the v1 C boundary.
//!
//! A C caller can pass any `size_t` with a pointer. A length or count whose
//! total size is over `isize::MAX` cannot describe a real object, and
//! forming a Rust slice over it aborts the host process instead of
//! unwinding into the panic guard. Every export must refuse it with
//! `RatifyErrBadArgument` (or NULL and an error message for the
//! string-returning functions) before reading the caller's memory.

use ratify_c::advanced::*;
use ratify_c::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

const HUGE: [usize; 2] = [isize::MAX as usize + 1, usize::MAX];

static ONE: [u8; 1] = [0];

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Take an error message, asserting it names the oversized length.
fn take_err(err: *mut c_char, what: &str) {
    assert!(!err.is_null(), "{what}: no error message");
    let msg = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe { ratify_error_free(err) };
    assert!(msg.contains("isize::MAX"), "{what}: {msg}");
}

fn take_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { ratify_string_free(s) };
    }
}

/// One export called with the forged length, writing its error to `err`.
type Probe<'a> = Box<dyn Fn(*mut *mut c_char) -> RatifyStatus + 'a>;

fn agent() -> *mut RatifyAgent {
    let (name, kind) = (cs("forged"), cs("custom"));
    let mut a = ptr::null_mut();
    assert_eq!(
        unsafe { ratify_agent_generate(name.as_ptr(), kind.as_ptr(), &mut a) },
        RatifyStatus::RatifyOk
    );
    a
}

#[test]
fn status_returning_exports_reject_lengths_over_isize_max() {
    let mut root = ptr::null_mut();
    assert_eq!(
        unsafe { ratify_human_root_generate(&mut root) },
        RatifyStatus::RatifyOk
    );
    let store = ratify_challenge_store_new(8);
    assert!(!store.is_null());
    let a = agent();
    let challenge = [7u8; 32];
    let sig = unsafe {
        ratify_agent_sign_challenge(
            a,
            challenge.as_ptr(),
            32,
            1_800_000_000,
            ptr::null(),
            0,
            ptr::null(),
            0,
            0,
            ptr::null_mut(),
        )
    };
    let public = unsafe { ratify_agent_pub_key_json(a, ptr::null_mut()) };
    assert!(!sig.is_null() && !public.is_null());
    let (id, aid, scope) = (cs("v1"), cs("agent"), cs("files:read"));
    let (op, resource, path) = (cs("read"), cs("r"), cs("/"));

    for len in HUGE {
        let mut cases: Vec<(&str, Probe)> = vec![
            (
                "policy_verdict_issue policy_secret",
                Box::new(|err| unsafe {
                    let mut out = ptr::null_mut();
                    let s = ratify_policy_verdict_issue(
                        id.as_ptr(),
                        aid.as_ptr(),
                        scope.as_ptr(),
                        1,
                        challenge.as_ptr(),
                        32,
                        0,
                        1,
                        ONE.as_ptr(),
                        len,
                        &mut out,
                        err,
                    );
                    assert!(out.is_null());
                    s
                }),
            ),
            (
                "witness_entry_issue entry_data",
                Box::new(|err| unsafe {
                    let mut out = ptr::null_mut();
                    let s = ratify_witness_entry_issue(
                        root,
                        ONE.as_ptr(),
                        len,
                        0,
                        ptr::null(),
                        0,
                        &mut out,
                        err,
                    );
                    assert!(out.is_null());
                    s
                }),
            ),
            (
                "challenge_store_check challenge",
                Box::new(|err| unsafe {
                    ratify_challenge_store_check(store, ONE.as_ptr(), len, ptr::null(), 0, 0, err)
                }),
            ),
            (
                "challenge_store_consume challenge",
                Box::new(|err| unsafe {
                    ratify_challenge_store_consume(store, ONE.as_ptr(), len, ptr::null(), 0, 0, err)
                }),
            ),
            (
                "challenge_store_check session_context",
                Box::new(|err| unsafe {
                    ratify_challenge_store_check(
                        store,
                        challenge.as_ptr(),
                        32,
                        ONE.as_ptr(),
                        len,
                        0,
                        err,
                    )
                }),
            ),
            (
                "operation_context_hash payload_digest",
                Box::new(|err| unsafe {
                    let mut out = [0u8; 32];
                    ratify_operation_context_hash(
                        scope.as_ptr(),
                        op.as_ptr(),
                        resource.as_ptr(),
                        path.as_ptr(),
                        ONE.as_ptr(),
                        len,
                        out.as_mut_ptr(),
                        err,
                    )
                }),
            ),
            (
                "verify_challenge_signature challenge",
                Box::new(|err| unsafe {
                    let mut valid = 1;
                    ratify_verify_challenge_signature(
                        ONE.as_ptr(),
                        len,
                        0,
                        ptr::null(),
                        0,
                        ptr::null(),
                        0,
                        0,
                        sig,
                        public,
                        &mut valid,
                        err,
                    )
                }),
            ),
            (
                "verify_delegation_signature_v2 signable",
                Box::new(|err| unsafe {
                    let mut valid = 1;
                    let s = ratify_verify_delegation_signature_v2(
                        ONE.as_ptr(),
                        len,
                        sig,
                        public,
                        &mut valid,
                        err,
                    );
                    assert_eq!(valid, 0);
                    s
                }),
            ),
        ];
        for (what, f) in cases.drain(..) {
            let mut err = ptr::null_mut();
            let status = f(&mut err);
            assert_eq!(
                status,
                RatifyStatus::RatifyErrBadArgument,
                "{what} length {len}"
            );
            if what.starts_with("verify_delegation_signature_v2") {
                // Its existing guard predates the shared diagnostic.
                take_string(err);
            } else {
                take_err(err, what);
            }
        }
    }
    take_string(sig);
    take_string(public);
    unsafe {
        ratify_agent_free(a);
        ratify_challenge_store_free(store);
        ratify_human_root_free(root);
    }
}

#[test]
fn pointer_returning_exports_reject_lengths_over_isize_max() {
    let a = agent();
    for len in HUGE {
        let mut err = ptr::null_mut();
        let out = unsafe {
            ratify_challenge_sign_bytes_hex(
                ONE.as_ptr(),
                len,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                0,
                &mut err,
            )
        };
        assert!(out.is_null());
        take_err(err, "challenge_sign_bytes_hex");

        let mut err = ptr::null_mut();
        let out = unsafe {
            ratify_agent_sign_challenge(
                a,
                ONE.as_ptr(),
                len,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                0,
                &mut err,
            )
        };
        assert!(out.is_null());
        take_err(err, "agent_sign_challenge");

        // A count of pointers whose total size is over isize::MAX.
        let arrays = [ptr::null::<c_char>()];
        let count = len / std::mem::size_of::<*const c_char>() + 1;
        let mut err = ptr::null_mut();
        let out = unsafe { ratify_scopes_intersect(arrays.as_ptr(), count, &mut err) };
        assert!(out.is_null());
        take_err(err, "scopes_intersect");
    }
    unsafe { ratify_agent_free(a) };
}
