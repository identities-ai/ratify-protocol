//! Panic containment at the C ABI boundary.
//!
//! A Rust panic that unwinds into C is undefined behaviour (or, since Rust
//! 1.81, a process abort). Every export must catch it and return its
//! documented internal-error value with outputs in a defined state, so a
//! verifier embedded in a long-running host fails closed on one request
//! instead of taking the host down. These tests drive the real exports through
//! the test-only `panic-test-hook` injection point, and statically check that
//! no export bypasses the guard.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;

use ratify_c::test_hook::{arm_after_body, arm_before_body};
use ratify_c::*;

const PANIC_MESSAGE: &str = "internal error: a panic was caught at the C ABI boundary";

fn sentinel<T>() -> *mut T {
    // A non-NULL value no export would ever write; it must not survive a panic.
    std::ptr::NonNull::dangling().as_ptr()
}

unsafe fn take_err(err: *mut c_char) -> String {
    assert!(!err.is_null(), "a caught panic must write err_out");
    let s = CStr::from_ptr(err).to_str().unwrap().to_owned();
    ratify_error_free(err);
    s
}

// --- v1 -------------------------------------------------------------------

/// The panic fires after the body has stored a fresh handle in `*out`; the
/// caller must still see NULL, never a handle from a call that reported failure.
#[test]
fn v1_status_export_panic_after_output_written_returns_internal_and_null_out() {
    unsafe {
        let mut out: *mut RatifyHumanRoot = sentinel();
        arm_after_body();
        let st = ratify_human_root_generate(&mut out);
        assert_eq!(st, RatifyStatus::RatifyErrInternal);
        assert!(out.is_null());
    }
}

#[test]
fn v1_status_export_panic_before_body_returns_internal_and_null_out() {
    unsafe {
        let mut out: *mut RatifyHumanRoot = sentinel();
        arm_before_body();
        assert_eq!(
            ratify_human_root_generate(&mut out),
            RatifyStatus::RatifyErrInternal
        );
        assert!(out.is_null());
    }
}

/// Key material is the worst partial output to leak: after a panic the seed
/// buffers must be zeroed and the public-key string NULL, with a diagnostic.
#[test]
fn v1_keypair_panic_zeroes_seeds_and_nulls_json() {
    unsafe {
        let mut pub_json: *mut c_char = sentinel();
        let mut ed = [0xAAu8; 32];
        let mut ml = [0xAAu8; 32];
        let mut err: *mut c_char = ptr::null_mut();
        arm_after_body();
        let st = ratify_generate_hybrid_keypair(
            &mut pub_json,
            ed.as_mut_ptr(),
            ml.as_mut_ptr(),
            &mut err,
        );
        assert_eq!(st, RatifyStatus::RatifyErrInternal);
        assert!(pub_json.is_null());
        assert_eq!(ed, [0u8; 32]);
        assert_eq!(ml, [0u8; 32]);
        assert_eq!(take_err(err), PANIC_MESSAGE);
    }
}

/// A validity flag written as 1 before the panic must read 0 (fail closed).
#[test]
fn v1_valid_out_is_cleared_to_invalid() {
    unsafe {
        let cert = c"{not json";
        let mut valid: i32 = 1;
        let mut err: *mut c_char = ptr::null_mut();
        arm_before_body();
        let st = ratify_verify_delegation_signature(cert.as_ptr(), &mut valid, &mut err);
        assert_eq!(st, RatifyStatus::RatifyErrInternal);
        assert_eq!(valid, 0);
        assert_eq!(take_err(err), PANIC_MESSAGE);
    }
}

#[test]
fn v1_pointer_and_value_exports_fail_closed() {
    unsafe {
        let mut err: *mut c_char = ptr::null_mut();
        arm_after_body();
        assert!(ratify_scopes_expand(c"[\"meeting:*\"]".as_ptr(), &mut err).is_null());
        assert_eq!(take_err(err), PANIC_MESSAGE);

        arm_before_body();
        assert!(ratify_scope_vocabulary().is_null());

        // Fail-closed integer results: treat as invalid / not granted /
        // sensitive / revoked rather than the permissive answer.
        arm_before_body();
        assert_eq!(ratify_verify_result_is_valid(ptr::null()), 0);
        arm_before_body();
        assert_eq!(ratify_scope_has(c"[\"a:b\"]".as_ptr(), c"a:b".as_ptr()), 0);
        arm_before_body();
        assert_eq!(ratify_scope_is_sensitive(c"meeting:attend".as_ptr()), 1);
        arm_before_body();
        assert_eq!(ratify_revocation_list_contains(ptr::null(), ptr::null()), 1);

        // Free functions swallow the panic.
        arm_before_body();
        ratify_string_free(ptr::null_mut());
    }
}

/// A caught panic leaves the library usable: the next call succeeds.
#[test]
fn library_is_usable_after_a_caught_panic() {
    unsafe {
        let mut out: *mut RatifyHumanRoot = ptr::null_mut();
        arm_before_body();
        assert_eq!(
            ratify_human_root_generate(&mut out),
            RatifyStatus::RatifyErrInternal
        );
        assert_eq!(ratify_human_root_generate(&mut out), RatifyStatus::RatifyOk);
        assert!(!out.is_null());
        ratify_human_root_free(out);
    }
}

// --- v2 -------------------------------------------------------------------

/// The panic fires after `ratify_v2_key_id` has written the 64-hex key ID;
/// the buffer must read as the empty string and the code must be `internal`.
#[test]
fn v2_export_panic_after_output_written_returns_internal_and_empty_out() {
    unsafe {
        let ed = [7u8; 32];
        let ml = [7u8; 1952];
        let mut out = [b'x' as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
        let mut err: *mut c_char = ptr::null_mut();

        // Sanity: without the hook the same call succeeds and writes the ID.
        let ok = ratify_v2_key_id(
            ed.as_ptr(),
            ed.len(),
            ml.as_ptr(),
            ml.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut err,
        );
        assert_eq!(ok, RatifyV2Code::RatifyV2Ok as i32);
        assert_eq!(CStr::from_ptr(out.as_ptr()).to_bytes().len(), 64);

        arm_after_body();
        let code = ratify_v2_key_id(
            ed.as_ptr(),
            ed.len(),
            ml.as_ptr(),
            ml.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut err,
        );
        assert_eq!(code, RatifyV2Code::RatifyV2ErrInternal as i32);
        assert_eq!(code, -3);
        assert_eq!(out[0], 0);
        assert_eq!(take_err(err), format!("internal: {PANIC_MESSAGE}"));
        assert_eq!(
            CStr::from_ptr(ratify_v2_error_class_str(code))
                .to_str()
                .unwrap(),
            "internal"
        );
    }
}

#[test]
fn v2_verify_panic_before_body_returns_internal() {
    unsafe {
        let wire = [0u8; 4];
        let mut err: *mut c_char = ptr::null_mut();
        arm_before_body();
        let code = ratify_v2_verify_object(1, wire.as_ptr(), wire.len(), ptr::null(), &mut err);
        assert_eq!(code, RatifyV2Code::RatifyV2ErrInternal as i32);
        assert!(take_err(err).starts_with("internal: "));

        // A failed ABI version query must not match any real header.
        arm_before_body();
        assert_eq!(ratify_v2_abi_version(), 0);
    }
}

// --- every export goes through the guard ------------------------------------

fn sdk_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Function names declared in the committed C header.
fn header_exports() -> BTreeSet<String> {
    let h = fs::read_to_string(sdk_dir().join("include/ratify.h")).unwrap();
    let mut names = BTreeSet::new();
    for line in h.lines() {
        if line.starts_with(' ') || line.starts_with('/') || line.starts_with('#') {
            continue;
        }
        if let Some(open) = line.find('(') {
            let head = &line[..open];
            let name = head
                .rsplit(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap();
            if name.starts_with("ratify_") {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

/// Skip past a string, char literal, or comment starting at `i`.
fn skip_literal(b: &[u8], i: usize) -> Option<usize> {
    match b[i] {
        b'/' if b.get(i + 1) == Some(&b'/') => Some(i + b[i..].iter().position(|&c| c == b'\n')?),
        b'"' => {
            let mut j = i + 1;
            while b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            Some(j + 1)
        }
        b'\'' if b[i + 1] == b'\\' => {
            Some(i + 2 + b[i + 2..].iter().position(|&c| c == b'\'')? + 1)
        }
        b'\'' if b.get(i + 2) == Some(&b'\'') => Some(i + 3),
        _ => None,
    }
}

/// Index of the bracket closing the one opened at `open`.
fn matching(b: &[u8], open: usize) -> usize {
    let (o, c) = (b[open], if b[open] == b'(' { b')' } else { b'}' });
    let (mut depth, mut i) = (0usize, open);
    loop {
        if let Some(j) = skip_literal(b, i) {
            i = j;
            continue;
        }
        if b[i] == o {
            depth += 1;
        } else if b[i] == c {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
        i += 1;
    }
}

/// Every Rust source file of the crate, relative to src/.
fn source_files() -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![sdk_dir().join("src")];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p.strip_prefix(sdk_dir().join("src")).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

/// The v2 guard helpers (src/v2/mod.rs); each must delegate to `ffi_guard`.
const V2_GUARDS: &[&str] = &["run(", "run_h(", "run_value("];

/// For every `extern "C" fn` in src/, the body must be exactly one call to a
/// guard: `crate::guard::{guard_status, guard_ptr, ffi_guard}(…)`, or a v2
/// helper (`run`, `run_h`, `run_value`), each of which must itself delegate
/// to `ffi_guard`.
fn guarded_source_exports() -> BTreeSet<String> {
    const GUARDS: &[&str] = &[
        "crate::guard::guard_status(",
        "crate::guard::guard_ptr(",
        "crate::guard::ffi_guard(",
    ];
    let v2 = fs::read_to_string(sdk_dir().join("src/v2/mod.rs")).unwrap();
    for helper in ["run", "run_h", "run_value"] {
        let at = v2.find(&format!("\npub(crate) fn {helper}")).unwrap_or_else(|| panic!("v2 helper {helper}"));
        let body_open = at + v2[at..].find("{\n").unwrap();
        let body = v2[body_open + 1..].trim_start();
        let body = body.strip_prefix("run_h(").map_or(body, |_| "crate::guard::ffi_guard(");
        assert!(body.starts_with("crate::guard::ffi_guard("), "v2 {helper} must use ffi_guard");
    }
    let mut names = BTreeSet::new();
    let mut unguarded = Vec::new();
    for file in source_files() {
        let file = file.as_str();
        let src = fs::read_to_string(sdk_dir().join("src").join(file)).unwrap();
        let b = src.as_bytes();
        let is_v2 = file.starts_with("v2");
        let mut from = 0;
        while let Some(at) = src[from..].find("extern \"C\" fn ratify_") {
            let start = from + at + "extern \"C\" fn ".len();
            let name: String = src[start..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let params_open = start + name.len();
            assert_eq!(b[params_open], b'(', "{name}: unexpected signature shape");
            let params_close = matching(b, params_open);
            let body_open = params_close + src[params_close..].find('{').unwrap();
            let body_close = matching(b, body_open);
            let body = src[body_open + 1..body_close].trim();
            let guard_len = GUARDS
                .iter()
                .find(|g| body.starts_with(**g))
                .map(|g| g.len())
                .or_else(|| {
                    V2_GUARDS
                        .iter()
                        .find(|g| is_v2 && body.starts_with(**g))
                        .map(|g| g.len())
                });
            let ok = guard_len.is_some_and(|len| {
                // The guard call must be the whole body: nothing may run
                // before it or after it outside the catch_unwind.
                let call_open = body_open
                    + 1
                    + (src[body_open + 1..].len() - src[body_open + 1..].trim_start().len())
                    + len
                    - 1;
                let call_close = matching(b, call_open);
                src[call_close + 1..body_close].trim().is_empty()
            });
            if !ok {
                unguarded.push(format!("{file}: {name}"));
            }
            names.insert(name);
            from = body_close;
        }
    }
    assert!(
        unguarded.is_empty(),
        "exports not wrapped in the panic guard: {unguarded:#?}"
    );
    names
}

#[test]
fn every_export_goes_through_the_panic_guard() {
    let header = header_exports();
    let source = guarded_source_exports();
    // The header is the ABI: every symbol declared there must be a guarded
    // source export, and the scan must not have missed any source export.
    assert!(
        header.len() > 100,
        "header parse found only {} exports",
        header.len()
    );
    assert_eq!(header, source, "header and guarded source exports differ");
}
