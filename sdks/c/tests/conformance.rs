//! C API conformance tests — validates the C FFI layer against the same
//! 59 canonical test vectors used by Go, TypeScript, Python, and Rust.
//!
//! Every "verify" fixture is loaded, its proof bundle serialised to JSON,
//! passed through the C API with the appropriate options (scope, clock,
//! session context, stream context, revocation provider, constraint context),
//! and the result compared against the expected outcome.
//!
//! If all verify fixtures pass, the C ABI produces byte-identical decisions
//! to every other reference SDK implementation.

use ratify_c::{
    ratify_error_free, ratify_string_free, ratify_verify_bundle_opts,
    ratify_verify_result_free, ratify_verify_result_identity_status,
    ratify_verify_result_is_valid, RatifyStatus, RatifyStreamContext,
    RatifyVerifierContext, RatifyVerifyOptions, RatifyVerifyResult,
};
use serde::Deserialize;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Fixture schema
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct FixtureVerifierContext {
    current_lat: Option<f64>,
    current_lon: Option<f64>,
    current_alt_m: Option<f64>,
    current_speed_mps: Option<f64>,
    requested_amount: Option<f64>,
    #[serde(default)]
    requested_currency: String,
    /// Fixed return value for the max_rate constraint's invocations counter.
    invocations_in_window_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    kind: String,
    bundle: Option<serde_json::Value>,
    #[serde(default)]
    verifier_context: Option<FixtureVerifierContext>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    verify_result: Option<VerifyResult>,
    verify_options: Option<VerifyOpts>,
}

#[derive(Debug, Deserialize)]
struct VerifyResult {
    valid: bool,
    identity_status: String,
}

#[derive(Debug, Deserialize, Default)]
struct VerifyOpts {
    #[serde(default)]
    required_scope: String,
    #[serde(default)]
    now: i64,
    /// base64-encoded 32-byte session context for session-bound bundles
    #[serde(default)]
    session_context: String,
    /// stream binding options for v1.1 stream-bound bundles
    stream: Option<StreamOpts>,
}

#[derive(Debug, Deserialize)]
struct StreamOpts {
    /// base64-encoded 32-byte stream ID
    stream_id: String,
    #[serde(default)]
    last_seen_seq: i64,
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

fn testvector_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("..").join("..").join("testvectors").join("v1")
}

fn load_fixtures() -> Vec<Fixture> {
    let dir = testvector_dir();
    let mut fixtures = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        if let Ok(f) = serde_json::from_str::<Fixture>(&raw) {
            fixtures.push(f);
        }
    }
    fixtures
}

// ---------------------------------------------------------------------------
// VerifierContext builder from fixture data
// ---------------------------------------------------------------------------

/// Conformance revocation callback.
/// `userdata` is a `*const c_char` pointing to the revoked cert_id (null-terminated).
/// Returns 1 if the queried cert_id matches the stored revoked cert_id, 0 otherwise.
unsafe extern "C" fn conformance_revocation(
    cert_id: *const std::os::raw::c_char,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if cert_id.is_null() || userdata.is_null() { return 0; }
    let queried = CStr::from_ptr(cert_id);
    let revoked = CStr::from_ptr(userdata as *const std::os::raw::c_char);
    if queried == revoked { 1 } else { 0 }
}

/// Rate-counter callback: `userdata` is a `*const i64` holding the fixed count
/// the fixture expects (simulates a rate-counter database).
unsafe extern "C" fn fixed_rate_count(
    _cert_id: *const std::os::raw::c_char,
    _window_s: i64,
    userdata: *mut std::ffi::c_void,
) -> i64 {
    *(userdata as *const i64)
}

struct BuiltContext {
    ctx: RatifyVerifierContext,
    /// currency string storage (must outlive ctx)
    _currency: Option<std::ffi::CString>,
    /// rate count storage (must outlive ctx)
    _rate_count: Option<Box<i64>>,
}

fn build_verifier_context(vc: &FixtureVerifierContext) -> BuiltContext {
    let has_location = vc.current_lat.is_some() as std::os::raw::c_int;
    let has_speed    = vc.current_speed_mps.is_some() as std::os::raw::c_int;
    let has_amount   = vc.requested_amount.is_some() as std::os::raw::c_int;

    let currency_cstr = if !vc.requested_currency.is_empty() {
        std::ffi::CString::new(vc.requested_currency.clone()).ok()
    } else {
        None
    };
    let currency_ptr = currency_cstr.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

    let rate_count_box = vc.invocations_in_window_count.map(Box::new);
    let (rate_fn, rate_ud) = if let Some(ref b) = rate_count_box {
        (
            Some(fixed_rate_count as unsafe extern "C" fn(*const _, i64, *mut _) -> i64),
            b.as_ref() as *const i64 as *mut std::ffi::c_void,
        )
    } else {
        (None, std::ptr::null_mut())
    };

    BuiltContext {
        ctx: RatifyVerifierContext {
            current_lat:        vc.current_lat.unwrap_or(0.0),
            current_lon:        vc.current_lon.unwrap_or(0.0),
            current_alt_m:      vc.current_alt_m.unwrap_or(0.0),
            has_location,
            current_speed_mps:  vc.current_speed_mps.unwrap_or(0.0),
            has_speed,
            requested_amount:   vc.requested_amount.unwrap_or(0.0),
            requested_currency: currency_ptr,
            has_amount,
            rate_fn,
            rate_userdata: rate_ud,
        },
        _currency: currency_cstr,
        _rate_count: rate_count_box,
    }
}

// ---------------------------------------------------------------------------
// C API helpers
// ---------------------------------------------------------------------------

unsafe fn c_verify_opts(
    bundle_json: &str,
    scope: &str,
    now: i64,
    session_ctx: Option<&[u8; 32]>,
    stream_ctx: Option<&RatifyStreamContext>,
    verifier_ctx: Option<&RatifyVerifierContext>,
    // When Some, wire a revocation callback that marks this specific cert_id as revoked.
    revoked_cert_id: Option<&CString>,
) -> (*mut RatifyVerifyResult, RatifyStatus) {
    let bundle_c = CString::new(bundle_json).expect("bundle_json nul");
    let scope_c = CString::new(scope).expect("scope nul");

    let (rev_fn, rev_ud) = if let Some(cid) = revoked_cert_id {
        (
            Some(conformance_revocation as unsafe extern "C" fn(*const _, *mut _) -> _),
            cid.as_ptr() as *mut std::ffi::c_void,
        )
    } else {
        (None, std::ptr::null_mut())
    };

    let mut result: *mut RatifyVerifyResult = std::ptr::null_mut();
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    let session_ctx_len = if session_ctx.is_some() { 32usize } else { 0usize };
    let opts = RatifyVerifyOptions {
        required_scope: if scope.is_empty() { std::ptr::null() } else { scope_c.as_ptr() },
        now_unix: now,
        session_context: session_ctx.map_or(std::ptr::null(), |b| b.as_ptr()),
        session_context_len: session_ctx_len,
        revocation_fn: rev_fn,
        revocation_userdata: rev_ud,
        context: verifier_ctx.map_or(std::ptr::null(), |c| c as *const _),
        stream: stream_ctx.map_or(std::ptr::null(), |s| s as *const _),
    };

    let status = ratify_verify_bundle_opts(bundle_c.as_ptr(), &opts, &mut result, &mut err);
    if !err.is_null() {
        let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
        ratify_error_free(err);
        eprintln!("  ratify_verify_bundle_opts error: {msg}");
    }
    (result, status)
}

unsafe fn result_valid(r: *const RatifyVerifyResult) -> bool {
    ratify_verify_result_is_valid(r) != 0
}

unsafe fn result_status(r: *const RatifyVerifyResult) -> String {
    let ptr = ratify_verify_result_identity_status(r);
    if ptr.is_null() { return String::new(); }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_string_free(ptr);
    s
}

// ---------------------------------------------------------------------------
// Conformance test
// ---------------------------------------------------------------------------

#[test]
fn c_api_passes_all_verify_fixtures() {
    let fixtures = load_fixtures();
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        if fixture.kind != "verify" { skipped += 1; continue; }
        let bundle_val = match &fixture.bundle { Some(b) => b, None => { skipped += 1; continue; } };
        let expected = match &fixture.expected.verify_result { Some(e) => e, None => { skipped += 1; continue; } };

        // "revoked" fixtures: use a conformance RevocationProvider that marks
        // delegations[1].cert_id as revoked — mirrors the Rust conformance test.

        total += 1;

        let bundle_json = serde_json::to_string(bundle_val)
            .unwrap_or_else(|e| panic!("re-serialise {}: {e}", fixture.name));

        let opts = fixture.expected.verify_options.as_ref();
        let scope = opts.map(|o| o.required_scope.as_str()).unwrap_or("");
        let now = opts.map(|o| o.now).unwrap_or(0);

        // Build verifier context from fixture (covers geo, speed, amount, rate)
        let built_ctx = fixture.verifier_context.as_ref().map(build_verifier_context);

        // For "revoked" fixtures: mark delegations[1].cert_id as revoked,
        // mirroring the Rust conformance test's ConformanceRevocation provider.
        let revoked_cert_cstr: Option<CString> = if expected.identity_status == "revoked" {
            let delegations = bundle_val.get("delegations")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();
            if delegations.len() > 1 {
                delegations[1].get("cert_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| CString::new(id).ok())
            } else {
                None
            }
        } else {
            None
        };

        // Decode session_context from base64 if present
        let session_bytes: Option<[u8; 32]> = opts
            .and_then(|o| if o.session_context.is_empty() { None } else { Some(&o.session_context) })
            .and_then(|b64| {
                let mut dec = Vec::new();
                if base64_decode(b64, &mut dec) && dec.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&dec);
                    Some(arr)
                } else {
                    eprintln!("  WARN {} bad session_context base64 (len={})", fixture.name, dec.len());
                    None
                }
            });

        // Decode stream context if present
        let stream_id_bytes: Option<[u8; 32]> = opts
            .and_then(|o| o.stream.as_ref())
            .and_then(|s| {
                let mut dec = Vec::new();
                if base64_decode(&s.stream_id, &mut dec) && dec.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&dec);
                    Some(arr)
                } else {
                    eprintln!("  WARN {} bad stream_id base64 (len={})", fixture.name, dec.len());
                    None
                }
            });
        let stream_last_seq = opts.and_then(|o| o.stream.as_ref()).map(|s| s.last_seen_seq).unwrap_or(0);

        let stream_ctx = stream_id_bytes.as_ref().map(|id| RatifyStreamContext {
            stream_id: id.as_ptr(),
            stream_id_len: 32,
            last_seen_seq: stream_last_seq,
        });

        unsafe {
            let (result, status) = c_verify_opts(
                &bundle_json,
                scope,
                now,
                session_bytes.as_ref(),
                stream_ctx.as_ref(),
                built_ctx.as_ref().map(|bc| &bc.ctx),
                revoked_cert_cstr.as_ref(),
            );

            if matches!(status, RatifyStatus::RatifyErrJson) {
                failures.push(format!(
                    "[{}] bundle JSON error — bundle shape may have changed", fixture.name
                ));
                if !result.is_null() { ratify_verify_result_free(result); }
                continue;
            }

            if result.is_null() {
                failures.push(format!("[{}] result is null (status={status:?})", fixture.name));
                continue;
            }

            let got_valid = result_valid(result);
            let got_status = result_status(result);
            ratify_verify_result_free(result);

            if got_valid == expected.valid && got_status == expected.identity_status {
                passed += 1;
            } else {
                failures.push(format!(
                    "[{}]\n  expected: valid={} status={}\n  got:      valid={} status={}",
                    fixture.name, expected.valid, expected.identity_status,
                    got_valid, got_status
                ));
            }
        }
    }

    println!(
        "\nC API conformance: {passed}/{total} passed, {skipped} skipped\n"
    );

    if !failures.is_empty() {
        panic!("{} conformance failure(s):\n{}", failures.len(), failures.join("\n\n"));
    }
}

// ---------------------------------------------------------------------------
// Minimal base64 decoder (no external deps — uses std only)
// ---------------------------------------------------------------------------

fn base64_decode(input: &str, out: &mut Vec<u8>) -> bool {
    // Standard base64 alphabet
    const TABLE: &[u8; 128] = b"\
        \x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\
        \x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\
        \x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x3e\x40\x40\x40\x3f\
        \x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x40\x40\x40\x40\x40\x40\
        \x40\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\
        \x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x40\x40\x40\x40\x40\
        \x40\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\
        \x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x40\x40\x40\x40\x40";

    let bytes = input.as_bytes();
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' { break; }
        if b as usize >= TABLE.len() { return false; }
        let v = TABLE[b as usize];
        if v == 0x40 { return false; }
        buf = (buf << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    true
}
