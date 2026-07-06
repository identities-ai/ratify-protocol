//! C API conformance tests — validates the C FFI layer against the same
//! 63 canonical test vectors used by Go, TypeScript, Python, and Rust.
//!
//! Every fixture is loaded and exercised through the C API:
//!
//! - "verify"              — proof-bundle verification (46 fixtures)
//! - "scope"               — scope expansion + validation (2 fixtures)
//! - "revocation"          — revocation list sign bytes + verify (1 fixture)
//! - "revocation_push"     — revocation push sign bytes + sig hex + verify (1 fixture)
//! - "key_rotation"        — key rotation sign bytes + verify (2 fixtures)
//! - "session_token"       — token sign bytes, MAC, streamed-turn verify (5 fixtures)
//! - "transaction_receipt" — receipt sign bytes + full verify (5 fixtures)
//! - "witness_entry"       — witness entry sign bytes + sig hex + verify (1 fixture)
//!
//! 63/63 fixtures pass (cross_sdk_vectors.json uses a different schema and is
//! handled by tests/cross_sdk.rs).

use ratify_c::{
    ratify_error_free, ratify_string_free,
    ratify_verify_bundle_opts, ratify_verify_result_free,
    ratify_verify_result_identity_status, ratify_verify_result_is_valid,
    ratify_scopes_expand, ratify_scopes_validate,
    ratify_revocation_list_sign_bytes_hex, ratify_revocation_list_verify,
    ratify_revocation_push_sign_bytes_hex,
    ratify_revocation_push_sig_ed25519_hex, ratify_revocation_push_sig_ml_dsa_65_hex,
    ratify_revocation_push_verify,
    ratify_key_rotation_sign_bytes_hex, ratify_key_rotation_verify,
    ratify_session_token_sign_bytes_hex, ratify_session_token_mac_hex,
    ratify_verify_streamed_turn,
    ratify_transaction_receipt_sign_bytes_hex, ratify_transaction_receipt_verify_full,
    ratify_witness_entry_sign_bytes_hex,
    ratify_witness_entry_sig_ed25519_hex, ratify_witness_entry_sig_ml_dsa_65_hex,
    ratify_witness_entry_verify,
    RatifyStatus, RatifyStreamContext, RatifyVerifierContext, RatifyVerifyOptions,
    RatifyVerifyResult,
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
    invocations_in_window_count: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    kind: String,
    bundle: Option<serde_json::Value>,
    #[serde(default)]
    verifier_context: Option<FixtureVerifierContext>,
    scope_input: Option<Vec<String>>,
    revocation_list: Option<serde_json::Value>,
    revocation_push: Option<serde_json::Value>,
    key_rotation: Option<serde_json::Value>,
    session_token: Option<FixtureSessionToken>,
    transaction_receipt: Option<serde_json::Value>,
    witness_entry: Option<serde_json::Value>,
    #[serde(default)]
    entities: Vec<FixtureEntity>,
    #[serde(default)]
    timestamps: std::collections::HashMap<String, i64>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct FixtureEntity {
    public_key: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct FixtureSessionToken {
    session_secret_hex: String,
    token: serde_json::Value,
    challenge: String,
    challenge_at: i64,
    challenge_sig: serde_json::Value,
    verify_now: i64,
}

#[derive(Debug, Deserialize)]
struct Expected {
    // verify fixtures
    verify_result: Option<VerifyResult>,
    verify_options: Option<VerifyOpts>,
    // scope fixtures
    expanded_scopes: Option<Vec<String>>,
    // revocation fixtures
    revocation_sign_bytes_hex: Option<String>,
    // revocation push fixtures
    revocation_push_sign_bytes_hex: Option<String>,
    revocation_push_signature_ed25519_hex: Option<String>,
    revocation_push_signature_ml_dsa_65_hex: Option<String>,
    // key rotation fixtures
    key_rotation_sign_bytes_hex: Option<String>,
    key_rotation_verify_ok: Option<bool>,
    #[serde(default)]
    key_rotation_error_reason: String,
    // session token fixtures
    session_token_sign_bytes_hex: Option<String>,
    session_token_mac_hex: Option<String>,
    streamed_turn: Option<StreamedTurn>,
    // transaction receipt fixtures
    receipt_sign_bytes_hex: Option<String>,
    receipt_valid: Option<bool>,
    #[serde(default)]
    receipt_error_reason: String,
    // witness entry fixtures
    witness_entry_sign_bytes_hex: Option<String>,
    witness_entry_signature_ed25519_hex: Option<String>,
    witness_entry_signature_ml_dsa_65_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyResult {
    valid: bool,
    identity_status: String,
}

#[derive(Debug, Deserialize)]
struct StreamedTurn {
    valid: bool,
    identity_status: String,
}

#[derive(Debug, Deserialize, Default)]
struct VerifyOpts {
    #[serde(default)]
    required_scope: String,
    #[serde(default)]
    now: i64,
    #[serde(default)]
    session_context: String,
    stream: Option<StreamOpts>,
}

#[derive(Debug, Deserialize)]
struct StreamOpts {
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
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {dir:?}: {e}"))
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut fixtures = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
        // cross_sdk_vectors.json uses a different schema — handled by tests/cross_sdk.rs
        if path.file_name().and_then(|n| n.to_str()) == Some("cross_sdk_vectors.json") { continue; }
        let raw = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        match serde_json::from_str::<Fixture>(&raw) {
            Ok(f) => fixtures.push(f),
            Err(e) => panic!("parse {path:?}: {e}"),
        }
    }
    fixtures
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn c_string(s: &str) -> CString {
    CString::new(s).expect("CString::new")
}

unsafe fn read_cstr(ptr: *mut std::os::raw::c_char) -> String {
    if ptr.is_null() { return String::new(); }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_string_free(ptr);
    s
}

unsafe fn read_err(ptr: *mut std::os::raw::c_char) -> String {
    if ptr.is_null() { return String::new(); }
    let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    ratify_error_free(ptr);
    s
}

fn base64_decode(input: &str, out: &mut Vec<u8>) -> bool {
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
        if bits >= 8 { bits -= 8; out.push((buf >> bits) as u8); }
    }
    true
}

// ---------------------------------------------------------------------------
// Revocation callback + rate callback (same as before)
// ---------------------------------------------------------------------------

unsafe extern "C" fn conformance_revocation(
    cert_id: *const std::os::raw::c_char,
    userdata: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    if cert_id.is_null() || userdata.is_null() { return 0; }
    let queried = CStr::from_ptr(cert_id);
    let revoked = CStr::from_ptr(userdata as *const std::os::raw::c_char);
    if queried == revoked { 1 } else { 0 }
}

unsafe extern "C" fn fixed_rate_count(
    _: *const std::os::raw::c_char,
    _: i64,
    userdata: *mut std::ffi::c_void,
) -> i64 {
    *(userdata as *const i64)
}

struct BuiltContext {
    ctx: RatifyVerifierContext,
    _currency: Option<CString>,
    _rate_count: Option<Box<i64>>,
}

fn build_verifier_context(vc: &FixtureVerifierContext) -> BuiltContext {
    let has_location = vc.current_lat.is_some() as std::os::raw::c_int;
    let has_speed    = vc.current_speed_mps.is_some() as std::os::raw::c_int;
    let has_amount   = vc.requested_amount.is_some() as std::os::raw::c_int;
    let currency_cstr = if !vc.requested_currency.is_empty() {
        CString::new(vc.requested_currency.clone()).ok()
    } else { None };
    let currency_ptr = currency_cstr.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
    let rate_count_box = vc.invocations_in_window_count.map(Box::new);
    let (rate_fn, rate_ud) = if let Some(ref b) = rate_count_box {
        (Some(fixed_rate_count as unsafe extern "C" fn(*const _, i64, *mut _) -> i64),
         b.as_ref() as *const i64 as *mut std::ffi::c_void)
    } else { (None, std::ptr::null_mut()) };
    BuiltContext {
        ctx: RatifyVerifierContext {
            current_lat: vc.current_lat.unwrap_or(0.0),
            current_lon: vc.current_lon.unwrap_or(0.0),
            current_alt_m: vc.current_alt_m.unwrap_or(0.0),
            has_location,
            current_speed_mps: vc.current_speed_mps.unwrap_or(0.0),
            has_speed,
            requested_amount: vc.requested_amount.unwrap_or(0.0),
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
// Fixture runners
// ---------------------------------------------------------------------------

unsafe fn run_verify_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let bundle_val = match &fixture.bundle { Some(b) => b, None => return false };
    let expected = match &fixture.expected.verify_result { Some(e) => e, None => return false };

    let bundle_json = serde_json::to_string(bundle_val)
        .unwrap_or_else(|e| panic!("re-serialise {}: {e}", fixture.name));

    let opts = fixture.expected.verify_options.as_ref();
    let scope = opts.map(|o| o.required_scope.as_str()).unwrap_or("");
    let now = opts.map(|o| o.now).unwrap_or(0);
    let built_ctx = fixture.verifier_context.as_ref().map(build_verifier_context);

    let revoked_cert_cstr: Option<CString> = if expected.identity_status == "revoked" {
        let delegations = bundle_val.get("delegations")
            .and_then(|d| d.as_array()).cloned().unwrap_or_default();
        if delegations.len() > 1 {
            delegations[1].get("cert_id").and_then(|id| id.as_str())
                .and_then(|id| CString::new(id).ok())
        } else { None }
    } else { None };

    let session_bytes: Option<[u8; 32]> = opts
        .and_then(|o| if o.session_context.is_empty() { None } else { Some(&o.session_context) })
        .and_then(|b64| {
            let mut dec = Vec::new();
            if base64_decode(b64, &mut dec) && dec.len() == 32 {
                let mut arr = [0u8; 32]; arr.copy_from_slice(&dec); Some(arr)
            } else { None }
        });

    let stream_id_bytes: Option<[u8; 32]> = opts
        .and_then(|o| o.stream.as_ref())
        .and_then(|s| {
            let mut dec = Vec::new();
            if base64_decode(&s.stream_id, &mut dec) && dec.len() == 32 {
                let mut arr = [0u8; 32]; arr.copy_from_slice(&dec); Some(arr)
            } else { None }
        });
    let stream_last_seq = opts.and_then(|o| o.stream.as_ref()).map(|s| s.last_seen_seq).unwrap_or(0);
    let stream_ctx = stream_id_bytes.as_ref().map(|id| RatifyStreamContext {
        stream_id: id.as_ptr(), stream_id_len: 32, last_seen_seq: stream_last_seq,
    });

    let bundle_c = c_string(&bundle_json);
    let scope_c = c_string(scope);
    let (rev_fn, rev_ud) = if let Some(cid) = &revoked_cert_cstr {
        (Some(conformance_revocation as unsafe extern "C" fn(*const _, *mut _) -> _),
         cid.as_ptr() as *mut std::ffi::c_void)
    } else { (None, std::ptr::null_mut()) };

    let session_ctx_len = if session_bytes.is_some() { 32usize } else { 0usize };
    let opts_c = RatifyVerifyOptions {
        required_scope: if scope.is_empty() { std::ptr::null() } else { scope_c.as_ptr() },
        now_unix: now,
        session_context: session_bytes.as_ref().map_or(std::ptr::null(), |b| b.as_ptr()),
        session_context_len: session_ctx_len,
        revocation_fn: rev_fn,
        revocation_userdata: rev_ud,
        context: built_ctx.as_ref().map_or(std::ptr::null(), |bc| &bc.ctx as *const _),
        stream: stream_ctx.as_ref().map_or(std::ptr::null(), |s| s as *const _),
    };

    let mut result: *mut RatifyVerifyResult = std::ptr::null_mut();
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();
    let status = ratify_verify_bundle_opts(bundle_c.as_ptr(), &opts_c, &mut result, &mut err);

    if matches!(status, RatifyStatus::RatifyErrJson) {
        failures.push(format!("[{}] JSON error", fixture.name));
        if !result.is_null() { ratify_verify_result_free(result); }
        return false;
    }
    if result.is_null() {
        failures.push(format!("[{}] result is null (status={status:?})", fixture.name));
        return false;
    }

    let got_valid = ratify_verify_result_is_valid(result) != 0;
    let status_ptr = ratify_verify_result_identity_status(result);
    let got_status = if status_ptr.is_null() { String::new() } else {
        let s = CStr::from_ptr(status_ptr).to_string_lossy().into_owned();
        ratify_string_free(status_ptr);
        s
    };
    ratify_verify_result_free(result);
    if !err.is_null() { ratify_error_free(err); }

    if got_valid == expected.valid && got_status == expected.identity_status {
        true
    } else {
        failures.push(format!(
            "[{}]\n  expected: valid={} status={}\n  got:      valid={} status={}",
            fixture.name, expected.valid, expected.identity_status, got_valid, got_status
        ));
        false
    }
}

unsafe fn run_scope_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let input = match &fixture.scope_input { Some(s) => s, None => return false };
    let want_expanded = match &fixture.expected.expanded_scopes { Some(s) => s, None => return false };

    let input_json = serde_json::to_string(input).unwrap();
    let input_c = c_string(&input_json);

    // ratify_scopes_expand(scopes_json, err_out) -> *mut c_char (JSON array)
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();
    let out = ratify_scopes_expand(input_c.as_ptr(), &mut err);
    let err_str = read_err(err);
    if out.is_null() {
        failures.push(format!("[{}] ratify_scopes_expand failed: {err_str}", fixture.name));
        return false;
    }
    let got_json = read_cstr(out);
    let mut got: Vec<String> = serde_json::from_str(&got_json).unwrap_or_default();
    let mut want = want_expanded.clone();
    got.sort(); want.sort();
    if got != want {
        failures.push(format!("[{}] expand_scopes: got {:?}, want {:?}", fixture.name, got, want));
        return false;
    }

    // ratify_scopes_validate(scopes_json) -> *mut c_char (error string or null = valid)
    let verr = ratify_scopes_validate(input_c.as_ptr());
    if !verr.is_null() { ratify_string_free(verr); } // non-null = has error, that's fine for unknown scope fixture

    true
}

unsafe fn run_revocation_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let raw = match &fixture.revocation_list { Some(r) => r, None => return false };
    let want_hex = match &fixture.expected.revocation_sign_bytes_hex { Some(h) => h, None => return false };

    let list_json = serde_json::to_string(raw).unwrap();
    let list_c = c_string(&list_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // Check sign bytes hex
    let got_hex_ptr = ratify_revocation_list_sign_bytes_hex(list_c.as_ptr(), &mut err);
    let got_hex = read_cstr(got_hex_ptr);
    if got_hex != *want_hex {
        failures.push(format!("[{}] revocation sign_bytes_hex: got {got_hex}, want {want_hex}", fixture.name));
        return false;
    }

    // Check signature verification against issuer's public key
    if fixture.entities.is_empty() {
        failures.push(format!("[{}] revocation fixture needs issuer entity", fixture.name));
        return false;
    }
    let pub_key_json = serde_json::to_string(&fixture.entities[0].public_key).unwrap();
    let pub_key_c = c_string(&pub_key_json);

    // ratify_revocation_list_verify(list_json, issuer_pub_json, err_out) -> RatifyStatus
    let mut verify_err: *mut std::os::raw::c_char = std::ptr::null_mut();
    let vs = ratify_revocation_list_verify(list_c.as_ptr(), pub_key_c.as_ptr(), &mut verify_err);
    let verify_err_str = read_err(verify_err);
    if !matches!(vs, RatifyStatus::RatifyOk) {
        failures.push(format!("[{}] revocation_list_verify failed: {verify_err_str}", fixture.name));
        return false;
    }
    true
}

unsafe fn run_revocation_push_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let raw = match &fixture.revocation_push { Some(r) => r, None => return false };
    let want_sign_hex = match &fixture.expected.revocation_push_sign_bytes_hex { Some(h) => h, None => return false };

    let push_json = serde_json::to_string(raw).unwrap();
    let push_c = c_string(&push_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // sign bytes hex
    let got_hex_ptr = ratify_revocation_push_sign_bytes_hex(push_c.as_ptr(), &mut err);
    let got_hex = read_cstr(got_hex_ptr);
    if got_hex != *want_sign_hex {
        failures.push(format!("[{}] push sign_bytes_hex: got {got_hex}, want {want_sign_hex}", fixture.name));
        return false;
    }

    // ed25519 sig hex
    if let Some(want_ed) = &fixture.expected.revocation_push_signature_ed25519_hex {
        let mut e2: *mut std::os::raw::c_char = std::ptr::null_mut();
        let got_ptr = ratify_revocation_push_sig_ed25519_hex(push_c.as_ptr(), &mut e2);
        let got = read_cstr(got_ptr);
        if &got != want_ed {
            failures.push(format!("[{}] push ed25519 sig hex drift", fixture.name));
            return false;
        }
    }

    // ml_dsa_65 sig hex
    if let Some(want_ml) = &fixture.expected.revocation_push_signature_ml_dsa_65_hex {
        let mut e3: *mut std::os::raw::c_char = std::ptr::null_mut();
        let got_ptr = ratify_revocation_push_sig_ml_dsa_65_hex(push_c.as_ptr(), &mut e3);
        let got = read_cstr(got_ptr);
        if &got != want_ml {
            failures.push(format!("[{}] push ml_dsa_65 sig hex drift", fixture.name));
            return false;
        }
    }

    // signature verification
    if fixture.entities.is_empty() {
        failures.push(format!("[{}] revocation_push fixture needs issuer entity", fixture.name));
        return false;
    }
    let pub_key_json = serde_json::to_string(&fixture.entities[0].public_key).unwrap();
    let pub_key_c = c_string(&pub_key_json);

    // ratify_revocation_push_verify(push_json, issuer_pub_json, err_out) -> RatifyStatus
    let mut ve: *mut std::os::raw::c_char = std::ptr::null_mut();
    let vs = ratify_revocation_push_verify(push_c.as_ptr(), pub_key_c.as_ptr(), &mut ve);
    let ve_str = read_err(ve);
    if !matches!(vs, RatifyStatus::RatifyOk) {
        failures.push(format!("[{}] push_verify failed: {ve_str}", fixture.name));
        return false;
    }
    true
}

unsafe fn run_key_rotation_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let raw = match &fixture.key_rotation { Some(r) => r, None => return false };
    let want_sign_hex = match &fixture.expected.key_rotation_sign_bytes_hex { Some(h) => h, None => return false };

    let rot_json = serde_json::to_string(raw).unwrap();
    let rot_c = c_string(&rot_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // sign bytes hex
    let got_hex_ptr = ratify_key_rotation_sign_bytes_hex(rot_c.as_ptr(), &mut err);
    let got_hex = read_cstr(got_hex_ptr);
    if got_hex != *want_sign_hex {
        failures.push(format!("[{}] key_rotation sign_bytes_hex drift", fixture.name));
        return false;
    }

    // ratify_key_rotation_verify(stmt_json, err_out) -> RatifyStatus
    let mut ve: *mut std::os::raw::c_char = std::ptr::null_mut();
    let vs = ratify_key_rotation_verify(rot_c.as_ptr(), &mut ve);
    let ve_str = read_err(ve);

    let got_ok = matches!(vs, RatifyStatus::RatifyOk);
    let want_ok = fixture.expected.key_rotation_verify_ok.unwrap_or(false);
    if got_ok != want_ok {
        failures.push(format!(
            "[{}] key_rotation verify: got ok={got_ok} (err={ve_str}), want ok={want_ok} ({})",
            fixture.name, fixture.expected.key_rotation_error_reason
        ));
        return false;
    }
    true
}

unsafe fn run_session_token_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let st = match &fixture.session_token { Some(s) => s, None => return false };
    let want_sign_hex = match &fixture.expected.session_token_sign_bytes_hex { Some(h) => h, None => return false };
    let want_mac_hex  = match &fixture.expected.session_token_mac_hex { Some(h) => h, None => return false };
    let want_streamed = match &fixture.expected.streamed_turn { Some(t) => t, None => return false };

    let token_json = serde_json::to_string(&st.token).unwrap();
    let token_c = c_string(&token_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // sign bytes hex
    let got_sign_ptr = ratify_session_token_sign_bytes_hex(token_c.as_ptr(), &mut err);
    let got_sign = read_cstr(got_sign_ptr);
    if &got_sign != want_sign_hex {
        failures.push(format!("[{}] session_token sign_bytes_hex drift", fixture.name));
        return false;
    }

    // MAC hex
    let mut e2: *mut std::os::raw::c_char = std::ptr::null_mut();
    let got_mac_ptr = ratify_session_token_mac_hex(token_c.as_ptr(), &mut e2);
    let got_mac = read_cstr(got_mac_ptr);
    if &got_mac != want_mac_hex {
        failures.push(format!("[{}] session_token MAC hex drift", fixture.name));
        return false;
    }

    // Decode session secret from hex
    let mut secret = Vec::with_capacity(st.session_secret_hex.len() / 2);
    for i in (0..st.session_secret_hex.len()).step_by(2) {
        match u8::from_str_radix(&st.session_secret_hex[i..i+2], 16) {
            Ok(b) => secret.push(b),
            Err(_) => {
                failures.push(format!("[{}] bad session_secret_hex at index {i}", fixture.name));
                return false;
            }
        }
    }

    // Decode challenge
    let mut chall: Vec<u8> = Vec::new();
    if !base64_decode(&st.challenge, &mut chall) {
        failures.push(format!("[{}] bad challenge base64", fixture.name));
        return false;
    }

    // Challenge signature JSON
    let sig_json = serde_json::to_string(&st.challenge_sig).unwrap();
    let sig_c = c_string(&sig_json);

    // Streamed turn verification
    let mut ve: *mut std::os::raw::c_char = std::ptr::null_mut();
    let result = ratify_verify_streamed_turn(
        token_c.as_ptr(),
        secret.as_ptr(), secret.len(),
        chall.as_ptr(), chall.len(),
        st.challenge_at,
        sig_c.as_ptr(),
        std::ptr::null(), 0,  // no session context
        std::ptr::null(), 0,  // no stream id
        0,
        st.verify_now,
        &mut ve,
    );

    if result.is_null() {
        let ve_str = read_err(ve);
        failures.push(format!("[{}] verify_streamed_turn returned null: {ve_str}", fixture.name));
        return false;
    }

    let got_valid = ratify_verify_result_is_valid(result) != 0;
    let status_ptr = ratify_verify_result_identity_status(result);
    let got_status = if status_ptr.is_null() { String::new() } else {
        let s = CStr::from_ptr(status_ptr).to_string_lossy().into_owned();
        ratify_string_free(status_ptr);
        s
    };
    ratify_verify_result_free(result);

    if got_valid != want_streamed.valid || got_status != want_streamed.identity_status {
        failures.push(format!(
            "[{}] streamed_turn: got valid={got_valid} status={got_status}, want valid={} status={}",
            fixture.name, want_streamed.valid, want_streamed.identity_status
        ));
        return false;
    }
    true
}

unsafe fn run_transaction_receipt_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let raw = match &fixture.transaction_receipt { Some(r) => r, None => return false };
    let want_sign_hex = match &fixture.expected.receipt_sign_bytes_hex { Some(h) => h, None => return false };
    let want_valid = match fixture.expected.receipt_valid { Some(v) => v, None => return false };

    let receipt_json = serde_json::to_string(raw).unwrap();
    let receipt_c = c_string(&receipt_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // sign bytes hex
    let got_hex_ptr = ratify_transaction_receipt_sign_bytes_hex(receipt_c.as_ptr(), &mut err);
    let got_hex = read_cstr(got_hex_ptr);
    if got_hex != *want_sign_hex {
        failures.push(format!("[{}] receipt sign_bytes_hex drift", fixture.name));
        return false;
    }

    // full verify
    let now = match fixture.timestamps.get("verifier_now") {
        Some(t) => *t,
        None => {
            failures.push(format!("[{}] missing timestamps.verifier_now", fixture.name));
            return false;
        }
    };

    let mut valid_out: std::os::raw::c_int = 0;
    let mut ve: *mut std::os::raw::c_char = std::ptr::null_mut();
    let s = ratify_transaction_receipt_verify_full(receipt_c.as_ptr(), now, &mut valid_out, &mut ve);
    let got_error_reason = read_err(ve);

    if !matches!(s, RatifyStatus::RatifyOk) {
        failures.push(format!("[{}] receipt_verify_full parse error", fixture.name));
        return false;
    }

    let got_valid = valid_out != 0;
    if got_valid != want_valid {
        failures.push(format!(
            "[{}] receipt valid: got={got_valid} reason={got_error_reason}, want={want_valid} reason={}",
            fixture.name, fixture.expected.receipt_error_reason
        ));
        return false;
    }
    if !want_valid && got_error_reason != fixture.expected.receipt_error_reason {
        failures.push(format!(
            "[{}] receipt error_reason: got={got_error_reason:?}, want={:?}",
            fixture.name, fixture.expected.receipt_error_reason
        ));
        return false;
    }
    true
}

unsafe fn run_witness_entry_fixture(fixture: &Fixture, failures: &mut Vec<String>) -> bool {
    let raw = match &fixture.witness_entry { Some(r) => r, None => return false };
    let want_sign_hex = match &fixture.expected.witness_entry_sign_bytes_hex { Some(h) => h, None => return false };

    let entry_json = serde_json::to_string(raw).unwrap();
    let entry_c = c_string(&entry_json);
    let mut err: *mut std::os::raw::c_char = std::ptr::null_mut();

    // sign bytes hex
    let got_hex_ptr = ratify_witness_entry_sign_bytes_hex(entry_c.as_ptr(), &mut err);
    let got_hex = read_cstr(got_hex_ptr);
    if got_hex != *want_sign_hex {
        failures.push(format!("[{}] witness_entry sign_bytes_hex drift", fixture.name));
        return false;
    }

    // ed25519 sig hex
    if let Some(want_ed) = &fixture.expected.witness_entry_signature_ed25519_hex {
        let mut e2: *mut std::os::raw::c_char = std::ptr::null_mut();
        let got_ptr = ratify_witness_entry_sig_ed25519_hex(entry_c.as_ptr(), &mut e2);
        let got = read_cstr(got_ptr);
        if &got != want_ed {
            failures.push(format!("[{}] witness ed25519 sig drift", fixture.name));
            return false;
        }
    }

    // ml_dsa_65 sig hex
    if let Some(want_ml) = &fixture.expected.witness_entry_signature_ml_dsa_65_hex {
        let mut e3: *mut std::os::raw::c_char = std::ptr::null_mut();
        let got_ptr = ratify_witness_entry_sig_ml_dsa_65_hex(entry_c.as_ptr(), &mut e3);
        let got = read_cstr(got_ptr);
        if &got != want_ml {
            failures.push(format!("[{}] witness ml_dsa_65 sig drift", fixture.name));
            return false;
        }
    }

    // signature verification
    if fixture.entities.is_empty() {
        failures.push(format!("[{}] witness_entry fixture needs witness entity", fixture.name));
        return false;
    }
    let pub_key_json = serde_json::to_string(&fixture.entities[0].public_key).unwrap();
    let pub_key_c = c_string(&pub_key_json);

    // ratify_witness_entry_verify(entry_json, witness_pub_json, err_out) -> RatifyStatus
    let mut ve: *mut std::os::raw::c_char = std::ptr::null_mut();
    let vs = ratify_witness_entry_verify(entry_c.as_ptr(), pub_key_c.as_ptr(), &mut ve);
    let ve_str = read_err(ve);
    if !matches!(vs, RatifyStatus::RatifyOk) {
        failures.push(format!("[{}] witness_entry_verify failed: {ve_str}", fixture.name));
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Main conformance test
// ---------------------------------------------------------------------------

#[test]
fn c_api_passes_all_verify_fixtures() {
    let fixtures = load_fixtures();
    let mut total = 0usize;
    let mut passed = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        total += 1;
        let ok = unsafe {
            match fixture.kind.as_str() {
                "verify"              => run_verify_fixture(fixture, &mut failures),
                "scope"               => run_scope_fixture(fixture, &mut failures),
                "revocation"          => run_revocation_fixture(fixture, &mut failures),
                "revocation_push"     => run_revocation_push_fixture(fixture, &mut failures),
                "key_rotation"        => run_key_rotation_fixture(fixture, &mut failures),
                "session_token"       => run_session_token_fixture(fixture, &mut failures),
                "transaction_receipt" => run_transaction_receipt_fixture(fixture, &mut failures),
                "witness_entry"       => run_witness_entry_fixture(fixture, &mut failures),
                other => {
                    failures.push(format!("[{}] unknown fixture kind: {other}", fixture.name));
                    false
                }
            }
        };
        if ok { passed += 1; }
    }

    println!("\nC API conformance: {passed}/{total} passed\n");

    if !failures.is_empty() {
        panic!("{} failure(s):\n{}", failures.len(), failures.join("\n\n"));
    }

    assert_eq!(passed, total, "not all fixtures passed");
}
