//! Protocol v2 C ABI tests: drive the `ratify_v2_*` extern functions with the
//! shared `testvectors/v2` corpus. Every positive object must verify through
//! the ABI and every object negative must fail with exactly the corpus error
//! class, so the C surface cannot drift from the Rust v2 verifier it wraps.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;

use ratify_c::*;
use ratify_protocol::base64_std_decode;
use serde_json::Value;

fn corpus(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/v2")
        .join(name);
    serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap()
}

fn b64(v: &Value) -> Vec<u8> {
    base64_std_decode(v.as_str().unwrap()).unwrap()
}

fn class(code: i32) -> String {
    unsafe { CStr::from_ptr(ratify_v2_error_class_str(code)) }
        .to_str()
        .unwrap()
        .to_owned()
}

/// Fixture key name -> `{"ed25519","ml_dsa_65"}` public key object.
fn public_keys() -> BTreeMap<String, Value> {
    corpus("keys.json")["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| (k["name"].as_str().unwrap().to_owned(), k["public_key"].clone()))
        .collect()
}

/// Corpus `verify` objects name fixture keys; the C ABI takes real public keys.
fn c_context(verify: &Value, keys: &BTreeMap<String, Value>) -> Option<CString> {
    let obj = verify.as_object()?;
    if obj.is_empty() {
        return None;
    }
    let mut v = verify.clone();
    for f in ["status_key", "witness_key", "verifier_key"] {
        if let Some(name) = v.get(f).and_then(Value::as_str) {
            v[f] = keys[name].clone();
        }
    }
    if let Some(name) = v
        .get("rotation_state")
        .and_then(|s| s.get("current_key"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        v["rotation_state"]["current_key"] = keys[&name].clone();
    }
    Some(CString::new(v.to_string()).unwrap())
}

fn kind_code(kind: &str) -> i32 {
    corpus("objects.json")["kind_object_type_codes"][kind]
        .as_i64()
        .unwrap_or_else(|| panic!("no code for {kind}")) as i32
}

fn verify_via_abi(kind: &str, wire: &[u8], bundle: &[u8], ctx: Option<&CString>) -> (i32, String) {
    let mut err: *mut c_char = ptr::null_mut();
    let code = unsafe {
        if kind == "receipt_bundle_binding" {
            ratify_v2_receipt_bundle_binding_check(
                wire.as_ptr(),
                wire.len(),
                bundle.as_ptr(),
                bundle.len(),
                &mut err,
            )
        } else {
            ratify_v2_verify_object(
                kind_code(kind),
                wire.as_ptr(),
                wire.len(),
                ctx.map_or(ptr::null(), |c| c.as_ptr()),
                &mut err,
            )
        }
    };
    let msg = if err.is_null() {
        String::new()
    } else {
        let m = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { ratify_error_free(err) };
        m
    };
    (code, msg)
}

#[test]
fn v2_abi_version_query() {
    assert_eq!(ratify_v2_abi_version(), RATIFY_V2_ABI_VERSION);
    assert_eq!(ratify_v2_protocol_version(), 2);
    let lib = unsafe { CStr::from_ptr(ratify_v2_library_version()) };
    assert_eq!(lib.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    assert!(
        env!("CARGO_PKG_VERSION").starts_with("2."),
        "the v2 ABI must ship on the ratify-c 2.x line, never under a 1.x version"
    );
}

#[test]
fn v2_abi_error_class_strings_are_distinct_and_stable() {
    let mut seen = BTreeSet::new();
    for code in 1..=41 {
        let s = class(code);
        assert_ne!(s, "unknown", "code {code} has no class spelling");
        assert!(seen.insert(s.clone()), "duplicate class spelling {s}");
    }
    assert_eq!(class(0), "ok");
    assert_eq!(class(RatifyV2Code::RatifyV2Malformed as i32), "malformed");
    assert_eq!(class(RatifyV2Code::RatifyV2InvalidSignature as i32), "invalid_signature");
    assert_eq!(class(RatifyV2Code::RatifyV2ErrNullPointer as i32), "null_pointer");
    assert_eq!(class(RatifyV2Code::RatifyV2ErrBadArgument as i32), "bad_argument");
    assert_eq!(class(RatifyV2Code::RatifyV2ErrInternal as i32), "internal");
    assert_eq!(class(42), "unknown");
    assert_eq!(class(-99), "unknown");
}

#[test]
fn v2_abi_key_ids_match_corpus() {
    let keys = corpus("keys.json");
    for k in keys["keys"].as_array().unwrap() {
        let ed = b64(&k["public_key"]["ed25519"]);
        let ml = b64(&k["public_key"]["ml_dsa_65"]);
        let mut out = [0 as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
        let code = unsafe {
            ratify_v2_key_id(ed.as_ptr(), ed.len(), ml.as_ptr(), ml.len(), out.as_mut_ptr(), out.len(), ptr::null_mut())
        };
        assert_eq!(code, 0, "{}", k["name"]);
        let got = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(got, k["key_id_v2"].as_str().unwrap(), "{}", k["name"]);
        let id = CString::new(got).unwrap();
        assert_eq!(unsafe { ratify_v2_key_id_check(id.as_ptr(), ptr::null_mut()) }, 0);
        // The v1 128-bit ID of the same key is never a v2 key ID.
        let v1 = CString::new(k["v1_key_id_128"].as_str().unwrap()).unwrap();
        assert_eq!(class(unsafe { ratify_v2_key_id_check(v1.as_ptr(), ptr::null_mut()) }), "malformed");
    }
    for bad in keys["invalid_v2_key_ids"].as_array().unwrap() {
        let id = CString::new(bad["value"].as_str().unwrap()).unwrap();
        let got = class(unsafe { ratify_v2_key_id_check(id.as_ptr(), ptr::null_mut()) });
        assert_eq!(got, bad["expected_error_class"].as_str().unwrap(), "{}", bad["name"]);
    }

    let k = &keys["keys"][0]["public_key"];
    let ed = b64(&k["ed25519"]);
    let ml = b64(&k["ml_dsa_65"]);
    let mut out = [0 as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
    // A truncated Ed25519 key is malformed, not a different valid ID.
    let code = unsafe {
        ratify_v2_key_id(ed.as_ptr(), 31, ml.as_ptr(), ml.len(), out.as_mut_ptr(), out.len(), ptr::null_mut())
    };
    assert_eq!(class(code), "malformed");
    // A too-small output buffer is a caller error, never a truncated ID.
    let code = unsafe {
        ratify_v2_key_id(ed.as_ptr(), ed.len(), ml.as_ptr(), ml.len(), out.as_mut_ptr(), 64, ptr::null_mut())
    };
    assert_eq!(class(code), "bad_argument");
    let code = unsafe {
        ratify_v2_key_id(ptr::null(), 0, ml.as_ptr(), ml.len(), out.as_mut_ptr(), out.len(), ptr::null_mut())
    };
    assert_eq!(class(code), "null_pointer");
}

#[test]
fn v2_abi_every_positive_object_verifies() {
    let keys = public_keys();
    let objects = corpus("objects.json");
    let mut kinds = BTreeSet::new();
    for o in objects["objects"].as_array().unwrap() {
        let kind = o["kind"].as_str().unwrap();
        kinds.insert(kind.to_owned());
        let ctx = c_context(&o["verify"], &keys);
        let (code, msg) = verify_via_abi(kind, &b64(&o["wire_b64"]), &[], ctx.as_ref());
        assert_eq!(code, 0, "{}: {} {msg}", o["name"], class(code));
    }
    assert_eq!(kinds.len(), 8, "positive corpus must cover all eight object kinds");
}

#[test]
fn v2_abi_every_object_negative_has_corpus_class() {
    let keys = public_keys();
    let f = corpus("object-negatives.json");
    let mut failures = Vec::new();
    let mut n = 0;
    for v in f["vectors"].as_array().unwrap() {
        n += 1;
        let kind = v["kind"].as_str().unwrap();
        let bundle = v.get("bundle_b64").map(b64).unwrap_or_default();
        let ctx = c_context(&v["verify"], &keys);
        let (code, msg) = verify_via_abi(kind, &b64(&v["wire_b64"]), &bundle, ctx.as_ref());
        let want = v["expected_error_class"].as_str().unwrap();
        if class(code) != want {
            failures.push(format!("{}: got {} want {want} ({msg})", v["name"], class(code)));
        }
        if code != 0 {
            assert!(code > 0, "{}: corpus failure reported as ABI error {}", v["name"], class(code));
        }
    }
    assert!(n > 200, "object-negatives corpus unexpectedly small: {n}");
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn v2_abi_proof_bundle_and_receipt_entry_points() {
    let keys = public_keys();
    let objects = corpus("objects.json");
    let find = |name: &str| {
        objects["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["name"] == name)
            .unwrap()
            .clone()
    };

    let bundle = find("proof_bundle_two_link_bound_context");
    let wire = b64(&bundle["wire_b64"]);
    let mut hash = [0 as c_char; 128];
    let code = unsafe {
        ratify_v2_proof_bundle_verify_signatures(wire.as_ptr(), wire.len(), hash.as_mut_ptr(), hash.len(), ptr::null_mut())
    };
    assert_eq!(code, 0, "{}", class(code));
    let got = unsafe { CStr::from_ptr(hash.as_ptr()) }.to_str().unwrap();
    assert_eq!(got, bundle["digests"]["bundle_hash_v2"].as_str().unwrap());

    // A single flipped byte inside the signed region must not verify.
    let mut tampered = wire.clone();
    let pos = String::from_utf8_lossy(&wire).find("\"challenge\":\"").unwrap() + 13;
    tampered[pos] = if tampered[pos] == b'A' { b'B' } else { b'A' };
    let code = unsafe {
        ratify_v2_proof_bundle_verify_signatures(tampered.as_ptr(), tampered.len(), ptr::null_mut(), 0, ptr::null_mut())
    };
    assert_ne!(code, 0);
    assert!(code > 0, "tamper must be a protocol class, got {}", class(code));

    let receipt = find("verification_receipt_allow_genesis");
    let rw = b64(&receipt["wire_b64"]);
    let vk = &keys[receipt["verify"]["verifier_key"].as_str().unwrap()];
    let (ed, ml) = (b64(&vk["ed25519"]), b64(&vk["ml_dsa_65"]));
    let head = CString::new(receipt["verify"]["head"].to_string()).unwrap();
    let code = unsafe {
        ratify_v2_verification_receipt_verify(rw.as_ptr(), rw.len(), ed.as_ptr(), ed.len(), ml.as_ptr(), ml.len(), head.as_ptr(), ptr::null_mut())
    };
    assert_eq!(code, 0, "{}", class(code));

    // Old-key substitution: the attacker key is not the receipt's verifier.
    let ak = &keys["attacker"];
    let (aed, aml) = (b64(&ak["ed25519"]), b64(&ak["ml_dsa_65"]));
    let code = unsafe {
        ratify_v2_verification_receipt_verify(rw.as_ptr(), rw.len(), aed.as_ptr(), aed.len(), aml.as_ptr(), aml.len(), head.as_ptr(), ptr::null_mut())
    };
    assert_eq!(class(code), "log_state_mismatch");

    let bad_head = CString::new("{not json").unwrap();
    let code = unsafe {
        ratify_v2_verification_receipt_verify(rw.as_ptr(), rw.len(), ed.as_ptr(), ed.len(), ml.as_ptr(), ml.len(), bad_head.as_ptr(), ptr::null_mut())
    };
    assert_eq!(class(code), "bad_argument");
}

#[test]
fn v2_abi_rejects_unsupported_kinds_and_missing_context() {
    let objects = corpus("objects.json");
    let list = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == "revocation_list")
        .unwrap();
    let wire = b64(&list["wire_b64"]);
    for kind in [0, 9, 10, -1, 0xffff] {
        let code = unsafe { ratify_v2_verify_object(kind, wire.as_ptr(), wire.len(), ptr::null(), ptr::null_mut()) };
        assert_eq!(class(code), "unsupported_object_type", "kind {kind}");
    }
    // A status object verified without caller-authenticated state is refused,
    // never accepted on its self-declared key.
    let code = unsafe { ratify_v2_verify_object(3, wire.as_ptr(), wire.len(), ptr::null(), ptr::null_mut()) };
    assert_eq!(class(code), "null_pointer");
    let code = unsafe { ratify_v2_verify_object(3, ptr::null(), 0, ptr::null(), ptr::null_mut()) };
    assert_eq!(class(code), "null_pointer");
    let mut err: *mut c_char = ptr::null_mut();
    let empty = CString::new("{}").unwrap();
    let code = unsafe { ratify_v2_verify_object(3, wire.as_ptr(), wire.len(), empty.as_ptr(), &mut err) };
    assert_eq!(class(code), "bad_argument");
    assert!(!err.is_null());
    let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_owned();
    unsafe { ratify_error_free(err) };
    assert!(msg.starts_with("bad_argument:"), "{msg}");
}

/// key-rotation-signature.json pins a genesis rotation and its continuation.
/// Each pinned wire must verify through the ABI against the caller state the
/// statement extends, and must fail when the caller's current key is not the
/// statement's old key.
#[test]
fn v2_abi_key_rotation_signature_vector() {
    let v = corpus("key-rotation-signature.json");
    let mut cases = vec![v.clone()];
    if v["continuation"].is_object() {
        cases.push(v["continuation"].clone());
    }
    assert_eq!(cases.len(), 2, "expected a genesis case and a continuation");
    for (n, c) in cases.iter().enumerate() {
        let wire = b64(&c["wire"]);
        let ctx = |current_key: &Value| {
            let state = serde_json::json!({
                "rotation_state": {
                    "authority_id": c["authority_id"],
                    "recovery_epoch": c["recovery_epoch"],
                    "role": c["role"],
                    "sequence": c["sequence"].as_i64().unwrap() - 1,
                    "head_hash_b64": c["previous_statement_hash"],
                    "current_key": current_key,
                    "used_key_ids": [c["old_key_id"]],
                },
                "now": c["not_before"],
                "future_skew_seconds": 0,
            });
            CString::new(state.to_string()).unwrap()
        };
        let good = ctx(&c["old_key"]);
        let (code, msg) = verify_via_abi("key_rotation_statement", &wire, &[], Some(&good));
        assert_eq!(code, 0, "case {n}: {} {msg}", class(code));

        let wrong = ctx(&c["new_key"]);
        let (code, msg) = verify_via_abi("key_rotation_statement", &wire, &[], Some(&wrong));
        assert!(code > 0, "case {n}: wrong current key must be a protocol failure, got {} {msg}", class(code));
    }
}
