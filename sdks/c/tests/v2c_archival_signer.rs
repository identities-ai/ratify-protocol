//! Shared archival (SPEC-v2 §6.10, testvectors/v2/archival.json), external
//! signer (§3.2, external-signer.json), and digest function (§4,
//! digest-functions.json) vectors through the C ABI, mirroring Go
//! `v2_conformance_archival_signer_test.go`.

mod v2c_common;

use std::collections::BTreeSet;
use std::os::raw::c_void;
use std::ptr;
use std::sync::Mutex;

use ratify_c::*;
use serde_json::Value;
use v2c_common::*;

#[test]
fn v2c_conformance_archival() {
    let fx = Fixture::load();
    let f = load("archival.json");
    let cases = arr(&f["cases"]);
    let mut kinds = BTreeSet::new();
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let kind = s(&c["kind"]);
        kinds.insert(kind.clone());
        let wire = b64(&c["wire_b64"]);
        let v = &c["verify"];
        let issuer = cs(&s(&v["issuer_id"]));
        let key_name = ["status_key", "witness_key", "verifier_key"]
            .iter()
            .map(|k| s(&v[*k]))
            .find(|k| !k.is_empty());
        let key = key_name.map(|k| fx.key(&k));
        let got = buf(|o| unsafe {
            ratify_v2_archival_verify(
                kind_code(&kind),
                ptr_of(&wire),
                wire.len(),
                if v["issuer_id"].is_null() {
                    ptr::null()
                } else {
                    issuer.as_ptr()
                },
                key.as_ref()
                    .map_or(ptr::null(), |k| k as *const RatifyV2PublicKey),
                o,
            )
        });
        let want_class = s(&c["expected_error_class"]);
        if !want_class.is_empty() {
            if class_of(&got) != want_class {
                failures.push(format!(
                    "{name}: class {}, want {want_class}",
                    class_of(&got)
                ));
            }
            continue;
        }
        match got {
            Ok(r) if parse(&r) == c["expected"] => {}
            Ok(r) => failures.push(format!(
                "{name}: result {}, want {}",
                parse(&r),
                c["expected"]
            )),
            Err(e) => failures.push(format!("{name}: {} ({})", e.class, e.message)),
        }
    }
    assert!(
        failures.is_empty(),
        "{} archival case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    for kind in [
        "proof_bundle",
        "delegation_certificate",
        "revocation_list",
        "revocation_push",
        "key_rotation_statement",
        "witness_entry",
        "verification_receipt",
        "transaction_receipt",
    ] {
        assert!(kinds.contains(kind), "no archival case for {kind}");
    }
    assert_eq!(cases.len(), 19, "archival cases");
    let readme = readme_line("archival.json");
    assert!(
        readme.contains("19 archival verification cases"),
        "README row: {readme}"
    );
}

/// Go `v2ScriptedSigner` behind the C external signer callbacks: reports a
/// fixed key, answers every sign request with fixed bytes, and records it.
/// `cancel_first` is the caller's cancellation before the call: the key
/// callback, which runs before any sign request, returns
/// `RatifyV2ErrCancelled`.
struct Scripted {
    key: RatifyV2PublicKey,
    response: String,
    signature: RatifyV2Signature,
    cancel_first: bool,
    requests: Mutex<Vec<Value>>,
}

unsafe extern "C" fn scripted_key(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32 {
    let s = &*(user as *const Scripted);
    if s.cancel_first {
        return RatifyV2Code::RatifyV2ErrCancelled as i32;
    }
    *out = s.key;
    0
}

unsafe extern "C" fn scripted_sign(
    user: *mut c_void,
    req: *const RatifyV2SignRequest,
    out: *mut RatifyV2Signature,
) -> i32 {
    let s = &*(user as *const Scripted);
    let r = &*req;
    let bytes = |sl: &RatifyV2Slice| -> Option<Vec<u8>> {
        (sl.len != 0).then(|| std::slice::from_raw_parts(sl.ptr, sl.len).to_vec())
    };
    s.requests.lock().unwrap().push(serde_json::json!({
        "mode": if r.mode == 1 { "direct" } else { "external_mu" },
        "message_b64": enc(&bytes(&r.message).unwrap_or_default()),
        "mldsa_context": bytes(&r.ml_dsa_context).map(|c| String::from_utf8(c).unwrap()),
        "mldsa_mu_b64": bytes(&r.ml_dsa_mu).map(|m| enc(&m)),
        "key_id_v2": std::ffi::CStr::from_ptr(r.key_id).to_string_lossy(),
        "key_matches": (*r.public_key).ed25519 == s.key.ed25519 && (*r.public_key).ml_dsa_65 == s.key.ml_dsa_65,
    }));
    match s.response.as_str() {
        "error" => return RatifyV2Code::RatifyV2StoreUnavailable as i32,
        // The caller cancels during the call; the returned signature is
        // discarded.
        "cancel" => return RatifyV2Code::RatifyV2ErrCancelled as i32,
        _ => {}
    }
    *out = s.signature;
    0
}

fn signature_struct(v: &Value) -> RatifyV2Signature {
    let mut sig: RatifyV2Signature = unsafe { std::mem::zeroed() };
    if v.is_null() {
        return sig;
    }
    let (ed, ml) = (b64(&v["ed25519"]), b64(&v["ml_dsa_65"]));
    sig.ed25519[..ed.len()].copy_from_slice(&ed);
    sig.ed25519_len = ed.len();
    sig.ml_dsa_65[..ml.len()].copy_from_slice(&ml);
    sig.ml_dsa_65_len = ml.len();
    sig
}

#[test]
fn v2c_conformance_external_signer() {
    let fx = Fixture::load();
    let f = load("external-signer.json");
    let cases = arr(&f["cases"]);
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let p = &c["provider"];
        let mode = match s(&p["mode"]).as_str() {
            "direct" => 1,
            "external_mu" => 2,
            other => panic!("{name}: unknown mode {other}"),
        };
        let scripted = Scripted {
            key: fx.key(&s(&p["public_key"])),
            response: s(&p["response"]),
            signature: signature_struct(&p["signature"]),
            cancel_first: b(&c["caller_cancelled"]),
            requests: Mutex::new(Vec::new()),
        };
        let signer = RatifyV2ExternalSigner {
            user: &scripted as *const Scripted as *mut c_void,
            mode,
            public_key: Some(scripted_key),
            sign: Some(scripted_sign),
        };
        let wire = b64(&c["object_b64"]);
        let signed = match s(&c["kind"]).as_str() {
            "delegation_certificate" => buf(|o| unsafe {
                ratify_v2_sign_delegation_certificate(
                    ptr_of(&wire),
                    wire.len(),
                    ptr::null(),
                    &signer,
                    o,
                )
            }),
            "revocation_list" => {
                let bind = &c["binding"];
                let issuer = cs(&s(&bind["issuer_id"]));
                let status = fx.key(&s(&bind["status_key"]));
                buf(|o| unsafe {
                    ratify_v2_sign_revocation_list(
                        ptr_of(&wire),
                        wire.len(),
                        issuer.as_ptr(),
                        &status,
                        ptr::null(),
                        &signer,
                        o,
                    )
                })
            }
            "proof_bundle" => buf(|o| unsafe {
                ratify_v2_sign_proof_bundle(ptr_of(&wire), wire.len(), ptr::null(), &signer, o)
            }),
            other => panic!("{name}: unknown kind {other}"),
        };
        let e = &c["expected"];
        let requests = scripted.requests.lock().unwrap().clone();
        if requests.len() as u64 != u(&e["provider_calls"]) {
            failures.push(format!(
                "{name}: provider calls {}, want {}",
                requests.len(),
                e["provider_calls"]
            ));
            continue;
        }
        if !e["request"].is_null() {
            let r = &requests[0];
            let want = &e["request"];
            if r["mode"] != want["mode"]
                || r["message_b64"] != want["message_b64"]
                || r["mldsa_context"] != want["mldsa_context"]
                || r["mldsa_mu_b64"] != want["mldsa_mu_b64"]
                || r["key_id_v2"] != want["key_id_v2"]
                || r["key_matches"] != true
            {
                failures.push(format!("{name}: provider request {r} differs from {want}"));
                continue;
            }
        }
        if s(&e["result"]) == "signed" {
            match &signed {
                Ok(bytes) if *bytes == b64(&e["signed_wire_b64"]) => {}
                other => failures.push(format!(
                    "{name}: signed object differs ({:?})",
                    class_of(other)
                )),
            }
            continue;
        }
        if class_of(&signed) != s(&e["error_class"]) {
            failures.push(format!(
                "{name}: class {}, want {}",
                class_of(&signed),
                e["error_class"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} external signer case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(cases.len(), 17, "external signer cases");
    let readme = readme_line("external-signer.json");
    assert!(
        readme.contains("17 external signer cases"),
        "README row: {readme}"
    );
}

#[test]
fn v2c_conformance_digest_functions() {
    let f = load("digest-functions.json");
    let cases = arr(&f["cases"]);
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let input = b64(&c["input_b64"]);
        let code = u(&c["object_type_code"]);
        let digest = match s(&c["function"]).as_str() {
            "statement_body_digest" => buf(|o| unsafe {
                ratify_v2_statement_body_digest(code as u32, ptr_of(&input), input.len(), o)
            }),
            // The wire object is decoded strictly as the kind named by the
            // code; a code outside 3 and 5 is unsupported_object_type.
            "status_evidence_digest" => buf(|o| unsafe {
                ratify_v2_status_evidence_digest(code as i32, ptr_of(&input), input.len(), o)
            }),
            other => panic!("{name}: unknown function {other}"),
        };
        let want_class = s(&c["expected_error_class"]);
        if !want_class.is_empty() {
            if class_of(&digest) != want_class {
                failures.push(format!(
                    "{name}: class {}, want {want_class}",
                    class_of(&digest)
                ));
            }
            continue;
        }
        match digest {
            Ok(d) if format!("sha384:{}", hex::encode(&d)) == s(&c["expected_digest"]) => {}
            other => failures.push(format!(
                "{name}: digest class {}, want {}",
                class_of(&other),
                c["expected_digest"]
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} digest case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(cases.len(), 25, "digest function cases");
    let readme = readme_line("digest-functions.json");
    assert!(
        readme.contains("25 cases for `StatementBodyDigest`"),
        "README row: {readme}"
    );
}
