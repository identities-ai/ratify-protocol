// Negative wire-acceptance corpus (testvectors/wire-negative): documents
// that the untrusted deserialization path must never accept as a valid
// bundle or session token.
//
// Contract (see testvectors/wire-negative/README.md):
//   - strictness "decode": deserialization itself must fail;
//   - strictness "decode_or_verify": deserialization may succeed
//     structurally, but verify_bundle must then return valid=false.

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::{verify_bundle, ProofBundle, SessionToken, VerifyOptions};

fn corpus_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("testvectors")
        .join("wire-negative")
        .join("cases.json")
}

#[test]
fn negative_wire_corpus_is_never_accepted() {
    let raw = std::fs::read_to_string(corpus_path()).expect("read corpus");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse corpus");
    let cases = doc["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 10, "corpus too small: {} cases", cases.len());

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let target = case["target"].as_str().unwrap();
        let strictness = case["strictness"].as_str().unwrap();
        let bytes = STANDARD
            .decode(case["doc_b64"].as_str().unwrap())
            .expect("corpus doc_b64");

        match target {
            "bundle" => match serde_json::from_slice::<ProofBundle>(&bytes) {
                Err(_) => {} // rejected at decode — always acceptable
                Ok(bundle) => {
                    assert_ne!(
                        strictness, "decode",
                        "[{name}] deserialization accepted a decode-class document"
                    );
                    let result = verify_bundle(&bundle, &VerifyOptions::default());
                    assert!(
                        !result.valid,
                        "[{name}] verify_bundle accepted a corpus document as valid"
                    );
                }
            },
            "token" => match serde_json::from_slice::<SessionToken>(&bytes) {
                Err(_) => {}
                Ok(_) => {
                    assert_ne!(
                        strictness, "decode",
                        "[{name}] deserialization accepted a decode-class token document"
                    );
                }
            },
            other => panic!("unknown corpus target {other:?}"),
        }
    }
}

// Exponent notation on a legitimate float field still deserializes — the
// lexical strictness applies to integer fields only.
#[test]
fn float_fields_accept_exponent_form() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("testvectors")
        .join("v1")
        .join("constraint_geo_circle_inside.json");
    let fx: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let text = serde_json::to_string(&fx["bundle"]).unwrap();
    let doc = text.replacen("\"radius_m\":500.0", "\"radius_m\":5e2", 1);
    let doc = if doc == text {
        text.replacen("\"radius_m\":500", "\"radius_m\":5e2", 1)
    } else {
        doc
    };
    assert_ne!(doc, text, "fixture must contain radius_m:500");
    let bundle: ProofBundle = serde_json::from_str(&doc).expect("exponent float must decode");
    assert_eq!(bundle.delegations[0].constraints[0].radius_m, 500.0);
}
