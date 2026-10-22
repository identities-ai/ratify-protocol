//! Shared archival (SPEC-v2 §6.10, testvectors/v2/archival.json), external
//! signer (§3.2, external-signer.json), and digest function (§4,
//! digest-functions.json) vectors, mirroring Go
//! `v2_conformance_archival_signer_test.go`.

mod v2_status_common;

use std::collections::BTreeSet;
use std::sync::Mutex;

use ratify_protocol::v2::*;
use ratify_protocol::{HybridPublicKey, HybridSignature};
use serde_json::{json, Value};
use v2_status_common::{i, load_v2_keys, load_v2_vector, readme_line, s, unb64};

fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn class_name(c: Option<V2ErrorClass>) -> &'static str {
    c.map_or("", |c| c.as_str())
}

fn archival_json(r: &ArchivalVerificationV2) -> Value {
    json!({
        "object_type_code": r.object_type,
        "freshness": r.freshness,
        "actionable": r.actionable,
        "digest": r.digest,
        "signer_key_ids": r.signer_key_ids,
    })
}

#[test]
fn v2_conformance_archival() {
    let fx = load_v2_keys();
    let f = load_v2_vector("archival.json");
    let cases = arr(&f["cases"]);
    let mut kinds = BTreeSet::new();
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let kind = s(&c["kind"]);
        kinds.insert(kind.clone());
        let wire = unb64(&c["wire_b64"]);
        let v = &c["verify"];
        let issuer = s(&v["issuer_id"]);
        let got: V2Result<Value> = match kind.as_str() {
            "proof_bundle" => verify_archival_proof_bundle_v2(&wire)
                .to_json()
                .map(|b| serde_json::from_slice(&b).expect("result JSON")),
            "delegation_certificate" => verify_archival_delegation_cert_v2(&wire).map(|r| archival_json(&r)),
            "revocation_list" => {
                verify_archival_revocation_list_v2(&wire, &issuer, &fx.public(&s(&v["status_key"])))
                    .map(|r| archival_json(&r))
            }
            "revocation_push" => {
                verify_archival_revocation_push_v2(&wire, &issuer, &fx.public(&s(&v["status_key"])))
                    .map(|r| archival_json(&r))
            }
            "key_rotation_statement" => verify_archival_key_rotation_statement_v2(&wire).map(|r| archival_json(&r)),
            "witness_entry" => {
                verify_archival_witness_entry_v2(&wire, &fx.public(&s(&v["witness_key"]))).map(|r| archival_json(&r))
            }
            "verification_receipt" => {
                verify_archival_verification_receipt_v2(&wire, &fx.public(&s(&v["verifier_key"])))
                    .map(|r| archival_json(&r))
            }
            "transaction_receipt" => verify_archival_transaction_receipt_v2(&wire).map(|r| archival_json(&r)),
            other => panic!("{name}: unknown kind {other}"),
        };
        let want_class = s(&c["expected_error_class"]);
        if !want_class.is_empty() {
            let got_class = class_name(v2_error_class_of(&got));
            if got_class != want_class {
                failures.push(format!("{name}: {got:?} (class {got_class:?}), want class {want_class}"));
            }
            continue;
        }
        match got {
            Ok(result) if result == c["expected"] => {}
            other => failures.push(format!("{name}: result {other:?}, want {}", c["expected"])),
        }
    }
    assert!(failures.is_empty(), "{} archival case(s) failed:\n{}", failures.len(), failures.join("\n"));
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
    assert!(readme.contains("19 archival verification cases"), "README row: {readme}");
}

/// Go `v2ScriptedSigner`: answers every request with fixed bytes and records
/// it.
struct ScriptedSigner {
    public: HybridPublicKey,
    mode: SignerModeV2,
    response: String,
    signature: HybridSignature,
    cancel: V2CancelHandle,
    requests: Mutex<Vec<SignRequestV2>>,
}

impl SignerV2 for ScriptedSigner {
    fn public_key_v2(&self) -> HybridPublicKey {
        self.public.clone()
    }

    fn mode_v2(&self) -> SignerModeV2 {
        self.mode
    }

    fn sign_v2(&self, _ctx: &V2Context, request: &SignRequestV2) -> Result<HybridSignature, V2SignError> {
        self.requests.lock().unwrap().push(request.clone());
        match self.response.as_str() {
            "error" => return Err(V2SignError::Provider("scripted provider failure".into())),
            "cancel" => self.cancel.cancel(),
            _ => {}
        }
        Ok(self.signature.clone())
    }
}

#[test]
fn v2_conformance_external_signer() {
    let fx = load_v2_keys();
    let f = load_v2_vector("external-signer.json");
    let cases = arr(&f["cases"]);
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let p = &c["provider"];
        let (ctx, cancel) = V2Context::background().with_cancel();
        let signer = ScriptedSigner {
            public: fx.public(&s(&p["public_key"])),
            mode: match s(&p["mode"]).as_str() {
                "direct" => SignerModeV2::Direct,
                "external_mu" => SignerModeV2::ExternalMu,
                other => panic!("{name}: unknown mode {other}"),
            },
            response: s(&p["response"]),
            signature: if p["signature"].is_null() {
                HybridSignature {
                    ed25519: Vec::new(),
                    ml_dsa_65: Vec::new(),
                }
            } else {
                HybridSignature {
                    ed25519: unb64(&p["signature"]["ed25519"]),
                    ml_dsa_65: unb64(&p["signature"]["ml_dsa_65"]),
                }
            },
            cancel: cancel.clone(),
            requests: Mutex::new(Vec::new()),
        };
        if c["caller_cancelled"].as_bool().unwrap_or(false) {
            cancel.cancel();
        }
        let wire = unb64(&c["object_b64"]);
        let signed: Result<Vec<u8>, V2SignError> = match s(&c["kind"]).as_str() {
            "delegation_certificate" => {
                let cert = decode_delegation_cert_v2(&wire).expect("certificate");
                sign_delegation_cert_v2_with_signer(&ctx, &cert, &signer)
                    .and_then(|out| encode_delegation_cert_v2(&out).map_err(V2SignError::from))
            }
            "revocation_list" => {
                let list = decode_revocation_list_v2(&wire).expect("list");
                let b = &c["binding"];
                sign_revocation_list_v2_with_signer(
                    &ctx,
                    &list,
                    &s(&b["issuer_id"]),
                    &fx.public(&s(&b["status_key"])),
                    &signer,
                )
                .and_then(|out| encode_revocation_list_v2(&out).map_err(V2SignError::from))
            }
            "proof_bundle" => {
                let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
                sign_proof_bundle_v2_with_signer(&ctx, &bundle, &signer)
                    .and_then(|out| encode_proof_bundle_v2(&out).map_err(V2SignError::from))
            }
            other => panic!("{name}: unknown kind {other}"),
        };
        let e = &c["expected"];
        let requests = signer.requests.lock().unwrap().clone();
        if requests.len() as i64 != i(&e["provider_calls"]) {
            failures.push(format!("{name}: provider calls {}, want {}", requests.len(), e["provider_calls"]));
            continue;
        }
        if !e["request"].is_null() {
            let (r, want) = (&requests[0], &e["request"]);
            let mode = match r.mode {
                SignerModeV2::Direct => "direct",
                SignerModeV2::ExternalMu => "external_mu",
            };
            let context_matches = match (&r.ml_dsa_context, want["mldsa_context"].as_str()) {
                (None, None) => true,
                (Some(got), Some(want)) => got.as_slice() == want.as_bytes(),
                _ => false,
            };
            let mu_matches = match (&r.ml_dsa_mu, want["mldsa_mu_b64"].is_null()) {
                (None, true) => true,
                (Some(got), false) => *got == unb64(&want["mldsa_mu_b64"]),
                _ => false,
            };
            if mode != s(&want["mode"])
                || r.message != unb64(&want["message_b64"])
                || !context_matches
                || !mu_matches
                || r.key_id != s(&want["key_id_v2"])
                || r.public_key != signer.public
            {
                failures.push(format!("{name}: provider request {r:?} differs from {want}"));
                continue;
            }
        }
        if s(&e["result"]) == "signed" {
            match &signed {
                Ok(bytes) if *bytes == unb64(&e["signed_wire_b64"]) => {}
                other => failures.push(format!("{name}: signed object differs ({:?})", other.as_ref().err())),
            }
            continue;
        }
        match signed {
            Err(err) if err.class().as_str() == s(&e["error_class"]) => {}
            Err(err) => failures.push(format!("{name}: error {err} (class {}), want {}", err.class(), e["error_class"])),
            Ok(_) => failures.push(format!("{name}: signed, want class {}", e["error_class"])),
        }
    }
    assert!(failures.is_empty(), "{} external signer case(s) failed:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(cases.len(), 17, "external signer cases");
    let readme = readme_line("external-signer.json");
    assert!(readme.contains("17 external signer cases"), "README row: {readme}");
}

#[test]
fn v2_conformance_digest_functions() {
    let f = load_v2_vector("digest-functions.json");
    let cases = arr(&f["cases"]);
    let mut failures = Vec::new();
    for c in &cases {
        let name = s(&c["name"]);
        let input = unb64(&c["input_b64"]);
        let code = u16::try_from(i(&c["object_type_code"])).expect("u16 code");
        let digest = match s(&c["function"]).as_str() {
            "statement_body_digest" => statement_body_digest_v2(code, &input),
            "status_evidence_digest" => {
                let list = decode_revocation_list_v2(&input).expect("list");
                status_evidence_digest_v2(code, StatusEvidenceObjectV2::List(&list))
            }
            other => panic!("{name}: unknown function {other}"),
        };
        let want_class = s(&c["expected_error_class"]);
        if !want_class.is_empty() {
            let got = class_name(v2_error_class_of(&digest));
            if got != want_class {
                failures.push(format!("{name}: {digest:?} (class {got:?}), want class {want_class}"));
            }
            continue;
        }
        match digest {
            Ok(d) if format!("sha384:{}", hex::encode(&d)) == s(&c["expected_digest"]) => {}
            other => failures.push(format!("{name}: digest {other:?}, want {}", c["expected_digest"])),
        }
    }
    assert!(failures.is_empty(), "{} digest case(s) failed:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(cases.len(), 16, "digest function cases");
    let readme = readme_line("digest-functions.json");
    assert!(readme.contains("16 cases for `StatementBodyDigest`"), "README row: {readme}");
}
