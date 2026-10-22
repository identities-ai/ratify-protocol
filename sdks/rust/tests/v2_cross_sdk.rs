//! Cross-SDK fixtures (SPEC-v2 §8.1, testvectors/v2/cross-sdk/). Every file
//! in the directory, from any SDK, must pass the objects.json positive
//! procedure here; a fixture this SDK cannot verify means two SDKs disagree on
//! the wire. The checks below are independent of the library verifier
//! (`verify_cross_sdk_fixture_v2`), which is also run on every file.

mod v2_common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::*;
use ratify_protocol::{derive_id, hybrid_keypair_from_seeds, ParamsValue};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use v2_common::*;

const TOP_LEVEL: [&str; 8] =
    ["version", "description", "sdk", "sdk_version", "generator", "kind_object_type_codes", "keys", "objects"];
const KEY_FIELDS: [&str; 6] =
    ["name", "ed25519_seed_hex", "ml_dsa_65_seed_hex", "public_key", "key_id_v2", "v1_key_id_128"];
const OBJECT_FIELDS: [&str; 7] = ["name", "kind", "description", "wire_b64", "verify", "signatures", "digests"];
const SIG_FIELDS: [&str; 11] = [
    "field",
    "object_type_code",
    "signer",
    "signer_key_id_v2",
    "signable_b64",
    "signable_sha384_hex",
    "message_b64",
    "mldsa_context",
    "mldsa_tr_b64",
    "mldsa_mu_b64",
    "signature",
];

/// Collects every failure instead of stopping at the first.
#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.0.push(what());
        }
    }
}

fn keys_of(v: &Value) -> BTreeSet<String> {
    v.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default()
}

fn lp(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u64).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

fn sha384_prefixed(prefix: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(prefix.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// `profile_digest` of SPEC-v2 §5.2 computed from the formula, not from the
/// library.
fn max_count_profile_digest() -> String {
    let body = br#"{"profile":"com.ratifyprotocol.max_count/v1","type":"com.ratifyprotocol.max_count"}"#;
    format!("sha384:{}", hex::encode(sha384_prefixed("ratify-protocol-constraint-profile-v2", &[body])))
}

fn fixture_session_inputs(b: &ProofBundleV2) -> SessionContextV2Inputs {
    SessionContextV2Inputs {
        verifier_id: b.verifier_id.clone(),
        workspace_id: "00000000-0000-4000-8000-000000000001".into(),
        agent_id: b.agent_id.clone(),
        session_id: "session-01".into(),
        invocation_id: "invocation-01".into(),
        request_hash: operation_context_v2_hash(&OperationContextV2 {
            required_scope: "data:read".into(),
            operation: "records.get".into(),
            resource_id: "customer/123".into(),
            requested_path: "/v1/customers/123".into(),
            payload_digest: vec![],
        })
        .unwrap(),
    }
}

/// Recompute one objects.json digest from the wire object (same rules as
/// tests/v2_objects.rs).
fn object_digest(name: &str, kind: &str, wire: &[u8], digests: &Value) -> Result<String, String> {
    let e = |e: V2Error| e.to_string();
    Ok(match name {
        "issuer_key_id_v2" => independent_key_id(&decode_delegation_cert_v2(wire).map_err(e)?.issuer_pub_key),
        "subject_key_id_v2" => independent_key_id(&decode_delegation_cert_v2(wire).map_err(e)?.subject_pub_key),
        "delegation_digest_hex" => {
            let b = decode_proof_bundle_v2(wire).map_err(e)?;
            let mut certs = b"[".to_vec();
            for (i, c) in b.delegations.iter().enumerate() {
                if i > 0 {
                    certs.push(b',');
                }
                certs.extend(encode_delegation_cert_v2(c).map_err(e)?);
            }
            certs.push(b']');
            let independent = sha384_prefixed("ratify-protocol-delegations-v2", &[&certs]);
            if independent != b.delegation_digest {
                return Err("wire delegation_digest differs from the recomputed chain digest".into());
            }
            hex::encode(independent)
        }
        "bundle_hash_v2" => {
            let independent = format!("sha384:{}", hex::encode(sha384_prefixed("ratify-protocol-bundle-v2", &[wire])));
            if bundle_hash_v2(&decode_proof_bundle_v2(wire).map_err(e)?).map_err(e)? != independent {
                return Err("library bundle hash differs from the formula".into());
            }
            independent
        }
        "session_context_hex" => {
            let b = decode_proof_bundle_v2(wire).map_err(e)?;
            let ctx = build_session_context_v2(&fixture_session_inputs(&b)).map_err(e)?;
            if b.session_context.as_ref() != Some(&ctx) {
                return Err("bundle session_context does not match the fixture request".into());
            }
            hex::encode(ctx)
        }
        "challenge_claim_digest_hex" => {
            hex::encode(challenge_claim_digest_v2(&decode_proof_bundle_v2(wire).map_err(e)?.challenge).map_err(e)?)
        }
        "claim_id" => {
            let b = decode_proof_bundle_v2(wire).map_err(e)?;
            let epoch: i64 = s(&digests["claim_replay_epoch"]).parse().map_err(|_| "claim_replay_epoch")?;
            protocol_claim_id_v2(&s(&digests["claim_verifier_namespace"]), epoch, &b.challenge).map_err(e)?
        }
        "claim_verifier_namespace" => "verify-test".into(),
        "claim_replay_epoch" => "3".into(),
        "receipt_outbox_body_b64" => {
            STANDARD.encode(verification_receipt_v2_body(&decode_verification_receipt_v2(wire).map_err(e)?).map_err(e)?)
        }
        "status_evidence_digest" => {
            let code: u16 = if kind == "revocation_list" { 3 } else { 5 };
            let independent = sha384_prefixed("ratify-protocol-status-evidence-v2", &[&code.to_be_bytes(), wire]);
            let library = if kind == "revocation_list" {
                status_evidence_digest_list_v2(&decode_revocation_list_v2(wire).map_err(e)?).map_err(e)?
            } else {
                status_evidence_digest_push_v2(&decode_revocation_push_v2(wire).map_err(e)?).map_err(e)?
            };
            if library != independent {
                return Err("library status evidence digest differs from the formula".into());
            }
            format!("sha384:{}", hex::encode(independent))
        }
        "statement_body_digest_hex" => {
            let (code, fields): (u16, &[&str]) = match kind {
                "key_rotation_statement" => (4, &["old_signature", "new_signature"]),
                "witness_entry" => (6, &["signature"]),
                "verification_receipt" => (8, &["signature"]),
                other => return Err(format!("statement digest for {other}")),
            };
            let body = projection(wire, if fields.len() == 2 { "old_signature" } else { "signature" });
            let independent = sha384_prefixed("ratify-protocol-statement-body-v2", &[&code.to_be_bytes(), &body]);
            let library = match kind {
                "key_rotation_statement" => {
                    key_rotation_statement_v2_digest(&decode_key_rotation_statement_v2(wire).map_err(e)?)
                }
                "witness_entry" => witness_entry_v2_digest(&decode_witness_entry_v2(wire).map_err(e)?),
                _ => verification_receipt_v2_digest(&decode_verification_receipt_v2(wire).map_err(e)?),
            }
            .map_err(e)?;
            if library != independent {
                return Err("library statement body digest differs from the formula".into());
            }
            hex::encode(independent)
        }
        "transaction_context_hex" => {
            let r = decode_transaction_receipt_v2(wire).map_err(e)?;
            let mut h = Sha256::new();
            h.update(b"ratify/transaction-context/v2");
            h.update(lp(r.transaction_id.as_bytes()));
            h.update(lp(r.terms_schema_uri.as_bytes()));
            h.update(Sha384::digest(&r.terms_canonical_json));
            let tx = h.finalize().to_vec();
            if transaction_context_hash_v2(&r) != tx {
                return Err("library transaction context differs from the formula".into());
            }
            hex::encode(tx)
        }
        other if other.contains('.') => {
            let r = decode_transaction_receipt_v2(wire).map_err(e)?;
            let (party_id, field) = other.split_once('.').unwrap();
            let p = r
                .parties
                .iter()
                .find(|p| p.party_id == party_id)
                .ok_or_else(|| format!("no party {party_id}"))?;
            let req = transaction_party_request_hash_v2(&transaction_context_hash_v2(&r), &p.required_scope);
            match field {
                "transaction_party_request_hash_hex" => hex::encode(req),
                "session_context_hex" => {
                    let ctx = build_session_context_v2(&SessionContextV2Inputs {
                        verifier_id: p.verifier_id.clone(),
                        workspace_id: p.workspace_id.clone(),
                        agent_id: p.agent_id.clone(),
                        session_id: p.session_id.clone(),
                        invocation_id: p.invocation_id.clone(),
                        request_hash: req,
                    })
                    .map_err(e)?;
                    let bound = p.proof_bundle.as_ref().and_then(|b| b.session_context.clone());
                    if bound.as_ref() != Some(&ctx) {
                        return Err(format!("{party_id} bundle session_context does not bind the transaction"));
                    }
                    hex::encode(ctx)
                }
                "proof_bundle_hash" => {
                    let b = p.proof_bundle.as_ref().ok_or("party has no proof bundle")?;
                    let h = bundle_hash_v2(b).map_err(e)?;
                    if h != p.proof_bundle_hash {
                        return Err(format!("{party_id} proof_bundle_hash differs from its bundle"));
                    }
                    h
                }
                f => return Err(format!("unknown party digest {f}")),
            }
        }
        other => return Err(format!("unknown digest {other}")),
    })
}

/// Verify one fixture document with the objects.json procedure. Returns every
/// failure found.
fn verify_fixture(data: &[u8], stem: &str) -> Vec<String> {
    let mut f = Failures::default();
    let doc: Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(e) => return vec![format!("parse: {e}")],
    };
    f.check(keys_of(&doc) == TOP_LEVEL.iter().map(|s| s.to_string()).collect(), || {
        format!("top-level members {:?}", keys_of(&doc))
    });
    f.check(doc["version"] == 2, || "version is not 2".into());
    f.check(doc["sdk"] == stem, || format!("sdk {} is not the file stem {stem}", doc["sdk"]));
    for k in ["description", "sdk_version", "generator"] {
        f.check(doc[k].as_str().is_some_and(|v| !v.is_empty()), || format!("{k} is empty"));
    }
    let codes = json!({"delegation_certificate": 1, "proof_bundle": 2, "revocation_list": 3, "key_rotation_statement": 4,
        "revocation_push": 5, "witness_entry": 6, "transaction_receipt": 7, "verification_receipt": 8});
    f.check(doc["kind_object_type_codes"] == codes, || "kind_object_type_codes differ from objects.json".into());

    // Keys: derive from seeds, recompute both IDs.
    let mut fx = Fixture { public: BTreeMap::new(), private: BTreeMap::new(), id: BTreeMap::new() };
    for k in arr(&doc["keys"]) {
        let name = s(&k["name"]);
        f.check(keys_of(k) == KEY_FIELDS.iter().map(|s| s.to_string()).collect(), || format!("key {name}: members"));
        let (public, private) =
            hybrid_keypair_from_seeds(&seed32(&s(&k["ed25519_seed_hex"])), &seed32(&s(&k["ml_dsa_65_seed_hex"])));
        let id = s(&k["key_id_v2"]);
        f.check(pub_key(&k["public_key"]) == public && keys_of(&k["public_key"]).len() == 2, || {
            format!("key {name}: seeds do not derive the public key")
        });
        f.check(
            independent_key_id(&public) == id && key_id_v2(&public).ok().as_deref() == Some(id.as_str()),
            || format!("key {name}: key_id_v2 does not recompute"),
        );
        let v1 = hex::encode(&Sha256::digest([public.ed25519.as_slice(), &public.ml_dsa_65].concat())[..16]);
        f.check(v1 == s(&k["v1_key_id_128"]) && derive_id(&public) == v1, || format!("key {name}: v1_key_id_128"));
        f.check(!fx.public.contains_key(&name), || format!("key {name}: duplicate"));
        fx.public.insert(name.clone(), public);
        fx.private.insert(name.clone(), private);
        fx.id.insert(name, id);
    }
    for name in CROSS_SDK_KEY_NAMES_V2 {
        f.check(fx.public.contains_key(name), || format!("missing key {name}"));
    }
    if !f.0.is_empty() {
        return f.0;
    }

    let mut kinds = BTreeSet::new();
    let mut codes = BTreeSet::new();
    let mut max_count_certs = BTreeSet::new();
    let mut every_constraint = false;
    let mut evaluator_receipts = 0;
    let want_profile = max_count_profile_digest();
    let library_profile = constraint_profile_digest_v2(&ConstraintProfileDescriptorV2 {
        profile: PROFILE_MAX_COUNT_V2.into(),
        kind: CONSTRAINT_MAX_COUNT_V2.into(),
    })
    .unwrap();
    f.check(library_profile == want_profile, || "library profile digest differs from the formula".into());
    let max_count_params: BTreeMap<String, ParamsValue> =
        BTreeMap::from([("counter".into(), ParamsValue::Str("nodes".into())), ("max".into(), ParamsValue::Int(10))]);

    for o in arr(&doc["objects"]) {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        kinds.insert(kind.clone());
        let wire = b64(&o["wire_b64"]);
        let is_binding = kind == "receipt_bundle_binding";
        let mut want_fields: BTreeSet<String> = OBJECT_FIELDS.iter().map(|s| s.to_string()).collect();
        if is_binding {
            want_fields.insert("bundle_b64".into());
        }
        f.check(keys_of(o) == want_fields, || format!("{name}: members {:?}", keys_of(o)));

        // Strict decode and byte-identical re-encode.
        let bundle = if is_binding { o.get("bundle_b64").map(b64).unwrap_or_default() } else { vec![] };
        let re = reencode(if is_binding { "verification_receipt" } else { &kind }, &wire);
        if !re.as_ref().is_ok_and(|b| *b == wire) {
            // Nothing below can be derived from a wire object that does not
            // strictly decode.
            f.check(false, || format!("{name}: re-encode {:?}", re.err()));
            continue;
        }
        if is_binding {
            let rb = reencode("proof_bundle", &bundle);
            f.check(rb.as_ref().is_ok_and(|b| *b == bundle), || format!("{name}: bundle re-encode {:?}", rb.err()));
            f.check(arr(&o["signatures"]).is_empty() && keys_of(&o["digests"]).is_empty(), || {
                format!("{name}: binding carries signatures or digests")
            });
        } else {
            f.check(!keys_of(&o["digests"]).is_empty(), || format!("{name}: no digests"));
        }

        // The per-kind verify procedure of object-negatives.json.
        let v = verify_object(&fx, &kind, &wire, &bundle, &o["verify"]);
        f.check(v.is_ok(), || format!("{name}: verify {v:?}"));

        // Every signature transcript.
        let wire_text = String::from_utf8_lossy(&wire).into_owned();
        for sig in arr(&o["signatures"]) {
            let field = s(&sig["field"]);
            let id = format!("{name}/{field}");
            f.check(keys_of(sig) == SIG_FIELDS.iter().map(|s| s.to_string()).collect(), || format!("{id}: members"));
            let code = i(&sig["object_type_code"]) as u16;
            codes.insert(code);
            let Some(ty) = V2ObjectType::from_code(code) else {
                f.check(false, || format!("{id}: unregistered code {code}"));
                continue;
            };
            let signable = b64(&sig["signable_b64"]);
            let m = v2_signing_message(ty, &signable);
            let ctx = String::from_utf8(v2_mldsa_context(ty)).unwrap();
            let signer = s(&sig["signer"]);
            let Some(signer_key) = fx.public.get(&signer).cloned() else {
                f.check(false, || format!("{id}: unknown signer {signer}"));
                continue;
            };
            let pinned = signature(&sig["signature"]);
            let verified = verify_v2_statement(ty, &signable, &pinned, &signer_key);
            let checks = [
                ("projection", projection(&wire, &field) == signable),
                ("sha384", hex::encode(Sha384::digest(&signable)) == s(&sig["signable_sha384_hex"])),
                ("M", m == b64(&sig["message_b64"]) && m.len() == 77),
                ("context", ctx == s(&sig["mldsa_context"]) && ctx == format!("ratify-protocol/2/{code:04x}")),
                ("signer key ID", fx.key_id(&signer) == s(&sig["signer_key_id_v2"])),
                ("tr", shake256_64(&signer_key.ml_dsa_65) == b64(&sig["mldsa_tr_b64"])),
                ("mu", external_mu_v2(&signer_key.ml_dsa_65, ctx.as_bytes(), &m) == b64(&sig["mldsa_mu_b64"])),
                ("ed25519 on wire", wire_text.contains(&format!("\"{}\"", STANDARD.encode(&pinned.ed25519)))),
                ("ml_dsa_65 on wire", wire_text.contains(&format!("\"{}\"", STANDARD.encode(&pinned.ml_dsa_65)))),
                ("verifies", verified.is_ok()),
            ];
            for (what, ok) in checks {
                f.check(ok, || format!("{id}: {what} differs"));
            }
        }

        // Every digest recomputes.
        if let Some(ds) = o["digests"].as_object() {
            for (dname, want) in ds {
                let got = object_digest(dname, &kind, &wire, &o["digests"]);
                f.check(got.as_deref() == Ok(s(want).as_str()), || format!("{name}/{dname}: got {got:?}, want {want}"));
            }
        }

        // Coverage of the extension constraint and the sealed evaluator digest.
        match kind.as_str() {
            "delegation_certificate" => {
                let c = decode_delegation_cert_v2(&wire).unwrap();
                let types: BTreeSet<&str> = c.constraints.iter().map(|k| k.kind.as_str()).collect();
                let max_count = c
                    .constraints
                    .iter()
                    .any(|k| k.kind == CONSTRAINT_MAX_COUNT_V2 && k.params.as_ref() == Some(&max_count_params));
                let raw: Value = serde_json::from_slice(&wire).unwrap();
                let raw_ok = arr(&raw["constraints"]).contains(
                    &json!({"type": "com.ratifyprotocol.max_count", "params": {"counter": "nodes", "max": 10}}),
                );
                if max_count && raw_ok {
                    max_count_certs.insert(c.cert_id.clone());
                    every_constraint |= [
                        CONSTRAINT_MAX_RATE,
                        CONSTRAINT_RECEIVER_AUDIENCE,
                        CONSTRAINT_RESOURCE_PATH,
                        CONSTRAINT_TIME_WINDOW,
                        CONSTRAINT_MAX_AMOUNT,
                    ]
                    .iter()
                    .all(|t| types.contains(t));
                }
            }
            "receipt_bundle_binding" => {
                let r = decode_verification_receipt_v2(&wire).unwrap();
                if !r.constraint_evaluators.is_empty() {
                    let b = decode_proof_bundle_v2(&bundle).unwrap();
                    let refs: Vec<(String, String)> =
                        r.constraint_evaluators.iter().map(|e| (e.kind.clone(), e.profile_digest.clone())).collect();
                    let carries = b.delegations.iter().any(|c| max_count_certs.contains(&c.cert_id));
                    let ok = refs == vec![(CONSTRAINT_MAX_COUNT_V2.to_string(), want_profile.clone())] && carries;
                    f.check(ok, || format!("{name}: constraint_evaluators {refs:?} or its bundle differs"));
                    evaluator_receipts += usize::from(ok);
                }
            }
            _ => {}
        }
    }
    for kind in CROSS_SDK_KINDS_V2 {
        f.check(kinds.contains(kind), || format!("no {kind} object"));
    }
    for code in 1..=9u16 {
        f.check(codes.contains(&code), || format!("no signature under code 0x{code:04x}"));
    }
    f.check(every_constraint, || "no certificate with every registered constraint and max_count".into());
    f.check(evaluator_receipts > 0, || "no receipt sealing the com.ratifyprotocol.max_count/v1 profile".into());
    f.0
}

fn assert_verifies(data: &[u8], stem: &str) {
    let failures = verify_fixture(data, stem);
    assert!(failures.is_empty(), "{stem}: {} failure(s):\n{}", failures.len(), failures.join("\n"));
    verify_cross_sdk_fixture_v2(data, stem).unwrap_or_else(|e| panic!("{stem}: library verifier: {e}"));
}

#[test]
fn v2_cross_sdk_fixtures() {
    let dir = corpus_dir().join("cross-sdk");
    let mut verified = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
        assert!(CROSS_SDK_NAMES_V2.contains(&stem.as_str()), "unexpected fixture {stem}.json");
        assert_verifies(&fs::read(&path).unwrap(), &stem);
        verified.push(stem);
    }
    verified.sort();
    println!("COVERAGE cross-sdk fixtures verified: {verified:?}");
    for required in ["go", "python", "rust", "typescript", "c"] {
        assert!(verified.iter().any(|v| v == required), "{required}.json is missing");
    }
}

#[test]
fn v2_cross_sdk_fresh_fixture_verifies() {
    let a = generate_cross_sdk_fixture_v2("rust", env!("CARGO_PKG_VERSION"), "in-memory test").unwrap();
    assert_verifies(&a, "rust");
    // Keys come from fresh randomness and ML-DSA-65 is hedged: a second
    // fixture shares no seed and no signature with the first.
    let b = generate_cross_sdk_fixture_v2("c", "0.0.0-test", "in-memory test").unwrap();
    assert_verifies(&b, "c");
    let (va, vb): (Value, Value) = (serde_json::from_slice(&a).unwrap(), serde_json::from_slice(&b).unwrap());
    for (ka, kb) in arr(&va["keys"]).iter().zip(arr(&vb["keys"])) {
        assert_ne!(ka["ed25519_seed_hex"], kb["ed25519_seed_hex"]);
        assert_ne!(ka["ml_dsa_65_seed_hex"], kb["ml_dsa_65_seed_hex"]);
    }
    // The file stem binds the producing SDK.
    assert!(!verify_fixture(&a, "go").is_empty());
    assert!(verify_cross_sdk_fixture_v2(&a, "go").is_err());
    assert!(generate_cross_sdk_fixture_v2("java", "1", "x").is_err());
}

#[test]
fn v2_cross_sdk_tampering_is_detected() {
    let data = fs::read(corpus_dir().join("cross-sdk/rust.json")).unwrap();
    let doc: Value = serde_json::from_slice(&data).unwrap();
    let tamper = |edit: &dyn Fn(&mut Value)| {
        let mut d = doc.clone();
        edit(&mut d);
        serde_json::to_vec(&d).unwrap()
    };
    let flip_b64 = |v: &mut Value| {
        let mut raw = STANDARD.decode(v.as_str().unwrap()).unwrap();
        raw[0] ^= 1;
        *v = Value::String(STANDARD.encode(raw));
    };
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        // (case, bytes, library verifier also rejects)
        ("seed", tamper(&|d| d["keys"][0]["ed25519_seed_hex"] = json!("00".repeat(32))), true),
        ("mu", tamper(&|d| flip_b64(&mut d["objects"][0]["signatures"][0]["mldsa_mu_b64"])), true),
        ("wire", tamper(&|d| flip_b64(&mut d["objects"][5]["wire_b64"])), true),
        ("digest", tamper(&|d| d["objects"][2]["digests"]["bundle_hash_v2"] = json!("sha384:00")), false),
        (
            "key id digest",
            tamper(&|d| {
                d["objects"][1]["digests"]["subject_key_id_v2"] = d["objects"][1]["digests"]["issuer_key_id_v2"].clone()
            }),
            false,
        ),
    ];
    for (case, bytes, library) in cases {
        assert!(!verify_fixture(&bytes, "rust").is_empty(), "{case}: tampering not detected");
        if library {
            assert!(verify_cross_sdk_fixture_v2(&bytes, "rust").is_err(), "{case}: library verifier accepted");
        }
    }
}
