//! Object-level corpus through the C ABI: keys.json, objects.json,
//! object-negatives.json, hedged-signatures.json, limits.json,
//! delegation-signature.json (and the derive-external-mu.py derivation),
//! key-rotation-signature.json, challenge-claim.json,
//! operation-session-context.json, annex-a.json, issuer-duties.json,
//! evaluator-profiles.json, and archival verification. Every Protocol
//! operation is a `ratify_*` extern "C" call; counts come from the corpus.

mod v2c_common;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use ratify_c::*;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use v2c_common::*;

fn shake256_64(input: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(input);
    let mut out = vec![0; 64];
    h.finalize_xof().read(&mut out);
    out
}

fn independent_key_id(k: &RatifyV2PublicKey) -> String {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"ratify-key-id-v2\0");
    sha2::Digest::update(&mut h, k.ed25519);
    sha2::Digest::update(&mut h, k.ml_dsa_65);
    hex::encode(h.finalize())
}

fn key_id_check(id: &str) -> R<()> {
    let c = cs(id);
    check(unsafe { ratify_v2_key_id_check(c.as_ptr(), ptr::null_mut()) })
}

fn set_top_level_string(wire: &[u8], field: &str, value: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    obj.insert(field.into(), Value::String(value.into()));
    canon(&Value::Object(obj))
}

fn object_by_kind(objects: &Value, kind: &str) -> Value {
    arr(&objects["objects"])
        .into_iter()
        .find(|o| o["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} object"))
}

/// SPEC-v2 §5 projection for a signature field, recomputed from the wire
/// with the ABI's canonical JSON.
fn projection(wire: &[u8], field: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    let mut drop = |fields: &[&str]| {
        for f in fields {
            obj.remove(*f);
        }
        canon(&Value::Object(obj.clone()))
    };
    match field {
        "signature" => drop(&["signature"]),
        "challenge_sig" => drop(&["delegations", "challenge_sig"]),
        "old_signature" | "new_signature" => drop(&["old_signature", "new_signature"]),
        _ => {
            if let Some(rest) = field.strip_prefix("delegations[") {
                let idx: usize = rest.trim_end_matches("].signature").parse().unwrap();
                let cert = serde_json::to_vec(&obj["delegations"][idx]).unwrap();
                return projection(&cert, "signature");
            }
            if field.starts_with("party_signatures[") {
                return signable(7, wire).unwrap();
            }
            panic!("unknown signature field {field}");
        }
    }
}

/// The ABI signable projection for a signature field.
fn abi_signable(wire: &[u8], field: &str, code: u32) -> R<Vec<u8>> {
    if let Some(rest) = field.strip_prefix("delegations[") {
        let idx: usize = rest.trim_end_matches("].signature").parse().unwrap();
        let obj: Value = serde_json::from_slice(wire).unwrap();
        let cert = canon(&obj["delegations"][idx]);
        return signable(1, &cert);
    }
    signable(code, wire)
}

#[test]
fn v2c_keys() {
    let keys = load("keys.json");
    let fx = Fixture::load();
    let mut t = Tally::default();
    for k in arr(&keys["keys"]) {
        let name = s(&k["name"]);
        let pinned = key_struct(&k["public_key"]);
        let id = s(&k["key_id_v2"]);
        let got = fx.key(&name);
        let v1 = s(&k["v1_key_id_128"]);
        t.check(
            "keys",
            &name,
            got.ed25519 == pinned.ed25519
                && got.ml_dsa_65 == pinned.ml_dsa_65
                && independent_key_id(&pinned) == id
                && key_id_of(&pinned).ok().as_deref() == Some(id.as_str())
                && fx.id[&name] == id
                && key_id_check(&id).is_ok()
                && class_of(&key_id_check(&v1)) == "malformed"
                && v1 != id[..32],
            || "seeds, key ID, or v1 ID differ".into(),
        );
    }
    let objects = load("objects.json");
    let bundle = b64(&object_by_kind(&objects, "proof_bundle")["wire_b64"]);
    let witness = b64(&object_by_kind(&objects, "witness_entry")["wire_b64"]);
    for bad in arr(&keys["invalid_v2_key_ids"]) {
        let value = s(&bad["value"]);
        let want = s(&bad["expected_error_class"]);
        let as_verifier = class_of(&canonicalize(
            2,
            &set_top_level_string(&bundle, "verifier_id", &value),
        ));
        let as_witness = class_of(&canonicalize(
            6,
            &set_top_level_string(&witness, "witness_id", &value),
        ));
        t.check(
            "invalid_v2_key_ids",
            &s(&bad["name"]),
            as_verifier == want && as_witness == want,
            || format!("classes {as_verifier}/{as_witness}, want {want}"),
        );
        t.check(
            "invalid_v2_key_ids format",
            &s(&bad["name"]),
            key_id_check(&value).is_err(),
            || "accepted".into(),
        );
    }
    let n_keys = arr(&keys["keys"]).len();
    let n_bad = arr(&keys["invalid_v2_key_ids"]).len();
    t.finish(&[
        ("keys", n_keys),
        ("invalid_v2_key_ids", n_bad),
        ("invalid_v2_key_ids format", n_bad),
    ]);
}

fn hex_buf(r: R<Vec<u8>>) -> String {
    hex::encode(r.expect("digest"))
}

fn op_hash(op: &Value) -> Vec<u8> {
    let j = json_bytes(op);
    buf(|o| unsafe { ratify_v2_operation_context_hash(j.as_ptr(), j.len(), o) })
        .expect("operation hash")
}

fn session_ctx(inputs: &Value) -> R<Vec<u8>> {
    let j = json_bytes(inputs);
    buf(|o| unsafe { ratify_v2_session_context(j.as_ptr(), j.len(), o) })
}

fn object_digest(name: &str, kind: &str, wire: &[u8], digests: &Value) -> Option<String> {
    let obj: Value = serde_json::from_slice(wire).unwrap();
    Some(match name {
        "issuer_key_id_v2" => {
            let k = key_struct(&obj["issuer_pub_key"]);
            let id = key_id_of(&k).unwrap();
            if id != independent_key_id(&k) {
                return Some("ABI key ID differs from the independent derivation".into());
            }
            id
        }
        "subject_key_id_v2" => key_id_of(&key_struct(&obj["subject_pub_key"])).unwrap(),
        "delegation_digest_hex" => hex_buf(buf(|o| unsafe {
            ratify_v2_delegation_digest(wire.as_ptr(), wire.len(), o)
        })),
        "bundle_hash_v2" => {
            string(|o| unsafe { ratify_v2_bundle_hash(wire.as_ptr(), wire.len(), o) }).unwrap()
        }
        "session_context_hex" => {
            let request_hash = op_hash(&json!({
                "required_scope": "data:read",
                "operation": "records.get",
                "resource_id": "customer/123",
                "requested_path": "/v1/customers/123",
            }));
            let ctx = session_ctx(&json!({
                "verifier_id": obj["verifier_id"],
                "workspace_id": "00000000-0000-4000-8000-000000000001",
                "agent_id": obj["agent_id"],
                "session_id": "session-01",
                "invocation_id": "invocation-01",
                "request_hash_b64": enc(&request_hash),
            }))
            .unwrap();
            if b64(&obj["session_context"]) != ctx {
                return Some(
                    "bundle session_context does not match the recomputed fixture context".into(),
                );
            }
            hex::encode(ctx)
        }
        "challenge_claim_digest_hex" => {
            let c = b64(&obj["challenge"]);
            hex_buf(buf(|o| unsafe {
                ratify_v2_challenge_claim_digest(c.as_ptr(), c.len(), o)
            }))
        }
        "claim_id" => {
            let c = b64(&obj["challenge"]);
            let epoch: i64 = s(&digests["claim_replay_epoch"]).parse().unwrap();
            let ns = s(&digests["claim_verifier_namespace"]);
            string(|o| unsafe {
                ratify_v2_claim_id(ns.as_ptr(), ns.len(), epoch, c.as_ptr(), c.len(), o)
            })
            .unwrap()
        }
        "claim_verifier_namespace" | "claim_replay_epoch" | "transaction_context_hex" => {
            return None
        }
        "receipt_outbox_body_b64" => enc(&buf(|o| unsafe {
            ratify_v2_verification_receipt_body(wire.as_ptr(), wire.len(), o)
        })
        .unwrap()),
        "status_evidence_digest" => {
            let k = kind_code(kind);
            format!(
                "sha384:{}",
                hex_buf(buf(|o| unsafe {
                    ratify_v2_status_evidence_digest(k, wire.as_ptr(), wire.len(), o)
                }))
            )
        }
        "statement_body_digest_hex" => {
            let k = kind_code(kind);
            hex_buf(buf(|o| unsafe {
                ratify_v2_object_body_digest(k, wire.as_ptr(), wire.len(), o)
            }))
        }
        other if other.starts_with("party-") => {
            let (party_id, field) = other.split_once('.').unwrap();
            let terms = b64(&obj["terms_canonical_json"]);
            let (tx_id, uri) = (
                cs(&s(&obj["transaction_id"])),
                cs(&s(&obj["terms_schema_uri"])),
            );
            let lp = |b: &[u8]| {
                let mut v = (b.len() as u64).to_be_bytes().to_vec();
                v.extend_from_slice(b);
                v
            };
            let mut txc = Sha256::new();
            sha2::Digest::update(&mut txc, b"ratify/transaction-context/v2");
            sha2::Digest::update(&mut txc, lp(s(&obj["transaction_id"]).as_bytes()));
            sha2::Digest::update(&mut txc, lp(s(&obj["terms_schema_uri"]).as_bytes()));
            sha2::Digest::update(&mut txc, Sha384::digest(&terms));
            let independent = txc.finalize().to_vec();
            let tx = buf(|o| unsafe {
                ratify_v2_transaction_context_hash(
                    tx_id.as_ptr(),
                    uri.as_ptr(),
                    terms.as_ptr(),
                    terms.len(),
                    o,
                )
            })
            .unwrap();
            if tx != independent || hex::encode(&tx) != s(&digests["transaction_context_hex"]) {
                return Some("transaction context differs".into());
            }
            let p = arr(&obj["parties"])
                .into_iter()
                .find(|p| s(&p["party_id"]) == party_id)
                .unwrap();
            let scope = cs(&s(&p["required_scope"]));
            let req = buf(|o| unsafe {
                ratify_v2_transaction_party_request_hash(tx.as_ptr(), tx.len(), scope.as_ptr(), o)
            })
            .unwrap();
            match field {
                "transaction_party_request_hash_hex" => hex::encode(req),
                "session_context_hex" => hex::encode(
                    session_ctx(&json!({
                        "verifier_id": p["verifier_id"],
                        "workspace_id": p["workspace_id"],
                        "agent_id": p["agent_id"],
                        "session_id": p["session_id"],
                        "invocation_id": p["invocation_id"],
                        "request_hash_b64": enc(&req),
                    }))
                    .unwrap(),
                ),
                "proof_bundle_hash" => {
                    let b = canon(&p["proof_bundle"]);
                    string(|o| unsafe { ratify_v2_bundle_hash(b.as_ptr(), b.len(), o) }).unwrap()
                }
                f => panic!("unknown party digest {f}"),
            }
        }
        other => panic!("unknown digest {other}"),
    })
}

#[test]
fn v2c_objects() {
    let fx = Fixture::load();
    let f = load("objects.json");
    let mut t = Tally::default();
    let mut codes = BTreeSet::new();
    let mut n_sigs = 0;
    for o in arr(&f["objects"]) {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        let wire = b64(&o["wire_b64"]);
        let re = canonicalize(kind_code(&kind), &wire);
        t.check(
            "re-encode",
            &name,
            re.as_ref().is_ok_and(|b| *b == wire),
            || format!("{:?}", re.as_ref().err()),
        );
        let v = verify_object(&fx, &kind, &wire, &[], &o["verify"]);
        t.check("verify", &name, v.is_ok(), || format!("{v:?}"));
        for sig in arr(&o["signatures"]) {
            n_sigs += 1;
            let field = s(&sig["field"]);
            let code = u(&sig["object_type_code"]) as u32;
            codes.insert(code);
            let id = format!("{name}/{field}");
            let signable_bytes = b64(&sig["signable_b64"]);
            let m = message(code, &signable_bytes).unwrap();
            let ctx = String::from_utf8(context(code).unwrap()).unwrap();
            let signer = s(&sig["signer"]);
            let key = fx.key(&signer);
            let pinned = &sig["signature"];
            let (ed, ml) = (b64(&pinned["ed25519"]), b64(&pinned["ml_dsa_65"]));
            let wire_text = String::from_utf8(wire.clone()).unwrap();
            let verified = verify_statement(code, &signable_bytes, &ed, &ml, &key);
            let ok = projection(&wire, &field) == signable_bytes
                && abi_signable(&wire, &field, code).ok().as_ref() == Some(&signable_bytes)
                && hex::encode(Sha384::digest(&signable_bytes)) == s(&sig["signable_sha384_hex"])
                && m == b64(&sig["message_b64"])
                && m.len() == 77
                && ctx == s(&sig["mldsa_context"])
                && ctx.len() == 22
                && fx.id[&signer] == s(&sig["signer_key_id_v2"])
                && shake256_64(&key.ml_dsa_65) == b64(&sig["mldsa_tr_b64"])
                && mu(&key, code, &m).ok() == Some(b64(&sig["mldsa_mu_b64"]))
                && wire_text.contains(&enc(&ed))
                && wire_text.contains(&enc(&ml))
                && verified.is_ok();
            t.check("signatures", &id, ok, || {
                format!("projection, transcript, or verification differs: {verified:?}")
            });
        }
        if let Some(ds) = o["digests"].as_object() {
            for (dname, want) in ds {
                if let Some(got) = object_digest(dname, &kind, &wire, &o["digests"]) {
                    t.check(
                        "digests",
                        &format!("{name}/{dname}"),
                        got == s(want),
                        || format!("got {got}, want {want}"),
                    );
                }
            }
        }
    }
    for code in 1..=9u32 {
        t.check(
            "codes",
            &format!("code {code}"),
            codes.contains(&code),
            || "no signature for code".into(),
        );
    }
    let n = arr(&f["objects"]).len();
    t.finish(&[
        ("re-encode", n),
        ("verify", n),
        ("signatures", n_sigs),
        ("codes", 9),
    ]);
}

#[test]
fn v2c_object_negatives() {
    let fx = Fixture::load();
    let f = load("object-negatives.json");
    let mut t = Tally::default();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let spec_classes: BTreeSet<String> = (1..=49).map(class).collect();
    for v in arr(&f["vectors"]) {
        let kind = s(&v["kind"]);
        *kinds.entry(kind.clone()).or_default() += 1;
        let bundle = v.get("bundle_b64").map(b64).unwrap_or_default();
        let want = s(&v["expected_error_class"]);
        assert!(
            spec_classes.contains(&want),
            "corpus class {want} is outside SPEC-v2 §2.7"
        );
        let got = class_of(&verify_object(
            &fx,
            &kind,
            &b64(&v["wire_b64"]),
            &bundle,
            &v["verify"],
        ));
        t.check("negatives", &s(&v["name"]), got == want, || {
            format!("class {got}, want {want} ({})", s(&v["mutation"]))
        });
    }
    assert!(kinds.len() >= 9, "negative kinds: {kinds:?}");
    t.finish(&[("negatives", arr(&f["vectors"]).len())]);
}

fn with_head(vc: &Value, sequence: i64, digest: &[u8]) -> Vec<u8> {
    let mut head = vc["head"].clone();
    head["sequence"] = json!(sequence);
    head["head_hash_b64"] = json!(enc(digest));
    head["accepted_digests_b64"] = json!({ sequence.to_string(): enc(digest) });
    json_bytes(&head)
}

fn hedged_idempotency(
    fx: &Fixture,
    kind: &str,
    vc: &Value,
    deterministic: &[u8],
    hedged: &[u8],
) -> Result<(), String> {
    let k = kind_code(kind);
    let digest =
        |w: &[u8]| buf(|o| unsafe { ratify_v2_object_body_digest(k, w.as_ptr(), w.len(), o) });
    match kind {
        "witness_entry" | "verification_receipt" => {
            let d1 = digest(deterministic).map_err(|e| format!("{e:?}"))?;
            if digest(hedged).ok() != Some(d1.clone()) {
                return Err("hedged object has a different body digest".into());
            }
            let seq = i(&parse(deterministic)["sequence"]);
            let head = with_head(vc, seq, &d1);
            let mut result = 0;
            let code = if kind == "witness_entry" {
                let key = fx.key(&s(&vc["witness_key"]));
                unsafe {
                    ratify_v2_witness_entry_append(
                        hedged.as_ptr(),
                        hedged.len(),
                        head.as_ptr(),
                        head.len(),
                        &key,
                        &mut result,
                        ptr::null_mut(),
                    )
                }
            } else {
                let key = fx.key(&s(&vc["verifier_key"]));
                unsafe {
                    ratify_v2_verification_receipt_append(
                        hedged.as_ptr(),
                        hedged.len(),
                        head.as_ptr(),
                        head.len(),
                        &key,
                        &mut result,
                        ptr::null_mut(),
                    )
                }
            };
            check(code).map_err(|e| format!("{e:?}"))?;
            if result == RatifyV2LogResult::RatifyV2LogReplay as i32 {
                Ok(())
            } else {
                Err(format!("not a replay: {result}"))
            }
        }
        "key_rotation_statement" => {
            if digest(deterministic).ok() != digest(hedged).ok() {
                return Err("hedged rotation statement has a different body digest".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[test]
fn v2c_hedged_signatures() {
    let fx = Fixture::load();
    let f = load("hedged-signatures.json");
    let mut t = Tally::default();
    let mut kinds = BTreeSet::new();
    let mut n = 0;
    for o in arr(&f["objects"]) {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        kinds.insert(kind.clone());
        let deterministic = b64(&o["deterministic_wire_b64"]);
        let fields: Vec<String> = arr(&o["resigned_fields"]).iter().map(s).collect();
        assert!(!fields.is_empty());
        let mut seen = vec![deterministic.clone()];
        for (k, encoded) in arr(&o["hedged_wire_b64"]).iter().enumerate() {
            n += 1;
            let wire = b64(encoded);
            let fresh = !seen.contains(&wire);
            seen.push(wire.clone());
            let re = canonicalize(kind_code(&kind), &wire);
            let v = verify_object(&fx, &kind, &wire, &[], &o["verify"]);
            let same = fields
                .iter()
                .all(|fname| projection(&wire, fname) == projection(&deterministic, fname));
            let idem = hedged_idempotency(&fx, &kind, &o["verify"], &deterministic, &wire);
            t.check("hedged", &format!("{name}#{k}"), fresh && re.as_ref().is_ok_and(|b| *b == wire) && v.is_ok() && same && idem.is_ok(), || {
                format!("fresh={fresh} reencode={:?} verify={v:?} projection={same} idempotency={idem:?}", re.is_ok())
            });
        }
    }
    assert!(kinds.len() >= 8, "hedged kinds: {kinds:?}");
    t.finish(&[("hedged", n)]);
}

fn build_limit_bytes(c: &Value) -> Vec<u8> {
    let opt_b64 = |k: &str| c.get(k).map(b64).unwrap_or_default();
    match c["method"].as_str().unwrap() {
        "inline" => b64(&c["wire_b64"]),
        "pad" => {
            let base = b64(&c["base_b64"]);
            let (last, body) = base.split_last().unwrap();
            let mut out = body.to_vec();
            out.extend(std::iter::repeat_n(b' ', i(&c["pad_count"]) as usize));
            out.push(*last);
            out
        }
        "repeat_items" => {
            let mut out = opt_b64("prefix_b64");
            let digits = c
                .get("item_index_digits")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let prefix = c.get("item_prefix").and_then(Value::as_str).unwrap_or("");
            let suffix = c.get("item_suffix").and_then(Value::as_str).unwrap_or("");
            for k in 0..i(&c["count"]) {
                if k > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(format!("{prefix}{k:0digits$}{suffix}").as_bytes());
            }
            out.extend(opt_b64("suffix_b64"));
            out
        }
        "repeat_item" => {
            let mut out = opt_b64("prefix_b64");
            let item = b64(&c["item_b64"]);
            for k in 0..i(&c["count"]) {
                if k > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&item);
            }
            out.extend(opt_b64("suffix_b64"));
            out
        }
        other => panic!("unknown construction {other}"),
    }
}

#[test]
fn v2c_limits() {
    let f = load("limits.json");
    let mut t = Tally::default();
    for v in arr(&f["vectors"]) {
        let name = s(&v["name"]);
        let limit = s(&v["limit"]);
        assert_eq!(f["limits"][&limit], v["limit_value"], "{name}: limit table");
        let data = build_limit_bytes(&v["construction"]);
        assert_eq!(data.len() as i64, i(&v["length"]), "{name}: length");
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            s(&v["sha256_hex"]),
            "{name}: digest"
        );
        let code = unsafe {
            ratify_v2_object_decode(
                kind_code(&s(&v["kind"])),
                data.as_ptr(),
                data.len(),
                ptr::null_mut(),
            )
        };
        let message = last_error();
        let result = check(code);
        let expectation_ok = match s(&v["expected"]).as_str() {
            "accept" => result.is_ok(),
            "reject" => class_of(&result) == s(&v["expected_error_class"]),
            other => panic!("unknown expectation {other}"),
        };
        let gate_failed = result.is_err()
            && message.contains(&format!("exceeds {limit} ("))
            && message.contains("rejected before parsing");
        let gate_ok = (s(&v["size_gate"]) == "fail") == gate_failed;
        t.check("limits", &name, expectation_ok && gate_ok, || {
            format!("{result:?}")
        });
    }
    t.finish(&[("limits", arr(&f["vectors"]).len())]);
}

// ---------------------------------------------------------------------------
// delegation-signature.json

/// The derivation of derive-external-mu.py: tr and mu of the shared vector,
/// computed independently and through `ratify_v2_external_mu`.
#[test]
fn v2c_external_mu_matches_shared_signature_vector() {
    let v = load("delegation-signature.json");
    let key = key_struct(&v["issuer_public_key"]);
    let context = b64(&v["mldsa_context"]);
    let m = b64(&v["message"]);
    assert_eq!((context.len(), m.len()), (22, 77));
    let tr = shake256_64(&key.ml_dsa_65);
    assert_eq!(tr, b64(&v["mldsa_tr"]));
    let mut input = tr.clone();
    input.extend_from_slice(&[0, context.len() as u8]);
    input.extend_from_slice(&context);
    input.extend_from_slice(&m);
    assert_eq!(shake256_64(&input), b64(&v["mldsa_mu"]));
    assert_eq!(
        mu(&key, u(&v["object_type_code"]) as u32, &m).unwrap(),
        b64(&v["mldsa_mu"])
    );
}

#[test]
fn v2c_delegation_signature_vector() {
    let v = load("delegation-signature.json");
    let code = u(&v["object_type_code"]) as u32;
    assert_eq!(code, 1);
    let signable_bytes = b64(&v["signable_bytes"]);
    assert_eq!(message(code, &signable_bytes).unwrap(), b64(&v["message"]));
    assert_eq!(context(code).unwrap(), b64(&v["mldsa_context"]));
    assert_ne!(context(code).unwrap(), b64(&v["alternate_mldsa_context"]));
    let key = key_struct(&v["issuer_public_key"]);
    assert_eq!(key_id_of(&key).unwrap(), s(&v["key_id_v2"]));
    let seeds = &v["issuer_seeds"];
    let kp = Kp::from_seeds(&b64(&seeds["ed25519"]), &b64(&seeds["ml_dsa_65"]));
    let derived = kp.public();
    assert!(derived.ed25519 == key.ed25519 && derived.ml_dsa_65 == key.ml_dsa_65);
    let (ed, ml) = (
        b64(&v["signature"]["ed25519"]),
        b64(&v["signature"]["ml_dsa_65"]),
    );
    verify_statement(code, &signable_bytes, &ed, &ml, &key).expect("pinned signature verifies");
    // The same signature under another registered code is a different
    // transcript; an unregistered code is unsupported.
    assert_eq!(
        class_of(&verify_statement(2, &signable_bytes, &ed, &ml, &key)),
        "invalid_signature"
    );
    assert_eq!(
        class_of(&verify_statement(0x000a, &signable_bytes, &ed, &ml, &key)),
        "unsupported_object_type"
    );
    // Every listed component mutation fails verification.
    let mask = u(&v["negative_mutations"]["xor_mask"]) as u8;
    let mut mutations = 0;
    for target in arr(&v["negative_mutations"]["targets"]) {
        let (mut sb, mut e, mut l, mut k) = (signable_bytes.clone(), ed.clone(), ml.clone(), key);
        match s(&target).as_str() {
            "signable_bytes" => sb[0] ^= mask,
            "signature.ed25519" => e[0] ^= mask,
            "signature.ml_dsa_65" => l[0] ^= mask,
            "issuer_public_key.ed25519" => k.ed25519[0] ^= mask,
            "issuer_public_key.ml_dsa_65" => k.ml_dsa_65[0] ^= mask,
            other => panic!("unknown mutation target {other}"),
        }
        assert!(
            verify_statement(code, &sb, &e, &l, &k).is_err(),
            "mutation {target} verified"
        );
        mutations += 1;
    }
    assert!(mutations > 0);
    // Truncated key components never derive a key ID.
    let (ked, kml) = (key.ed25519, key.ml_dsa_65);
    let mut out = [0 as c_char; RATIFY_V2_KEY_ID_BUF_LEN];
    let c = unsafe {
        ratify_v2_key_id(
            ked.as_ptr(),
            31,
            kml.as_ptr(),
            1952,
            out.as_mut_ptr(),
            out.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(class(c), "malformed");
    let c = unsafe {
        ratify_v2_key_id(
            ked.as_ptr(),
            32,
            kml.as_ptr(),
            1951,
            out.as_mut_ptr(),
            out.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(class(c), "malformed");
}

// ---------------------------------------------------------------------------
// key-rotation-signature.json

#[test]
fn v2c_key_rotation_signature_vector() {
    let v = load("key-rotation-signature.json");
    let mut t = Tally::default();
    let mut cases = vec![v.clone()];
    if v["continuation"].is_object() {
        cases.push(v["continuation"].clone());
    }
    let row = "key-rotation-signature.json";
    for (n, c) in cases.iter().enumerate() {
        let seed = |x: &Value| hex::decode(s(x)).unwrap();
        let old = Kp::from_seeds(
            &seed(&c["old_key_seeds"]["ed25519"]),
            &seed(&c["old_key_seeds"]["ml_dsa_65"]),
        );
        let new = Kp::from_seeds(
            &seed(&c["new_key_seeds"]["ed25519"]),
            &seed(&c["new_key_seeds"]["ml_dsa_65"]),
        );
        let (old_pub, new_pub) = (old.public(), new.public());
        t.check(
            row,
            &format!("case {n} keys"),
            key_json(&old_pub) == c["old_key"] && key_json(&new_pub) == c["new_key"],
            || "seed-derived keys differ".into(),
        );
        let stmt = json!({
            "version": c["version"],
            "authority_id": c["authority_id"],
            "recovery_epoch": c["recovery_epoch"],
            "role": c["role"],
            "sequence": c["sequence"],
            "previous_statement_hash": c["previous_statement_hash"],
            "old_key": c["old_key"],
            "new_key": c["new_key"],
            "old_key_id": c["old_key_id"],
            "new_key_id": c["new_key_id"],
            "issued_at": c["issued_at"],
            "not_before": c["not_before"],
            "old_signature": c["old_signature"],
            "new_signature": c["new_signature"],
        });
        let built = canon(&stmt);
        let wire = canonicalize(4, &built);
        t.check(
            row,
            &format!("case {n} wire"),
            wire.as_ref().ok() == Some(&b64(&c["wire"])),
            || format!("{:?}", wire.as_ref().err()),
        );
        let wire = b64(&c["wire"]);
        let sb = signable(4, &wire).unwrap();
        t.check(
            row,
            &format!("case {n} signable"),
            sb == b64(&c["signable_bytes"]) && signable(9, &wire).ok() == Some(sb.clone()),
            || "signable differs".into(),
        );
        let digest =
            buf(|o| unsafe { ratify_v2_object_body_digest(4, wire.as_ptr(), wire.len(), o) })
                .unwrap();
        t.check(
            row,
            &format!("case {n} digest"),
            hex::encode(&digest) == s(&c["statement_body_digest"]),
            || "digest differs".into(),
        );
        t.check(
            row,
            &format!("case {n} contexts"),
            context(4).unwrap() == s(&c["old_mldsa_context"]).as_bytes()
                && context(9).unwrap() == s(&c["new_mldsa_context"]).as_bytes(),
            || "contexts differ".into(),
        );
        let sig = |f: &str| (b64(&c[f]["ed25519"]), b64(&c[f]["ml_dsa_65"]));
        let ((oe, om), (ne, nm)) = (sig("old_signature"), sig("new_signature"));
        let ok = verify_statement(4, &sb, &oe, &om, &old_pub).is_ok()
            && verify_statement(9, &sb, &ne, &nm, &new_pub).is_ok();
        t.check(row, &format!("case {n} signatures"), ok, || {
            "pinned signatures do not verify".into()
        });
        // Fresh (hedged) signatures through the typed ABI signer verify too.
        let resigned = buf(|o| unsafe {
            ratify_v2_sign_key_rotation_statement(
                wire.as_ptr(),
                wire.len(),
                old.0,
                ptr::null(),
                new.0,
                ptr::null(),
                o,
            )
        });
        let ok = resigned.as_ref().is_ok_and(|r| {
            let rv = parse(r);
            let (oe, om) = (
                b64(&rv["old_signature"]["ed25519"]),
                b64(&rv["old_signature"]["ml_dsa_65"]),
            );
            let (ne, nm) = (
                b64(&rv["new_signature"]["ed25519"]),
                b64(&rv["new_signature"]["ml_dsa_65"]),
            );
            signable(4, r).ok() == Some(sb.clone())
                && verify_statement(4, &sb, &oe, &om, &old_pub).is_ok()
                && verify_statement(9, &sb, &ne, &nm, &new_pub).is_ok()
        });
        t.check(row, &format!("case {n} resign"), ok, || {
            format!("{:?}", resigned.err())
        });
    }
    t.finish(&[(row, cases.len() * 7)]);
}

// ---------------------------------------------------------------------------
// challenge-claim.json and operation-session-context.json

fn claim_id(ns: &str, epoch: i64, challenge: &[u8]) -> R<String> {
    string(|o| unsafe {
        ratify_v2_claim_id(
            ptr_of(ns.as_bytes()),
            ns.len(),
            epoch,
            ptr_of(challenge),
            challenge.len(),
            o,
        )
    })
}

fn claim_id_from_digest(ns: &str, epoch: i64, digest: &[u8]) -> R<String> {
    string(|o| unsafe {
        ratify_v2_claim_id_from_digest(
            ptr_of(ns.as_bytes()),
            ns.len(),
            epoch,
            ptr_of(digest),
            digest.len(),
            o,
        )
    })
}

#[test]
fn v2c_challenge_claim() {
    let v = load("challenge-claim.json");
    let challenge = hex::decode(s(&v["challenge_hex"])).unwrap();
    let digest = buf(|o| unsafe {
        ratify_v2_challenge_claim_digest(challenge.as_ptr(), challenge.len(), o)
    })
    .unwrap();
    assert_eq!(
        hex::encode(&digest),
        s(&v["expected_challenge_claim_digest_hex"])
    );
    let mut cases = vec![(v["claim_id_input"].clone(), s(&v["expected_claim_id"]))];
    for c in arr(&v["additional_claim_id_cases"]) {
        cases.push((c.clone(), s(&c["expected_claim_id"])));
    }
    for (input, want) in &cases {
        let (ns, epoch) = (s(&input["verifier_namespace"]), i(&input["replay_epoch"]));
        assert_eq!(&claim_id(&ns, epoch, &challenge).unwrap(), want, "{input}");
        assert_eq!(
            &claim_id_from_digest(&ns, epoch, &digest).unwrap(),
            want,
            "{input}"
        );
    }
    println!(
        "C-ABI COVERAGE challenge-claim.json: {} claim IDs",
        cases.len()
    );
    for len in [0usize, 31, 33] {
        let c = vec![0u8; len];
        assert!(
            buf(|o| unsafe { ratify_v2_challenge_claim_digest(ptr_of(&c), c.len(), o) }).is_err()
        );
    }
    assert!(claim_id("", 7, &[0; 32]).is_err());
    assert!(claim_id("verify-prod", 1 << 53, &[0; 32]).is_err());
    for len in [0usize, 47, 49] {
        assert!(claim_id_from_digest("verify-prod", 7, &vec![0; len]).is_err());
    }
}

fn operation_from(v: &Value) -> Value {
    let mut o = json!({
        "required_scope": v["required_scope"],
        "operation": v["operation"],
        "resource_id": v["resource_id"],
        "requested_path": v["requested_path"],
    });
    if let Some(h) = v["payload_digest_hex"].as_str() {
        o["payload_digest_b64"] = json!(enc(&hex::decode(h).unwrap()));
    }
    o
}

fn session_from(v: &Value, request_hash: &[u8]) -> Value {
    json!({
        "verifier_id": v["verifier_id"],
        "workspace_id": v["workspace_id"],
        "agent_id": v["agent_id"],
        "session_id": v["session_id"],
        "invocation_id": v["invocation_id"],
        "request_hash_b64": enc(request_hash),
    })
}

fn try_op_hash(op: &Value) -> R<Vec<u8>> {
    let j = json_bytes(op);
    buf(|o| unsafe { ratify_v2_operation_context_hash(j.as_ptr(), j.len(), o) })
}

#[test]
fn v2c_operation_session_context() {
    let v = load("operation-session-context.json");
    let req = op_hash(&operation_from(&v["operation_input"]));
    assert_eq!(hex::encode(&req), s(&v["expected_request_hash_hex"]));
    let input_hash = hex::decode(s(&v["input"]["request_hash_hex"])).unwrap();
    assert_eq!(
        hex::encode(session_ctx(&session_from(&v["input"], &input_hash)).unwrap()),
        s(&v["expected_session_context_hex"])
    );
    let empty = op_hash(&operation_from(&v["empty_payload_operation_input"]));
    assert_eq!(
        hex::encode(&empty),
        s(&v["expected_empty_request_hash_hex"])
    );
    assert_eq!(
        hex::encode(session_ctx(&session_from(&v["input"], &empty)).unwrap()),
        s(&v["expected_empty_session_context_hex"])
    );
    // The context policy digest of the shared policy.
    let p = &v["context_policy"];
    // A bound policy needs an authenticated context; it is excluded from the digest.
    let expected_ctx = enc(&hex::decode(s(&v["expected_session_context_hex"])).unwrap());
    let policy = json_bytes(&json!({
        "profile": p["profile"],
        "require_bound": p["require_bound"],
        "required_fields": p["required_fields"],
        "expected_session_context_b64": expected_ctx,
    }));
    let digest =
        string(|o| unsafe { ratify_v2_context_policy_digest(policy.as_ptr(), policy.len(), o) })
            .unwrap();
    assert_eq!(digest, s(&v["context_policy_digest"]));
    let mut n = 0;
    for scope in arr(&v["invalid_required_scopes"]) {
        let mut op = operation_from(&v["operation_input"]);
        op["required_scope"] = scope.clone();
        assert!(try_op_hash(&op).is_err(), "accepted {scope}");
        n += 1;
    }
    for c in arr(&v["verify_api_payload_digest_decode_cases"]) {
        let encoded = c["encoded"].as_str().map(cs);
        let mut present = 0;
        let got = buf(|o| unsafe {
            ratify_v2_payload_digest_decode(
                encoded.as_ref().map_or(ptr::null(), |e| e.as_ptr()),
                o,
                &mut present,
            )
        });
        assert_eq!(got.is_ok(), b(&c["valid"]), "case {}", c["name"]);
        if let Ok(d) = got {
            assert_eq!(hex::encode(d), s(&c["expected_hex"]), "case {}", c["name"]);
            assert_eq!(
                present != 0,
                !s(&c["expected_hex"]).is_empty(),
                "case {}",
                c["name"]
            );
        }
        n += 1;
    }
    let input = &v["verify_api_operation_input"];
    let enc_digest = cs(&s(&input["payload_digest"]));
    let mut present = 0;
    let digest =
        buf(|o| unsafe { ratify_v2_payload_digest_decode(enc_digest.as_ptr(), o, &mut present) })
            .unwrap();
    let op = json!({
        "required_scope": input["required_scope"],
        "operation": input["operation"],
        "resource_id": input["resource_id"],
        "requested_path": input["requested_path"],
        "payload_digest_b64": enc(&digest),
    });
    assert_eq!(
        hex::encode(op_hash(&op)),
        s(&v["expected_verify_api_request_hash_hex"])
    );
    assert_eq!(
        op_hash(&op),
        req,
        "Verify text digest and canonical raw digest must bind the same action"
    );
    // Malformed IDs, hashes, and payload lengths.
    let mut short = operation_from(&v["operation_input"]);
    let mut pd = hex::decode(s(&v["operation_input"]["payload_digest_hex"])).unwrap();
    pd.pop();
    short["payload_digest_b64"] = json!(enc(&pd));
    assert!(try_op_hash(&short).is_err());
    let good = session_from(&v["input"], &[0; 32]);
    for (field, value) in [
        (
            "verifier_id",
            json!(s(&v["input"]["verifier_id"]).to_uppercase()),
        ),
        (
            "verifier_id",
            json!(s(&v["input"]["verifier_id"])[..32].to_string()),
        ),
        (
            "workspace_id",
            json!("00000000-0000-4000-8000-00000000000A"),
        ),
        ("agent_id", json!("not-a-key-id")),
        ("request_hash_b64", json!(enc(&[0; 31]))),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(session_ctx(&bad).is_err(), "{field} accepted");
    }
    println!("C-ABI COVERAGE operation-session-context.json: {n} cases");
}

// ---------------------------------------------------------------------------
// annex-a.json

fn take_c(p: *mut c_char) -> String {
    assert!(!p.is_null(), "v1 scope export returned NULL");
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
    unsafe { ratify_string_free(p) };
    s
}

fn strings(v: &Value) -> Vec<String> {
    arr(v).iter().map(s).collect()
}

fn expand(scopes: &[String]) -> Vec<String> {
    let j = cs(&serde_json::to_string(scopes).unwrap());
    serde_json::from_str(&take_c(unsafe {
        ratify_scopes_expand(j.as_ptr(), ptr::null_mut())
    }))
    .unwrap()
}

fn sensitive(scope: &str) -> bool {
    let c = cs(scope);
    unsafe { ratify_scope_is_sensitive(c.as_ptr()) != 0 }
}

fn validate_scopes(scopes: &[String]) -> R<()> {
    let j = serde_json::to_vec(scopes).unwrap();
    check(unsafe { ratify_v2_validate_scopes(j.as_ptr(), j.len()) })
}

fn is_canonical_object(input: &[u8]) -> bool {
    input.first() == Some(&b'{') && canonical_json(input).is_ok_and(|c| c == input)
}

#[test]
fn v2c_annex_a() {
    let f = load("annex-a.json");
    let mut t = Tally::default();
    let annex =
        std::fs::read_to_string(corpus_dir().join("../../SPEC-v2-ANNEX-A.md")).expect("annex");
    let lines: Vec<&str> = annex.split('\n').collect();
    for c in arr(&f["clauses"]) {
        let id = s(&c["id"]);
        let begin = lines
            .iter()
            .position(|l| *l == format!("<!-- annex-a:begin {id} -->"));
        let end = lines
            .iter()
            .position(|l| *l == format!("<!-- annex-a:end {id} -->"));
        let ok = match (begin, end) {
            (Some(bg), Some(e)) if e > bg + 1 => {
                let block = lines[bg + 1..e].join("\n");
                block.len() as i64 == i(&c["bytes"])
                    && hex::encode(Sha256::digest(block.as_bytes())) == s(&c["sha256"])
                    && annex.contains(&format!("`{}`", s(&c["sha256"])))
            }
            _ => false,
        };
        t.check("clauses", &id, ok, || {
            "clause bytes or digest differ".into()
        });
    }
    for v in arr(&f["canonical_json"]) {
        let input = b64(&v["input_b64"]);
        let got = canonical_json(&input);
        let want = s(&v["canonical"]);
        let canonical_input = is_canonical_object(&input);
        let ok = got.as_ref().is_ok_and(|g| g == want.as_bytes())
            && is_canonical_object(want.as_bytes())
            && canonical_input == b(&v["input_is_canonical"])
            && canonical_input == (got.as_ref().ok().map(Vec::as_slice) == Some(input.as_slice()));
        t.check("canonical_json", &s(&v["name"]), ok, || format!("{got:?}"));
    }
    for v in arr(&f["strict_decode_rejections"]) {
        let input = b64(&v["input_b64"]);
        t.check(
            "strict_decode_rejections",
            &s(&v["name"]),
            canonical_json(&input).is_err(),
            || format!("{:?} accepted", String::from_utf8_lossy(&input)),
        );
    }
    let vocab = &f["vocabulary"];
    let canonical = strings(&vocab["canonical"]);
    let ours: Vec<String> = serde_json::from_str(&take_c(ratify_scope_vocabulary())).unwrap();
    t.check("vocabulary", "canonical", ours == canonical, || {
        format!("{ours:?}")
    });
    let sens: Vec<String> = canonical.iter().filter(|c| sensitive(c)).cloned().collect();
    t.check(
        "vocabulary",
        "sensitive",
        sens == strings(&vocab["sensitive"]),
        || format!("{sens:?}"),
    );
    for c in &canonical {
        t.check(
            "vocabulary",
            c,
            validate_scopes(std::slice::from_ref(c)).is_ok(),
            || "rejected".into(),
        );
    }
    let wildcards = vocab["wildcards"].as_object().unwrap();
    for (w, want) in wildcards {
        let got = expand(std::slice::from_ref(w));
        let want = strings(want);
        t.check(
            "wildcards",
            w,
            got == want && want.iter().all(|x| !sensitive(x)),
            || format!("{got:?}"),
        );
    }
    for v in arr(&f["scope_validation"]) {
        let valid = validate_scopes(&strings(&v["scopes"])).is_ok();
        t.check(
            "scope_validation",
            &s(&v["name"]),
            valid == b(&v["valid"]),
            || format!("valid={valid}"),
        );
    }
    for v in arr(&f["scope_expansion"]) {
        let got = expand(&strings(&v["scopes"]));
        t.check(
            "scope_expansion",
            &s(&v["name"]),
            got == strings(&v["expanded"]),
            || format!("{got:?}"),
        );
    }
    for v in arr(&f["scope_intersection"]) {
        let lists: Vec<std::ffi::CString> = arr(&v["lists"])
            .iter()
            .map(|l| cs(&l.to_string()))
            .collect();
        let ptrs: Vec<*const c_char> = lists.iter().map(|c| c.as_ptr()).collect();
        let got: Vec<String> = serde_json::from_str(&take_c(unsafe {
            ratify_scopes_intersect(ptrs.as_ptr(), ptrs.len(), ptr::null_mut())
        }))
        .unwrap();
        t.check(
            "scope_intersection",
            &s(&v["name"]),
            got == strings(&v["effective"]),
            || format!("{got:?}"),
        );
    }
    let n = |k: &str| arr(&f[k]).len();
    t.finish(&[
        ("clauses", n("clauses")),
        ("canonical_json", n("canonical_json")),
        ("strict_decode_rejections", n("strict_decode_rejections")),
        ("vocabulary", canonical.len() + 2),
        ("wildcards", wildcards.len()),
        ("scope_validation", n("scope_validation")),
        ("scope_expansion", n("scope_expansion")),
        ("scope_intersection", n("scope_intersection")),
    ]);
}

// ---------------------------------------------------------------------------
// issuer-duties.json

/// An external signer that only counts calls and refuses to sign.
struct CountingRefusal {
    calls: AtomicUsize,
    key: RatifyV2PublicKey,
}

unsafe extern "C" fn counting_public_key(user: *mut c_void, out: *mut RatifyV2PublicKey) -> i32 {
    let c = &*(user as *const CountingRefusal);
    c.calls.fetch_add(1, Ordering::SeqCst);
    *out = c.key;
    0
}

unsafe extern "C" fn counting_sign(
    user: *mut c_void,
    _req: *const RatifyV2SignRequest,
    _out: *mut RatifyV2Signature,
) -> i32 {
    (*(user as *const CountingRefusal))
        .calls
        .fetch_add(1, Ordering::SeqCst);
    RatifyV2Code::RatifyV2SignProvider as i32
}

#[test]
fn v2c_issuer_duties() {
    let fx = Fixture::load();
    let f = load("issuer-duties.json");
    let mut t = Tally::default();
    for v in arr(&f["vectors"]) {
        let name = s(&v["name"]);
        let unsigned = b64(&v["unsigned_certificate_b64"]);
        let issuer = s(&v["issuer"]);
        let ok = match s(&v["expected"]).as_str() {
            "sign" => {
                let signed = buf(|o| unsafe {
                    ratify_v2_sign_delegation_certificate(
                        unsigned.as_ptr(),
                        unsigned.len(),
                        fx.kp(&issuer).0,
                        ptr::null(),
                        o,
                    )
                });
                signed.is_ok_and(|c| {
                    verify_object(&fx, "delegation_certificate", &c, &[], &Value::Null).is_ok()
                })
            }
            "reject" => {
                let counter = CountingRefusal {
                    calls: AtomicUsize::new(0),
                    key: fx.key(&issuer),
                };
                let ext = RatifyV2ExternalSigner {
                    user: &counter as *const CountingRefusal as *mut c_void,
                    mode: RatifyV2SignerMode::RatifyV2SignerDirect as i32,
                    public_key: Some(counting_public_key),
                    sign: Some(counting_sign),
                };
                let r = buf(|o| unsafe {
                    ratify_v2_sign_delegation_certificate(
                        unsigned.as_ptr(),
                        unsigned.len(),
                        ptr::null(),
                        &ext,
                        o,
                    )
                });
                // The local signer refuses with the same issuer duty.
                let local = buf(|o| unsafe {
                    ratify_v2_sign_delegation_certificate(
                        unsigned.as_ptr(),
                        unsigned.len(),
                        fx.kp(&issuer).0,
                        ptr::null(),
                        o,
                    )
                });
                r.as_ref().err().map(|e| e.code)
                    == Some(RatifyV2Code::RatifyV2SignIssuerDuty as i32)
                    && local.err().map(|e| e.code)
                        == Some(RatifyV2Code::RatifyV2SignIssuerDuty as i32)
                    && counter.calls.load(Ordering::SeqCst) == 0
            }
            other => panic!("unknown expectation {other}"),
        };
        t.check("issuer-duties", &name, ok, || {
            "wrong signing outcome or a signer method ran".into()
        });
    }
    t.finish(&[("issuer-duties", arr(&f["vectors"]).len())]);
}

// ---------------------------------------------------------------------------
// evaluator-profiles.json

fn eval_context(v: &Value) -> Value {
    let mut c = json!({});
    if v["extension_counts"].is_object() {
        c["extension_counts"] = v["extension_counts"].clone();
    }
    if v["extension_values"].is_object() {
        c["extension_values"] = v["extension_values"].clone();
    }
    c
}

fn validate_context(c: &Value) -> R<()> {
    let j = json_bytes(c);
    check(unsafe { ratify_v2_validate_request_context(j.as_ptr(), j.len()) })
}

#[test]
fn v2c_evaluator_profiles() {
    let f = load("evaluator-profiles.json");
    let mut t = Tally::default();
    let suites = arr(&f["profiles"]);
    assert!(!suites.is_empty());
    let mut rows = Vec::new();
    for suite in &suites {
        let profile = s(&suite["profile"]);
        let (p, ty) = (cs(&profile), cs(&s(&suite["type"])));
        let digest =
            string(|o| unsafe { ratify_v2_constraint_profile_digest(p.as_ptr(), ty.as_ptr(), o) })
                .unwrap();
        assert_eq!(digest, s(&suite["profile_digest"]), "{profile} digest");
        let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
        let cases = arr(&suite["cases"]);
        for c in &cases {
            let ctx = eval_context(&c["context"]);
            validate_context(&ctx).expect("case context is inside the request-context bounds");
            let mut input = json!({
                "type": suite["type"],
                "delegation_index": 0,
                "constraint_index": 0,
                "issuer_id": "issuer-1",
                "cert_id": "cert-1",
                "context": ctx,
                "evaluation_time": 1000,
            });
            if !b(&c["params_absent"]) {
                input["params"] = c["params"].clone();
            }
            let j = json_bytes(&input);
            let (mut outcome, mut until) = (0i32, -1i64);
            let mut detail: *mut c_char = ptr::null_mut();
            check(unsafe {
                ratify_v2_evaluate_standard_profile(
                    p.as_ptr(),
                    j.as_ptr(),
                    j.len(),
                    &mut outcome,
                    &mut until,
                    &mut detail,
                )
            })
            .expect("standard profiles never error");
            let detail = take_str(detail);
            let got = match outcome {
                1 => "pass",
                2 => "denied",
                3 => "unverifiable",
                _ => "invalid",
            };
            let want = s(&c["outcome"]);
            *outcomes.entry(want.clone()).or_default() += 1;
            t.check(&profile, &s(&c["name"]), got == want && until == 0, || {
                format!("{got} ({detail}), want {want}")
            });
        }
        assert_eq!(outcomes.len(), 3, "{profile} outcomes {outcomes:?}");
        rows.push((profile, cases.len()));
    }
    for c in arr(&f["context_bounds"]) {
        let got = class_of(&validate_context(&eval_context(&c["context"])));
        let want = c["error_class"]
            .as_str()
            .filter(|x| !x.is_empty())
            .unwrap_or("ok")
            .to_string();
        t.check("context_bounds", &s(&c["name"]), got == want, || {
            format!("{got}, want {want}")
        });
    }
    let n_bounds = arr(&f["context_bounds"]).len();
    let mut exact: Vec<(&str, usize)> = rows.iter().map(|(p, n)| (p.as_str(), *n)).collect();
    exact.push(("context_bounds", n_bounds));
    t.finish(&exact);
}

// ---------------------------------------------------------------------------
// Archival verification (SPEC-v2 §6.10)

fn archival(
    kind: i32,
    wire: &[u8],
    issuer: Option<&str>,
    key: Option<&RatifyV2PublicKey>,
) -> R<Value> {
    let issuer = issuer.map(cs);
    buf(|o| unsafe {
        ratify_v2_archival_verify(
            kind,
            wire.as_ptr(),
            wire.len(),
            issuer.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            key.map_or(ptr::null(), |k| k as *const _),
            o,
        )
    })
    .map(|b| parse(&b))
}

#[test]
fn v2c_archival_results_are_labelled_and_non_actionable() {
    let f = load("verifier-ordering.json");
    let v = arr(&f["vectors"])
        .into_iter()
        .find(|v| s(&v["name"]) == "allow_bound_context")
        .expect("vector");
    let wire = b64(&f["bundles_b64"][s(&v["bundle"])]);
    let bundle = parse(&wire);
    let got = archival(2, &wire, None, None).unwrap();
    let hash = string(|o| unsafe { ratify_v2_bundle_hash(wire.as_ptr(), wire.len(), o) }).unwrap();
    let mut issuers: Vec<String> = arr(&bundle["delegations"])
        .iter()
        .map(|c| s(&c["issuer_id"]))
        .collect();
    issuers.sort();
    issuers.dedup();
    assert_eq!(
        got,
        json!({"actionable": false, "agent_id": bundle["agent_id"], "assessment": "freshness_unverified", "bundle_hash": hash, "error_class": null, "issuer_ids": issuers})
    );
    let text = String::from_utf8(wire.clone()).unwrap();
    let tampered = text.replacen("\"challenge_at\":", "\"challenge_at\":1", 1);
    let got = archival(2, tampered.as_bytes(), None, None).unwrap();
    assert_eq!(
        (got["error_class"].clone(), got["actionable"].clone()),
        (json!("invalid_signature"), json!(false))
    );
    assert_eq!(
        archival(2, b"{", None, None).unwrap()["error_class"],
        "malformed"
    );
    let cert = canon(&bundle["delegations"][0]);
    let got = archival(1, &cert, None, None).unwrap();
    assert_eq!(got["object_type_code"], 1);
    assert_eq!(
        (
            got["actionable"].clone(),
            got["freshness"].clone(),
            got["digest"].clone()
        ),
        (json!(false), json!("freshness_unverified"), json!(""))
    );
    assert_eq!(
        got["signer_key_ids"],
        json!([bundle["delegations"][0]["issuer_id"]])
    );
}

#[test]
fn v2c_archival_status_and_log_objects_use_caller_keys() {
    let (status, _, _) = Kp::generate();
    let (other, _, _) = Kp::generate();
    let issuer = "b".repeat(64);
    let list = json_bytes(
        &json!({"version": 2, "issuer_id": issuer, "updated_at": 1, "next_update": 10, "sequence": 1, "revoked": []}),
    );
    let ic = cs(&issuer);
    let status_pub = status.public();
    let signed = buf(|o| unsafe {
        ratify_v2_sign_revocation_list(
            list.as_ptr(),
            list.len(),
            ic.as_ptr(),
            &status_pub,
            status.0,
            ptr::null(),
            o,
        )
    })
    .unwrap();
    let got = archival(3, &signed, Some(&issuer), Some(&status_pub)).unwrap();
    let digest =
        buf(|o| unsafe { ratify_v2_status_evidence_digest(3, signed.as_ptr(), signed.len(), o) })
            .unwrap();
    assert_eq!(got["actionable"], false);
    assert_eq!(got["signer_key_ids"], json!([status.id()]));
    assert_eq!(
        got["digest"],
        json!(format!("sha384:{}", hex::encode(digest)))
    );
    assert_eq!(
        class_of(&archival(3, &signed, Some(&issuer), Some(&other.public()))),
        "invalid_signature"
    );
    assert_eq!(
        class_of(&archival(
            3,
            &signed,
            Some(&"c".repeat(64)),
            Some(&status_pub)
        )),
        "status_key_binding_mismatch"
    );

    let (witness, _, _) = Kp::generate();
    let entry = json_bytes(&json!({
        "version": 2,
        "log_id": "a".repeat(32),
        "sequence": 7,
        "prev_hash": enc(&[1; 48]),
        "entry_data": enc(b"x"),
        "timestamp": 1,
        "witness_id": witness.id(),
    }));
    let signed = buf(|o| unsafe {
        ratify_v2_sign_witness_entry(entry.as_ptr(), entry.len(), witness.0, ptr::null(), o)
    })
    .unwrap();
    let got = archival(6, &signed, None, Some(&witness.public())).unwrap();
    let digest =
        buf(|o| unsafe { ratify_v2_object_body_digest(6, signed.as_ptr(), signed.len(), o) })
            .unwrap();
    assert!(got["actionable"] == false && s(&got["digest"]).ends_with(&hex::encode(digest)));
    assert_eq!(
        class_of(&archival(6, &signed, None, Some(&other.public()))),
        "key_id_mismatch"
    );
}
