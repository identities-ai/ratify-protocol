//! Protocol v2 object corpus: keys.json, objects.json,
//! object-negatives.json, hedged-signatures.json, and limits.json.

mod v2_common;

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::derive_id;
use ratify_protocol::v2::*;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
use v2_common::*;

fn object_by_kind(objects: &Value, kind: &str) -> Value {
    arr(&objects["objects"])
        .iter()
        .find(|o| o["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} object"))
        .clone()
}

#[test]
fn v2_keys() {
    let keys = load("keys.json");
    let fx = fixture();
    let mut t = Tally::default();
    for k in arr(&keys["keys"]) {
        let name = s(&k["name"]);
        let pinned = pub_key(&k["public_key"]);
        let id = s(&k["key_id_v2"]);
        let v1 = derive_id(&pinned);
        t.check(
            "keys",
            &name,
            fx.key(&name) == pinned
                && independent_key_id(&pinned) == id
                && key_id_v2(&pinned).ok().as_deref() == Some(id.as_str())
                && v1 == s(&k["v1_key_id_128"])
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
        let as_verifier = class_of(&decode_proof_bundle_v2(&set_top_level_string(&bundle, "verifier_id", &value)));
        let as_witness = class_of(&decode_witness_entry_v2(&set_top_level_string(&witness, "witness_id", &value)));
        t.check("invalid_v2_key_ids", &s(&bad["name"]), as_verifier == want && as_witness == want, || {
            format!("classes {as_verifier}/{as_witness}, want {want}")
        });
        // Invalid IDs are also never accepted as a key ID format.
        t.check("invalid_v2_key_ids format", &s(&bad["name"]), !valid_v2_id(&value), || "accepted".into());
    }
    t.finish(&[("keys", 18), ("invalid_v2_key_ids", 6), ("invalid_v2_key_ids format", 6)]);
}

fn object_digest(name: &str, kind: &str, wire: &[u8], digests: &Value) -> Option<String> {
    let session_inputs = |b: &ProofBundleV2| SessionContextV2Inputs {
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
    };
    Some(match name {
        "issuer_key_id_v2" => independent_key_id(&decode_delegation_cert_v2(wire).unwrap().issuer_pub_key),
        "subject_key_id_v2" => independent_key_id(&decode_delegation_cert_v2(wire).unwrap().subject_pub_key),
        "delegation_digest_hex" => hex::encode(decode_proof_bundle_v2(wire).unwrap().delegation_digest),
        "bundle_hash_v2" => bundle_hash_v2(&decode_proof_bundle_v2(wire).unwrap()).unwrap(),
        "session_context_hex" => {
            let b = decode_proof_bundle_v2(wire).unwrap();
            let ctx = build_session_context_v2(&session_inputs(&b)).unwrap();
            if b.session_context.as_ref() != Some(&ctx) {
                return Some("bundle session_context does not match the recomputed fixture context".into());
            }
            hex::encode(ctx)
        }
        "challenge_claim_digest_hex" => {
            hex::encode(challenge_claim_digest_v2(&decode_proof_bundle_v2(wire).unwrap().challenge).unwrap())
        }
        "claim_id" => {
            let b = decode_proof_bundle_v2(wire).unwrap();
            let epoch: i64 = s(&digests["claim_replay_epoch"]).parse().unwrap();
            protocol_claim_id_v2(&s(&digests["claim_verifier_namespace"]), epoch, &b.challenge).unwrap()
        }
        "claim_verifier_namespace" | "claim_replay_epoch" | "transaction_context_hex" => return None,
        "receipt_outbox_body_b64" => {
            STANDARD.encode(verification_receipt_v2_body(&decode_verification_receipt_v2(wire).unwrap()).unwrap())
        }
        "status_evidence_digest" => {
            let d = if kind == "revocation_list" {
                status_evidence_digest_list_v2(&decode_revocation_list_v2(wire).unwrap()).unwrap()
            } else {
                status_evidence_digest_push_v2(&decode_revocation_push_v2(wire).unwrap()).unwrap()
            };
            format!("sha384:{}", hex::encode(d))
        }
        "statement_body_digest_hex" => hex::encode(match kind {
            "key_rotation_statement" => {
                key_rotation_statement_v2_digest(&decode_key_rotation_statement_v2(wire).unwrap()).unwrap()
            }
            "witness_entry" => witness_entry_v2_digest(&decode_witness_entry_v2(wire).unwrap()).unwrap(),
            "verification_receipt" => {
                verification_receipt_v2_digest(&decode_verification_receipt_v2(wire).unwrap()).unwrap()
            }
            other => panic!("statement digest for {other}"),
        }),
        other if other.starts_with("party-") => {
            let r = decode_transaction_receipt_v2(wire).unwrap();
            let (party_id, field) = other.split_once('.').unwrap();
            let lp = |b: &[u8]| {
                let mut v = (b.len() as u64).to_be_bytes().to_vec();
                v.extend_from_slice(b);
                v
            };
            let mut txc = Sha256::new();
            sha2::Digest::update(&mut txc, b"ratify/transaction-context/v2");
            sha2::Digest::update(&mut txc, lp(r.transaction_id.as_bytes()));
            sha2::Digest::update(&mut txc, lp(r.terms_schema_uri.as_bytes()));
            sha2::Digest::update(&mut txc, Sha384::digest(&r.terms_canonical_json));
            let tx = txc.finalize().to_vec();
            if hex::encode(&tx) != s(&digests["transaction_context_hex"]) || transaction_context_hash_v2(&r) != tx {
                return Some("transaction context differs".into());
            }
            let p = r.parties.iter().find(|p| p.party_id == party_id).unwrap();
            let req = transaction_party_request_hash_v2(&tx, &p.required_scope);
            match field {
                "transaction_party_request_hash_hex" => hex::encode(req),
                "session_context_hex" => hex::encode(
                    build_session_context_v2(&SessionContextV2Inputs {
                        verifier_id: p.verifier_id.clone(),
                        workspace_id: p.workspace_id.clone(),
                        agent_id: p.agent_id.clone(),
                        session_id: p.session_id.clone(),
                        invocation_id: p.invocation_id.clone(),
                        request_hash: req,
                    })
                    .unwrap(),
                ),
                "proof_bundle_hash" => bundle_hash_v2(p.proof_bundle.as_ref().unwrap()).unwrap(),
                f => panic!("unknown party digest {f}"),
            }
        }
        other => panic!("unknown digest {other}"),
    })
}

#[test]
fn v2_objects() {
    let fx = fixture();
    let f = load("objects.json");
    let mut t = Tally::default();
    let mut codes = BTreeSet::new();
    for o in arr(&f["objects"]) {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        let wire = b64(&o["wire_b64"]);
        let re = reencode(&kind, &wire);
        t.check("re-encode", &name, re.as_ref().is_ok_and(|b| *b == wire), || {
            format!("{re:?}").chars().take(300).collect()
        });
        let v = verify_object(&fx, &kind, &wire, &[], &o["verify"]);
        t.check("verify", &name, v.is_ok(), || format!("{v:?}"));
        for sig in arr(&o["signatures"]) {
            let field = s(&sig["field"]);
            let code = i(&sig["object_type_code"]) as u16;
            codes.insert(code);
            let id = format!("{name}/{field}");
            let signable = b64(&sig["signable_b64"]);
            let ty = V2ObjectType::from_code(code).expect("registered code");
            let m = v2_signing_message(ty, &signable);
            let ctx = String::from_utf8(v2_mldsa_context(ty)).unwrap();
            let signer = s(&sig["signer"]);
            let signer_key = fx.key(&signer);
            let tr = shake256_64(&signer_key.ml_dsa_65);
            let pinned = signature(&sig["signature"]);
            let wire_text = String::from_utf8(wire.clone()).unwrap();
            let verified = verify_v2_statement(ty, &signable, &pinned, &signer_key);
            let ok = projection(&wire, &field) == signable
                && hex::encode(Sha384::digest(&signable)) == s(&sig["signable_sha384_hex"])
                && m == b64(&sig["message_b64"])
                && m.len() == 77
                && ctx == s(&sig["mldsa_context"])
                && ctx.len() == 22
                && fx.key_id(&signer) == s(&sig["signer_key_id_v2"])
                && tr == b64(&sig["mldsa_tr_b64"])
                && external_mu_v2(&signer_key.ml_dsa_65, ctx.as_bytes(), &m) == b64(&sig["mldsa_mu_b64"])
                && wire_text.contains(&STANDARD.encode(&pinned.ed25519))
                && wire_text.contains(&STANDARD.encode(&pinned.ml_dsa_65))
                && verified.is_ok();
            t.check("signatures", &id, ok, || format!("projection, transcript, or verification differs: {verified:?}"));
        }
        if let Some(ds) = o["digests"].as_object() {
            for (dname, want) in ds {
                if let Some(got) = object_digest(dname, &kind, &wire, &o["digests"]) {
                    t.check("digests", &format!("{name}/{dname}"), got == s(want), || {
                        format!("got {got}, want {want}")
                    });
                }
            }
        }
    }
    for code in 1..=9u16 {
        t.check("codes", &format!("code {code}"), codes.contains(&code), || "no signature for code".into());
    }
    t.finish(&[("re-encode", 13), ("verify", 13), ("signatures", 19), ("codes", 9)]);
}

#[test]
fn v2_object_negatives() {
    let fx = fixture();
    let f = load("object-negatives.json");
    let mut t = Tally::default();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for v in arr(&f["vectors"]) {
        let kind = s(&v["kind"]);
        *kinds.entry(kind.clone()).or_default() += 1;
        let bundle = v.get("bundle_b64").map(b64).unwrap_or_default();
        let want = s(&v["expected_error_class"]);
        assert!(V2ErrorClass::parse(&want).is_some(), "corpus class {want} is outside SPEC-v2 §2.7");
        let got = class_of(&verify_object(&fx, &kind, &b64(&v["wire_b64"]), &bundle, &v["verify"]));
        t.check("negatives", &s(&v["name"]), got == want, || {
            format!("class {got}, want {want} ({})", s(&v["mutation"]))
        });
    }
    assert_eq!(kinds.len(), 9, "negative kinds: {kinds:?}");
    t.finish(&[("negatives", 468)]);
}

fn hedged_idempotency(fx: &Fixture, kind: &str, vc: &Value, deterministic: &[u8], hedged: &[u8]) -> Result<(), String> {
    match kind {
        "witness_entry" => {
            let first = decode_witness_entry_v2(deterministic).map_err(|e| e.to_string())?;
            let again = decode_witness_entry_v2(hedged).map_err(|e| e.to_string())?;
            let digest = witness_entry_v2_digest(&first).map_err(|e| e.to_string())?;
            if witness_entry_v2_digest(&again).ok() != Some(digest.clone()) {
                return Err("hedged witness entry has a different body digest".into());
            }
            let mut head = witness_head(&vc["head"]);
            head.sequence = first.sequence;
            head.head_hash = digest.clone();
            head.accepted_digests = BTreeMap::from([(first.sequence, digest)]);
            match verify_witness_entry_v2(&again, &head, &fx.key(&s(&vc["witness_key"]))) {
                Ok(WitnessEntryV2Result::Replay) => Ok(()),
                other => Err(format!("not a replay: {other:?}")),
            }
        }
        "verification_receipt" => {
            let first = decode_verification_receipt_v2(deterministic).map_err(|e| e.to_string())?;
            let again = decode_verification_receipt_v2(hedged).map_err(|e| e.to_string())?;
            let digest = verification_receipt_v2_digest(&first).map_err(|e| e.to_string())?;
            if verification_receipt_v2_digest(&again).ok() != Some(digest.clone()) {
                return Err("hedged receipt has a different body digest".into());
            }
            let mut head = receipt_head(&vc["head"]);
            head.sequence = first.sequence;
            head.head_hash = digest.clone();
            head.accepted_digests = BTreeMap::from([(first.sequence, digest)]);
            match verify_verification_receipt_v2(&again, &fx.key(&s(&vc["verifier_key"])), &head) {
                Ok(WitnessEntryV2Result::Replay) => Ok(()),
                other => Err(format!("not a replay: {other:?}")),
            }
        }
        "key_rotation_statement" => {
            let first = decode_key_rotation_statement_v2(deterministic).map_err(|e| e.to_string())?;
            let again = decode_key_rotation_statement_v2(hedged).map_err(|e| e.to_string())?;
            if key_rotation_statement_v2_digest(&first).ok() != key_rotation_statement_v2_digest(&again).ok() {
                return Err("hedged rotation statement has a different body digest".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[test]
fn v2_hedged_signatures() {
    let fx = fixture();
    let f = load("hedged-signatures.json");
    let mut t = Tally::default();
    let mut kinds = BTreeSet::new();
    for o in arr(&f["objects"]) {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        kinds.insert(kind.clone());
        let deterministic = b64(&o["deterministic_wire_b64"]);
        let fields: Vec<String> = arr(&o["resigned_fields"]).iter().map(s).collect();
        assert!(!fields.is_empty());
        let mut seen = vec![deterministic.clone()];
        for (n, encoded) in arr(&o["hedged_wire_b64"]).iter().enumerate() {
            let wire = b64(encoded);
            let id = format!("{name}#{n}");
            let fresh = !seen.contains(&wire);
            seen.push(wire.clone());
            let re = reencode(&kind, &wire);
            let v = verify_object(&fx, &kind, &wire, &[], &o["verify"]);
            let same_projection = fields.iter().all(|fname| projection(&wire, fname) == projection(&deterministic, fname));
            let idem = hedged_idempotency(&fx, &kind, &o["verify"], &deterministic, &wire);
            t.check("hedged", &id, fresh && re.as_ref().is_ok_and(|b| *b == wire) && v.is_ok() && same_projection && idem.is_ok(), || {
                format!("fresh={fresh} reencode={:?} verify={v:?} projection={same_projection} idempotency={idem:?}", re.is_ok())
            });
        }
    }
    assert_eq!(kinds.len(), 8, "hedged kinds: {kinds:?}");
    t.finish(&[("hedged", 20)]);
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
            let digits = c.get("item_index_digits").and_then(Value::as_u64).unwrap_or(0) as usize;
            let prefix = c.get("item_prefix").and_then(Value::as_str).unwrap_or("");
            let suffix = c.get("item_suffix").and_then(Value::as_str).unwrap_or("");
            for n in 0..i(&c["count"]) {
                if n > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(format!("{prefix}{n:0digits$}{suffix}").as_bytes());
            }
            out.extend(opt_b64("suffix_b64"));
            out
        }
        "repeat_item" => {
            let mut out = opt_b64("prefix_b64");
            let item = b64(&c["item_b64"]);
            for n in 0..i(&c["count"]) {
                if n > 0 {
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

fn decode_limit(kind: &str, data: &[u8]) -> V2Result<()> {
    match kind {
        "delegation_certificate" => decode_delegation_cert_v2(data).map(|_| ()),
        "proof_bundle" => decode_proof_bundle_v2(data).map(|_| ()),
        "key_rotation_statement" => decode_key_rotation_statement_v2(data).map(|_| ()),
        "revocation_list" => decode_revocation_list_v2(data).map(|_| ()),
        "revocation_push" => decode_revocation_push_v2(data).map(|_| ()),
        "witness_entry" => decode_witness_entry_v2(data).map(|_| ()),
        "verification_receipt" => decode_verification_receipt_v2(data).map(|_| ()),
        "verification_receipt_body" => decode_verification_receipt_body_v2(data).map(|_| ()),
        "transaction_receipt" => decode_transaction_receipt_v2(data).map(|_| ()),
        "status_evidence_batch" => decode_v2_status_evidence_batch(data).map(|_| ()),
        other => panic!("no decoder for {other}"),
    }
}

#[test]
fn v2_limits() {
    let f = load("limits.json");
    let mut t = Tally::default();
    for v in arr(&f["vectors"]) {
        let name = s(&v["name"]);
        let limit = s(&v["limit"]);
        assert_eq!(f["limits"][&limit], v["limit_value"], "{name}: limit table");
        let data = build_limit_bytes(&v["construction"]);
        assert_eq!(data.len() as i64, i(&v["length"]), "{name}: length");
        assert_eq!(hex::encode(Sha256::digest(&data)), s(&v["sha256_hex"]), "{name}: digest");
        let result = decode_limit(&s(&v["kind"]), &data);
        let expectation_ok = match s(&v["expected"]).as_str() {
            "accept" => result.is_ok(),
            "reject" => class_of(&result) == s(&v["expected_error_class"]),
            other => panic!("unknown expectation {other}"),
        };
        let gate_failed = result.as_ref().err().is_some_and(|e| {
            e.message.contains(&format!("exceeds {limit} (")) && e.message.contains("rejected before parsing")
        });
        let gate_ok = (s(&v["size_gate"]) == "fail") == gate_failed;
        t.check("limits", &name, expectation_ok && gate_ok, || format!("{result:?}"));
    }
    t.finish(&[("limits", 76)]);
}
