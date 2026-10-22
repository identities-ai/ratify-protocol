//! Protocol v2 log and rotation corpus: log-sequences.json,
//! rotation-sequences.json, key-rotation-signature.json, and
//! delegation-signature.json.

mod v2_common;

use std::collections::BTreeMap;

use ratify_protocol::hybrid_keypair_from_seeds;
use ratify_protocol::v2::*;
use ratify_protocol::HybridSignature;
use serde_json::Value;
use v2_common::*;

fn total_steps(f: &Value) -> usize {
    arr(&f["scenarios"]).iter().map(|sc| arr(&sc["steps"]).len()).sum()
}

#[test]
fn v2_log_sequences() {
    let fx = fixture();
    let f = load("log-sequences.json");
    let scenarios = f["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 2, "want witness and receipt log scenarios");
    let mut t = Tally::default();
    for sc in scenarios {
        let kind = s(&sc["kind"]);
        let genesis = |log_id: String| WitnessV2Head {
            log_id,
            sequence: 0,
            head_hash: vec![0; 48],
            accepted_digests: BTreeMap::new(),
            frozen: false,
        };
        let mut head = genesis(s(&sc["initial_log_id"]));
        for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            if step["op"] == "recover" {
                head = genesis(s(&step["log_id"]));
                continue;
            }
            assert_eq!(step["op"], "verify", "unknown log op");
            let wire = b64(&step["wire_b64"]);
            let key = fx.key(&s(&step["key"]));
            let (result, digest, seq) = if kind == "witness_entry" {
                match decode_witness_entry_v2(&wire) {
                    Ok(e) => (
                        verify_witness_entry_v2(&e, &head, &key),
                        witness_entry_v2_digest(&e).ok(),
                        e.sequence,
                    ),
                    Err(e) => (Err(e), None, 0),
                }
            } else {
                match decode_verification_receipt_v2(&wire) {
                    Ok(r) => {
                        let rh = ReceiptV2Head {
                            log_id: head.log_id.clone(),
                            verifier_id: s(&sc["verifier_id"]),
                            sequence: head.sequence,
                            head_hash: head.head_hash.clone(),
                            accepted_digests: head.accepted_digests.clone(),
                            frozen: head.frozen,
                        };
                        (
                            verify_verification_receipt_v2(&r, &key, &rh),
                            verification_receipt_v2_digest(&r).ok(),
                            r.sequence,
                        )
                    }
                    Err(e) => (Err(e), None, 0),
                }
            };
            let got = match &result {
                Ok(WitnessEntryV2Result::Appended) => "appended".to_string(),
                Ok(WitnessEntryV2Result::Replay) => "replay".to_string(),
                Err(e) => e.class.as_str().to_string(),
            };
            let want = s(&step["expect"]);
            t.check(
                &format!("log-sequences.json {kind}"),
                &format!("step {n} {}", s(&step["label"])),
                got == want,
                || format!("got {got}, want {want}"),
            );
            match got.as_str() {
                "appended" => {
                    let d = digest.unwrap();
                    head.sequence = seq;
                    head.head_hash = d.clone();
                    head.accepted_digests.insert(seq, d);
                }
                "log_fork" => head.frozen = true,
                _ => {}
            }
        }
    }
    let rows: Vec<(String, usize)> = arr(&f["scenarios"])
        .iter()
        .map(|sc| (format!("log-sequences.json {}", s(&sc["kind"])), arr(&sc["steps"]).iter().filter(|st| st["op"] != "recover").count()))
        .collect();
    let rows: Vec<(&str, usize)> = rows.iter().map(|(r, n)| (r.as_str(), *n)).collect();
    t.finish(&rows);
}

// ---------------------------------------------------------------------------
// Rotation sequences

#[test]
fn v2_rotation_sequences() {
    let fx = fixture();
    let f = load("rotation-sequences.json");
    let mut t = Tally::default();
    for sc in f["scenarios"].as_array().unwrap() {
        let mut journal = new_key_rotation_v2_journal(
            &s(&sc["authority_id"]),
            i(&sc["recovery_epoch"]),
            &s(&sc["role"]),
            &fx.key(&s(&sc["genesis_key"])),
        )
        .unwrap();
        let row = format!("rotation-sequences.json {}", s(&sc["name"]));
        for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let got = if step["op"] == "recover" {
                match recover_key_rotation_v2(
                    &journal,
                    i(&step["new_recovery_epoch"]),
                    &fx.key(&s(&step["new_genesis_key"])),
                ) {
                    Ok(next) => {
                        journal = next;
                        "recovered".to_string()
                    }
                    Err(e) => e.class.as_str().to_string(),
                }
            } else {
                assert_eq!(step["op"], "accept", "unknown rotation op");
                let stmt = decode_key_rotation_statement_v2(&b64(&step["wire_b64"]))
                    .expect("rotation step decodes");
                let (next, result) = accept_key_rotation_statement_v2(
                    &stmt,
                    &journal,
                    i(&step["now"]),
                    i(&sc["future_skew_seconds"]),
                );
                journal = next;
                match result {
                    Ok(WitnessEntryV2Result::Appended) => "appended".into(),
                    Ok(WitnessEntryV2Result::Replay) => "replay".into(),
                    Err(e) => e.class.as_str().into(),
                }
            };
            let want = s(&step["expect"]);
            let state_ok = journal.state.sequence == i(&step["expect_sequence"])
                && journal.state.current_key.ml_dsa_65
                    == fx.key(&s(&step["expect_current_key"])).ml_dsa_65
                && journal.state.recovery_epoch == i(&step["expect_recovery_epoch"])
                && journal.frozen == step["expect_frozen"].as_bool().unwrap();
            t.check(
                &row,
                &format!("step {n} {}", s(&step["label"])),
                got == want && state_ok,
                || {
                    format!(
                        "got {got} (want {want}); state seq={} epoch={} frozen={}",
                        journal.state.sequence, journal.state.recovery_epoch, journal.frozen
                    )
                },
            );
        }
    }
    let ran: usize = arr(&f["scenarios"])
        .iter()
        .map(|sc| t.total(&format!("rotation-sequences.json {}", s(&sc["name"]))))
        .sum();
    assert_eq!(ran, total_steps(&f), "every rotation step must run");
    t.finish(&[]);
}

// ---------------------------------------------------------------------------
// Hand-maintained primitive vectors

#[test]
fn v2_key_rotation_signature_vector() {
    let v = load("key-rotation-signature.json");
    let mut t = Tally::default();
    let mut cases = vec![v.clone()];
    if v["continuation"].is_object() {
        cases.push(v["continuation"].clone());
    }
    for (n, c) in cases.iter().enumerate() {
        let row = "key-rotation-signature.json";
        let seed = |x: &Value| seed32(&s(x));
        let (old_pub, old_priv) = hybrid_keypair_from_seeds(
            &seed(&c["old_key_seeds"]["ed25519"]),
            &seed(&c["old_key_seeds"]["ml_dsa_65"]),
        );
        let (new_pub, new_priv) = hybrid_keypair_from_seeds(
            &seed(&c["new_key_seeds"]["ed25519"]),
            &seed(&c["new_key_seeds"]["ml_dsa_65"]),
        );
        t.check(
            row,
            &format!("case {n} keys"),
            old_pub == pub_key(&c["old_key"]) && new_pub == pub_key(&c["new_key"]),
            || "seed-derived keys differ".into(),
        );
        let stmt = KeyRotationStatementV2 {
            version: i(&c["version"]),
            authority_id: s(&c["authority_id"]),
            recovery_epoch: i(&c["recovery_epoch"]),
            role: s(&c["role"]),
            sequence: i(&c["sequence"]),
            previous_statement_hash: b64(&c["previous_statement_hash"]),
            old_key: old_pub.clone(),
            new_key: new_pub.clone(),
            old_key_id: s(&c["old_key_id"]),
            new_key_id: s(&c["new_key_id"]),
            issued_at: i(&c["issued_at"]),
            not_before: i(&c["not_before"]),
            old_signature: signature(&c["old_signature"]),
            new_signature: signature(&c["new_signature"]),
        };
        let signable = key_rotation_statement_v2_signable_bytes(&stmt).unwrap();
        t.check(
            row,
            &format!("case {n} signable"),
            signable == b64(&c["signable_bytes"]),
            || "signable differs".into(),
        );
        let digest = key_rotation_statement_v2_digest(&stmt).unwrap();
        t.check(
            row,
            &format!("case {n} digest"),
            hex::encode(&digest) == s(&c["statement_body_digest"]),
            || "digest differs".into(),
        );
        t.check(
            row,
            &format!("case {n} contexts"),
            v2_mldsa_context(V2ObjectType::KeyRotationAuthorization)
                == s(&c["old_mldsa_context"]).as_bytes()
                && v2_mldsa_context(V2ObjectType::KeyRotationProofOfPossession)
                    == s(&c["new_mldsa_context"]).as_bytes(),
            || "contexts differ".into(),
        );
        let ok = verify_v2_statement(
            V2ObjectType::KeyRotationAuthorization,
            &signable,
            &stmt.old_signature,
            &old_pub,
        )
        .is_ok()
            && verify_v2_statement(
                V2ObjectType::KeyRotationProofOfPossession,
                &signable,
                &stmt.new_signature,
                &new_pub,
            )
            .is_ok();
        t.check(row, &format!("case {n} signatures"), ok, || {
            "pinned signatures do not verify".into()
        });
        let wire = encode_key_rotation_statement_v2(&stmt).unwrap();
        t.check(
            row,
            &format!("case {n} wire"),
            wire == b64(&c["wire"]),
            || "wire differs".into(),
        );
        let decoded = decode_key_rotation_statement_v2(&wire);
        t.check(row, &format!("case {n} decode"), decoded.is_ok(), || {
            format!("{decoded:?}")
        });
        // Fresh signatures under our signer verify too (hedged ML-DSA).
        let resigned = sign_key_rotation_statement_v2(&stmt, &old_priv, &new_priv).unwrap();
        let ok = verify_v2_statement(
            V2ObjectType::KeyRotationAuthorization,
            &signable,
            &resigned.old_signature,
            &old_pub,
        )
        .is_ok()
            && verify_v2_statement(
                V2ObjectType::KeyRotationProofOfPossession,
                &signable,
                &resigned.new_signature,
                &new_pub,
            )
            .is_ok();
        t.check(row, &format!("case {n} resign"), ok, || {
            "re-signed statement does not verify".into()
        });
    }
    t.finish(&[("key-rotation-signature.json", 16)]);
}

#[test]
fn v2_delegation_signature_vector() {
    // Detailed byte checks live in tests/v2_crypto.rs; this pins the vector
    // through the v2 object-level API as well.
    let v = load("delegation-signature.json");
    let signable = b64(&v["signable_bytes"]);
    let message = v2_signing_message(V2ObjectType::DelegationCertificate, &signable);
    assert_eq!(message, b64(&v["message"]));
    assert_eq!(
        v2_mldsa_context(V2ObjectType::DelegationCertificate),
        b64(&v["mldsa_context"])
    );
    let key = pub_key(&v["issuer_public_key"]);
    let sig: HybridSignature = signature(&v["signature"]);
    verify_v2_statement(V2ObjectType::DelegationCertificate, &signable, &sig, &key)
        .expect("pinned signature verifies");
    assert_eq!(
        class_of(&verify_v2_statement(
            V2ObjectType::ChallengePresentation,
            &signable,
            &sig,
            &key
        )),
        "invalid_signature"
    );
    assert_eq!(
        class_of(&verify_v2_statement_code(0x000a, &signable, &sig, &key)),
        "unsupported_object_type"
    );
}

