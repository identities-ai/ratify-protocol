//! Protocol v2 signing round trips. The shared corpus pins verification of
//! fixed bytes; these tests check that every Rust signer produces objects
//! the Rust verifier accepts and that tampering is rejected with the right class.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::*;
use ratify_protocol::{
    hybrid_keypair_from_seeds, Constraint, HybridPrivateKey, HybridPublicKey, HybridSignature,
};
use serde_json::Value;

fn keys() -> BTreeMap<String, (HybridPublicKey, HybridPrivateKey)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/keys.json");
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let ed: [u8; 32] = hex::decode(k["ed25519_seed_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let ml: [u8; 32] = hex::decode(k["ml_dsa_65_seed_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            (
                k["name"].as_str().unwrap().to_string(),
                hybrid_keypair_from_seeds(&ed, &ml),
            )
        })
        .collect()
}

fn empty_sig() -> HybridSignature {
    HybridSignature {
        ed25519: vec![],
        ml_dsa_65: vec![],
    }
}

fn cert(
    issuer: &HybridPublicKey,
    subject: &HybridPublicKey,
    id: &str,
    scope: &[&str],
    constraints: Vec<Constraint>,
) -> DelegationCertV2 {
    DelegationCertV2 {
        version: 2,
        cert_id: id.into(),
        issuer_id: key_id_v2(issuer).unwrap(),
        issuer_pub_key: issuer.clone(),
        subject_id: key_id_v2(subject).unwrap(),
        subject_pub_key: subject.clone(),
        scope: scope.iter().map(|s| s.to_string()).collect(),
        constraints,
        issued_at: 1_799_990_000,
        expires_at: 1_800_090_000,
        signature: empty_sig(),
    }
}

#[test]
fn delegation_and_bundle_sign_verify_and_reject_tampering() {
    let k = keys();
    let (root, root_sk) = &k["root"];
    let (inter, inter_sk) = &k["intermediate"];
    let (agent, agent_sk) = &k["agent"];
    let rate = Constraint {
        kind: "max_rate".into(),
        count: 5,
        window_s: 60,
        ..Default::default()
    };
    let root_cert = sign_delegation_cert_v2(
        &cert(
            root,
            inter,
            "c-root",
            &["identity:delegate", "data:read"],
            vec![],
        ),
        root_sk,
    )
    .unwrap();
    let leaf = sign_delegation_cert_v2(
        &cert(inter, agent, "c-leaf", &["data:read"], vec![rate]),
        inter_sk,
    )
    .unwrap();
    verify_delegation_cert_v2_signature(&leaf).unwrap();
    let wire = encode_delegation_cert_v2(&leaf).unwrap();
    assert_eq!(
        encode_delegation_cert_v2(&decode_delegation_cert_v2(&wire).unwrap()).unwrap(),
        wire
    );

    // A wrong issuer key is refused at signing time.
    assert!(
        sign_delegation_cert_v2(&cert(inter, agent, "c-x", &["data:read"], vec![]), root_sk)
            .is_err()
    );

    let bundle = ProofBundleV2 {
        version: 2,
        verifier_id: key_id_v2(&k["verifier"].0).unwrap(),
        agent_id: key_id_v2(agent).unwrap(),
        agent_pub_key: agent.clone(),
        delegations: vec![leaf.clone(), root_cert],
        delegation_digest: vec![],
        challenge: vec![9; 32],
        challenge_at: 1_800_000_000,
        challenge_sig: empty_sig(),
        session_context: Some(vec![3; 32]),
        stream_id: None,
        stream_seq: None,
    };
    let signed = sign_proof_bundle_v2(&bundle, agent_sk).unwrap();
    verify_proof_bundle_v2_signatures(&signed).unwrap();
    let wire = encode_proof_bundle_v2(&signed).unwrap();
    assert_eq!(
        encode_proof_bundle_v2(&decode_proof_bundle_v2(&wire).unwrap()).unwrap(),
        wire
    );
    assert!(bundle_hash_v2(&signed).unwrap().starts_with("sha384:"));

    let mut tampered = signed.clone();
    tampered.challenge_at += 1;
    assert_eq!(
        verify_proof_bundle_v2_signatures(&tampered)
            .unwrap_err()
            .class,
        V2ErrorClass::InvalidSignature
    );
    let mut swapped = signed.clone();
    swapped.delegations.reverse();
    swapped.delegation_digest = delegation_digest_v2(&swapped.delegations).unwrap();
    assert_eq!(
        verify_proof_bundle_v2_signatures(&swapped)
            .unwrap_err()
            .class,
        V2ErrorClass::ChainLinkageMismatch
    );
    let mut digest = signed.clone();
    digest.delegation_digest[0] ^= 1;
    assert_eq!(
        verify_proof_bundle_v2_signatures(&digest)
            .unwrap_err()
            .class,
        V2ErrorClass::DelegationDigestMismatch
    );
}

#[test]
fn revocation_status_objects_sign_and_bind_to_the_status_key() {
    let k = keys();
    let issuer = key_id_v2(&k["root"].0).unwrap();
    let (status, status_sk) = &k["status_root"];
    let list = RevocationListV2 {
        version: 2,
        issuer_id: issuer.clone(),
        updated_at: 1_800_000_000,
        next_update: 1_800_003_600,
        sequence: 1,
        revoked: vec![RevokedCertV2 {
            cert_id: "c1".into(),
        }],
        signature: empty_sig(),
    };
    let signed = sign_revocation_list_v2(&list, &issuer, status, status_sk).unwrap();
    verify_revocation_list_v2_signature(&signed, &issuer, status).unwrap();
    assert!(
        sign_revocation_list_v2(&list, &issuer, &k["status_intermediate"].0, status_sk).is_err()
    );
    assert_eq!(
        verify_revocation_list_v2_signature(
            &signed,
            &key_id_v2(&k["intermediate"].0).unwrap(),
            status
        )
        .unwrap_err()
        .class,
        V2ErrorClass::StatusKeyBindingMismatch
    );
    let push = RevocationPushV2 {
        version: 2,
        issuer_id: issuer.clone(),
        sequence: 2,
        pushed_at: 1_800_000_010,
        revoked: vec![RevokedCertV2 {
            cert_id: "c2".into(),
        }],
        signature: empty_sig(),
    };
    let signed_push = sign_revocation_push_v2(&push, &issuer, status, status_sk).unwrap();
    let policy = RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: 3600,
        max_status_age_seconds: 600,
        clock_skew_seconds: 5,
    };
    let state = apply_revocation_list_v2(
        &RevocationStatusStateV2::default(),
        &signed,
        &issuer,
        1,
        status,
        &policy,
        1_800_000_020,
    )
    .unwrap();
    let state = apply_revocation_push_v2(
        &state,
        &signed_push,
        &issuer,
        1,
        status,
        &policy,
        1_800_000_020,
    )
    .unwrap();
    assert_eq!(state.floor, 2);
    let r = revocation_status_for_cert_v2(&state, &issuer, "c2", 1, status, &policy, 1_800_000_020)
        .unwrap();
    assert_eq!(r.status, "revoked");
    let r = revocation_status_for_cert_v2(&state, &issuer, "c9", 1, status, &policy, 1_800_000_020)
        .unwrap();
    assert_eq!((r.status.as_str(), r.evidence.len()), ("not_revoked", 2));
}

#[test]
fn witness_rotation_and_prepared_receipt_round_trips() {
    let k = keys();
    let (witness, witness_sk) = &k["witness"];
    let entry = WitnessEntryV2 {
        version: 2,
        log_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1".into(),
        sequence: 1,
        prev_hash: vec![0; 48],
        entry_data: b"entry".to_vec(),
        timestamp: 1_800_000_000,
        witness_id: key_id_v2(witness).unwrap(),
        signature: empty_sig(),
    };
    let signed = sign_witness_entry_v2(&entry, witness_sk).unwrap();
    let head = WitnessV2Head {
        log_id: entry.log_id.clone(),
        head_hash: vec![0; 48],
        ..Default::default()
    };
    assert_eq!(
        verify_witness_entry_v2(&signed, &head, witness).unwrap(),
        WitnessEntryV2Result::Appended
    );
    let wire = encode_witness_entry_v2(&signed).unwrap();
    decode_witness_entry_v2(&wire).unwrap();

    let (g, g_sk) = &k["rotation_genesis"];
    let (n, n_sk) = &k["rotation_second"];
    let journal =
        new_key_rotation_v2_journal("0123456789abcdef0123456789abcdef", 1, "issuer", g).unwrap();
    let stmt = KeyRotationStatementV2 {
        version: 2,
        authority_id: "0123456789abcdef0123456789abcdef".into(),
        recovery_epoch: 1,
        role: "issuer".into(),
        sequence: 1,
        previous_statement_hash: vec![0; 48],
        old_key: g.clone(),
        new_key: n.clone(),
        old_key_id: key_id_v2(g).unwrap(),
        new_key_id: key_id_v2(n).unwrap(),
        issued_at: 1_800_000_000,
        not_before: 1_800_000_000,
        old_signature: empty_sig(),
        new_signature: empty_sig(),
    };
    let signed = sign_key_rotation_statement_v2(&stmt, g_sk, n_sk).unwrap();
    let (next, result) = accept_key_rotation_statement_v2(&signed, &journal, 1_800_000_000, 5);
    assert_eq!(result.unwrap(), WitnessEntryV2Result::Appended);
    assert_eq!(next.state.current_key, *n);
    // A different validly signed body at the accepted sequence freezes the journal.
    let mut fork = stmt.clone();
    fork.issued_at += 1;
    let fork = sign_key_rotation_statement_v2(&fork, g_sk, n_sk).unwrap();
    let (frozen, result) = accept_key_rotation_statement_v2(&fork, &next, 1_800_000_000, 5);
    assert_eq!(result.unwrap_err().class, V2ErrorClass::RotationFork);
    assert!(frozen.frozen);

    // Prepared verification receipt body from the shared positive object.
    let objects: Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/objects.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let wire = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == "verification_receipt")
        .map(|o| STANDARD.decode(o["wire_b64"].as_str().unwrap()).unwrap())
        .unwrap();
    let receipt = decode_verification_receipt_v2(&wire).unwrap();
    let body = verification_receipt_v2_body(&receipt).unwrap();
    assert_eq!(
        decode_verification_receipt_body_v2(&body).unwrap().decision,
        receipt.decision
    );
    let (verifier, verifier_sk) = &k["verifier"];
    let head = ReceiptV2Head {
        log_id: "cccccccccccccccccccccccccccccc02".into(),
        verifier_id: key_id_v2(verifier).unwrap(),
        head_hash: vec![0; 48],
        ..Default::default()
    };
    let signed = sign_prepared_verification_receipt_v2(&body, &head, verifier_sk).unwrap();
    assert_eq!(
        verify_verification_receipt_v2(&signed, verifier, &head).unwrap(),
        WitnessEntryV2Result::Appended
    );
    let wrong_head = ReceiptV2Head {
        verifier_id: key_id_v2(&k["attacker"].0).unwrap(),
        ..head.clone()
    };
    assert!(sign_prepared_verification_receipt_v2(&body, &wrong_head, verifier_sk).is_err());
}

#[test]
fn transaction_party_signatures_round_trip() {
    let k = keys();
    let objects: Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/objects.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let wire = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == "transaction_receipt")
        .map(|o| STANDARD.decode(o["wire_b64"].as_str().unwrap()).unwrap())
        .unwrap();
    let mut receipt = decode_transaction_receipt_v2(&wire).unwrap();
    let mut fresh = Vec::new();
    for p in &receipt.parties {
        let sk = &k
            .values()
            .find(|(public, _)| *public == p.agent_pub_key)
            .expect("party key in fixture")
            .1;
        fresh.push(sign_transaction_receipt_party_v2(&receipt, &p.party_id, sk).unwrap());
    }
    receipt.party_signatures = fresh;
    verify_transaction_receipt_v2_signatures(&receipt).unwrap();
    let encoded = encode_transaction_receipt_v2(&receipt).unwrap();
    decode_transaction_receipt_v2(&encoded).unwrap();
    receipt.party_signatures.pop();
    assert_eq!(
        verify_transaction_receipt_v2_signatures(&receipt)
            .unwrap_err()
            .class,
        V2ErrorClass::TransactionSignatureSetInvalid
    );
}

#[test]
fn negative_float_coordinates_decode_while_negative_zero_is_malformed() {
    let k = keys();
    let (root, root_sk) = &k["root"];
    let circle = Constraint {
        kind: "geo_circle".into(),
        lat: -0.5,
        lon: -122.25,
        radius_m: 100.0,
        ..Default::default()
    };
    let signed = sign_delegation_cert_v2(
        &cert(root, &k["agent"].0, "c-geo", &["data:read"], vec![circle]),
        root_sk,
    )
    .unwrap();
    let wire = encode_delegation_cert_v2(&signed).unwrap();
    assert!(String::from_utf8_lossy(&wire).contains("\"lat\":-0.5"));
    let decoded = decode_delegation_cert_v2(&wire).unwrap();
    assert_eq!(decoded.constraints[0].lat, -0.5);
    verify_delegation_cert_v2_signature(&decoded).unwrap();
    assert_eq!(
        canonical_json_v2(br#"{"a":-0.5}"#).unwrap(),
        br#"{"a":-0.5}"#.to_vec()
    );
    for bad in ["-0", "-0.0", "-0e5", "-0E0"] {
        let mutated = String::from_utf8(wire.clone())
            .unwrap()
            .replace("\"lat\":-0.5", &format!("\"lat\":{bad}"));
        assert_eq!(
            decode_delegation_cert_v2(mutated.as_bytes())
                .unwrap_err()
                .class,
            V2ErrorClass::Malformed,
            "{bad}"
        );
    }
}
