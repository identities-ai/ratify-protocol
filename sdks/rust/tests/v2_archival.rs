//! Archival verification (SPEC-v2 §6.10), porting Go archival_v2_test.go.

mod v2_verify_common;

use ratify_protocol::v2::*;
use ratify_protocol::{generate_hybrid_keypair, HybridSignature};
use v2_verify_common::{arr, load_v2_vector, s, unb64};

fn corpus_bundle(name: &str) -> Vec<u8> {
    let f = load_v2_vector("verifier-ordering.json");
    let v = arr(&f["vectors"]).into_iter().find(|v| s(&v["name"]) == name).expect("vector");
    unb64(&f["bundles_b64"][s(&v["bundle"])])
}

fn empty_sig() -> HybridSignature {
    HybridSignature {
        ed25519: Vec::new(),
        ml_dsa_65: Vec::new(),
    }
}

#[test]
fn archival_results_are_labelled_and_non_actionable() {
    let wire = corpus_bundle("allow_bound_context");
    let bundle = decode_proof_bundle_v2(&wire).expect("bundle");
    let got = verify_archival_proof_bundle_v2(&wire);
    assert_eq!(FRESHNESS_UNVERIFIED_V2, "freshness_unverified");
    assert_eq!(got.assessment, FRESHNESS_UNVERIFIED_V2);
    assert!(!got.actionable);
    assert_eq!(got.error_class, None, "{}", got.error_message);
    assert_eq!(got.bundle_hash, bundle_hash_v2(&bundle).unwrap());
    assert_eq!(got.agent_id, bundle.agent_id);
    let mut issuers: Vec<String> = bundle.delegations.iter().map(|c| c.issuer_id.clone()).collect();
    issuers.sort();
    issuers.dedup();
    assert_eq!(got.issuer_ids, issuers);

    let text = String::from_utf8(wire.clone()).unwrap();
    let tampered = text.replacen("\"challenge_at\":", "\"challenge_at\":1", 1);
    let got = verify_archival_proof_bundle_v2(tampered.as_bytes());
    assert_eq!(got.error_class, Some(V2ErrorClass::InvalidSignature));
    assert!(!got.actionable && got.assessment == FRESHNESS_UNVERIFIED_V2);
    assert_eq!(verify_archival_proof_bundle_v2(b"{").error_class, Some(V2ErrorClass::Malformed));

    let cert_wire = encode_delegation_cert_v2(&bundle.delegations[0]).unwrap();
    let cert = verify_archival_delegation_cert_v2(&cert_wire).expect("certificate");
    assert!(!cert.actionable && cert.freshness == FRESHNESS_UNVERIFIED_V2 && cert.digest.is_empty());
    assert_eq!(cert.object_type, 0x0001);
    assert_eq!(cert.signer_key_ids, vec![bundle.delegations[0].issuer_id.clone()]);
}

#[test]
fn archival_status_and_log_objects_use_caller_keys() {
    let (status_pub, status_priv) = generate_hybrid_keypair();
    let (other_pub, _) = generate_hybrid_keypair();
    let issuer = "b".repeat(64);
    let list = RevocationListV2 {
        version: 2,
        issuer_id: issuer.clone(),
        updated_at: 1,
        next_update: 10,
        sequence: 1,
        revoked: Vec::new(),
        signature: empty_sig(),
    };
    let signed = sign_revocation_list_v2(&list, &issuer, &status_pub, &status_priv).expect("sign list");
    let wire = encode_revocation_list_v2(&signed).unwrap();
    let got = verify_archival_revocation_list_v2(&wire, &issuer, &status_pub).expect("archival list");
    assert!(!got.actionable && got.freshness == FRESHNESS_UNVERIFIED_V2);
    assert_eq!(got.signer_key_ids, vec![key_id_v2(&status_pub).unwrap()]);
    assert_eq!(got.digest, format!("sha384:{}", hex::encode(status_evidence_digest_list_v2(&signed).unwrap())));
    let e = verify_archival_revocation_list_v2(&wire, &issuer, &other_pub).expect_err("other key");
    assert_eq!(e.class, V2ErrorClass::InvalidSignature);
    let e = verify_archival_revocation_list_v2(&wire, &"c".repeat(64), &status_pub).expect_err("other issuer");
    assert_eq!(e.class, V2ErrorClass::StatusKeyBindingMismatch);

    let (witness_pub, witness_priv) = generate_hybrid_keypair();
    let entry = WitnessEntryV2 {
        version: 2,
        log_id: "a".repeat(32),
        sequence: 7,
        prev_hash: vec![1; 48],
        entry_data: b"x".to_vec(),
        timestamp: 1,
        witness_id: key_id_v2(&witness_pub).unwrap(),
        signature: empty_sig(),
    };
    let signed = sign_witness_entry_v2(&entry, &witness_priv).expect("sign witness");
    let entry_wire = encode_witness_entry_v2(&signed).unwrap();
    let got = verify_archival_witness_entry_v2(&entry_wire, &witness_pub).expect("archival witness");
    let digest = witness_entry_v2_digest(&signed).unwrap();
    assert!(!got.actionable && got.digest.ends_with(&hex::encode(digest)));
    let e = verify_archival_witness_entry_v2(&entry_wire, &other_pub).expect_err("other key");
    assert_eq!(e.class, V2ErrorClass::KeyIdMismatch);
}

/// Go TestArchivalProofBundleResultV2JSON: the language-neutral members
/// with a null error_class on success.
#[test]
fn archival_proof_bundle_result_json() {
    let ok = ArchivalProofBundleResultV2 {
        assessment: FRESHNESS_UNVERIFIED_V2.into(),
        actionable: false,
        bundle_hash: "sha384:x".into(),
        agent_id: "a".into(),
        issuer_ids: vec!["i".into()],
        error_class: None,
        error_message: "ignored".into(),
    };
    assert_eq!(
        String::from_utf8(ok.to_json().unwrap()).unwrap(),
        r#"{"actionable":false,"agent_id":"a","assessment":"freshness_unverified","bundle_hash":"sha384:x","error_class":null,"issuer_ids":["i"]}"#
    );
    let failed = ArchivalProofBundleResultV2 {
        issuer_ids: Vec::new(),
        error_class: Some(V2ErrorClass::InvalidSignature),
        ..ok
    };
    let text = String::from_utf8(failed.to_json().unwrap()).unwrap();
    assert!(text.contains(r#""error_class":"invalid_signature""#) && text.contains(r#""issuer_ids":[]"#), "{text}");
}
