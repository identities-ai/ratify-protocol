use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use ratify_protocol::{
    delegation_signature_message_v2, derive_key_id_v2, hybrid_keypair_from_seeds,
    verify_delegation_v2, HybridPrivateKey, HybridPublicKey, HybridSignature,
};
use serde_json::Value;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn vector() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/v2/delegation-signature.json");
    serde_json::from_slice(&fs::read(path).expect("read shared v2 signature vector"))
        .expect("parse shared v2 signature vector")
}

fn decode(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("base64 string"))
        .unwrap()
}

fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut result = [0; 64];
    hasher.finalize_xof().read(&mut result);
    result
}

#[test]
fn v2_external_mu_matches_shared_signature_vector() {
    let v = vector();
    let pk = decode(&v["issuer_public_key"]["ml_dsa_65"]);
    let context = decode(&v["mldsa_context"]);
    let message = decode(&v["message"]);
    assert_eq!((pk.len(), context.len(), message.len()), (1952, 22, 77));
    let tr = shake256_64(&pk);
    assert_eq!(tr.as_slice(), decode(&v["mldsa_tr"]));
    let mut mu_input = Vec::with_capacity(64 + 2 + context.len() + message.len());
    mu_input.extend_from_slice(&tr);
    mu_input.extend_from_slice(&[0, context.len() as u8]);
    mu_input.extend_from_slice(&context);
    mu_input.extend_from_slice(&message);
    assert_eq!(shake256_64(&mu_input).as_slice(), decode(&v["mldsa_mu"]));
}

fn fixture_keys(v: &Value) -> (HybridPublicKey, HybridPrivateKey) {
    let seeds = &v["issuer_seeds"];
    let ed: [u8; 32] = decode(&seeds["ed25519"]).try_into().unwrap();
    let ml: [u8; 32] = decode(&seeds["ml_dsa_65"]).try_into().unwrap();
    hybrid_keypair_from_seeds(&ed, &ml)
}

fn fixture_public(v: &Value) -> HybridPublicKey {
    HybridPublicKey {
        ed25519: decode(&v["issuer_public_key"]["ed25519"]),
        ml_dsa_65: decode(&v["issuer_public_key"]["ml_dsa_65"]),
    }
}

fn fixture_signature(v: &Value) -> HybridSignature {
    HybridSignature {
        ed25519: decode(&v["signature"]["ed25519"]),
        ml_dsa_65: decode(&v["signature"]["ml_dsa_65"]),
    }
}

#[test]
fn v2_signing_matches_shared_message_key_id_and_signature_vector() {
    let v = vector();
    assert_eq!(v["object_type_code"].as_u64().unwrap(), 1);
    let message = delegation_signature_message_v2(&decode(&v["signable_bytes"]));
    assert_eq!(STANDARD.encode(&message), v["message"].as_str().unwrap());

    let public = fixture_public(&v);
    assert_eq!(
        derive_key_id_v2(&public).unwrap(),
        v["key_id_v2"].as_str().unwrap()
    );
    let (derived_public, private) = fixture_keys(&v);
    assert_eq!(derived_public.ed25519, public.ed25519);
    assert_eq!(derived_public.ml_dsa_65, public.ml_dsa_65);

    let signature = fixture_signature(&v);
    verify_delegation_v2(&decode(&v["signable_bytes"]), &signature, &public)
        .expect("shared cross-language signature vector verifies");
    // Typed signing of the delegation transcript is covered by the object
    // vectors; no exported function signs caller-selected bytes.
    let _ = &private;
}

#[test]
fn v2_signature_vector_rejects_each_component_mutation() {
    let v = vector();
    let signable = decode(&v["signable_bytes"]);
    let public = fixture_public(&v);
    let signature = fixture_signature(&v);
    let mut changed = signable.clone();
    changed[0] ^= 1;
    assert!(verify_delegation_v2(&changed, &signature, &public).is_err());

    let mut changed_signature = signature.clone();
    changed_signature.ed25519[0] ^= 1;
    assert!(verify_delegation_v2(&signable, &changed_signature, &public).is_err());
    let mut changed_signature = signature.clone();
    changed_signature.ml_dsa_65[0] ^= 1;
    assert!(verify_delegation_v2(&signable, &changed_signature, &public).is_err());

    let mut changed_public = public.clone();
    changed_public.ed25519[0] ^= 1;
    assert!(verify_delegation_v2(&signable, &signature, &changed_public).is_err());
    let mut changed_public = public;
    changed_public.ml_dsa_65[0] ^= 1;
    assert!(verify_delegation_v2(&signable, &signature, &changed_public).is_err());
}

#[test]
fn v2_rejects_wrong_or_empty_mldsa_context() {
    let v = vector();
    let signable = decode(&v["signable_bytes"]);
    let public = fixture_public(&v);
    let signature = fixture_signature(&v);
    let (_, private) = fixture_keys(&v);
    let ml_sk_bytes: [u8; ml_dsa_65::SK_LEN] = private.ml_dsa_65().try_into().unwrap();
    let ml_sk = ml_dsa_65::PrivateKey::try_from_bytes(ml_sk_bytes).unwrap();
    let message = delegation_signature_message_v2(&signable);

    for context in [decode(&v["alternate_mldsa_context"]), Vec::new()] {
        let wrong_context_sig = ml_sk
            .try_sign_with_seed(&[0; 32], &message, &context)
            .unwrap();
        let wrong_context_hybrid = HybridSignature {
            ed25519: signature.ed25519.clone(),
            ml_dsa_65: wrong_context_sig.to_vec(),
        };
        assert!(verify_delegation_v2(&signable, &wrong_context_hybrid, &public).is_err());
    }
}

#[test]
fn v2_key_id_rejects_invalid_hybrid_key_lengths() {
    let v = vector();
    let mut public = fixture_public(&v);
    public.ed25519.pop();
    assert!(derive_key_id_v2(&public).is_err());
    let mut public = fixture_public(&v);
    public.ml_dsa_65.pop();
    assert!(derive_key_id_v2(&public).is_err());
}
