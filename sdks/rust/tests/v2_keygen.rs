//! The v2 key generators are reachable from `ratify_protocol::v2`, so a v2
//! caller never has to reach into the crate root for them, and they are the
//! same functions the crate root exports: a key generated through either path
//! is the same key.

use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::{
    generate_hybrid_keypair, hybrid_keypair_from_seeds, key_id_v2, public_key_v2,
};
use serde_json::Value;

fn decode(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("base64 string"))
        .unwrap()
}

fn signature_vector() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/v2/delegation-signature.json");
    serde_json::from_slice(&fs::read(path).expect("read shared v2 signature vector"))
        .expect("parse shared v2 signature vector")
}

// Seeded generation must reproduce the shared v2 vector's issuer key: the
// cross-SDK fixtures depend on every SDK deriving byte-identical keys from
// the same seeds.
#[test]
fn v2_seeded_keygen_reproduces_the_shared_vector_key() {
    let v = signature_vector();
    let ed: [u8; 32] = decode(&v["issuer_seeds"]["ed25519"]).try_into().unwrap();
    let ml: [u8; 32] = decode(&v["issuer_seeds"]["ml_dsa_65"]).try_into().unwrap();
    let (public, private) = hybrid_keypair_from_seeds(&ed, &ml);
    assert_eq!(public.ed25519, decode(&v["issuer_public_key"]["ed25519"]));
    assert_eq!(
        public.ml_dsa_65,
        decode(&v["issuer_public_key"]["ml_dsa_65"])
    );
    assert_eq!(public_key_v2(&private).unwrap(), public);

    let (root_public, _) = ratify_protocol::hybrid_keypair_from_seeds(&ed, &ml);
    assert_eq!(
        root_public, public,
        "v2 and crate-root seeded keygen must agree"
    );
}

// Random generation must yield a usable v2 key (the private half derives the
// public half and it has a valid v2 key id) and must not repeat.
#[test]
fn v2_random_keygen_yields_distinct_usable_keys() {
    let (public_a, private_a) = generate_hybrid_keypair();
    let (public_b, _) = generate_hybrid_keypair();
    assert_eq!(public_key_v2(&private_a).unwrap(), public_a);
    assert_ne!(public_a, public_b, "two random keypairs must differ");
    assert_ne!(key_id_v2(&public_a).unwrap(), key_id_v2(&public_b).unwrap());

    let (root_public, root_private) = ratify_protocol::generate_hybrid_keypair();
    assert_eq!(public_key_v2(&root_private).unwrap(), root_public);
}
