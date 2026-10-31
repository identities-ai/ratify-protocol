//! Shared helpers for the v2 conformance integration tests (Go
//! `loadV2Vector`, `loadV2Keys`, `unb64`).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::{key_id_v2, RevocationStatusPolicyV2};
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey};
use serde_json::Value;

pub fn load_v2_vector(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testvectors/v2")
        .join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

pub fn unb64(v: &Value) -> Vec<u8> {
    STANDARD
        .decode(v.as_str().expect("base64 string"))
        .expect("valid base64")
}

pub fn s(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

pub fn i(v: &Value) -> i64 {
    v.as_i64().unwrap_or_default()
}

pub fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_default()
}

pub struct Fixture {
    pub public: BTreeMap<String, HybridPublicKey>,
    pub private: BTreeMap<String, HybridPrivateKey>,
    pub id: BTreeMap<String, String>,
}

impl Fixture {
    /// The named public key, or the zero key for an unknown name (Go map
    /// lookup).
    pub fn public(&self, name: &str) -> HybridPublicKey {
        self.public.get(name).cloned().unwrap_or(HybridPublicKey {
            ed25519: Vec::new(),
            ml_dsa_65: Vec::new(),
        })
    }
}

/// Go `loadV2Keys`: every fixture key derived from its seeds; the derived
/// public key and v2 key ID must equal the recorded ones.
pub fn load_v2_keys() -> Fixture {
    let file = load_v2_vector("keys.json");
    let mut fx = Fixture {
        public: BTreeMap::new(),
        private: BTreeMap::new(),
        id: BTreeMap::new(),
    };
    for k in file["keys"].as_array().expect("keys") {
        let ed: [u8; 32] = hex::decode(s(&k["ed25519_seed_hex"]))
            .expect("hex")
            .try_into()
            .expect("32");
        let ml: [u8; 32] = hex::decode(s(&k["ml_dsa_65_seed_hex"]))
            .expect("hex")
            .try_into()
            .expect("32");
        let (public, private) = hybrid_keypair_from_seeds(&ed, &ml);
        assert_eq!(public.ed25519, unb64(&k["public_key"]["ed25519"]));
        assert_eq!(public.ml_dsa_65, unb64(&k["public_key"]["ml_dsa_65"]));
        let id = s(&k["key_id_v2"]);
        assert_eq!(key_id_v2(&public).expect("key id"), id);
        let name = s(&k["name"]);
        fx.public.insert(name.clone(), public);
        fx.private.insert(name.clone(), private);
        fx.id.insert(name, id);
    }
    fx
}

pub fn public_key_json(v: &Value) -> HybridPublicKey {
    HybridPublicKey {
        ed25519: unb64(&v["ed25519"]),
        ml_dsa_65: unb64(&v["ml_dsa_65"]),
    }
}

pub fn policy(v: &Value) -> RevocationStatusPolicyV2 {
    RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: i(&v["max_list_lifetime_seconds"]),
        max_status_age_seconds: i(&v["max_status_age_seconds"]),
        clock_skew_seconds: i(&v["clock_skew_seconds"]),
    }
}

/// The count a corpus README states, e.g. `readme_count("status-sequences.json", "status-reducer scenarios")`.
pub fn readme_line(file: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2/README.md");
    let readme = std::fs::read_to_string(path).expect("read README");
    readme
        .lines()
        .find(|l| l.starts_with(&format!("| `{file}`")))
        .unwrap_or_else(|| panic!("README has no row for {file}"))
        .to_string()
}
