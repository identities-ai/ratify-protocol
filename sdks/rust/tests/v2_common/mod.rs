//! Shared helpers for the Protocol v2 corpus runners (testvectors/v2).
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::*;
use ratify_protocol::{hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey, HybridSignature};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2")
}

pub fn load(name: &str) -> Value {
    let data = fs::read(corpus_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

pub fn b64(v: &Value) -> Vec<u8> {
    STANDARD
        .decode(v.as_str().unwrap_or_else(|| panic!("expected base64 string, got {v}")))
        .expect("base64")
}

pub fn s(v: &Value) -> String {
    v.as_str()
        .unwrap_or_else(|| panic!("expected string, got {v}"))
        .to_string()
}

pub fn i(v: &Value) -> i64 {
    v.as_i64().unwrap_or_else(|| panic!("expected integer, got {v}"))
}

pub fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap_or_else(|| panic!("expected array, got {v}"))
}

pub fn class_of<T>(r: &V2Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.class.as_str().into(),
    }
}

pub struct Fixture {
    pub public: BTreeMap<String, HybridPublicKey>,
    pub private: BTreeMap<String, HybridPrivateKey>,
    pub id: BTreeMap<String, String>,
}

impl Fixture {
    pub fn key(&self, name: &str) -> HybridPublicKey {
        self.public
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
            .clone()
    }

    pub fn private(&self, name: &str) -> HybridPrivateKey {
        self.private
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
            .clone()
    }

    pub fn key_id(&self, name: &str) -> String {
        self.id
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
            .clone()
    }
}

pub fn seed32(hex_text: &str) -> [u8; 32] {
    hex::decode(hex_text)
        .expect("hex seed")
        .try_into()
        .expect("32-byte seed")
}

pub fn fixture() -> Fixture {
    let keys = load("keys.json");
    let mut fx = Fixture {
        public: BTreeMap::new(),
        private: BTreeMap::new(),
        id: BTreeMap::new(),
    };
    for k in arr(&keys["keys"]) {
        let (public, private) = hybrid_keypair_from_seeds(
            &seed32(&s(&k["ed25519_seed_hex"])),
            &seed32(&s(&k["ml_dsa_65_seed_hex"])),
        );
        let name = s(&k["name"]);
        fx.public.insert(name.clone(), public);
        fx.private.insert(name.clone(), private);
        fx.id.insert(name, s(&k["key_id_v2"]));
    }
    fx
}

pub fn pub_key(v: &Value) -> HybridPublicKey {
    HybridPublicKey {
        ed25519: b64(&v["ed25519"]),
        ml_dsa_65: b64(&v["ml_dsa_65"]),
    }
}

pub fn signature(v: &Value) -> HybridSignature {
    HybridSignature {
        ed25519: b64(&v["ed25519"]),
        ml_dsa_65: b64(&v["ml_dsa_65"]),
    }
}

pub fn independent_key_id(k: &HybridPublicKey) -> String {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"ratify-key-id-v2\0");
    sha2::Digest::update(&mut h, &k.ed25519);
    sha2::Digest::update(&mut h, &k.ml_dsa_65);
    hex::encode(h.finalize())
}

pub fn shake256_64(input: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(input);
    let mut out = vec![0; 64];
    h.finalize_xof().read(&mut out);
    out
}

pub fn set_top_level_string(wire: &[u8], field: &str, value: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    obj.insert(field.into(), Value::String(value.into()));
    canonical_json_v2(serde_json::to_string(&obj).unwrap().as_bytes()).unwrap()
}

/// Per-row pass/total counts with exact-count assertions at the end.
#[derive(Default)]
pub struct Tally {
    rows: BTreeMap<String, (usize, usize)>,
    failures: Vec<String>,
}

impl Tally {
    pub fn check(&mut self, row: &str, name: &str, ok: bool, detail: impl FnOnce() -> String) {
        let e = self.rows.entry(row.to_string()).or_default();
        e.1 += 1;
        if ok {
            e.0 += 1;
        } else {
            self.failures.push(format!("[{row}] {name}: {}", detail()));
        }
    }

    pub fn total(&self, row: &str) -> usize {
        self.rows.get(row).map_or(0, |r| r.1)
    }

    /// Fail on any mismatch, and require each listed row to have run exactly
    /// the stated number of checks.
    pub fn finish(self, exact_rows: &[(&str, usize)]) {
        for (row, (pass, total)) in &self.rows {
            println!("COVERAGE {row}: {pass}/{total}");
        }
        for (row, want) in exact_rows {
            let total = self.rows.get(*row).map_or(0, |r| r.1);
            assert_eq!(total, *want, "{row}: ran {total} checks, expected exactly {want}");
        }
        assert!(
            self.failures.is_empty(),
            "{} failure(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

pub fn witness_head(h: &Value) -> WitnessV2Head {
    let mut accepted = BTreeMap::new();
    if let Some(m) = h["accepted_digests_b64"].as_object() {
        for (k, v) in m {
            accepted.insert(k.parse::<i64>().unwrap(), b64(v));
        }
    }
    WitnessV2Head {
        log_id: s(&h["log_id"]),
        sequence: i(&h["sequence"]),
        head_hash: b64(&h["head_hash_b64"]),
        accepted_digests: accepted,
        frozen: h["frozen"].as_bool().unwrap_or(false),
    }
}

pub fn receipt_head(h: &Value) -> ReceiptV2Head {
    let w = witness_head(h);
    ReceiptV2Head {
        log_id: w.log_id,
        verifier_id: s(&h["verifier_id"]),
        sequence: w.sequence,
        head_hash: w.head_hash,
        accepted_digests: w.accepted_digests,
        frozen: w.frozen,
    }
}

pub fn rotation_state(v: &Value, fx: &Fixture) -> KeyRotationV2State {
    KeyRotationV2State {
        authority_id: s(&v["authority_id"]),
        recovery_epoch: i(&v["recovery_epoch"]),
        role: s(&v["role"]),
        sequence: i(&v["sequence"]),
        head_hash: b64(&v["head_hash_b64"]),
        current_key: fx.key(&s(&v["current_key"])),
        used_key_ids: arr(&v["used_key_ids"]).iter().map(s).collect(),
    }
}

/// The per-kind decode and verify procedure of object-negatives.json.
pub fn verify_object(fx: &Fixture, kind: &str, wire: &[u8], bundle: &[u8], vc: &Value) -> V2Result<()> {
    match kind {
        "delegation_certificate" => verify_delegation_cert_v2_signature(&decode_delegation_cert_v2(wire)?),
        "proof_bundle" => verify_proof_bundle_v2_signatures(&decode_proof_bundle_v2(wire)?),
        "revocation_list" => verify_revocation_list_v2_signature(
            &decode_revocation_list_v2(wire)?,
            &s(&vc["bound_issuer_id"]),
            &fx.key(&s(&vc["status_key"])),
        ),
        "revocation_push" => verify_revocation_push_v2_signature(
            &decode_revocation_push_v2(wire)?,
            &s(&vc["bound_issuer_id"]),
            &fx.key(&s(&vc["status_key"])),
        ),
        "key_rotation_statement" => verify_key_rotation_statement_v2(
            &decode_key_rotation_statement_v2(wire)?,
            &rotation_state(&vc["rotation_state"], fx),
            i(&vc["now"]),
            i(&vc["future_skew_seconds"]),
        ),
        "witness_entry" => verify_witness_entry_v2(
            &decode_witness_entry_v2(wire)?,
            &witness_head(&vc["head"]),
            &fx.key(&s(&vc["witness_key"])),
        )
        .map(|_| ()),
        "transaction_receipt" => verify_transaction_receipt_v2_signatures(&decode_transaction_receipt_v2(wire)?),
        "verification_receipt" => verify_verification_receipt_v2(
            &decode_verification_receipt_v2(wire)?,
            &fx.key(&s(&vc["verifier_key"])),
            &receipt_head(&vc["head"]),
        )
        .map(|_| ()),
        "receipt_bundle_binding" => {
            let r = decode_verification_receipt_v2(wire)?;
            let b = decode_proof_bundle_v2(bundle)?;
            check_verification_receipt_v2_bundle_binding(&r, &b)
        }
        other => panic!("unknown kind {other}"),
    }
}

pub fn reencode(kind: &str, wire: &[u8]) -> V2Result<Vec<u8>> {
    match kind {
        "delegation_certificate" => encode_delegation_cert_v2(&decode_delegation_cert_v2(wire)?),
        "proof_bundle" => encode_proof_bundle_v2(&decode_proof_bundle_v2(wire)?),
        "revocation_list" => encode_revocation_list_v2(&decode_revocation_list_v2(wire)?),
        "revocation_push" => encode_revocation_push_v2(&decode_revocation_push_v2(wire)?),
        "key_rotation_statement" => encode_key_rotation_statement_v2(&decode_key_rotation_statement_v2(wire)?),
        "witness_entry" => encode_witness_entry_v2(&decode_witness_entry_v2(wire)?),
        "transaction_receipt" => encode_transaction_receipt_v2(&decode_transaction_receipt_v2(wire)?),
        "verification_receipt" => encode_verification_receipt_v2(&decode_verification_receipt_v2(wire)?),
        other => panic!("unknown kind {other}"),
    }
}

/// SPEC-v2 §5 projection for a signature field, recomputed from the wire.
pub fn projection(wire: &[u8], field: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    let drop = |obj: &mut Map<String, Value>, fields: &[&str]| {
        for f in fields {
            obj.remove(*f);
        }
        canonical_json_v2(serde_json::to_string(obj).unwrap().as_bytes()).unwrap()
    };
    match field {
        "signature" => drop(&mut obj, &["signature"]),
        "challenge_sig" => drop(&mut obj, &["delegations", "challenge_sig"]),
        "old_signature" | "new_signature" => drop(&mut obj, &["old_signature", "new_signature"]),
        _ => {
            if let Some(rest) = field.strip_prefix("delegations[") {
                let idx: usize = rest.trim_end_matches("].signature").parse().unwrap();
                let cert = serde_json::to_vec(&obj["delegations"][idx]).unwrap();
                return projection(&cert, "signature");
            }
            if field.starts_with("party_signatures[") {
                return transaction_receipt_v2_sign_bytes(&decode_transaction_receipt_v2(wire).unwrap()).unwrap();
            }
            panic!("unknown signature field {field}");
        }
    }
}
