//! Property tests for every v2 decoder (the in-tree complement to
//! sdks/rust/fuzz). Untrusted bytes must never panic a decoder, and a strict
//! decoder that accepts bytes must have been handed the canonical encoding of
//! what it decoded: re-encoding reproduces the input exactly. Otherwise two
//! SDKs could hash or sign different bytes for the same accepted object.

mod v2_common;

use std::sync::OnceLock;

use proptest::prelude::*;
use ratify_protocol::v2::*;
use serde_json::Value;
use v2_common::*;

type Decoder = fn(&[u8]) -> Option<V2Result<Vec<u8>>>;

/// Decode, and when decoding succeeds return the re-encoding.
macro_rules! wire {
    ($decode:path, $encode:path) => {
        |data: &[u8]| -> Option<V2Result<Vec<u8>>> { $decode(data).ok().map(|v| $encode(&v)) }
    };
}

/// Every decoder that exists in the crate, by objects.json kind name.
const DECODERS: [(&str, Decoder); 9] = [
    ("delegation_certificate", wire!(decode_delegation_cert_v2, encode_delegation_cert_v2)),
    ("proof_bundle", wire!(decode_proof_bundle_v2, encode_proof_bundle_v2)),
    ("revocation_list", wire!(decode_revocation_list_v2, encode_revocation_list_v2)),
    ("revocation_push", wire!(decode_revocation_push_v2, encode_revocation_push_v2)),
    ("key_rotation_statement", wire!(decode_key_rotation_statement_v2, encode_key_rotation_statement_v2)),
    ("witness_entry", wire!(decode_witness_entry_v2, encode_witness_entry_v2)),
    ("verification_receipt", wire!(decode_verification_receipt_v2, encode_verification_receipt_v2)),
    ("verification_receipt_body", wire!(decode_verification_receipt_body_v2, verification_receipt_v2_body)),
    ("transaction_receipt", wire!(decode_transaction_receipt_v2, encode_transaction_receipt_v2)),
];

fn decoder(kind: &str) -> Decoder {
    DECODERS.iter().find(|(k, _)| *k == kind).map(|(_, d)| *d).unwrap()
}

/// The strict-decoder property for one decoder and input.
fn check_wire(kind: &str, data: &[u8]) -> Result<(), TestCaseError> {
    if let Some(reencoded) = decoder(kind)(data) {
        let reencoded = reencoded.map_err(|e| TestCaseError::fail(format!("{kind}: decoded object does not encode: {e}")))?;
        prop_assert!(
            reencoded == data,
            "{} accepted bytes that re-encode differently:\n input: {}\n  again: {}",
            kind,
            String::from_utf8_lossy(data),
            String::from_utf8_lossy(&reencoded)
        );
    }
    Ok(())
}

/// Constraint decoding accepts any JSON spelling, so its property is a stable
/// round trip through the canonical form.
fn check_constraint(data: &[u8]) -> Result<(), TestCaseError> {
    if let Ok(c) = ConstraintV2::decode(data) {
        let canonical = c.canonical_json().map_err(|e| TestCaseError::fail(format!("constraint encode: {e}")))?;
        let again = ConstraintV2::decode(&canonical).map_err(|e| TestCaseError::fail(format!("constraint redecode: {e}")))?;
        prop_assert_eq!(&again, &c);
        prop_assert_eq!(again.canonical_json().ok(), Some(canonical));
    }
    Ok(())
}

fn check_canonical(data: &[u8]) -> Result<(), TestCaseError> {
    if let Ok(c) = canonical_json_v2(data) {
        prop_assert_eq!(canonical_json_v2(&c).ok(), Some(c.clone()), "canonical_json_v2 is not idempotent");
    }
    Ok(())
}

fn check_all(data: &[u8]) -> Result<(), TestCaseError> {
    for (kind, _) in DECODERS {
        check_wire(kind, data)?;
    }
    check_constraint(data)?;
    check_canonical(data)
}

/// Valid objects of objects.json (kind, wire), plus each receipt's outbox body
/// and each certificate constraint as its own seed.
fn seeds() -> &'static Vec<(String, Vec<u8>)> {
    static SEEDS: OnceLock<Vec<(String, Vec<u8>)>> = OnceLock::new();
    SEEDS.get_or_init(|| {
        let f = load("objects.json");
        let mut out = Vec::new();
        for o in arr(&f["objects"]) {
            let kind = s(&o["kind"]);
            let wire = b64(&o["wire_b64"]);
            if let Some(body) = o["digests"].get("receipt_outbox_body_b64") {
                out.push(("verification_receipt_body".to_string(), b64(body)));
            }
            if kind == "delegation_certificate" {
                let v: Value = serde_json::from_slice(&wire).unwrap();
                for c in arr(&v["constraints"]) {
                    out.push(("constraint".to_string(), serde_json::to_vec(c).unwrap()));
                }
            }
            out.push((kind, wire));
        }
        assert_eq!(out.iter().filter(|(k, _)| k != "constraint").count(), 11, "objects.json seeds");
        out
    })
}

fn check_kind(kind: &str, data: &[u8]) -> Result<(), TestCaseError> {
    if kind == "constraint" {
        check_constraint(data)
    } else {
        check_wire(kind, data)
    }
}

#[derive(Debug, Clone)]
enum Mutation {
    FlipBit(usize, u8),
    Insert(usize, u8),
    Delete(usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(i, b)| Mutation::FlipBit(i, b)),
        (any::<usize>(), any::<u8>()).prop_map(|(i, b)| Mutation::Insert(i, b)),
        any::<usize>().prop_map(Mutation::Delete),
    ]
}

fn apply(data: &[u8], mutations: &[Mutation]) -> Vec<u8> {
    let mut out = data.to_vec();
    for m in mutations {
        match *m {
            Mutation::FlipBit(i, bit) if !out.is_empty() => {
                let n = out.len();
                out[i % n] ^= 1 << bit;
            }
            Mutation::Insert(i, b) => out.insert(i % (out.len() + 1), b),
            Mutation::Delete(i) if !out.is_empty() => {
                let n = out.len();
                out.remove(i % n);
            }
            _ => {}
        }
    }
    out
}

const FIELD_NAMES: [&str; 24] = [
    "version", "type", "params", "cert_id", "issuer_id", "subject_id", "scope", "constraints", "signature",
    "ed25519", "ml_dsa_65", "delegations", "challenge", "session_context", "stream_seq", "revoked",
    "sequence", "log_id", "prev_hash", "parties", "party_id", "status_evidence", "constraint_evaluators",
    "max",
];

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        (-1.0e6f64..1.0e6).prop_map(Value::from),
        "[a-z0-9:_/.=+ -]{0,16}".prop_map(Value::String),
        "\\PC{0,8}".prop_map(Value::String),
    ];
    let name = prop_oneof![proptest::sample::select(&FIELD_NAMES[..]).prop_map(str::to_string), "[a-z_]{1,10}"];
    leaf.prop_recursive(4, 48, 6, move |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(name.clone(), inner, 0..6).prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    // 256 cases per property by default; PROPTEST_CASES overrides for longer runs.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Arbitrary bytes never panic any decoder.
    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        check_all(&data)?;
    }

    /// JSON-shaped text (balanced or not) never panics any decoder.
    #[test]
    fn json_ish_text_never_panics(text in "[\\[\\]{}\":,0-9a-z_. \\\\-]{0,256}") {
        check_all(text.as_bytes())?;
    }

    /// Structurally valid JSON documents, compact and canonicalized, never
    /// panic any decoder, and canonicalization is idempotent on them.
    #[test]
    fn json_documents_never_panic(v in json_value()) {
        let text = serde_json::to_vec(&v).unwrap();
        check_all(&text)?;
        if let Ok(c) = canonical_json_v2(&text) {
            check_all(&c)?;
        }
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        check_canonical(&pretty)?;
    }

    /// Bit flips, byte insertions, and deletions of valid objects never panic,
    /// and an accepted mutant is always canonical.
    #[test]
    fn mutated_valid_objects(index in any::<usize>(), mutations in prop::collection::vec(mutation(), 1..4)) {
        let all = seeds();
        let (kind, wire) = &all[index % all.len()];
        let mutated = apply(wire, &mutations);
        check_kind(kind, &mutated)?;
        check_canonical(&mutated)?;
    }

    /// Replacing one member of a valid object with an arbitrary JSON value
    /// never panics, and an accepted result is canonical.
    #[test]
    fn member_replacement_of_valid_objects(index in any::<usize>(), field in any::<usize>(), value in json_value()) {
        let all = seeds();
        let (kind, wire) = &all[index % all.len()];
        let mut doc: Value = serde_json::from_slice(wire).unwrap();
        let obj = doc.as_object_mut().unwrap();
        let key = obj.keys().nth(field % obj.len()).unwrap().clone();
        obj.insert(key, value);
        let text = serde_json::to_vec(&doc).unwrap();
        check_kind(kind, &text)?;
        if let Ok(c) = canonical_json_v2(&text) {
            check_kind(kind, &c)?;
        }
    }
}

/// Every unmodified seed decodes and is its own canonical form, so the
/// mutation tests start from accepted objects.
#[test]
fn seeds_are_canonical_and_accepted() {
    for (kind, wire) in seeds() {
        assert_eq!(canonical_json_v2(wire).unwrap(), *wire, "{kind}: seed is not canonical");
        if kind == "constraint" {
            assert!(ConstraintV2::decode(wire).is_ok(), "constraint seed rejected");
        } else {
            let re = decoder(kind)(wire).unwrap_or_else(|| panic!("{kind}: seed rejected"));
            assert_eq!(re.unwrap(), *wire, "{kind}: seed does not re-encode");
        }
    }
}

fn seed_with(kind: &str, field: &str, value: Value) -> Vec<u8> {
    let (_, wire) = seeds().iter().find(|(k, _)| k == kind).unwrap();
    let mut doc: Value = serde_json::from_slice(wire).unwrap();
    doc[field] = value;
    canonical_json_v2(&serde_json::to_vec(&doc).unwrap()).unwrap()
}

/// SPEC-v2 §2.1 strict decoding: a proof bundle whose `agent_pub_key` is
/// `{}` (a required hybrid key with missing members) is malformed.
#[test]
fn proof_bundle_empty_agent_key_is_malformed() {
    let data = seed_with("proof_bundle", "agent_pub_key", serde_json::json!({}));
    let e = decode_proof_bundle_v2(&data).expect_err("{} agent_pub_key must be rejected");
    assert_eq!(e.class, V2ErrorClass::Malformed);
}

/// SPEC-v2 §2.1 strict decoding: `null` as a delegation `scope` element is
/// malformed rather than decoding as `""`.
#[test]
fn delegation_scope_null_element_is_malformed() {
    let data = seed_with("delegation_certificate", "scope", serde_json::json!([null]));
    let e = decode_delegation_cert_v2(&data).expect_err("null scope element must be rejected");
    assert_eq!(e.class, V2ErrorClass::Malformed);
}
