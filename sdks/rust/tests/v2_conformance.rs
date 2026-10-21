//! Shared Protocol v2 conformance corpus runner (testvectors/v2).
//!
//! Every JSON file in the corpus directory is loaded; an unrecognized file
//! fails the run so no vector class can be skipped silently. Each runner
//! collects every mismatch and fails at the end with the full list.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ratify_protocol::v2::*;
use ratify_protocol::{
    derive_id, hybrid_keypair_from_seeds, HybridPrivateKey, HybridPublicKey, HybridSignature,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/v2")
}

fn load(name: &str) -> Value {
    let data = fs::read(corpus_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn b64(v: &Value) -> Vec<u8> {
    STANDARD
        .decode(v.as_str().expect("base64 string"))
        .expect("base64")
}

fn s(v: &Value) -> String {
    v.as_str()
        .unwrap_or_else(|| panic!("expected string, got {v}"))
        .to_string()
}

fn i(v: &Value) -> i64 {
    v.as_i64()
        .unwrap_or_else(|| panic!("expected integer, got {v}"))
}

fn class_of<T>(r: &V2Result<T>) -> String {
    match r {
        Ok(_) => "ok".into(),
        Err(e) => e.class.as_str().into(),
    }
}

struct Fixture {
    public: BTreeMap<String, HybridPublicKey>,
    private: BTreeMap<String, HybridPrivateKey>,
    id: BTreeMap<String, String>,
}

impl Fixture {
    fn key(&self, name: &str) -> HybridPublicKey {
        self.public
            .get(name)
            .unwrap_or_else(|| panic!("unknown fixture key {name}"))
            .clone()
    }
}

fn fixture() -> Fixture {
    let keys = load("keys.json");
    let mut fx = Fixture {
        public: BTreeMap::new(),
        private: BTreeMap::new(),
        id: BTreeMap::new(),
    };
    for k in keys["keys"].as_array().unwrap() {
        let ed: [u8; 32] = hex::decode(s(&k["ed25519_seed_hex"]))
            .unwrap()
            .try_into()
            .unwrap();
        let ml: [u8; 32] = hex::decode(s(&k["ml_dsa_65_seed_hex"]))
            .unwrap()
            .try_into()
            .unwrap();
        let (public, private) = hybrid_keypair_from_seeds(&ed, &ml);
        let name = s(&k["name"]);
        fx.public.insert(name.clone(), public);
        fx.private.insert(name.clone(), private);
        fx.id.insert(name, s(&k["key_id_v2"]));
    }
    fx
}

fn pub_key(v: &Value) -> HybridPublicKey {
    HybridPublicKey {
        ed25519: b64(&v["ed25519"]),
        ml_dsa_65: b64(&v["ml_dsa_65"]),
    }
}

fn independent_key_id(k: &HybridPublicKey) -> String {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"ratify-key-id-v2\0");
    sha2::Digest::update(&mut h, &k.ed25519);
    sha2::Digest::update(&mut h, &k.ml_dsa_65);
    hex::encode(h.finalize())
}

fn shake256_64(input: &[u8]) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(input);
    let mut out = vec![0; 64];
    h.finalize_xof().read(&mut out);
    out
}

/// Coverage rows: (file, section) -> (passed, total).
#[derive(Default)]
struct Tally {
    rows: BTreeMap<String, (usize, usize)>,
    failures: Vec<String>,
}

impl Tally {
    fn check(&mut self, row: &str, name: &str, ok: bool, detail: impl FnOnce() -> String) {
        let e = self.rows.entry(row.to_string()).or_default();
        e.1 += 1;
        if ok {
            e.0 += 1;
        } else {
            self.failures.push(format!("[{row}] {name}: {}", detail()));
        }
    }

    fn finish(self, min_rows: &[(&str, usize)]) {
        for (row, (pass, total)) in &self.rows {
            println!("COVERAGE {row}: {pass}/{total}");
        }
        for (row, min) in min_rows {
            let total = self.rows.get(*row).map_or(0, |r| r.1);
            assert!(
                total >= *min,
                "{row}: only {total} cases ran, expected at least {min}"
            );
        }
        assert!(
            self.failures.is_empty(),
            "{} failure(s):\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

// ---------------------------------------------------------------------------
// Corpus completeness

const HANDLED: &[&str] = &[
    "challenge-claim.json",
    "delegation-signature.json",
    "key-rotation-signature.json",
    "keys.json",
    "log-sequences.json",
    "object-negatives.json",
    "objects.json",
    "operation-session-context.json",
    "rotation-sequences.json",
    "status-sequences.json",
    "verifier-ordering.json",
];

#[test]
fn v2_corpus_every_json_file_has_a_runner() {
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(corpus_dir()).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".json") {
            found.insert(name);
        }
    }
    let handled: BTreeSet<String> = HANDLED.iter().map(|s| s.to_string()).collect();
    assert_eq!(found, handled, "corpus JSON files and Rust runners differ");
}

// ---------------------------------------------------------------------------
// Keys

fn set_top_level_string(wire: &[u8], field: &str, value: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    obj.insert(field.into(), Value::String(value.into()));
    canonical_json_v2(serde_json::to_string(&obj).unwrap().as_bytes()).unwrap()
}

fn object_by_kind(objects: &Value, kind: &str) -> Value {
    objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} object"))
        .clone()
}

#[test]
fn v2_conformance_keys() {
    let keys = load("keys.json");
    let fx = fixture();
    let mut t = Tally::default();
    for k in keys["keys"].as_array().unwrap() {
        let name = s(&k["name"]);
        let pinned = pub_key(&k["public_key"]);
        t.check("keys.json keys", &name, fx.key(&name) == pinned, || {
            "seeds do not derive the pinned key".into()
        });
        let id = s(&k["key_id_v2"]);
        t.check(
            "keys.json keys",
            &name,
            independent_key_id(&pinned) == id && key_id_v2(&pinned).unwrap() == id,
            || "key_id_v2 differs".into(),
        );
        let v1 = derive_id(&pinned);
        t.check(
            "keys.json keys",
            &name,
            v1 == s(&k["v1_key_id_128"]) && v1 != id[..32],
            || format!("v1 id {v1} wrong or aliases v2 prefix"),
        );
    }
    let objects = load("objects.json");
    let bundle = b64(&object_by_kind(&objects, "proof_bundle")["wire_b64"]);
    let witness = b64(&object_by_kind(&objects, "witness_entry")["wire_b64"]);
    for bad in keys["invalid_v2_key_ids"].as_array().unwrap() {
        let value = s(&bad["value"]);
        let want = s(&bad["expected_error_class"]);
        let got = class_of(&decode_proof_bundle_v2(&set_top_level_string(
            &bundle,
            "verifier_id",
            &value,
        )));
        t.check(
            "keys.json invalid_v2_key_ids",
            &format!("{} as verifier_id", bad["name"]),
            got == want,
            || format!("class {got}, want {want}"),
        );
        let got = class_of(&decode_witness_entry_v2(&set_top_level_string(
            &witness,
            "witness_id",
            &value,
        )));
        t.check(
            "keys.json invalid_v2_key_ids",
            &format!("{} as witness_id", bad["name"]),
            got == want,
            || format!("class {got}, want {want}"),
        );
    }
    t.finish(&[("keys.json keys", 3), ("keys.json invalid_v2_key_ids", 2)]);
}

// ---------------------------------------------------------------------------
// Objects and negatives

fn witness_head(h: &Value) -> WitnessV2Head {
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

fn receipt_head(h: &Value) -> ReceiptV2Head {
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

fn rotation_state(v: &Value, fx: &Fixture) -> KeyRotationV2State {
    KeyRotationV2State {
        authority_id: s(&v["authority_id"]),
        recovery_epoch: i(&v["recovery_epoch"]),
        role: s(&v["role"]),
        sequence: i(&v["sequence"]),
        head_hash: b64(&v["head_hash_b64"]),
        current_key: fx.key(&s(&v["current_key"])),
        used_key_ids: v["used_key_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
    }
}

/// Per-kind decode and verify procedure (object-negatives.json procedure_by_kind).
fn verify_object(fx: &Fixture, kind: &str, wire: &[u8], bundle: &[u8], vc: &Value) -> V2Result<()> {
    match kind {
        "delegation_certificate" => {
            verify_delegation_cert_v2_signature(&decode_delegation_cert_v2(wire)?)
        }
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
        "transaction_receipt" => {
            verify_transaction_receipt_v2_signatures(&decode_transaction_receipt_v2(wire)?)
        }
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

fn reencode(kind: &str, wire: &[u8]) -> V2Result<Vec<u8>> {
    match kind {
        "delegation_certificate" => encode_delegation_cert_v2(&decode_delegation_cert_v2(wire)?),
        "proof_bundle" => encode_proof_bundle_v2(&decode_proof_bundle_v2(wire)?),
        "revocation_list" => encode_revocation_list_v2(&decode_revocation_list_v2(wire)?),
        "revocation_push" => encode_revocation_push_v2(&decode_revocation_push_v2(wire)?),
        "key_rotation_statement" => {
            encode_key_rotation_statement_v2(&decode_key_rotation_statement_v2(wire)?)
        }
        "witness_entry" => encode_witness_entry_v2(&decode_witness_entry_v2(wire)?),
        "transaction_receipt" => {
            encode_transaction_receipt_v2(&decode_transaction_receipt_v2(wire)?)
        }
        "verification_receipt" => {
            encode_verification_receipt_v2(&decode_verification_receipt_v2(wire)?)
        }
        other => panic!("unknown kind {other}"),
    }
}

/// SPEC-v2 §5 projection rule for a signature field, from the wire object.
fn projection(wire: &[u8], field: &str) -> Vec<u8> {
    let mut obj: Map<String, Value> = serde_json::from_slice(wire).unwrap();
    let drop = |obj: &mut Map<String, Value>, fields: &[&str]| {
        for f in fields {
            obj.remove(*f);
        }
        canonical_json_v2(serde_json::to_string(obj).unwrap().as_bytes()).unwrap()
    };
    if field == "signature" {
        return drop(&mut obj, &["signature"]);
    }
    if field == "challenge_sig" {
        return drop(&mut obj, &["delegations", "challenge_sig"]);
    }
    if field == "old_signature" || field == "new_signature" {
        return drop(&mut obj, &["old_signature", "new_signature"]);
    }
    if let Some(rest) = field.strip_prefix("delegations[") {
        let idx: usize = rest.trim_end_matches("].signature").parse().unwrap();
        let cert = serde_json::to_vec(&obj["delegations"][idx]).unwrap();
        return projection(&cert, "signature");
    }
    if field.starts_with("party_signatures[") {
        return transaction_receipt_v2_sign_bytes(&decode_transaction_receipt_v2(wire).unwrap())
            .unwrap();
    }
    panic!("unknown signature field {field}");
}

fn object_digest(name: &str, kind: &str, wire: &[u8], digests: &Value) -> Option<String> {
    let session_inputs = |b: &ProofBundleV2| ratify_protocol::SessionContextV2Inputs {
        verifier_id: b.verifier_id.clone(),
        workspace_id: "00000000-0000-4000-8000-000000000001".into(),
        agent_id: b.agent_id.clone(),
        session_id: "session-01".into(),
        invocation_id: "invocation-01".into(),
        request_hash: ratify_protocol::operation_context_v2_hash(
            &ratify_protocol::OperationContextV2 {
                required_scope: "data:read".into(),
                operation: "records.get".into(),
                resource_id: "customer/123".into(),
                requested_path: "/v1/customers/123".into(),
                payload_digest: vec![],
            },
        )
        .unwrap(),
    };
    Some(match name {
        "issuer_key_id_v2" => {
            independent_key_id(&decode_delegation_cert_v2(wire).unwrap().issuer_pub_key)
        }
        "subject_key_id_v2" => {
            independent_key_id(&decode_delegation_cert_v2(wire).unwrap().subject_pub_key)
        }
        "delegation_digest_hex" => {
            hex::encode(decode_proof_bundle_v2(wire).unwrap().delegation_digest)
        }
        "bundle_hash_v2" => bundle_hash_v2(&decode_proof_bundle_v2(wire).unwrap()).unwrap(),
        "session_context_hex" => {
            let b = decode_proof_bundle_v2(wire).unwrap();
            let ctx = ratify_protocol::build_session_context_v2(&session_inputs(&b)).unwrap();
            if b.session_context.as_ref() != Some(&ctx) {
                return Some(
                    "bundle session_context does not match the recomputed fixture context".into(),
                );
            }
            hex::encode(ctx)
        }
        "challenge_claim_digest_hex" => hex::encode(
            ratify_protocol::challenge_claim_digest_v2(
                &decode_proof_bundle_v2(wire).unwrap().challenge,
            )
            .unwrap(),
        ),
        "claim_id" => {
            let b = decode_proof_bundle_v2(wire).unwrap();
            let epoch: u64 = s(&digests["claim_replay_epoch"]).parse().unwrap();
            ratify_protocol::protocol_claim_id_v2(
                &s(&digests["claim_verifier_namespace"]),
                epoch,
                &b.challenge,
            )
            .unwrap()
        }
        "claim_verifier_namespace" | "claim_replay_epoch" | "transaction_context_hex" => {
            return None
        }
        "receipt_outbox_body_b64" => STANDARD.encode(
            verification_receipt_v2_body(&decode_verification_receipt_v2(wire).unwrap()).unwrap(),
        ),
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
                key_rotation_statement_v2_digest(&decode_key_rotation_statement_v2(wire).unwrap())
                    .unwrap()
            }
            "witness_entry" => {
                witness_entry_v2_digest(&decode_witness_entry_v2(wire).unwrap()).unwrap()
            }
            "verification_receipt" => {
                verification_receipt_v2_digest(&decode_verification_receipt_v2(wire).unwrap())
                    .unwrap()
            }
            other => panic!("statement digest for {other}"),
        }),
        other if other.starts_with("party-") => {
            let r = decode_transaction_receipt_v2(wire).unwrap();
            let (party_id, field) = other.split_once('.').unwrap();
            // Independent transaction context construction.
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
            if hex::encode(&tx) != s(&digests["transaction_context_hex"])
                || transaction_context_hash_v2(&r) != tx
            {
                return Some("transaction context differs".into());
            }
            let p = r.parties.iter().find(|p| p.party_id == party_id).unwrap();
            let req = transaction_party_request_hash_v2(&tx, &p.required_scope);
            match field {
                "transaction_party_request_hash_hex" => hex::encode(req),
                "session_context_hex" => hex::encode(
                    ratify_protocol::build_session_context_v2(
                        &ratify_protocol::SessionContextV2Inputs {
                            verifier_id: p.verifier_id.clone(),
                            workspace_id: p.workspace_id.clone(),
                            agent_id: p.agent_id.clone(),
                            session_id: p.session_id.clone(),
                            invocation_id: p.invocation_id.clone(),
                            request_hash: req,
                        },
                    )
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
fn v2_conformance_objects() {
    let fx = fixture();
    let f = load("objects.json");
    let mut t = Tally::default();
    let mut codes = BTreeSet::new();
    for o in f["objects"].as_array().unwrap() {
        let name = s(&o["name"]);
        let kind = s(&o["kind"]);
        let wire = b64(&o["wire_b64"]);
        let re = reencode(&kind, &wire);
        t.check(
            "objects.json re-encode",
            &name,
            re.as_ref().is_ok_and(|b| *b == wire),
            || format!("{re:?}").chars().take(300).collect(),
        );
        let v = verify_object(&fx, &kind, &wire, &[], &o["verify"]);
        t.check("objects.json verify", &name, v.is_ok(), || format!("{v:?}"));
        for sig in o["signatures"].as_array().unwrap() {
            let field = s(&sig["field"]);
            let code = i(&sig["object_type_code"]) as u16;
            codes.insert(code);
            let row = "objects.json signatures";
            let id = format!("{name}/{field}");
            let signable = b64(&sig["signable_b64"]);
            t.check(
                row,
                &format!("{id} projection"),
                projection(&wire, &field) == signable,
                || "signable projection differs".into(),
            );
            t.check(
                row,
                &format!("{id} sha384"),
                hex::encode(Sha384::digest(&signable)) == s(&sig["signable_sha384_hex"]),
                || "signable SHA-384 differs".into(),
            );
            let ty = V2ObjectType::from_code(code).expect("registered code");
            let m = v2_signing_message(ty, &signable);
            t.check(
                row,
                &format!("{id} message"),
                m == b64(&sig["message_b64"]) && m.len() == 77,
                || "transcript M differs".into(),
            );
            let ctx = String::from_utf8(v2_mldsa_context(ty)).unwrap();
            t.check(
                row,
                &format!("{id} context"),
                ctx == s(&sig["mldsa_context"]) && ctx.len() == 22,
                || format!("context {ctx}"),
            );
            let signer = s(&sig["signer"]);
            t.check(
                row,
                &format!("{id} signer id"),
                fx.id[&signer] == s(&sig["signer_key_id_v2"]),
                || "signer key ID differs".into(),
            );
            let signer_key = fx.key(&signer);
            let tr = shake256_64(&signer_key.ml_dsa_65);
            let mut mu_in = tr.clone();
            mu_in.extend_from_slice(&[0, ctx.len() as u8]);
            mu_in.extend_from_slice(ctx.as_bytes());
            mu_in.extend_from_slice(&m);
            t.check(
                row,
                &format!("{id} tr/mu"),
                tr == b64(&sig["mldsa_tr_b64"]) && shake256_64(&mu_in) == b64(&sig["mldsa_mu_b64"]),
                || "external-mu tr/mu differ".into(),
            );
            let pinned = HybridSignature {
                ed25519: b64(&sig["signature"]["ed25519"]),
                ml_dsa_65: b64(&sig["signature"]["ml_dsa_65"]),
            };
            let wire_text = String::from_utf8(wire.clone()).unwrap();
            t.check(
                row,
                &format!("{id} carried"),
                wire_text.contains(&STANDARD.encode(&pinned.ed25519))
                    && wire_text.contains(&STANDARD.encode(&pinned.ml_dsa_65)),
                || "pinned signature is not carried by the wire object".into(),
            );
            let verified = verify_v2_statement(ty, &signable, &pinned, &signer_key);
            t.check(row, &format!("{id} verifies"), verified.is_ok(), || {
                format!("{verified:?}")
            });
        }
        if let Some(ds) = o["digests"].as_object() {
            for (dname, want) in ds {
                if let Some(got) = object_digest(dname, &kind, &wire, &o["digests"]) {
                    t.check(
                        "objects.json digests",
                        &format!("{name}/{dname}"),
                        got == s(want),
                        || format!("got {got}, want {want}"),
                    );
                }
            }
        }
    }
    for code in 1..=9u16 {
        t.check(
            "objects.json codes",
            &format!("code {code}"),
            codes.contains(&code),
            || "no signature for code".into(),
        );
    }
    t.finish(&[
        ("objects.json re-encode", 10),
        ("objects.json signatures", 14 * 8),
    ]);
}

#[test]
fn v2_conformance_object_negatives() {
    let fx = fixture();
    let f = load("object-negatives.json");
    let mut t = Tally::default();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for v in f["vectors"].as_array().unwrap() {
        let kind = s(&v["kind"]);
        *kinds.entry(kind.clone()).or_default() += 1;
        let bundle = v
            .get("bundle_b64")
            .and_then(Value::as_str)
            .map(|x| STANDARD.decode(x).unwrap())
            .unwrap_or_default();
        let want = s(&v["expected_error_class"]);
        let got = class_of(&verify_object(
            &fx,
            &kind,
            &b64(&v["wire_b64"]),
            &bundle,
            &v["verify"],
        ));
        t.check(
            &format!("object-negatives.json {kind}"),
            &s(&v["name"]),
            got == want,
            || format!("class {got}, want {want} ({})", s(&v["mutation"])),
        );
    }
    for kind in [
        "delegation_certificate",
        "proof_bundle",
        "revocation_list",
        "revocation_push",
        "key_rotation_statement",
        "witness_entry",
        "transaction_receipt",
        "verification_receipt",
        "receipt_bundle_binding",
    ] {
        assert!(
            kinds.get(kind).copied().unwrap_or(0) > 0,
            "no negative vectors for {kind}"
        );
    }
    let total: usize = kinds.values().sum();
    assert_eq!(total, f["vectors"].as_array().unwrap().len());
    t.finish(&[]);
}

// ---------------------------------------------------------------------------
// Witness and receipt logs

#[test]
fn v2_conformance_log_sequences() {
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
    t.finish(&[]);
}

// ---------------------------------------------------------------------------
// Rotation sequences

#[test]
fn v2_conformance_rotation_sequences() {
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
    t.finish(&[]);
}

// ---------------------------------------------------------------------------
// Hand-maintained primitive vectors

#[test]
fn v2_conformance_key_rotation_signature_vector() {
    let v = load("key-rotation-signature.json");
    let mut t = Tally::default();
    let mut cases = vec![v.clone()];
    if v["continuation"].is_object() {
        cases.push(v["continuation"].clone());
    }
    for (n, c) in cases.iter().enumerate() {
        let row = "key-rotation-signature.json";
        let seed = |x: &Value| -> [u8; 32] { hex::decode(s(x)).unwrap().try_into().unwrap() };
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
            old_signature: HybridSignature {
                ed25519: b64(&c["old_signature"]["ed25519"]),
                ml_dsa_65: b64(&c["old_signature"]["ml_dsa_65"]),
            },
            new_signature: HybridSignature {
                ed25519: b64(&c["new_signature"]["ed25519"]),
                ml_dsa_65: b64(&c["new_signature"]["ml_dsa_65"]),
            },
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
    t.finish(&[("key-rotation-signature.json", 8)]);
}

#[test]
fn v2_conformance_delegation_signature_vector() {
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
    let sig = HybridSignature {
        ed25519: b64(&v["signature"]["ed25519"]),
        ml_dsa_65: b64(&v["signature"]["ml_dsa_65"]),
    };
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

#[test]
fn v2_conformance_operation_session_and_claim_vectors_load() {
    // Byte-level assertions for these hand-maintained files are in
    // tests/operation_context_v2.rs and tests/challenge_claim_v2.rs; this
    // confirms the files parse so the completeness check is meaningful.
    for name in ["operation-session-context.json", "challenge-claim.json"] {
        assert!(load(name).is_object(), "{name} is not a JSON object");
    }
}

// ---------------------------------------------------------------------------
// Status sequences

fn status_policy(v: &Value) -> RevocationStatusPolicyV2 {
    RevocationStatusPolicyV2 {
        max_list_lifetime_seconds: i(&v["max_list_lifetime_seconds"]),
        max_status_age_seconds: i(&v["max_status_age_seconds"]),
        clock_skew_seconds: i(&v["clock_skew_seconds"]),
    }
}

fn evidence(v: &Value) -> Vec<StatusEvidenceEntryV2> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|e| StatusEvidenceEntryV2 {
                    issuer_id: s(&e["issuer_id"]),
                    status_key_id: s(&e["status_key_id"]),
                    sequence: i(&e["sequence"]),
                    object_type: i(&e["object_type_code"]) as u16,
                    digest: s(&e["digest"]),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(s).collect()
}

#[test]
fn v2_conformance_status_sequences() {
    let fx = fixture();
    let f = load("status-sequences.json");
    let scenarios = f["scenarios"].as_array().unwrap();
    assert!(!scenarios.is_empty(), "no status scenarios");
    let mut t = Tally::default();
    let mut queries = 0;
    for sc in scenarios {
        let issuer = s(&sc["issuer_id"]);
        let mut state = RevocationStatusStateV2::default();
        let row = "status-sequences.json steps";
        for (n, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let id = format!(
                "{}/step {n} {} {}",
                s(&sc["name"]),
                s(&step["op"]),
                step["label"].as_str().unwrap_or("")
            );
            let key = fx.key(&s(&step["status_key"]));
            let epoch = step["status_key_epoch"].as_u64().unwrap();
            let now = step["now"].as_i64().unwrap_or(0);
            let policy = if step["policy"].is_object() {
                status_policy(&step["policy"])
            } else {
                status_policy(&sc["policy"])
            };
            let op = s(&step["op"]);
            let result = match op.as_str() {
                "apply_list" => decode_revocation_list_v2(&b64(&step["wire_b64"])).and_then(|l| {
                    apply_revocation_list_v2(&state, &l, &issuer, epoch, &key, &policy, now)
                }),
                "apply_push" => decode_revocation_push_v2(&b64(&step["wire_b64"])).and_then(|p| {
                    apply_revocation_push_v2(&state, &p, &issuer, epoch, &key, &policy, now)
                }),
                "transition_epoch" => {
                    transition_revocation_status_epoch_v2(&state, &issuer, epoch, &key)
                }
                "query" => {
                    queries += 1;
                    let r = revocation_status_for_cert_v2(
                        &state,
                        &issuer,
                        &s(&step["cert_id"]),
                        epoch,
                        &key,
                        &policy,
                        now,
                    );
                    let want = &step["expect_result"];
                    match r {
                        Ok(r) => {
                            let ok = r.status == s(&want["status"])
                                && r.reason == want["reason"].as_str().unwrap_or("")
                                && r.evidence == evidence(&want["evidence"]);
                            t.check("status-sequences.json queries", &id, ok, || {
                                format!("got {r:?}, want {want}")
                            });
                        }
                        Err(e) => t.check("status-sequences.json queries", &id, false, || {
                            format!("query error {e}")
                        }),
                    }
                    continue;
                }
                other => panic!("unknown status op {other}"),
            };
            if let Some(want) = step["expect_error_class"]
                .as_str()
                .filter(|c| !c.is_empty())
            {
                let got = class_of(&result);
                t.check(row, &id, got == want, || {
                    format!("class {got}, want {want}")
                });
                continue;
            }
            match result {
                Err(e) => t.check(row, &id, false, || format!("unexpected error {e}")),
                Ok(next) => {
                    state = next;
                    let w = &step["expect_state"];
                    let mut diffs = Vec::new();
                    let mut cmp = |name: &str, got: String, want: &Value| {
                        if !want.is_null() {
                            let want = match want {
                                Value::Array(_) => format!("{:?}", strings(want)),
                                other => other.to_string(),
                            };
                            if got != want {
                                diffs.push(format!("{name}: got {got}, want {want}"));
                            }
                        }
                    };
                    cmp("has_floor", state.has_floor.to_string(), &w["has_floor"]);
                    cmp("floor", state.floor.to_string(), &w["floor"]);
                    cmp(
                        "max_observed_sequence",
                        state.max_observed_sequence.to_string(),
                        &w["max_observed_sequence"],
                    );
                    cmp(
                        "fork_sequence",
                        state.fork_sequence.to_string(),
                        &w["fork_sequence"],
                    );
                    cmp(
                        "reconciliation_required",
                        state.reconciliation_required.to_string(),
                        &w["reconciliation_required"],
                    );
                    cmp(
                        "future_dated_object_observed",
                        state.future_dated_object_observed.to_string(),
                        &w["future_dated_object_observed"],
                    );
                    cmp(
                        "accepted_set",
                        format!("{:?}", state.accepted_cert_ids),
                        &w["accepted_set"],
                    );
                    cmp(
                        "deny_union",
                        format!("{:?}", state.deny_union_cert_ids),
                        &w["deny_union"],
                    );
                    t.check(row, &id, diffs.is_empty(), || diffs.join("; "));
                }
            }
        }
    }
    assert!(queries > 0, "no status queries ran");
    t.finish(&[("status-sequences.json queries", 39)]);
}

// ---------------------------------------------------------------------------
// Verifier ordering

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Counts {
    receiver_binding: i64,
    claim: i64,
    trust: i64,
    status: i64,
    audience: i64,
    rate: i64,
    finalize: i64,
}

type Shared = Rc<RefCell<Counts>>;

struct Hook {
    reject: bool,
    counts: Shared,
}
impl V2ReceiverBinding for Hook {
    fn check(&mut self, _: &ProofBundleV2, _: &ExpectedChallengeV2) -> Result<(), String> {
        self.counts.borrow_mut().receiver_binding += 1;
        if self.reject {
            Err("application receiver binding rejected".into())
        } else {
            Ok(())
        }
    }
}

/// Single-claim, in-memory test double; not a durable production store.
struct ScriptedClaimStore {
    mode: String,
    now: i64,
    counts: Shared,
    final_body: Vec<u8>,
}
impl ClaimStoreV2 for ScriptedClaimStore {
    fn claim_v2(&mut self, _: &V2ChallengeClaim) -> Result<V2ClaimResult, V2ClaimStoreError> {
        self.counts.borrow_mut().claim += 1;
        let r = |d, token: Vec<u8>| {
            Ok(V2ClaimResult {
                disposition: d,
                claimed_at: self.now,
                owner_token: token,
            })
        };
        match self.mode.as_str() {
            "create" => r(V2ClaimDisposition::Created, vec![7; 32]),
            "proof_conflict" => Err(V2ClaimStoreError::ProofConflict),
            "in_progress" => r(V2ClaimDisposition::InProgress, vec![]),
            "terminal_replay" => r(V2ClaimDisposition::TerminalReplay, vec![]),
            _ => Err(V2ClaimStoreError::Unavailable(
                "scripted claim store unavailable".into(),
            )),
        }
    }
    fn finalize_v2_claim(
        &mut self,
        _: &str,
        _: &[u8],
        _: &[u8],
        body: &[u8],
        _: i64,
    ) -> Result<bool, V2FinalizeError> {
        self.counts.borrow_mut().finalize += 1;
        self.final_body = body.to_vec();
        Ok(true)
    }
    fn recover_interrupted_v2_claim(
        &mut self,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> Result<bool, String> {
        Err("not used by conformance vectors".into())
    }
}

struct ScriptedRate {
    mode: String,
    counts: Shared,
    batch: Vec<V2RateReservation>,
}
impl V2RateReservationStore for ScriptedRate {
    fn reserve_v2_rate_batch(
        &mut self,
        _: &str,
        _: &[u8],
        _: &str,
        batch: &[V2RateReservation],
    ) -> Result<(), V2RateError> {
        self.counts.borrow_mut().rate += 1;
        self.batch = batch.to_vec();
        match self.mode.as_str() {
            "reserve" => Ok(()),
            "exceeded" => Err(V2RateError::LimitExceeded),
            _ => Err(V2RateError::Unavailable(
                "scripted rate store unavailable".into(),
            )),
        }
    }
}

struct Trust {
    v: Value,
    counts: Shared,
}
impl V2TrustResolver for Trust {
    fn resolve(&mut self, _: &[DelegationCertV2]) -> Result<V2TrustResolution, String> {
        self.counts.borrow_mut().trust += 1;
        if !self.v.is_object() || self.v["available"] != true {
            return Ok(V2TrustResolution::default());
        }
        Ok(V2TrustResolution {
            available: true,
            root_id: s(&self.v["root_key_id"]),
            root_key: Some(pub_key(&self.v["root_public_key"])),
        })
    }
}

struct Status {
    v: Value,
    counts: Shared,
}
impl V2StatusProvider for Status {
    fn status(&mut self, r: &CertificateRefV2) -> RevocationStatusResultV2 {
        self.counts.borrow_mut().status += 1;
        let entry = &self.v[format!("{}/{}", r.issuer_id, r.cert_id)];
        if entry.is_null() {
            return RevocationStatusResultV2::unavailable();
        }
        RevocationStatusResultV2 {
            status: s(&entry["status"]),
            reason: entry["reason"].as_str().unwrap_or("").into(),
            evidence: evidence(&entry["evidence"]),
            fresh_until: entry["fresh_until"].as_i64().unwrap_or(0),
        }
    }
}

struct Audience {
    v: Value,
    counts: Shared,
}
impl V2AudienceProvider for Audience {
    fn memberships(
        &mut self,
        _: &[V2DeferredConstraint],
        _: &str,
    ) -> Result<Vec<V2AudienceMembership>, String> {
        self.counts.borrow_mut().audience += 1;
        Ok(self
            .v
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|m| V2AudienceMembership {
                        delegation_index: i(&m["delegation_index"]) as usize,
                        constraint_index: i(&m["constraint_index"]) as usize,
                        receiver_id: s(&m["receiver_id"]),
                        trust_domain_ids: strings(&m["trust_domain_ids"]),
                        issued_at: i(&m["issued_at"]),
                        expires_at: i(&m["expires_at"]),
                        evidence_digest: s(&m["evidence_digest"]),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

fn opt_b64(v: &Value) -> Option<Vec<u8>> {
    v.as_str().map(|x| STANDARD.decode(x).unwrap())
}

/// Run one ordering vector; returns a list of mismatches.
fn run_ordering_vector(v: &Value, bundle: Vec<u8>) -> Vec<String> {
    let counts: Shared = Rc::new(RefCell::new(Counts::default()));
    let mut req = V2VerifyRequest {
        bundle,
        required_scope: s(&v["required_scope"]),
        verifier_namespace: s(&v["configured_namespace"]),
        replay_epoch: i(&v["configured_replay_epoch"]),
        now: i(&v["now"]),
        max_challenge_age_seconds: i(&v["max_challenge_age_seconds"]),
        future_skew_seconds: i(&v["future_skew_seconds"]),
        ..Default::default()
    };
    let e = &v["expected_challenge"];
    if e.is_object() {
        let mut exp = ExpectedChallengeV2 {
            value: b64(&e["value_b64"]),
            issued_at: i(&e["issued_at"]),
            expires_at: i(&e["expires_at"]),
            verifier_namespace: s(&e["verifier_namespace"]),
            replay_epoch: i(&e["replay_epoch"]),
            verifier_id: s(&e["verifier_id"]),
            ..Default::default()
        };
        if let Some(id) = e["expected_agent_id"].as_str() {
            exp.expected_agent_id = id.into();
            exp.expected_agent_public_key = e["expected_agent_public_key"]
                .is_object()
                .then(|| pub_key(&e["expected_agent_public_key"]));
        }
        if let Some(r) = e["expected_receiver_id"].as_str() {
            exp.expected_receiver_id = r.into();
        }
        exp.expected_session_context = opt_b64(&e["expected_session_context_b64"]);
        req.expected = Some(exp);
    }
    let p = &v["context_policy"];
    let mut mismatches = Vec::new();
    if p.is_object() {
        let policy = V2ContextPolicy::new(
            &s(&p["profile"]),
            p["require_bound"].as_bool().unwrap(),
            &strings(&p["required_fields"]),
            opt_b64(&p["expected_session_context_b64"]).as_deref(),
        )
        .expect("vector context policy is valid");
        if policy.digest() != s(&p["digest"]) {
            mismatches.push(format!(
                "context policy digest {} != {}",
                policy.digest(),
                s(&p["digest"])
            ));
        }
        req.context_policy = Some(policy);
    }
    let c = &v["request_context"];
    if c.is_object() && c["has_resource"] == true {
        req.context.requested_resource_id = Some(s(&c["requested_resource_id"]));
        req.context.requested_path = c["requested_path"]
            .as_str()
            .filter(|p| !p.is_empty())
            .map(String::from);
    }
    let roles = &v["status_roles"];
    let map = |x: &Value| -> BTreeMap<String, String> {
        x.as_object()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), s(v))).collect())
            .unwrap_or_default()
    };
    req.status_roles = V2StatusRoleBindings {
        status_key_issuers: map(&roles["status_key_issuers"]),
        current_status_key_ids: map(&roles["current_status_key_ids"]),
        reserved_key_ids: roles["reserved_key_ids"]
            .as_array()
            .map(|a| a.iter().map(s).collect())
            .unwrap_or_default(),
    };

    let mut store = ScriptedClaimStore {
        mode: s(&v["claim_store"]),
        now: i(&v["now"]),
        counts: counts.clone(),
        final_body: vec![],
    };
    let mut trust = Trust {
        v: v["trust"].clone(),
        counts: counts.clone(),
    };
    let mut status = Status {
        v: v["status"].clone(),
        counts: counts.clone(),
    };
    let mut audience = Audience {
        v: v["audience_memberships"].clone(),
        counts: counts.clone(),
    };
    let hook_mode = s(&v["receiver_binding_hook"]);
    let mut hook = Hook {
        reject: hook_mode == "reject",
        counts: counts.clone(),
    };
    let rate_mode = s(&v["rate"]);
    let mut rate = ScriptedRate {
        mode: rate_mode.clone(),
        counts: counts.clone(),
        batch: vec![],
    };
    let cb = V2VerifyCallbacks {
        receiver_binding: match hook_mode.as_str() {
            "accept" | "reject" => Some(&mut hook as &mut dyn V2ReceiverBinding),
            "absent" => None,
            other => panic!("unknown hook mode {other}"),
        },
        claim_store: Some(&mut store),
        trust: Some(&mut trust),
        status: Some(&mut status),
        audience: Some(&mut audience),
        rate: (rate_mode != "absent").then_some(&mut rate as &mut dyn V2RateReservationStore),
    };
    let outcome = match verify_proof_bundle_v2(&req, cb) {
        Ok(o) => o,
        Err(failed) => {
            let e = &failed.1;
            mismatches.push(format!("evaluation did not terminate: {e}"));
            return mismatches;
        }
    };
    let want = &v["expected"];
    let want_stage = s(&want["stage"]);
    if outcome.stage.as_str() != want_stage {
        mismatches.push(format!(
            "stage {} ({:?} {}/{}), want {want_stage}",
            outcome.stage.as_str(),
            outcome.error,
            outcome.decision,
            outcome.reason
        ));
        return mismatches;
    }
    let got_class = outcome
        .error_class()
        .map(|c| c.as_str().to_string())
        .unwrap_or_default();
    if got_class != want["error_class"].as_str().unwrap_or("") {
        mismatches.push(format!(
            "error class {got_class:?} ({:?}), want {}",
            outcome.error, want["error_class"]
        ));
    }
    if let Some(d) = want["disposition"].as_str().filter(|d| !d.is_empty()) {
        if outcome.disposition.map(|x| x.as_str()) != Some(d) {
            mismatches.push(format!("disposition {:?}, want {d}", outcome.disposition));
        }
    }
    let cc = &want["callback_counts"];
    let want_counts = Counts {
        receiver_binding: i(&cc["receiver_binding"]),
        claim: i(&cc["claim"]),
        trust: i(&cc["trust"]),
        status: i(&cc["status"]),
        audience: i(&cc["audience"]),
        rate: i(&cc["rate"]),
        finalize: i(&cc["finalize"]),
    };
    if *counts.borrow() != want_counts {
        mismatches.push(format!(
            "callback counts {:?}, want {want_counts:?}",
            counts.borrow()
        ));
    }
    if want_stage != "terminal" {
        return mismatches;
    }
    let r = outcome.receipt.as_ref().expect("terminal receipt");
    let got = [
        &outcome.decision,
        &outcome.reason,
        &outcome.identity_status,
        &r.trust_assessment,
        &r.status_assessment,
        &r.context_assessment,
    ]
    .map(|x| x.to_string())
    .join("|");
    let exp = [
        "decision",
        "decision_reason",
        "identity_status",
        "trust_assessment",
        "status_assessment",
        "context_assessment",
    ]
    .map(|k| want[k].as_str().unwrap_or("").to_string())
    .join("|");
    if got != exp {
        mismatches.push(format!("terminal tuple {got}, want {exp}"));
    }
    if r.context_policy_digest.as_deref() != want["context_policy_digest"].as_str() {
        mismatches.push(format!(
            "context_policy_digest {:?}, want {}",
            r.context_policy_digest, want["context_policy_digest"]
        ));
    }
    let want_body = b64(&want["receipt_body_b64"]);
    if outcome.receipt_body != want_body || store.final_body != outcome.receipt_body {
        mismatches.push(format!(
            "receipt body differs:\n got {}\nwant {}",
            String::from_utf8_lossy(&outcome.receipt_body),
            String::from_utf8_lossy(&want_body)
        ));
    }
    if outcome.allow_valid_until != want["allow_valid_until"].as_i64().unwrap_or(0) {
        mismatches.push(format!(
            "allow_valid_until {}, want {}",
            outcome.allow_valid_until, want["allow_valid_until"]
        ));
    }
    if let Some(batch) = want["rate_batch"].as_array().filter(|b| !b.is_empty()) {
        let wanted: Vec<V2RateReservation> = batch
            .iter()
            .map(|w| V2RateReservation {
                issuer_id: s(&w["issuer_id"]),
                cert_id: s(&w["cert_id"]),
                window_s: i(&w["window_s"]),
                limit: i(&w["limit"]),
            })
            .collect();
        if rate.batch != wanted {
            mismatches.push(format!("rate batch {:?}, want {wanted:?}", rate.batch));
        }
    }
    if want["status_evidence"].is_array() && r.status_evidence != evidence(&want["status_evidence"])
    {
        mismatches.push(format!(
            "status evidence {:?}, want {}",
            r.status_evidence, want["status_evidence"]
        ));
    }
    if want["granted_scope"].is_array() && r.granted_scope != strings(&want["granted_scope"]) {
        mismatches.push(format!(
            "granted scope {:?}, want {}",
            r.granted_scope, want["granted_scope"]
        ));
    }
    mismatches
}

#[test]
fn v2_conformance_verifier_ordering() {
    let f = load("verifier-ordering.json");
    let vectors = f["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty(), "no ordering vectors");
    let mut t = Tally::default();
    for v in vectors {
        let name = s(&v["name"]);
        let bundle = f["bundles_b64"][s(&v["bundle"])]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: unknown bundle"));
        let stage = s(&v["expected"]["stage"]);
        let mismatches = run_ordering_vector(v, STANDARD.decode(bundle).unwrap());
        t.check(
            &format!("verifier-ordering.json {stage}"),
            &name,
            mismatches.is_empty(),
            || mismatches.join("; "),
        );
    }
    t.finish(&[
        ("verifier-ordering.json preflight", 32),
        ("verifier-ordering.json replay", 2),
        ("verifier-ordering.json terminal", 47),
    ]);
}
