//! Provider evidence records (testvectors/v2/provider-evidence/). Every
//! record present is checked through the public v2 API: its key must issue
//! its delegation certificate, prove possession in its key rotation
//! statement, and sign its revocation list, and every object must re-encode
//! to its wire bytes.

mod v2_common;

use std::fs;

use ratify_protocol::v2::*;
use serde_json::Value;
use v2_common::*;

#[test]
fn v2_provider_evidence_records() {
    let dir = corpus_dir().join("provider-evidence");
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "provider-evidence/ has no records");
    let mut t = Tally::default();
    for file in &files {
        let data = fs::read(dir.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let r: Value =
            serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {file}: {e}"));
        let expected_name = format!("{}-{}.json", s(&r["platform"]), s(&r["provider"]));
        t.check(
            "records",
            &format!("{file} name"),
            *file == expected_name && i(&r["version"]) == 1,
            || {
                format!(
                    "expected {expected_name} at version 1, got version {}",
                    r["version"]
                )
            },
        );
        let key = pub_key(&r["public_key"]);
        let id = s(&r["key_id_v2"]);
        let derived = key_id_v2(&key);
        t.check(
            "records",
            &format!("{file} key ID"),
            derived.as_ref().ok() == Some(&id),
            || format!("derived {derived:?}, record states {id}"),
        );
        // Exactly one object of each kind, with its role.
        let mut pairs: Vec<(String, String)> = arr(&r["objects"])
            .iter()
            .map(|o| (s(&o["kind"]), s(&o["role"])))
            .collect();
        pairs.sort();
        let want: Vec<(String, String)> = [
            ("delegation_certificate", "issuer"),
            ("key_rotation_statement", "new_key"),
            ("revocation_list", "status_key"),
        ]
        .iter()
        .map(|(k, r)| (k.to_string(), r.to_string()))
        .collect();
        t.check("records", &format!("{file} objects"), pairs == want, || {
            format!("{pairs:?}")
        });
        for o in arr(&r["objects"]) {
            let kind = s(&o["kind"]);
            let wire = b64(&o["wire_b64"]);
            let name = format!("{file} {kind}");
            let re = reencode(&kind, &wire);
            let same = re.as_ref().ok() == Some(&wire);
            match kind.as_str() {
                "delegation_certificate" => {
                    let c =
                        decode_delegation_cert_v2(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
                    let v = class_of(&verify_delegation_cert_v2_signature(&c));
                    let ok = v == "ok" && c.issuer_pub_key == key && c.issuer_id == id && same;
                    t.check("objects", &name, ok, || {
                        format!(
                            "verify={v} issuer_key={} issuer_id={} reencode={same}",
                            c.issuer_pub_key == key,
                            c.issuer_id
                        )
                    });
                    let mut bad = c.clone();
                    bad.signature.ml_dsa_65[0] ^= 1;
                    let v = class_of(&verify_delegation_cert_v2_signature(&bad));
                    t.check("negatives", &name, v == "invalid_signature", || {
                        format!("flipped ML-DSA-65 signature byte gave {v}")
                    });
                }
                "key_rotation_statement" => {
                    let st = decode_key_rotation_statement_v2(&wire)
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    let signable = key_rotation_statement_v2_signable_bytes(&st).unwrap();
                    let old = class_of(&verify_v2_statement(
                        V2ObjectType::KeyRotationAuthorization,
                        &signable,
                        &st.old_signature,
                        &st.old_key,
                    ));
                    let new = class_of(&verify_v2_statement(
                        V2ObjectType::KeyRotationProofOfPossession,
                        &signable,
                        &st.new_signature,
                        &st.new_key,
                    ));
                    let ok = old == "ok" && new == "ok" && st.new_key == key && same;
                    t.check("objects", &name, ok, || {
                        format!(
                            "old={old} new={new} new_key={} reencode={same}",
                            st.new_key == key
                        )
                    });
                }
                "revocation_list" => {
                    let l =
                        decode_revocation_list_v2(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
                    let v = class_of(&verify_revocation_list_v2_signature(&l, &id, &key));
                    t.check("objects", &name, v == "ok" && same, || {
                        format!("verify={v} reencode={same}")
                    });
                }
                other => panic!("{name}: unknown kind {other}"),
            }
        }
    }
    let n = files.len();
    assert!(t.total("objects") > 0, "no provider evidence checks ran");
    t.finish(&[("records", 3 * n), ("objects", 3 * n), ("negatives", n)]);
}
