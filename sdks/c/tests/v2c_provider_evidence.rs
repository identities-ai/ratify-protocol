//! Provider evidence records (testvectors/v2/provider-evidence/) through the
//! C ABI. Every record present is checked with `ratify_v2_*` exports only:
//! its key must issue its delegation certificate, prove possession in its
//! key rotation statement, and sign its revocation list, and every object
//! must strictly decode and re-encode to its wire bytes.

mod v2c_common;

use std::ffi::CString;
use std::ptr;

use ratify_c::*;
use serde_json::{json, Value};
use v2c_common::*;

fn verify(kind: i32, wire: &[u8], ctx: Option<&Value>) -> R<()> {
    let ctx = ctx.map(|c| CString::new(c.to_string()).unwrap());
    check(unsafe {
        ratify_v2_verify_object(
            kind,
            ptr_of(wire),
            wire.len(),
            ctx.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
            ptr::null_mut(),
        )
    })
}

#[test]
fn v2c_provider_evidence_records() {
    let dir = corpus_dir().join("provider-evidence");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "provider-evidence/ has no records");
    let mut t = Tally::default();
    for file in &files {
        let data = std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
        let r: Value =
            serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {file}: {e}"));
        let expected_name = format!("{}-{}.json", s(&r["platform"]), s(&r["provider"]));
        t.check(
            "records",
            &format!("{file} name"),
            *file == expected_name && r["version"] == json!(1),
            || format!("expected {expected_name} at version 1, got version {}", r["version"]),
        );
        let key = key_struct(&r["public_key"]);
        let id = s(&r["key_id_v2"]);
        let derived = key_id_of(&key);
        t.check(
            "records",
            &format!("{file} key ID"),
            derived.as_ref().ok() == Some(&id),
            || format!("derived {:?}, record states {id}", derived.as_ref().ok()),
        );
        for o in arr(&r["objects"]) {
            let kind = s(&o["kind"]);
            let wire = b64(&o["wire_b64"]);
            let name = format!("{file} {kind}");
            let code = kind_code(&kind);
            let re = canonicalize(code, &wire);
            let same = re.as_ref().ok() == Some(&wire);
            let obj = parse(&wire);
            match kind.as_str() {
                "delegation_certificate" => {
                    let v = class_of(&verify(code, &wire, None));
                    let issuer_key = key_struct(&obj["issuer_pub_key"]);
                    let key_ok = issuer_key.ed25519 == key.ed25519
                        && issuer_key.ml_dsa_65 == key.ml_dsa_65;
                    let ok = v == "ok" && key_ok && s(&obj["issuer_id"]) == id && same;
                    t.check("objects", &name, ok, || {
                        format!(
                            "verify={v} issuer_key={key_ok} issuer_id={} reencode={same}",
                            obj["issuer_id"]
                        )
                    });
                    let mut bad = obj.clone();
                    let mut ml = b64(&obj["signature"]["ml_dsa_65"]);
                    ml[0] ^= 1;
                    bad["signature"]["ml_dsa_65"] = json!(enc(&ml));
                    let v = class_of(&verify(code, &canon(&bad), None));
                    t.check("negatives", &name, v == "invalid_signature", || {
                        format!("flipped ML-DSA-65 signature byte gave {v}")
                    });
                }
                "key_rotation_statement" => {
                    let sb = signable(4, &wire).unwrap_or_else(|f| panic!("{name}: {}", f.message));
                    let sig = |f: &str| (b64(&obj[f]["ed25519"]), b64(&obj[f]["ml_dsa_65"]));
                    let ((oe, om), (ne, nm)) = (sig("old_signature"), sig("new_signature"));
                    let (old_key, new_key) = (key_struct(&obj["old_key"]), key_struct(&obj["new_key"]));
                    let old = class_of(&verify_statement(4, &sb, &oe, &om, &old_key));
                    let new = class_of(&verify_statement(9, &sb, &ne, &nm, &new_key));
                    let key_ok =
                        new_key.ed25519 == key.ed25519 && new_key.ml_dsa_65 == key.ml_dsa_65;
                    let ok = old == "ok" && new == "ok" && key_ok && same;
                    t.check("objects", &name, ok, || {
                        format!("old={old} new={new} new_key={key_ok} reencode={same}")
                    });
                }
                "revocation_list" => {
                    let ctx = json!({"bound_issuer_id": id, "status_key": key_json(&key)});
                    let v = class_of(&verify(code, &wire, Some(&ctx)));
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
    t.finish(&[("records", 2 * n), ("objects", 3 * n), ("negatives", n)]);
}
