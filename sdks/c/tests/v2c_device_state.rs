//! testvectors/v2/device-state.json through the C ABI: each case's records
//! are loaded into the reference primary by
//! `ratify_v2_ref_device_state_projection`, which must reproduce every
//! member's canonical bytes (whose SHA-384 is recomputed here), the
//! projection object, and the complete-state digest exactly (SPEC-v2
//! §7.13). The digest the primary anchors to its checkpoint must equal the
//! projection digest, or a component would accept a primary it cannot
//! reproduce.

mod v2c_common;

use ratify_c::*;
use sha2::{Digest, Sha384};
use v2c_common::*;

const MEMBERS: [&str; 5] = [
    "claims",
    "streams",
    "rate_counters",
    "receipt_log",
    "issuance_records",
];

fn projection(state: &[u8]) -> R<serde_json::Value> {
    let out =
        buf(|o| unsafe { ratify_v2_ref_device_state_projection(state.as_ptr(), state.len(), o) })?;
    Ok(parse(&out))
}

#[test]
fn v2c_device_state_projection_vectors() {
    let f = load("device-state.json");
    assert_eq!(s(&f["label"]), "ratify/device-complete-state/v2");
    assert_eq!(i(&f["version"]), 1);
    let cases = arr(&f["cases"]);
    let mut t = Tally::default();
    for c in &cases {
        let name = s(&c["name"]);
        let state = json_bytes(&c["state"]);
        let got = projection(&state).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let want = &c["expect"];
        let mut mismatches = Vec::new();
        for m in MEMBERS {
            let bytes = s(&got[format!("{m}_canonical_json")]);
            if bytes != s(&want[format!("{m}_canonical_json")]) {
                mismatches.push(format!("{m} canonical bytes"));
            }
            if hex::encode(Sha384::digest(bytes.as_bytes())) != s(&want[format!("{m}_sha384")]) {
                mismatches.push(format!("{m} digest"));
            }
        }
        if got["projection_canonical_json"] != want["projection_canonical_json"] {
            mismatches.push("projection object".into());
        }
        if got["complete_state_digest_hex"] != want["complete_state_digest_hex"] {
            mismatches.push("complete-state digest".into());
        }
        if got["anchoring_digest_hex"] != got["complete_state_digest_hex"] {
            mismatches.push("anchoring digest differs from the projection digest".into());
        }
        t.check("device-state", &name, mismatches.is_empty(), || {
            mismatches.join(", ")
        });
    }
    t.finish(&[("device-state", cases.len())]);
    println!("C-ABI COVERAGE device-state.json: {} cases", cases.len());
    let readme = readme_line("device-state.json");
    assert!(
        readme.contains(&format!(
            "{} single-device offline complete-state projection known answers",
            cases.len()
        )),
        "README row: {readme}"
    );
}

/// A state that is not the §7.13 record encoding is refused with a class,
/// and changing one record changes the digest.
#[test]
fn v2c_device_state_projection_rejects_and_binds() {
    let f = load("device-state.json");
    let case = arr(&f["cases"])
        .into_iter()
        .find(|c| c["name"] == "every_record_kind")
        .expect("every_record_kind case");
    let mut state = case["state"].clone();
    state["replay_epoch"] = (i(&state["replay_epoch"]) + 1).into();
    let got = projection(&json_bytes(&state)).unwrap();
    assert_ne!(
        got["complete_state_digest_hex"],
        case["expect"]["complete_state_digest_hex"]
    );
    let refused = projection(b"{\"claims\":[]}");
    assert_eq!(class_of(&refused), "malformed", "{refused:?}");
    let null = buf(|o| unsafe { ratify_v2_ref_device_state_projection(std::ptr::null(), 0, o) });
    assert_eq!(class_of(&null), "null_pointer");
}
