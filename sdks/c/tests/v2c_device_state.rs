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

// Every progress record the shared vectors persist is a record a C store
// accepts: the C ABI's progress encoding has the §7.5 member names and the
// RatifyCanonicalJSON form the other SDKs write.
#[test]
fn v2c_device_state_progress_records_are_valid_c_progress() {
    fn collect(v: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if k == "progress" && x.is_object() {
                        out.push(x.clone());
                    }
                    collect(x, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    let mut records = Vec::new();
    collect(&load("device-state.json"), &mut records);
    assert!(records.iter().any(|p| !arr(&p["status_evidence_digests"]).is_empty()));
    for p in &records {
        let bytes = json_bytes(p);
        assert_eq!(
            unsafe { ratify_v2_valid_evaluation_progress(bytes.as_ptr(), bytes.len()) },
            1,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

// Every sealed claim object in the shared vectors (SPEC-v2 §7.13) is a claim
// record the C ABI accepts unchanged and keys by its replay key: the record
// a C claim store persists is exactly that object.
#[test]
fn v2c_device_state_sealed_claims_are_c_claim_records() {
    let f = load("device-state.json");
    let mut n = 0;
    for c in arr(&f["cases"]) {
        for rec in arr(&c["state"]["claims"]) {
            let claim = &rec["claim"];
            let bytes = json_bytes(claim);
            let id = std::ffi::CString::new(s(&claim["claim_id"])).unwrap();
            let ns = std::ffi::CString::new(s(&claim["namespace"])).unwrap();
            let view = RatifyV2ClaimView {
                claim_id: id.as_ptr(),
                verifier_namespace: ns.as_ptr(),
                replay_epoch: i(&claim["replay_epoch"]),
                agent_id: std::ptr::null(),
                issued_at: 0,
                expires_at: 0,
                max_age_seconds: 0,
                clock_skew_seconds: 0,
                has_stream_id: 0,
                stream_id: RatifyV2Slice { ptr: std::ptr::null(), len: 0 },
                has_stream_seq: 0,
                stream_seq: 0,
                rate_batch: std::ptr::null(),
                rate_batch_len: 0,
                record: RatifyV2Slice { ptr: bytes.as_ptr(), len: bytes.len() },
            };
            assert_eq!(
                unsafe { ratify_v2_claim_id_matches_key(&view) },
                1,
                "{}",
                String::from_utf8_lossy(&bytes)
            );
            n += 1;
        }
    }
    assert!(n > 0);
}
