//! testvectors/v2/device-state.json: the single-device offline
//! complete-state projection known answers (SPEC-v2 §7.13), mirroring Go
//! `TestDeviceStateProjectionVectors`. Each case's records are loaded into a
//! reference primary, which must reproduce every member's canonical bytes
//! and digest, the projection object, and the complete-state digest exactly.

mod v2_status_common;

use ratify_protocol::v2::reference::DevicePrimaryTestOnly;
use sha2::{Digest, Sha384};
use v2_status_common::{load_v2_vector, readme_line, s};

#[test]
fn v2_device_state_projection_vectors() {
    let f = load_v2_vector("device-state.json");
    assert_eq!(s(&f["label"]), "ratify/device-complete-state/v2");
    assert_eq!(f["version"].as_i64(), Some(1));
    let cases = f["cases"].as_array().expect("cases");
    for c in cases {
        let name = s(&c["name"]);
        let state = serde_json::to_vec(&c["state"]).unwrap();
        let primary = DevicePrimaryTestOnly::from_records_test_only(&state).unwrap_or_else(|e| panic!("{name}: load: {e}"));
        let got = primary.projection_test_only().unwrap_or_else(|e| panic!("{name}: projection: {e}"));
        let expect = &c["expect"];
        for (member, bytes) in [
            ("claims", &got.claims),
            ("streams", &got.streams),
            ("rate_counters", &got.rate_counters),
            ("receipt_log", &got.receipt_log),
            ("issuance_records", &got.issuance_records),
        ] {
            assert_eq!(
                String::from_utf8_lossy(bytes),
                s(&expect[format!("{member}_canonical_json")]),
                "{name}: {member} canonical bytes"
            );
            assert_eq!(hex::encode(Sha384::digest(bytes)), s(&expect[format!("{member}_sha384")]), "{name}: {member} digest");
        }
        assert_eq!(
            String::from_utf8_lossy(&got.projection),
            s(&expect["projection_canonical_json"]),
            "{name}: projection object"
        );
        assert_eq!(hex::encode(&got.complete_state_digest), s(&expect["complete_state_digest_hex"]), "{name}: digest");
        assert_eq!(
            primary.complete_state_digest_test_only().unwrap(),
            got.complete_state_digest,
            "{name}: the anchoring digest differs from the projection digest"
        );
    }
    assert_eq!(cases.len(), 5);
    let readme = readme_line("device-state.json");
    assert!(readme.contains("5 single-device offline complete-state projection known answers"), "README row: {readme}");
}
