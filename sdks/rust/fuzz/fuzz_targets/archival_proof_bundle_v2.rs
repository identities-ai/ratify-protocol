#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::{verify_archival_proof_bundle_v2, FRESHNESS_UNVERIFIED_V2};

// Go FuzzVerifyArchivalProofBundleV2NeverPanics: archival verification of
// stored, possibly corrupted bytes never panics, is never actionable, is
// always freshness_unverified, and an accepted bundle carries its hash.
fuzz_target!(|data: &[u8]| {
    let result = verify_archival_proof_bundle_v2(data);
    assert!(!result.actionable, "archival result is actionable: {result:?}");
    assert_eq!(result.assessment, FRESHNESS_UNVERIFIED_V2, "archival result is not freshness_unverified");
    if result.error_class.is_none() {
        assert!(!result.bundle_hash.is_empty(), "accepted archival bundle has no bundle hash: {result:?}");
    }
    result.to_json().expect("archival result encodes");
});
