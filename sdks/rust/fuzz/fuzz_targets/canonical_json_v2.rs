#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::canonical_json_v2;

// Canonicalization never panics, and canonical output is a fixed point.
fuzz_target!(|data: &[u8]| {
    let Ok(canonical) = canonical_json_v2(data) else { return };
    let again = canonical_json_v2(&canonical).expect("canonical output must canonicalize");
    assert_eq!(again, canonical, "canonical_json_v2 is not idempotent");
});
