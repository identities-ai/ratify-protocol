#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::ConstraintV2;

// ConstraintV2::decode accepts any JSON spelling of a valid constraint, so the
// property is decode -> canonical_json -> decode yields the same constraint
// and the same canonical bytes.
fuzz_target!(|data: &[u8]| {
    let Ok(c) = ConstraintV2::decode(data) else { return };
    let canonical = c.canonical_json().expect("decoded constraint must encode");
    let again = ConstraintV2::decode(&canonical).expect("canonical constraint must decode");
    assert_eq!(again, c, "round trip changed the constraint");
    assert_eq!(
        again.canonical_json().expect("re-encode"),
        canonical,
        "canonical form is not stable"
    );
});
