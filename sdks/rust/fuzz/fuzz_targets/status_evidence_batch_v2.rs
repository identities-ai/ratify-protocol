#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::{
    decode_v2_status_evidence_batch, encode_v2_status_evidence_batch, V2ErrorClass,
    MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2,
};

fuzz_target!(|data: &[u8]| {
    let decoded = match decode_v2_status_evidence_batch(data) {
        Ok(d) => d,
        Err(e) => {
            assert_eq!(e.class, V2ErrorClass::Malformed, "decode error is not malformed: {e}");
            return;
        }
    };
    assert!(decoded.objects.len() <= MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2);
    if let Ok(reencoded) = encode_v2_status_evidence_batch(&decoded) {
        let again = decode_v2_status_evidence_batch(&reencoded).expect("re-encoded batch decodes");
        assert_eq!(
            encode_v2_status_evidence_batch(&again).expect("stable"),
            reencoded,
            "batch round trip is not stable"
        );
    }
});
