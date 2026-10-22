//! Shared properties for the v2 decoder fuzz targets.

use ratify_protocol::v2::V2Result;

/// Every v2 wire decoder is strict: a successful decode means the input is
/// the canonical encoding of the decoded object. So the object must re-encode
/// to exactly the input, and that encoding must decode and re-encode again to
/// the same bytes. Decoding itself must never panic.
pub fn wire_roundtrip<T>(data: &[u8], decode: fn(&[u8]) -> V2Result<T>, encode: fn(&T) -> V2Result<Vec<u8>>) {
    let Ok(value) = decode(data) else { return };
    let encoded = match encode(&value) {
        Ok(e) => e,
        Err(e) => panic!("decoded object does not re-encode: {e}"),
    };
    assert_eq!(encoded, data, "decoded object re-encodes to different bytes");
    let again = match decode(&encoded) {
        Ok(v) => v,
        Err(e) => panic!("re-encoding does not decode: {e}"),
    };
    match encode(&again) {
        Ok(e) => assert_eq!(e, encoded, "second round trip is not stable"),
        Err(e) => panic!("second decode does not re-encode: {e}"),
    }
}
