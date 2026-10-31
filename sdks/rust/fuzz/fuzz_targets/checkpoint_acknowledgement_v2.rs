#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::{
    decode_v2_checkpoint_acknowledgement, encode_v2_checkpoint_acknowledgement, V2ErrorClass,
};

fuzz_target!(|data: &[u8]| {
    match decode_v2_checkpoint_acknowledgement(data) {
        Ok(ack) => assert_eq!(
            encode_v2_checkpoint_acknowledgement(&ack).expect("accepted acknowledgement re-encodes"),
            data,
            "accepted acknowledgement does not re-encode identically"
        ),
        Err(e) => assert_eq!(e.class, V2ErrorClass::Malformed, "decode error is not malformed: {e}"),
    }
});
