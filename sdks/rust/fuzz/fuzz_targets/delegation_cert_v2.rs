#![no_main]

use libfuzzer_sys::fuzz_target;
use ratify_protocol::v2::{decode_delegation_cert_v2, encode_delegation_cert_v2};
use ratify_protocol_fuzz::wire_roundtrip;

fuzz_target!(|data: &[u8]| wire_roundtrip(data, decode_delegation_cert_v2, encode_delegation_cert_v2));
