//! Test-only §7.13 reference projection for the device-state corpus.

use ratify_protocol::v2::reference::{DevicePrimaryTestOnly, DeviceStateProjectionTestOnly};

use crate::error::FfiResult;
use crate::guard::call;

#[derive(uniffi::Record)]
pub struct FfiDeviceStateProjectionTestOnly {
    pub claims: Vec<u8>,
    pub streams: Vec<u8>,
    pub rate_counters: Vec<u8>,
    pub receipt_log: Vec<u8>,
    pub issuance_records: Vec<u8>,
    pub projection: Vec<u8>,
    pub complete_state_digest: Vec<u8>,
}

impl From<DeviceStateProjectionTestOnly> for FfiDeviceStateProjectionTestOnly {
    fn from(value: DeviceStateProjectionTestOnly) -> Self {
        Self {
            claims: value.claims,
            streams: value.streams,
            rate_counters: value.rate_counters,
            receipt_log: value.receipt_log,
            issuance_records: value.issuance_records,
            projection: value.projection,
            complete_state_digest: value.complete_state_digest,
        }
    }
}

#[uniffi::export]
pub fn ffi_device_state_projection_test_only(state_json: Vec<u8>) -> FfiResult<FfiDeviceStateProjectionTestOnly> {
    call(|| {
        let primary = DevicePrimaryTestOnly::from_records_test_only(&state_json)?;
        Ok(primary.projection_test_only()?.into())
    })
}
