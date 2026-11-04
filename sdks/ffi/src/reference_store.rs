//! TestSupport access to the Rust Part B reference store.

use std::sync::Arc;

use ratify_protocol::v2::reference::Store;

use crate::error::FfiResult;
use crate::guard::{call_with, call_on, Poison};
use crate::keys::FfiSoftwareKey;

#[derive(uniffi::Object)]
pub struct FfiReferenceStore {
    poison: Poison,
    inner: Arc<Store>,
}

#[uniffi::export]
impl FfiReferenceStore {
    #[uniffi::constructor]
    pub fn new(now: i64, lease_seconds: i64, log_id: String, verifier_key: Arc<FfiSoftwareKey>) -> FfiResult<Arc<Self>> {
        call_with(&[&verifier_key.poison], || {
            Ok(Arc::new(Self {
                poison: Poison::default(),
                inner: Arc::new(Store::new(now, lease_seconds, &log_id, &verifier_key.private)?),
            }))
        })
    }

    pub fn clone_store(&self) -> FfiResult<Arc<Self>> {
        call_on(&self.poison, || Ok(Arc::new(Self {
            poison: Poison::default(),
            inner: Arc::new(self.inner.clone_store()),
        })))
    }

    pub fn set_time(&self, now: i64) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.set_time(now)))
    }

    pub fn now(&self) -> FfiResult<i64> {
        call_on(&self.poison, || Ok(self.inner.now()))
    }

    pub fn set_signer_failure(&self, failing: bool) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.set_signer_failure(failing)))
    }

    pub fn set_acknowledgement_withheld(&self, withheld: bool) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.set_acknowledgement_withheld(withheld)))
    }

    pub fn log_length(&self) -> FfiResult<u64> {
        call_on(&self.poison, || Ok(self.inner.log_length() as u64))
    }

    pub fn plant_release_test_only(&self, claim_id: String, ack_timestamp: i64) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.plant_release_test_only(&claim_id, ack_timestamp)))
    }

    pub fn abandon_pending_receipts(&self) -> FfiResult<Vec<String>> {
        call_on(&self.poison, || Ok(self.inner.abandon_pending_receipts()))
    }
}
