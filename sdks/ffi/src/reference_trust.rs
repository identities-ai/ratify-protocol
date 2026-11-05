//! Test and conformance access to the core reference trust registry.

use std::sync::Arc;

use ratify_protocol::v2::{reference::TrustRegistry, V2Context, V2ErrorClass};

use crate::error::{protocol, FfiResult};
use crate::guard::{call, call_on, Poison};
use crate::keys::FfiPublicKey;
use crate::live_providers::FfiTrustResolution;
use crate::objects::FfiDelegationCert;

#[derive(uniffi::Object)]
pub struct FfiReferenceTrustRegistry {
    inner: TrustRegistry,
    poison: Poison,
}

#[uniffi::export]
pub fn ffi_reference_trust_registry(records: Vec<FfiPublicKey>) -> FfiResult<Arc<FfiReferenceTrustRegistry>> {
    call(|| {
        let records = records.into_iter().map(Into::into).collect::<Vec<_>>();
        Ok(Arc::new(FfiReferenceTrustRegistry {
            inner: TrustRegistry::new(&records)?,
            poison: Poison::default(),
        }))
    })
}

#[uniffi::export]
impl FfiReferenceTrustRegistry {
    pub fn resolve(&self, chain: Vec<FfiDelegationCert>) -> FfiResult<FfiTrustResolution> {
        call_on(&self.poison, || {
            let chain = chain.into_iter().map(Into::into).collect::<Vec<_>>();
            let answer = self.inner.resolve(&V2Context::background(), &chain)
                .map_err(|e| protocol(V2ErrorClass::ConfigurationInvalid, e.to_string()))?;
            Ok(FfiTrustResolution {
                outcome: answer.outcome.as_str().into(),
                root_key: (&answer.root_key).into(),
            })
        })
    }
}
