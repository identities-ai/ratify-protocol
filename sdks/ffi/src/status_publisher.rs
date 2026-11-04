//! Signed status production through the anchored journal and an app signer.

use std::sync::Arc;

use ratify_protocol::v2::{
    self as core, V2StatusPublication, V2StatusPublisher, V2StatusPublisherState,
};

use crate::context::FfiCancelToken;
use crate::error::FfiResult;
use crate::guard::{call, call_on, call_with, Poison};
use crate::journal::{FfiJournalStore, ForeignJournalStore};
use crate::keys::{FfiPublicKey, FfiSoftwareKey};
use crate::objects::{FfiRevocationList, FfiRevocationPush};
use crate::sign::{FfiSigner, Foreign};

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusPublisherState {
    pub issuer_id: String,
    pub status_key_id: String,
    pub sequence: i64,
    pub updated_at: i64,
    pub revoked: Vec<String>,
}

impl From<FfiStatusPublisherState> for V2StatusPublisherState {
    fn from(s: FfiStatusPublisherState) -> Self {
        Self {
            issuer_id: s.issuer_id,
            status_key_id: s.status_key_id,
            sequence: s.sequence,
            updated_at: s.updated_at,
            revoked: s.revoked,
        }
    }
}

impl From<V2StatusPublisherState> for FfiStatusPublisherState {
    fn from(s: V2StatusPublisherState) -> Self {
        Self {
            issuer_id: s.issuer_id,
            status_key_id: s.status_key_id,
            sequence: s.sequence,
            updated_at: s.updated_at,
            revoked: s.revoked,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusPublication {
    pub state: FfiStatusPublisherState,
    pub list: FfiRevocationList,
    pub push: Option<FfiRevocationPush>,
}

impl From<V2StatusPublication> for FfiStatusPublication {
    fn from(p: V2StatusPublication) -> Self {
        Self {
            state: p.state.into(),
            list: (&p.list).into(),
            push: p.push.as_ref().map(Into::into),
        }
    }
}

#[derive(uniffi::Object)]
pub struct FfiStatusPublisher {
    poison: Poison,
    publisher: V2StatusPublisher,
}

#[uniffi::export]
pub fn ffi_new_status_publisher_with_key(
    store: Arc<dyn FfiJournalStore>,
    token: Arc<FfiCancelToken>,
    issuer_key: FfiPublicKey,
    status_key: Arc<FfiSoftwareKey>,
    lifetime_seconds: i64,
) -> FfiResult<Arc<FfiStatusPublisher>> {
    call_with(&[&status_key.poison], || {
        let publisher = core::new_v2_status_publisher_with_key(
            token.context(),
            &ForeignJournalStore(store),
            &issuer_key.into(),
            &status_key.private,
            lifetime_seconds,
        )?;
        Ok(Arc::new(FfiStatusPublisher {
            poison: Poison::default(),
            publisher,
        }))
    })
}

#[uniffi::export]
pub fn ffi_new_status_publisher_with_signer(
    store: Arc<dyn FfiJournalStore>,
    token: Arc<FfiCancelToken>,
    issuer_key: FfiPublicKey,
    status_signer: Arc<dyn FfiSigner>,
    lifetime_seconds: i64,
) -> FfiResult<Arc<FfiStatusPublisher>> {
    call(|| {
        let publisher = core::new_v2_status_publisher(
            token.context(),
            &ForeignJournalStore(store),
            &issuer_key.into(),
            Arc::new(Foreign(status_signer)),
            lifetime_seconds,
        )?;
        Ok(Arc::new(FfiStatusPublisher {
            poison: Poison::default(),
            publisher,
        }))
    })
}

#[uniffi::export]
impl FfiStatusPublisher {
    pub fn issuer_id(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.publisher.issuer_id().to_string()))
    }

    pub fn status_key(&self) -> FfiResult<FfiPublicKey> {
        call_on(&self.poison, || Ok((&self.publisher.status_key()).into()))
    }

    pub fn genesis(
        &self,
        token: Arc<FfiCancelToken>,
        updated_at: i64,
    ) -> FfiResult<FfiStatusPublication> {
        call_on(&self.poison, || {
            Ok(self.publisher.genesis(token.context(), updated_at)?.into())
        })
    }

    pub fn heartbeat(
        &self,
        token: Arc<FfiCancelToken>,
        state: FfiStatusPublisherState,
        updated_at: i64,
    ) -> FfiResult<FfiStatusPublication> {
        call_on(&self.poison, || {
            Ok(self
                .publisher
                .heartbeat(token.context(), &state.into(), updated_at)?
                .into())
        })
    }

    pub fn revoke(
        &self,
        token: Arc<FfiCancelToken>,
        state: FfiStatusPublisherState,
        cert_ids: Vec<String>,
        at: i64,
    ) -> FfiResult<FfiStatusPublication> {
        call_on(&self.poison, || {
            Ok(self
                .publisher
                .revoke(token.context(), &state.into(), &cert_ids, at)?
                .into())
        })
    }
}
