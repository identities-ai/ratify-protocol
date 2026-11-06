//! Shared Part B callback error and authoritative clock boundary.

use std::sync::Arc;

use ratify_protocol::v2::{V2AuthoritativeClock, V2Context, V2Error, V2ErrorClass, V2StoreError};

use crate::error::FfiResult;
use crate::guard::{call_on, Poison};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiStoreError {
    #[error("{detail} ({class})")]
    Classified { class: String, detail: String },
    #[error("{detail}")]
    Unavailable { detail: String },
    #[error("claim proof conflict")]
    ClaimProofConflict,
    #[error("rate limit exceeded")]
    RateLimitExceeded,
    #[error("release state mismatch")]
    ReleaseStateMismatch,
    #[error("acknowledgement not found")]
    AcknowledgementNotFound,
    #[error("challenge issuance conflict")]
    ChallengeIssuanceConflict,
    #[error("challenge issuance not found")]
    ChallengeIssuanceNotFound,
    #[error("callback cancelled")]
    Cancelled,
    /// Only the SDK adapter emits this when a nested guarded call failed.
    #[error("internal store callback failure")]
    Internal { kind: String, detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unavailable { detail: e.reason }
    }
}

impl From<FfiStoreError> for V2StoreError {
    fn from(e: FfiStoreError) -> Self {
        match e {
            FfiStoreError::Classified { class, detail } => match V2ErrorClass::parse(&class) {
                Some(class) => Self::Classified(V2Error::new(class, detail)),
                None => Self::Unavailable("store returned an unknown error class".into()),
            },
            FfiStoreError::Unavailable { detail } => Self::Unavailable(detail),
            FfiStoreError::ClaimProofConflict => Self::ClaimProofConflict,
            FfiStoreError::RateLimitExceeded => Self::RateLimitExceeded,
            FfiStoreError::ReleaseStateMismatch => Self::ReleaseStateMismatch,
            FfiStoreError::AcknowledgementNotFound => Self::AcknowledgementNotFound,
            FfiStoreError::ChallengeIssuanceConflict => Self::ChallengeIssuanceConflict,
            FfiStoreError::ChallengeIssuanceNotFound => Self::ChallengeIssuanceNotFound,
            FfiStoreError::Cancelled => Self::Classified(V2Error::new(
                V2ErrorClass::EvaluationCancelled,
                "store callback cancelled",
            )),
            FfiStoreError::Internal { .. } => panic!("an internal store callback failure crossed the guarded FFI boundary"),
        }
    }
}

#[derive(uniffi::Object)]
pub struct FfiStoreContext {
    poison: Poison,
    ctx: V2Context,
}

impl FfiStoreContext {
    pub(crate) fn new(ctx: &V2Context) -> Arc<Self> {
        Arc::new(Self {
            poison: Poison::default(),
            ctx: ctx.clone(),
        })
    }
}

#[uniffi::export]
impl FfiStoreContext {
    pub fn is_cancelled(&self) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.ctx.is_done()))
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiAuthoritativeClock: Send + Sync {
    fn authoritative_time(&self, context: Arc<FfiStoreContext>) -> Result<i64, FfiStoreError>;
}

pub(crate) struct ForeignClock(pub(crate) Arc<dyn FfiAuthoritativeClock>);

impl V2AuthoritativeClock for ForeignClock {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.0
            .authoritative_time(FfiStoreContext::new(ctx))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_internal_store_failure_stays_internal() {
        let outcome: FfiResult<()> = crate::guard::call(|| {
            let _: V2StoreError = FfiStoreError::Internal { kind: "poisoned".into(), detail: "nested handle".into() }.into();
            Ok(())
        });
        assert!(matches!(outcome, Err(crate::error::FfiError::Internal { kind, .. }) if kind == "panic"));
    }
}
