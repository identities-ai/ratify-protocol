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
