//! Challenge issuance through the Part B clock, store and random callbacks.

use std::io::{Error as IoError, ErrorKind, Read};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use ratify_protocol::v2::{
    self as core, ExpectedChallengeV2, V2ChallengeIssuanceStore, V2ChallengeIssueRequest,
    V2ChallengeIssuer, V2Context, V2Error, V2ErrorClass, V2RandomSource, V2StoreError,
};

use crate::context::{FfiCancelToken, FfiContextPolicy};
use crate::error::FfiResult;
use crate::guard::call;
use crate::keys::FfiPublicKey;
use crate::store::{FfiAuthoritativeClock, FfiStoreContext, FfiStoreError, ForeignClock};

#[derive(uniffi::Record, Clone)]
pub struct FfiChallengeIssueRequest {
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub lifetime_seconds: i64,
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<FfiPublicKey>,
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
}

impl From<FfiChallengeIssueRequest> for V2ChallengeIssueRequest {
    fn from(r: FfiChallengeIssueRequest) -> Self {
        Self {
            verifier_namespace: r.verifier_namespace,
            replay_epoch: r.replay_epoch,
            verifier_id: r.verifier_id,
            lifetime_seconds: r.lifetime_seconds,
            expected_agent_id: r.expected_agent_id,
            expected_agent_public_key: r.expected_agent_public_key.map(Into::into),
            expected_receiver_id: r.expected_receiver_id,
            expected_session_context: r.expected_session_context,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiExpectedChallenge {
    pub value: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub verifier_namespace: String,
    pub replay_epoch: i64,
    pub verifier_id: String,
    pub expected_agent_id: String,
    pub expected_agent_public_key: Option<FfiPublicKey>,
    pub expected_receiver_id: String,
    pub expected_session_context: Option<Vec<u8>>,
    pub context_policy: Option<Arc<FfiContextPolicy>>,
}

impl From<ExpectedChallengeV2> for FfiExpectedChallenge {
    fn from(r: ExpectedChallengeV2) -> Self {
        Self {
            value: r.value,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            verifier_namespace: r.verifier_namespace,
            replay_epoch: r.replay_epoch,
            verifier_id: r.verifier_id,
            expected_agent_id: r.expected_agent_id,
            expected_agent_public_key: r.expected_agent_public_key.as_ref().map(Into::into),
            expected_receiver_id: r.expected_receiver_id,
            expected_session_context: r.expected_session_context,
            context_policy: r.context_policy.map(FfiContextPolicy::from_inner),
        }
    }
}

impl TryFrom<FfiExpectedChallenge> for ExpectedChallengeV2 {
    type Error = V2StoreError;

    fn try_from(r: FfiExpectedChallenge) -> Result<Self, Self::Error> {
        if r.context_policy.as_ref().is_some_and(|p| p.poison.is_set()) {
            return Err(V2StoreError::Unavailable(
                "context policy handle is poisoned".into(),
            ));
        }
        Ok(Self {
            value: r.value,
            issued_at: r.issued_at,
            expires_at: r.expires_at,
            verifier_namespace: r.verifier_namespace,
            replay_epoch: r.replay_epoch,
            verifier_id: r.verifier_id,
            expected_agent_id: r.expected_agent_id,
            expected_agent_public_key: r.expected_agent_public_key.map(Into::into),
            expected_receiver_id: r.expected_receiver_id,
            expected_session_context: r.expected_session_context,
            context_policy: r.context_policy.map(|p| p.inner.clone()),
        })
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiChallengeIssuanceStore: Send + Sync {
    fn persist(
        &self,
        record: FfiExpectedChallenge,
        context: Arc<FfiStoreContext>,
    ) -> Result<(), FfiStoreError>;
    fn load(
        &self,
        namespace: String,
        replay_epoch: i64,
        claim_digest: Vec<u8>,
        context: Arc<FfiStoreContext>,
    ) -> Result<FfiExpectedChallenge, FfiStoreError>;
}

struct ForeignChallengeStore(Arc<dyn FfiChallengeIssuanceStore>);

impl V2ChallengeIssuanceStore for ForeignChallengeStore {
    fn persist_v2_challenge(
        &self,
        ctx: &V2Context,
        record: ExpectedChallengeV2,
    ) -> Result<(), V2StoreError> {
        self.0
            .persist(record.into(), FfiStoreContext::new(ctx))
            .map_err(Into::into)
    }

    fn load_v2_challenge(
        &self,
        ctx: &V2Context,
        namespace: &str,
        replay_epoch: i64,
        claim_digest: &[u8],
    ) -> Result<ExpectedChallengeV2, V2StoreError> {
        self.0
            .load(
                namespace.into(),
                replay_epoch,
                claim_digest.to_vec(),
                FfiStoreContext::new(ctx),
            )
            .map_err(V2StoreError::from)?
            .try_into()
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiRandomError {
    #[error("{detail}")]
    Failed { detail: String },
    #[error("random callback cancelled")]
    Cancelled,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiRandomError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { detail: e.reason }
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiRandomSource: Send + Sync {
    fn fill(&self, count: u32, context: Arc<FfiStoreContext>) -> Result<Vec<u8>, FfiRandomError>;
}

struct ForeignRandom {
    source: Arc<dyn FfiRandomSource>,
    ctx: V2Context,
    cancelled: Arc<AtomicBool>,
}

impl Read for ForeignRandom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self
            .source
            .fill(buf.len() as u32, FfiStoreContext::new(&self.ctx))
            .map_err(|e| {
                if matches!(e, FfiRandomError::Cancelled) {
                    self.cancelled.store(true, Ordering::SeqCst);
                }
                IoError::other(e.to_string())
            })?;
        if bytes.len() != buf.len() {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "random callback returned the wrong byte count",
            ));
        }
        buf.copy_from_slice(&bytes);
        Ok(bytes.len())
    }
}

#[uniffi::export]
pub fn ffi_issue_challenge(
    clock: Arc<dyn FfiAuthoritativeClock>,
    store: Arc<dyn FfiChallengeIssuanceStore>,
    random: Option<Arc<dyn FfiRandomSource>>,
    token: Arc<FfiCancelToken>,
    request: FfiChallengeIssueRequest,
) -> FfiResult<FfiExpectedChallenge> {
    call(|| {
        let cancelled = Arc::new(AtomicBool::new(false));
        let source: Option<V2RandomSource> = random.map(|source| {
            Arc::new(Mutex::new(ForeignRandom {
                source,
                ctx: token.context().clone(),
                cancelled: cancelled.clone(),
            })) as V2RandomSource
        });
        let issuer = V2ChallengeIssuer {
            clock: Arc::new(ForeignClock(clock)),
            store: Arc::new(ForeignChallengeStore(store)),
            random: source,
        };
        let result = issuer.issue_challenge_v2(token.context(), &request.into());
        if token.context().is_done() || cancelled.load(Ordering::SeqCst) {
            return Err(V2Error::new(
                V2ErrorClass::EvaluationCancelled,
                "challenge issuance cancelled",
            )
            .into());
        }
        Ok(result?.into())
    })
}

#[uniffi::export]
pub fn ffi_load_expected_challenge(
    store: Arc<dyn FfiChallengeIssuanceStore>,
    token: Arc<FfiCancelToken>,
    namespace: String,
    replay_epoch: i64,
    challenge: Vec<u8>,
) -> FfiResult<FfiExpectedChallenge> {
    call(|| {
        let result = core::load_expected_challenge_v2(
            token.context(),
            &ForeignChallengeStore(store),
            &namespace,
            replay_epoch,
            &challenge,
        );
        if token.context().is_done() {
            return Err(V2Error::new(
                V2ErrorClass::EvaluationCancelled,
                "challenge load cancelled",
            )
            .into());
        }
        Ok(result?.into())
    })
}
