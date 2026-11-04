//! Receipt publication and the only actionable decision boundary.

use std::sync::Arc;

use ratify_protocol::v2::{self as core, V2AuthoritativeClock, V2Context, V2ReceiptCheckpoint,
    V2ReceiptPublisher, V2ReleaseClaimStore, V2StoreError};

use crate::context::FfiCancelToken;
use crate::error::FfiResult;
use crate::guard::{call, call_on, call_with, Poison};
use crate::keys::FfiPublicKey;
use crate::objects::FfiVerificationReceipt;
use crate::store::{FfiAuthoritativeClock, FfiStoreContext, FfiStoreError, ForeignClock};

#[derive(uniffi::Record, Clone)]
pub struct FfiReleaseRecord {
    pub claim_id: String,
    pub entry_hash: Vec<u8>,
    pub ack_timestamp: i64,
    pub outcome: String,
    pub reason: String,
}

impl From<core::V2ReleaseRecord> for FfiReleaseRecord {
    fn from(r: core::V2ReleaseRecord) -> Self {
        Self { claim_id: r.claim_id, entry_hash: r.entry_hash, ack_timestamp: r.ack_timestamp,
            outcome: r.outcome.as_str().into(), reason: r.reason }
    }
}

impl TryFrom<FfiReleaseRecord> for core::V2ReleaseRecord {
    type Error = V2StoreError;
    fn try_from(r: FfiReleaseRecord) -> Result<Self, Self::Error> {
        let outcome = parse_status(&r.outcome)?;
        Ok(Self { claim_id: r.claim_id, entry_hash: r.entry_hash, ack_timestamp: r.ack_timestamp,
            outcome, reason: r.reason })
    }
}

fn parse_status(value: &str) -> Result<core::V2ReleaseStatus, V2StoreError> {
    match value {
        "released" => Ok(core::V2ReleaseStatus::Released),
        "pending" => Ok(core::V2ReleaseStatus::Pending),
        "withheld" => Ok(core::V2ReleaseStatus::Withheld),
        "rejected" => Ok(core::V2ReleaseStatus::Rejected),
        _ => Err(V2StoreError::Unavailable("release store returned an unknown status".into())),
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiTerminalClaimRecord {
    pub terminal: bool,
    pub receipt_outbox_digest: String,
    pub challenge_expires_at: i64,
    pub allow_horizon: i64,
    pub finalized_at: i64,
    pub receipt_abandoned: bool,
    pub release: Option<FfiReleaseRecord>,
}

impl From<core::V2TerminalClaimRecord> for FfiTerminalClaimRecord {
    fn from(r: core::V2TerminalClaimRecord) -> Self {
        Self { terminal: r.terminal, receipt_outbox_digest: r.receipt_outbox_digest,
            challenge_expires_at: r.challenge_expires_at, allow_horizon: r.allow_horizon,
            finalized_at: r.finalized_at, receipt_abandoned: r.receipt_abandoned,
            release: r.release.map(Into::into) }
    }
}

impl TryFrom<FfiTerminalClaimRecord> for core::V2TerminalClaimRecord {
    type Error = V2StoreError;
    fn try_from(r: FfiTerminalClaimRecord) -> Result<Self, Self::Error> {
        Ok(Self { terminal: r.terminal, receipt_outbox_digest: r.receipt_outbox_digest,
            challenge_expires_at: r.challenge_expires_at, allow_horizon: r.allow_horizon,
            finalized_at: r.finalized_at, receipt_abandoned: r.receipt_abandoned,
            release: r.release.map(TryInto::try_into).transpose()? })
    }
}

#[derive(uniffi::Record, Clone)]
pub struct FfiCheckpointAcknowledgement {
    pub log_id: String,
    pub sequence: i64,
    pub entry_hash: Vec<u8>,
    pub timestamp: i64,
}

impl From<core::V2CheckpointAcknowledgement> for FfiCheckpointAcknowledgement {
    fn from(a: core::V2CheckpointAcknowledgement) -> Self {
        Self { log_id: a.log_id, sequence: a.sequence, entry_hash: a.entry_hash, timestamp: a.timestamp }
    }
}
impl From<FfiCheckpointAcknowledgement> for core::V2CheckpointAcknowledgement {
    fn from(a: FfiCheckpointAcknowledgement) -> Self {
        Self { log_id: a.log_id, sequence: a.sequence, entry_hash: a.entry_hash, timestamp: a.timestamp }
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiReceiptPublisher: Send + Sync {
    fn publish(&self, claim_id: String, receipt_body: Vec<u8>,
        context: Arc<FfiStoreContext>) -> Result<Vec<u8>, FfiStoreError>;
}

struct ForeignPublisher(Arc<dyn FfiReceiptPublisher>);
impl V2ReceiptPublisher for ForeignPublisher {
    fn publish_v2_receipt(&self, ctx: &V2Context, claim_id: &str, body: &[u8]) -> Result<Vec<u8>, V2StoreError> {
        self.0.publish(claim_id.into(), body.into(), FfiStoreContext::new(ctx)).map_err(Into::into)
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiReleaseClaimStore: Send + Sync {
    fn authoritative_time(&self, context: Arc<FfiStoreContext>) -> Result<i64, FfiStoreError>;
    fn load_terminal(&self, claim_id: String,
        context: Arc<FfiStoreContext>) -> Result<FfiTerminalClaimRecord, FfiStoreError>;
    fn record_release(&self, record: FfiReleaseRecord,
        context: Arc<FfiStoreContext>) -> Result<(), FfiStoreError>;
}

struct ForeignReleaseStore(Arc<dyn FfiReleaseClaimStore>);
impl V2AuthoritativeClock for ForeignReleaseStore {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.0.authoritative_time(FfiStoreContext::new(ctx)).map_err(Into::into)
    }
}
impl V2ReleaseClaimStore for ForeignReleaseStore {
    fn load_v2_terminal_claim(&self, ctx: &V2Context, id: &str) -> Result<core::V2TerminalClaimRecord, V2StoreError> {
        self.0.load_terminal(id.into(), FfiStoreContext::new(ctx)).map_err(V2StoreError::from)?.try_into()
    }
    fn record_v2_release(&self, ctx: &V2Context, record: core::V2ReleaseRecord) -> Result<(), V2StoreError> {
        self.0.record_release(record.into(), FfiStoreContext::new(ctx)).map_err(Into::into)
    }
}

#[uniffi::export(with_foreign)]
pub trait FfiReceiptCheckpoint: Send + Sync {
    fn acknowledge(&self, log_id: String, sequence: i64, previous_entry_hash: Vec<u8>,
        entry_hash: Vec<u8>, context: Arc<FfiStoreContext>) -> Result<FfiCheckpointAcknowledgement, FfiStoreError>;
    fn get(&self, log_id: String, sequence: i64,
        context: Arc<FfiStoreContext>) -> Result<FfiCheckpointAcknowledgement, FfiStoreError>;
}

struct ForeignCheckpoint(Arc<dyn FfiReceiptCheckpoint>);
impl V2ReceiptCheckpoint for ForeignCheckpoint {
    fn acknowledge_v2_receipt(&self, ctx: &V2Context, log_id: &str, sequence: i64,
        previous_entry_hash: &[u8], entry_hash: &[u8]) -> Result<core::V2CheckpointAcknowledgement, V2StoreError> {
        self.0.acknowledge(log_id.into(), sequence, previous_entry_hash.into(), entry_hash.into(),
            FfiStoreContext::new(ctx)).map(Into::into).map_err(Into::into)
    }
    fn get_v2_acknowledgement(&self, ctx: &V2Context, log_id: &str, sequence: i64)
        -> Result<core::V2CheckpointAcknowledgement, V2StoreError> {
        self.0.get(log_id.into(), sequence, FfiStoreContext::new(ctx)).map(Into::into).map_err(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct FfiReleasedDecision { poison: Poison, inner: core::V2ReleasedDecision }
impl FfiReleasedDecision {
    fn new(inner: core::V2ReleasedDecision) -> Arc<Self> { Arc::new(Self { poison: Poison::default(), inner }) }
}

#[uniffi::export]
impl FfiReleasedDecision {
    pub fn claim_id(&self) -> FfiResult<String> { call_on(&self.poison, || Ok(self.inner.claim_id())) }
    pub fn decision(&self) -> FfiResult<String> { call_on(&self.poison, || Ok(self.inner.decision())) }
    pub fn reason(&self) -> FfiResult<String> { call_on(&self.poison, || Ok(self.inner.reason())) }
    pub fn identity_status(&self) -> FfiResult<String> { call_on(&self.poison, || Ok(self.inner.identity_status())) }
    pub fn granted_scope(&self) -> FfiResult<Vec<String>> { call_on(&self.poison, || Ok(self.inner.granted_scope())) }
    pub fn receipt_wire(&self) -> FfiResult<Vec<u8>> { call_on(&self.poison, || Ok(self.inner.receipt_wire())) }
    pub fn receipt(&self) -> FfiResult<FfiVerificationReceipt> {
        call_on(&self.poison, || Ok(FfiVerificationReceipt::from(&self.inner.receipt()?)))
    }
    pub fn release_time(&self) -> FfiResult<i64> { call_on(&self.poison, || Ok(self.inner.release_time())) }
    pub fn challenge_expires_at(&self) -> FfiResult<i64> { call_on(&self.poison, || Ok(self.inner.challenge_expires_at())) }
    pub fn allow_horizon(&self) -> FfiResult<Option<i64>> { call_on(&self.poison, || Ok(self.inner.allow_horizon())) }
    pub fn allowed(&self, clock: Arc<dyn FfiAuthoritativeClock>, token: Arc<FfiCancelToken>) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.inner.allowed(token.context(), &ForeignClock(clock))))
    }
}

#[derive(uniffi::Record)]
pub struct FfiReleaseResult {
    pub status: String,
    pub reason: String,
    pub decision: Option<Arc<FfiReleasedDecision>>,
}

#[uniffi::export]
pub fn ffi_publish_receipt(publisher: Arc<dyn FfiReceiptPublisher>, claim_id: String,
    receipt_body: Vec<u8>, token: Arc<FfiCancelToken>) -> FfiResult<Vec<u8>> {
    call(|| ForeignPublisher(publisher).publish_v2_receipt(token.context(), &claim_id, &receipt_body)
        .map_err(|e| crate::error::protocol(e.class().unwrap_or(core::V2ErrorClass::ClaimStoreUnavailable), format!("{e:?}"))))
}

#[uniffi::export]
pub fn ffi_release_decision(committed: Arc<crate::claim::FfiCommittedOutcome>,
    signed_receipt: Option<Vec<u8>>, verifier_public_key: FfiPublicKey, log_id: String,
    claim_store: Arc<dyn FfiReleaseClaimStore>, checkpoint: Arc<dyn FfiReceiptCheckpoint>,
    token: Arc<FfiCancelToken>) -> FfiResult<FfiReleaseResult> {
    call_with(&[&committed.poison], || {
        let store = ForeignReleaseStore(claim_store);
        let checkpoint = ForeignCheckpoint(checkpoint);
        let key = verifier_public_key.into();
        let result = core::release_v2_decision(token.context(), &committed.inner, signed_receipt.as_deref(),
            core::V2ReleaseConfig { verifier_public_key: &key, log_id: &log_id,
                claim_store: &store, checkpoint: &checkpoint });
        Ok(FfiReleaseResult { status: result.status.as_str().into(), reason: result.reason.clone(),
            decision: result.into_decision().map(FfiReleasedDecision::new) })
    })
}

#[uniffi::export]
pub fn ffi_receipt_outbox_digest(body: Vec<u8>) -> FfiResult<String> {
    call(|| Ok(core::receipt_outbox_digest_v2(&body)))
}

#[uniffi::export]
pub fn ffi_valid_release_record_outcome(outcome: String, reason: String) -> FfiResult<bool> {
    call(|| Ok(parse_status(&outcome).is_ok_and(|status| core::valid_v2_release_record_outcome(status, &reason))))
}
