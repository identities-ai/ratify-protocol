//! TestSupport access to the Rust Part B reference store.

use std::sync::Arc;

use ratify_protocol::v2::{ClaimStoreV2, V2AuthoritativeClock, V2CommittedClaimStore, V2Context,
    V2ReceiptPublisher, V2ReceiptCheckpoint, V2ReleaseClaimStore, V2StoreError};
use ratify_protocol::v2::reference::Store;

use crate::claim::{FfiChallengeClaim, FfiClaimResult, FfiCommittedClaim, FfiEvaluationProgress, FfiInterruptedClaim};
use crate::error::FfiResult;
use crate::guard::{call_with, call_on, Poison};
use crate::keys::FfiSoftwareKey;
use crate::release::{FfiCheckpointAcknowledgement, FfiReleaseRecord, FfiTerminalClaimRecord};

/// A store failure is data inside a guarded export, so Rust panics still use
/// FfiError::Internal and every UniFFI method retains the one-guard rule.
#[derive(uniffi::Record)]
pub struct FfiReferenceStoreFailure {
    pub kind: String,
    pub class: String,
    pub detail: String,
}

impl From<V2StoreError> for FfiReferenceStoreFailure {
    fn from(error: V2StoreError) -> Self {
        match error {
            V2StoreError::Classified(e) => Self { kind: "classified".into(), class: e.class.as_str().into(), detail: e.message },
            V2StoreError::Unavailable(detail) => Self { kind: "unavailable".into(), class: String::new(), detail },
            V2StoreError::ClaimProofConflict => Self::sentinel("claim_proof_conflict"),
            V2StoreError::RateLimitExceeded => Self::sentinel("rate_limit_exceeded"),
            V2StoreError::ReleaseStateMismatch => Self::sentinel("release_state_mismatch"),
            V2StoreError::AcknowledgementNotFound => Self::sentinel("acknowledgement_not_found"),
            V2StoreError::ChallengeIssuanceConflict => Self::sentinel("challenge_issuance_conflict"),
            V2StoreError::ChallengeIssuanceNotFound => Self::sentinel("challenge_issuance_not_found"),
        }
    }
}

impl FfiReferenceStoreFailure {
    fn sentinel(kind: &str) -> Self { Self { kind: kind.into(), class: String::new(), detail: String::new() } }
}

#[derive(Default, uniffi::Record)]
pub struct FfiReferenceStoreReply {
    pub time: Option<i64>,
    pub claim: Option<FfiClaimResult>,
    pub interrupted: Option<FfiInterruptedClaim>,
    pub committed: Option<FfiCommittedClaim>,
    pub terminal: Option<FfiTerminalClaimRecord>,
    pub receipt: Option<Vec<u8>>,
    pub acknowledgement: Option<FfiCheckpointAcknowledgement>,
    pub boolean: Option<bool>,
    pub failure: Option<FfiReferenceStoreFailure>,
}

#[derive(uniffi::Object)]
pub struct FfiReferenceStore {
    pub(crate) poison: Poison,
    pub(crate) inner: Arc<Store>,
}

impl FfiReferenceStore {
    fn reply<T>(result: Result<T, V2StoreError>, success: impl FnOnce(&mut FfiReferenceStoreReply, T)) -> FfiReferenceStoreReply {
        let mut reply = FfiReferenceStoreReply::default();
        match result {
            Ok(value) => success(&mut reply, value),
            Err(error) => reply.failure = Some(error.into()),
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FfiError;

    #[test]
    fn a_panicked_reference_handle_stays_poisoned() {
        let (_, key) = ratify_protocol::hybrid_keypair_from_seeds(&[1; 32], &[2; 32]);
        let store = FfiReferenceStore {
            poison: Poison::default(),
            inner: Arc::new(Store::new(100, 5, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &key).unwrap()),
        };
        let first: FfiResult<()> = call_on(&store.poison, || panic!("reference store panic"));
        assert!(matches!(first, Err(FfiError::Internal { kind, .. }) if kind == "panic"));
        assert!(matches!(store.authoritative_time(), Err(FfiError::Internal { kind, .. }) if kind == "poisoned"));
    }
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

    pub fn enable_rate_at_finalization(&self) -> FfiResult<()> {
        call_on(&self.poison, || {
            self.inner.with_rate_at_finalization();
            Ok(())
        })
    }

    pub fn set_time(&self, now: i64) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.set_time(now)))
    }

    pub fn corrupt_sealed_state_test_only(&self, claim_id: String) -> FfiResult<()> {
        call_on(&self.poison, || Ok(self.inner.corrupt_sealed_state_test_only(&claim_id)))
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

    pub fn authoritative_time(&self) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.authoritative_time_v2(&V2Context::background()),
            |reply, value| reply.time = Some(value))))
    }

    pub fn claim(&self, claim: FfiChallengeClaim) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.claim_v2(&V2Context::background(), claim.into()),
            |reply, value| reply.claim = Some(value.into()))))
    }

    pub fn finalize(&self, claim_id: String, owner_token: Vec<u8>, terminal_result: Vec<u8>,
                    receipt_body: Vec<u8>, allow_valid_until: i64) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.finalize_v2_claim(&V2Context::background(), &claim_id,
            &owner_token, &terminal_result, &receipt_body, allow_valid_until), |reply, value| reply.boolean = Some(value))))
    }

    pub fn record_progress(&self, claim_id: String, owner_token: Vec<u8>,
                           progress: FfiEvaluationProgress) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.record_v2_evaluation_progress(&V2Context::background(),
            &claim_id, &owner_token, progress.into()), |_, ()| {})))
    }

    pub fn load_interrupted(&self, claim_id: String) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.load_v2_interrupted_claim(&V2Context::background(), &claim_id),
            |reply, value| reply.interrupted = Some(value.into()))))
    }

    pub fn recover_interrupted(&self, claim_id: String, terminal_result: Vec<u8>,
                               receipt_body: Vec<u8>) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.recover_interrupted_v2_claim(&V2Context::background(),
            &claim_id, &terminal_result, &receipt_body), |reply, value| reply.boolean = Some(value))))
    }

    pub fn load_committed(&self, claim_id: String) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.load_v2_committed_claim(&V2Context::background(), &claim_id),
            |reply, value| reply.committed = Some(value.into()))))
    }

    pub fn load_terminal(&self, claim_id: String) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.load_v2_terminal_claim(&V2Context::background(), &claim_id),
            |reply, value| reply.terminal = Some(value.into()))))
    }

    pub fn record_release(&self, record: FfiReleaseRecord) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(record.try_into().and_then(|record| self.inner.record_v2_release(
            &V2Context::background(), record)), |_, ()| {})))
    }

    pub fn publish_receipt(&self, claim_id: String, receipt_body: Vec<u8>) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.publish_v2_receipt(&V2Context::background(),
            &claim_id, &receipt_body), |reply, value| reply.receipt = Some(value))))
    }

    pub fn acknowledge_receipt(&self, log_id: String, sequence: i64, previous_entry_hash: Vec<u8>,
                               entry_hash: Vec<u8>) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.acknowledge_v2_receipt(&V2Context::background(),
            &log_id, sequence, &previous_entry_hash, &entry_hash),
            |reply, value| reply.acknowledgement = Some(value.into()))))
    }

    pub fn get_acknowledgement(&self, log_id: String, sequence: i64) -> FfiResult<FfiReferenceStoreReply> {
        call_on(&self.poison, || Ok(Self::reply(self.inner.get_v2_acknowledgement(&V2Context::background(),
            &log_id, sequence), |reply, value| reply.acknowledgement = Some(value.into()))))
    }
}
