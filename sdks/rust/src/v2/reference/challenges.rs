//! The in-memory REFERENCE challenge issuance store. Mirrors Go
//! `v2reference/challenges.go`.
//!
//! TEST AND CONFORMANCE USE ONLY: it is not durable, does not survive a
//! restart, and does not span processes, so a verifier using it cannot claim
//! durable issuance or release conformance.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::v2::challenge_issuance::V2ChallengeIssuanceStore;
use crate::v2::claim_store::V2StoreError;
use crate::v2::context::V2Context;
use crate::v2::operation_context::challenge_claim_digest_v2;
use crate::v2::preflight::ExpectedChallengeV2;

/// The message of a scripted persistence failure (Go `ErrPersistFailed`).
pub const ERR_PERSIST_FAILED: &str = "v2reference: scripted issuance persistence failure";

/// Scripts the next `persist_v2_challenge` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PersistFault {
    /// Store the record normally.
    #[default]
    Ok,
    /// Fail without storing anything.
    FailBeforeCommit,
    /// Store the record, then report failure, as a crash after the durable
    /// write but before the response would.
    FailAfterCommit,
}

struct State {
    records: BTreeMap<String, ExpectedChallengeV2>,
    fault: PersistFault,
}

/// The in-memory reference [`V2ChallengeIssuanceStore`]. TEST ONLY.
pub struct TestOnlyChallengeIssuanceStore {
    state: Mutex<State>,
}

impl std::fmt::Debug for TestOnlyChallengeIssuanceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestOnlyChallengeIssuanceStore")
            .field("records", &self.len())
            .finish()
    }
}

impl Default for TestOnlyChallengeIssuanceStore {
    fn default() -> Self {
        Self::new()
    }
}

fn issuance_key(namespace: &str, epoch: i64, digest: &[u8]) -> String {
    format!("{}:{}|{}|{}", namespace.len(), namespace, epoch, hex::encode(digest))
}

impl TestOnlyChallengeIssuanceStore {
    /// An empty store.
    pub fn new() -> Self {
        TestOnlyChallengeIssuanceStore {
            state: Mutex::new(State {
                records: BTreeMap::new(),
                fault: PersistFault::Ok,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Arm a fault for the next `persist_v2_challenge` call only.
    pub fn fail_next_persist(&self, fault: PersistFault) {
        self.lock().fault = fault;
    }

    /// The number of stored records.
    pub fn len(&self) -> usize {
        self.lock().records.len()
    }

    /// Whether no record is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every stored record by issuance key (read by the single-device
    /// profile's complete-state digest, copy, and undo).
    pub(crate) fn records(&self) -> BTreeMap<String, ExpectedChallengeV2> {
        self.lock().records.clone()
    }

    /// Replace every stored record.
    pub(crate) fn set_records(&self, records: BTreeMap<String, ExpectedChallengeV2>) {
        self.lock().records = records;
    }
}

impl V2ChallengeIssuanceStore for TestOnlyChallengeIssuanceStore {
    /// Insert only, never overwrite.
    fn persist_v2_challenge(&self, _ctx: &V2Context, record: ExpectedChallengeV2) -> Result<(), V2StoreError> {
        let mut s = self.lock();
        let fault = std::mem::take(&mut s.fault);
        if fault == PersistFault::FailBeforeCommit {
            return Err(V2StoreError::Unavailable(ERR_PERSIST_FAILED.into()));
        }
        let digest = challenge_claim_digest_v2(&record.value)?;
        let key = issuance_key(&record.verifier_namespace, record.replay_epoch, &digest);
        if s.records.contains_key(&key) {
            return Err(V2StoreError::ChallengeIssuanceConflict);
        }
        s.records.insert(key, record);
        if fault == PersistFault::FailAfterCommit {
            return Err(V2StoreError::Unavailable(ERR_PERSIST_FAILED.into()));
        }
        Ok(())
    }

    fn load_v2_challenge(
        &self,
        _ctx: &V2Context,
        namespace: &str,
        replay_epoch: i64,
        claim_digest: &[u8],
    ) -> Result<ExpectedChallengeV2, V2StoreError> {
        self.lock()
            .records
            .get(&issuance_key(namespace, replay_epoch, claim_digest))
            .cloned()
            .ok_or(V2StoreError::ChallengeIssuanceNotFound)
    }
}
