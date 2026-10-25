//! The in-memory REFERENCE implementation of the Protocol v2 Part B
//! deployment interfaces: claim store with stream sequence and evaluation
//! progress, authoritative clock, receipt outbox and publisher, independent
//! checkpoint, and optional rate admission at finalization. Mirrors Go
//! `v2reference/store.go`.
//!
//! FOR TESTS AND CONFORMANCE SCENARIOS ONLY. Nothing here is durable,
//! survives a restart, spans processes, or provides an independent failure
//! domain. A deployment that uses it in production has no replay protection
//! after a restart and no independent checkpoint, and must not release
//! decisions on its authority.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::types::HybridPrivateKey;
use crate::v2::checkpoint_ack::V2CheckpointAcknowledgement;
use crate::v2::claim_store::{
    challenge_claim_time_current_v2, validate_v2_finalization_payload, ClaimStoreV2, V2AuthoritativeClock, V2ChallengeClaim, V2ClaimDisposition,
    V2ClaimResult, V2RateAtFinalizationStore, V2RateReservationStore, V2StoreError,
};
use crate::v2::context::V2Context;
use crate::v2::crypto::{key_id_v2, public_key_v2};
use crate::v2::errors::{V2Error, V2ErrorClass, V2Result};
use crate::v2::evaluation_progress::{
    initial_v2_evaluation_progress, validate_v2_evaluation_progress_inner, V2EvaluationProgress,
    V2InterruptedClaim,
};
use crate::v2::rate_reservation::V2RateReservation;
use crate::v2::receipt::{
    encode_verification_receipt_v2, sign_prepared_verification_receipt_v2, verification_receipt_v2_digest,
    ReceiptV2Head,
};
use crate::v2::release::{
    receipt_outbox_digest_v2, valid_v2_release_record_outcome, V2ReceiptCheckpoint, V2ReceiptPublisher,
    V2ReleaseClaimStore, V2ReleaseRecord, V2ReleaseStatus, V2TerminalClaimRecord,
};
use crate::v2::stream_sequence::check_v2_stream_sequence;

/// The message of the reference checkpoint's refusal (Go
/// `ErrNotAcknowledged`).
pub const ERR_NOT_ACKNOWLEDGED: &str = "v2reference: checkpoint refused the acknowledgement";
/// Go `ErrHeadOfLineBlocked`: an earlier receipt-log entry of the same log is
/// still unpublished (SPEC-v2 §7.6, §7.7).
pub const ERR_HEAD_OF_LINE_BLOCKED: &str = "v2reference: an earlier receipt-log entry is still pending";
/// Go `ErrSignerUnavailable`: the reference signer is configured to fail.
pub const ERR_SIGNER_UNAVAILABLE: &str = "v2reference: receipt signer unavailable";
/// Go `ErrLogFrozen`: the log was abandoned.
pub const ERR_LOG_FROZEN: &str = "v2reference: the receipt log is frozen after abandonment";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimState {
    Evaluating,
    Terminal,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimRecord {
    pub claim: V2ChallengeClaim,
    pub owner_digest: [u8; 32],
    pub lease_expires_at: i64,
    pub state: ClaimState,
    pub terminal: Vec<u8>,
    pub receipt_body: Vec<u8>,
    pub allow_horizon: i64,
    pub claimed_at: i64,
    pub finalized_at: i64,
    pub release: Option<V2ReleaseRecord>,
    pub progress: V2EvaluationProgress,
    pub abandoned: bool,
    /// Index into the outbox; `None` until the terminal commit.
    pub outbox_index: Option<usize>,
}

/// One receipt-log position, assigned at terminal commit. `wire` is `None`
/// until the entry is signed and appended.
#[derive(Debug, Clone)]
pub(crate) struct OutboxEntry {
    pub claim_id: String,
    // Go keeps the committed body with its log position; it is read by the
    // durable-state digests of the offline-device profile.
    pub body: Vec<u8>,
    pub wire: Option<Vec<u8>>,
    pub digest: Vec<u8>,
    pub ack: Option<V2CheckpointAcknowledgement>,
}

/// The owner-token random source (Go `ownerTokenRand`).
pub(crate) type OwnerTokenRand = Arc<dyn Fn(&mut [u8]) -> Result<(), String> + Send + Sync>;

/// A durable security-state anchor (Go `anchor`): called with the state
/// before and after a change; an error undoes the change. It is set only by
/// the single-device offline profile and never copied by
/// [`Store::clone_store`].
pub(crate) type StoreAnchor = Arc<dyn Fn(&StoreState, &StoreState) -> Result<(), V2Error> + Send + Sync>;

/// The complete reference store state, guarded by one mutex.
#[derive(Clone)]
pub(crate) struct StoreState {
    pub now: i64,
    pub high_water: i64,
    pub lease_seconds: i64,
    pub claims: BTreeMap<String, ClaimRecord>,
    pub streams: BTreeMap<StreamKey, i64>,
    pub verifier_key: HybridPrivateKey,
    pub verifier_id: String,
    pub log_id: String,
    pub outbox: Vec<OutboxEntry>,
    pub ack_withheld: bool,
    pub log_frozen: bool,
    /// The reference checkpoint refused a fork for this log (SPEC-v2 §7.8)
    /// and acknowledges nothing further for it.
    pub checkpoint_frozen: bool,
    pub signer_failure: bool,
    pub rate_at_finalization: bool,
    pub rate_commits: BTreeMap<(String, String, i64), Vec<i64>>,
    pub owner_token_rand: OwnerTokenRand,
    pub anchor: Option<StoreAnchor>,
}

/// The reference Part B store. All methods are safe for concurrent use;
/// every operation runs under one mutex, which makes the claim and the
/// stream-sequence advance one atomic step, and terminal commit and outbox
/// sequence assignment another. TEST/REFERENCE ONLY.
pub struct Store {
    state: Mutex<StoreState>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.lock();
        f.debug_struct("Store")
            .field("now", &s.now)
            .field("claims", &s.claims.len())
            .field("log_length", &s.outbox.len())
            .finish_non_exhaustive()
    }
}

fn classified(class: V2ErrorClass, message: &str) -> V2StoreError {
    V2StoreError::Classified(V2Error::new(class, message))
}

impl Store {
    /// Go `NewStore`: a reference store whose authoritative clock starts at
    /// `now`, whose evaluator leases last `lease_seconds`, and whose receipt
    /// log `log_id` is signed by `verifier_key`.
    pub fn new(now: i64, lease_seconds: i64, log_id: &str, verifier_key: &HybridPrivateKey) -> V2Result<Store> {
        let id = key_id_v2(&public_key_v2(verifier_key)?)?;
        if lease_seconds <= 0 || log_id.len() != 32 {
            return Err(V2Error::new(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: lease must be positive and log ID 32 hex characters",
            ));
        }
        Ok(Store {
            state: Mutex::new(StoreState {
                now,
                high_water: now,
                lease_seconds,
                claims: BTreeMap::new(),
                streams: BTreeMap::new(),
                verifier_key: verifier_key.clone(),
                verifier_id: id,
                log_id: log_id.to_string(),
                outbox: Vec::new(),
                ack_withheld: false,
                log_frozen: false,
                checkpoint_frozen: false,
                signer_failure: false,
                rate_at_finalization: false,
                rate_commits: BTreeMap::new(),
                owner_token_rand: Arc::new(|buf: &mut [u8]| OsRng.try_fill_bytes(buf).map_err(|e| e.to_string())),
                anchor: None,
            }),
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, StoreState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Go `Clone`: an independent copy of the complete state, modelling a
    /// restore that exactly equals the anchored state. The anchor is not
    /// copied.
    pub fn clone_store(&self) -> Store {
        let mut copy = self.lock().clone();
        copy.anchor = None;
        Store {
            state: Mutex::new(copy),
        }
    }

    /// Go `SetTime`: set the authoritative clock. Tests may move it
    /// backward to exercise clock-regression handling.
    pub fn set_time(&self, now: i64) {
        self.lock().now = now;
    }

    /// Go `Now`: the clock setting without an authoritative reading.
    pub fn now(&self) -> i64 {
        self.lock().now
    }

    /// Go `SetSignerFailure`: make the reference receipt signer fail (or
    /// recover). A failed publication appends nothing.
    pub fn set_signer_failure(&self, failing: bool) {
        self.lock().signer_failure = failing;
    }

    /// Go `SetAcknowledgementWithheld`: stop (or resume) submitting appended
    /// entries to the checkpoint. Resuming acknowledges every pending entry
    /// in log order at the current clock.
    pub fn set_acknowledgement_withheld(&self, withheld: bool) {
        let mut s = self.lock();
        s.ack_withheld = withheld;
        if !withheld {
            s.acknowledge_pending_locked();
        }
    }

    /// Go `LogLength`: the number of appended (signed) receipts.
    pub fn log_length(&self) -> usize {
        self.lock().outbox.iter().take_while(|e| e.wire.is_some()).count()
    }

    /// Go `PlantReleaseTestOnly`: write a release record for `claim_id`
    /// directly, bypassing release and anchoring (models an attacker who can
    /// write the primary's storage).
    pub fn plant_release_test_only(&self, claim_id: &str, ack_timestamp: i64) {
        let mut s = self.lock();
        let entry_hash = s
            .claims
            .get(claim_id)
            .and_then(|r| r.outbox_index)
            .and_then(|i| s.outbox.get(i))
            .filter(|e| e.wire.is_some())
            .map(|e| e.digest.clone());
        if let (Some(entry_hash), Some(record)) = (entry_hash, s.claims.get_mut(claim_id)) {
            record.release = Some(V2ReleaseRecord {
                claim_id: claim_id.to_string(),
                entry_hash,
                ack_timestamp,
                outcome: V2ReleaseStatus::Released,
                reason: String::new(),
            });
        }
    }

    /// Go `AbandonPendingReceipts`: freeze the receipt log and mark every
    /// claim whose committed outbox entry was not yet appended as
    /// receipt_abandoned. Returns the abandoned claim IDs in log order.
    pub fn abandon_pending_receipts(&self) -> Vec<String> {
        let mut s = self.lock();
        let mut abandoned = Vec::new();
        let changed = s.change_locked(|s| {
            s.log_frozen = true;
            let pending: Vec<String> = s
                .outbox
                .iter()
                .filter(|e| e.wire.is_none())
                .map(|e| e.claim_id.clone())
                .collect();
            for claim_id in pending {
                if let Some(record) = s.claims.get_mut(&claim_id) {
                    record.abandoned = true;
                }
                abandoned.push(claim_id);
            }
        });
        if changed.is_err() {
            return Vec::new();
        }
        abandoned
    }

    /// Go `WithRateAtFinalization`: enable rate admission at finalization and
    /// return the view that advertises it. Use the view as both the claim
    /// store and the rate store.
    pub fn with_rate_at_finalization(self: &Arc<Self>) -> Arc<RateAtFinalizationStore> {
        self.lock().rate_at_finalization = true;
        Arc::new(RateAtFinalizationStore(Arc::clone(self)))
    }
}

/// Why the owner check of a live, evaluating claim failed; `Terminal` keeps
/// the record's committed payload for the identical-repeat comparison.
enum OwnerFailure {
    Failed(V2StoreError),
    Terminal(V2StoreError),
}

impl StoreState {
    /// Go `changeLocked`: apply `mutate` as one durable security-state
    /// change, anchored first when an anchor is configured.
    pub(crate) fn change_locked(&mut self, mutate: impl FnOnce(&mut StoreState)) -> Result<(), V2StoreError> {
        let Some(anchor) = self.anchor.clone() else {
            mutate(self);
            return Ok(());
        };
        let before = self.clone();
        mutate(self);
        if let Err(e) = anchor(&before, self) {
            self.claims = before.claims;
            self.streams = before.streams;
            self.outbox = before.outbox;
            self.rate_commits = before.rate_commits;
            self.log_frozen = before.log_frozen;
            return Err(classified(
                V2ErrorClass::ClaimStoreUnavailable,
                &format!("v2reference: durable state change was not anchored: {}", e.message),
            ));
        }
        Ok(())
    }

    /// Go `acknowledgePendingLocked`: submit every appended, unacknowledged
    /// entry to the reference checkpoint in log order. Acknowledgements are
    /// timestamped by one authoritative reading (SPEC-v2 §7.2), which
    /// advances the high-water mark; while the clock is regressed nothing is
    /// acknowledged.
    fn acknowledge_pending_locked(&mut self) {
        if self.checkpoint_frozen {
            return;
        }
        let mut now = None;
        for i in 0..self.outbox.len() {
            if self.outbox[i].wire.is_none() {
                return;
            }
            if self.outbox[i].ack.is_some() {
                continue;
            }
            let timestamp = match now {
                Some(t) => t,
                None => match self.read_clock_locked() {
                    Ok(t) => *now.insert(t),
                    Err(_) => return,
                },
            };
            let log_id = self.log_id.clone();
            let entry = &mut self.outbox[i];
            entry.ack = Some(V2CheckpointAcknowledgement {
                log_id,
                sequence: i as i64 + 1,
                entry_hash: entry.digest.clone(),
                timestamp,
            });
        }
    }

    /// Go `readClockLocked`: one authoritative reading; a reading below the
    /// greatest reading already returned is a clock regression.
    fn read_clock_locked(&mut self) -> Result<i64, V2StoreError> {
        if self.now < self.high_water {
            return Err(classified(
                V2ErrorClass::ClockRegressed,
                &format!(
                    "v2reference: authoritative clock {} is below its high-water mark {}",
                    self.now, self.high_water
                ),
            ));
        }
        self.high_water = self.now;
        Ok(self.now)
    }

    /// Go `ownerLocked`: the evaluator capability of a live, evaluating claim.
    fn owner_locked(&mut self, claim_id: &str, owner_token: &[u8]) -> Result<i64, OwnerFailure> {
        let Some(record) = self.claims.get(claim_id) else {
            return Err(OwnerFailure::Failed(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim")));
        };
        let digest: [u8; 32] = Sha256::digest(owner_token).into();
        if !constant_time_eq(&digest, &record.owner_digest) {
            return Err(OwnerFailure::Failed(classified(
                V2ErrorClass::ClaimLeaseLost,
                "v2reference: evaluator owner mismatch",
            )));
        }
        if record.state == ClaimState::Terminal {
            return Err(OwnerFailure::Terminal(classified(
                V2ErrorClass::ClaimAlreadyTerminal,
                "v2reference: claim already terminal",
            )));
        }
        let (claimed_at, lease_expires_at) = (record.claimed_at, record.lease_expires_at);
        let now = self.read_clock_locked().map_err(OwnerFailure::Failed)?;
        if now < claimed_at {
            return Err(OwnerFailure::Failed(classified(
                V2ErrorClass::ClockRegressed,
                &format!("v2reference: clock {now} is before T_claim {claimed_at}"),
            )));
        }
        if now >= lease_expires_at {
            return Err(OwnerFailure::Failed(classified(
                V2ErrorClass::ClaimLeaseLost,
                "v2reference: evaluator lease expired",
            )));
        }
        Ok(now)
    }

    /// Go `commitTerminalLocked`: make a terminal result immutable and assign
    /// its receipt-log position in the same critical section.
    fn commit_terminal_locked(&mut self, claim_id: &str, terminal: &[u8], body: &[u8], allow_horizon: i64, final_at: i64) {
        let index = self.outbox.len();
        if let Some(record) = self.claims.get_mut(claim_id) {
            record.state = ClaimState::Terminal;
            record.terminal = terminal.to_vec();
            record.receipt_body = body.to_vec();
            record.allow_horizon = allow_horizon;
            record.finalized_at = final_at;
            record.outbox_index = Some(index);
            self.outbox.push(OutboxEntry {
                claim_id: claim_id.to_string(),
                body: body.to_vec(),
                wire: None,
                digest: Vec::new(),
                ack: None,
            });
        }
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The durable stream-state key `(namespace, agent_id, stream_id)` of
/// SPEC-v2 §7.4, with the raw stream ID bytes. Its ordering is the §7.13
/// sort order: strings by UTF-8 bytes, then the stream ID by unsigned bytes.
pub(crate) type StreamKey = (String, String, Vec<u8>);

fn stream_key(claim: &V2ChallengeClaim) -> StreamKey {
    (
        claim.namespace.clone(),
        claim.agent_id.clone(),
        claim.stream_id.clone().unwrap_or_default(),
    )
}

impl V2AuthoritativeClock for Store {
    /// A regressed clock fails with `clock_regressed`.
    fn authoritative_time_v2(&self, _ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.lock().read_clock_locked()
    }
}

impl ClaimStoreV2 for Store {
    /// The atomic claim: authoritative clock reading (a regressed clock
    /// creates nothing and fails with `claim_store_unavailable`), replay key
    /// check, authoritative freshness recheck, stream-sequence advance, and
    /// insertion, all under one lock.
    fn claim_v2(&self, _ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
        let mut s = self.lock();
        if claim.claim_id.is_empty() {
            return Err(V2StoreError::Unavailable("v2reference: claim ID is required".into()));
        }
        let now = s
            .read_clock_locked()
            .map_err(|e| classified(V2ErrorClass::ClaimStoreUnavailable, &e.to_string()))?;
        if let Some(existing) = s.claims.get(&claim.claim_id) {
            if existing.claim != claim {
                return Err(V2StoreError::ClaimProofConflict);
            }
            if existing.abandoned {
                return Err(classified(
                    V2ErrorClass::ReceiptAbandoned,
                    "v2reference: the receipt for this claim was abandoned; a fresh challenge is required",
                ));
            }
            let disposition = if existing.state == ClaimState::Terminal {
                V2ClaimDisposition::TerminalReplay
            } else {
                V2ClaimDisposition::InProgress
            };
            return Ok(V2ClaimResult {
                disposition,
                claimed_at: existing.claimed_at,
                owner_token: Vec::new(),
            });
        }
        if !challenge_claim_time_current_v2(&claim, now) {
            return Err(classified(
                V2ErrorClass::ChallengeNotFresh,
                "v2reference: challenge is not current at the store clock",
            ));
        }
        let mut key: Option<StreamKey> = None;
        if claim.stream_id.is_some() || claim.stream_seq.is_some() {
            let Some(seq) = claim.stream_seq.filter(|_| claim.stream_id.is_some()) else {
                return Err(classified(
                    V2ErrorClass::Malformed,
                    "v2reference: stream_id and stream_seq must appear together",
                ));
            };
            let k = stream_key(&claim);
            let last = s.streams.get(&k).copied();
            key = Some(k);
            check_v2_stream_sequence(last.is_some(), last.unwrap_or_default(), seq)?;
        }
        let mut owner = vec![0u8; 32];
        (s.owner_token_rand)(&mut owner).map_err(V2StoreError::Unavailable)?;
        let owner_digest: [u8; 32] = Sha256::digest(&owner).into();
        let lease_expires_at = now + s.lease_seconds;
        s.change_locked(|s| {
            if let (Some(k), Some(seq)) = (&key, claim.stream_seq) {
                s.streams.insert(k.clone(), seq);
            }
            s.claims.insert(
                claim.claim_id.clone(),
                ClaimRecord {
                    claim: claim.clone(),
                    owner_digest,
                    lease_expires_at,
                    state: ClaimState::Evaluating,
                    terminal: Vec::new(),
                    receipt_body: Vec::new(),
                    allow_horizon: 0,
                    claimed_at: now,
                    finalized_at: 0,
                    release: None,
                    progress: initial_v2_evaluation_progress(),
                    abandoned: false,
                    outbox_index: None,
                },
            );
        })?;
        Ok(V2ClaimResult {
            disposition: V2ClaimDisposition::Created,
            claimed_at: now,
            owner_token: owner,
        })
    }

    /// Commit the evaluator's terminal result while its lease is live,
    /// reading T_final inside the same critical section. The receipt body
    /// must bind the sealed claim ([`validate_v2_finalization_payload`]:
    /// `malformed` or `configuration_invalid` otherwise, committing
    /// nothing). A regressed clock
    /// fails with `clock_regressed`; an allow is rejected at or beyond its
    /// horizon or the challenge expiry. With rate admission at finalization,
    /// an allow is admitted against the sealed rate batch here and fails
    /// with the exact [`V2StoreError::RateLimitExceeded`], committing
    /// nothing, when a counter is exhausted. An identical repeat returns
    /// `Ok(false)`.
    fn finalize_v2_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        let mut s = self.lock();
        let final_at = match s.owner_locked(claim_id, owner_token) {
            Ok(t) => t,
            Err(OwnerFailure::Terminal(e)) => {
                let identical = s
                    .claims
                    .get(claim_id)
                    .is_some_and(|r| r.terminal == terminal_result && r.receipt_body == receipt_body);
                return if identical { Ok(false) } else { Err(e) };
            }
            Err(OwnerFailure::Failed(e)) => return Err(e),
        };
        let Some(record) = s.claims.get(claim_id) else {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        };
        validate_v2_finalization_payload(&record.claim, terminal_result, receipt_body)?;
        // SPEC-v2 §6.8: an allow carries a positive allow horizon and every
        // other decision carries none, so the horizon and the rate admission
        // below always apply to exactly the allows.
        let decision = crate::v2::receipt::decode_verification_receipt_body_v2(receipt_body)?.decision;
        let horizon_ok = if decision == "allow" {
            allow_valid_until > 0 && allow_valid_until <= crate::v2::limits::V2_MAX_TIMESTAMP_SECONDS
        } else {
            allow_valid_until == 0
        };
        if !horizon_ok {
            return Err(classified(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: the allow horizon does not match the decision",
            ));
        }
        if allow_valid_until > 0 && (final_at >= allow_valid_until || final_at >= record.claim.expires_at) {
            return Err(classified(
                V2ErrorClass::AllowHorizonPassed,
                "v2reference: allow is at or beyond its horizon",
            ));
        }
        let batch: Vec<V2RateReservation> = record.claim.rate_batch.clone();
        let admit_rate = allow_valid_until > 0 && s.rate_at_finalization && !batch.is_empty();
        if admit_rate {
            for item in &batch {
                let key = (item.issuer_id.clone(), item.cert_id.clone(), item.window_s);
                let active = s
                    .rate_commits
                    .get(&key)
                    .map_or(0, |times| times.iter().filter(|&&at| at > final_at - item.window_s).count());
                if active as i64 >= item.limit {
                    return Err(V2StoreError::RateLimitExceeded);
                }
            }
        }
        s.change_locked(|s| {
            if admit_rate {
                for item in &batch {
                    s.rate_commits
                        .entry((item.issuer_id.clone(), item.cert_id.clone(), item.window_s))
                        .or_default()
                        .push(final_at);
                }
            }
            s.commit_terminal_locked(claim_id, terminal_result, receipt_body, allow_valid_until, final_at);
        })?;
        Ok(true)
    }

    /// The owner's progress is stored only while the claim is evaluating and
    /// its lease is live.
    fn record_v2_evaluation_progress(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        let mut s = self.lock();
        match s.owner_locked(claim_id, owner_token) {
            Ok(_) => {}
            Err(OwnerFailure::Failed(e)) | Err(OwnerFailure::Terminal(e)) => return Err(e),
        }
        if let Err(e) = validate_v2_evaluation_progress_inner(&progress) {
            return Err(V2StoreError::Classified(e.classify(V2ErrorClass::Malformed)));
        }
        s.change_locked(|s| {
            if let Some(record) = s.claims.get_mut(claim_id) {
                record.progress = progress;
            }
        })
    }

    /// Refuses while the lease is live, so the returned progress is final.
    /// A terminal claim is returned too (idempotent recovery).
    fn load_v2_interrupted_claim(&self, _ctx: &V2Context, claim_id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
        let mut s = self.lock();
        if !s.claims.contains_key(claim_id) {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        }
        let now = s.read_clock_locked()?;
        let Some(record) = s.claims.get(claim_id) else {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        };
        if record.state == ClaimState::Evaluating && now < record.lease_expires_at {
            return Err(classified(V2ErrorClass::ClaimLeaseLive, "v2reference: evaluator lease is still live"));
        }
        Ok(V2InterruptedClaim {
            claim: record.claim.clone(),
            claimed_at: record.claimed_at,
            progress: record.progress.clone(),
        })
    }

    /// Commit the canonical interrupted result after the lease expired. The
    /// result and receipt body are validated exactly as finalization
    /// validates them ([`validate_v2_finalization_payload`]: `malformed` or
    /// `configuration_invalid`), and the decision and reason must be
    /// `indeterminate` / `evaluation_interrupted` (`configuration_invalid`
    /// otherwise); a refused recovery commits nothing (SPEC-v2 §7.5).
    fn recover_interrupted_v2_claim(
        &self,
        _ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        let mut s = self.lock();
        let Some(record) = s.claims.get(claim_id) else {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        };
        if record.state == ClaimState::Terminal {
            if record.terminal == terminal_result && record.receipt_body == receipt_body {
                return Ok(false);
            }
            return Err(classified(V2ErrorClass::ClaimAlreadyTerminal, "v2reference: claim already terminal"));
        }
        let lease_expires_at = record.lease_expires_at;
        let now = s.read_clock_locked()?;
        if now < lease_expires_at {
            return Err(classified(V2ErrorClass::ClaimLeaseLive, "v2reference: evaluator lease is still live"));
        }
        let Some(record) = s.claims.get(claim_id) else {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        };
        validate_v2_finalization_payload(&record.claim, terminal_result, receipt_body)?;
        // The payload check above binds the terminal result's decision and
        // reason to the strictly decoded body, so the body names them.
        let body = crate::v2::receipt::decode_verification_receipt_body_v2(receipt_body)?;
        if body.decision != "indeterminate" || body.decision_reason != "evaluation_interrupted" {
            return Err(classified(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: recovery may commit only indeterminate/evaluation_interrupted",
            ));
        }
        s.change_locked(|s| s.commit_terminal_locked(claim_id, terminal_result, receipt_body, 0, now))?;
        Ok(true)
    }
}

impl V2ReleaseClaimStore for Store {
    fn load_v2_terminal_claim(&self, _ctx: &V2Context, claim_id: &str) -> Result<V2TerminalClaimRecord, V2StoreError> {
        let s = self.lock();
        let Some(record) = s.claims.get(claim_id) else {
            return Err(classified(V2ErrorClass::ClaimNotFound, "v2reference: unknown claim"));
        };
        let terminal = record.state == ClaimState::Terminal;
        Ok(V2TerminalClaimRecord {
            terminal,
            receipt_outbox_digest: if terminal {
                receipt_outbox_digest_v2(&record.receipt_body)
            } else {
                String::new()
            },
            challenge_expires_at: record.claim.expires_at,
            allow_horizon: record.allow_horizon,
            finalized_at: record.finalized_at,
            receipt_abandoned: record.abandoned,
            release: record.release.clone(),
        })
    }

    /// Records a release or a withheld result (SPEC-v2 §6.9): the first
    /// record for a claim wins, an identical repeat is a no-op, and any
    /// different record is [`V2StoreError::ReleaseStateMismatch`]. A new
    /// record is a durable security-state change, anchored like any other.
    fn record_v2_release(&self, _ctx: &V2Context, release: V2ReleaseRecord) -> Result<(), V2StoreError> {
        let mut s = self.lock();
        if !valid_v2_release_record_outcome(release.outcome, &release.reason) {
            return Err(classified(
                V2ErrorClass::ConfigurationInvalid,
                &format!(
                    "v2reference: invalid release record outcome {:?} reason {:?}",
                    release.outcome.as_str(),
                    release.reason
                ),
            ));
        }
        let Some(record) = s.claims.get(&release.claim_id) else {
            return Err(V2StoreError::ReleaseStateMismatch);
        };
        if record.state != ClaimState::Terminal {
            return Err(V2StoreError::ReleaseStateMismatch);
        }
        if let Some(existing) = &record.release {
            if existing.entry_hash == release.entry_hash
                && existing.ack_timestamp == release.ack_timestamp
                && existing.outcome == release.outcome
                && existing.reason == release.reason
            {
                return Ok(());
            }
            return Err(V2StoreError::ReleaseStateMismatch);
        }
        let claim_id = release.claim_id.clone();
        s.change_locked(|s| {
            if let Some(record) = s.claims.get_mut(&claim_id) {
                record.release = Some(release);
            }
        })
    }
}

impl V2ReceiptPublisher for Store {
    /// Sign and append the committed outbox body for `claim_id` at the log
    /// position assigned at terminal commit, or return the receipt already
    /// appended. A different body is refused, an earlier unpublished entry
    /// blocks it, and a failing signer or frozen log appends nothing.
    fn publish_v2_receipt(&self, _ctx: &V2Context, claim_id: &str, receipt_body: &[u8]) -> Result<Vec<u8>, V2StoreError> {
        let mut s = self.lock();
        let index = match s.claims.get(claim_id) {
            Some(r) if r.state == ClaimState::Terminal && r.receipt_body == receipt_body => r.outbox_index,
            _ => None,
        };
        let Some(index) = index.filter(|&i| i < s.outbox.len()) else {
            return Err(V2StoreError::Unavailable(
                "v2reference: no committed outbox body for this claim matches".into(),
            ));
        };
        if let Some(wire) = s.outbox.get(index).and_then(|e| e.wire.clone()) {
            return Ok(wire);
        }
        if s.log_frozen {
            return Err(V2StoreError::Unavailable(ERR_LOG_FROZEN.into()));
        }
        if index > 0 && s.outbox.get(index - 1).is_some_and(|e| e.wire.is_none()) {
            return Err(V2StoreError::Unavailable(ERR_HEAD_OF_LINE_BLOCKED.into()));
        }
        if s.signer_failure {
            return Err(V2StoreError::Unavailable(ERR_SIGNER_UNAVAILABLE.into()));
        }
        let mut head = ReceiptV2Head {
            log_id: s.log_id.clone(),
            verifier_id: s.verifier_id.clone(),
            sequence: index as i64,
            head_hash: vec![0; 48],
            accepted_digests: BTreeMap::new(),
            frozen: false,
        };
        for (i, entry) in s.outbox.iter().take(index).enumerate() {
            head.accepted_digests.insert(i as i64 + 1, entry.digest.clone());
        }
        if index > 0 {
            if let Some(previous) = s.outbox.get(index - 1) {
                head.head_hash = previous.digest.clone();
            }
        }
        let receipt = sign_prepared_verification_receipt_v2(receipt_body, &head, &s.verifier_key)
            .map_err(|e| V2StoreError::Unavailable(e.to_string()))?;
        let wire = encode_verification_receipt_v2(&receipt).map_err(V2StoreError::Classified)?;
        let digest = verification_receipt_v2_digest(&receipt).map_err(V2StoreError::Classified)?;
        let stored = wire.clone();
        s.change_locked(|s| {
            if let Some(entry) = s.outbox.get_mut(index) {
                entry.wire = Some(stored);
                entry.digest = digest;
            }
        })?;
        if !s.ack_withheld {
            s.acknowledge_pending_locked();
        }
        Ok(wire)
    }
}

impl V2ReceiptCheckpoint for Store {
    /// Accept only the next appended entry of the log, linked by
    /// `previous_entry_hash`, and return the original acknowledgement for an
    /// identical retry. A different entry hash at an acknowledged sequence is
    /// a fork (SPEC-v2 §7.8): it is refused and freezes the log, after which
    /// the checkpoint acknowledges nothing further for it, neither here nor
    /// from the publisher's submissions. Identical retries of
    /// acknowledgements made before the fork still return the original
    /// acknowledgement.
    fn acknowledge_v2_receipt(
        &self,
        _ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let mut s = self.lock();
        let refused = || V2StoreError::Unavailable(ERR_NOT_ACKNOWLEDGED.into());
        if log_id != s.log_id || sequence < 1 || sequence as usize > s.outbox.len() {
            return Err(refused());
        }
        let index = sequence as usize - 1;
        let acked = s.outbox[index].ack.as_ref().map(|a| a.entry_hash.clone());
        if acked.as_ref().is_some_and(|h| h != entry_hash) {
            s.checkpoint_frozen = true;
            return Err(V2StoreError::Unavailable(format!(
                "{ERR_NOT_ACKNOWLEDGED}: a different entry hash at acknowledged sequence {sequence} is a fork; the log is frozen"
            )));
        }
        if s.checkpoint_frozen && acked.is_none() {
            return Err(V2StoreError::Unavailable(format!(
                "{ERR_NOT_ACKNOWLEDGED}: the log is frozen after a fork"
            )));
        }
        match s.outbox.get(index) {
            Some(e) if e.wire.is_some() && e.digest == entry_hash => {}
            _ => return Err(refused()),
        }
        let mut previous = vec![0u8; 48];
        if index > 0 {
            match s.outbox.get(index - 1) {
                Some(p) if p.ack.is_some() => previous = p.digest.clone(),
                _ => return Err(refused()),
            }
        }
        if previous != previous_entry_hash {
            return Err(refused());
        }
        if s.outbox[index].ack.is_none() {
            let now = s.read_clock_locked()?;
            let entry = s.outbox.get_mut(index).ok_or_else(refused)?;
            entry.ack = Some(V2CheckpointAcknowledgement {
                log_id: log_id.to_string(),
                sequence,
                entry_hash: entry_hash.to_vec(),
                timestamp: now,
            });
        }
        s.outbox[index].ack.clone().ok_or_else(refused)
    }

    fn get_v2_acknowledgement(
        &self,
        _ctx: &V2Context,
        log_id: &str,
        sequence: i64,
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let s = self.lock();
        if log_id != s.log_id || sequence < 1 {
            return Err(V2StoreError::AcknowledgementNotFound);
        }
        s.outbox
            .get(sequence as usize - 1)
            .and_then(|e| e.ack.clone())
            .ok_or(V2StoreError::AcknowledgementNotFound)
    }
}

/// The reference store with `max_rate` admission moved into the
/// finalization compare-and-set ([`V2RateAtFinalizationStore`]). Use it as
/// both the claim store and the rate store.
#[derive(Debug)]
pub struct RateAtFinalizationStore(pub Arc<Store>);

impl V2AuthoritativeClock for RateAtFinalizationStore {
    fn authoritative_time_v2(&self, ctx: &V2Context) -> Result<i64, V2StoreError> {
        self.0.authoritative_time_v2(ctx)
    }
}

impl ClaimStoreV2 for RateAtFinalizationStore {
    fn claim_v2(&self, ctx: &V2Context, claim: V2ChallengeClaim) -> Result<V2ClaimResult, V2StoreError> {
        self.0.claim_v2(ctx, claim)
    }
    fn finalize_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        terminal_result: &[u8],
        receipt_body: &[u8],
        allow_valid_until: i64,
    ) -> Result<bool, V2StoreError> {
        self.0
            .finalize_v2_claim(ctx, claim_id, owner_token, terminal_result, receipt_body, allow_valid_until)
    }
    fn record_v2_evaluation_progress(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        owner_token: &[u8],
        progress: V2EvaluationProgress,
    ) -> Result<(), V2StoreError> {
        self.0.record_v2_evaluation_progress(ctx, claim_id, owner_token, progress)
    }
    fn load_v2_interrupted_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2InterruptedClaim, V2StoreError> {
        self.0.load_v2_interrupted_claim(ctx, claim_id)
    }
    fn recover_interrupted_v2_claim(
        &self,
        ctx: &V2Context,
        claim_id: &str,
        terminal_result: &[u8],
        receipt_body: &[u8],
    ) -> Result<bool, V2StoreError> {
        self.0.recover_interrupted_v2_claim(ctx, claim_id, terminal_result, receipt_body)
    }
    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        Some(self)
    }
}

impl V2RateReservationStore for RateAtFinalizationStore {
    /// Exists only to satisfy [`V2RateReservationStore`]. The verifier never
    /// calls it for a store that admits at finalization, and it always fails
    /// (SPEC-v2 §7.1, §7.6).
    fn reserve_v2_rate_batch(
        &self,
        _ctx: &V2Context,
        _claim_id: &str,
        _owner_token: &[u8],
        _bundle_hash: &str,
        _batch: &[V2RateReservation],
    ) -> Result<(), V2StoreError> {
        Err(V2StoreError::Unavailable(
            "v2reference: provisional rate reservation is not used with admission at finalization".into(),
        ))
    }
    fn rate_at_finalization_view(&self) -> Option<&dyn V2RateAtFinalizationStore> {
        Some(self)
    }
}

impl V2RateAtFinalizationStore for RateAtFinalizationStore {
    fn admits_v2_rate_at_finalization(&self) {}
}

impl V2ReleaseClaimStore for RateAtFinalizationStore {
    fn load_v2_terminal_claim(&self, ctx: &V2Context, claim_id: &str) -> Result<V2TerminalClaimRecord, V2StoreError> {
        self.0.load_v2_terminal_claim(ctx, claim_id)
    }
    fn record_v2_release(&self, ctx: &V2Context, record: V2ReleaseRecord) -> Result<(), V2StoreError> {
        self.0.record_v2_release(ctx, record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_hybrid_keypair;

    // The reference store admits max_rate inside its terminal compare-and-set
    // (SPEC-v2 §7.1, §7.6). Its provisional reservation call exists only to
    // satisfy the rate-store interface and must never report capacity: if a
    // verifier ever called it, the result has to fail closed.
    #[test]
    fn rate_at_finalization_store_never_reserves_provisionally() {
        let (_, private) = generate_hybrid_keypair();
        let store = Arc::new(Store::new(1_800_000_000, 30, "dddddddddddddddddddddddddddddd01", &private).unwrap())
            .with_rate_at_finalization();
        let batch = [V2RateReservation {
            issuer_id: "i".into(),
            cert_id: "c".into(),
            window_s: 60,
            limit: 1,
        }];
        let reserved = store.reserve_v2_rate_batch(&V2Context::background(), "claim", &[0; 32], "sha384:x", &batch);
        assert!(reserved.is_err(), "the reference provisional reservation reported capacity");
    }
}
