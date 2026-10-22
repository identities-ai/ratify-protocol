//! Complete security state of a single-device offline primary (SPEC-v2
//! §7.13), TEST ONLY. Mirrors Go `v2reference/device_state.go`.
//!
//! [`DevicePrimaryTestOnly`] groups every durable security record the
//! primary holds: the claim store with its release records, stream
//! sequences, rate counters and receipt log ([`Store`]), its anchored
//! `SecurityJournalV2` store, its challenge issuance records, and its replay
//! epoch. Its complete-state digest is a labelled SHA-384 over a versioned
//! canonical projection of all of them. Once bound to a device component,
//! every durable change in any of these stores is anchored in the component
//! before it takes effect; a change the component refuses is undone.
//!
//! SPEC-v2 §7.13 leaves the byte encoding of a record within a member
//! implementation-defined (only the device and its own component compare the
//! digest). Go digests its records with `json.Marshal`; this port digests
//! the derived `Debug` rendering, which carries every field of the record.

use std::fmt::Debug;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::json;
use sha2::{Digest, Sha384};

use super::challenges::TestOnlyChallengeIssuanceStore;
use super::journal::JournalStore;
use super::offline_device::DeviceComponentTestOnly;
use super::store::{ClaimState, Store, StoreAnchor, StoreState};
use crate::v2::challenge_issuance::V2ChallengeIssuanceStore;
use crate::v2::claim_store::V2StoreError;
use crate::v2::context::V2Context;
use crate::v2::errors::{V2Error, V2ErrorClass, V2Result};
use crate::v2::journal::{
    SecurityJournalHeadV2, SecurityJournalStoreErrorV2, SecurityJournalStoreV2, SecurityJournalV2,
};
use crate::v2::json::canonical_json_v2;
use crate::v2::preflight::ExpectedChallengeV2;

/// The domain label of the complete-state digest.
const DEVICE_STATE_LABEL: &str = "ratify/device-complete-state/v2";
/// The projection version.
const DEVICE_STATE_VERSION: i64 = 1;

/// The member digests of a [`Store`]'s durable state (Go
/// `storeStateTestOnly`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StoreDigests {
    claims: String,
    streams: String,
    rate_counters: String,
    receipt_log: String,
}

fn sha384_hex(b: &[u8]) -> String {
    hex::encode(Sha384::digest(b))
}

fn canonical(v: &serde_json::Value) -> V2Result<Vec<u8>> {
    let body = serde_json::to_vec(v).map_err(|e| V2Error::plain(format!("v2reference: projection: {e}")))?;
    canonical_json_v2(&body)
}

/// Lowercase hex SHA-384 of the RatifyCanonicalJSON of `v`.
fn member_digest(v: &serde_json::Value) -> V2Result<String> {
    Ok(sha384_hex(&canonical(v)?))
}

/// Digest of one record in its implementation-defined encoding.
fn record_digest(v: &impl Debug) -> String {
    sha384_hex(format!("{v:?}").as_bytes())
}

fn optional_digest(b: &[u8]) -> String {
    if b.is_empty() {
        String::new()
    } else {
        sha384_hex(b)
    }
}

/// Go `stateDigestsLocked`: digests every durable security record of the
/// store: claims in every state (evaluating, terminal, interrupted,
/// abandoned) with their sealed values and release records, stream
/// sequences, rate counters, and the receipt log with its outbox. Checkpoint
/// acknowledgements and clock readings are excluded.
pub(crate) fn store_state_digests(s: &StoreState) -> V2Result<StoreDigests> {
    // BTreeMap iteration yields every member in primary-key order.
    let claims: Vec<serde_json::Value> = s
        .claims
        .iter()
        .map(|(id, r)| {
            let state = match r.state {
                ClaimState::Evaluating => "evaluating",
                ClaimState::Terminal => "terminal",
            };
            json!({
                "abandoned": r.abandoned,
                "allow_horizon": r.allow_horizon,
                "claim_id": id,
                "claim_sha384": record_digest(&r.claim),
                "claimed_at": r.claimed_at,
                "finalized_at": r.finalized_at,
                "lease_expires_at": r.lease_expires_at,
                // Go records index 0 until the terminal commit assigns one.
                "outbox_index": r.outbox_index.unwrap_or(0),
                "owner_digest": hex::encode(r.owner_digest),
                "progress_sha384": record_digest(&r.progress),
                "receipt_body_sha384": optional_digest(&r.receipt_body),
                "release_sha384": r.release.as_ref().map(record_digest).unwrap_or_default(),
                "state": state,
                "terminal_sha384": optional_digest(&r.terminal),
            })
        })
        .collect();
    let streams: Vec<serde_json::Value> =
        s.streams.iter().map(|(key, seq)| json!({"last_seq": seq, "stream": key})).collect();
    let rates: Vec<serde_json::Value> = s
        .rate_commits
        .iter()
        .map(|((issuer, cert, window), commits)| {
            json!({"cert_id": cert, "commits": commits, "issuer_id": issuer, "window_s": window})
        })
        .collect();
    let entries: Vec<serde_json::Value> = s
        .outbox
        .iter()
        .enumerate()
        .map(|(i, e)| {
            json!({
                "body_sha384": optional_digest(&e.body),
                "claim_id": e.claim_id,
                "entry_hash": hex::encode(&e.digest),
                "sequence": i + 1,
            })
        })
        .collect();
    let log = json!({"entries": entries, "frozen": s.log_frozen, "log_id": s.log_id});
    Ok(StoreDigests {
        claims: member_digest(&serde_json::Value::Array(claims))?,
        streams: member_digest(&serde_json::Value::Array(streams))?,
        rate_counters: member_digest(&serde_json::Value::Array(rates))?,
        receipt_log: member_digest(&log)?,
    })
}

/// The anchor lock's state: the bound component and the store member
/// digests of the last anchored state.
pub(crate) struct AnchorState {
    pub(crate) component: Option<Arc<DeviceComponentTestOnly>>,
    pub(crate) last_store: StoreDigests,
}

/// What the primary and its sub-stores share: the anchor lock (Go
/// `DevicePrimaryTestOnly.mu`), the journal and issuance records, the log
/// ID, and the replay epoch.
pub(crate) struct PrimaryShared {
    replay_epoch: i64,
    log_id: String,
    journal: JournalStore,
    issuance: TestOnlyChallengeIssuanceStore,
    anchor: Mutex<AnchorState>,
}

impl PrimaryShared {
    /// The anchor lock. Lock order: a sub-store's own lock, then this lock,
    /// then the journal or issuance store lock and the component lock.
    pub(crate) fn lock_anchor(&self) -> MutexGuard<'_, AnchorState> {
        self.anchor.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Go `composeLocked`: the complete-state digest for the given store
    /// member digests and the current journal and issuance records.
    pub(crate) fn compose(&self, store: &StoreDigests) -> V2Result<Vec<u8>> {
        let (head, snapshot) = self.journal.anchored();
        let records: Vec<serde_json::Value> = self
            .issuance
            .records()
            .iter()
            .map(|(key, record)| json!({"key": key, "record_sha384": record_digest(record)}))
            .collect();
        let body = canonical(&json!({
            "claims": store.claims,
            "issuance_records": member_digest(&serde_json::Value::Array(records))?,
            "log_id": self.log_id,
            "rate_counters": store.rate_counters,
            "receipt_log": store.receipt_log,
            "replay_epoch": self.replay_epoch,
            "security_journal": {"generation": head.generation, "snapshot_sha384": sha384_hex(&snapshot)},
            "streams": store.streams,
            "version": DEVICE_STATE_VERSION,
        }))?;
        let mut h = Sha384::new();
        h.update(DEVICE_STATE_LABEL.as_bytes());
        h.update([0u8]);
        h.update(&body);
        Ok(h.finalize().to_vec())
    }

    /// Go `CompleteStateDigestTestOnly`: recompute the digest from the
    /// primary's current records.
    pub(crate) fn complete_state_digest(&self, store: &Store) -> V2Result<Vec<u8>> {
        let current = store_state_digests(&store.lock())?;
        let _anchor = self.lock_anchor();
        self.compose(&current)
    }

    /// Go `anchorStore`: the store hook, run with the store lock held.
    fn anchor_store(&self, previous: &StoreState, next: &StoreState) -> Result<(), V2Error> {
        let (previous, next) = (store_state_digests(previous)?, store_state_digests(next)?);
        let mut anchor = self.lock_anchor();
        let before = self.compose(&previous)?;
        let after = self.compose(&next)?;
        let component = anchor
            .component
            .clone()
            .ok_or_else(|| V2Error::plain("v2reference: device primary is not bound"))?;
        component
            .anchor_state(&before, &after)
            .map_err(|e| V2Error::plain(e.to_string()))?;
        anchor.last_store = next;
        Ok(())
    }

    /// Go `changeOther`: apply a journal or issuance change. With a bound
    /// component the change is anchored before it takes effect and undone if
    /// the component refuses it; `apply`'s own result is returned when
    /// anchoring succeeds or nothing changed.
    fn change_other<E>(
        &self,
        apply: impl FnOnce() -> Result<(), E>,
        undo: impl FnOnce(),
        unanchored: impl FnOnce(V2Error) -> E,
    ) -> Result<(), E> {
        let anchor = self.lock_anchor();
        let Some(component) = anchor.component.clone() else {
            return apply();
        };
        let before = match self.compose(&anchor.last_store) {
            Ok(d) => d,
            Err(e) => return Err(unanchored(e)),
        };
        let applied = apply();
        let failure = match self.compose(&anchor.last_store) {
            Err(e) => Some(e.message),
            Ok(after) if after != before => component.anchor_state(&before, &after).err().map(|e| e.to_string()),
            Ok(_) => None,
        };
        if let Some(message) = failure {
            undo();
            return Err(unanchored(V2Error::new(
                V2ErrorClass::ClaimStoreUnavailable,
                format!("v2reference: durable state change was not anchored: {message}"),
            )));
        }
        applied
    }
}

/// The primary of the single-device offline profile (Go
/// `DevicePrimaryTestOnly`). TEST ONLY.
pub struct DevicePrimaryTestOnly {
    pub store: Arc<Store>,
    pub journal: DeviceJournalTestOnly,
    pub issuance: DeviceIssuanceTestOnly,
    pub(crate) shared: Arc<PrimaryShared>,
}

impl std::fmt::Debug for DevicePrimaryTestOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePrimaryTestOnly")
            .field("store", &self.store)
            .field("replay_epoch", &self.shared.replay_epoch)
            .finish_non_exhaustive()
    }
}

impl DevicePrimaryTestOnly {
    /// Go `NewDevicePrimaryTestOnly`: wrap `store` with an empty anchored
    /// journal store and an empty issuance store, serving `replay_epoch`.
    pub fn new(store: Arc<Store>, replay_epoch: i64) -> V2Result<Self> {
        if replay_epoch < 0 {
            return Err(V2Error::new(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: device primary needs a store and a non-negative replay epoch",
            ));
        }
        let log_id = store.lock().log_id.clone();
        Ok(Self::assemble(store, replay_epoch, log_id, JournalStore::new()?, TestOnlyChallengeIssuanceStore::new()))
    }

    fn assemble(
        store: Arc<Store>,
        replay_epoch: i64,
        log_id: String,
        journal: JournalStore,
        issuance: TestOnlyChallengeIssuanceStore,
    ) -> Self {
        let shared = Arc::new(PrimaryShared {
            replay_epoch,
            log_id,
            journal,
            issuance,
            anchor: Mutex::new(AnchorState {
                component: None,
                last_store: StoreDigests::default(),
            }),
        });
        DevicePrimaryTestOnly {
            store,
            journal: DeviceJournalTestOnly {
                shared: Arc::clone(&shared),
            },
            issuance: DeviceIssuanceTestOnly {
                shared: Arc::clone(&shared),
            },
            shared,
        }
    }

    /// Go `Clone`: copy the complete primary state, modelling a backup or
    /// snapshot. The copy is not bound to any component.
    pub fn clone_primary(&self) -> Self {
        let (head, snapshot) = self.shared.journal.anchored();
        let issuance = TestOnlyChallengeIssuanceStore::new();
        issuance.set_records(self.shared.issuance.records());
        Self::assemble(
            Arc::new(self.store.clone_store()),
            self.shared.replay_epoch,
            self.shared.log_id.clone(),
            JournalStore::from_anchored(head, snapshot),
            issuance,
        )
    }

    /// Go `bind`: attach the component and anchor every later durable
    /// change in it.
    pub(crate) fn bind(&self, component: Arc<DeviceComponentTestOnly>) -> V2Result<()> {
        let current = store_state_digests(&self.store.lock())?;
        {
            let mut anchor = self.shared.lock_anchor();
            anchor.component = Some(component);
            anchor.last_store = current;
        }
        let shared = Arc::clone(&self.shared);
        let hook: StoreAnchor = Arc::new(move |previous, next| shared.anchor_store(previous, next));
        self.store.lock().anchor = Some(hook);
        Ok(())
    }

    /// Go `CompleteStateDigestTestOnly`.
    pub fn complete_state_digest_test_only(&self) -> V2Result<Vec<u8>> {
        self.shared.complete_state_digest(&self.store)
    }
}

/// The primary's anchored `SecurityJournalV2` store (Go
/// `DeviceJournalTestOnly`).
pub struct DeviceJournalTestOnly {
    shared: Arc<PrimaryShared>,
}

impl std::fmt::Debug for DeviceJournalTestOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceJournalTestOnly").field("head", &self.head()).finish()
    }
}

impl DeviceJournalTestOnly {
    /// The journal's anchored head.
    pub fn head(&self) -> SecurityJournalHeadV2 {
        self.shared.journal.head()
    }
}

impl SecurityJournalStoreV2 for DeviceJournalTestOnly {
    fn load(&self, ctx: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)> {
        self.shared.journal.load(ctx)
    }

    /// The new journal state is anchored with the rest of the primary's
    /// state.
    fn compare_and_swap(
        &self,
        ctx: &V2Context,
        expected: &SecurityJournalHeadV2,
        next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        let journal = &self.shared.journal;
        let (head, snapshot) = journal.anchored();
        self.shared.change_other(
            || journal.compare_and_swap(ctx, expected, next),
            || journal.restore_anchored(head, snapshot),
            SecurityJournalStoreErrorV2::Failed,
        )
    }
}

/// The primary's challenge issuance store (Go `DeviceIssuanceTestOnly`).
pub struct DeviceIssuanceTestOnly {
    shared: Arc<PrimaryShared>,
}

impl std::fmt::Debug for DeviceIssuanceTestOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIssuanceTestOnly").finish_non_exhaustive()
    }
}

impl V2ChallengeIssuanceStore for DeviceIssuanceTestOnly {
    /// The new record is anchored with the rest of the primary's state.
    fn persist_v2_challenge(&self, ctx: &V2Context, record: ExpectedChallengeV2) -> Result<(), V2StoreError> {
        let issuance = &self.shared.issuance;
        let saved = issuance.records();
        self.shared.change_other(
            || issuance.persist_v2_challenge(ctx, record),
            || issuance.set_records(saved),
            V2StoreError::Classified,
        )
    }

    fn load_v2_challenge(
        &self,
        ctx: &V2Context,
        namespace: &str,
        replay_epoch: i64,
        claim_digest: &[u8],
    ) -> Result<ExpectedChallengeV2, V2StoreError> {
        self.shared.issuance.load_v2_challenge(ctx, namespace, replay_epoch, claim_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::super::offline_device::{DeviceCheckpointTestOnly, DeviceErrorTestOnly, DeviceStartupStatus};
    use super::super::store::OutboxEntry;
    use super::*;
    use crate::crypto::generate_hybrid_keypair;
    use crate::v2::claim_store::{ClaimStoreV2, V2ChallengeClaim};
    use crate::v2::journal::record_security_key_role_v2;
    use crate::v2::release::V2ReleaseRecord;

    const LOG_ID: &str = "dddddddddddddddddddddddddddddd01";

    type TestDevice = (DevicePrimaryTestOnly, Arc<DeviceComponentTestOnly>, DeviceCheckpointTestOnly);

    fn new_test_device(capacity: usize) -> TestDevice {
        let (_, private) = generate_hybrid_keypair();
        let store = Arc::new(Store::new(1_000, 30, LOG_ID, &private).unwrap());
        store.set_acknowledgement_withheld(true);
        let primary = DevicePrimaryTestOnly::new(store.clone(), 3).unwrap();
        let component = Arc::new(DeviceComponentTestOnly::new(&[7; 32], capacity, store).unwrap());
        let device = DeviceCheckpointTestOnly::new(&primary, component.clone(), &component.public_key()).unwrap();
        device.provision().unwrap();
        (primary, component, device)
    }

    fn test_challenge_record(b: u8) -> ExpectedChallengeV2 {
        ExpectedChallengeV2 {
            value: vec![b; 32],
            issued_at: 990,
            expires_at: 1_290,
            verifier_namespace: "device-ns".into(),
            replay_epoch: 3,
            ..Default::default()
        }
    }

    fn test_claim(id: &str) -> V2ChallengeClaim {
        V2ChallengeClaim {
            claim_id: id.into(),
            namespace: "device-ns".into(),
            replay_epoch: 3,
            issued_at: 990,
            expires_at: 1_290,
            max_age_seconds: 300,
            ..Default::default()
        }
    }

    fn release_record(entry: u8, at: i64) -> V2ReleaseRecord {
        V2ReleaseRecord {
            claim_id: "claim-1".into(),
            entry_hash: vec![entry; 48],
            ack_timestamp: at,
        }
    }

    /// A copy of `p` whose store state was changed by `mutate`.
    fn with_store(p: &DevicePrimaryTestOnly, mutate: impl FnOnce(&mut StoreState)) -> DevicePrimaryTestOnly {
        let copy = p.clone_primary();
        mutate(&mut copy.store.lock());
        copy
    }

    fn claim_1(s: &mut StoreState) -> &mut super::super::store::ClaimRecord {
        s.claims.get_mut("claim-1").unwrap()
    }

    // Every member of the complete-state projection changes the digest on its
    // own, so a rollback of any one durable record is detectable even when
    // the receipt log and every other record are unchanged (SPEC-v2 §7.13).
    #[test]
    fn state_digest_covers_every_member() {
        let ctx = V2Context::background();
        let (primary, _, _) = new_test_device(4);
        primary.store.claim_v2(&ctx, test_claim("claim-1")).unwrap();
        let base = primary.complete_state_digest_test_only().unwrap();
        let mut mutated: Vec<(&str, DevicePrimaryTestOnly)> = vec![
            ("claim state", with_store(&primary, |s| claim_1(s).state = ClaimState::Terminal)),
            ("claim lease", with_store(&primary, |s| claim_1(s).lease_expires_at += 1)),
            ("claim progress", with_store(&primary, |s| claim_1(s).progress.trust_assessment = "trusted".into())),
            ("claim abandoned", with_store(&primary, |s| claim_1(s).abandoned = true)),
            ("claim removed", with_store(&primary, |s| drop(s.claims.remove("claim-1")))),
            ("release record", with_store(&primary, |s| claim_1(s).release = Some(release_record(1, 1_000)))),
            ("stream sequence", with_store(&primary, |s| {
                s.streams.insert("stream".into(), 2);
            })),
            (
                "rate counter",
                with_store(&primary, |s| drop(s.rate_commits.insert(("issuer".into(), "cert".into(), 60), vec![1_000]))),
            ),
            (
                "outbox entry",
                with_store(&primary, |s| {
                    s.outbox.push(OutboxEntry {
                        claim_id: "claim-1".into(),
                        body: b"{}".to_vec(),
                        wire: None,
                        digest: Vec::new(),
                        ack: None,
                    })
                }),
            ),
            ("log frozen", with_store(&primary, |s| s.log_frozen = true)),
        ];
        let copy = primary.clone_primary();
        let (head, snapshot) = copy.shared.journal.anchored();
        let issuance = TestOnlyChallengeIssuanceStore::new();
        issuance.set_records(copy.shared.issuance.records());
        mutated.push((
            "replay epoch",
            DevicePrimaryTestOnly::assemble(
                copy.store.clone(),
                copy.shared.replay_epoch + 1,
                copy.shared.log_id.clone(),
                JournalStore::from_anchored(head, snapshot),
                issuance,
            ),
        ));
        let issued = primary.clone_primary();
        issued.shared.issuance.persist_v2_challenge(&ctx, test_challenge_record(9)).unwrap();
        mutated.push(("issuance record", issued));
        let journaled = primary.clone_primary();
        let (public, _) = generate_hybrid_keypair();
        record_security_key_role_v2(&ctx, &journaled.shared.journal, "verifier", &public).unwrap();
        mutated.push(("security journal", journaled));
        for (name, p) in mutated {
            assert_ne!(p.complete_state_digest_test_only().unwrap(), base, "changing the {name} does not change the digest");
        }
        // Every field of a release record is covered, not only its presence.
        let released = with_store(&primary, |s| claim_1(s).release = Some(release_record(1, 1_000)));
        let with_release = released.complete_state_digest_test_only().unwrap();
        for (name, record) in [("release entry hash", release_record(2, 1_000)), ("release ack timestamp", release_record(1, 999))] {
            let p = with_store(&released, |s| claim_1(s).release = Some(record));
            assert_ne!(p.complete_state_digest_test_only().unwrap(), with_release, "changing the {name} does not change the digest");
        }
        // Excluded by design: clock readings and checkpoint acknowledgements.
        let clock = with_store(&primary, |s| s.high_water += 100);
        assert_eq!(clock.complete_state_digest_test_only().unwrap(), base, "a clock reading changed the digest");
    }

    // Journal and issuance changes are anchored like claim-store changes: a
    // restore that loses either is detected at startup, and a restored
    // primary cannot make a new change.
    #[test]
    fn journal_and_issuance_rollback_detected() {
        let ctx = V2Context::background();
        type Change = fn(&V2Context, &DevicePrimaryTestOnly) -> Option<V2ErrorClass>;
        let changes: [(&str, Change); 2] = [
            ("journal", |ctx, p| {
                let (public, _) = generate_hybrid_keypair();
                record_security_key_role_v2(ctx, &p.journal, "verifier", &public).err().map(|e| e.class)
            }),
            ("issuance", |ctx, p| {
                p.issuance
                    .persist_v2_challenge(ctx, test_challenge_record(1))
                    .err()
                    .map(|e| e.class().unwrap_or(V2ErrorClass::Malformed))
            }),
        ];
        for (name, change) in changes {
            let (primary, component, device) = new_test_device(4);
            let snapshot = primary.clone_primary();
            assert_eq!(change(&ctx, &primary), None, "{name}: anchored change");
            assert_eq!(device.startup(), DeviceStartupStatus::Ready, "{name}: after an anchored change");
            let restored = snapshot.clone_primary();
            let restored_device = DeviceCheckpointTestOnly::new(&restored, component.clone(), &component.public_key()).unwrap();
            assert_eq!(restored_device.startup(), DeviceStartupStatus::StateDigestMismatch, "{name}: after a rollback");
            let before = restored.complete_state_digest_test_only().unwrap();
            assert_eq!(
                change(&ctx, &restored),
                Some(V2ErrorClass::ClaimStoreUnavailable),
                "{name}: a rolled-back primary made a change"
            );
            assert_eq!(restored.complete_state_digest_test_only().unwrap(), before, "{name}: a refused change was not undone");
        }
    }

    // A different entry at an acknowledged sequence freezes the component; a
    // frozen component anchors nothing more.
    #[test]
    fn component_freezes_on_fork() {
        let ctx = V2Context::background();
        let (primary, component, device) = new_test_device(4);
        let state = {
            let anchor = primary.shared.lock_anchor();
            primary.shared.compose(&anchor.last_store).unwrap()
        };
        let (zero, entry, other) = (vec![0u8; 48], vec![1u8; 48], vec![2u8; 48]);
        component.commit(&ctx, LOG_ID, 1, &zero, &entry, &state).unwrap();
        let ack = component.commit(&ctx, LOG_ID, 1, &zero, &entry, &state).unwrap();
        assert_eq!(ack.sequence, 1, "identical retry");
        assert_eq!(component.commit(&ctx, LOG_ID, 1, &zero, &other, &state), Err(DeviceErrorTestOnly::Frozen));
        assert_eq!(component.anchor_state(&state, &state), Err(DeviceErrorTestOnly::Frozen));
        assert_eq!(device.startup(), DeviceStartupStatus::CheckpointFrozen);
        assert!(component.provision_state(&state).is_err(), "a provisioned component was provisioned again");
    }

    // An acknowledgement racing anchored state changes never sees a stale
    // anchored digest: the primary holds its anchor lock from composing the
    // digest through the component commit, so a concurrent claim anchors
    // either before or after it, never between (SPEC-v2 §7.13).
    #[test]
    fn acknowledgement_racing_claims_never_mismatches() {
        const ENTRIES: i64 = 16;
        const WORKERS: usize = 4;
        const CLAIMS_PER_ROUND: usize = 2;
        let ctx = V2Context::background();
        let (primary, _, device) = new_test_device(ENTRIES as usize);
        let store = &primary.store;
        for sequence in 1..=ENTRIES {
            // Append an entry through the anchored change path, then
            // acknowledge it while claim workers anchor new state concurrently.
            store
                .lock()
                .change_locked(|s| {
                    s.outbox.push(OutboxEntry {
                        claim_id: format!("entry-{sequence}"),
                        body: b"{}".to_vec(),
                        wire: Some(vec![1]),
                        digest: vec![sequence as u8; 48],
                        ack: None,
                    })
                })
                .unwrap_or_else(|e| panic!("append {sequence}: {e:?}"));
            let ack = std::thread::scope(|scope| {
                for worker in 0..WORKERS {
                    let ctx = &ctx;
                    scope.spawn(move || {
                        for n in 0..CLAIMS_PER_ROUND {
                            let id = format!("claim-{sequence}-{worker}-{n}");
                            store.claim_v2(ctx, test_claim(&id)).unwrap_or_else(|e| panic!("claim {id}: {e:?}"));
                        }
                    });
                }
                device.resubmit(&ctx, sequence)
            });
            ack.unwrap_or_else(|e| panic!("acknowledging sequence {sequence} while claims race: {e}"));
        }
        assert_eq!(device.startup(), DeviceStartupStatus::Ready, "startup after the race");
    }
}
