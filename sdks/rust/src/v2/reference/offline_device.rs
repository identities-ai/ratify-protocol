//! Single-device offline profile (SPEC-v2 §7.13), TEST ONLY. Mirrors Go
//! `v2reference/offline_device.go`.
//!
//! [`DeviceComponentTestOnly`] models the independent component the profile
//! requires on one device: an independently programmed secure element or
//! TPM-backed module with its own key. It holds the anchored complete-state
//! digest of the primary ([`DevicePrimaryTestOnly`]), which the primary
//! advances before every durable security-state change takes effect, and it
//! records, for every receipt-log entry, the entry hash and the
//! complete-state digest it acknowledged, advances monotonically, and signs
//! each acknowledgement. Nothing here is durable or independent; it exists
//! so the shared profile scenarios can exercise power loss, primary rollback
//! with and without a changed receipt prefix, digest mismatch, full storage,
//! clock regression, and offline recovery against exact semantics.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

use super::device_state::{DevicePrimaryTestOnly, PrimaryShared};
use super::store::Store;
use crate::v2::checkpoint_ack::V2CheckpointAcknowledgement;
use crate::v2::claim_store::{V2AuthoritativeClock, V2StoreError};
use crate::v2::context::V2Context;
use crate::v2::errors::{V2Error, V2ErrorClass, V2Result};
use crate::v2::release::V2ReceiptCheckpoint;

/// The failures of the device component and checkpoint (Go
/// `ErrDevicePowerLoss`, `ErrDeviceStorageFull`, `ErrDeviceStateMismatch`,
/// `ErrDeviceFrozen`, and `ErrNotAcknowledged`), plus a store or clock
/// failure passed through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceErrorTestOnly {
    /// Power was lost during a checkpoint submission. Before the component
    /// commits nothing is recorded; after it commits, the acknowledgement is
    /// durable but its response is lost.
    PowerLoss,
    /// The component has no space for another acknowledgement. It never
    /// overwrites or wraps.
    StorageFull,
    /// A state anchor or submission does not extend the component's head:
    /// the previous complete-state digest differs from the anchored one, the
    /// previous entry hash differs, or the sequence is not the next one.
    StateMismatch,
    /// A different entry was submitted at an acknowledged sequence; the
    /// component acknowledges nothing further.
    Frozen,
    /// The primary holds no appended entry with that hash at that sequence.
    NotAcknowledged,
    /// A security-clock, signature, or store failure.
    Store(V2StoreError),
}

impl fmt::Display for DeviceErrorTestOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceErrorTestOnly::PowerLoss => f.write_str("v2reference: power lost during the device checkpoint submission"),
            DeviceErrorTestOnly::StorageFull => f.write_str("v2reference: device checkpoint storage is full"),
            DeviceErrorTestOnly::StateMismatch => {
                f.write_str("v2reference: submission does not extend the device checkpoint head")
            }
            DeviceErrorTestOnly::Frozen => f.write_str("v2reference: device checkpoint is frozen after a conflicting entry"),
            DeviceErrorTestOnly::NotAcknowledged => f.write_str(super::store::ERR_NOT_ACKNOWLEDGED),
            DeviceErrorTestOnly::Store(e) => write!(f, "{e:?}"),
        }
    }
}

impl std::error::Error for DeviceErrorTestOnly {}

impl From<DeviceErrorTestOnly> for V2StoreError {
    fn from(e: DeviceErrorTestOnly) -> Self {
        match e {
            DeviceErrorTestOnly::Store(inner) => inner,
            other => V2StoreError::Unavailable(other.to_string()),
        }
    }
}

/// Where the next submission loses power (Go `DevicePowerLoss`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DevicePowerLoss {
    #[default]
    Ok,
    BeforeCommit,
    AfterCommit,
}

/// One signed component record (Go `DeviceAcknowledgementTestOnly`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAcknowledgementTestOnly {
    pub log_id: String,
    pub sequence: i64,
    pub entry_hash: Vec<u8>,
    pub state_digest: Vec<u8>,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

fn lp_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_be_bytes());
    out.extend_from_slice(b);
}

/// Go `deviceAckMessage`: the exact byte string the component signs.
fn device_ack_message(a: &DeviceAcknowledgementTestOnly) -> Vec<u8> {
    let mut m = b"ratify-test-device-checkpoint-v2\0".to_vec();
    lp_bytes(&mut m, a.log_id.as_bytes());
    m.extend_from_slice(&(a.sequence as u64).to_be_bytes());
    lp_bytes(&mut m, &a.entry_hash);
    lp_bytes(&mut m, &a.state_digest);
    m.extend_from_slice(&(a.timestamp as u64).to_be_bytes());
    m
}

/// Go `VerifyDeviceAcknowledgementTestOnly`: check a record under the pinned
/// component public key.
pub fn verify_device_acknowledgement_test_only(public: &[u8], a: &DeviceAcknowledgementTestOnly) -> Result<(), String> {
    let refused = || "v2reference: device acknowledgement signature does not verify".to_string();
    let key: [u8; 32] = public.try_into().map_err(|_| refused())?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| refused())?;
    let signature = Signature::from_slice(&a.signature).map_err(|_| refused())?;
    key.verify(&device_ack_message(a), &signature).map_err(|_| refused())
}

struct ComponentState {
    records: Vec<DeviceAcknowledgementTestOnly>,
    /// The anchored complete-state digest; `None` until provisioned.
    state: Option<Vec<u8>>,
    frozen: bool,
    fault: DevicePowerLoss,
}

/// The independent monotonic authenticated component (Go
/// `DeviceComponentTestOnly`). Its clock is the device's configured
/// security-clock source.
pub struct DeviceComponentTestOnly {
    key: SigningKey,
    clock: Arc<dyn V2AuthoritativeClock>,
    capacity: usize,
    state: Mutex<ComponentState>,
}

impl fmt::Debug for DeviceComponentTestOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (head, _, frozen) = self.head();
        f.debug_struct("DeviceComponentTestOnly")
            .field("head", &head)
            .field("frozen", &frozen)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl DeviceComponentTestOnly {
    /// Go `NewDeviceComponentTestOnly`: a component with its own signing
    /// key (from a 32-byte test seed) and room for `capacity`
    /// acknowledgements.
    pub fn new(seed: &[u8], capacity: usize, clock: Arc<dyn V2AuthoritativeClock>) -> V2Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            V2Error::new(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: device component needs a 32-byte seed, positive capacity, and a clock",
            )
        })?;
        if capacity < 1 {
            return Err(V2Error::new(
                V2ErrorClass::ConfigurationInvalid,
                "v2reference: device component needs a 32-byte seed, positive capacity, and a clock",
            ));
        }
        Ok(DeviceComponentTestOnly {
            key: SigningKey::from_bytes(&seed),
            clock,
            capacity,
            state: Mutex::new(ComponentState {
                records: Vec::new(),
                state: None,
                frozen: false,
                fault: DevicePowerLoss::Ok,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, ComponentState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The component key the primary pins.
    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    /// Arm a power loss for the next submission only.
    pub fn set_power_loss(&self, fault: DevicePowerLoss) {
        self.lock().fault = fault;
    }

    /// The acknowledged sequence (0 before the first acknowledgement), the
    /// anchored complete-state digest (`None` before provisioning), and
    /// whether the component is frozen.
    pub fn head(&self) -> (i64, Option<Vec<u8>>, bool) {
        let s = self.lock();
        (s.records.len() as i64, s.state.clone(), s.frozen)
    }

    /// Anchor the primary's initial complete-state digest. Accepted once,
    /// before any other anchor or acknowledgement.
    pub fn provision_state(&self, digest: &[u8]) -> V2Result<()> {
        let mut s = self.lock();
        if s.state.is_some() || !s.records.is_empty() || digest.len() != 48 {
            return Err(V2Error::plain(
                "v2reference: device component is already provisioned or the digest is not 48 bytes",
            ));
        }
        s.state = Some(digest.to_vec());
        Ok(())
    }

    /// Advance the anchored complete-state digest from `previous` to `next`.
    /// `previous` must equal the anchored digest: a primary whose state was
    /// rolled back, restored, or altered cannot extend it. The register only
    /// moves forward through this call; nothing lowers or restores it.
    pub fn anchor_state(&self, previous: &[u8], next: &[u8]) -> Result<(), DeviceErrorTestOnly> {
        let mut s = self.lock();
        if s.frozen {
            return Err(DeviceErrorTestOnly::Frozen);
        }
        if s.state.as_deref() != Some(previous) || next.len() != 48 {
            return Err(DeviceErrorTestOnly::StateMismatch);
        }
        s.state = Some(next.to_vec());
        Ok(())
    }

    /// Go `Commit`: record the next receipt-log entry. It accepts only
    /// sequence head+1 whose previous entry hash equals the head's and whose
    /// state digest equals the anchored complete-state digest. An identical
    /// retry (same log ID and entry hash) of an acknowledged sequence returns
    /// the original record, and a different entry at an acknowledged
    /// sequence freezes the component.
    pub fn commit(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
        state: &[u8],
    ) -> Result<DeviceAcknowledgementTestOnly, DeviceErrorTestOnly> {
        // The security clock is read before the component lock: the
        // primary's clock source may itself take the store lock, which is
        // held while the store anchors state here.
        let now = self.clock.authoritative_time_v2(ctx);
        self.commit_at(now, log_id, sequence, previous_entry_hash, entry_hash, state)
    }

    /// Go `commitAt`: `commit` with a security-clock reading taken before
    /// any lock, so a caller may hold the primary's anchor lock across it.
    pub(crate) fn commit_at(
        &self,
        now: Result<i64, V2StoreError>,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
        state: &[u8],
    ) -> Result<DeviceAcknowledgementTestOnly, DeviceErrorTestOnly> {
        let mut s = self.lock();
        if s.frozen {
            return Err(DeviceErrorTestOnly::Frozen);
        }
        let acknowledged = s.records.len() as i64;
        if sequence >= 1 && sequence <= acknowledged {
            let existing = &s.records[sequence as usize - 1];
            if existing.log_id == log_id && existing.entry_hash == entry_hash {
                return Ok(existing.clone());
            }
            s.frozen = true;
            return Err(DeviceErrorTestOnly::Frozen);
        }
        let mut head_entry = vec![0u8; 48];
        if let Some(last) = s.records.last() {
            if last.log_id != log_id {
                return Err(DeviceErrorTestOnly::StateMismatch);
            }
            head_entry = last.entry_hash.clone();
        }
        if sequence != acknowledged + 1 || head_entry != previous_entry_hash || s.state.as_deref() != Some(state) {
            return Err(DeviceErrorTestOnly::StateMismatch);
        }
        if s.records.len() >= self.capacity {
            return Err(DeviceErrorTestOnly::StorageFull);
        }
        let fault = std::mem::take(&mut s.fault);
        if fault == DevicePowerLoss::BeforeCommit {
            return Err(DeviceErrorTestOnly::PowerLoss);
        }
        let now = now.map_err(DeviceErrorTestOnly::Store)?;
        let mut ack = DeviceAcknowledgementTestOnly {
            log_id: log_id.to_string(),
            sequence,
            entry_hash: entry_hash.to_vec(),
            state_digest: state.to_vec(),
            timestamp: now,
            signature: Vec::new(),
        };
        ack.signature = self.key.sign(&device_ack_message(&ack)).to_bytes().to_vec();
        s.records.push(ack.clone());
        if fault == DevicePowerLoss::AfterCommit {
            return Err(DeviceErrorTestOnly::PowerLoss);
        }
        Ok(ack)
    }

    /// The record for `sequence`, or `AcknowledgementNotFound`.
    pub fn get(&self, log_id: &str, sequence: i64) -> Result<DeviceAcknowledgementTestOnly, V2StoreError> {
        let s = self.lock();
        match s.records.get((sequence.max(1) - 1) as usize) {
            Some(r) if sequence >= 1 && r.log_id == log_id => Ok(r.clone()),
            _ => Err(V2StoreError::AcknowledgementNotFound),
        }
    }
}

impl Store {
    /// Go `CorruptSealedStateTestOnly`: flip one byte of a committed claim's
    /// sealed terminal result, modelling corrupted primary storage.
    pub fn corrupt_sealed_state_test_only(&self, claim_id: &str) {
        if let Some(record) = self.lock().claims.get_mut(claim_id) {
            if let Some(first) = record.terminal.first_mut() {
                *first ^= 1;
            }
        }
    }

    /// Go `appendedEntry`: the entry hash of an appended receipt-log entry.
    pub(crate) fn appended_entry(&self, sequence: i64) -> Option<Vec<u8>> {
        if sequence < 1 {
            return None;
        }
        let s = self.lock();
        s.outbox
            .get(sequence as usize - 1)
            .filter(|e| e.wire.is_some())
            .map(|e| e.digest.clone())
    }

    /// The signed wire of an appended receipt-log entry.
    fn appended_wire(&self, sequence: i64) -> Option<Vec<u8>> {
        if sequence < 1 {
            return None;
        }
        self.lock().outbox.get(sequence as usize - 1).and_then(|e| e.wire.clone())
    }

    fn log_id(&self) -> String {
        self.lock().log_id.clone()
    }
}

/// The result of the primary's startup comparison with the component head
/// (Go `DeviceStartupStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStartupStatus {
    /// The primary's state at the component head equals the acknowledged
    /// digest; any later appended entries are submitted in order.
    Ready,
    /// The primary holds fewer appended entries than the component
    /// acknowledged (rollback or lost state). The device stays recovering
    /// until its recovery authority advances the replay epoch.
    PrimaryBehind,
    /// The primary's complete-state digest differs from the anchored one,
    /// including a rollback that kept the receipt-log prefix but lost or
    /// altered any other durable security record.
    StateDigestMismatch,
    /// The component saw a conflicting entry.
    CheckpointFrozen,
}

impl DeviceStartupStatus {
    /// The spelling the shared vectors use.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceStartupStatus::Ready => "ready",
            DeviceStartupStatus::PrimaryBehind => "primary_behind",
            DeviceStartupStatus::StateDigestMismatch => "state_digest_mismatch",
            DeviceStartupStatus::CheckpointFrozen => "checkpoint_frozen",
        }
    }
}

/// The primary's view of the component (Go `DeviceCheckpointTestOnly`). It
/// implements [`V2ReceiptCheckpoint`]: every acknowledgement it returns
/// carries a component signature verified under the pinned key.
pub struct DeviceCheckpointTestOnly {
    device: Arc<PrimaryShared>,
    primary: Arc<Store>,
    component: Arc<DeviceComponentTestOnly>,
    pinned: Vec<u8>,
}

impl fmt::Debug for DeviceCheckpointTestOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCheckpointTestOnly")
            .field("component", &self.component)
            .finish_non_exhaustive()
    }
}

impl DeviceCheckpointTestOnly {
    /// Go `NewDeviceCheckpointTestOnly`: bind a device primary to a
    /// component whose key the primary pinned at provisioning; from now on
    /// every durable change of the primary is anchored in the component
    /// before it takes effect. The primary's store must not self-acknowledge
    /// (`set_acknowledgement_withheld(true)`). A fresh device then calls
    /// [`Self::provision`] once; a primary restored from a copy is bound
    /// again without provisioning, and its first change or startup shows
    /// whether it matches the anchored state.
    pub fn new(
        primary: &DevicePrimaryTestOnly,
        component: Arc<DeviceComponentTestOnly>,
        pinned: &[u8],
    ) -> V2Result<Self> {
        primary.bind(Arc::clone(&component))?;
        Ok(DeviceCheckpointTestOnly {
            device: Arc::clone(&primary.shared),
            primary: Arc::clone(&primary.store),
            component,
            pinned: pinned.to_vec(),
        })
    }

    /// Anchor the primary's current complete-state digest as the
    /// component's initial state.
    pub fn provision(&self) -> V2Result<()> {
        let digest = self.device.complete_state_digest(&self.primary)?;
        self.component.provision_state(&digest)
    }

    fn to_ack(&self, a: DeviceAcknowledgementTestOnly) -> Result<V2CheckpointAcknowledgement, DeviceErrorTestOnly> {
        verify_device_acknowledgement_test_only(&self.pinned, &a)
            .map_err(|e| DeviceErrorTestOnly::Store(V2StoreError::Unavailable(e)))?;
        Ok(V2CheckpointAcknowledgement {
            log_id: a.log_id,
            sequence: a.sequence,
            entry_hash: a.entry_hash,
            timestamp: a.timestamp,
        })
    }

    /// Go `AcknowledgeV2Receipt`: submit the primary's appended entry with
    /// the primary's anchored complete-state digest, which already covers
    /// the append. The security clock is read first, with no lock held,
    /// because the clock source may take the store lock, which precedes the
    /// anchor lock. The anchor lock is then held from composing the anchored
    /// digest through the component commit, so a concurrent anchored change
    /// cannot advance the component's digest in between.
    pub fn acknowledge(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, DeviceErrorTestOnly> {
        if self.primary.appended_entry(sequence).as_deref() != Some(entry_hash) {
            return Err(DeviceErrorTestOnly::NotAcknowledged);
        }
        let now = self.component.clock.authoritative_time_v2(ctx);
        let ack = {
            let anchor = self.device.lock_anchor();
            let state = self
                .device
                .compose(&anchor.last_store)
                .map_err(|e| DeviceErrorTestOnly::Store(V2StoreError::Classified(e)))?;
            self.component
                .commit_at(now, log_id, sequence, previous_entry_hash, entry_hash, &state)?
        };
        self.to_ack(ack)
    }

    /// Go `SubmitPending`: submit, in log order, every appended entry of the
    /// primary that the component has not acknowledged with the same entry
    /// hash, and return the sequences acknowledged by this call with the
    /// failure that stopped it, if any. A rolled-back primary therefore
    /// resubmits its own version of an acknowledged sequence, which the
    /// component refuses.
    pub fn submit_pending(&self, ctx: &V2Context) -> (Vec<i64>, Option<DeviceErrorTestOnly>) {
        let mut acknowledged = Vec::new();
        let log_id = self.primary.log_id();
        let mut next = 1;
        while let Some(entry) = self.primary.appended_entry(next) {
            let already = matches!(self.component.get(&log_id, next), Ok(existing) if existing.entry_hash == entry);
            if !already {
                if let Err(e) = self.resubmit(ctx, next) {
                    return (acknowledged, Some(e));
                }
                acknowledged.push(next);
            }
            next += 1;
        }
        (acknowledged, None)
    }

    /// Go `Resubmit`: retry the exact tuple for `sequence` (for example
    /// after a power loss whose outcome is unknown) and return the
    /// acknowledgement.
    pub fn resubmit(&self, ctx: &V2Context, sequence: i64) -> Result<V2CheckpointAcknowledgement, DeviceErrorTestOnly> {
        let entry = self
            .primary
            .appended_entry(sequence)
            .ok_or(DeviceErrorTestOnly::NotAcknowledged)?;
        let previous = if sequence > 1 {
            self.primary
                .appended_entry(sequence - 1)
                .ok_or(DeviceErrorTestOnly::NotAcknowledged)?
        } else {
            vec![0u8; 48]
        };
        self.acknowledge(ctx, &self.primary.log_id(), sequence, &previous, &entry)
    }

    /// Go `Startup`: compare the primary with the component head before the
    /// device serves any request: frozen component, then fewer appended
    /// entries than acknowledged, then the recomputed complete-state digest
    /// against the anchored one.
    pub fn startup(&self) -> DeviceStartupStatus {
        let (head, anchored, frozen) = self.component.head();
        if frozen {
            return DeviceStartupStatus::CheckpointFrozen;
        }
        if (self.primary.log_length() as i64) < head {
            return DeviceStartupStatus::PrimaryBehind;
        }
        match self.device.complete_state_digest(&self.primary) {
            Ok(state) if Some(&state) == anchored.as_ref() => DeviceStartupStatus::Ready,
            _ => DeviceStartupStatus::StateDigestMismatch,
        }
    }
}

impl V2ReceiptCheckpoint for DeviceCheckpointTestOnly {
    fn acknowledge_v2_receipt(
        &self,
        ctx: &V2Context,
        log_id: &str,
        sequence: i64,
        previous_entry_hash: &[u8],
        entry_hash: &[u8],
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        Ok(self.acknowledge(ctx, log_id, sequence, previous_entry_hash, entry_hash)?)
    }

    /// Read and verify the component record.
    fn get_v2_acknowledgement(
        &self,
        _ctx: &V2Context,
        log_id: &str,
        sequence: i64,
    ) -> Result<V2CheckpointAcknowledgement, V2StoreError> {
        let ack = self.component.get(log_id, sequence)?;
        Ok(self.to_ack(ack)?)
    }
}

/// The outbox upload after reconnection (Go `DeviceUplinkTestOnly`). It
/// uploads signed receipts only from the component-acknowledged prefix, in
/// log order, once each. Upload is an outbox operation: it never releases a
/// decision, changes a release record, or makes a withheld result
/// actionable.
#[derive(Debug)]
pub struct DeviceUplinkTestOnly {
    device: Arc<DeviceCheckpointTestOnly>,
    state: Mutex<(i64, Vec<Vec<u8>>)>,
}

impl DeviceUplinkTestOnly {
    /// An uplink for the device.
    pub fn new(device: Arc<DeviceCheckpointTestOnly>) -> Self {
        DeviceUplinkTestOnly {
            device,
            state: Mutex::new((0, Vec::new())),
        }
    }

    /// Send every acknowledged receipt not yet uploaded and return their
    /// sequences.
    pub fn upload(&self, _ctx: &V2Context) -> Vec<i64> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (head, _, _) = self.device.component.head();
        let mut sent = Vec::new();
        while state.0 < head {
            let next = state.0 + 1;
            let Some(wire) = self.device.primary.appended_wire(next) else {
                break;
            };
            state.1.push(wire);
            state.0 = next;
            sent.push(next);
        }
        sent
    }

    /// The receipts uploaded so far, in log order.
    pub fn collected(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).1.clone()
    }
}
