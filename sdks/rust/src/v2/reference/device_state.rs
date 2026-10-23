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
//! Every record is projected in the normative record encoding of SPEC-v2
//! §7.13, so the digest is reproducible across implementations and
//! upgrades; `testvectors/v2/device-state.json` pins it byte for byte.

use std::sync::{Arc, Mutex, MutexGuard};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

use super::challenges::TestOnlyChallengeIssuanceStore;
use super::journal::JournalStore;
use super::offline_device::DeviceComponentTestOnly;
use super::store::{ClaimRecord, ClaimState, Store, StoreAnchor, StoreState};
use crate::v2::challenge_issuance::V2ChallengeIssuanceStore;
use crate::v2::claim_store::{V2ChallengeClaim, V2StoreError};
use crate::v2::context::V2Context;
use crate::v2::errors::{V2Error, V2ErrorClass, V2Result};
use crate::v2::evaluation_progress::V2EvaluationProgress;
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

fn canonical(v: &Value) -> V2Result<Vec<u8>> {
    let body = serde_json::to_vec(v).map_err(|e| V2Error::plain(format!("v2reference: projection: {e}")))?;
    canonical_json_v2(&body)
}

/// Padded base64 of a held byte string, or `null` when none is held.
fn bytes_or_null(b: &[u8]) -> Value {
    if b.is_empty() {
        Value::Null
    } else {
        Value::String(STANDARD.encode(b))
    }
}

/// Unlabelled lowercase hex SHA-384 of exact stored bytes, or `null` when
/// none are stored.
fn sha384_or_null(b: &[u8]) -> Value {
    if b.is_empty() {
        Value::Null
    } else {
        Value::String(sha384_hex(b))
    }
}

/// The sealed claim object of §7.13.
fn sealed_claim_projection(c: &V2ChallengeClaim) -> Value {
    let evaluators: Vec<Value> = c
        .constraint_evaluators
        .iter()
        .map(|e| json!({"profile_digest": e.profile_digest, "type": e.kind}))
        .collect();
    let rate_batch: Vec<Value> = c
        .rate_batch
        .iter()
        .map(|r| json!({"cert_id": r.cert_id, "issuer_id": r.issuer_id, "limit": r.limit, "window_s": r.window_s}))
        .collect();
    let policy = if c.context_policy_digest.is_empty() {
        Value::Null
    } else {
        Value::String(c.context_policy_digest.clone())
    };
    json!({
        "agent_id": c.agent_id,
        "bundle_hash": c.bundle_hash,
        "challenge_digest": c.challenge_digest,
        "claim_id": c.claim_id,
        "clock_skew_seconds": c.clock_skew_seconds,
        "constraint_evaluators": evaluators,
        "context_policy_digest": policy,
        "expires_at": c.expires_at,
        "issued_at": c.issued_at,
        "issuer_ids": c.issuer_ids,
        "max_age_seconds": c.max_age_seconds,
        "namespace": c.namespace,
        "proof_digest": c.proof_digest,
        "rate_batch": rate_batch,
        "replay_epoch": c.replay_epoch,
        "required_scope": c.required_scope,
        "requires_rate": c.requires_rate,
        "stream_id": bytes_or_null(c.stream_id.as_deref().unwrap_or_default()),
        "stream_seq": c.stream_seq,
        "verifier_id": c.verifier_id,
    })
}

/// The evaluation progress object of §7.5 with its five members.
fn progress_projection(p: &V2EvaluationProgress) -> Value {
    let evidence: Vec<Value> = p
        .status_evidence
        .iter()
        .map(|e| {
            json!({
                "digest": e.digest,
                "issuer_id": e.issuer_id,
                "object_type_code": e.object_type,
                "sequence": e.sequence,
                "status_key_id": e.status_key_id,
            })
        })
        .collect();
    json!({
        "context_assessment": p.context_assessment,
        "context_policy_digest": p.context_policy_digest,
        "status_assessment": p.status_assessment,
        "status_evidence_digests": evidence,
        "trust_assessment": p.trust_assessment,
    })
}

fn claim_projection(id: &str, r: &ClaimRecord) -> Value {
    let release = r.release.as_ref().map(|rel| {
        let reason = (!rel.reason.is_empty()).then_some(rel.reason.as_str());
        json!({"ack_timestamp": rel.ack_timestamp, "claim_id": rel.claim_id, "entry_hash": STANDARD.encode(&rel.entry_hash),
            "outcome": rel.outcome.as_str(), "reason": reason})
    });
    let state = match r.state {
        ClaimState::Evaluating => "evaluating",
        ClaimState::Terminal => "terminal",
    };
    json!({
        "abandoned": r.abandoned,
        "allow_horizon": r.allow_horizon,
        "claim": sealed_claim_projection(&r.claim),
        "claim_id": id,
        "claimed_at": r.claimed_at,
        "finalized_at": r.finalized_at,
        "lease_expires_at": r.lease_expires_at,
        "log_sequence": r.outbox_index.map(|i| i as i64 + 1),
        "owner_digest": STANDARD.encode(r.owner_digest),
        "progress": progress_projection(&r.progress),
        "receipt_body_sha384": sha384_or_null(&r.receipt_body),
        "release": release,
        "state": state,
        "terminal_sha384": sha384_or_null(&r.terminal),
    })
}

fn issuance_projection(e: &ExpectedChallengeV2) -> Value {
    let agent_key = e.expected_agent_public_key.as_ref().map(|k| {
        json!({"ed25519": STANDARD.encode(&k.ed25519), "ml_dsa_65": STANDARD.encode(&k.ml_dsa_65)})
    });
    let policy = e.context_policy.as_ref().map(|p| {
        json!({
            "expected_session_context": bytes_or_null(&p.expected_session_context()),
            "profile": p.profile(),
            "require_bound": p.require_bound(),
            "required_fields": p.required_fields(),
            "version": 1,
        })
    });
    json!({
        "context_policy": policy,
        "expected_agent_id": e.expected_agent_id,
        "expected_agent_pub_key": agent_key,
        "expected_receiver_id": e.expected_receiver_id,
        "expected_session_context": bytes_or_null(e.expected_session_context.as_deref().unwrap_or_default()),
        "expires_at": e.expires_at,
        "issued_at": e.issued_at,
        "replay_epoch": e.replay_epoch,
        "value": STANDARD.encode(&e.value),
        "verifier_id": e.verifier_id,
        "verifier_namespace": e.verifier_namespace,
    })
}

/// The RatifyCanonicalJSON of the store's projection members.
pub(crate) struct StoreMembers {
    pub(crate) claims: Vec<u8>,
    pub(crate) streams: Vec<u8>,
    pub(crate) rate_counters: Vec<u8>,
    pub(crate) receipt_log: Vec<u8>,
}

/// Go `storeMembersLocked`: every claim in every state (evaluating,
/// terminal, interrupted, abandoned) with its sealed values and release
/// record, every stream sequence, every rate counter, and the receipt log
/// with its outbox, in the §7.13 record encodings. Checkpoint
/// acknowledgements and clock readings are excluded.
pub(crate) fn store_members(s: &StoreState) -> V2Result<StoreMembers> {
    // BTreeMap iteration yields each collection in its §7.13 sort order:
    // strings compare by UTF-8 bytes, byte strings by unsigned bytes.
    let claims: Vec<Value> = s.claims.iter().map(|(id, r)| claim_projection(id, r)).collect();
    let streams: Vec<Value> = s
        .streams
        .iter()
        .map(|((namespace, agent_id, stream_id), seq)| {
            json!({"agent_id": agent_id, "last_sequence": seq, "namespace": namespace, "stream_id": STANDARD.encode(stream_id)})
        })
        .collect();
    let rates: Vec<Value> = s
        .rate_commits
        .iter()
        .map(|((issuer, cert, window), commits)| {
            json!({"cert_id": cert, "commits": commits, "issuer_id": issuer, "window_s": window})
        })
        .collect();
    let entries: Vec<Value> = s
        .outbox
        .iter()
        .enumerate()
        .map(|(i, e)| {
            json!({
                "body_sha384": sha384_hex(&e.body),
                "claim_id": e.claim_id,
                "entry_hash": bytes_or_null(&e.digest),
                "sequence": i + 1,
            })
        })
        .collect();
    Ok(StoreMembers {
        claims: canonical(&Value::Array(claims))?,
        streams: canonical(&Value::Array(streams))?,
        rate_counters: canonical(&Value::Array(rates))?,
        receipt_log: canonical(&json!({"entries": entries, "frozen": s.log_frozen, "log_id": s.log_id}))?,
    })
}

/// Go `stateDigestsLocked`: the digests of the store members.
pub(crate) fn store_state_digests(s: &StoreState) -> V2Result<StoreDigests> {
    let m = store_members(s)?;
    Ok(StoreDigests {
        claims: sha384_hex(&m.claims),
        streams: sha384_hex(&m.streams),
        rate_counters: sha384_hex(&m.rate_counters),
        receipt_log: sha384_hex(&m.receipt_log),
    })
}

/// Go `issuanceMemberLocked`: the RatifyCanonicalJSON of the
/// `issuance_records` member, sorted by (verifier_namespace, replay_epoch,
/// value).
fn issuance_member(issuance: &TestOnlyChallengeIssuanceStore) -> V2Result<Vec<u8>> {
    let mut records: Vec<ExpectedChallengeV2> = issuance.records().into_values().collect();
    records.sort_by(|a, b| {
        a.verifier_namespace
            .as_bytes()
            .cmp(b.verifier_namespace.as_bytes())
            .then(a.replay_epoch.cmp(&b.replay_epoch))
            .then(a.value.cmp(&b.value))
    });
    canonical(&Value::Array(records.iter().map(issuance_projection).collect()))
}

/// Go `completeStateDigest`: the labelled SHA-384 of the projection bytes.
fn complete_state_digest(projection: &[u8]) -> Vec<u8> {
    let mut h = Sha384::new();
    h.update(DEVICE_STATE_LABEL.as_bytes());
    h.update([0u8]);
    h.update(projection);
    h.finalize().to_vec()
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

    /// Go `projectionLocked`: the RatifyCanonicalJSON of the version 1
    /// projection object.
    fn projection(&self, store: &StoreDigests, issuance_digest: &str) -> V2Result<Vec<u8>> {
        let (head, snapshot) = self.journal.anchored();
        canonical(&json!({
            "claims": store.claims,
            "issuance_records": issuance_digest,
            "log_id": self.log_id,
            "rate_counters": store.rate_counters,
            "receipt_log": store.receipt_log,
            "replay_epoch": self.replay_epoch,
            "security_journal": {"generation": head.generation, "snapshot_sha384": sha384_hex(&snapshot)},
            "streams": store.streams,
            "version": DEVICE_STATE_VERSION,
        }))
    }

    /// Go `composeLocked`: the complete-state digest for the given store
    /// member digests and the current journal and issuance records.
    pub(crate) fn compose(&self, store: &StoreDigests) -> V2Result<Vec<u8>> {
        let issuance = issuance_member(&self.issuance)?;
        Ok(complete_state_digest(&self.projection(store, &sha384_hex(&issuance))?))
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

    /// The §7.13 projection of the primary's current records: the canonical
    /// bytes of every member, the projection object, and the complete-state
    /// digest.
    pub fn projection_test_only(&self) -> V2Result<DeviceStateProjectionTestOnly> {
        let members = store_members(&self.store.lock())?;
        let issuance_records = issuance_member(&self.shared.issuance)?;
        let digests = StoreDigests {
            claims: sha384_hex(&members.claims),
            streams: sha384_hex(&members.streams),
            rate_counters: sha384_hex(&members.rate_counters),
            receipt_log: sha384_hex(&members.receipt_log),
        };
        let projection = self.shared.projection(&digests, &sha384_hex(&issuance_records))?;
        Ok(DeviceStateProjectionTestOnly {
            claims: members.claims,
            streams: members.streams,
            rate_counters: members.rate_counters,
            receipt_log: members.receipt_log,
            issuance_records,
            complete_state_digest: complete_state_digest(&projection),
            projection,
        })
    }

    /// A primary holding exactly the records of one `state` object of
    /// `testvectors/v2/device-state.json` (the §7.13 record encodings, with
    /// sealed bytes as `terminal_b64`, `receipt_body_b64`, `body_b64`, and
    /// `snapshot_b64`).
    pub fn from_records_test_only(state_json: &[u8]) -> V2Result<Self> {
        load_records(state_json).map_err(|e| e.classify(V2ErrorClass::Malformed))
    }
}

/// The canonical bytes of every §7.13 projection member, the projection
/// object, and the complete-state digest of a primary. TEST ONLY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStateProjectionTestOnly {
    pub claims: Vec<u8>,
    pub streams: Vec<u8>,
    pub rate_counters: Vec<u8>,
    pub receipt_log: Vec<u8>,
    pub issuance_records: Vec<u8>,
    pub projection: Vec<u8>,
    pub complete_state_digest: Vec<u8>,
}

fn field<'a>(v: &'a Value, key: &str) -> V2Result<&'a Value> {
    v.get(key).ok_or_else(|| V2Error::plain(format!("v2reference: device state: missing {key:?}")))
}

fn text(v: &Value, key: &str) -> V2Result<String> {
    field(v, key)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| V2Error::plain(format!("v2reference: device state: {key:?} is not a string")))
}

fn int(v: &Value, key: &str) -> V2Result<i64> {
    field(v, key)?
        .as_i64()
        .ok_or_else(|| V2Error::plain(format!("v2reference: device state: {key:?} is not an integer")))
}

fn flag(v: &Value, key: &str) -> V2Result<bool> {
    field(v, key)?
        .as_bool()
        .ok_or_else(|| V2Error::plain(format!("v2reference: device state: {key:?} is not a boolean")))
}

fn items<'a>(v: &'a Value, key: &str) -> V2Result<&'a Vec<Value>> {
    field(v, key)?
        .as_array()
        .ok_or_else(|| V2Error::plain(format!("v2reference: device state: {key:?} is not an array")))
}

fn texts(v: &Value, key: &str) -> V2Result<Vec<String>> {
    items(v, key)?
        .iter()
        .map(|x| x.as_str().map(str::to_string).ok_or_else(|| V2Error::plain("v2reference: device state: expected strings")))
        .collect()
}

/// Base64 bytes, or empty for `null`.
fn opt_bytes(v: &Value, key: &str) -> V2Result<Option<Vec<u8>>> {
    match field(v, key)? {
        Value::Null => Ok(None),
        Value::String(s) => STANDARD
            .decode(s)
            .map(Some)
            .map_err(|_| V2Error::plain(format!("v2reference: device state: {key:?} is not base64"))),
        _ => Err(V2Error::plain(format!("v2reference: device state: {key:?} is not base64 or null"))),
    }
}

fn bytes(v: &Value, key: &str) -> V2Result<Vec<u8>> {
    Ok(opt_bytes(v, key)?.unwrap_or_default())
}

fn load_records(state_json: &[u8]) -> V2Result<DevicePrimaryTestOnly> {
    use crate::v2::claim_store::V2ChallengeClaim;
    use crate::v2::context_policy::V2ContextPolicy;
    use crate::v2::evaluator::ConstraintEvaluatorRefV2;
    use crate::v2::rate_reservation::V2RateReservation;
    use crate::v2::receipt::StatusEvidenceEntryV2;
    use crate::v2::release::{V2ReleaseRecord, V2ReleaseStatus};
    use super::store::OutboxEntry;

    let st: Value = serde_json::from_slice(state_json)
        .map_err(|e| V2Error::plain(format!("v2reference: device state is not JSON: {e}")))?;
    let (_, private) = crate::crypto::generate_hybrid_keypair();
    let store = Store::new(1_800_000_000, 30, &text(&st, "log_id")?, &private)?;
    {
        let mut s = store.lock();
        for c in items(&st, "claims")? {
            let sc = field(c, "claim")?;
            let mut evaluators = Vec::new();
            for e in items(sc, "constraint_evaluators")? {
                evaluators.push(ConstraintEvaluatorRefV2 { kind: text(e, "type")?, profile_digest: text(e, "profile_digest")? });
            }
            let mut rate_batch = Vec::new();
            for r in items(sc, "rate_batch")? {
                rate_batch.push(V2RateReservation {
                    issuer_id: text(r, "issuer_id")?,
                    cert_id: text(r, "cert_id")?,
                    window_s: int(r, "window_s")?,
                    limit: int(r, "limit")?,
                });
            }
            let claim = V2ChallengeClaim {
                claim_id: text(sc, "claim_id")?,
                namespace: text(sc, "namespace")?,
                replay_epoch: int(sc, "replay_epoch")?,
                challenge_digest: text(sc, "challenge_digest")?,
                proof_digest: text(sc, "proof_digest")?,
                bundle_hash: text(sc, "bundle_hash")?,
                issuer_ids: texts(sc, "issuer_ids")?,
                required_scope: text(sc, "required_scope")?,
                context_policy_digest: field(sc, "context_policy_digest")?.as_str().unwrap_or_default().to_string(),
                verifier_id: text(sc, "verifier_id")?,
                agent_id: text(sc, "agent_id")?,
                requires_rate: flag(sc, "requires_rate")?,
                rate_batch,
                issued_at: int(sc, "issued_at")?,
                expires_at: int(sc, "expires_at")?,
                max_age_seconds: int(sc, "max_age_seconds")?,
                clock_skew_seconds: int(sc, "clock_skew_seconds")?,
                stream_id: opt_bytes(sc, "stream_id")?,
                stream_seq: field(sc, "stream_seq")?.as_i64(),
                constraint_evaluators: evaluators,
            };
            let p = field(c, "progress")?;
            let mut evidence = Vec::new();
            for e in items(p, "status_evidence_digests")? {
                evidence.push(StatusEvidenceEntryV2 {
                    issuer_id: text(e, "issuer_id")?,
                    status_key_id: text(e, "status_key_id")?,
                    sequence: int(e, "sequence")?,
                    object_type: u16::try_from(int(e, "object_type_code")?)
                        .map_err(|_| V2Error::plain("v2reference: device state: object type code out of range"))?,
                    digest: text(e, "digest")?,
                });
            }
            let progress = V2EvaluationProgress {
                trust_assessment: text(p, "trust_assessment")?,
                status_assessment: text(p, "status_assessment")?,
                context_assessment: text(p, "context_assessment")?,
                context_policy_digest: field(p, "context_policy_digest")?.as_str().map(str::to_string),
                status_evidence: evidence,
            };
            let release = match field(c, "release")? {
                Value::Null => None,
                r => Some(V2ReleaseRecord {
                    claim_id: text(r, "claim_id")?,
                    entry_hash: bytes(r, "entry_hash")?,
                    ack_timestamp: int(r, "ack_timestamp")?,
                    outcome: match text(r, "outcome")?.as_str() {
                        "released" => V2ReleaseStatus::Released,
                        "withheld" => V2ReleaseStatus::Withheld,
                        _ => return Err(V2Error::plain("v2reference: device state: unknown release outcome")),
                    },
                    reason: field(r, "reason")?.as_str().unwrap_or_default().to_string(),
                }),
            };
            let owner = bytes(c, "owner_digest")?;
            let owner_digest: [u8; 32] = owner
                .try_into()
                .map_err(|_| V2Error::plain("v2reference: device state: owner_digest is not 32 bytes"))?;
            let outbox_index = match field(c, "log_sequence")?.as_i64() {
                Some(n) if n >= 1 => Some((n - 1) as usize),
                Some(_) => return Err(V2Error::plain("v2reference: device state: log_sequence starts at 1")),
                None => None,
            };
            let state = match text(c, "state")?.as_str() {
                "evaluating" => ClaimState::Evaluating,
                "terminal" => ClaimState::Terminal,
                other => return Err(V2Error::plain(format!("v2reference: device state: unknown claim state {other:?}"))),
            };
            s.claims.insert(
                text(c, "claim_id")?,
                ClaimRecord {
                    claim,
                    owner_digest,
                    lease_expires_at: int(c, "lease_expires_at")?,
                    state,
                    terminal: bytes(c, "terminal_b64")?,
                    receipt_body: bytes(c, "receipt_body_b64")?,
                    allow_horizon: int(c, "allow_horizon")?,
                    claimed_at: int(c, "claimed_at")?,
                    finalized_at: int(c, "finalized_at")?,
                    release,
                    progress,
                    abandoned: flag(c, "abandoned")?,
                    outbox_index,
                },
            );
        }
        for x in items(&st, "streams")? {
            s.streams.insert(
                (text(x, "namespace")?, text(x, "agent_id")?, bytes(x, "stream_id")?),
                int(x, "last_sequence")?,
            );
        }
        for r in items(&st, "rate_counters")? {
            let commits = items(r, "commits")?
                .iter()
                .map(|n| n.as_i64().ok_or_else(|| V2Error::plain("v2reference: device state: commit is not an integer")))
                .collect::<V2Result<Vec<i64>>>()?;
            s.rate_commits.insert((text(r, "issuer_id")?, text(r, "cert_id")?, int(r, "window_s")?), commits);
        }
        let log = field(&st, "receipt_log")?;
        for e in items(log, "entries")? {
            s.outbox.push(OutboxEntry {
                claim_id: text(e, "claim_id")?,
                body: bytes(e, "body_b64")?,
                wire: None,
                digest: bytes(e, "entry_hash")?,
                ack: None,
            });
        }
        s.log_frozen = flag(log, "frozen")?;
    }
    let journal_state = field(&st, "security_journal")?;
    let generation = u64::try_from(int(journal_state, "generation")?)
        .map_err(|_| V2Error::plain("v2reference: device state: negative journal generation"))?;
    let snapshot = bytes(journal_state, "snapshot_b64")?;
    let head = SecurityJournalHeadV2 {
        generation,
        digest: crate::v2::journal_snapshot::security_journal_snapshot_digest_v2(&snapshot),
    };
    let issuance = TestOnlyChallengeIssuanceStore::new();
    let mut records = std::collections::BTreeMap::new();
    for r in items(&st, "issuance_records")? {
        let context_policy = match field(r, "context_policy")? {
            Value::Null => None,
            p => Some(V2ContextPolicy::new(
                &text(p, "profile")?,
                flag(p, "require_bound")?,
                &texts(p, "required_fields")?,
                &bytes(p, "expected_session_context")?,
            )?),
        };
        let expected_agent_public_key = match field(r, "expected_agent_pub_key")? {
            Value::Null => None,
            k => Some(crate::types::HybridPublicKey { ed25519: bytes(k, "ed25519")?, ml_dsa_65: bytes(k, "ml_dsa_65")? }),
        };
        let record = ExpectedChallengeV2 {
            value: bytes(r, "value")?,
            issued_at: int(r, "issued_at")?,
            expires_at: int(r, "expires_at")?,
            verifier_namespace: text(r, "verifier_namespace")?,
            replay_epoch: int(r, "replay_epoch")?,
            verifier_id: text(r, "verifier_id")?,
            expected_agent_id: text(r, "expected_agent_id")?,
            expected_agent_public_key,
            expected_receiver_id: text(r, "expected_receiver_id")?,
            expected_session_context: opt_bytes(r, "expected_session_context")?,
            context_policy,
        };
        let digest = crate::v2::operation_context::challenge_claim_digest_v2(&record.value)?;
        records.insert(
            super::challenges::issuance_key(&record.verifier_namespace, record.replay_epoch, &digest),
            record,
        );
    }
    issuance.set_records(records);
    let store = Arc::new(store);
    let log_id = store.lock().log_id.clone();
    Ok(DevicePrimaryTestOnly::assemble(
        store,
        int(&st, "replay_epoch")?,
        log_id,
        JournalStore::from_anchored(head, snapshot),
        issuance,
    ))
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
    use crate::v2::release::{V2ReleaseRecord, V2ReleaseStatus};

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
            outcome: V2ReleaseStatus::Released,
            reason: String::new(),
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
                s.streams.insert(("ns".into(), "agent".into(), vec![7; 32]), 2);
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
        let withheld = V2ReleaseRecord {
            outcome: V2ReleaseStatus::Withheld,
            reason: "challenge_expired".into(),
            ..release_record(1, 1_000)
        };
        for (name, record) in [
            ("release entry hash", release_record(2, 1_000)),
            ("release ack timestamp", release_record(1, 999)),
            ("release outcome", withheld),
        ] {
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
