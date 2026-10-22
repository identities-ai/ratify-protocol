//! `SecurityJournalV2` (SPEC-v2 §6.6): the deployment's status, role, and
//! status-key state, its validated transitions, and the anchored
//! compare-and-swap store contract. Mirrors Go `security_journal_v2.go`.
//!
//! The logical snapshot, digest, export/import, and version 1 migration live
//! in [`super::journal_snapshot`].
//!
//! Error classes: Go returns most journal errors unclassified. At this
//! module's public boundary they are classified as SPEC-v2 §6.6 implies:
//! journal operations (`record_security_key_role_v2`,
//! `configure_status_key_epoch_v2`, `apply_revocation_*_to_journal_v2`,
//! `register_*`) use `status_object_rejected`; the query
//! `revocation_status_from_journal_v2` uses `configuration_invalid`;
//! record validation (`validate_security_journal_v2`) uses `malformed`;
//! `validate_security_journal_transition_v2` reports an invalid record as
//! `malformed` and an invalid transition between valid records as
//! `status_object_rejected`. A class Go
//! already fixed (a reducer rejection, an epoch transition's
//! `configuration_invalid`, a store's own class) is kept.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::context::V2Context;
use super::crypto::sha384;
use super::errors::{plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::journal_snapshot::{same_security_journal_content_v2, security_journal_digest_v2};
use super::status::{
    apply_revocation_list_v2, apply_revocation_push_v2, canonicalize_state, compact, contains_all,
    equal_sets, key_id_plain, must_retain, revocation_status_for_cert_inner, semantic_key,
    transition_revocation_status_epoch_v2, validate_accepted_state, validate_binding,
    RevocationStatusPolicyV2, RevocationStatusResultV2, RevocationStatusStateV2, LIST, PUSH,
};
use super::wire::{RevocationListV2, RevocationPushV2, MAX_SAFE};
use crate::types::HybridPublicKey;

/// The current record version (canonical snapshot digest). Version 1
/// records use the legacy Go `encoding/json` digest and must be migrated.
pub(crate) const SECURITY_JOURNAL_VERSION_V2: u16 = 2;
/// The version 1 (alpha) record version, accepted only for migration.
pub(crate) const SECURITY_JOURNAL_LEGACY_VERSION: u16 = 1;

/// The independently anchored head of a deployment's security journal. A
/// backend must not derive its rollback protection solely from the journal
/// records it stores.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct SecurityJournalHeadV2 {
    pub generation: u64,
    pub digest: String,
}

/// Permanently assigns a key ID and both hybrid key components to one role
/// for a verifier deployment.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct KeyRoleBindingV2 {
    pub key_id: String,
    pub ed25519_digest: String,
    pub ml_dsa_65_digest: String,
    pub role: String,
}

/// Preserves every authenticated status-key epoch, including retired
/// epochs, for one issuer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct StatusKeyBindingV2 {
    pub issuer_id: String,
    pub epoch: u64,
    pub status_key_id: String,
    pub ed25519_digest: String,
    pub ml_dsa_65_digest: String,
}

/// The state whose loss or rollback can make verification unsafe. It is a
/// logical record; durability and anti-rollback guarantees come from
/// [`SecurityJournalStoreV2`].
///
/// Construct one with [`empty_security_journal_v2`],
/// `import_security_journal_snapshot_v2`, or
/// `decode_security_journal_json_v2` (or `Default` and field assignment).
#[derive(Debug, Clone, Default)]
pub struct SecurityJournalV2 {
    pub version: u16,
    pub generation: u64,
    pub previous_digest: String,
    pub digest: String,
    pub status_by_issuer: BTreeMap<String, RevocationStatusStateV2>,
    pub key_role_history: Vec<KeyRoleBindingV2>,
    pub status_key_history: Vec<StatusKeyBindingV2>,
    /// Members that were JSON `null` (Go nil slices and maps) when a
    /// version 1 record was decoded. Go's legacy digest re-encodes a nil
    /// slice as `null` and an empty one as `[]`; Rust cannot tell them apart
    /// without this record. It affects only the version 1 digest and the
    /// "incomplete shape" check, and is empty for every other journal.
    pub(crate) legacy_null_members: BTreeSet<String>,
}

/// Why a [`SecurityJournalStoreV2::compare_and_swap`] did not commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityJournalStoreErrorV2 {
    /// Another writer advanced the anchored journal (Go
    /// `ErrSecurityJournalConflictV2`). The operation must be reloaded and
    /// re-evaluated, not blindly retried with a stale state transition.
    Conflict,
    /// Any other store failure.
    Failed(V2Error),
}

impl fmt::Display for SecurityJournalStoreErrorV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityJournalStoreErrorV2::Conflict => {
                f.write_str(SECURITY_JOURNAL_CONFLICT_MESSAGE_V2)
            }
            SecurityJournalStoreErrorV2::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SecurityJournalStoreErrorV2 {}

impl From<V2Error> for SecurityJournalStoreErrorV2 {
    fn from(e: V2Error) -> Self {
        SecurityJournalStoreErrorV2::Failed(e)
    }
}

/// The diagnostic message of a compare-and-swap conflict reported through a
/// public journal operation (Go `ErrSecurityJournalConflictV2`).
pub const SECURITY_JOURNAL_CONFLICT_MESSAGE_V2: &str = "security journal compare-and-swap conflict";

/// Whether a public journal operation failed because another writer
/// advanced the anchored journal (Go `errors.Is(err,
/// ErrSecurityJournalConflictV2)`).
pub fn is_security_journal_conflict_v2(e: &V2Error) -> bool {
    e.message == SECURITY_JOURNAL_CONFLICT_MESSAGE_V2
}

impl SecurityJournalStoreErrorV2 {
    fn into_v2(self) -> V2Error {
        match self {
            SecurityJournalStoreErrorV2::Conflict => {
                V2Error::plain(SECURITY_JOURNAL_CONFLICT_MESSAGE_V2)
            }
            SecurityJournalStoreErrorV2::Failed(e) => e,
        }
    }
}

/// An atomic compare-and-swap store backed by an independent,
/// rollback-resistant head. `load` returns the record together with the
/// independently anchored head it was read against, or fails closed.
/// `compare_and_swap` must atomically advance both the durable record and its
/// independent head, reject stale writers with
/// [`SecurityJournalStoreErrorV2::Conflict`], and preserve enough history to
/// recover the anchored head after a crash. A normal file, database
/// transaction, or checksum chain does not by itself satisfy this contract.
/// No production backend is provided by this protocol library.
pub trait SecurityJournalStoreV2: Send + Sync {
    fn load(&self, ctx: &V2Context) -> V2Result<(SecurityJournalV2, SecurityJournalHeadV2)>;
    fn compare_and_swap(
        &self,
        ctx: &V2Context,
        expected: &SecurityJournalHeadV2,
        next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2>;
}

/// The only valid genesis record.
pub fn empty_security_journal_v2() -> SecurityJournalV2 {
    let mut journal = SecurityJournalV2 {
        version: SECURITY_JOURNAL_VERSION_V2,
        ..Default::default()
    };
    // Go ignores this error; the genesis snapshot always encodes.
    journal.digest = security_journal_digest_v2(&journal).unwrap_or_default();
    journal
}

/// Go `updateSecurityJournalV2`: one validated journal transition. The
/// backend's anchored CAS is the serialization point for concurrent callers.
pub(crate) fn update_security_journal_v2<F>(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    update: F,
) -> Result<SecurityJournalV2, SecurityJournalStoreErrorV2>
where
    F: FnOnce(&mut SecurityJournalV2) -> V2Result<()>,
{
    let current = load_anchored_security_journal_v2(ctx, store)?;
    let mut next = current.clone();
    update(&mut next)?;
    commit_security_journal_transition_v2(ctx, store, &current, next)
}

/// Go `commitSecurityJournalTransitionV2`: compacts and canonicalizes `next`,
/// returns `current` unchanged when the canonical content is identical
/// (no-op), and otherwise chains, validates, and commits it by
/// compare-and-swap against `current`'s head. A conflict is returned, never
/// retried.
pub(crate) fn commit_security_journal_transition_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    current: &SecurityJournalV2,
    mut next: SecurityJournalV2,
) -> Result<SecurityJournalV2, SecurityJournalStoreErrorV2> {
    prune_security_journal_observations_v2(&mut next);
    canonicalize_security_journal_v2(&mut next);
    if same_security_journal_content_v2(&next, current) {
        return Ok(current.clone());
    }
    next.generation = match current.generation.checked_add(1) {
        Some(g) if g <= MAX_SAFE as u64 => g,
        _ => return Err(V2Error::plain("security journal generation exhausted").into()),
    };
    next.version = SECURITY_JOURNAL_VERSION_V2;
    next.previous_digest = current.digest.clone();
    next.digest = String::new();
    next.digest = security_journal_digest_v2(&next)?;
    validate_security_journal_transition_inner(current, &next)
        .map_err(|e| e.context("invalid security journal transition"))?;
    let head = SecurityJournalHeadV2 {
        generation: current.generation,
        digest: current.digest.clone(),
    };
    match store.compare_and_swap(ctx, &head, &next) {
        Ok(()) => Ok(next),
        Err(SecurityJournalStoreErrorV2::Conflict) => Err(SecurityJournalStoreErrorV2::Conflict),
        Err(SecurityJournalStoreErrorV2::Failed(e)) => Err(SecurityJournalStoreErrorV2::Failed(
            e.context("commit rollback-protected security journal"),
        )),
    }
}

/// Go `loadAnchoredSecurityJournalV2`: loads a version 2 record and requires
/// it to match the anchored head returned with it.
pub(crate) fn load_anchored_security_journal_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
) -> V2Result<SecurityJournalV2> {
    let (current, head) = store
        .load(ctx)
        .map_err(|e| e.context("load rollback-protected security journal"))?;
    if head.generation != current.generation
        || head.digest.is_empty()
        || head.digest != current.digest
    {
        return plain("loaded security journal is not anchored by the store head");
    }
    if current.version != SECURITY_JOURNAL_VERSION_V2 {
        return plain(format!(
            "security journal version {} requires migration",
            current.version
        ));
    }
    validate_security_journal_inner(&current)
        .map_err(|e| e.context("validate loaded security journal"))?;
    Ok(current)
}

fn journal_op<T>(r: Result<T, SecurityJournalStoreErrorV2>) -> V2Result<T> {
    r.map_err(SecurityJournalStoreErrorV2::into_v2)
        .classify(V2ErrorClass::StatusObjectRejected)
}

/// Durably add a non-status key role after the caller has authenticated the
/// trust-configuration event that admits that key.
pub fn record_security_key_role_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    role: &str,
    public_key: &HybridPublicKey,
) -> V2Result<SecurityJournalV2> {
    if role == "status" {
        return plain("status keys must be recorded with their issuer and epoch")
            .classify(V2ErrorClass::StatusObjectRejected);
    }
    journal_op(update_security_journal_v2(ctx, store, |journal| {
        register_key_role_inner(journal, role, public_key)
    }))
}

/// Persist an authenticated status-key binding. A first binding starts at
/// epoch 1; later bindings must advance exactly one epoch and preserve
/// prior-epoch denials and authenticated evidence.
pub fn configure_status_key_epoch_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
) -> V2Result<SecurityJournalV2> {
    journal_op(update_security_journal_v2(ctx, store, |journal| {
        register_status_key_epoch_inner(journal, issuer_id, epoch, public_key)?;
        if let Some(prior) = journal.status_by_issuer.get(issuer_id) {
            if epoch == prior.status_key_epoch {
                return require_journal_status_key_v2(journal, issuer_id, epoch, public_key);
            }
            let updated =
                transition_revocation_status_epoch_v2(prior, issuer_id, epoch, public_key)?;
            journal
                .status_by_issuer
                .insert(issuer_id.to_string(), updated);
            return Ok(());
        }
        if epoch != 1 {
            return plain("first status-key epoch must be 1");
        }
        let key_id = key_id_plain(public_key)?;
        journal.status_by_issuer.insert(
            issuer_id.to_string(),
            RevocationStatusStateV2 {
                issuer_id: issuer_id.to_string(),
                status_key_epoch: epoch,
                status_key_id: key_id,
                ..Default::default()
            },
        );
        Ok(())
    }))
}

/// Authenticate, reduce, and atomically persist a full status snapshot under
/// the configured issuer key epoch.
#[allow(clippy::too_many_arguments)]
pub fn apply_revocation_list_to_journal_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    list: &RevocationListV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<SecurityJournalV2> {
    journal_op(update_security_journal_v2(ctx, store, |journal| {
        require_journal_status_key_v2(journal, issuer_id, epoch, public_key)?;
        let current = journal
            .status_by_issuer
            .get(issuer_id)
            .cloned()
            .unwrap_or_default();
        let state =
            apply_revocation_list_v2(&current, list, issuer_id, epoch, public_key, policy, now)?;
        journal
            .status_by_issuer
            .insert(issuer_id.to_string(), state);
        Ok(())
    }))
}

/// Authenticate, reduce, and atomically persist one push under the
/// configured issuer key epoch.
#[allow(clippy::too_many_arguments)]
pub fn apply_revocation_push_to_journal_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    push: &RevocationPushV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<SecurityJournalV2> {
    journal_op(update_security_journal_v2(ctx, store, |journal| {
        require_journal_status_key_v2(journal, issuer_id, epoch, public_key)?;
        let current = journal
            .status_by_issuer
            .get(issuer_id)
            .cloned()
            .unwrap_or_default();
        let state =
            apply_revocation_push_v2(&current, push, issuer_id, epoch, public_key, policy, now)?;
        journal
            .status_by_issuer
            .insert(issuer_id.to_string(), state);
        Ok(())
    }))
}

/// Read an anchored state and return a fail-closed status decision for one
/// issuer-scoped certificate reference. Go also returns an
/// indeterminate/unavailable result alongside an error; this port returns
/// only the error.
#[allow(clippy::too_many_arguments)]
pub fn revocation_status_from_journal_v2(
    ctx: &V2Context,
    store: &dyn SecurityJournalStoreV2,
    issuer_id: &str,
    cert_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusResultV2> {
    (|| {
        let journal = load_anchored_security_journal_v2(ctx, store)?;
        require_journal_status_key_v2(&journal, issuer_id, epoch, public_key)?;
        let state = journal
            .status_by_issuer
            .get(issuer_id)
            .cloned()
            .unwrap_or_default();
        revocation_status_for_cert_inner(&state, issuer_id, cert_id, epoch, public_key, policy, now)
    })()
    .classify(V2ErrorClass::ConfigurationInvalid)
}

pub(crate) fn require_journal_status_key_v2(
    journal: &SecurityJournalV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    if issuer_id.is_empty() || epoch == 0 {
        return plain("issuer and status-key epoch are required");
    }
    let Some(binding) = status_binding_at_epoch(&journal.status_key_history, issuer_id, epoch)
    else {
        return plain("issuer status key is not present in the retained trust history");
    };
    let actual = status_key_binding_v2(issuer_id, epoch, public_key)?;
    if *binding != actual {
        return plain("status key does not match the retained issuer and epoch binding");
    }
    match journal.status_by_issuer.get(issuer_id) {
        Some(state)
            if state.status_key_epoch == epoch && state.status_key_id == binding.status_key_id =>
        {
            Ok(())
        }
        _ => plain("status key is not the current issuer epoch"),
    }
}

/// Validate record integrity and internal indexes (class `malformed`).
pub fn validate_security_journal_v2(journal: &SecurityJournalV2) -> V2Result<()> {
    validate_security_journal_inner(journal).classify(V2ErrorClass::Malformed)
}

/// Go `ValidateSecurityJournalV2` with Go's (unclassified) error classes.
pub(crate) fn validate_security_journal_inner(journal: &SecurityJournalV2) -> V2Result<()> {
    let nil = |member: &str| journal.legacy_null_members.contains(member);
    if (journal.version != SECURITY_JOURNAL_VERSION_V2
        && journal.version != SECURITY_JOURNAL_LEGACY_VERSION)
        || nil("status_by_issuer")
        || nil("key_role_history")
        || nil("status_key_history")
    {
        return plain("security journal has unsupported or incomplete shape");
    }
    if journal.generation == 0 && !journal.previous_digest.is_empty() {
        return plain("security journal genesis has a predecessor");
    }
    if journal.generation == 0
        && (!journal.status_by_issuer.is_empty()
            || !journal.key_role_history.is_empty()
            || !journal.status_key_history.is_empty())
    {
        return plain("security journal genesis must be empty");
    }
    if journal.generation > 0
        && (journal.previous_digest.is_empty() || journal.previous_digest.len() != 96)
    {
        return plain("security journal record is missing its predecessor digest");
    }
    let digest = security_journal_digest_v2(journal)?;
    if journal.digest != digest {
        return plain("security journal digest mismatch");
    }
    for (issuer_id, state) in &journal.status_by_issuer {
        if issuer_id.is_empty() || state.issuer_id != *issuer_id || state.status_key_epoch == 0 {
            return plain("security journal contains a misbound issuer status state");
        }
        validate_binding(state, issuer_id, state.status_key_epoch)
            .map_err(|e| e.context(format!("invalid status state for issuer {issuer_id:?}")))?;
        validate_accepted_state(state).map_err(|e| {
            e.context(format!(
                "invalid accepted status state for issuer {issuer_id:?}"
            ))
        })?;
        match status_binding_at_epoch(
            &journal.status_key_history,
            issuer_id,
            state.status_key_epoch,
        ) {
            Some(binding) if binding.status_key_id == state.status_key_id => {}
            _ => return plain("current status state has no matching retained key binding"),
        }
        let mut max_observed = 0i64;
        let retired: Vec<String> = journal
            .status_key_history
            .iter()
            .filter(|b| b.issuer_id == *issuer_id && b.epoch < state.status_key_epoch)
            .map(|b| b.status_key_id.clone())
            .collect();
        for o in &state.observations {
            let bound =
                status_binding_at_epoch(&journal.status_key_history, issuer_id, o.status_key_epoch);
            if bound.is_none_or(|b| o.status_key_id != b.status_key_id)
                || o.sequence <= 0
                || o.sequence > MAX_SAFE
                || o.evidence_digest.len() != 48
                || o.body_digest.len() != 48
                || (o.object_type != LIST && o.object_type != PUSH)
            {
                return plain("security journal contains malformed or misbound status evidence");
            }
            if o.status_key_epoch == state.status_key_epoch && o.sequence > max_observed {
                max_observed = o.sequence;
            }
        }
        if state.max_observed_sequence != max_observed
            || !equal_sets(&state.retired_status_key_ids, &retired)
        {
            return plain("status state does not match retained sequence and key history");
        }
    }
    validate_key_role_history(&journal.key_role_history)?;
    validate_status_key_history(&journal.status_key_history, &journal.key_role_history)?;
    let mut latest: BTreeMap<&str, u64> = BTreeMap::new();
    for b in &journal.status_key_history {
        let entry = latest.entry(b.issuer_id.as_str()).or_insert(0);
        if b.epoch > *entry {
            *entry = b.epoch;
        }
    }
    for (issuer_id, epoch) in latest {
        match journal.status_by_issuer.get(issuer_id) {
            Some(state) if state.status_key_epoch == epoch => {}
            _ => {
                return plain(
                    "security journal status state is not at the latest retained issuer epoch",
                )
            }
        }
    }
    Ok(())
}

/// Enforce generation continuity and append-only key histories. An invalid
/// record is `malformed`; an invalid transition between valid records is
/// `status_object_rejected`. Status-state evolution itself is performed by
/// the reducer and the epoch transition before this validation.
pub fn validate_security_journal_transition_v2(
    current: &SecurityJournalV2,
    next: &SecurityJournalV2,
) -> V2Result<()> {
    validate_security_journal_v2(current).map_err(|e| e.context("invalid current journal"))?;
    validate_security_journal_v2(next).map_err(|e| e.context("invalid next journal"))?;
    validate_security_journal_transition_inner(current, next)
        .classify(V2ErrorClass::StatusObjectRejected)
}

/// Go `ValidateSecurityJournalTransitionV2` with Go's (unclassified) classes.
pub(crate) fn validate_security_journal_transition_inner(
    current: &SecurityJournalV2,
    next: &SecurityJournalV2,
) -> V2Result<()> {
    validate_security_journal_inner(current).map_err(|e| e.context("invalid current journal"))?;
    validate_security_journal_inner(next).map_err(|e| e.context("invalid next journal"))?;
    if current.generation.checked_add(1) != Some(next.generation)
        || next.previous_digest != current.digest
    {
        return plain("journal generation or predecessor is not contiguous");
    }
    if next.version != SECURITY_JOURNAL_VERSION_V2 {
        return plain(format!(
            "journal transitions must produce a version {SECURITY_JOURNAL_VERSION_V2} record"
        ));
    }
    if current.version == SECURITY_JOURNAL_LEGACY_VERSION
        && !same_security_journal_content_v2(current, next)
    {
        return plain("journal migration must not change logical content");
    }
    if !current
        .key_role_history
        .iter()
        .all(|b| next.key_role_history.contains(b))
        || !current
            .status_key_history
            .iter()
            .all(|b| next.status_key_history.contains(b))
    {
        return plain("journal key binding history was removed or rewritten");
    }
    for (issuer_id, state) in &current.status_by_issuer {
        let Some(next_state) = next.status_by_issuer.get(issuer_id) else {
            return plain("journal transition removed issuer status or a retained revocation");
        };
        if !contains_all(&next_state.deny_union_cert_ids, &state.deny_union_cert_ids) {
            return plain("journal transition removed issuer status or a retained revocation");
        }
        for old in &state.observations {
            // Go keys observations by their complete JSON encoding.
            if next_state.observations.contains(old) {
                continue;
            }
            if !must_retain(next_state, old) {
                continue;
            }
            // Go keeps the last observation per semantic key.
            let key = semantic_key(old);
            let compacted = next_state
                .observations
                .iter()
                .rev()
                .find(|o| semantic_key(o) == key);
            let lost = match compacted {
                None => true,
                Some(c) => {
                    !contains_all(&c.revoked_cert_ids, &old.revoked_cert_ids)
                        || (old.fork && !c.fork)
                        || (old.gap && next_state.reconciliation_required && !c.gap)
                        || (old.future_dated
                            && next_state.future_dated_object_observed
                            && !c.future_dated)
                }
            };
            if lost {
                return plain("journal transition removed authenticated status evidence");
            }
        }
        if next_state.status_key_epoch < state.status_key_epoch {
            return plain("journal transition rolled back a status-key epoch");
        }
        if next_state.status_key_epoch > state.status_key_epoch {
            let mut retired = state.retired_status_key_ids.clone();
            retired.push(state.status_key_id.clone());
            if next_state.status_key_id == state.status_key_id
                || state
                    .retired_status_key_ids
                    .contains(&next_state.status_key_id)
                || !equal_sets(&next_state.retired_status_key_ids, &retired)
                || next_state.has_floor
                || next_state.floor != 0
                || next_state.accepted_snapshot.is_some()
                || !next_state.accepted_cert_ids.is_empty()
                || next_state.has_preceding_checkpoint
                || next_state.preceding_floor != 0
                || !next_state.preceding_accepted_cert_ids.is_empty()
                || next_state.max_observed_sequence != 0
                || next_state.fork_sequence != 0
                || next_state.reconciliation_required
                || next_state.future_dated_object_observed
            {
                return plain(
                    "status-key epoch transition did not perform the required fail-closed reset",
                );
            }
            if next_state
                .observations
                .iter()
                .any(|o| o.status_key_epoch >= next_state.status_key_epoch)
            {
                return plain(
                    "status-key epoch transition contains evidence from the new epoch before bootstrap",
                );
            }
        }
        if next_state.status_key_epoch == state.status_key_epoch
            && state.has_floor
            && (!next_state.has_floor || next_state.floor < state.floor)
        {
            return plain("journal transition rolled back the accepted status floor");
        }
        if next_state.status_key_epoch == state.status_key_epoch
            && next_state.max_observed_sequence < state.max_observed_sequence
        {
            return plain("journal transition rolled back the observed status sequence");
        }
        if next_state.status_key_epoch == state.status_key_epoch
            && state.reconciliation_required
            && !next_state.reconciliation_required
            && (!has_accepted_snapshot_after(
                next_state,
                state.status_key_epoch,
                state.max_observed_sequence,
                state.fork_sequence,
                &state.deny_union_cert_ids,
            ) || !contains_all(&next_state.accepted_cert_ids, &state.deny_union_cert_ids))
        {
            return plain(
                "journal transition cleared reconciliation without a caught-up full snapshot",
            );
        }
    }
    for (issuer_id, state) in &next.status_by_issuer {
        if !current.status_by_issuer.contains_key(issuer_id)
            && status_binding_at_epoch(&next.status_key_history, issuer_id, state.status_key_epoch)
                .is_none()
        {
            return plain("new issuer status state lacks authenticated key history");
        }
    }
    Ok(())
}

fn has_accepted_snapshot_after(
    state: &RevocationStatusStateV2,
    epoch: u64,
    min_sequence: i64,
    fork_sequence: i64,
    deny_union: &[String],
) -> bool {
    state.observations.iter().any(|o| {
        o.status_key_epoch == epoch
            && o.object_type == LIST
            && o.accepted
            && o.sequence >= min_sequence
            && (fork_sequence == 0 || o.sequence > fork_sequence)
            && contains_all(&o.revoked_cert_ids, deny_union)
    })
}

/// Go `pruneSecurityJournalObservationsV2` over every issuer state.
pub(crate) fn prune_security_journal_observations_v2(journal: &mut SecurityJournalV2) {
    for state in journal.status_by_issuer.values_mut() {
        *state = compact(std::mem::take(state));
    }
}

/// Go `canonicalizeSecurityJournalV2`: every set and history in snapshot
/// order. Observation order is compaction order and is not changed here.
pub(crate) fn canonicalize_security_journal_v2(journal: &mut SecurityJournalV2) {
    sort_key_role_history(&mut journal.key_role_history);
    sort_status_key_history(&mut journal.status_key_history);
    for state in journal.status_by_issuer.values_mut() {
        *state = canonicalize_state(std::mem::take(state));
    }
}

/// Record a permanent global role assignment. Repeating the identical
/// assignment is idempotent; any key-ID or component reuse is denied (class
/// `status_object_rejected`).
pub fn register_key_role_v2(
    journal: &mut SecurityJournalV2,
    role: &str,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    register_key_role_inner(journal, role, public_key).classify(V2ErrorClass::StatusObjectRejected)
}

fn register_key_role_inner(
    journal: &mut SecurityJournalV2,
    role: &str,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    if !valid_security_key_role(role) || role == "status" {
        return plain("security key role is invalid");
    }
    register_any_key_role(journal, role, public_key)
}

fn register_any_key_role(
    journal: &mut SecurityJournalV2,
    role: &str,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    let binding = key_role_binding_v2(role, public_key)?;
    for existing in &journal.key_role_history {
        if *existing == binding {
            return Ok(());
        }
        if existing.key_id == binding.key_id
            || existing.ed25519_digest == binding.ed25519_digest
            || existing.ml_dsa_65_digest == binding.ml_dsa_65_digest
            || existing.ed25519_digest == binding.ml_dsa_65_digest
            || existing.ml_dsa_65_digest == binding.ed25519_digest
        {
            return plain(format!(
                "hybrid key ID or component is already permanently assigned to role {:?}",
                existing.role
            ));
        }
    }
    journal.key_role_history.push(binding);
    sort_key_role_history(&mut journal.key_role_history);
    Ok(())
}

/// Record caller-authenticated status-key history and the corresponding
/// permanent global status role before status objects apply (class
/// `status_object_rejected`).
pub fn register_status_key_epoch_v2(
    journal: &mut SecurityJournalV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    register_status_key_epoch_inner(journal, issuer_id, epoch, public_key)
        .classify(V2ErrorClass::StatusObjectRejected)
}

fn register_status_key_epoch_inner(
    journal: &mut SecurityJournalV2,
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
) -> V2Result<()> {
    if issuer_id.is_empty() || epoch == 0 || epoch > MAX_SAFE as u64 {
        return plain("status-key binding has invalid issuer or epoch");
    }
    let binding = status_key_binding_v2(issuer_id, epoch, public_key)?;
    for existing in &journal.status_key_history {
        if existing.issuer_id == issuer_id && existing.epoch == epoch {
            if *existing == binding {
                return Ok(());
            }
            return plain("status-key epoch is permanently bound to a different key");
        }
        if existing.status_key_id == binding.status_key_id
            || existing.ed25519_digest == binding.ed25519_digest
            || existing.ml_dsa_65_digest == binding.ml_dsa_65_digest
        {
            return plain("status key was previously bound in this deployment");
        }
    }
    let highest = journal
        .status_key_history
        .iter()
        .filter(|b| b.issuer_id == issuer_id)
        .map(|b| b.epoch)
        .max()
        .unwrap_or(0);
    if Some(epoch) != highest.checked_add(1) {
        return plain("status-key epoch must advance by one from retained issuer history");
    }
    register_any_key_role(journal, "status", public_key)?;
    journal.status_key_history.push(binding);
    sort_status_key_history(&mut journal.status_key_history);
    Ok(())
}

/// Go `keyRoleBindingV2`: the key ID and SHA-384 component digests.
pub(crate) fn key_role_binding_v2(
    role: &str,
    public_key: &HybridPublicKey,
) -> V2Result<KeyRoleBindingV2> {
    let key_id = key_id_plain(public_key)?;
    Ok(KeyRoleBindingV2 {
        key_id,
        ed25519_digest: hex::encode(sha384(&[&public_key.ed25519])),
        ml_dsa_65_digest: hex::encode(sha384(&[&public_key.ml_dsa_65])),
        role: role.to_string(),
    })
}

fn status_key_binding_v2(
    issuer_id: &str,
    epoch: u64,
    public_key: &HybridPublicKey,
) -> V2Result<StatusKeyBindingV2> {
    let role = key_role_binding_v2("status", public_key)?;
    Ok(StatusKeyBindingV2 {
        issuer_id: issuer_id.to_string(),
        epoch,
        status_key_id: role.key_id,
        ed25519_digest: role.ed25519_digest,
        ml_dsa_65_digest: role.ml_dsa_65_digest,
    })
}

fn validate_key_role_history(history: &[KeyRoleBindingV2]) -> V2Result<()> {
    let mut ids: BTreeMap<&str, &KeyRoleBindingV2> = BTreeMap::new();
    let mut components: BTreeMap<&str, &KeyRoleBindingV2> = BTreeMap::new();
    for b in history {
        if b.key_id.is_empty()
            || !valid_security_key_role(&b.role)
            || !valid_digest_hex(&b.ed25519_digest)
            || !valid_digest_hex(&b.ml_dsa_65_digest)
        {
            return plain("security journal contains malformed key-role history");
        }
        if ids.get(b.key_id.as_str()).is_some_and(|prior| *prior != b) {
            return plain("security journal reuses a key ID across roles");
        }
        ids.insert(&b.key_id, b);
        for component in [b.ed25519_digest.as_str(), b.ml_dsa_65_digest.as_str()] {
            if components.get(component).is_some_and(|prior| *prior != b) {
                return plain("security journal reuses key material across roles");
            }
            components.insert(component, b);
        }
    }
    Ok(())
}

fn validate_status_key_history(
    history: &[StatusKeyBindingV2],
    roles: &[KeyRoleBindingV2],
) -> V2Result<()> {
    let mut last_epoch: BTreeMap<&str, u64> = BTreeMap::new();
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut components: BTreeSet<&str> = BTreeSet::new();
    for b in history {
        if b.issuer_id.is_empty()
            || b.epoch == 0
            || b.status_key_id.is_empty()
            || !valid_digest_hex(&b.ed25519_digest)
            || !valid_digest_hex(&b.ml_dsa_65_digest)
        {
            return plain("security journal contains malformed status-key history");
        }
        let last = last_epoch.get(b.issuer_id.as_str()).copied().unwrap_or(0);
        if last.checked_add(1) != Some(b.epoch) {
            return plain("security journal status-key epochs are missing or out of order");
        }
        last_epoch.insert(&b.issuer_id, b.epoch);
        let role = roles.iter().find(|r| {
            r.key_id == b.status_key_id
                && r.ed25519_digest == b.ed25519_digest
                && r.ml_dsa_65_digest == b.ml_dsa_65_digest
        });
        if role.is_none_or(|r| r.role != "status") {
            return plain("status-key history lacks its global status role assignment");
        }
        if !ids.insert(&b.status_key_id) {
            return plain("security journal reuses a status key ID");
        }
        for component in [b.ed25519_digest.as_str(), b.ml_dsa_65_digest.as_str()] {
            if !components.insert(component) {
                return plain("security journal reuses a status-key component");
            }
        }
    }
    Ok(())
}

pub(crate) fn status_binding_at_epoch<'a>(
    history: &'a [StatusKeyBindingV2],
    issuer_id: &str,
    epoch: u64,
) -> Option<&'a StatusKeyBindingV2> {
    history
        .iter()
        .find(|b| b.issuer_id == issuer_id && b.epoch == epoch)
}

fn valid_security_key_role(role: &str) -> bool {
    matches!(
        role,
        "status"
            | "delegation"
            | "rotation"
            | "verifier"
            | "witness"
            | "receiver"
            | "issuer"
            | "other"
    )
}

fn valid_digest_hex(value: &str) -> bool {
    hex::decode(value).is_ok_and(|d| d.len() == 48 && hex::encode(&d) == value)
}

pub(crate) fn sort_key_role_history(history: &mut [KeyRoleBindingV2]) {
    history.sort_by(|a, b| (&a.key_id, &a.role).cmp(&(&b.key_id, &b.role)));
}

pub(crate) fn sort_status_key_history(history: &mut [StatusKeyBindingV2]) {
    history.sort_by(|a, b| (&a.issuer_id, a.epoch).cmp(&(&b.issuer_id, b.epoch)));
}
