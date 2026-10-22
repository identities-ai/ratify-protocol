//! Issuer status reducer (rollback-protected state), status queries, and
//! CertificateRef status aggregation. Mirrors Go `status_state_v2.go`,
//! `status_evaluation_v2.go`, and the observation compaction and accepted-state
//! validation from `security_journal_v2.go`.

use std::collections::{BTreeMap, BTreeSet};

use super::crypto::{key_id_v2, sha384, valid_prefixed_digest, valid_v2_id};
use super::errors::{plain, Classify, V2Error, V2ErrorClass, V2Result};
use super::json::{canonical, CJ};
use super::limits::{
    valid_v2_timestamp, V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_STATUS_LIFETIME_SECONDS,
};
use super::receipt::{
    compare_evidence, has_accepted_status_history_per_issuer, StatusEvidenceEntryV2,
};
use super::wire::{
    decode_revocation_list_v2, encode_revocation_list_v2, revocation_list_v2_signable_bytes,
    revocation_push_v2_signable_bytes, status_evidence_digest_list_v2,
    status_evidence_digest_push_v2, verify_revocation_list_v2_signature,
    verify_revocation_push_v2_signature, RevocationListV2, RevocationPushV2, RevokedCertV2,
    MAX_SAFE,
};
use crate::types::HybridPublicKey;

pub(crate) const LIST: u16 = 0x0003;
pub(crate) const PUSH: u16 = 0x0005;

/// Go `keyIDV2`, whose length errors are unclassified (the caller's
/// `v2Classify` fixes their class). The public `key_id_v2` reports
/// `malformed` explicitly, so internal ports that mirror Go use this.
pub(crate) fn key_id_plain(key: &HybridPublicKey) -> V2Result<String> {
    key_id_v2(key).map_err(|e| V2Error::plain(e.message))
}

/// Finite freshness bounds. A zero maximum means "not configured": status
/// can then never be current.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevocationStatusPolicyV2 {
    pub max_list_lifetime_seconds: i64,
    pub max_status_age_seconds: i64,
    pub clock_skew_seconds: i64,
}

/// Authenticated status evidence observation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevocationObservationV2 {
    pub object_type: u16,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub sequence: i64,
    pub evidence_digest: Vec<u8>,
    pub body_digest: Vec<u8>,
    pub revoked_set_digest: Vec<u8>,
    pub revoked_cert_ids: Vec<String>,
    pub future_dated: bool,
    pub fork: bool,
    pub gap: bool,
    pub accepted: bool,
}

/// A fail-closed answer for one CertificateRef with its evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RevocationStatusResultV2 {
    /// "not_revoked", "revoked", or "indeterminate".
    pub status: String,
    /// "" or, for indeterminate, "unavailable" / "stale".
    pub reason: String,
    pub evidence: Vec<StatusEvidenceEntryV2>,
    pub fresh_until: i64,
}

impl RevocationStatusResultV2 {
    pub fn unavailable() -> Self {
        RevocationStatusResultV2 {
            status: "indeterminate".into(),
            reason: "unavailable".into(),
            evidence: Vec::new(),
            fresh_until: 0,
        }
    }
}

/// One issuer's rollback-protected reducer state. Callers serialize applies
/// and persist the returned value atomically.
#[derive(Debug, Clone, Default)]
pub struct RevocationStatusStateV2 {
    pub issuer_id: String,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub retired_status_key_ids: Vec<String>,
    pub has_floor: bool,
    pub floor: i64,
    pub accepted_snapshot: Option<RevocationListV2>,
    pub accepted_cert_ids: Vec<String>,
    pub has_preceding_checkpoint: bool,
    pub preceding_floor: i64,
    pub preceding_accepted_cert_ids: Vec<String>,
    pub deny_union_cert_ids: Vec<String>,
    pub observations: Vec<RevocationObservationV2>,
    pub max_observed_sequence: i64,
    pub fork_sequence: i64,
    pub reconciliation_required: bool,
    pub future_dated_object_observed: bool,
}

pub(crate) fn sorted_unique(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn contains_all(have: &[String], want: &[String]) -> bool {
    want.iter().all(|w| have.contains(w))
}

pub(crate) fn equal_sets(a: &[String], b: &[String]) -> bool {
    sorted_unique(a).len() == sorted_unique(b).len() && contains_all(a, b)
}

fn concat(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().chain(b.iter()).cloned().collect()
}

pub(crate) fn revoked_ids(refs: &[RevokedCertV2]) -> Vec<String> {
    refs.iter().map(|r| r.cert_id.clone()).collect()
}

/// RevokedSetDigest (SPEC-v2 §4): SHA-384("ratify-protocol-revoked-set-v2" ||
/// 0x00 || RatifyCanonicalJSON(sorted, deduplicated cert_ids)).
fn revoked_set_digest(refs: &[RevokedCertV2]) -> V2Result<Vec<u8>> {
    let encoded = canonical(&CJ::strs(&sorted_unique(&revoked_ids(refs))))
        .map_err(|e| e.context("encode revoked certificate set"))?;
    Ok(sha384(&[b"ratify-protocol-revoked-set-v2", &[0], &encoded]))
}

fn beyond_skew(timestamp: i64, now: i64, skew: i64) -> bool {
    timestamp > now && timestamp - now > skew
}

fn list_fresh(l: &RevocationListV2, p: &RevocationStatusPolicyV2, now: i64) -> bool {
    if p.max_list_lifetime_seconds == 0
        || p.max_status_age_seconds == 0
        || l.next_update - l.updated_at > p.max_list_lifetime_seconds
        || beyond_skew(l.updated_at, now, p.clock_skew_seconds)
        || now >= l.next_update
    {
        // Exclusive deadline: a list is fresh only while now < next_update.
        return false;
    }
    // Exclusive age deadline: fresh only while now < updated_at + max_status_age.
    now < l.updated_at || now - l.updated_at < p.max_status_age_seconds
}

fn validate_policy(p: &RevocationStatusPolicyV2) -> V2Result<()> {
    // Zero lifetime or age means "not configured" (status is then never
    // current); configured values are bounded by SPEC-v2 §2.5.
    if p.max_list_lifetime_seconds < 0
        || p.max_status_age_seconds < 0
        || p.clock_skew_seconds < 0
        || p.max_list_lifetime_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
        || p.max_status_age_seconds > V2_MAX_STATUS_LIFETIME_SECONDS
        || p.clock_skew_seconds > V2_MAX_FUTURE_SKEW_SECONDS
    {
        return plain("revocation status policy contains invalid time bounds");
    }
    Ok(())
}

pub(crate) fn validate_binding(
    s: &RevocationStatusStateV2,
    issuer_id: &str,
    epoch: u64,
) -> V2Result<()> {
    if !s.issuer_id.is_empty() && s.issuer_id != issuer_id {
        return plain("revocation status state belongs to a different issuer");
    }
    if !s.issuer_id.is_empty() && s.status_key_epoch != epoch {
        return plain("revocation status state belongs to a different status-key epoch");
    }
    if s.floor < 0 || s.max_observed_sequence < 0 || s.fork_sequence < 0 {
        return plain("revocation status state has negative sequence state");
    }
    if s.preceding_floor < 0
        || s.preceding_floor > MAX_SAFE
        || (s.preceding_floor == 0 && !s.preceding_accepted_cert_ids.is_empty())
        || sorted_unique(&s.preceding_accepted_cert_ids).len()
            != s.preceding_accepted_cert_ids.len()
    {
        return plain("revocation status state has invalid preceding checkpoint");
    }
    if s.has_floor
        && (s.floor == 0
            || s.floor > MAX_SAFE
            || s.accepted_snapshot
                .as_ref()
                .is_none_or(|l| l.sequence <= 0 || l.sequence > s.floor))
    {
        return plain("revocation status state has inconsistent accepted floor");
    }
    if !s.has_floor
        && (s.floor != 0 || s.accepted_snapshot.is_some() || !s.accepted_cert_ids.is_empty())
    {
        return plain("revocation status state has accepted data without a floor");
    }
    if s.max_observed_sequence > MAX_SAFE
        || s.fork_sequence > MAX_SAFE
        || epoch == 0
        || epoch > MAX_SAFE as u64
    {
        return plain("revocation status state has invalid sequence or epoch");
    }
    if !s.issuer_id.is_empty() && !valid_v2_id(&s.status_key_id) {
        return plain("revocation status state has an invalid status-key ID");
    }
    if sorted_unique(&s.retired_status_key_ids).len() != s.retired_status_key_ids.len()
        || s.retired_status_key_ids.contains(&s.status_key_id)
    {
        return plain("revocation status state has invalid retired status-key history");
    }
    if s.retired_status_key_ids.iter().any(|k| !valid_v2_id(k)) {
        return plain("revocation status state has an invalid retired status-key ID");
    }
    Ok(())
}

pub(crate) fn has_accepted_observation(
    obs: &[RevocationObservationV2],
    epoch: u64,
    ty: u16,
    seq: i64,
    digest: &[u8],
) -> bool {
    obs.iter().any(|o| {
        o.status_key_epoch == epoch
            && o.object_type == ty
            && o.sequence == seq
            && o.evidence_digest == digest
            && o.accepted
            && !o.fork
            && !o.future_dated
    })
}

pub(crate) fn validate_accepted_state(s: &RevocationStatusStateV2) -> V2Result<()> {
    if sorted_unique(&s.deny_union_cert_ids).len() != s.deny_union_cert_ids.len()
        || sorted_unique(&s.accepted_cert_ids).len() != s.accepted_cert_ids.len()
    {
        return plain("revocation status sets are not canonical");
    }
    let mut observed = Vec::new();
    let mut fork_recorded = false;
    for o in &s.observations {
        if o.sequence <= 0
            || o.sequence > MAX_SAFE
            || !valid_v2_id(&o.status_key_id)
            || (o.object_type != LIST && o.object_type != PUSH)
            || o.evidence_digest.len() != 48
            || o.body_digest.len() != 48
            || o.revoked_set_digest.len() != 48
            || sorted_unique(&o.revoked_cert_ids).len() != o.revoked_cert_ids.len()
        {
            return plain("security journal contains a malformed status observation");
        }
        if o.revoked_cert_ids.iter().any(String::is_empty) {
            return plain("status observation contains an invalid certificate ID");
        }
        fork_recorded = fork_recorded || (o.status_key_epoch == s.status_key_epoch && o.fork);
        observed.extend(o.revoked_cert_ids.iter().cloned());
        if o.status_key_epoch == s.status_key_epoch && o.sequence > s.max_observed_sequence {
            return plain("observed sequence exceeds its high-water mark");
        }
        if !contains_all(&s.deny_union_cert_ids, &o.revoked_cert_ids) {
            return plain("deny union omits a revocation from authenticated evidence");
        }
    }
    if !contains_all(&observed, &s.deny_union_cert_ids) {
        return plain("deny union contains a revocation without a retained authenticated witness");
    }
    if s.fork_sequence > 0 && (!s.reconciliation_required || !fork_recorded) {
        return plain("unresolved fork state lacks its retained fork marker");
    }
    if s.has_floor && s.floor > s.max_observed_sequence {
        return plain("accepted floor exceeds the observed sequence high-water mark");
    }
    if !s.has_floor {
        return Ok(());
    }
    let Some(snap) = s.accepted_snapshot.as_ref() else {
        // Go dereferences the snapshot here; every caller validates the
        // binding (has_floor implies a snapshot) first.
        return plain("accepted snapshot does not match issuer or floor");
    };
    if snap.issuer_id != s.issuer_id || snap.sequence > s.floor {
        return plain("accepted snapshot does not match issuer or floor");
    }
    let digest = status_evidence_digest_list_v2(snap)?;
    if !has_accepted_observation(
        &s.observations,
        s.status_key_epoch,
        LIST,
        snap.sequence,
        &digest,
    ) {
        return plain("accepted snapshot has no matching authenticated observation");
    }
    let mut accepted = revoked_ids(&snap.revoked);
    let mut pushes: Vec<&RevocationObservationV2> = s
        .observations
        .iter()
        .filter(|o| {
            o.status_key_epoch == s.status_key_epoch
                && o.object_type == PUSH
                && o.accepted
                && o.sequence > snap.sequence
                && o.sequence <= s.floor
        })
        .collect();
    for p in &pushes {
        accepted.extend(p.revoked_cert_ids.iter().cloned());
    }
    pushes.sort_by_key(|p| p.sequence);
    let mut expected = snap.sequence;
    for p in pushes {
        if expected >= MAX_SAFE || p.sequence != expected + 1 {
            return plain(
                "accepted push observations are not contiguous after the accepted snapshot",
            );
        }
        expected = p.sequence;
    }
    if expected != s.floor {
        return plain("accepted push history does not reach the recorded floor");
    }
    if !equal_sets(&accepted, &s.accepted_cert_ids) {
        return plain("accepted certificate set does not follow the accepted snapshot and pushes");
    }
    Ok(())
}

pub(crate) fn semantic_key(o: &RevocationObservationV2) -> String {
    let digest = if o.object_type == LIST {
        &o.revoked_set_digest
    } else {
        &o.body_digest
    };
    format!(
        "{}:{}:{}:{}:future={}:fork={}",
        o.status_key_epoch,
        o.object_type,
        o.sequence,
        hex::encode(digest),
        o.future_dated,
        o.fork
    )
}

pub(crate) fn must_retain(s: &RevocationStatusStateV2, o: &RevocationObservationV2) -> bool {
    if o.status_key_epoch != s.status_key_epoch {
        return false;
    }
    if let Some(snap) = &s.accepted_snapshot {
        if o.object_type == PUSH
            && o.accepted
            && o.sequence > snap.sequence
            && o.sequence <= s.floor
        {
            return true;
        }
    }
    s.reconciliation_required && (o.sequence > s.floor || o.fork || o.gap || o.future_dated)
}

/// Go `canonicalizeRevocationStatusStateV2`: every string set in snapshot
/// order. Observation order (compaction order) is not changed.
pub(crate) fn canonicalize_state(mut s: RevocationStatusStateV2) -> RevocationStatusStateV2 {
    s.retired_status_key_ids = sorted_unique(&s.retired_status_key_ids);
    s.accepted_cert_ids = sorted_unique(&s.accepted_cert_ids);
    s.preceding_accepted_cert_ids = sorted_unique(&s.preceding_accepted_cert_ids);
    s.deny_union_cert_ids = sorted_unique(&s.deny_union_cert_ids);
    for o in &mut s.observations {
        o.revoked_cert_ids = sorted_unique(&o.revoked_cert_ids);
    }
    s
}

/// Go `pruneSecurityJournalObservationsV2` for one issuer state (also Go
/// `compactRevocationStatusObservationsV2`), followed by canonicalization.
pub(crate) fn compact(mut s: RevocationStatusStateV2) -> RevocationStatusStateV2 {
    let base_digest = s
        .accepted_snapshot
        .as_ref()
        .and_then(|l| status_evidence_digest_list_v2(l).ok())
        .unwrap_or_default();
    let mut obs = s.observations.clone();
    obs.sort_by(|a, b| {
        (
            a.status_key_epoch,
            a.sequence,
            a.object_type,
            &a.revoked_set_digest,
            &a.body_digest,
        )
            .cmp(&(
                b.status_key_epoch,
                b.sequence,
                b.object_type,
                &b.revoked_set_digest,
                &b.body_digest,
            ))
    });
    let mut retained: Vec<RevocationObservationV2> = Vec::new();
    let mut witnessed = BTreeSet::new();
    let mut semantic: BTreeMap<String, usize> = BTreeMap::new();
    for mut o in obs {
        let accepted_base = !base_digest.is_empty()
            && o.status_key_epoch == s.status_key_epoch
            && o.object_type == LIST
            && Some(o.sequence) == s.accepted_snapshot.as_ref().map(|l| l.sequence)
            && o.evidence_digest == base_digest;
        let full = accepted_base || must_retain(&s, &o);
        let mut new_witnesses = Vec::new();
        for id in &o.revoked_cert_ids {
            if witnessed.insert(id.clone()) {
                new_witnesses.push(id.clone());
            }
        }
        if !full {
            o.revoked_cert_ids = new_witnesses;
        }
        let key = semantic_key(&o);
        if let Some(&idx) = semantic.get(&key) {
            let prior = &mut retained[idx];
            prior.accepted = prior.accepted || o.accepted;
            prior.fork = prior.fork || o.fork;
            prior.gap = prior.gap || o.gap;
            prior.future_dated = (prior.future_dated || o.future_dated) && !prior.accepted;
            prior.revoked_cert_ids =
                sorted_unique(&concat(&prior.revoked_cert_ids, &o.revoked_cert_ids));
            if accepted_base {
                prior.evidence_digest = o.evidence_digest.clone();
                prior.accepted = true;
                if !s.reconciliation_required {
                    prior.gap = false;
                }
                prior.future_dated = false;
            }
            continue;
        }
        semantic.insert(key, retained.len());
        retained.push(o);
    }
    if !s.reconciliation_required {
        if let Some(snap) = &s.accepted_snapshot {
            if let Some(o) = retained.iter_mut().find(|o| {
                o.status_key_epoch == s.status_key_epoch
                    && o.object_type == LIST
                    && o.sequence == snap.sequence
                    && o.accepted
                    && !o.future_dated
                    && o.evidence_digest == base_digest
            }) {
                o.gap = false;
            }
        }
    }
    s.observations = retained;
    canonicalize_state(s)
}

fn initialize(s: &mut RevocationStatusStateV2, issuer_id: &str, epoch: u64) {
    if s.issuer_id.is_empty() {
        s.issuer_id = issuer_id.to_string();
        s.status_key_epoch = epoch;
    }
    s.accepted_cert_ids = sorted_unique(&s.accepted_cert_ids);
    s.deny_union_cert_ids = sorted_unique(&s.deny_union_cert_ids);
}

fn add_revocations(s: &mut RevocationStatusStateV2, values: &[String]) {
    s.deny_union_cert_ids = sorted_unique(&concat(&s.deny_union_cert_ids, values));
}

fn mark_fork(s: &mut RevocationStatusStateV2, o: &mut RevocationObservationV2, sequence: i64) {
    o.fork = true;
    s.reconciliation_required = true;
    s.fork_sequence = [s.fork_sequence, s.floor, sequence, 0]
        .into_iter()
        .max()
        .unwrap_or(0);
}

fn find_observation(
    obs: &[RevocationObservationV2],
    epoch: u64,
    ty: u16,
    seq: i64,
    digest: &[u8],
) -> Option<usize> {
    obs.iter().rposition(|o| {
        o.status_key_epoch == epoch
            && o.object_type == ty
            && o.sequence == seq
            && o.evidence_digest == digest
    })
}

fn find_set_observation(
    obs: &[RevocationObservationV2],
    inc: &RevocationObservationV2,
) -> Option<RevocationObservationV2> {
    obs.iter()
        .rev()
        .find(|o| {
            o.status_key_epoch == inc.status_key_epoch
                && o.object_type == inc.object_type
                && o.sequence == inc.sequence
                && o.revoked_set_digest == inc.revoked_set_digest
        })
        .cloned()
}

fn has_forked_sequence(obs: &[RevocationObservationV2], epoch: u64, ty: u16, seq: i64) -> bool {
    obs.iter().any(|o| {
        o.status_key_epoch == epoch
            && (ty == 0 || o.object_type == ty)
            && o.sequence == seq
            && o.fork
    })
}

fn sequence_conflict(obs: &[RevocationObservationV2], inc: &RevocationObservationV2) -> bool {
    obs.iter().any(|o| {
        o.status_key_epoch == inc.status_key_epoch
            && o.sequence == inc.sequence
            && o.object_type == inc.object_type
            && ((inc.object_type == LIST && o.revoked_set_digest != inc.revoked_set_digest)
                || (inc.object_type == PUSH && o.body_digest != inc.body_digest))
    })
}

fn required_for_snapshot(obs: &[RevocationObservationV2], epoch: u64, seq: i64) -> Vec<String> {
    let mut v = Vec::new();
    for o in obs
        .iter()
        .filter(|o| o.status_key_epoch == epoch && o.sequence <= seq)
    {
        v.extend(o.revoked_cert_ids.iter().cloned());
    }
    sorted_unique(&v)
}

fn snapshot_conflicts_with_push(
    s: &RevocationStatusStateV2,
    epoch: u64,
    seq: i64,
    ids: &[String],
) -> bool {
    s.observations
        .iter()
        .filter(|o| o.status_key_epoch == epoch && o.object_type == PUSH && o.sequence == seq)
        .any(|o| {
            if s.has_floor && s.floor == seq - 1 {
                !equal_sets(ids, &concat(&s.accepted_cert_ids, &o.revoked_cert_ids))
            } else {
                !contains_all(ids, &o.revoked_cert_ids)
            }
        })
}

fn snapshot_omission_for_push(
    s: &RevocationStatusStateV2,
    epoch: u64,
    push: &RevocationObservationV2,
) -> Option<i64> {
    let mut conflicting = 0i64;
    let mut check = |seq: i64, revoked: &[String]| {
        if seq >= push.sequence
            && !contains_all(revoked, &push.revoked_cert_ids)
            && seq > conflicting
        {
            conflicting = seq;
        }
    };
    if let Some(snap) = &s.accepted_snapshot {
        if s.status_key_epoch == epoch {
            check(snap.sequence, &revoked_ids(&snap.revoked));
        }
    }
    if s.reconciliation_required {
        for o in &s.observations {
            if o.status_key_epoch == epoch
                && o.object_type == LIST
                && o.sequence > s.floor
                && o.sequence >= push.sequence
                && (o.fork || o.gap || o.future_dated)
            {
                check(o.sequence, &o.revoked_cert_ids);
            }
        }
    }
    (conflicting != 0).then_some(conflicting)
}

fn heartbeat_preferred(
    incoming: &RevocationListV2,
    incoming_digest: &[u8],
    accepted: &RevocationListV2,
) -> bool {
    if incoming.updated_at != accepted.updated_at {
        return incoming.updated_at > accepted.updated_at;
    }
    status_evidence_digest_list_v2(accepted).is_ok_and(|d| incoming_digest < d.as_slice())
}

pub(crate) fn clone_list(l: &RevocationListV2) -> V2Result<RevocationListV2> {
    decode_revocation_list_v2(&encode_revocation_list_v2(l)?)
}

/// Go `cloneRevocationStatusStateV2`: the accepted snapshot is copied through
/// its wire form, so a snapshot that does not encode is an error.
fn clone_state(s: &RevocationStatusStateV2) -> V2Result<RevocationStatusStateV2> {
    let mut copy = s.clone();
    if let Some(list) = &s.accepted_snapshot {
        copy.accepted_snapshot = Some(clone_list(list)?);
    }
    Ok(copy)
}

/// Verify a list against the caller-authenticated status-key binding and
/// apply it. Errors (class `status_object_rejected` unless already
/// classified) leave the state untouched.
pub fn apply_revocation_list_v2(
    state: &RevocationStatusStateV2,
    list: &RevocationListV2,
    bound_issuer_id: &str,
    status_key_epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusStateV2> {
    apply_list_inner(
        state,
        list,
        bound_issuer_id,
        status_key_epoch,
        status_key,
        policy,
        now,
    )
    .map(|r| {
        if r.issuer_id.is_empty() {
            r
        } else {
            compact(r)
        }
    })
    .classify(V2ErrorClass::StatusObjectRejected)
}

fn apply_list_inner(
    state: &RevocationStatusStateV2,
    list: &RevocationListV2,
    bound_issuer_id: &str,
    epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusStateV2> {
    validate_policy(policy)?;
    if !valid_v2_timestamp(now) || epoch == 0 || epoch > MAX_SAFE as u64 {
        return plain("revocation list application has invalid time or status-key epoch");
    }
    verify_revocation_list_v2_signature(list, bound_issuer_id, status_key)?;
    validate_binding(state, bound_issuer_id, epoch)?;
    let digest = status_evidence_digest_list_v2(list)?;
    let body_digest = sha384(&[&revocation_list_v2_signable_bytes(list)?]);
    let set_digest = revoked_set_digest(&list.revoked)?;
    let mut next = clone_state(state)?;
    initialize(&mut next, bound_issuer_id, epoch);
    let key_id = key_id_plain(status_key)?;
    if !next.status_key_id.is_empty() && next.status_key_id != key_id {
        return plain("revocation list status key does not match configured epoch binding");
    }
    next.status_key_id = key_id.clone();
    let dup_index = find_observation(&next.observations, epoch, LIST, list.sequence, &digest);
    let duplicate = dup_index.is_some();
    let future = beyond_skew(list.updated_at, now, policy.clock_skew_seconds);
    let mut obs = RevocationObservationV2 {
        object_type: LIST,
        status_key_epoch: epoch,
        status_key_id: key_id,
        sequence: list.sequence,
        evidence_digest: digest.clone(),
        body_digest,
        revoked_set_digest: set_digest,
        revoked_cert_ids: revoked_ids(&list.revoked),
        future_dated: future,
        ..Default::default()
    };
    let fresh = list_fresh(list, policy, now);
    if !duplicate {
        if let Some(prior) = find_set_observation(&next.observations, &obs) {
            if prior.fork {
                return Ok(next);
            }
            if (prior.future_dated || prior.gap) && !future && fresh {
                if (next.has_floor && list.sequence < next.floor)
                    || has_forked_sequence(&next.observations, epoch, 0, list.sequence)
                {
                    return Ok(next);
                }
            } else if !prior.accepted
                && !prior.fork
                && next.has_floor
                && list.sequence == next.floor
                && next
                    .accepted_snapshot
                    .as_ref()
                    .is_some_and(|a| a.sequence < next.floor)
                && !future
                && fresh
            {
                // A fresh same-set snapshot at a push-advanced floor becomes the new base.
            } else if prior.accepted
                && next.has_floor
                && list.sequence == next.floor
                && next
                    .accepted_snapshot
                    .as_ref()
                    .is_some_and(|a| heartbeat_preferred(list, &digest, a))
            {
                // A newer same-set current-floor heartbeat may refresh freshness.
            } else {
                return Ok(next);
            }
        }
    }
    if let Some(idx) = dup_index {
        let prior = &next.observations[idx];
        if prior.accepted || (!prior.future_dated && !prior.gap) || future || !fresh {
            return Ok(next);
        }
        if next.has_floor && list.sequence < next.floor {
            return Ok(next);
        }
        if has_forked_sequence(&next.observations, epoch, 0, list.sequence) {
            return Ok(next);
        }
    } else {
        add_revocations(&mut next, &obs.revoked_cert_ids);
        if list.sequence > next.max_observed_sequence {
            next.max_observed_sequence = list.sequence;
        }
    }
    if future {
        next.future_dated_object_observed = true;
        next.reconciliation_required = true;
    }
    if sequence_conflict(&next.observations, &obs)
        || (next.has_floor
            && list.sequence == next.floor
            && !equal_sets(&obs.revoked_cert_ids, &next.accepted_cert_ids))
        || (next.has_floor
            && list.sequence < next.floor
            && !contains_all(&next.accepted_cert_ids, &obs.revoked_cert_ids))
    {
        mark_fork(&mut next, &mut obs, list.sequence);
    }
    let applicable = required_for_snapshot(&next.observations, epoch, list.sequence);
    if !contains_all(&obs.revoked_cert_ids, &applicable) {
        mark_fork(&mut next, &mut obs, list.sequence);
    }
    if snapshot_conflicts_with_push(&next, epoch, list.sequence, &obs.revoked_cert_ids.clone()) {
        mark_fork(&mut next, &mut obs, list.sequence);
    }
    let push_obs = |next: &mut RevocationStatusStateV2, obs: RevocationObservationV2| {
        if !duplicate {
            next.observations.push(obs);
        }
    };
    if !fresh {
        if next.has_floor && list.sequence <= next.floor {
            push_obs(&mut next, obs);
            return Ok(next);
        }
        next.reconciliation_required = true;
        obs.gap = true;
        push_obs(&mut next, obs);
        return Ok(next);
    }
    if obs.fork {
        push_obs(&mut next, obs);
        return Ok(next);
    }
    if !next.has_floor
        && (!contains_all(&obs.revoked_cert_ids, &next.deny_union_cert_ids)
            || list.sequence < next.max_observed_sequence)
    {
        next.reconciliation_required = true;
        obs.gap = true;
        push_obs(&mut next, obs);
        return Ok(next);
    }
    if next.has_floor && list.sequence < next.floor {
        push_obs(&mut next, obs);
        return Ok(next);
    }
    if next.has_floor && list.sequence == next.floor {
        if !equal_sets(&obs.revoked_cert_ids, &next.accepted_cert_ids) {
            mark_fork(&mut next, &mut obs, list.sequence);
            push_obs(&mut next, obs);
            return Ok(next);
        }
        let replace = match &next.accepted_snapshot {
            None => true,
            Some(a) => a.sequence < list.sequence || heartbeat_preferred(list, &digest, a),
        };
        if replace {
            next.accepted_snapshot = Some(clone_list(list)?);
        }
        obs.accepted = true;
    } else {
        let copy = clone_list(list)?;
        if next.has_floor && list.sequence == next.floor + 1 {
            next.has_preceding_checkpoint = true;
            next.preceding_floor = next.floor;
            next.preceding_accepted_cert_ids = sorted_unique(&next.accepted_cert_ids);
        } else {
            next.has_preceding_checkpoint = false;
            next.preceding_floor = 0;
            next.preceding_accepted_cert_ids = Vec::new();
        }
        next.accepted_snapshot = Some(copy);
        next.accepted_cert_ids = sorted_unique(&obs.revoked_cert_ids);
        next.has_floor = true;
        next.floor = list.sequence;
        obs.accepted = true;
    }
    if next.reconciliation_required {
        let recoverable = next.fork_sequence == 0
            || (list.sequence > next.fork_sequence && list.sequence >= next.max_observed_sequence);
        let fully = contains_all(&obs.revoked_cert_ids, &next.deny_union_cert_ids);
        if recoverable && fully && list.sequence >= next.max_observed_sequence {
            next.reconciliation_required = false;
            next.future_dated_object_observed = false;
            next.fork_sequence = 0;
        }
    } else if list.sequence >= next.max_observed_sequence
        && contains_all(&obs.revoked_cert_ids, &next.deny_union_cert_ids)
    {
        next.reconciliation_required = false;
    }
    let prior_accepted = dup_index.map(|i| next.observations[i].accepted);
    if !duplicate || (obs.accepted && prior_accepted == Some(false)) {
        next.observations.push(obs);
    }
    Ok(next)
}

/// Verify and apply one signed push. Noncontiguous or future pushes join
/// the deny union but make current status unavailable until repaired.
pub fn apply_revocation_push_v2(
    state: &RevocationStatusStateV2,
    push: &RevocationPushV2,
    bound_issuer_id: &str,
    status_key_epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusStateV2> {
    apply_push_inner(
        state,
        push,
        bound_issuer_id,
        status_key_epoch,
        status_key,
        policy,
        now,
    )
    .map(|r| {
        if r.issuer_id.is_empty() {
            r
        } else {
            compact(r)
        }
    })
    .classify(V2ErrorClass::StatusObjectRejected)
}

fn apply_push_inner(
    state: &RevocationStatusStateV2,
    push: &RevocationPushV2,
    bound_issuer_id: &str,
    epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusStateV2> {
    validate_policy(policy)?;
    if !valid_v2_timestamp(now) || epoch == 0 || epoch > MAX_SAFE as u64 {
        return plain("revocation push application has invalid time or status-key epoch");
    }
    verify_revocation_push_v2_signature(push, bound_issuer_id, status_key)?;
    validate_binding(state, bound_issuer_id, epoch)?;
    let digest = status_evidence_digest_push_v2(push)?;
    let body_digest = sha384(&[&revocation_push_v2_signable_bytes(push)?]);
    let set_digest = revoked_set_digest(&push.revoked)?;
    let mut next = clone_state(state)?;
    initialize(&mut next, bound_issuer_id, epoch);
    let key_id = key_id_plain(status_key)?;
    if !next.status_key_id.is_empty() && next.status_key_id != key_id {
        return plain("revocation push status key does not match configured epoch binding");
    }
    next.status_key_id = key_id.clone();
    if find_observation(&next.observations, epoch, PUSH, push.sequence, &digest).is_some()
        || next.observations.iter().any(|o| {
            o.status_key_epoch == epoch
                && o.object_type == PUSH
                && o.sequence == push.sequence
                && o.body_digest == body_digest
        })
    {
        return Ok(next);
    }
    let future = beyond_skew(push.pushed_at, now, policy.clock_skew_seconds);
    let mut obs = RevocationObservationV2 {
        object_type: PUSH,
        status_key_epoch: epoch,
        status_key_id: key_id,
        sequence: push.sequence,
        evidence_digest: digest,
        body_digest,
        revoked_set_digest: set_digest,
        revoked_cert_ids: revoked_ids(&push.revoked),
        future_dated: future,
        ..Default::default()
    };
    add_revocations(&mut next, &obs.revoked_cert_ids);
    if push.sequence > next.max_observed_sequence {
        next.max_observed_sequence = push.sequence;
    }
    if future {
        next.future_dated_object_observed = true;
        next.reconciliation_required = true;
    }
    if sequence_conflict(&next.observations, &obs) {
        mark_fork(&mut next, &mut obs, push.sequence);
    }
    if let Some(conflicting) = snapshot_omission_for_push(&next, epoch, &obs) {
        mark_fork(&mut next, &mut obs, conflicting);
    }
    let expected = if next.has_floor { next.floor + 1 } else { 1 };
    if next.has_floor && push.sequence <= next.floor {
        if push.sequence == next.floor {
            let checkpoint_mismatch = next.has_preceding_checkpoint
                && next.preceding_floor == push.sequence - 1
                && !equal_sets(
                    &next.accepted_cert_ids,
                    &concat(&next.preceding_accepted_cert_ids, &obs.revoked_cert_ids),
                );
            if checkpoint_mismatch || !contains_all(&next.accepted_cert_ids, &obs.revoked_cert_ids)
            {
                mark_fork(&mut next, &mut obs, push.sequence);
            } else if !obs.fork && contains_all(&next.accepted_cert_ids, &obs.revoked_cert_ids) {
                // The accepted full set already proves these entries.
            } else {
                obs.gap = true;
                next.reconciliation_required = true;
            }
            next.observations.push(obs);
            return Ok(next);
        }
        if !contains_all(&next.accepted_cert_ids, &obs.revoked_cert_ids) {
            mark_fork(&mut next, &mut obs, push.sequence);
        }
        next.observations.push(obs);
        return Ok(next);
    }
    if !next.has_floor || push.sequence != expected || next.reconciliation_required || future {
        obs.gap = !obs.fork;
        next.reconciliation_required = true;
        next.observations.push(obs);
        return Ok(next);
    }
    next.accepted_cert_ids = sorted_unique(&concat(&next.accepted_cert_ids, &obs.revoked_cert_ids));
    next.has_preceding_checkpoint = false;
    next.preceding_floor = 0;
    next.preceding_accepted_cert_ids = Vec::new();
    next.has_floor = true;
    next.floor = push.sequence;
    obs.accepted = true;
    next.observations.push(obs);
    Ok(next)
}

/// Apply an already-authenticated status-key epoch transition, preserving
/// issuer-wide denials and making old accepted state unusable.
pub fn transition_revocation_status_epoch_v2(
    state: &RevocationStatusStateV2,
    issuer_id: &str,
    next_epoch: u64,
    next_status_key: &HybridPublicKey,
) -> V2Result<RevocationStatusStateV2> {
    (|| {
        if issuer_id.is_empty() || next_epoch == 0 || next_epoch > MAX_SAFE as u64 {
            return plain("status-key epoch transition has invalid issuer or epoch");
        }
        if state.issuer_id != issuer_id
            || state.status_key_epoch == 0
            || state.status_key_epoch >= MAX_SAFE as u64
            || next_epoch != state.status_key_epoch + 1
        {
            return plain(
                "status-key epoch transition must advance exactly one configured issuer epoch",
            );
        }
        validate_binding(state, issuer_id, state.status_key_epoch)
            .map_err(|e| e.context("cannot transition malformed status state"))?;
        validate_accepted_state(state)
            .map_err(|e| e.context("cannot transition invalid accepted status state"))?;
        let key_id = key_id_plain(next_status_key)?;
        if key_id == state.status_key_id || state.retired_status_key_ids.contains(&key_id) {
            return plain(
                "status-key epoch transition cannot reuse a current or retired status key",
            );
        }
        let mut next = clone_state(state)?;
        let mut retired = next.retired_status_key_ids.clone();
        retired.push(state.status_key_id.clone());
        next.retired_status_key_ids = sorted_unique(&retired);
        next.status_key_epoch = next_epoch;
        next.status_key_id = key_id;
        next.has_floor = false;
        next.floor = 0;
        next.accepted_snapshot = None;
        next.accepted_cert_ids = Vec::new();
        next.has_preceding_checkpoint = false;
        next.preceding_floor = 0;
        next.preceding_accepted_cert_ids = Vec::new();
        next.max_observed_sequence = 0;
        next.fork_sequence = 0;
        next.reconciliation_required = false;
        next.future_dated_object_observed = false;
        Ok(next)
    })()
    .classify(V2ErrorClass::ConfigurationInvalid)
}

fn evidence_entry(
    issuer_id: &str,
    status_key_id: &str,
    o: &RevocationObservationV2,
) -> StatusEvidenceEntryV2 {
    let key = if o.status_key_id.is_empty() {
        status_key_id
    } else {
        &o.status_key_id
    };
    StatusEvidenceEntryV2 {
        issuer_id: issuer_id.to_string(),
        status_key_id: key.to_string(),
        sequence: o.sequence,
        object_type: o.object_type,
        digest: format!("sha384:{}", hex::encode(&o.evidence_digest)),
    }
}

fn push_unique(evidence: &mut Vec<StatusEvidenceEntryV2>, e: StatusEvidenceEntryV2) {
    if !evidence.contains(&e) {
        evidence.push(e);
    }
}

pub(crate) fn sort_evidence(
    mut evidence: Vec<StatusEvidenceEntryV2>,
) -> Vec<StatusEvidenceEntryV2> {
    evidence.sort_by(compare_evidence);
    evidence
}

fn accepted_evidence(
    s: &RevocationStatusStateV2,
    issuer_id: &str,
    key_id: &str,
) -> Vec<StatusEvidenceEntryV2> {
    let mut evidence = Vec::new();
    let Some(snap) = &s.accepted_snapshot else {
        return evidence;
    };
    if let Ok(d) = status_evidence_digest_list_v2(snap) {
        evidence.push(StatusEvidenceEntryV2 {
            issuer_id: issuer_id.to_string(),
            status_key_id: key_id.to_string(),
            sequence: snap.sequence,
            object_type: LIST,
            digest: format!("sha384:{}", hex::encode(d)),
        });
    }
    for o in &s.observations {
        if o.status_key_epoch == s.status_key_epoch
            && o.object_type == PUSH
            && o.accepted
            && o.sequence > snap.sequence
            && o.sequence <= s.floor
        {
            push_unique(&mut evidence, evidence_entry(issuer_id, key_id, o));
        }
    }
    sort_evidence(evidence)
}

fn unavailable_evidence(
    s: &RevocationStatusStateV2,
    issuer_id: &str,
    key_id: &str,
) -> Vec<StatusEvidenceEntryV2> {
    let mut evidence = accepted_evidence(s, issuer_id, key_id);
    for o in &s.observations {
        if o.status_key_epoch != s.status_key_epoch {
            continue;
        }
        if o.sequence > s.floor
            || o.fork
            || o.gap
            || o.future_dated
            || (s.reconciliation_required && !o.accepted)
        {
            push_unique(&mut evidence, evidence_entry(issuer_id, key_id, o));
        }
    }
    sort_evidence(evidence)
}

/// Derive a fail-closed answer and deterministic evidence for one
/// CertificateRef from the issuer's reducer state.
///
/// Go `RevocationStatusForCertV2` returns these errors unclassified; this
/// port classifies them `configuration_invalid` (an invalid query, policy,
/// or state binding), keeping any class already fixed (for example the
/// accepted snapshot's signature verification class).
pub fn revocation_status_for_cert_v2(
    state: &RevocationStatusStateV2,
    issuer_id: &str,
    cert_id: &str,
    status_key_epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusResultV2> {
    revocation_status_for_cert_inner(
        state,
        issuer_id,
        cert_id,
        status_key_epoch,
        status_key,
        policy,
        now,
    )
    .classify(V2ErrorClass::ConfigurationInvalid)
}

/// Go `RevocationStatusForCertV2` with Go's (unclassified) error classes.
pub(crate) fn revocation_status_for_cert_inner(
    state: &RevocationStatusStateV2,
    issuer_id: &str,
    cert_id: &str,
    status_key_epoch: u64,
    status_key: &HybridPublicKey,
    policy: &RevocationStatusPolicyV2,
    now: i64,
) -> V2Result<RevocationStatusResultV2> {
    validate_policy(policy)?;
    validate_binding(state, issuer_id, status_key_epoch)?;
    validate_accepted_state(state)?;
    if cert_id.is_empty() || !valid_v2_timestamp(now) {
        return plain("status query has invalid certificate ID or time");
    }
    let key_id = key_id_plain(status_key)?;
    if state.issuer_id != issuer_id
        || state.status_key_epoch != status_key_epoch
        || state.status_key_id != key_id
    {
        return plain("status query does not match the configured issuer status-key binding");
    }
    if let Some(snap) = &state.accepted_snapshot {
        verify_revocation_list_v2_signature(snap, issuer_id, status_key)
            .map_err(|e| e.context("accepted status snapshot signature is invalid"))?;
    }
    let cert = [cert_id.to_string()];
    if contains_all(&state.deny_union_cert_ids, &cert) {
        let mut evidence = accepted_evidence(state, issuer_id, &key_id);
        for o in &state.observations {
            if o.revoked_cert_ids.contains(&cert[0]) {
                push_unique(&mut evidence, evidence_entry(issuer_id, &key_id, o));
            }
        }
        return Ok(RevocationStatusResultV2 {
            status: "revoked".into(),
            reason: String::new(),
            evidence: sort_evidence(evidence),
            fresh_until: 0,
        });
    }
    if !state.has_floor
        || state.accepted_snapshot.is_none()
        || policy.max_list_lifetime_seconds == 0
        || policy.max_status_age_seconds == 0
        || state.future_dated_object_observed
        || state.reconciliation_required
        || state.floor < state.max_observed_sequence
        || !contains_all(&state.accepted_cert_ids, &state.deny_union_cert_ids)
    {
        return Ok(RevocationStatusResultV2 {
            status: "indeterminate".into(),
            reason: "unavailable".into(),
            evidence: unavailable_evidence(state, issuer_id, &key_id),
            fresh_until: 0,
        });
    }
    let Some(snap) = state.accepted_snapshot.as_ref() else {
        return Ok(RevocationStatusResultV2::unavailable());
    };
    if !list_fresh(snap, policy, now) {
        return Ok(RevocationStatusResultV2 {
            status: "indeterminate".into(),
            reason: "stale".into(),
            evidence: accepted_evidence(state, issuer_id, &key_id),
            fresh_until: 0,
        });
    }
    Ok(RevocationStatusResultV2 {
        status: "not_revoked".into(),
        reason: String::new(),
        evidence: accepted_evidence(state, issuer_id, &key_id),
        fresh_until: snap
            .next_update
            .min(snap.updated_at + policy.max_status_age_seconds),
    })
}

// ---------------------------------------------------------------------------
// Aggregation over every CertificateRef

/// Every issuer-scoped certificate whose status must be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2CertificateStatusCheck {
    pub delegation_index: usize,
    pub issuer_id: String,
    pub subject_id: String,
    pub cert_id: String,
}

/// Caller-authenticated status-key role bindings.
#[derive(Debug, Clone, Default)]
pub struct V2StatusRoleBindings {
    /// status key ID -> issuer ID.
    pub status_key_issuers: BTreeMap<String, String>,
    /// issuer ID -> current status key ID.
    pub current_status_key_ids: BTreeMap<String, String>,
    /// Non-status key roles that must never authenticate status.
    pub reserved_key_ids: BTreeSet<String>,
}

/// Deterministic aggregate of one result per CertificateRef.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StatusAssessment {
    pub assessment: String,
    pub reason: String,
    pub evidence: Vec<StatusEvidenceEntryV2>,
    pub fresh_until: i64,
}

fn validate_roles(
    roles: &V2StatusRoleBindings,
    checks: &[V2CertificateStatusCheck],
    allow_unbound_issuers: bool,
) -> V2Result<()> {
    for (key, issuer) in &roles.status_key_issuers {
        if !valid_v2_id(key) || !valid_v2_id(issuer) {
            return plain("authenticated status-key binding is malformed");
        }
        if roles.reserved_key_ids.contains(key) {
            return plain("status key collides with a reserved non-status key role");
        }
    }
    for check in checks {
        let bound = roles.current_status_key_ids.get(&check.issuer_id);
        if bound.is_none() && allow_unbound_issuers {
            continue;
        }
        let key = bound.cloned().unwrap_or_default();
        if roles.status_key_issuers.get(&key) != Some(&check.issuer_id) {
            return plain("issuer lacks an authenticated current status-key binding");
        }
    }
    if roles.reserved_key_ids.iter().any(|k| !valid_v2_id(k)) {
        return plain("reserved non-status key ID is malformed");
    }
    Ok(())
}

fn valid_current_evidence(evidence: &[StatusEvidenceEntryV2], issuer_id: &str) -> bool {
    if evidence.is_empty() {
        return false;
    }
    let mut base: Option<&StatusEvidenceEntryV2> = None;
    let mut bases = 0;
    let mut pushes = Vec::new();
    for e in evidence {
        if e.issuer_id != issuer_id {
            return false;
        }
        match e.object_type {
            LIST => {
                bases += 1;
                base = Some(e);
            }
            PUSH => pushes.push(e),
            _ => return false,
        }
    }
    let (1, Some(base)) = (bases, base) else {
        return false;
    };
    pushes.sort_by_key(|p| p.sequence);
    pushes.iter().enumerate().all(|(i, p)| {
        p.status_key_id == base.status_key_id && p.sequence == base.sequence + i as i64 + 1
    })
}

fn add_history(
    h: &mut BTreeMap<String, Vec<StatusEvidenceEntryV2>>,
    issuer: &str,
    evidence: &[StatusEvidenceEntryV2],
) -> bool {
    let canonical = sort_evidence(evidence.to_vec());
    match h.get(issuer) {
        None => {
            h.insert(issuer.to_string(), canonical);
            true
        }
        Some(prior) => *prior == canonical,
    }
}

/// Go `aggregateCertificateStatusResultsV2` (internal; SPEC-v2 §6.5):
/// exactly one reducer result per check, in order. Revoked outranks
/// unavailable, which outranks stale, independent of chain order.
// Go uses it only in resolveClaimProofBundleV2AfterStatusResults, which only
// Go unit tests call; the live verifier aggregates inside runV2StatusStage.
// Kept for parity.
#[allow(dead_code)]
pub(crate) fn aggregate_certificate_status_results_v2(
    checks: &[V2CertificateStatusCheck],
    results: &[RevocationStatusResultV2],
    roles: &V2StatusRoleBindings,
) -> V2Result<V2StatusAssessment> {
    aggregate_certificate_status_v2(checks, results, roles, false)
}

/// Go `aggregateCertificateStatusV2`, the shared aggregator.
/// `allow_unbound_issuers` is used only by the live verifier, which derives
/// results from its own journal and reports an issuer without authenticated
/// status configuration as unavailable instead of aborting the evaluation.
pub(crate) fn aggregate_certificate_status_v2(
    checks: &[V2CertificateStatusCheck],
    results: &[RevocationStatusResultV2],
    roles: &V2StatusRoleBindings,
    allow_unbound_issuers: bool,
) -> V2Result<V2StatusAssessment> {
    if checks.is_empty() || checks.len() != results.len() {
        return plain(
            "v2 status aggregation requires one result for every non-empty certificate list",
        );
    }
    validate_roles(roles, checks, allow_unbound_issuers)?;
    let mut issuers = Vec::new();
    let mut seen_refs = BTreeSet::new();
    let mut issuer_set = BTreeSet::new();
    let mut subject_set = BTreeSet::new();
    for (i, c) in checks.iter().enumerate() {
        if c.delegation_index != i
            || !valid_v2_id(&c.issuer_id)
            || !valid_v2_id(&c.subject_id)
            || c.cert_id.is_empty()
        {
            return plain(format!(
                "v2 status check {i} has an invalid delegation index or CertificateRef"
            ));
        }
        if !seen_refs.insert((c.issuer_id.clone(), c.cert_id.clone())) {
            return plain("v2 status checks contain a duplicate CertificateRef");
        }
        subject_set.insert(c.subject_id.clone());
        if issuer_set.insert(c.issuer_id.clone()) {
            issuers.push(c.issuer_id.clone());
        }
    }
    let mut evidence_out: Vec<StatusEvidenceEntryV2> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut bindings: BTreeMap<String, StatusEvidenceEntryV2> = BTreeMap::new();
    let mut invalid_digests = BTreeSet::new();
    let (mut invalid, mut any_revoked, mut any_unavailable, mut any_stale) =
        (false, false, false, false);
    let mut fresh_until = 0i64;
    let mut revoked_candidates = Vec::new();
    let mut history = BTreeMap::new();
    for (i, c) in checks.iter().enumerate() {
        let r = &results[i];
        let mut valid = true;
        for e in &r.evidence {
            if e.issuer_id != c.issuer_id
                || !valid_v2_id(&e.status_key_id)
                || e.sequence <= 0
                || e.sequence > MAX_SAFE
                || !valid_prefixed_digest(&e.digest)
                || (e.object_type != LIST && e.object_type != PUSH)
            {
                valid = false;
                continue;
            }
            if issuer_set.contains(&e.status_key_id) || subject_set.contains(&e.status_key_id) {
                valid = false;
                continue;
            }
            if roles.reserved_key_ids.contains(&e.status_key_id)
                || roles.status_key_issuers.get(&e.status_key_id) != Some(&e.issuer_id)
                || (r.status != "revoked"
                    && roles.current_status_key_ids.get(&e.issuer_id) != Some(&e.status_key_id))
            {
                valid = false;
                continue;
            }
            if let Some(prior) = bindings.get(&e.digest) {
                if prior != e {
                    invalid_digests.insert(e.digest.clone());
                }
            }
            bindings.insert(e.digest.clone(), e.clone());
            if seen.insert(e.clone()) {
                evidence_out.push(e.clone());
            }
        }
        match r.status.as_str() {
            "not_revoked" => {
                valid = valid
                    && r.reason.is_empty()
                    && r.fresh_until > 0
                    && r.fresh_until <= MAX_SAFE
                    && valid_current_evidence(&r.evidence, &c.issuer_id);
                if valid {
                    if fresh_until == 0 || r.fresh_until < fresh_until {
                        fresh_until = r.fresh_until;
                    }
                    valid = add_history(&mut history, &c.issuer_id, &r.evidence);
                }
            }
            "revoked" => {
                valid = valid && r.reason.is_empty() && !r.evidence.is_empty();
                if valid {
                    revoked_candidates.push(i);
                }
            }
            "indeterminate" => match r.reason.as_str() {
                "unavailable" => any_unavailable = true,
                "stale" => {
                    valid = valid && valid_current_evidence(&r.evidence, &c.issuer_id);
                    if valid {
                        valid = add_history(&mut history, &c.issuer_id, &r.evidence);
                    }
                    any_stale = true;
                }
                _ => valid = false,
            },
            _ => valid = false,
        }
        invalid = invalid || !valid;
    }
    if !invalid_digests.is_empty() {
        evidence_out.retain(|e| !invalid_digests.contains(&e.digest));
        invalid = true;
    }
    for i in revoked_candidates {
        let r = &results[i];
        let ok = !r.evidence.is_empty()
            && !r
                .evidence
                .iter()
                .any(|e| invalid_digests.contains(&e.digest));
        any_revoked = any_revoked || ok;
    }
    let evidence = sort_evidence(evidence_out);
    let mut issuers_sorted = issuers.clone();
    issuers_sorted.sort();
    let (assessment, reason) = if any_revoked {
        ("revoked", "delegation_revoked")
    } else if invalid || any_unavailable {
        ("unavailable", "status_unavailable")
    } else if any_stale {
        ("stale", "status_stale")
    } else if !has_accepted_status_history_per_issuer(&evidence, &issuers_sorted) {
        ("unavailable", "status_unavailable")
    } else {
        ("current", "")
    };
    Ok(V2StatusAssessment {
        assessment: assessment.into(),
        reason: reason.into(),
        evidence,
        fresh_until: if assessment == "current" {
            fresh_until
        } else {
            0
        },
    })
}
