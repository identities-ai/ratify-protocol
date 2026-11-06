//! The revocation status reducer (SPEC-v2 §6.6): caller-persisted state as a
//! plain value, advanced by verified lists and pushes and queried per
//! certificate. Each call is one core call; the caller persists the result.

use ratify_protocol::v2::{
    self as core, RevocationObservationV2, RevocationStatusPolicyV2, RevocationStatusStateV2,
    StatusEvidenceEntryV2,
};

use crate::error::FfiResult;
use crate::guard::call;
use crate::keys::FfiPublicKey;
use crate::objects::{FfiRevocationList, FfiRevocationPush, FfiStatusEvidenceEntry};

/// The relying party's freshness policy for status evidence.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusPolicy {
    pub max_list_lifetime_seconds: i64,
    pub max_status_age_seconds: i64,
    pub clock_skew_seconds: i64,
}

impl From<FfiStatusPolicy> for RevocationStatusPolicyV2 {
    fn from(p: FfiStatusPolicy) -> Self {
        RevocationStatusPolicyV2 {
            max_list_lifetime_seconds: p.max_list_lifetime_seconds,
            max_status_age_seconds: p.max_status_age_seconds,
            clock_skew_seconds: p.clock_skew_seconds,
        }
    }
}

/// One status object the reducer observed.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusObservation {
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

/// Caller-persisted revocation status state for one issuer.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusState {
    pub issuer_id: String,
    pub status_key_epoch: u64,
    pub status_key_id: String,
    pub retired_status_key_ids: Vec<String>,
    pub has_floor: bool,
    pub floor: i64,
    pub accepted_snapshot: Option<FfiRevocationList>,
    pub accepted_cert_ids: Vec<String>,
    pub has_preceding_checkpoint: bool,
    pub preceding_floor: i64,
    pub preceding_accepted_cert_ids: Vec<String>,
    pub deny_union_cert_ids: Vec<String>,
    pub observations: Vec<FfiStatusObservation>,
    pub max_observed_sequence: i64,
    pub fork_sequence: i64,
    pub reconciliation_required: bool,
    pub future_dated_object_observed: bool,
}

impl From<&RevocationStatusStateV2> for FfiStatusState {
    fn from(s: &RevocationStatusStateV2) -> Self {
        FfiStatusState {
            issuer_id: s.issuer_id.clone(),
            status_key_epoch: s.status_key_epoch,
            status_key_id: s.status_key_id.clone(),
            retired_status_key_ids: s.retired_status_key_ids.clone(),
            has_floor: s.has_floor,
            floor: s.floor,
            accepted_snapshot: s.accepted_snapshot.as_ref().map(Into::into),
            accepted_cert_ids: s.accepted_cert_ids.clone(),
            has_preceding_checkpoint: s.has_preceding_checkpoint,
            preceding_floor: s.preceding_floor,
            preceding_accepted_cert_ids: s.preceding_accepted_cert_ids.clone(),
            deny_union_cert_ids: s.deny_union_cert_ids.clone(),
            observations: s
                .observations
                .iter()
                .map(|o| FfiStatusObservation {
                    object_type: o.object_type,
                    status_key_epoch: o.status_key_epoch,
                    status_key_id: o.status_key_id.clone(),
                    sequence: o.sequence,
                    evidence_digest: o.evidence_digest.clone(),
                    body_digest: o.body_digest.clone(),
                    revoked_set_digest: o.revoked_set_digest.clone(),
                    revoked_cert_ids: o.revoked_cert_ids.clone(),
                    future_dated: o.future_dated,
                    fork: o.fork,
                    gap: o.gap,
                    accepted: o.accepted,
                })
                .collect(),
            max_observed_sequence: s.max_observed_sequence,
            fork_sequence: s.fork_sequence,
            reconciliation_required: s.reconciliation_required,
            future_dated_object_observed: s.future_dated_object_observed,
        }
    }
}

impl From<FfiStatusState> for RevocationStatusStateV2 {
    fn from(s: FfiStatusState) -> Self {
        RevocationStatusStateV2 {
            issuer_id: s.issuer_id,
            status_key_epoch: s.status_key_epoch,
            status_key_id: s.status_key_id,
            retired_status_key_ids: s.retired_status_key_ids,
            has_floor: s.has_floor,
            floor: s.floor,
            accepted_snapshot: s.accepted_snapshot.map(Into::into),
            accepted_cert_ids: s.accepted_cert_ids,
            has_preceding_checkpoint: s.has_preceding_checkpoint,
            preceding_floor: s.preceding_floor,
            preceding_accepted_cert_ids: s.preceding_accepted_cert_ids,
            deny_union_cert_ids: s.deny_union_cert_ids,
            observations: s
                .observations
                .into_iter()
                .map(|o| RevocationObservationV2 {
                    object_type: o.object_type,
                    status_key_epoch: o.status_key_epoch,
                    status_key_id: o.status_key_id,
                    sequence: o.sequence,
                    evidence_digest: o.evidence_digest,
                    body_digest: o.body_digest,
                    revoked_set_digest: o.revoked_set_digest,
                    revoked_cert_ids: o.revoked_cert_ids,
                    future_dated: o.future_dated,
                    fork: o.fork,
                    gap: o.gap,
                    accepted: o.accepted,
                })
                .collect(),
            max_observed_sequence: s.max_observed_sequence,
            fork_sequence: s.fork_sequence,
            reconciliation_required: s.reconciliation_required,
            future_dated_object_observed: s.future_dated_object_observed,
        }
    }
}

/// A certificate's revocation status from the reducer state.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiStatusResult {
    /// "not_revoked", "revoked", or "indeterminate".
    pub status: String,
    /// "" or, for indeterminate, "unavailable" / "stale".
    pub reason: String,
    pub evidence: Vec<FfiStatusEvidenceEntry>,
    pub fresh_until: i64,
}

pub(crate) fn evidence_out(e: &StatusEvidenceEntryV2) -> FfiStatusEvidenceEntry {
    FfiStatusEvidenceEntry {
        issuer_id: e.issuer_id.clone(),
        status_key_id: e.status_key_id.clone(),
        sequence: e.sequence,
        object_type: e.object_type,
        digest: e.digest.clone(),
    }
}

/// The empty initial state.
#[uniffi::export]
pub fn ffi_empty_status_state() -> FfiResult<FfiStatusState> {
    call(|| Ok((&RevocationStatusStateV2::default()).into()))
}

#[uniffi::export]
pub fn ffi_apply_revocation_list(
    state: FfiStatusState,
    list: FfiRevocationList,
    bound_issuer_id: String,
    status_key_epoch: u64,
    status_key: FfiPublicKey,
    policy: FfiStatusPolicy,
    now: i64,
) -> FfiResult<FfiStatusState> {
    call(|| {
        let next = core::apply_revocation_list_v2(
            &state.into(),
            &list.into(),
            &bound_issuer_id,
            status_key_epoch,
            &status_key.into(),
            &policy.into(),
            now,
        )?;
        Ok((&next).into())
    })
}

#[uniffi::export]
pub fn ffi_apply_revocation_push(
    state: FfiStatusState,
    push: FfiRevocationPush,
    bound_issuer_id: String,
    status_key_epoch: u64,
    status_key: FfiPublicKey,
    policy: FfiStatusPolicy,
    now: i64,
) -> FfiResult<FfiStatusState> {
    call(|| {
        let next = core::apply_revocation_push_v2(
            &state.into(),
            &push.into(),
            &bound_issuer_id,
            status_key_epoch,
            &status_key.into(),
            &policy.into(),
            now,
        )?;
        Ok((&next).into())
    })
}

#[uniffi::export]
pub fn ffi_transition_revocation_status_epoch(
    state: FfiStatusState,
    issuer_id: String,
    next_epoch: u64,
    next_status_key: FfiPublicKey,
) -> FfiResult<FfiStatusState> {
    call(|| {
        let next = core::transition_revocation_status_epoch_v2(
            &state.into(),
            &issuer_id,
            next_epoch,
            &next_status_key.into(),
        )?;
        Ok((&next).into())
    })
}

#[uniffi::export]
pub fn ffi_revocation_status_for_cert(
    state: FfiStatusState,
    issuer_id: String,
    cert_id: String,
    status_key_epoch: u64,
    status_key: FfiPublicKey,
    policy: FfiStatusPolicy,
    now: i64,
) -> FfiResult<FfiStatusResult> {
    call(|| {
        let r = core::revocation_status_for_cert_v2(
            &state.into(),
            &issuer_id,
            &cert_id,
            status_key_epoch,
            &status_key.into(),
            &policy.into(),
            now,
        )?;
        Ok(FfiStatusResult {
            status: r.status,
            reason: r.reason,
            evidence: r.evidence.iter().map(evidence_out).collect(),
            fresh_until: r.fresh_until,
        })
    })
}
