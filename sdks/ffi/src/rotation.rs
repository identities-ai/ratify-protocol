//! Key-rotation journals (SPEC-v2 §5.4): caller-persisted continuity state
//! for one authority, as plain values. Accepting a statement returns the next
//! journal even when the statement is refused (a fork freezes it).

use ratify_protocol::v2::{
    self as core, KeyRotationV2AcceptedEntry, KeyRotationV2Journal, KeyRotationV2State,
};

use crate::error::FfiResult;
use crate::guard::call;
use crate::keys::FfiPublicKey;
use crate::objects::FfiKeyRotationStatement;
use crate::verify::{FfiLogResult, FfiRotationState};

impl From<&KeyRotationV2State> for FfiRotationState {
    fn from(s: &KeyRotationV2State) -> Self {
        FfiRotationState {
            authority_id: s.authority_id.clone(),
            recovery_epoch: s.recovery_epoch,
            role: s.role.clone(),
            sequence: s.sequence,
            head_hash: s.head_hash.clone(),
            current_key: (&s.current_key).into(),
            used_key_ids: s.used_key_ids.clone(),
        }
    }
}

/// One accepted rotation, retained for replay and fork checks.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiRotationAcceptedEntry {
    pub sequence: i64,
    pub body_digest: Vec<u8>,
    pub old_key: FfiPublicKey,
}

/// Caller-persisted continuity state for one authority.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiRotationJournal {
    pub state: FfiRotationState,
    pub accepted: Vec<FfiRotationAcceptedEntry>,
    pub frozen: bool,
}

impl From<&KeyRotationV2Journal> for FfiRotationJournal {
    fn from(j: &KeyRotationV2Journal) -> Self {
        FfiRotationJournal {
            state: (&j.state).into(),
            accepted: j
                .accepted
                .iter()
                .map(|e| FfiRotationAcceptedEntry {
                    sequence: e.sequence,
                    body_digest: e.body_digest.clone(),
                    old_key: (&e.old_key).into(),
                })
                .collect(),
            frozen: j.frozen,
        }
    }
}

impl From<FfiRotationJournal> for KeyRotationV2Journal {
    fn from(j: FfiRotationJournal) -> Self {
        KeyRotationV2Journal {
            state: j.state.into(),
            accepted: j
                .accepted
                .into_iter()
                .map(|e| KeyRotationV2AcceptedEntry {
                    sequence: e.sequence,
                    body_digest: e.body_digest,
                    old_key: e.old_key.into(),
                })
                .collect(),
            frozen: j.frozen,
        }
    }
}

/// The next journal and what the statement did. Exactly one of `result`
/// and `error` is set; `error` is a protocol error.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiRotationAcceptance {
    pub journal: FfiRotationJournal,
    pub result: Option<FfiLogResult>,
    pub error: Option<FfiRotationRefusal>,
}

/// A refused rotation statement: its §2.7 class and diagnostic.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiRotationRefusal {
    pub class: String,
    pub detail: String,
}

#[uniffi::export]
pub fn ffi_new_key_rotation_journal(
    authority_id: String,
    recovery_epoch: i64,
    role: String,
    genesis_key: FfiPublicKey,
) -> FfiResult<FfiRotationJournal> {
    call(|| {
        Ok((&core::new_key_rotation_v2_journal(
            &authority_id,
            recovery_epoch,
            &role,
            &genesis_key.into(),
        )?)
            .into())
    })
}

#[uniffi::export]
pub fn ffi_accept_key_rotation_statement(
    statement: FfiKeyRotationStatement,
    journal: FfiRotationJournal,
    now: i64,
    future_skew: i64,
) -> FfiResult<FfiRotationAcceptance> {
    call(|| {
        let (next, result) = core::accept_key_rotation_statement_v2(
            &statement.into(),
            &journal.into(),
            now,
            future_skew,
        );
        let (result, error) = match result {
            Ok(r) => (Some(r.into()), None),
            Err(e) => (
                None,
                Some(FfiRotationRefusal {
                    class: e.class.as_str().into(),
                    detail: e.message,
                }),
            ),
        };
        Ok(FfiRotationAcceptance {
            journal: (&next).into(),
            result,
            error,
        })
    })
}

#[uniffi::export]
pub fn ffi_recover_key_rotation(
    journal: FfiRotationJournal,
    new_recovery_epoch: i64,
    new_genesis_key: FfiPublicKey,
) -> FfiResult<FfiRotationJournal> {
    call(|| {
        let j: KeyRotationV2Journal = journal.into();
        Ok(
            (&core::recover_key_rotation_v2(&j, new_recovery_epoch, &new_genesis_key.into())?)
                .into(),
        )
    })
}
