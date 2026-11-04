//! Snapshot boundary for the security journal. The Rust core owns its
//! internal representation; mobile callers exchange canonical snapshot bytes
//! together with the independently anchored head.

use std::sync::Arc;

use ratify_protocol::v2::{
    self as core, SecurityJournalStoreErrorV2, SecurityJournalStoreV2, SecurityJournalV2,
    V2Context, V2Error, V2ErrorClass,
    empty_security_journal_v2, export_security_journal_snapshot_v2,
    import_security_journal_snapshot_v2, security_journal_snapshot_digest_v2,
    decode_security_journal_json_v2, migrate_security_journal_v2,
    validate_security_journal_transition_v2,
    SecurityJournalHeadV2,
};

use crate::error::FfiResult;
use crate::guard::{call, call_on, Poison};
use crate::context::FfiCancelToken;
use crate::keys::FfiPublicKey;
use crate::objects::{FfiRevocationList, FfiRevocationPush};
use crate::status::{FfiStatusPolicy, FfiStatusResult, evidence_out};

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiJournalHead {
    pub generation: u64,
    pub digest: String,
}

impl From<FfiJournalHead> for SecurityJournalHeadV2 {
    fn from(head: FfiJournalHead) -> Self {
        Self { generation: head.generation, digest: head.digest }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiJournalSnapshot {
    pub snapshot: Vec<u8>,
    pub head: FfiJournalHead,
}

fn snapshot_out(journal: &SecurityJournalV2) -> FfiResult<FfiJournalSnapshot> {
    Ok(FfiJournalSnapshot {
        snapshot: export_security_journal_snapshot_v2(journal)?,
        head: FfiJournalHead { generation: journal.generation, digest: journal.digest.clone() },
    })
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiJournalStoreError {
    #[error("security journal compare-and-swap conflict")]
    Conflict,
    #[error("journal store callback cancelled")]
    Cancelled,
    #[error("journal store failed: {detail}")]
    Failed { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiJournalStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Failed { detail: e.reason }
    }
}

#[derive(uniffi::Object)]
pub struct FfiJournalContext {
    poison: Poison,
    ctx: V2Context,
}

#[uniffi::export]
impl FfiJournalContext {
    pub fn is_cancelled(&self) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.ctx.is_done()))
    }
}

/// Implementations must anchor the head independently from the journal bytes
/// and atomically compare-and-swap both values.
#[uniffi::export(with_foreign)]
pub trait FfiJournalStore: Send + Sync {
    fn load(&self, context: Arc<FfiJournalContext>) -> Result<FfiJournalSnapshot, FfiJournalStoreError>;
    fn compare_and_swap(
        &self, expected: FfiJournalHead, next: FfiJournalSnapshot, context: Arc<FfiJournalContext>,
    ) -> Result<(), FfiJournalStoreError>;
}

pub(crate) struct ForeignJournalStore(pub(crate) Arc<dyn FfiJournalStore>);

impl ForeignJournalStore {
    fn context(ctx: &V2Context) -> Arc<FfiJournalContext> {
        Arc::new(FfiJournalContext { poison: Poison::default(), ctx: ctx.clone() })
    }

    fn error(error: FfiJournalStoreError) -> V2Error {
        match error {
            FfiJournalStoreError::Cancelled => V2Error::new(V2ErrorClass::EvaluationCancelled, "journal store callback cancelled"),
            FfiJournalStoreError::Conflict => V2Error::new(V2ErrorClass::StatusObjectRejected, core::SECURITY_JOURNAL_CONFLICT_MESSAGE_V2),
            FfiJournalStoreError::Failed { detail } => V2Error::new(V2ErrorClass::StatusObjectRejected, format!("journal store failed: {detail}")),
        }
    }
}

impl SecurityJournalStoreV2 for ForeignJournalStore {
    fn load(&self, ctx: &V2Context) -> Result<(SecurityJournalV2, SecurityJournalHeadV2), V2Error> {
        let result = self.0.load(Self::context(ctx)).map_err(|error| match error {
            FfiJournalStoreError::Conflict => V2Error::new(V2ErrorClass::StatusObjectRejected, "journal load cannot report a compare-and-swap conflict"),
            other => Self::error(other),
        })?;
        let head: SecurityJournalHeadV2 = result.head.into();
        let own = SecurityJournalHeadV2 {
            generation: head.generation,
            digest: security_journal_snapshot_digest_v2(&result.snapshot),
        };
        let journal = import_security_journal_snapshot_v2(&result.snapshot, &own)?;
        Ok((journal, head))
    }

    fn compare_and_swap(
        &self, ctx: &V2Context, expected: &SecurityJournalHeadV2, next: &SecurityJournalV2,
    ) -> Result<(), SecurityJournalStoreErrorV2> {
        let snapshot = FfiJournalSnapshot {
            snapshot: export_security_journal_snapshot_v2(next).map_err(SecurityJournalStoreErrorV2::Failed)?,
            head: FfiJournalHead { generation: next.generation, digest: next.digest.clone() },
        };
        let head = FfiJournalHead { generation: expected.generation, digest: expected.digest.clone() };
        self.0.compare_and_swap(head, snapshot, Self::context(ctx)).map_err(|e| match e {
            FfiJournalStoreError::Conflict => SecurityJournalStoreErrorV2::Conflict,
            other => SecurityJournalStoreErrorV2::Failed(Self::error(other)),
        })
    }
}

#[uniffi::export]
pub fn ffi_record_security_key_role(
    store: Arc<dyn FfiJournalStore>, token: Arc<FfiCancelToken>, role: String, key: FfiPublicKey,
) -> FfiResult<FfiJournalSnapshot> {
    call(|| snapshot_out(&core::record_security_key_role_v2(token.context(), &ForeignJournalStore(store), &role, &key.into())?))
}

#[uniffi::export]
pub fn ffi_configure_status_key_epoch(
    store: Arc<dyn FfiJournalStore>, token: Arc<FfiCancelToken>, issuer_id: String, epoch: u64, key: FfiPublicKey,
) -> FfiResult<FfiJournalSnapshot> {
    call(|| snapshot_out(&core::configure_status_key_epoch_v2(token.context(), &ForeignJournalStore(store), &issuer_id, epoch, &key.into())?))
}

#[uniffi::export]
pub fn ffi_apply_revocation_list_to_journal(
    store: Arc<dyn FfiJournalStore>, token: Arc<FfiCancelToken>, list: FfiRevocationList,
    issuer_id: String, epoch: u64, key: FfiPublicKey, policy: FfiStatusPolicy, now: i64,
) -> FfiResult<FfiJournalSnapshot> {
    call(|| snapshot_out(&core::apply_revocation_list_to_journal_v2(
        token.context(), &ForeignJournalStore(store), &list.into(), &issuer_id, epoch, &key.into(), &policy.into(), now,
    )?))
}

#[uniffi::export]
pub fn ffi_apply_revocation_push_to_journal(
    store: Arc<dyn FfiJournalStore>, token: Arc<FfiCancelToken>, push: FfiRevocationPush,
    issuer_id: String, epoch: u64, key: FfiPublicKey, policy: FfiStatusPolicy, now: i64,
) -> FfiResult<FfiJournalSnapshot> {
    call(|| snapshot_out(&core::apply_revocation_push_to_journal_v2(
        token.context(), &ForeignJournalStore(store), &push.into(), &issuer_id, epoch, &key.into(), &policy.into(), now,
    )?))
}

#[uniffi::export]
pub fn ffi_revocation_status_from_journal(
    store: Arc<dyn FfiJournalStore>, token: Arc<FfiCancelToken>, issuer_id: String, cert_id: String,
    epoch: u64, key: FfiPublicKey, policy: FfiStatusPolicy, now: i64,
) -> FfiResult<FfiStatusResult> {
    call(|| {
        let r = core::revocation_status_from_journal_v2(
            token.context(), &ForeignJournalStore(store), &issuer_id, &cert_id, epoch, &key.into(), &policy.into(), now,
        )?;
        Ok(FfiStatusResult { status: r.status.as_str().into(), reason: r.reason, evidence: r.evidence.iter().map(evidence_out).collect(), fresh_until: r.fresh_until })
    })
}

#[uniffi::export]
pub fn ffi_empty_security_journal_snapshot() -> FfiResult<FfiJournalSnapshot> {
    call(|| {
        let journal = empty_security_journal_v2();
        let snapshot = export_security_journal_snapshot_v2(&journal)?;
        Ok(FfiJournalSnapshot {
            head: FfiJournalHead { generation: journal.generation, digest: journal.digest },
            snapshot,
        })
    })
}

#[uniffi::export]
pub fn ffi_validate_security_journal_snapshot(snapshot: Vec<u8>, head: FfiJournalHead) -> FfiResult<()> {
    call(|| {
        import_security_journal_snapshot_v2(&snapshot, &head.into())?;
        Ok(())
    })
}

#[uniffi::export]
pub fn ffi_security_journal_snapshot_digest(snapshot: Vec<u8>) -> FfiResult<String> {
    call(|| Ok(security_journal_snapshot_digest_v2(&snapshot)))
}

#[uniffi::export]
pub fn ffi_migrate_security_journal_json(legacy_json: Vec<u8>) -> FfiResult<FfiJournalSnapshot> {
    call(|| {
        let legacy = decode_security_journal_json_v2(&legacy_json)?;
        snapshot_out(&migrate_security_journal_v2(&legacy)?)
    })
}

#[uniffi::export]
pub fn ffi_validate_security_journal_transition(
    current: FfiJournalSnapshot, next: FfiJournalSnapshot,
) -> FfiResult<()> {
    call(|| {
        let before = import_security_journal_snapshot_v2(&current.snapshot, &current.head.into())?;
        let after = import_security_journal_snapshot_v2(&next.snapshot, &next.head.into())?;
        Ok(validate_security_journal_transition_v2(&before, &after)?)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn genesis_is_pinned_and_rejects_a_rolled_back_head() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testvectors/v2/security-journal.json"
        ))
        .unwrap();
        let genesis = ffi_empty_security_journal_snapshot().unwrap();
        assert_eq!(genesis.snapshot, vector["genesis_snapshot"].as_str().unwrap().as_bytes());
        assert_eq!(genesis.head.digest, vector["genesis_digest"].as_str().unwrap());
        assert_eq!(ffi_security_journal_snapshot_digest(genesis.snapshot.clone()).unwrap(), genesis.head.digest);
        ffi_validate_security_journal_snapshot(genesis.snapshot.clone(), genesis.head.clone()).unwrap();
        for negative in vector["import_negatives"].as_array().unwrap() {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(negative["snapshot_b64"].as_str().unwrap()).unwrap();
            let head = &negative["head"];
            let error = ffi_validate_security_journal_snapshot(bytes, FfiJournalHead {
                generation: head["generation"].as_u64().unwrap(),
                digest: head["digest"].as_str().unwrap().into(),
            }).unwrap_err();
            assert!(matches!(error, crate::error::FfiError::Protocol { class, .. }
                if class == negative["expect_error_class"].as_str().unwrap()), "{}", negative["name"]);
        }
    }
}
