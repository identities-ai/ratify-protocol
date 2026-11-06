//! Composed transaction receipt verification through the core.

use std::collections::BTreeMap;
use std::sync::Arc;

use ratify_protocol::v2::{self as core, TransactionVerifyRequestV2, TransactionVerifySourcesV2};

use crate::context::FfiCancelToken;
use crate::error::FfiResult;
use crate::guard::call;
use crate::journal::{FfiJournalStore, ForeignJournalStore};
use crate::live_providers::{status_callback, trust_callback, FfiStatusEvidenceProvider, FfiTrustProvider};
use crate::live_verify::FfiStatusKeyConfig;
use crate::objects::FfiStatusEvidenceEntry;
use crate::status::{evidence_out, FfiStatusPolicy};

#[derive(uniffi::Record)]
pub struct FfiTransactionVerifyRequest {
    pub receipt: Vec<u8>,
    pub now: i64,
    pub future_skew_seconds: i64,
    pub status_keys: std::collections::HashMap<String, FfiStatusKeyConfig>,
    pub status_policy: FfiStatusPolicy,
}

#[derive(uniffi::Record)]
pub struct FfiTransactionPartyVerification {
    pub party_id: String,
    pub agent_id: String,
    pub required_scope: String,
    pub trust_assessment: String,
    pub delegation_assessment: String,
    pub delegation_expires_at: Option<i64>,
    pub status_assessment: String,
    pub scope_assessment: String,
    pub freshness: String,
    pub status_evidence: Vec<FfiStatusEvidenceEntry>,
}

impl From<core::TransactionPartyVerificationV2> for FfiTransactionPartyVerification {
    fn from(p: core::TransactionPartyVerificationV2) -> Self {
        Self { party_id: p.party_id, agent_id: p.agent_id, required_scope: p.required_scope,
            trust_assessment: p.trust_assessment, delegation_assessment: p.delegation_assessment,
            delegation_expires_at: p.delegation_expires_at, status_assessment: p.status_assessment,
            scope_assessment: p.scope_assessment, freshness: p.freshness,
            status_evidence: p.status_evidence.iter().map(evidence_out).collect() }
    }
}

#[derive(uniffi::Record)]
pub struct FfiTransactionVerification {
    pub transaction_id: String,
    pub actionable: bool,
    pub parties: Vec<FfiTransactionPartyVerification>,
}

impl From<core::TransactionReceiptVerificationV2> for FfiTransactionVerification {
    fn from(v: core::TransactionReceiptVerificationV2) -> Self {
        Self { transaction_id: v.transaction_id, actionable: v.actionable,
            parties: v.parties.into_iter().map(Into::into).collect() }
    }
}

#[uniffi::export]
pub fn ffi_verify_transaction_receipt(request: FfiTransactionVerifyRequest,
    trust: Option<Arc<dyn FfiTrustProvider>>,
    status_evidence: Option<Arc<dyn FfiStatusEvidenceProvider>>,
    status_journal: Option<Arc<dyn FfiJournalStore>>,
    token: Arc<FfiCancelToken>) -> FfiResult<FfiTransactionVerification> {
    call(|| {
        let req = TransactionVerifyRequestV2 { receipt: request.receipt, now: request.now,
            future_skew_seconds: request.future_skew_seconds };
        let sources = TransactionVerifySourcesV2 {
            trust: trust.map(trust_callback),
            status_evidence: status_evidence.map(status_callback),
            status_journal: status_journal.map(|s| Arc::new(ForeignJournalStore(s)) as Arc<dyn core::SecurityJournalStoreV2>),
            status_keys: request.status_keys.into_iter().map(|(issuer, config)| (issuer,
                core::V2StatusKeyConfig { epoch: config.epoch, key: config.key.into() })).collect::<BTreeMap<_, _>>(),
            status_policy: request.status_policy.into(),
        };
        Ok(core::verify_transaction_receipt_v2(token.context(), &req, &sources)?.into())
    })
}
