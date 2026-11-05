//! TestSupport access to the Rust dual-root reference ledger.

use std::sync::Arc;

use ratify_protocol::v2::reference::{ApprovalLedgerTestOnly, ApprovalSetTestOnly};
use ratify_protocol::v2::V2Context;

use crate::error::FfiResult;
use crate::guard::{call_on, call_with, Poison};
use crate::keys::FfiPublicKey;
use crate::reference_store::FfiReferenceStore;
use crate::release::FfiReleasedDecision;

#[derive(uniffi::Record)]
pub struct FfiApprovalSet {
    pub approval_set_id: String,
    pub verifier_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub agent_public_key: FfiPublicKey,
    pub required_scope: String,
    pub request_hash: Vec<u8>,
    pub root_a: FfiPublicKey,
    pub root_b: FfiPublicKey,
}

impl From<FfiApprovalSet> for ApprovalSetTestOnly {
    fn from(value: FfiApprovalSet) -> Self {
        Self {
            approval_set_id: value.approval_set_id,
            verifier_id: value.verifier_id,
            workspace_id: value.workspace_id,
            session_id: value.session_id,
            agent_public_key: value.agent_public_key.into(),
            required_scope: value.required_scope,
            request_hash: value.request_hash,
            roots: [value.root_a.into(), value.root_b.into()],
        }
    }
}

#[derive(Default, uniffi::Record)]
pub struct FfiApprovalReply {
    pub complete: Option<bool>,
    pub failure: Option<String>,
}

#[derive(uniffi::Object)]
pub struct FfiApprovalLedger {
    poison: Poison,
    inner: ApprovalLedgerTestOnly,
}

#[uniffi::export]
impl FfiApprovalLedger {
    #[uniffi::constructor]
    pub fn new() -> FfiResult<Arc<Self>> {
        crate::guard::call(|| Ok(Arc::new(Self {
            poison: Poison::default(),
            inner: ApprovalLedgerTestOnly::new(),
        })))
    }

    pub fn open(&self, set: FfiApprovalSet) -> FfiResult<FfiApprovalReply> {
        call_on(&self.poison, || Ok(match self.inner.open(set.into()) {
            Ok(()) => FfiApprovalReply::default(),
            Err(error) => FfiApprovalReply { failure: Some(error.as_str().into()), ..Default::default() },
        }))
    }

    pub fn record(&self, set_id: String, slot: u32, decision: Option<Arc<FfiReleasedDecision>>,
                  bundle_wire: Vec<u8>) -> FfiResult<FfiApprovalReply> {
        call_with(&[&self.poison, decision.as_ref().map_or(&self.poison, |value| &value.poison)],
            || Ok(match self.inner.record_approval(&set_id, slot as usize,
            decision.as_ref().map(|value| &value.inner), &bundle_wire) {
            Ok(complete) => FfiApprovalReply { complete: Some(complete), ..Default::default() },
            Err(error) => FfiApprovalReply { failure: Some(error.as_str().into()), ..Default::default() },
        }))
    }

    pub fn execute(&self, set_id: String, clock: Arc<FfiReferenceStore>) -> FfiResult<FfiApprovalReply> {
        call_with(&[&self.poison, &clock.poison], || Ok(match self.inner.execute(
            &V2Context::background(), &set_id, clock.inner.as_ref()) {
            Ok(()) => FfiApprovalReply::default(),
            Err(error) => FfiApprovalReply { failure: Some(error.as_str().into()), ..Default::default() },
        }))
    }
}
