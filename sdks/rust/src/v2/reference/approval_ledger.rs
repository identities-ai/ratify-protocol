//! Dual-root composition profile (SPEC-v2 §7.14), TEST ONLY. Mirrors Go
//! `v2reference/approval_ledger.go`.
//!
//! [`ApprovalLedgerTestOnly`] is the application ledger of the profile. An
//! approval set names one action through its authenticated fields: the
//! verifier ID, the workspace and session identifiers, the complete agent
//! key, the required scope, the action's request hash, and two distinct
//! pinned root keys. The ledger derives the expected session context from
//! those fields with invocation_id = approval_set_id (SPEC-v2 §2.4); it never
//! accepts a caller-supplied context. Each root approves through its own
//! challenge and its own independently released Protocol decision. The
//! ledger marks the action executable only when both released allows match
//! the set and are still within their deadlines, lets it execute exactly
//! once, and refuses to count one released decision toward more than one
//! approval set. The composite result is application state, not a Protocol
//! receipt.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::types::HybridPublicKey;
use crate::v2::claim_store::V2AuthoritativeClock;
use crate::v2::context::V2Context;
use crate::v2::crypto::key_id_v2;
use crate::v2::operation_context::{build_session_context_v2, SessionContextV2Inputs};
use crate::v2::release::V2ReleasedDecision;
use crate::v2::wire::{bundle_hash_v2, decode_proof_bundle_v2, validate_required_scope_v2};

/// The ledger's refusals (Go `ErrApproval*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalErrorTestOnly {
    /// The approval is not a released allow.
    NotReleased,
    /// The approval does not bind this approval set's action.
    ActionMismatch,
    /// The approval chain does not end at the slot's pinned root.
    RootMismatch,
    /// The slot already holds a different approval.
    SlotFilled,
    /// The approval is already recorded in another approval set.
    Reused,
    /// The approval set is missing a released approval.
    Incomplete,
    /// An approval is past its release deadline.
    Expired,
    /// The approval set already executed.
    AlreadyExecuted,
    /// The approval set is invalid.
    SetInvalid,
    /// The approval set is unknown.
    SetUnknown,
    /// The approval set is already open.
    SetAlreadyExists,
    /// The slot is not 0 or 1.
    InvalidSlot,
}

impl ApprovalErrorTestOnly {
    /// The spelling the shared vectors use.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalErrorTestOnly::NotReleased => "not_released",
            ApprovalErrorTestOnly::ActionMismatch => "action_mismatch",
            ApprovalErrorTestOnly::RootMismatch => "root_mismatch",
            ApprovalErrorTestOnly::SlotFilled => "slot_filled",
            ApprovalErrorTestOnly::Reused => "approval_reused",
            ApprovalErrorTestOnly::Incomplete => "incomplete",
            ApprovalErrorTestOnly::Expired => "expired",
            ApprovalErrorTestOnly::AlreadyExecuted => "already_executed",
            ApprovalErrorTestOnly::SetInvalid => "approval_set_invalid",
            ApprovalErrorTestOnly::SetUnknown => "approval_set_unknown",
            ApprovalErrorTestOnly::SetAlreadyExists => "approval_set_already_exists",
            ApprovalErrorTestOnly::InvalidSlot => "invalid_slot",
        }
    }
}

impl fmt::Display for ApprovalErrorTestOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v2reference: approval ledger: {}", self.as_str())
    }
}

impl std::error::Error for ApprovalErrorTestOnly {}

/// The authenticated approval set an application opens before issuing
/// either challenge (SPEC-v2 §7.14 step 1). Every field comes from
/// authenticated application state, never from the presenter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalSetTestOnly {
    pub approval_set_id: String,
    pub verifier_id: String,
    pub workspace_id: String,
    pub session_id: String,
    pub agent_public_key: HybridPublicKey,
    pub required_scope: String,
    /// The action's 32-byte operation-context hash (§2.4).
    pub request_hash: Vec<u8>,
    /// The complete public keys of the two pinned roots, in slot order.
    pub roots: [HybridPublicKey; 2],
}

struct ApprovalRecord {
    claim_id: String,
    decision: Arc<V2ReleasedDecision>,
}

struct ApprovalState {
    set: ApprovalSetTestOnly,
    agent_id: String,
    root_ids: [String; 2],
    session_context: Vec<u8>,
    approvals: [Option<ApprovalRecord>; 2],
    executed: bool,
}

#[derive(Default)]
struct Ledger {
    sets: BTreeMap<String, ApprovalState>,
    /// Each recorded claim ID and the approval set it counts toward, so one
    /// released decision never counts toward two sets.
    recorded: BTreeMap<String, String>,
}

/// The dual-root application ledger. Safe for concurrent use; each
/// operation is one atomic step under a mutex.
#[derive(Default)]
pub struct ApprovalLedgerTestOnly {
    state: Mutex<Ledger>,
}

impl fmt::Debug for ApprovalLedgerTestOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalLedgerTestOnly").finish_non_exhaustive()
    }
}

impl ApprovalLedgerTestOnly {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Go `Open`: record an approval set. It derives the agent and root key
    /// IDs and the expected session context from the set's fields. The two
    /// root keys must be distinct: one root never counts twice.
    pub fn open(&self, set: ApprovalSetTestOnly) -> Result<(), ApprovalErrorTestOnly> {
        use ApprovalErrorTestOnly::*;
        if set.approval_set_id.is_empty()
            || set.request_hash.len() != 32
            || validate_required_scope_v2(&set.required_scope).is_err()
        {
            return Err(SetInvalid);
        }
        let agent_id = key_id_v2(&set.agent_public_key).map_err(|_| SetInvalid)?;
        let root_ids = [
            key_id_v2(&set.roots[0]).map_err(|_| SetInvalid)?,
            key_id_v2(&set.roots[1]).map_err(|_| SetInvalid)?,
        ];
        if root_ids[0] == root_ids[1] {
            return Err(SetInvalid);
        }
        let session_context = build_session_context_v2(&SessionContextV2Inputs {
            verifier_id: set.verifier_id.clone(),
            workspace_id: set.workspace_id.clone(),
            agent_id: agent_id.clone(),
            session_id: set.session_id.clone(),
            invocation_id: set.approval_set_id.clone(),
            request_hash: set.request_hash.clone(),
        })
        .map_err(|_| SetInvalid)?;
        let mut ledger = self.lock();
        if ledger.sets.contains_key(&set.approval_set_id) {
            return Err(SetAlreadyExists);
        }
        ledger.sets.insert(
            set.approval_set_id.clone(),
            ApprovalState {
                set,
                agent_id,
                root_ids,
                session_context,
                approvals: [None, None],
                executed: false,
            },
        );
        Ok(())
    }

    /// Go `RecordApproval`: bind a released decision and the exact proof
    /// bundle it verified to slot 0 or 1, and return whether both slots are
    /// now filled. Checks, in order: a released allow; the receipt's
    /// bundle_hash equals the bundle's hash; the claim is not already
    /// recorded in another set; the receipt and bundle name the set's
    /// verifier and agent (complete key), the receipt names the set's
    /// required scope, and the bundle's session_context equals the context
    /// derived from the set; the chain's terminal issuer key equals the
    /// slot's pinned root key and the receipt's issuer_ids contain that
    /// root; the slot is empty or holds this claim.
    pub fn record_approval(
        &self,
        set_id: &str,
        slot: usize,
        decision: Option<&Arc<V2ReleasedDecision>>,
        bundle_wire: &[u8],
    ) -> Result<bool, ApprovalErrorTestOnly> {
        use ApprovalErrorTestOnly::*;
        if slot > 1 {
            return Err(InvalidSlot);
        }
        let decision = match decision {
            Some(d) if d.decision() == "allow" => d,
            _ => return Err(NotReleased),
        };
        let receipt = decision.receipt().map_err(|_| NotReleased)?;
        let bundle = decode_proof_bundle_v2(bundle_wire).map_err(|_| ActionMismatch)?;
        match bundle_hash_v2(&bundle) {
            Ok(hash) if hash == receipt.bundle_hash => {}
            _ => return Err(ActionMismatch),
        }
        let claim_id = decision.claim_id();
        let mut ledger = self.lock();
        let ledger = &mut *ledger;
        let state = ledger.sets.get_mut(set_id).ok_or(SetUnknown)?;
        if ledger.recorded.get(&claim_id).is_some_and(|owner| owner != set_id) {
            return Err(Reused);
        }
        let set = &state.set;
        if receipt.verifier_id != set.verifier_id
            || bundle.verifier_id != set.verifier_id
            || receipt.agent_id != state.agent_id
            || bundle.agent_id != state.agent_id
            || bundle.agent_pub_key != set.agent_public_key
            || receipt.required_scope != set.required_scope
            || bundle.session_context.as_deref() != Some(state.session_context.as_slice())
        {
            return Err(ActionMismatch);
        }
        let root = bundle.delegations.last().ok_or(RootMismatch)?;
        if root.issuer_id != state.root_ids[slot]
            || root.issuer_pub_key != set.roots[slot]
            || !receipt.issuer_ids.contains(&state.root_ids[slot])
        {
            return Err(RootMismatch);
        }
        match &state.approvals[slot] {
            Some(current) if current.claim_id != claim_id => return Err(SlotFilled),
            Some(_) => {}
            None => {
                state.approvals[slot] = Some(ApprovalRecord {
                    claim_id: claim_id.clone(),
                    decision: Arc::clone(decision),
                });
                ledger.recorded.insert(claim_id, set_id.to_string());
            }
        }
        Ok(state.approvals.iter().all(Option::is_some))
    }

    /// Go `Execute`: atomically check that both approvals are recorded and
    /// each is still allowed at the receiver's authoritative time, then mark
    /// the set executed. It succeeds at most once per set.
    pub fn execute(
        &self,
        ctx: &V2Context,
        set_id: &str,
        clock: &dyn V2AuthoritativeClock,
    ) -> Result<(), ApprovalErrorTestOnly> {
        use ApprovalErrorTestOnly::*;
        let mut ledger = self.lock();
        let state = ledger.sets.get_mut(set_id).ok_or(SetUnknown)?;
        if state.executed {
            return Err(AlreadyExecuted);
        }
        let [Some(first), Some(second)] = &state.approvals else {
            return Err(Incomplete);
        };
        if !first.decision.allowed(ctx, clock) || !second.decision.allowed(ctx, clock) {
            return Err(Expired);
        }
        state.executed = true;
        Ok(())
    }
}
