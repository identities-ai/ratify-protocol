package v2reference

// Dual-root composition profile (SPEC-v2 §7.14), TEST ONLY.
//
// ApprovalLedgerTestOnly is the application ledger of the profile. An
// approval set names one action through its authenticated fields: the
// verifier ID, the workspace and session identifiers, the complete agent key,
// the required scope, the action's request hash, and two distinct pinned root
// keys. The ledger derives the expected session context from those fields
// with invocation_id = approval_set_id (SPEC-v2 §2.4); it never accepts a
// caller-supplied context. Each root approves through its own challenge and
// its own independently released Protocol decision. The ledger marks the
// action executable only when both released allows match the set and are
// still within their deadlines, lets it execute exactly once, and refuses to
// count one released decision toward more than one approval set. The
// composite result is application state, not a Protocol receipt.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

var (
	ErrApprovalNotReleased      = errors.New("v2reference: approval is not a released allow")
	ErrApprovalActionMismatch   = errors.New("v2reference: approval does not bind this approval set's action")
	ErrApprovalRootMismatch     = errors.New("v2reference: approval chain does not end at the slot's pinned root")
	ErrApprovalSlotFilled       = errors.New("v2reference: slot already holds a different approval")
	ErrApprovalReused           = errors.New("v2reference: approval is already recorded in another approval set")
	ErrApprovalIncomplete       = errors.New("v2reference: approval set is missing a released approval")
	ErrApprovalExpired          = errors.New("v2reference: an approval is past its release deadline")
	ErrApprovalAlreadyExecuted  = errors.New("v2reference: approval set already executed")
	ErrApprovalSetInvalid       = errors.New("v2reference: invalid approval set")
	ErrApprovalSetUnknown       = errors.New("v2reference: unknown approval set")
	ErrApprovalSetAlreadyExists = errors.New("v2reference: approval set already open")
)

// ApprovalSetTestOnly is the authenticated approval set an application opens
// before issuing either challenge (SPEC-v2 §7.14 step 1). Every field comes
// from authenticated application state, never from the presenter.
type ApprovalSetTestOnly struct {
	ApprovalSetID  string
	VerifierID     string
	WorkspaceID    string
	SessionID      string
	AgentPublicKey ratify.HybridPublicKey
	RequiredScope  string
	// RequestHash is the action's 32-byte operation-context hash (§2.4).
	RequestHash []byte
	// Roots are the complete public keys of the two pinned roots, in slot
	// order.
	Roots [2]ratify.HybridPublicKey
}

type approvalRecord struct {
	claimID  string
	decision *ratify.V2ReleasedDecision
}

type approvalState struct {
	set            ApprovalSetTestOnly
	agentID        string
	rootIDs        [2]string
	sessionContext []byte
	approvals      [2]*approvalRecord
	executed       bool
}

// ApprovalLedgerTestOnly is safe for concurrent use; each operation is one
// atomic step under a mutex.
type ApprovalLedgerTestOnly struct {
	mu   sync.Mutex
	sets map[string]*approvalState
	// recorded maps each recorded claim ID to the approval set it counts
	// toward, so one released decision never counts toward two sets.
	recorded map[string]string
}

// NewApprovalLedgerTestOnly returns an empty ledger.
func NewApprovalLedgerTestOnly() *ApprovalLedgerTestOnly {
	return &ApprovalLedgerTestOnly{sets: map[string]*approvalState{}, recorded: map[string]string{}}
}

func cloneHybridPublicKey(k ratify.HybridPublicKey) ratify.HybridPublicKey {
	return ratify.HybridPublicKey{Ed25519: bytes.Clone(k.Ed25519), MLDSA65: bytes.Clone(k.MLDSA65)}
}

func sameHybridPublicKey(a, b ratify.HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}

// Open records an approval set. It derives the agent and root key IDs and
// the expected session context from the set's fields. The two root keys must
// be distinct: one root never counts twice.
func (l *ApprovalLedgerTestOnly) Open(set ApprovalSetTestOnly) error {
	if set.ApprovalSetID == "" || len(set.RequestHash) != 32 || ratify.ValidateRequiredScopeV2(set.RequiredScope) != nil {
		return ErrApprovalSetInvalid
	}
	agentID, err := ratify.KeyIDV2(set.AgentPublicKey)
	if err != nil {
		return ErrApprovalSetInvalid
	}
	var rootIDs [2]string
	for i, root := range set.Roots {
		if rootIDs[i], err = ratify.KeyIDV2(root); err != nil {
			return ErrApprovalSetInvalid
		}
	}
	if rootIDs[0] == rootIDs[1] {
		return ErrApprovalSetInvalid
	}
	sessionContext, err := ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{
		VerifierID: set.VerifierID, WorkspaceID: set.WorkspaceID, AgentID: agentID,
		SessionID: set.SessionID, InvocationID: set.ApprovalSetID, RequestHash: set.RequestHash,
	})
	if err != nil {
		return ErrApprovalSetInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.sets[set.ApprovalSetID]; ok {
		return ErrApprovalSetAlreadyExists
	}
	set.RequestHash = bytes.Clone(set.RequestHash)
	set.AgentPublicKey = cloneHybridPublicKey(set.AgentPublicKey)
	set.Roots = [2]ratify.HybridPublicKey{cloneHybridPublicKey(set.Roots[0]), cloneHybridPublicKey(set.Roots[1])}
	l.sets[set.ApprovalSetID] = &approvalState{set: set, agentID: agentID, rootIDs: rootIDs, sessionContext: sessionContext}
	return nil
}

// RecordApproval binds a released decision and the exact proof bundle it
// verified to slot 0 or 1. It returns whether both slots are now filled.
// Checks, in order: a released allow; the receipt's bundle_hash equals the
// bundle's BundleHashV2; the claim is not already recorded in another set;
// the receipt and bundle name the set's verifier and agent (complete key),
// the receipt names the set's required scope, and the bundle's
// session_context equals the context derived from the set; the chain's
// terminal issuer key equals the slot's pinned root key and the receipt's
// issuer_ids contain that root; the slot is empty or holds this claim.
func (l *ApprovalLedgerTestOnly) RecordApproval(setID string, slot int, decision *ratify.V2ReleasedDecision, bundleWire []byte) (bool, error) {
	if slot != 0 && slot != 1 {
		return false, fmt.Errorf("v2reference: slot must be 0 or 1")
	}
	if decision == nil || decision.Decision() != "allow" {
		return false, ErrApprovalNotReleased
	}
	receipt, err := decision.Receipt()
	if err != nil {
		return false, ErrApprovalNotReleased
	}
	bundle, err := ratify.DecodeProofBundleV2(bundleWire)
	if err != nil {
		return false, ErrApprovalActionMismatch
	}
	bundleHash, err := ratify.BundleHashV2(bundle)
	if err != nil || bundleHash != receipt.BundleHash {
		return false, ErrApprovalActionMismatch
	}
	claimID := decision.ClaimID()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.sets[setID]
	if !ok {
		return false, ErrApprovalSetUnknown
	}
	if owner, ok := l.recorded[claimID]; ok && owner != setID {
		return false, ErrApprovalReused
	}
	set := state.set
	if receipt.VerifierID != set.VerifierID || bundle.VerifierID != set.VerifierID ||
		receipt.AgentID != state.agentID || bundle.AgentID != state.agentID || !sameHybridPublicKey(bundle.AgentPubKey, set.AgentPublicKey) ||
		receipt.RequiredScope != set.RequiredScope ||
		bundle.SessionContext == nil || !bytes.Equal(*bundle.SessionContext, state.sessionContext) {
		return false, ErrApprovalActionMismatch
	}
	if len(bundle.Delegations) == 0 {
		return false, ErrApprovalRootMismatch
	}
	root := bundle.Delegations[len(bundle.Delegations)-1]
	if root.IssuerID != state.rootIDs[slot] || !sameHybridPublicKey(root.IssuerPubKey, set.Roots[slot]) || !slices.Contains(receipt.IssuerIDs, state.rootIDs[slot]) {
		return false, ErrApprovalRootMismatch
	}
	if current := state.approvals[slot]; current != nil {
		if current.claimID != claimID {
			return false, ErrApprovalSlotFilled
		}
	} else {
		state.approvals[slot] = &approvalRecord{claimID: claimID, decision: decision}
		l.recorded[claimID] = setID
	}
	return state.approvals[0] != nil && state.approvals[1] != nil, nil
}

// Execute atomically checks that both approvals are recorded and each is
// still Allowed at the receiver's authoritative time, then marks the set
// executed. It succeeds at most once per set.
func (l *ApprovalLedgerTestOnly) Execute(ctx context.Context, setID string, clock ratify.V2AuthoritativeClock) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.sets[setID]
	if !ok {
		return ErrApprovalSetUnknown
	}
	if state.executed {
		return ErrApprovalAlreadyExecuted
	}
	if state.approvals[0] == nil || state.approvals[1] == nil {
		return ErrApprovalIncomplete
	}
	for _, approval := range state.approvals {
		if !approval.decision.Allowed(ctx, clock) {
			return ErrApprovalExpired
		}
	}
	state.executed = true
	return nil
}
