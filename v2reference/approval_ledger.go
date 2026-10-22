package v2reference

// Dual-root composition profile (SPEC-v2 §7.14), TEST ONLY.
//
// ApprovalLedgerTestOnly is the application ledger of the profile. An
// approval set names one action (through the expected session context, which
// binds the action's request hash and the approval set) and two distinct
// pinned roots. Each root approves through its own challenge and its own
// independently released Protocol decision. The ledger marks the action
// executable only when both released allows match the set and are still
// within their deadlines, and lets it execute exactly once. The composite
// result is application state, not a Protocol receipt.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

var (
	ErrApprovalNotReleased      = errors.New("v2reference: approval is not a released allow")
	ErrApprovalActionMismatch   = errors.New("v2reference: approval does not bind this approval set's action")
	ErrApprovalRootMismatch     = errors.New("v2reference: approval chain does not end at the slot's pinned root")
	ErrApprovalSlotFilled       = errors.New("v2reference: slot already holds a different approval")
	ErrApprovalIncomplete       = errors.New("v2reference: approval set is missing a released approval")
	ErrApprovalExpired          = errors.New("v2reference: an approval is past its release deadline")
	ErrApprovalAlreadyExecuted  = errors.New("v2reference: approval set already executed")
	ErrApprovalSetInvalid       = errors.New("v2reference: invalid approval set")
	ErrApprovalSetUnknown       = errors.New("v2reference: unknown approval set")
	ErrApprovalSetAlreadyExists = errors.New("v2reference: approval set already open")
)

// ApprovalSetTestOnly is the authenticated approval set an application opens
// before issuing either challenge.
type ApprovalSetTestOnly struct {
	ApprovalSetID string
	AgentID       string
	RequiredScope string
	// SessionContext is the expected 32-byte session context of both
	// challenges: invocation_id is the approval set ID and request_hash is
	// the action's operation-context hash (SPEC-v2 §2.4, §7.14).
	SessionContext []byte
	// Roots are the complete-key IDs of the two pinned roots, in slot order.
	Roots [2]string
}

type approvalRecord struct {
	claimID  string
	decision *ratify.V2ReleasedDecision
}

type approvalState struct {
	set       ApprovalSetTestOnly
	approvals [2]*approvalRecord
	executed  bool
}

// ApprovalLedgerTestOnly is safe for concurrent use; each operation is one
// atomic step under a mutex.
type ApprovalLedgerTestOnly struct {
	mu   sync.Mutex
	sets map[string]*approvalState
}

// NewApprovalLedgerTestOnly returns an empty ledger.
func NewApprovalLedgerTestOnly() *ApprovalLedgerTestOnly {
	return &ApprovalLedgerTestOnly{sets: map[string]*approvalState{}}
}

// Open records an approval set. The two roots must be present and distinct:
// one root never counts twice.
func (l *ApprovalLedgerTestOnly) Open(set ApprovalSetTestOnly) error {
	if set.ApprovalSetID == "" || set.AgentID == "" || set.RequiredScope == "" || len(set.SessionContext) != 32 ||
		set.Roots[0] == "" || set.Roots[1] == "" || set.Roots[0] == set.Roots[1] {
		return ErrApprovalSetInvalid
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.sets[set.ApprovalSetID]; ok {
		return ErrApprovalSetAlreadyExists
	}
	set.SessionContext = bytes.Clone(set.SessionContext)
	l.sets[set.ApprovalSetID] = &approvalState{set: set}
	return nil
}

// RecordApproval binds a released decision and the exact proof bundle it
// verified to slot 0 or 1. It returns whether both slots are now filled.
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
	l.mu.Lock()
	defer l.mu.Unlock()
	state, ok := l.sets[setID]
	if !ok {
		return false, ErrApprovalSetUnknown
	}
	set := state.set
	if bundle.SessionContext == nil || !bytes.Equal(*bundle.SessionContext, set.SessionContext) ||
		receipt.AgentID != set.AgentID || bundle.AgentID != set.AgentID || receipt.RequiredScope != set.RequiredScope {
		return false, ErrApprovalActionMismatch
	}
	if len(bundle.Delegations) == 0 || bundle.Delegations[len(bundle.Delegations)-1].IssuerID != set.Roots[slot] {
		return false, ErrApprovalRootMismatch
	}
	claimID := decision.ClaimID()
	if current := state.approvals[slot]; current != nil {
		if current.claimID != claimID {
			return false, ErrApprovalSlotFilled
		}
	} else {
		state.approvals[slot] = &approvalRecord{claimID: claimID, decision: decision}
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
