package ratify

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func verificationLifecycleOperationV2Test(state VerificationLifecycleV2State, event VerificationLifecycleV2Event) VerificationLifecycleV2Operation {
	op := VerificationLifecycleV2Operation{Event: event}
	if state.phase == VerificationLifecycleV2Claim && event == VerificationLifecycleV2ClaimCreated {
		op.ClaimID = strings.Repeat("a", 64)
		op.TerminalGeneration = 1
	} else if state.claimID != "" {
		op.ClaimID = state.claimID
		op.TerminalGeneration = state.terminalGeneration
	}
	if event == VerificationLifecycleV2TerminalCommitted {
		op.ReceiptSequence = 1
		op.PreviousReceipt = make([]byte, 48)
		op.ReceiptBodyDigest = bytes.Repeat([]byte{1}, 48)
	} else if event == VerificationLifecycleV2ReceiptAppended || event == VerificationLifecycleV2PublicationCheckpointed {
		op.ReceiptSequence = state.receiptSequence
		op.PreviousReceipt = bytes.Clone(state.previousReceipt)
		op.ReceiptBodyDigest = bytes.Clone(state.receiptBodyDigest)
	}
	return op
}

func verificationLifecycleStateV2Test(phase VerificationLifecycleV2Phase) VerificationLifecycleV2State {
	state := VerificationLifecycleV2State{phase: phase}
	if phase != VerificationLifecycleV2Preflight && phase != VerificationLifecycleV2Claim && phase != VerificationLifecycleV2Stopped && phase != VerificationLifecycleV2Released {
		state.claimID = strings.Repeat("a", 64)
		state.terminalGeneration = 1
	}
	if phase == VerificationLifecycleV2PublicationCheckpoint {
		state.receiptSequence = 1
		state.previousReceipt = make([]byte, 48)
		state.receiptBodyDigest = bytes.Repeat([]byte{1}, 48)
	}
	return state
}

func TestVerificationLifecycleV2EnforcesReleaseOrdering(t *testing.T) {
	tests := []struct {
		name   string
		events []VerificationLifecycleV2Event
	}{
		{
			name: "allow path",
			events: []VerificationLifecycleV2Event{
				VerificationLifecycleV2PreflightPassed,
				VerificationLifecycleV2ClaimCreated,
				VerificationLifecycleV2ClaimCheckpointed,
				VerificationLifecycleV2TrustTrusted,
				VerificationLifecycleV2StatusCurrent,
				VerificationLifecycleV2LocalPolicyPassed,
				VerificationLifecycleV2RateReserved,
				VerificationLifecycleV2TerminalCommitted,
				VerificationLifecycleV2ReceiptAppended,
				VerificationLifecycleV2PublicationCheckpointed,
			},
		},
		{
			name: "untrusted chain terminates without status lookup",
			events: []VerificationLifecycleV2Event{
				VerificationLifecycleV2PreflightPassed,
				VerificationLifecycleV2ClaimCreated,
				VerificationLifecycleV2ClaimCheckpointed,
				VerificationLifecycleV2TrustRejected,
				VerificationLifecycleV2TerminalCommitted,
				VerificationLifecycleV2ReceiptAppended,
				VerificationLifecycleV2PublicationCheckpointed,
			},
		},
		{
			name: "status failure skips rate reservation",
			events: []VerificationLifecycleV2Event{
				VerificationLifecycleV2PreflightPassed,
				VerificationLifecycleV2ClaimCreated,
				VerificationLifecycleV2ClaimCheckpointed,
				VerificationLifecycleV2TrustTrusted,
				VerificationLifecycleV2StatusRejected,
				VerificationLifecycleV2TerminalCommitted,
				VerificationLifecycleV2ReceiptAppended,
				VerificationLifecycleV2PublicationCheckpointed,
			},
		},
		{
			name: "rate policy not required",
			events: []VerificationLifecycleV2Event{
				VerificationLifecycleV2PreflightPassed,
				VerificationLifecycleV2ClaimCreated,
				VerificationLifecycleV2ClaimCheckpointed,
				VerificationLifecycleV2TrustTrusted,
				VerificationLifecycleV2StatusCurrent,
				VerificationLifecycleV2LocalPolicyPassed,
				VerificationLifecycleV2RateNotRequired,
				VerificationLifecycleV2TerminalCommitted,
				VerificationLifecycleV2ReceiptAppended,
				VerificationLifecycleV2PublicationCheckpointed,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := VerificationLifecycleV2State{}
			var err error
			for _, event := range test.events {
				state, err = AdvanceVerificationLifecycleV2(state, verificationLifecycleOperationV2Test(state, event))
				if err != nil {
					t.Fatalf("event %q rejected in phase %q: %v", event, state.Phase(), err)
				}
			}
			if state.Phase() != VerificationLifecycleV2Released {
				t.Fatalf("lifecycle ended in %q, want released", state.Phase())
			}
		})
	}
}

func TestVerificationLifecycleV2EmptyDelegationStopsBeforeTrustAndStatus(t *testing.T) {
	state := VerificationLifecycleV2State{}
	for _, event := range []VerificationLifecycleV2Event{
		VerificationLifecycleV2PreflightPassed,
		VerificationLifecycleV2ClaimCreated,
		VerificationLifecycleV2ClaimCheckpointed,
		VerificationLifecycleV2NotDelegated,
	} {
		var err error
		state, err = AdvanceVerificationLifecycleV2(state, verificationLifecycleOperationV2Test(state, event))
		if err != nil {
			t.Fatalf("event %q rejected: %v", event, err)
		}
	}
	if state.Phase() != VerificationLifecycleV2TerminalCommit {
		t.Fatalf("empty delegation ended in %q, want terminal commit", state.Phase())
	}
	if _, err := AdvanceVerificationLifecycleV2(state, verificationLifecycleOperationV2Test(state, VerificationLifecycleV2ReceiptAppended)); err == nil {
		t.Fatal("empty delegation bypassed terminal outbox commit")
	}
}

func TestVerificationLifecycleV2StopsBeforeClaimWhenPreflightFails(t *testing.T) {
	state, err := AdvanceVerificationLifecycleV2(VerificationLifecycleV2State{}, VerificationLifecycleV2Operation{Event: VerificationLifecycleV2PreflightRejected})
	if err != nil {
		t.Fatal(err)
	}
	if state.Phase() != VerificationLifecycleV2Stopped {
		t.Fatalf("preflight rejection ended in %q, want stopped without release", state.Phase())
	}
	if _, err := AdvanceVerificationLifecycleV2(state, verificationLifecycleOperationV2Test(state, VerificationLifecycleV2ClaimCreated)); err == nil {
		t.Fatal("preflight rejection allowed a claim")
	}
}

func TestVerificationLifecycleV2RejectsClaimAndOutboxSubstitution(t *testing.T) {
	state := verificationLifecycleStateV2Test(VerificationLifecycleV2Trust)
	wrongClaim := verificationLifecycleOperationV2Test(state, VerificationLifecycleV2TrustTrusted)
	wrongClaim.ClaimID = strings.Repeat("b", 64)
	if got, err := AdvanceVerificationLifecycleV2(state, wrongClaim); err == nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("mismatched claim event was accepted or changed state: state=%+v err=%v", got, err)
	}
	staleGeneration := verificationLifecycleOperationV2Test(state, VerificationLifecycleV2TrustTrusted)
	staleGeneration.TerminalGeneration++
	if got, err := AdvanceVerificationLifecycleV2(state, staleGeneration); err == nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("stale generation event was accepted or changed state: state=%+v err=%v", got, err)
	}

	state = VerificationLifecycleV2State{}
	for _, event := range []VerificationLifecycleV2Event{
		VerificationLifecycleV2PreflightPassed,
		VerificationLifecycleV2ClaimCreated,
		VerificationLifecycleV2ClaimCheckpointed,
		VerificationLifecycleV2TrustTrusted,
		VerificationLifecycleV2StatusCurrent,
		VerificationLifecycleV2LocalPolicyPassed,
		VerificationLifecycleV2RateNotRequired,
		VerificationLifecycleV2TerminalCommitted,
	} {
		var err error
		state, err = AdvanceVerificationLifecycleV2(state, verificationLifecycleOperationV2Test(state, event))
		if err != nil {
			t.Fatalf("event %q rejected: %v", event, err)
		}
	}
	changedOutbox := verificationLifecycleOperationV2Test(state, VerificationLifecycleV2ReceiptAppended)
	changedOutbox.ReceiptBodyDigest[0] ^= 1
	if got, err := AdvanceVerificationLifecycleV2(state, changedOutbox); err == nil || !reflect.DeepEqual(got, state) {
		t.Fatalf("substituted receipt outbox was accepted or changed state: state=%+v err=%v", got, err)
	}
}

func TestVerificationLifecycleV2RejectsOutOfOrderOperations(t *testing.T) {
	tests := []struct {
		name  string
		state VerificationLifecycleV2State
		event VerificationLifecycleV2Event
	}{
		{"claim before preflight", VerificationLifecycleV2State{}, VerificationLifecycleV2ClaimCreated},
		{"callback before claim checkpoint", verificationLifecycleStateV2Test(VerificationLifecycleV2ClaimCheckpoint), VerificationLifecycleV2TrustTrusted},
		{"status before trust", verificationLifecycleStateV2Test(VerificationLifecycleV2Trust), VerificationLifecycleV2StatusCurrent},
		{"local policy before status", verificationLifecycleStateV2Test(VerificationLifecycleV2Status), VerificationLifecycleV2LocalPolicyPassed},
		{"rate before all status checks", verificationLifecycleStateV2Test(VerificationLifecycleV2Status), VerificationLifecycleV2RateReserved},
		{"receipt before terminal outbox", verificationLifecycleStateV2Test(VerificationLifecycleV2TerminalCommit), VerificationLifecycleV2ReceiptAppended},
		{"release before publication checkpoint", verificationLifecycleStateV2Test(VerificationLifecycleV2ReceiptAppend), VerificationLifecycleV2PublicationCheckpointed},
		{"advance after release", verificationLifecycleStateV2Test(VerificationLifecycleV2Released), VerificationLifecycleV2PublicationCheckpointed},
		{"advance after preflight stop", verificationLifecycleStateV2Test(VerificationLifecycleV2Stopped), VerificationLifecycleV2ClaimCreated},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := AdvanceVerificationLifecycleV2(test.state, verificationLifecycleOperationV2Test(test.state, test.event))
			if err == nil {
				t.Fatalf("out-of-order event %q advanced to %q", test.event, got.Phase())
			}
			want := test.state
			if want.phase == "" {
				want.phase = VerificationLifecycleV2Preflight
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rejected event changed state: got %+v, want %+v", got, want)
			}
		})
	}
}

// VerificationLifecycleV2Phase names the protocol evaluation boundary reached
// by a verifier. This reducer describes ordering only. It does not persist a
// claim, checkpoint state, resolve trust, verify status, or authorize an
// action. Production callers must provide the durable, fenced operations
// required by SPEC-v2 before advancing these phases.
type VerificationLifecycleV2Phase string

const (
	VerificationLifecycleV2Preflight             VerificationLifecycleV2Phase = "preflight"
	VerificationLifecycleV2Claim                 VerificationLifecycleV2Phase = "claim"
	VerificationLifecycleV2ClaimCheckpoint       VerificationLifecycleV2Phase = "claim_checkpoint"
	VerificationLifecycleV2Trust                 VerificationLifecycleV2Phase = "trust"
	VerificationLifecycleV2LocalPolicy           VerificationLifecycleV2Phase = "local_policy"
	VerificationLifecycleV2Status                VerificationLifecycleV2Phase = "status"
	VerificationLifecycleV2RateReservation       VerificationLifecycleV2Phase = "rate_reservation"
	VerificationLifecycleV2TerminalCommit        VerificationLifecycleV2Phase = "terminal_commit"
	VerificationLifecycleV2ReceiptAppend         VerificationLifecycleV2Phase = "receipt_append"
	VerificationLifecycleV2PublicationCheckpoint VerificationLifecycleV2Phase = "publication_checkpoint"
	VerificationLifecycleV2Released              VerificationLifecycleV2Phase = "released"
	VerificationLifecycleV2Stopped               VerificationLifecycleV2Phase = "stopped_without_release"
)

// VerificationLifecycleV2Event is an observed completed operation. Events do
// not assert that the operation was durable; the runtime adapter must enforce
// the matching storage and checkpoint contract itself.
type VerificationLifecycleV2Event string

const (
	VerificationLifecycleV2PreflightPassed         VerificationLifecycleV2Event = "preflight_passed"
	VerificationLifecycleV2PreflightRejected       VerificationLifecycleV2Event = "preflight_rejected"
	VerificationLifecycleV2ClaimCreated            VerificationLifecycleV2Event = "claim_created"
	VerificationLifecycleV2ClaimReplay             VerificationLifecycleV2Event = "claim_replay"
	VerificationLifecycleV2ClaimConflict           VerificationLifecycleV2Event = "claim_conflict"
	VerificationLifecycleV2ClaimCheckpointed       VerificationLifecycleV2Event = "claim_checkpointed"
	VerificationLifecycleV2NotDelegated            VerificationLifecycleV2Event = "not_delegated"
	VerificationLifecycleV2TrustTrusted            VerificationLifecycleV2Event = "trust_trusted"
	VerificationLifecycleV2TrustUnavailable        VerificationLifecycleV2Event = "trust_unavailable"
	VerificationLifecycleV2TrustRejected           VerificationLifecycleV2Event = "trust_rejected"
	VerificationLifecycleV2LocalPolicyPassed       VerificationLifecycleV2Event = "local_policy_passed"
	VerificationLifecycleV2LocalPolicyRejected     VerificationLifecycleV2Event = "local_policy_rejected"
	VerificationLifecycleV2StatusCurrent           VerificationLifecycleV2Event = "status_current"
	VerificationLifecycleV2StatusRejected          VerificationLifecycleV2Event = "status_rejected"
	VerificationLifecycleV2RateReserved            VerificationLifecycleV2Event = "rate_reserved"
	VerificationLifecycleV2RateNotRequired         VerificationLifecycleV2Event = "rate_not_required"
	VerificationLifecycleV2RateRejected            VerificationLifecycleV2Event = "rate_rejected"
	VerificationLifecycleV2TerminalCommitted       VerificationLifecycleV2Event = "terminal_committed"
	VerificationLifecycleV2ReceiptAppended         VerificationLifecycleV2Event = "receipt_appended"
	VerificationLifecycleV2PublicationCheckpointed VerificationLifecycleV2Event = "publication_checkpointed"
)

// VerificationLifecycleV2State is a non-durable ordering cursor. In
// particular, Released is not an authorization decision and must never be
// used as evidence that a handler may run.
type VerificationLifecycleV2State struct {
	phase              VerificationLifecycleV2Phase
	claimID            string
	terminalGeneration int64
	receiptSequence    int64
	previousReceipt    []byte
	receiptBodyDigest  []byte
}

// Phase returns the current ordering phase. It does not confer permission to
// expose a result or execute a handler.
func (s VerificationLifecycleV2State) Phase() VerificationLifecycleV2Phase { return s.phase }

// VerificationLifecycleV2Operation binds post-claim events to one durable
// claim generation. The store remains responsible for authenticating this
// identity and enforcing its fence; the reducer only rejects mismatched data.
type VerificationLifecycleV2Operation struct {
	Event              VerificationLifecycleV2Event
	ClaimID            string
	TerminalGeneration int64
	ReceiptSequence    int64
	PreviousReceipt    []byte
	ReceiptBodyDigest  []byte
}

// AdvanceVerificationLifecycleV2 applies the normative Verify operation
// order. A failed trust, local-policy, status, or rate check proceeds directly
// to terminal commit; successful checks proceed to the next required stage.
// Preflight rejection and an already-owned replay/conflict stop without
// creating a new receipt. Storage errors leave the phase unchanged so the
// caller can retry or reload validated durable state.
func AdvanceVerificationLifecycleV2(state VerificationLifecycleV2State, operation VerificationLifecycleV2Operation) (VerificationLifecycleV2State, error) {
	event := operation.Event
	if state.phase == "" {
		state.phase = VerificationLifecycleV2Preflight
	}
	var next VerificationLifecycleV2Phase
	if state.phase == VerificationLifecycleV2Preflight {
		if operation.ClaimID != "" || operation.TerminalGeneration != 0 || operation.ReceiptSequence != 0 || len(operation.PreviousReceipt) != 0 || len(operation.ReceiptBodyDigest) != 0 {
			return state, fmt.Errorf("v2 lifecycle: claim identity is only set by successful claim creation")
		}
	} else if state.phase == VerificationLifecycleV2Claim && event != VerificationLifecycleV2ClaimCreated {
		if operation.ClaimID != "" || operation.TerminalGeneration != 0 || operation.ReceiptSequence != 0 || len(operation.PreviousReceipt) != 0 || len(operation.ReceiptBodyDigest) != 0 {
			return state, fmt.Errorf("v2 lifecycle: replay and conflict outcomes cannot carry evaluator ownership")
		}
	} else if state.phase != VerificationLifecycleV2Stopped && state.phase != VerificationLifecycleV2Released {
		if state.phase != VerificationLifecycleV2Claim && (operation.ClaimID != state.claimID || operation.TerminalGeneration != state.terminalGeneration) {
			return state, fmt.Errorf("v2 lifecycle: event claim or terminal generation does not match the active claim")
		}
	}
	switch state.phase {
	case VerificationLifecycleV2Preflight:
		if event == VerificationLifecycleV2PreflightRejected {
			// A preflight rejection ends without a claim or Protocol receipt.
			next = VerificationLifecycleV2Stopped
		} else if event == VerificationLifecycleV2PreflightPassed {
			next = VerificationLifecycleV2Claim
		} else {
			return state, fmt.Errorf("v2 lifecycle: only successful preflight may create a claim")
		}
	case VerificationLifecycleV2Claim:
		if event == VerificationLifecycleV2ClaimReplay || event == VerificationLifecycleV2ClaimConflict {
			// A duplicate or conflicting claim never starts a second evaluation.
			next = VerificationLifecycleV2Stopped
		} else if event == VerificationLifecycleV2ClaimCreated {
			if !lowerHexString(operation.ClaimID) || len(operation.ClaimID) != 64 || operation.TerminalGeneration <= 0 {
				return state, fmt.Errorf("v2 lifecycle: created claim requires a canonical claim ID and positive terminal generation")
			}
			next = VerificationLifecycleV2ClaimCheckpoint
		} else {
			return state, fmt.Errorf("v2 lifecycle: claim creation must follow preflight")
		}
	case VerificationLifecycleV2ClaimCheckpoint:
		if event != VerificationLifecycleV2ClaimCheckpointed {
			return state, fmt.Errorf("v2 lifecycle: claim checkpoint must precede external evaluation")
		}
		next = VerificationLifecycleV2Trust
	case VerificationLifecycleV2Trust:
		switch event {
		case VerificationLifecycleV2NotDelegated:
			// An empty but validly signed chain is terminal after claim and does
			// not consult trust roots, status providers, or authorization policy.
			next = VerificationLifecycleV2TerminalCommit
		case VerificationLifecycleV2TrustTrusted:
			next = VerificationLifecycleV2Status
		case VerificationLifecycleV2TrustUnavailable, VerificationLifecycleV2TrustRejected:
			next = VerificationLifecycleV2TerminalCommit
		default:
			return state, fmt.Errorf("v2 lifecycle: trust resolution must precede local policy and status")
		}
	case VerificationLifecycleV2LocalPolicy:
		switch event {
		case VerificationLifecycleV2LocalPolicyPassed:
			next = VerificationLifecycleV2RateReservation
		case VerificationLifecycleV2LocalPolicyRejected:
			next = VerificationLifecycleV2TerminalCommit
		default:
			return state, fmt.Errorf("v2 lifecycle: local policy must precede status evaluation")
		}
	case VerificationLifecycleV2Status:
		switch event {
		case VerificationLifecycleV2StatusCurrent:
			next = VerificationLifecycleV2LocalPolicy
		case VerificationLifecycleV2StatusRejected:
			next = VerificationLifecycleV2TerminalCommit
		default:
			return state, fmt.Errorf("v2 lifecycle: all certificate status checks must finish before rate reservation")
		}
	case VerificationLifecycleV2RateReservation:
		switch event {
		case VerificationLifecycleV2RateReserved, VerificationLifecycleV2RateNotRequired, VerificationLifecycleV2RateRejected:
			next = VerificationLifecycleV2TerminalCommit
		default:
			return state, fmt.Errorf("v2 lifecycle: rate reservation must precede terminal commit")
		}
	case VerificationLifecycleV2TerminalCommit:
		if event != VerificationLifecycleV2TerminalCommitted {
			return state, fmt.Errorf("v2 lifecycle: terminal result and receipt outbox must commit before signing")
		}
		if operation.ReceiptSequence <= 0 || operation.ReceiptSequence > maxSafeInteger || len(operation.PreviousReceipt) != 48 || len(operation.ReceiptBodyDigest) != 48 {
			return state, fmt.Errorf("v2 lifecycle: terminal commit requires a sequence, previous receipt hash, and body digest")
		}
		state.receiptSequence = operation.ReceiptSequence
		state.previousReceipt = bytes.Clone(operation.PreviousReceipt)
		state.receiptBodyDigest = bytes.Clone(operation.ReceiptBodyDigest)
		next = VerificationLifecycleV2ReceiptAppend
	case VerificationLifecycleV2ReceiptAppend:
		if event != VerificationLifecycleV2ReceiptAppended {
			return state, fmt.Errorf("v2 lifecycle: signed receipt append must precede publication checkpoint")
		}
		if operation.ReceiptSequence != state.receiptSequence || !bytes.Equal(operation.PreviousReceipt, state.previousReceipt) || !bytes.Equal(operation.ReceiptBodyDigest, state.receiptBodyDigest) {
			return state, fmt.Errorf("v2 lifecycle: appended receipt does not match the committed outbox identity")
		}
		next = VerificationLifecycleV2PublicationCheckpoint
	case VerificationLifecycleV2PublicationCheckpoint:
		if event != VerificationLifecycleV2PublicationCheckpointed {
			return state, fmt.Errorf("v2 lifecycle: publication checkpoint must precede release")
		}
		if operation.ReceiptSequence != state.receiptSequence || !bytes.Equal(operation.PreviousReceipt, state.previousReceipt) || !bytes.Equal(operation.ReceiptBodyDigest, state.receiptBodyDigest) {
			return state, fmt.Errorf("v2 lifecycle: publication checkpoint does not cover the committed receipt")
		}
		next = VerificationLifecycleV2Released
	case VerificationLifecycleV2Released, VerificationLifecycleV2Stopped:
		return state, fmt.Errorf("v2 lifecycle: terminal phase %q cannot advance", state.phase)
	default:
		return state, fmt.Errorf("v2 lifecycle: unknown or terminal phase %q", state.phase)
	}
	if state.phase == VerificationLifecycleV2Claim && event == VerificationLifecycleV2ClaimCreated {
		state.claimID = operation.ClaimID
		state.terminalGeneration = operation.TerminalGeneration
	}
	state.phase = next
	return state, nil
}
