package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
)

// Committed versus released (SPEC-v2 §6.9, §7.9; amendment A1).
//
// VerifyProofBundleV2 commits a terminal Protocol result and returns an
// opaque CommittedV2Outcome holding the handoff tuple {claim_id,
// receipt_body_digest, challenge_expires_at, allow_horizon} and the sealed
// receipt outbox body. It exposes no decision. ReleaseV2Decision is the only
// path to an actionable decision; it returns released, pending (retryable),
// withheld (permanent), or rejected (permanent).
//
// There is no production local-log substitute for an independent checkpoint.
// The in-memory store in package v2reference exists only for tests and
// conformance scenarios.

// CommittedV2Outcome is the immutable, non-actionable handoff from a
// committed verification to publication and ReleaseV2Decision.
type CommittedV2Outcome struct {
	claimID            string
	verifierID         string
	receiptBody        []byte
	challengeExpiresAt int64
	allowHorizon       int64
}

func newCommittedV2Outcome(claim V2ChallengeClaim, body []byte, allowHorizon int64) *CommittedV2Outcome {
	return &CommittedV2Outcome{claimID: claim.ClaimID, verifierID: claim.VerifierID, receiptBody: bytes.Clone(body), challengeExpiresAt: claim.ExpiresAt, allowHorizon: allowHorizon}
}

// ClaimID is the Protocol claim ID of the committed evaluation.
func (c *CommittedV2Outcome) ClaimID() string { return c.claimID }

// ReceiptBody returns a copy of the sealed receipt outbox body, for the
// receipt publisher only. Applications must not parse it to authorize.
func (c *CommittedV2Outcome) ReceiptBody() []byte { return bytes.Clone(c.receiptBody) }

// ReceiptBodyDigest is ReceiptOutboxDigest of the sealed body (SPEC-v2 §4).
func (c *CommittedV2Outcome) ReceiptBodyDigest() string { return ReceiptOutboxDigestV2(c.receiptBody) }

// ChallengeExpiresAt is the sealed exclusive challenge deadline.
func (c *CommittedV2Outcome) ChallengeExpiresAt() int64 { return c.challengeExpiresAt }

// AllowHorizon is the exclusive allow deadline; ok is false (null) unless the
// committed result can become an allow.
func (c *CommittedV2Outcome) AllowHorizon() (horizon int64, ok bool) {
	return c.allowHorizon, c.allowHorizon > 0
}

// ReceiptOutboxDigestV2 is "sha384:" + hex(SHA-384("ratify-protocol-receipt-outbox-v2" || 0x00 || body)).
func ReceiptOutboxDigestV2(body []byte) string {
	h := sha512.New384()
	_, _ = h.Write([]byte("ratify-protocol-receipt-outbox-v2"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	return "sha384:" + hex.EncodeToString(h.Sum(nil))
}

// V2ReceiptPublisher is the Part B receipt outbox drain (§7.7). It signs and
// appends the exact committed body for claimID at the next ordered log
// position, or returns the receipt already appended for that claim, and
// returns the signed receipt wire. It refuses a body that differs from the
// committed outbox body.
type V2ReceiptPublisher interface {
	PublishV2Receipt(ctx context.Context, claimID string, receiptBody []byte) ([]byte, error)
}

// V2CheckpointAcknowledgement is an independent checkpoint's acknowledgement
// of one receipt-log entry (§7.8). EntryHash is
// StatementBodyDigest(0x0008, receipt signable body); Timestamp is immutable.
type V2CheckpointAcknowledgement struct {
	LogID     string
	Sequence  int64
	EntryHash []byte
	Timestamp int64
}

// ErrV2AcknowledgementNotFound is returned by GetV2Acknowledgement for an
// entry the checkpoint has not acknowledged.
var ErrV2AcknowledgementNotFound = errors.New("v2 checkpoint acknowledgement not found")

// V2ReceiptCheckpoint is the caller-configured independent checkpoint (§7.8).
// AcknowledgeV2Receipt accepts only the next sequence of the log, linked by
// previousEntryHash, and returns the original acknowledgement on an identical
// retry. GetV2Acknowledgement returns an acknowledgement,
// ErrV2AcknowledgementNotFound, or another error for unavailability.
type V2ReceiptCheckpoint interface {
	AcknowledgeV2Receipt(ctx context.Context, logID string, sequence int64, previousEntryHash, entryHash []byte) (V2CheckpointAcknowledgement, error)
	GetV2Acknowledgement(ctx context.Context, logID string, sequence int64) (V2CheckpointAcknowledgement, error)
}

// V2ReleaseRecord is the durable release record of §6.9 step 9.
type V2ReleaseRecord struct {
	ClaimID      string
	EntryHash    []byte
	AckTimestamp int64
}

// V2TerminalClaimRecord is what the claim store returns to release (§7.3):
// the sealed handoff values, the recorded finalization time T_final, any
// receipt_abandoned marking, and any prior release record.
type V2TerminalClaimRecord struct {
	Terminal            bool
	ReceiptOutboxDigest string
	ChallengeExpiresAt  int64
	AllowHorizon        int64
	FinalizedAt         int64
	ReceiptAbandoned    bool
	Release             *V2ReleaseRecord
}

// ErrV2ReleaseStateMismatch is returned by RecordV2Release when a different
// release record already exists for the claim.
var ErrV2ReleaseStateMismatch = errors.New("v2 claim already records a different release")

// V2ReleaseClaimStore is the claim-store view release needs.
type V2ReleaseClaimStore interface {
	V2AuthoritativeClock
	LoadV2TerminalClaim(ctx context.Context, claimID string) (V2TerminalClaimRecord, error)
	RecordV2Release(ctx context.Context, record V2ReleaseRecord) error
}

// V2ReleaseConfig is caller-authenticated release configuration.
type V2ReleaseConfig struct {
	VerifierPublicKey HybridPublicKey
	LogID             string
	ClaimStore        V2ReleaseClaimStore
	Checkpoint        V2ReceiptCheckpoint
}

// V2ReleaseStatus is the release outcome class of §6.9.
type V2ReleaseStatus string

const (
	V2ReleaseReleased V2ReleaseStatus = "released"
	V2ReleasePending  V2ReleaseStatus = "pending"
	V2ReleaseWithheld V2ReleaseStatus = "withheld"
	V2ReleaseRejected V2ReleaseStatus = "rejected"
)

// V2ReleasedDecision is an actionable decision; it exists only inside a
// released V2ReleaseResult.
type V2ReleasedDecision struct {
	ClaimID            string
	Decision           string
	Reason             string
	IdentityStatus     string
	GrantedScope       []string
	Receipt            *VerificationReceiptV2
	ReleaseTime        int64
	ChallengeExpiresAt int64
	AllowHorizon       int64
}

// Allowed reports whether this released allow may still be acted on at the
// receiver's authoritative time now (now < every exclusive deadline). The
// receiver calls it immediately before its side effect.
func (d V2ReleasedDecision) Allowed(now int64) bool {
	return d.Decision == "allow" && d.Receipt != nil && now < d.ChallengeExpiresAt && now < d.AllowHorizon
}

// V2ReleaseResult is the result of ReleaseV2Decision. Decision is non-nil
// only when Status is released; Reason is empty only when released.
type V2ReleaseResult struct {
	Status   V2ReleaseStatus
	Reason   string
	Decision *V2ReleasedDecision
}

func releaseResultV2(status V2ReleaseStatus, reason string) V2ReleaseResult {
	return V2ReleaseResult{Status: status, Reason: reason}
}

// ReleaseV2Decision performs the release steps of SPEC-v2 §6.9 in order and
// stops at the first that does not pass. signedReceipt is the publisher's
// signed receipt wire, or nil when it has not been appended yet.
func ReleaseV2Decision(ctx context.Context, committed *CommittedV2Outcome, signedReceipt []byte, config V2ReleaseConfig) V2ReleaseResult {
	if ctx == nil || committed == nil || committed.claimID == "" || len(committed.receiptBody) == 0 || config.ClaimStore == nil || config.Checkpoint == nil {
		return releaseResultV2(V2ReleaseRejected, "release_state_mismatch")
	}
	verifierID, err := keyIDV2(config.VerifierPublicKey)
	if err != nil || verifierID != committed.verifierID || len(config.LogID) != 32 || !lowerHexString(config.LogID) {
		return releaseResultV2(V2ReleaseRejected, "release_state_mismatch")
	}
	// 1. Committed state.
	record, err := loadV2TerminalClaimSafely(ctx, config.ClaimStore, committed.claimID)
	if err != nil {
		return releaseResultV2(V2ReleasePending, "claim_store_unavailable")
	}
	if record.ReceiptAbandoned {
		return releaseResultV2(V2ReleaseWithheld, "receipt_abandoned")
	}
	if !record.Terminal || record.ReceiptOutboxDigest != committed.ReceiptBodyDigest() ||
		record.ChallengeExpiresAt != committed.challengeExpiresAt || record.AllowHorizon != committed.allowHorizon {
		return releaseResultV2(V2ReleaseRejected, "release_state_mismatch")
	}
	// 3. Receipt.
	if len(signedReceipt) == 0 {
		return releaseResultV2(V2ReleasePending, "receipt_not_appended")
	}
	receipt, err := verifyPublishedV2Receipt(signedReceipt, config)
	if err != nil || receipt.VerifierID != committed.verifierID {
		return releaseResultV2(V2ReleaseRejected, "receipt_invalid")
	}
	// 4. Body binding.
	body, err := VerificationReceiptV2Body(receipt)
	if err != nil || !bytes.Equal(body, committed.receiptBody) {
		return releaseResultV2(V2ReleaseRejected, "receipt_body_mismatch")
	}
	entryHash, err := VerificationReceiptV2Digest(receipt)
	if err != nil {
		return releaseResultV2(V2ReleaseRejected, "receipt_invalid")
	}
	var ack V2CheckpointAcknowledgement
	if record.Release != nil {
		// 2. Prior release: the same receipt entry, then the clock and deadlines.
		if record.Release.ClaimID != committed.claimID || !bytes.Equal(record.Release.EntryHash, entryHash) {
			return releaseResultV2(V2ReleaseRejected, "release_state_mismatch")
		}
		ack = V2CheckpointAcknowledgement{LogID: receipt.LogID, Sequence: receipt.Sequence, EntryHash: entryHash, Timestamp: record.Release.AckTimestamp}
	} else {
		// 5. Predecessor.
		if receipt.Sequence > 1 {
			previous, err := getV2AcknowledgementSafely(ctx, config.Checkpoint, receipt.LogID, receipt.Sequence-1)
			if err != nil {
				return releaseResultV2(V2ReleasePending, "acknowledgement_unavailable")
			}
			if previous.LogID != receipt.LogID || previous.Sequence != receipt.Sequence-1 || !bytes.Equal(previous.EntryHash, receipt.PreviousReceiptHash) {
				return releaseResultV2(V2ReleaseRejected, "log_predecessor_mismatch")
			}
		}
		// 6. Acknowledgement.
		ack, err = getV2AcknowledgementSafely(ctx, config.Checkpoint, receipt.LogID, receipt.Sequence)
		if err != nil {
			return releaseResultV2(V2ReleasePending, "acknowledgement_unavailable")
		}
		if ack.LogID != receipt.LogID || ack.Sequence != receipt.Sequence || !bytes.Equal(ack.EntryHash, entryHash) {
			return releaseResultV2(V2ReleaseRejected, "acknowledgement_mismatch")
		}
	}
	// 7. Clock.
	now, err := readV2AuthoritativeTime(ctx, config.ClaimStore)
	if err != nil {
		return releaseResultV2(V2ReleasePending, "clock_unavailable")
	}
	if !validV2Timestamp(ack.Timestamp) || record.FinalizedAt > ack.Timestamp || ack.Timestamp > now {
		return releaseResultV2(V2ReleaseWithheld, "clock_regressed")
	}
	// 8. Deadlines.
	if ack.Timestamp >= committed.challengeExpiresAt || now >= committed.challengeExpiresAt {
		return releaseResultV2(V2ReleaseWithheld, "challenge_expired")
	}
	if receipt.Decision == "allow" && (committed.allowHorizon <= 0 || ack.Timestamp >= committed.allowHorizon || now >= committed.allowHorizon) {
		return releaseResultV2(V2ReleaseWithheld, "allow_horizon_passed")
	}
	// 9. Record.
	if record.Release == nil {
		err := recordV2ReleaseSafely(ctx, config.ClaimStore, V2ReleaseRecord{ClaimID: committed.claimID, EntryHash: bytes.Clone(entryHash), AckTimestamp: ack.Timestamp})
		switch {
		case errors.Is(err, ErrV2ReleaseStateMismatch):
			return releaseResultV2(V2ReleaseRejected, "release_state_mismatch")
		case err != nil:
			return releaseResultV2(V2ReleasePending, "claim_store_unavailable")
		}
	}
	// 10. Return.
	decision := &V2ReleasedDecision{
		ClaimID: committed.claimID, Decision: receipt.Decision, Reason: receipt.DecisionReason,
		IdentityStatus: receipt.IdentityStatus, GrantedScope: slices.Clone(receipt.GrantedScope), Receipt: receipt,
		ReleaseTime: ack.Timestamp, ChallengeExpiresAt: committed.challengeExpiresAt,
	}
	if receipt.Decision == "allow" {
		decision.AllowHorizon = committed.allowHorizon
	}
	return V2ReleaseResult{Status: V2ReleaseReleased, Decision: decision}
}

func verifyPublishedV2Receipt(wire []byte, config V2ReleaseConfig) (*VerificationReceiptV2, error) {
	receipt, err := DecodeVerificationReceiptV2(wire)
	if err != nil {
		return nil, err
	}
	if receipt.LogID != config.LogID {
		return nil, fmt.Errorf("v2 published receipt belongs to an unconfigured log")
	}
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		return nil, err
	}
	if err := verifyV2Statement(v2VerificationReceipt, body, receipt.Signature, config.VerifierPublicKey); err != nil {
		return nil, err
	}
	return receipt, nil
}

func loadV2TerminalClaimSafely(ctx context.Context, store V2ReleaseClaimStore, claimID string) (record V2TerminalClaimRecord, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			record, err = V2TerminalClaimRecord{}, fmt.Errorf("claim store panicked: %v", recovered)
		}
	}()
	return store.LoadV2TerminalClaim(ctx, claimID)
}

func recordV2ReleaseSafely(ctx context.Context, store V2ReleaseClaimStore, record V2ReleaseRecord) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("claim store panicked: %v", recovered)
		}
	}()
	return store.RecordV2Release(ctx, record)
}

func getV2AcknowledgementSafely(ctx context.Context, checkpoint V2ReceiptCheckpoint, logID string, sequence int64) (ack V2CheckpointAcknowledgement, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			ack, err = V2CheckpointAcknowledgement{}, fmt.Errorf("checkpoint panicked: %v", recovered)
		}
	}()
	return checkpoint.GetV2Acknowledgement(ctx, logID, sequence)
}

// V2EvaluationInterruptedResult builds the canonical terminal result object
// and receipt outbox body for indeterminate/evaluation_interrupted, as
// committed by lease-expiry recovery (SPEC-v2 §6.7, §7.5) when no stage
// progress is known. Every assessment is not_evaluated, granted_scope and
// status evidence are empty, and the body is bound to the claim's sealed
// bundle hash, issuers, verifier, agent and required scope. verifiedAt is the
// claim's authoritative claim time (T_claim).
func V2EvaluationInterruptedResult(claim V2ChallengeClaim, verifiedAt int64) (terminalResult, receiptBody []byte, err error) {
	if !validV2Timestamp(verifiedAt) {
		return nil, nil, v2Errorf(V2ErrConfigurationInvalid, "v2 recovery time is outside the timestamp domain")
	}
	issuers := append([]string{}, claim.IssuerIDs...)
	slices.Sort(issuers)
	receipt := &VerificationReceiptV2{
		Version: 2, VerifierID: claim.VerifierID, AgentID: claim.AgentID, BundleHash: claim.BundleHash, IssuerIDs: slices.Compact(issuers),
		Decision: "indeterminate", DecisionReason: "evaluation_interrupted", IdentityStatus: "authorization_unverified",
		TrustAssessment: "not_evaluated", StatusAssessment: "not_evaluated", ChallengeAssessment: "current",
		ContextAssessment: "not_evaluated", VerifiedAt: verifiedAt, RequiredScope: claim.RequiredScope,
		GrantedScope: []string{}, StatusEvidence: []StatusEvidenceEntryV2{},
	}
	receiptBody, err = VerificationReceiptV2Body(receipt)
	if err != nil {
		return nil, nil, v2Classify(V2ErrMalformed, err)
	}
	terminalResult, err = CanonicalJSON(map[string]string{"decision": "indeterminate", "decision_reason": "evaluation_interrupted", "identity_status": "authorization_unverified"})
	if err != nil {
		return nil, nil, err
	}
	return terminalResult, receiptBody, nil
}

// RecoverInterruptedClaimV2 commits the canonical evaluation_interrupted
// result for a claim whose evaluator lease expired and returns the committed
// (non-actionable) outcome for publication and release. claimedAt is the
// claim's authoritative claim time, which becomes verified_at. The store
// rejects recovery while the lease is live or after another terminal result.
func RecoverInterruptedClaimV2(ctx context.Context, store ClaimStoreV2, claim V2ChallengeClaim, claimedAt int64) (*CommittedV2Outcome, error) {
	if ctx == nil || store == nil || claim.ClaimID == "" {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 recovery requires a context, claim store and claim")
	}
	terminal, body, err := V2EvaluationInterruptedResult(claim, claimedAt)
	if err != nil {
		return nil, err
	}
	if _, err := recoverV2Safely(ctx, store, claim.ClaimID, terminal, body); err != nil {
		if V2ErrorClassOf(err) == V2ErrUnclassified {
			err = v2Classify(V2ErrClaimStoreUnavailable, err)
		}
		return nil, err
	}
	return newCommittedV2Outcome(claim, body, 0), nil
}

func recoverV2Safely(ctx context.Context, store ClaimStoreV2, claimID string, terminal, body []byte) (recovered bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			recovered, err = false, fmt.Errorf("claim store recovery panicked: %v", r)
		}
	}()
	return store.RecoverInterruptedV2Claim(ctx, claimID, terminal, body)
}
