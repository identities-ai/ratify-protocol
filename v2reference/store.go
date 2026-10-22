// Package v2reference is the in-memory REFERENCE implementation of the
// Ratify Protocol v2 Part B deployment interfaces: claim store with stream
// sequence, authoritative clock, receipt publisher, independent checkpoint,
// and anchored security-journal store.
//
// FOR TESTS AND CONFORMANCE SCENARIOS ONLY. Nothing here is durable, survives
// a restart, spans processes, or provides an independent failure domain. A
// deployment that uses it in production has no replay protection after a
// restart and no independent checkpoint, and must not release decisions on
// its authority. It exists so that every SDK can replay the shared
// lifecycle-scenarios.json vectors against identical semantics.
package v2reference

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ErrNotAcknowledged is returned by AcknowledgeV2Receipt for an entry that is
// not the next correctly linked entry of the log.
var ErrNotAcknowledged = errors.New("v2reference: checkpoint refused the acknowledgement")

type claimState string

const (
	stateEvaluating claimState = "evaluating"
	stateTerminal   claimState = "terminal"
)

type claimRecord struct {
	claim          ratify.V2ChallengeClaim
	ownerDigest    [32]byte
	leaseExpiresAt int64
	state          claimState
	terminal       []byte
	receiptBody    []byte
	allowHorizon   int64
	finalizedAt    int64
	release        *ratify.V2ReleaseRecord
}

type logEntry struct {
	claimID string
	body    []byte
	wire    []byte
	digest  []byte
	ack     *ratify.V2CheckpointAcknowledgement
}

// Store is the reference Part B store. All methods are safe for concurrent
// use; every operation runs under one mutex, which is what makes ClaimV2 and
// the stream-sequence advance a single atomic step.
type Store struct {
	mu             sync.Mutex
	now            int64
	leaseSeconds   int64
	claims         map[string]*claimRecord // keyed by claim ID
	streams        map[string]int64
	verifierKey    ratify.HybridPrivateKey
	verifierID     string
	logID          string
	log            []logEntry
	published      map[string]int
	ackWithheld    bool
	ownerTokenRand func([]byte) error
}

// NewStore returns a reference store whose authoritative clock starts at now,
// whose evaluator leases last leaseSeconds, and whose receipt log logID is
// signed by verifierKey.
func NewStore(now, leaseSeconds int64, logID string, verifierKey ratify.HybridPrivateKey) (*Store, error) {
	id := keyIDV2(verifierKey.Public())
	if leaseSeconds <= 0 || len(logID) != 32 {
		return nil, fmt.Errorf("v2reference: lease must be positive and log ID 32 hex characters")
	}
	return &Store{
		now: now, leaseSeconds: leaseSeconds, claims: map[string]*claimRecord{}, streams: map[string]int64{},
		verifierKey: verifierKey, verifierID: id, logID: logID, published: map[string]int{},
		ownerTokenRand: func(b []byte) error { _, err := rand.Read(b); return err },
	}, nil
}

// SetTime sets the authoritative clock. Tests may move it backward to
// exercise clock-regression handling.
func (s *Store) SetTime(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// SetAcknowledgementWithheld stops (or resumes) the reference outbox from
// submitting appended entries to the checkpoint, modelling a late
// independent checkpoint. Resuming acknowledges every pending entry in log
// order at the current clock.
func (s *Store) SetAcknowledgementWithheld(withheld bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ackWithheld = withheld
	if !withheld {
		s.acknowledgePendingLocked()
	}
}

func (s *Store) acknowledgePendingLocked() {
	for i := range s.log {
		if s.log[i].ack != nil {
			continue
		}
		s.log[i].ack = &ratify.V2CheckpointAcknowledgement{LogID: s.logID, Sequence: int64(i + 1), EntryHash: bytes.Clone(s.log[i].digest), Timestamp: s.now}
	}
}

// LogLength returns the number of appended receipts.
func (s *Store) LogLength() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.log)
}

// AuthoritativeTimeV2 implements ratify.V2AuthoritativeClock.
func (s *Store) AuthoritativeTimeV2(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now, nil
}

// keyIDV2 is SPEC-v2 §2.1: hex(SHA-256("ratify-key-id-v2" || 0x00 || ed25519 || ml_dsa_65)).
func keyIDV2(pub ratify.HybridPublicKey) string {
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2"))
	h.Write([]byte{0})
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	return hex.EncodeToString(h.Sum(nil))
}

func streamKey(claim ratify.V2ChallengeClaim) string {
	return fmt.Sprintf("%d:%s|%d:%s|%x", len(claim.Namespace), claim.Namespace, len(claim.AgentID), claim.AgentID, claim.StreamID)
}

func sameImmutableClaim(a, b ratify.V2ChallengeClaim) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(left, right)
}

// ClaimV2 implements the atomic claim: replay key check, authoritative
// freshness recheck, stream-sequence advance, and insertion, all under one
// lock. Order: (1) an existing claim with identical immutable fields is an
// exact retry (in_progress or terminal_replay, no owner token); a different
// proof or field set is ErrV2ClaimProofConflict; (2) the challenge must be
// current at the store clock; (3) the stream sequence must advance by one.
func (s *Store) ClaimV2(_ context.Context, claim ratify.V2ChallengeClaim) (ratify.V2ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if claim.ClaimID == "" {
		return ratify.V2ClaimResult{}, fmt.Errorf("v2reference: claim ID is required")
	}
	if existing, ok := s.claims[claim.ClaimID]; ok {
		if !sameImmutableClaim(existing.claim, claim) {
			return ratify.V2ClaimResult{}, ratify.ErrV2ClaimProofConflict
		}
		disposition := ratify.V2ClaimInProgress
		if existing.state == stateTerminal {
			disposition = ratify.V2ClaimTerminalReplay
		}
		return ratify.V2ClaimResult{Disposition: disposition, ClaimedAt: s.now}, nil
	}
	if !ratify.ChallengeClaimTimeCurrentV2(claim, s.now) {
		return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrChallengeNotFresh, Err: fmt.Errorf("v2reference: challenge is not current at the store clock")}
	}
	var key string
	if claim.StreamID != nil || claim.StreamSeq != nil {
		if claim.StreamID == nil || claim.StreamSeq == nil {
			return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrMalformed, Err: fmt.Errorf("v2reference: stream_id and stream_seq must appear together")}
		}
		key = streamKey(claim)
		last, hasLast := s.streams[key]
		if err := ratify.CheckV2StreamSequence(hasLast, last, *claim.StreamSeq); err != nil {
			return ratify.V2ClaimResult{}, err
		}
	}
	owner := make([]byte, 32)
	if err := s.ownerTokenRand(owner); err != nil {
		return ratify.V2ClaimResult{}, err
	}
	if key != "" {
		s.streams[key] = *claim.StreamSeq
	}
	s.claims[claim.ClaimID] = &claimRecord{claim: claim, ownerDigest: sha256.Sum256(owner), leaseExpiresAt: s.now + s.leaseSeconds, state: stateEvaluating}
	return ratify.V2ClaimResult{Disposition: ratify.V2ClaimCreated, ClaimedAt: s.now, OwnerToken: owner}, nil
}

// FinalizeV2Claim commits the evaluator's terminal result while its lease is
// live, recording T_final. An allow is rejected at or beyond its allow
// horizon or the challenge expiry (SPEC-v2 §7.5). An identical repeat
// returns (false, nil).
func (s *Store) FinalizeV2Claim(_ context.Context, claimID string, ownerToken, terminalResult, receiptBody []byte, allowValidUntil int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimNotFound, Err: fmt.Errorf("v2reference: unknown claim")}
	}
	digest := sha256.Sum256(ownerToken)
	if subtle.ConstantTimeCompare(digest[:], record.ownerDigest[:]) != 1 {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLost, Err: fmt.Errorf("v2reference: evaluator owner mismatch")}
	}
	if record.state == stateTerminal {
		if bytes.Equal(record.terminal, terminalResult) && bytes.Equal(record.receiptBody, receiptBody) {
			return false, nil
		}
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimAlreadyTerminal, Err: fmt.Errorf("v2reference: claim already has a different terminal result")}
	}
	if s.now >= record.leaseExpiresAt {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLost, Err: fmt.Errorf("v2reference: evaluator lease expired")}
	}
	if allowValidUntil > 0 && (s.now >= allowValidUntil || s.now >= record.claim.ExpiresAt) {
		return false, &ratify.V2Error{Class: ratify.V2ErrAllowHorizonPassed, Err: fmt.Errorf("v2reference: allow is at or beyond its horizon")}
	}
	record.state, record.terminal, record.receiptBody = stateTerminal, bytes.Clone(terminalResult), bytes.Clone(receiptBody)
	record.allowHorizon, record.finalizedAt = allowValidUntil, s.now
	return true, nil
}

// RecoverInterruptedV2Claim commits the canonical interrupted result after
// the lease expired. It refuses while the lease is live.
func (s *Store) RecoverInterruptedV2Claim(_ context.Context, claimID string, terminalResult, receiptBody []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimNotFound, Err: fmt.Errorf("v2reference: unknown claim")}
	}
	if record.state == stateTerminal {
		if bytes.Equal(record.terminal, terminalResult) && bytes.Equal(record.receiptBody, receiptBody) {
			return false, nil
		}
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimAlreadyTerminal, Err: fmt.Errorf("v2reference: claim already terminal")}
	}
	if s.now < record.leaseExpiresAt {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLive, Err: fmt.Errorf("v2reference: evaluator lease is still live")}
	}
	var fields map[string]string
	if json.Unmarshal(terminalResult, &fields) != nil || fields["decision"] != "indeterminate" || fields["decision_reason"] != "evaluation_interrupted" {
		return false, fmt.Errorf("v2reference: recovery may commit only indeterminate/evaluation_interrupted")
	}
	record.state, record.terminal, record.receiptBody = stateTerminal, bytes.Clone(terminalResult), bytes.Clone(receiptBody)
	record.allowHorizon, record.finalizedAt = 0, s.now
	return true, nil
}

// LoadV2TerminalClaim implements ratify.V2ReleaseClaimStore.
func (s *Store) LoadV2TerminalClaim(_ context.Context, claimID string) (ratify.V2TerminalClaimRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok {
		return ratify.V2TerminalClaimRecord{}, &ratify.V2Error{Class: ratify.V2ErrClaimNotFound, Err: fmt.Errorf("v2reference: unknown claim")}
	}
	out := ratify.V2TerminalClaimRecord{Terminal: record.state == stateTerminal, ChallengeExpiresAt: record.claim.ExpiresAt, AllowHorizon: record.allowHorizon, FinalizedAt: record.finalizedAt}
	if out.Terminal {
		out.ReceiptOutboxDigest = ratify.ReceiptOutboxDigestV2(record.receiptBody)
	}
	if record.release != nil {
		release := *record.release
		release.EntryHash = bytes.Clone(release.EntryHash)
		out.Release = &release
	}
	return out, nil
}

// RecordV2Release implements ratify.V2ReleaseClaimStore. An identical repeat
// is a no-op; a different existing record is ErrV2ReleaseStateMismatch.
func (s *Store) RecordV2Release(_ context.Context, release ratify.V2ReleaseRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[release.ClaimID]
	if !ok || record.state != stateTerminal {
		return ratify.ErrV2ReleaseStateMismatch
	}
	if record.release != nil {
		if bytes.Equal(record.release.EntryHash, release.EntryHash) && record.release.AckTimestamp == release.AckTimestamp {
			return nil
		}
		return ratify.ErrV2ReleaseStateMismatch
	}
	release.EntryHash = bytes.Clone(release.EntryHash)
	record.release = &release
	return nil
}

// PublishV2Receipt implements ratify.V2ReceiptPublisher: it signs and appends
// the committed outbox body for claimID at the next log position, or returns
// the receipt already appended for that claim. A body that differs from the
// committed outbox body is refused.
func (s *Store) PublishV2Receipt(_ context.Context, claimID string, receiptBody []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok || record.state != stateTerminal || !bytes.Equal(record.receiptBody, receiptBody) {
		return nil, fmt.Errorf("v2reference: no committed outbox body for this claim matches")
	}
	if index, done := s.published[claimID]; done {
		return bytes.Clone(s.log[index].wire), nil
	}
	head := ratify.ReceiptV2Head{LogID: s.logID, VerifierID: s.verifierID, Sequence: int64(len(s.log)), HeadHash: make([]byte, 48), AcceptedDigests: map[int64][]byte{}}
	for i, entry := range s.log {
		head.AcceptedDigests[int64(i+1)] = bytes.Clone(entry.digest)
	}
	if len(s.log) > 0 {
		head.HeadHash = bytes.Clone(s.log[len(s.log)-1].digest)
	}
	receipt, err := ratify.SignPreparedVerificationReceiptV2(receiptBody, head, s.verifierKey)
	if err != nil {
		return nil, err
	}
	wire, err := ratify.EncodeVerificationReceiptV2(receipt)
	if err != nil {
		return nil, err
	}
	digest, err := ratify.VerificationReceiptV2Digest(receipt)
	if err != nil {
		return nil, err
	}
	s.log = append(s.log, logEntry{claimID: claimID, body: bytes.Clone(receiptBody), wire: wire, digest: digest})
	s.published[claimID] = len(s.log) - 1
	if !s.ackWithheld {
		s.acknowledgePendingLocked()
	}
	return bytes.Clone(wire), nil
}

// AcknowledgeV2Receipt implements ratify.V2ReceiptCheckpoint: it accepts only
// the next entry of the log, linked by previousEntryHash, and returns the
// original acknowledgement for an identical retry.
func (s *Store) AcknowledgeV2Receipt(_ context.Context, logID string, sequence int64, previousEntryHash, entryHash []byte) (ratify.V2CheckpointAcknowledgement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if logID != s.logID || sequence < 1 || sequence > int64(len(s.log)) || !bytes.Equal(s.log[sequence-1].digest, entryHash) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	previous := make([]byte, 48)
	if sequence > 1 {
		previous = s.log[sequence-2].digest
		if s.log[sequence-2].ack == nil {
			return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
		}
	}
	if !bytes.Equal(previous, previousEntryHash) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	if s.log[sequence-1].ack == nil {
		s.log[sequence-1].ack = &ratify.V2CheckpointAcknowledgement{LogID: logID, Sequence: sequence, EntryHash: bytes.Clone(entryHash), Timestamp: s.now}
	}
	ack := *s.log[sequence-1].ack
	ack.EntryHash = bytes.Clone(ack.EntryHash)
	return ack, nil
}

// GetV2Acknowledgement implements ratify.V2ReceiptCheckpoint.
func (s *Store) GetV2Acknowledgement(_ context.Context, logID string, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if logID != s.logID || sequence < 1 || sequence > int64(len(s.log)) || s.log[sequence-1].ack == nil {
		return ratify.V2CheckpointAcknowledgement{}, ratify.ErrV2AcknowledgementNotFound
	}
	ack := *s.log[sequence-1].ack
	ack.EntryHash = bytes.Clone(ack.EntryHash)
	return ack, nil
}
