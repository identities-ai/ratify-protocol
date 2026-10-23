// Package v2reference is the in-memory REFERENCE implementation of the
// Ratify Protocol v2 Part B deployment interfaces: claim store with stream
// sequence and evaluation progress, authoritative clock, receipt outbox and
// publisher, independent checkpoint, optional rate admission at
// finalization, and anchored security-journal store.
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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ErrNotAcknowledged is returned by AcknowledgeV2Receipt for an entry that is
// not the next correctly linked entry of the log.
var ErrNotAcknowledged = errors.New("v2reference: checkpoint refused the acknowledgement")

// ErrHeadOfLineBlocked is returned by PublishV2Receipt while an earlier
// outbox entry of the same receipt log is still unpublished (SPEC-v2 §7.6,
// §7.7): no entry publishes out of sequence.
var ErrHeadOfLineBlocked = errors.New("v2reference: an earlier receipt-log entry is still pending")

// ErrSignerUnavailable is returned by PublishV2Receipt while the reference
// signer is configured to fail; nothing is appended.
var ErrSignerUnavailable = errors.New("v2reference: receipt signer unavailable")

// ErrLogFrozen is returned by PublishV2Receipt after the log was abandoned.
var ErrLogFrozen = errors.New("v2reference: the receipt log is frozen after abandonment")

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
	claimedAt      int64
	finalizedAt    int64
	release        *ratify.V2ReleaseRecord
	progress       ratify.V2EvaluationProgress
	abandoned      bool
	outboxIndex    int
}

// outboxEntry is one receipt-log position, assigned at terminal commit. wire
// is nil until the entry is signed and appended.
type outboxEntry struct {
	claimID string
	body    []byte
	wire    []byte
	digest  []byte
	ack     *ratify.V2CheckpointAcknowledgement
}

type rateKey struct {
	issuerID, certID string
	windowS          int64
}

// Store is the reference Part B store. All methods are safe for concurrent
// use; every operation runs under one mutex, which is what makes ClaimV2 and
// the stream-sequence advance a single atomic step, and terminal commit and
// outbox sequence assignment another.
type Store struct {
	mu                 sync.Mutex
	now                int64
	highWater          int64
	leaseSeconds       int64
	claims             map[string]*claimRecord // keyed by claim ID
	streams            map[streamKeyV2]int64
	verifierKey        ratify.HybridPrivateKey
	verifierID         string
	logID              string
	outbox             []outboxEntry
	ackWithheld        bool
	logFrozen          bool
	checkpointFrozen   bool
	signerFailure      bool
	rateAtFinalization bool
	rateCommits        map[rateKey][]int64
	ownerTokenRand     func([]byte) error
	// anchor, when set by a single-device offline profile primary, anchors
	// every durable security-state change before it takes effect (SPEC-v2
	// §7.13). It is never copied by Clone.
	anchor func(previous, next storeStateTestOnly) error
}

// NewStore returns a reference store whose authoritative clock starts at now,
// whose evaluator leases last leaseSeconds, and whose receipt log logID is
// signed by verifierKey.
func NewStore(now, leaseSeconds int64, logID string, verifierKey ratify.HybridPrivateKey) (*Store, error) {
	id, err := ratify.KeyIDV2(verifierKey.Public())
	if err != nil {
		return nil, err
	}
	if leaseSeconds <= 0 || len(logID) != 32 {
		return nil, fmt.Errorf("v2reference: lease must be positive and log ID 32 hex characters")
	}
	return &Store{
		now: now, highWater: now, leaseSeconds: leaseSeconds, claims: map[string]*claimRecord{}, streams: map[streamKeyV2]int64{},
		verifierKey: verifierKey, verifierID: id, logID: logID, rateCommits: map[rateKey][]int64{},
		ownerTokenRand: func(b []byte) error { _, err := rand.Read(b); return err },
	}, nil
}

// Clone returns an independent copy of the store's complete state, modelling
// a restore that exactly equals the anchored state (no epoch change needed).
func (s *Store) Clone() *Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cloneLocked()
}

func (s *Store) cloneLocked() *Store {
	out := &Store{
		now: s.now, highWater: s.highWater, leaseSeconds: s.leaseSeconds, claims: map[string]*claimRecord{}, streams: maps.Clone(s.streams),
		verifierKey: s.verifierKey, verifierID: s.verifierID, logID: s.logID, ackWithheld: s.ackWithheld, logFrozen: s.logFrozen, checkpointFrozen: s.checkpointFrozen,
		signerFailure: s.signerFailure, rateAtFinalization: s.rateAtFinalization, rateCommits: map[rateKey][]int64{}, ownerTokenRand: s.ownerTokenRand,
	}
	for id, record := range s.claims {
		copied := *record
		copied.claim = cloneClaim(record.claim)
		copied.terminal, copied.receiptBody = bytes.Clone(record.terminal), bytes.Clone(record.receiptBody)
		copied.progress = cloneProgress(record.progress)
		if record.release != nil {
			release := *record.release
			release.EntryHash = bytes.Clone(release.EntryHash)
			copied.release = &release
		}
		out.claims[id] = &copied
	}
	for _, entry := range s.outbox {
		copied := outboxEntry{claimID: entry.claimID, body: bytes.Clone(entry.body), wire: bytes.Clone(entry.wire), digest: bytes.Clone(entry.digest)}
		if entry.ack != nil {
			ack := *entry.ack
			ack.EntryHash = bytes.Clone(ack.EntryHash)
			copied.ack = &ack
		}
		out.outbox = append(out.outbox, copied)
	}
	for key, times := range s.rateCommits {
		out.rateCommits[key] = slices.Clone(times)
	}
	return out
}

// changeLocked applies mutate as one durable security-state change. Without
// an anchor it only applies it. With one, it digests the state before and
// after, and anchors the new state before the change can take effect; if
// anchoring fails, the change is undone and claim_store_unavailable is
// returned. Clock readings are not durable security state and are kept.
func (s *Store) changeLocked(mutate func()) error {
	if s.anchor == nil {
		mutate()
		return nil
	}
	before := s.cloneLocked()
	previous, err := s.stateDigestsLocked()
	if err == nil {
		mutate()
		var next storeStateTestOnly
		if next, err = s.stateDigestsLocked(); err == nil {
			err = s.anchor(previous, next)
		}
	}
	if err != nil {
		s.claims, s.streams, s.outbox, s.rateCommits, s.logFrozen = before.claims, before.streams, before.outbox, before.rateCommits, before.logFrozen
		return &ratify.V2Error{Class: ratify.V2ErrClaimStoreUnavailable, Err: fmt.Errorf("v2reference: durable state change was not anchored: %w", err)}
	}
	return nil
}

// SetTime sets the authoritative clock. Tests may move it backward to
// exercise clock-regression handling: the store remembers the greatest
// reading it has returned, and every operation that reads the clock fails
// closed while the clock is below that high-water mark (SPEC-v2 §7.2).
func (s *Store) SetTime(now int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Now returns the store's current clock setting without taking an
// authoritative reading (for test harnesses that derive request times).
func (s *Store) Now() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now
}

// SetSignerFailure makes the reference receipt signer fail (or recover).
// A failed publication appends nothing; a retry signs the same sealed body.
func (s *Store) SetSignerFailure(failing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signerFailure = failing
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

// acknowledgePendingLocked submits every appended, unacknowledged entry to
// the reference checkpoint in log order. Acknowledgements are timestamped by
// one authoritative reading (SPEC-v2 §7.2), which advances the high-water
// mark; while the clock is regressed nothing is acknowledged.
func (s *Store) acknowledgePendingLocked() {
	if s.checkpointFrozen {
		return
	}
	var now int64
	read := false
	for i := range s.outbox {
		if s.outbox[i].wire == nil {
			return
		}
		if s.outbox[i].ack != nil {
			continue
		}
		if !read {
			var err error
			if now, err = s.readClockLocked(); err != nil {
				return
			}
			read = true
		}
		s.outbox[i].ack = &ratify.V2CheckpointAcknowledgement{LogID: s.logID, Sequence: int64(i + 1), EntryHash: bytes.Clone(s.outbox[i].digest), Timestamp: now}
	}
}

// LogLength returns the number of appended (signed) receipts.
func (s *Store) LogLength() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for n < len(s.outbox) && s.outbox[n].wire != nil {
		n++
	}
	return n
}

// readClockLocked is one authoritative reading. A reading below the
// greatest reading already returned is a clock regression.
func (s *Store) readClockLocked() (int64, error) {
	if s.now < s.highWater {
		return 0, &ratify.V2Error{Class: ratify.V2ErrClockRegressed, Err: fmt.Errorf("v2reference: authoritative clock %d is below its high-water mark %d", s.now, s.highWater)}
	}
	s.highWater = s.now
	return s.now, nil
}

// AuthoritativeTimeV2 implements ratify.V2AuthoritativeClock. A regressed
// clock fails with clock_regressed.
func (s *Store) AuthoritativeTimeV2(context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readClockLocked()
}

// streamKeyV2 is the durable stream-state key (namespace, agent_id,
// stream_id) of SPEC-v2 §7.4; streamID holds the raw stream ID bytes.
type streamKeyV2 struct {
	namespace, agentID, streamID string
}

func streamKey(claim ratify.V2ChallengeClaim) streamKeyV2 {
	return streamKeyV2{namespace: claim.Namespace, agentID: claim.AgentID, streamID: string(claim.StreamID)}
}

func sameImmutableClaim(a, b ratify.V2ChallengeClaim) bool {
	left, err1 := json.Marshal(a)
	right, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(left, right)
}

// ClaimV2 implements the atomic claim: authoritative clock reading (a
// regressed clock creates nothing and fails with claim_store_unavailable),
// replay key check, authoritative freshness recheck, stream-sequence
// advance, and insertion, all under one lock. Order: (1) an existing claim
// with identical immutable fields is an exact retry (in_progress or
// terminal_replay, no owner token; receipt_abandoned if its receipt was
// abandoned); a different proof or field set is ErrV2ClaimProofConflict;
// (2) the challenge must be current at the store clock; (3) the stream
// sequence must advance by one.
func (s *Store) ClaimV2(_ context.Context, claim ratify.V2ChallengeClaim) (ratify.V2ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if claim.ClaimID == "" {
		return ratify.V2ClaimResult{}, fmt.Errorf("v2reference: claim ID is required")
	}
	now, err := s.readClockLocked()
	if err != nil {
		return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrClaimStoreUnavailable, Err: err}
	}
	if existing, ok := s.claims[claim.ClaimID]; ok {
		if !sameImmutableClaim(existing.claim, claim) {
			return ratify.V2ClaimResult{}, ratify.ErrV2ClaimProofConflict
		}
		if existing.abandoned {
			return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrReceiptAbandoned, Err: fmt.Errorf("v2reference: the receipt for this claim was abandoned; a fresh challenge is required")}
		}
		disposition := ratify.V2ClaimInProgress
		if existing.state == stateTerminal {
			disposition = ratify.V2ClaimTerminalReplay
		}
		return ratify.V2ClaimResult{Disposition: disposition, ClaimedAt: existing.claimedAt}, nil
	}
	if !ratify.ChallengeClaimTimeCurrentV2(claim, now) {
		return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrChallengeNotFresh, Err: fmt.Errorf("v2reference: challenge is not current at the store clock")}
	}
	var key streamKeyV2
	bound := false
	if claim.StreamID != nil || claim.StreamSeq != nil {
		if claim.StreamID == nil || claim.StreamSeq == nil {
			return ratify.V2ClaimResult{}, &ratify.V2Error{Class: ratify.V2ErrMalformed, Err: fmt.Errorf("v2reference: stream_id and stream_seq must appear together")}
		}
		key, bound = streamKey(claim), true
		last, hasLast := s.streams[key]
		if err := ratify.CheckV2StreamSequence(hasLast, last, *claim.StreamSeq); err != nil {
			return ratify.V2ClaimResult{}, err
		}
	}
	owner := make([]byte, 32)
	if err := s.ownerTokenRand(owner); err != nil {
		return ratify.V2ClaimResult{}, err
	}
	if err := s.changeLocked(func() {
		if bound {
			s.streams[key] = *claim.StreamSeq
		}
		s.claims[claim.ClaimID] = &claimRecord{claim: cloneClaim(claim), ownerDigest: sha256.Sum256(owner), leaseExpiresAt: now + s.leaseSeconds, state: stateEvaluating,
			claimedAt: now, progress: ratify.InitialV2EvaluationProgress(), outboxIndex: -1}
	}); err != nil {
		return ratify.V2ClaimResult{}, err
	}
	return ratify.V2ClaimResult{Disposition: ratify.V2ClaimCreated, ClaimedAt: now, OwnerToken: owner}, nil
}

// ownerLocked checks the evaluator capability of a live, evaluating claim.
func (s *Store) ownerLocked(claimID string, ownerToken []byte) (*claimRecord, int64, error) {
	record, ok := s.claims[claimID]
	if !ok {
		return nil, 0, &ratify.V2Error{Class: ratify.V2ErrClaimNotFound, Err: fmt.Errorf("v2reference: unknown claim")}
	}
	digest := sha256.Sum256(ownerToken)
	if subtle.ConstantTimeCompare(digest[:], record.ownerDigest[:]) != 1 {
		return nil, 0, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLost, Err: fmt.Errorf("v2reference: evaluator owner mismatch")}
	}
	if record.state == stateTerminal {
		return record, 0, &ratify.V2Error{Class: ratify.V2ErrClaimAlreadyTerminal, Err: fmt.Errorf("v2reference: claim already terminal")}
	}
	now, err := s.readClockLocked()
	if err != nil {
		return nil, 0, err
	}
	if now < record.claimedAt {
		return nil, 0, &ratify.V2Error{Class: ratify.V2ErrClockRegressed, Err: fmt.Errorf("v2reference: clock %d is before T_claim %d", now, record.claimedAt)}
	}
	if now >= record.leaseExpiresAt {
		return nil, 0, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLost, Err: fmt.Errorf("v2reference: evaluator lease expired")}
	}
	return record, now, nil
}

// commitTerminalLocked makes a terminal result immutable and assigns its
// receipt-log position in the same critical section (single-store terminal
// commit point, SPEC-v2 §7.7).
func (s *Store) commitTerminalLocked(record *claimRecord, terminal, body []byte, allowHorizon, finalAt int64) {
	record.state, record.terminal, record.receiptBody = stateTerminal, bytes.Clone(terminal), bytes.Clone(body)
	record.allowHorizon, record.finalizedAt = allowHorizon, finalAt
	record.outboxIndex = len(s.outbox)
	s.outbox = append(s.outbox, outboxEntry{claimID: record.claim.ClaimID, body: bytes.Clone(body)})
}

// FinalizeV2Claim commits the evaluator's terminal result while its lease is
// live, reading T_final inside the same critical section and recording it.
// The receipt body must bind the sealed claim (ratify.ValidateV2FinalizationPayload:
// malformed or configuration_invalid otherwise, committing nothing). A
// regressed clock (below the high-water mark or below T_claim) fails with
// clock_regressed; an allow is rejected at or beyond its allow horizon or the
// challenge expiry (SPEC-v2 §7.2, §7.5). With rate admission at finalization
// enabled, an allow is admitted against the sealed rate batch here and fails
// with the exact ErrV2RateLimitExceeded, committing nothing, when a counter
// is exhausted. An identical repeat returns (false, nil).
func (s *Store) FinalizeV2Claim(_ context.Context, claimID string, ownerToken, terminalResult, receiptBody []byte, allowValidUntil int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, finalAt, err := s.ownerLocked(claimID, ownerToken)
	if err != nil {
		if record != nil && record.state == stateTerminal && bytes.Equal(record.terminal, terminalResult) && bytes.Equal(record.receiptBody, receiptBody) {
			return false, nil
		}
		return false, err
	}
	if err := ratify.ValidateV2FinalizationPayload(record.claim, terminalResult, receiptBody); err != nil {
		return false, err
	}
	if allowValidUntil > 0 && (finalAt >= allowValidUntil || finalAt >= record.claim.ExpiresAt) {
		return false, &ratify.V2Error{Class: ratify.V2ErrAllowHorizonPassed, Err: fmt.Errorf("v2reference: allow is at or beyond its horizon")}
	}
	admitRate := allowValidUntil > 0 && s.rateAtFinalization && len(record.claim.RateBatch) != 0
	if admitRate {
		for _, item := range record.claim.RateBatch {
			key := rateKey{item.IssuerID, item.CertID, item.WindowS}
			active := int64(0)
			for _, at := range s.rateCommits[key] {
				if at > finalAt-item.WindowS {
					active++
				}
			}
			if active >= item.Limit {
				return false, ratify.ErrV2RateLimitExceeded
			}
		}
	}
	if err := s.changeLocked(func() {
		if admitRate {
			for _, item := range record.claim.RateBatch {
				key := rateKey{item.IssuerID, item.CertID, item.WindowS}
				s.rateCommits[key] = append(s.rateCommits[key], finalAt)
			}
		}
		s.commitTerminalLocked(record, terminalResult, receiptBody, allowValidUntil, finalAt)
	}); err != nil {
		return false, err
	}
	return true, nil
}

// RecordV2EvaluationProgress implements ratify.ClaimStoreV2: the owner's
// progress is stored only while the claim is evaluating and its lease live.
func (s *Store) RecordV2EvaluationProgress(_ context.Context, claimID string, ownerToken []byte, progress ratify.V2EvaluationProgress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, _, err := s.ownerLocked(claimID, ownerToken)
	if err != nil {
		return err
	}
	if err := ratify.ValidateV2EvaluationProgress(progress); err != nil {
		return &ratify.V2Error{Class: ratify.V2ErrMalformed, Err: err}
	}
	return s.changeLocked(func() { record.progress = cloneProgress(progress) })
}

// LoadV2InterruptedClaim implements ratify.ClaimStoreV2. It refuses while
// the lease is live, so the returned progress is final.
func (s *Store) LoadV2InterruptedClaim(_ context.Context, claimID string) (ratify.V2InterruptedClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok {
		return ratify.V2InterruptedClaim{}, &ratify.V2Error{Class: ratify.V2ErrClaimNotFound, Err: fmt.Errorf("v2reference: unknown claim")}
	}
	now, err := s.readClockLocked()
	if err != nil {
		return ratify.V2InterruptedClaim{}, err
	}
	if record.state == stateEvaluating && now < record.leaseExpiresAt {
		return ratify.V2InterruptedClaim{}, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLive, Err: fmt.Errorf("v2reference: evaluator lease is still live")}
	}
	// A terminal claim is returned too: RecoverInterruptedV2Claim then
	// accepts only the identical interrupted result (idempotent recovery).
	return ratify.V2InterruptedClaim{Claim: cloneClaim(record.claim), ClaimedAt: record.claimedAt, Progress: cloneProgress(record.progress)}, nil
}

func cloneProgress(p ratify.V2EvaluationProgress) ratify.V2EvaluationProgress {
	out := p
	if p.ContextPolicyDigest != nil {
		digest := *p.ContextPolicyDigest
		out.ContextPolicyDigest = &digest
	}
	out.StatusEvidence = append([]ratify.StatusEvidenceEntryV2{}, p.StatusEvidence...)
	return out
}

func cloneClaim(claim ratify.V2ChallengeClaim) ratify.V2ChallengeClaim {
	claim.IssuerIDs = slices.Clone(claim.IssuerIDs)
	claim.RateBatch = slices.Clone(claim.RateBatch)
	claim.StreamID = bytes.Clone(claim.StreamID)
	if claim.StreamSeq != nil {
		seq := *claim.StreamSeq
		claim.StreamSeq = &seq
	}
	claim.ConstraintEvaluators = slices.Clone(claim.ConstraintEvaluators)
	return claim
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
	now, err := s.readClockLocked()
	if err != nil {
		return false, err
	}
	if now < record.leaseExpiresAt {
		return false, &ratify.V2Error{Class: ratify.V2ErrClaimLeaseLive, Err: fmt.Errorf("v2reference: evaluator lease is still live")}
	}
	var fields map[string]string
	if json.Unmarshal(terminalResult, &fields) != nil || fields["decision"] != "indeterminate" || fields["decision_reason"] != "evaluation_interrupted" {
		return false, fmt.Errorf("v2reference: recovery may commit only indeterminate/evaluation_interrupted")
	}
	if err := s.changeLocked(func() { s.commitTerminalLocked(record, terminalResult, receiptBody, 0, now) }); err != nil {
		return false, err
	}
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
	out := ratify.V2TerminalClaimRecord{Terminal: record.state == stateTerminal, ChallengeExpiresAt: record.claim.ExpiresAt, AllowHorizon: record.allowHorizon, FinalizedAt: record.finalizedAt, ReceiptAbandoned: record.abandoned}
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

// RecordV2Release implements ratify.V2ReleaseClaimStore. It records a
// release or a withheld result (SPEC-v2 §6.9): the first record for a claim
// wins, an identical repeat is a no-op, and any different record is
// ErrV2ReleaseStateMismatch. A new record is a durable security-state change,
// anchored like any other.
func (s *Store) RecordV2Release(_ context.Context, release ratify.V2ReleaseRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ratify.ValidV2ReleaseRecordOutcome(release.Outcome, release.Reason) {
		return &ratify.V2Error{Class: ratify.V2ErrConfigurationInvalid, Err: fmt.Errorf("v2reference: invalid release record outcome %q reason %q", release.Outcome, release.Reason)}
	}
	record, ok := s.claims[release.ClaimID]
	if !ok || record.state != stateTerminal {
		return ratify.ErrV2ReleaseStateMismatch
	}
	if record.release != nil {
		if bytes.Equal(record.release.EntryHash, release.EntryHash) && record.release.AckTimestamp == release.AckTimestamp &&
			record.release.Outcome == release.Outcome && record.release.Reason == release.Reason {
			return nil
		}
		return ratify.ErrV2ReleaseStateMismatch
	}
	release.EntryHash = bytes.Clone(release.EntryHash)
	return s.changeLocked(func() { record.release = &release })
}

// PlantReleaseTestOnly writes a release record for claimID directly into
// primary storage, bypassing release and anchoring: the record names the
// claim's appended receipt entry and ackTimestamp. It models an attacker who
// can write the primary's storage.
func (s *Store) PlantReleaseTestOnly(claimID string, ackTimestamp int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, ok := s.claims[claimID]; ok && record.outboxIndex >= 0 && s.outbox[record.outboxIndex].wire != nil {
		record.release = &ratify.V2ReleaseRecord{ClaimID: claimID, EntryHash: bytes.Clone(s.outbox[record.outboxIndex].digest), AckTimestamp: ackTimestamp, Outcome: ratify.V2ReleaseReleased}
	}
}

// PublishV2Receipt implements ratify.V2ReceiptPublisher: it signs and appends
// the committed outbox body for claimID at the log position assigned at
// terminal commit, or returns the receipt already appended for that claim. A
// body that differs from the committed outbox body is refused, an earlier
// unpublished entry blocks it (ErrHeadOfLineBlocked), and a failing signer or
// frozen log appends nothing.
func (s *Store) PublishV2Receipt(_ context.Context, claimID string, receiptBody []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.claims[claimID]
	if !ok || record.state != stateTerminal || !bytes.Equal(record.receiptBody, receiptBody) {
		return nil, fmt.Errorf("v2reference: no committed outbox body for this claim matches")
	}
	index := record.outboxIndex
	if s.outbox[index].wire != nil {
		return bytes.Clone(s.outbox[index].wire), nil
	}
	switch {
	case s.logFrozen:
		return nil, ErrLogFrozen
	case index > 0 && s.outbox[index-1].wire == nil:
		return nil, ErrHeadOfLineBlocked
	case s.signerFailure:
		return nil, ErrSignerUnavailable
	}
	head := ratify.ReceiptV2Head{LogID: s.logID, VerifierID: s.verifierID, Sequence: int64(index), HeadHash: make([]byte, 48), AcceptedDigests: map[int64][]byte{}}
	for i := 0; i < index; i++ {
		head.AcceptedDigests[int64(i+1)] = bytes.Clone(s.outbox[i].digest)
	}
	if index > 0 {
		head.HeadHash = bytes.Clone(s.outbox[index-1].digest)
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
	if err := s.changeLocked(func() { s.outbox[index].wire, s.outbox[index].digest = wire, digest }); err != nil {
		return nil, err
	}
	if !s.ackWithheld {
		s.acknowledgePendingLocked()
	}
	return bytes.Clone(wire), nil
}

// AcknowledgeV2Receipt implements ratify.V2ReceiptCheckpoint: it accepts only
// the next appended entry of the log, linked by previousEntryHash, and
// returns the original acknowledgement for an identical retry. A different
// entry hash at an acknowledged sequence is a fork (SPEC-v2 §7.8): it is
// refused and freezes the log, after which the checkpoint acknowledges
// nothing further for it, neither here nor from the publisher's submissions.
// Identical retries of acknowledgements made before the fork still return
// the original acknowledgement.
func (s *Store) AcknowledgeV2Receipt(_ context.Context, logID string, sequence int64, previousEntryHash, entryHash []byte) (ratify.V2CheckpointAcknowledgement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if logID != s.logID || sequence < 1 || sequence > int64(len(s.outbox)) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	if acked := s.outbox[sequence-1].ack; acked != nil && !bytes.Equal(acked.EntryHash, entryHash) {
		s.checkpointFrozen = true
		return ratify.V2CheckpointAcknowledgement{}, fmt.Errorf("%w: a different entry hash at acknowledged sequence %d is a fork; the log is frozen", ErrNotAcknowledged, sequence)
	}
	if s.checkpointFrozen && s.outbox[sequence-1].ack == nil {
		return ratify.V2CheckpointAcknowledgement{}, fmt.Errorf("%w: the log is frozen after a fork", ErrNotAcknowledged)
	}
	if s.outbox[sequence-1].wire == nil || !bytes.Equal(s.outbox[sequence-1].digest, entryHash) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	previous := make([]byte, 48)
	if sequence > 1 {
		previous = s.outbox[sequence-2].digest
		if s.outbox[sequence-2].ack == nil {
			return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
		}
	}
	if !bytes.Equal(previous, previousEntryHash) {
		return ratify.V2CheckpointAcknowledgement{}, ErrNotAcknowledged
	}
	if s.outbox[sequence-1].ack == nil {
		now, err := s.readClockLocked()
		if err != nil {
			return ratify.V2CheckpointAcknowledgement{}, err
		}
		s.outbox[sequence-1].ack = &ratify.V2CheckpointAcknowledgement{LogID: logID, Sequence: sequence, EntryHash: bytes.Clone(entryHash), Timestamp: now}
	}
	ack := *s.outbox[sequence-1].ack
	ack.EntryHash = bytes.Clone(ack.EntryHash)
	return ack, nil
}

// GetV2Acknowledgement implements ratify.V2ReceiptCheckpoint.
func (s *Store) GetV2Acknowledgement(_ context.Context, logID string, sequence int64) (ratify.V2CheckpointAcknowledgement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if logID != s.logID || sequence < 1 || sequence > int64(len(s.outbox)) || s.outbox[sequence-1].ack == nil {
		return ratify.V2CheckpointAcknowledgement{}, ratify.ErrV2AcknowledgementNotFound
	}
	ack := *s.outbox[sequence-1].ack
	ack.EntryHash = bytes.Clone(ack.EntryHash)
	return ack, nil
}

// AbandonPendingReceipts is the reference receipt-abandonment procedure of
// SPEC-v2 §7.7: it freezes the receipt log and marks every claim whose
// committed outbox entry was not yet appended as receipt_abandoned. It
// returns the abandoned claim IDs in log order. Release of an abandoned claim
// returns withheld/receipt_abandoned, and an exact retry of an abandoned
// claim fails before claim with receipt_abandoned.
func (s *Store) AbandonPendingReceipts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	abandoned := []string{}
	if s.changeLocked(func() {
		s.logFrozen = true
		for _, entry := range s.outbox {
			if entry.wire == nil {
				s.claims[entry.claimID].abandoned = true
				abandoned = append(abandoned, entry.claimID)
			}
		}
	}) != nil {
		return []string{}
	}
	return abandoned
}

// RateAtFinalizationStore is the reference store with max_rate admission
// moved into the finalization compare-and-set (ratify.V2RateAtFinalizationStore).
// Use it as both the claim store and the rate store.
type RateAtFinalizationStore struct{ *Store }

// WithRateAtFinalization enables rate admission at finalization on s and
// returns the view that advertises it.
func (s *Store) WithRateAtFinalization() *RateAtFinalizationStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rateAtFinalization = true
	return &RateAtFinalizationStore{s}
}

// AdmitsV2RateAtFinalization implements ratify.V2RateAtFinalizationStore.
func (*RateAtFinalizationStore) AdmitsV2RateAtFinalization() {}

// ReserveV2RateBatch exists only to satisfy ratify.V2RateReservationStore.
// The verifier never calls it for a store that admits at finalization, and
// it always fails (SPEC-v2 §7.1, §7.6).
func (*RateAtFinalizationStore) ReserveV2RateBatch(context.Context, string, []byte, string, []ratify.V2RateReservation) error {
	return fmt.Errorf("v2reference: provisional rate reservation is not used with admission at finalization")
}
