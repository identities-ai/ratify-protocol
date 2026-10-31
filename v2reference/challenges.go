package v2reference

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ErrPersistFailed is returned by TestOnlyChallengeIssuanceStore when a
// scripted persistence failure is armed.
var ErrPersistFailed = errors.New("v2reference: scripted issuance persistence failure")

// PersistFault scripts the next PersistV2Challenge call.
type PersistFault int

const (
	// PersistOK stores the record normally.
	PersistOK PersistFault = iota
	// PersistFailBeforeCommit fails without storing anything.
	PersistFailBeforeCommit
	// PersistFailAfterCommit stores the record, then reports failure, as a
	// crash after the durable write but before the response would.
	PersistFailAfterCommit
)

// TestOnlyChallengeIssuanceStore is the in-memory REFERENCE implementation of
// ratify.V2ChallengeIssuanceStore. TEST AND CONFORMANCE USE ONLY: it is not
// durable, does not survive a restart, and does not span processes, so a
// verifier using it cannot claim durable issuance or release conformance.
type TestOnlyChallengeIssuanceStore struct {
	mu      sync.Mutex
	records map[string]ratify.ExpectedChallengeV2
	fault   PersistFault
}

// NewTestOnlyChallengeIssuanceStore returns an empty store.
func NewTestOnlyChallengeIssuanceStore() *TestOnlyChallengeIssuanceStore {
	return &TestOnlyChallengeIssuanceStore{records: map[string]ratify.ExpectedChallengeV2{}}
}

// FailNextPersist arms a fault for the next PersistV2Challenge call only.
func (s *TestOnlyChallengeIssuanceStore) FailNextPersist(fault PersistFault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = fault
}

// Len returns the number of stored records.
func (s *TestOnlyChallengeIssuanceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func issuanceKey(namespace string, epoch int64, digest []byte) string {
	return fmt.Sprintf("%d:%s|%d|%s", len(namespace), namespace, epoch, hex.EncodeToString(digest))
}

// PersistV2Challenge implements ratify.V2ChallengeIssuanceStore: insert only,
// never overwrite.
func (s *TestOnlyChallengeIssuanceStore) PersistV2Challenge(_ context.Context, record ratify.ExpectedChallengeV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fault := s.fault
	s.fault = PersistOK
	if fault == PersistFailBeforeCommit {
		return ErrPersistFailed
	}
	digest, err := ratify.ChallengeClaimDigestV2(record.Value)
	if err != nil {
		return err
	}
	key := issuanceKey(record.VerifierNamespace, record.ReplayEpoch, digest)
	if _, exists := s.records[key]; exists {
		return ratify.ErrV2ChallengeIssuanceConflict
	}
	s.records[key] = cloneExpected(record)
	if fault == PersistFailAfterCommit {
		return ErrPersistFailed
	}
	return nil
}

// LoadV2Challenge implements ratify.V2ChallengeIssuanceStore.
func (s *TestOnlyChallengeIssuanceStore) LoadV2Challenge(_ context.Context, namespace string, epoch int64, digest []byte) (ratify.ExpectedChallengeV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[issuanceKey(namespace, epoch, digest)]
	if !ok {
		return ratify.ExpectedChallengeV2{}, ratify.ErrV2ChallengeIssuanceNotFound
	}
	return cloneExpected(record), nil
}

func cloneExpected(e ratify.ExpectedChallengeV2) ratify.ExpectedChallengeV2 {
	e.Value = bytes.Clone(e.Value)
	e.ExpectedSessionContext = bytes.Clone(e.ExpectedSessionContext)
	if e.ExpectedAgentPublicKey != nil {
		key := ratify.HybridPublicKey{Ed25519: bytes.Clone(e.ExpectedAgentPublicKey.Ed25519), MLDSA65: bytes.Clone(e.ExpectedAgentPublicKey.MLDSA65)}
		e.ExpectedAgentPublicKey = &key
	}
	return e
}
