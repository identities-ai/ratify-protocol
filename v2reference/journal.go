package v2reference

import (
	"context"
	"sync"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// JournalStore is the reference anchored SecurityJournalV2 store. It persists
// the canonical snapshot bytes and an anchored head, and advances both under
// one lock by compare-and-swap. TEST/REFERENCE ONLY: an in-process anchor is
// not an independent, rollback-resistant head.
type JournalStore struct {
	mu       sync.Mutex
	head     ratify.SecurityJournalHeadV2
	snapshot []byte
}

// NewJournalStore returns a store anchored at the genesis journal.
func NewJournalStore() (*JournalStore, error) {
	genesis := ratify.EmptySecurityJournalV2()
	snapshot, err := ratify.ExportSecurityJournalSnapshotV2(genesis)
	if err != nil {
		return nil, err
	}
	return &JournalStore{head: ratify.SecurityJournalHeadV2{Generation: genesis.Generation, Digest: genesis.Digest}, snapshot: snapshot}, nil
}

// Load implements ratify.SecurityJournalStoreV2 by importing the stored
// snapshot against the anchored head.
func (s *JournalStore) Load(context.Context) (ratify.SecurityJournalV2, ratify.SecurityJournalHeadV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	journal, err := ratify.ImportSecurityJournalSnapshotV2(s.snapshot, s.head)
	if err != nil {
		return ratify.SecurityJournalV2{}, ratify.SecurityJournalHeadV2{}, err
	}
	return journal, s.head, nil
}

// CompareAndSwap implements ratify.SecurityJournalStoreV2.
func (s *JournalStore) CompareAndSwap(_ context.Context, expected ratify.SecurityJournalHeadV2, next ratify.SecurityJournalV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.head {
		return ratify.ErrSecurityJournalConflictV2
	}
	current, err := ratify.ImportSecurityJournalSnapshotV2(s.snapshot, s.head)
	if err != nil {
		return err
	}
	if err := ratify.ValidateSecurityJournalTransitionV2(current, next); err != nil {
		return err
	}
	snapshot, err := ratify.ExportSecurityJournalSnapshotV2(next)
	if err != nil {
		return err
	}
	s.snapshot = snapshot
	s.head = ratify.SecurityJournalHeadV2{Generation: next.Generation, Digest: next.Digest}
	return nil
}

// Head returns the anchored head.
func (s *JournalStore) Head() ratify.SecurityJournalHeadV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}
