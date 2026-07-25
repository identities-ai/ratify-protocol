package ratify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ErrUnknownChallenge is returned by ChallengeStore implementations when a
// presented challenge cannot be consumed: it was never issued, has expired,
// has already been consumed, or was issued under a different session
// binding. The wording is deliberately uniform across those cases so a
// rejection does not reveal whether a challenge exists, and it matches the
// reference verifier's documented error text.
var ErrUnknownChallenge = errors.New("challenge was not issued by this verifier or has already been used")

// ErrChallengeStoreFull is returned by Issue when the store is at capacity.
var ErrChallengeStoreFull = errors.New("challenge store full — too many pending challenges")

// ChallengeStore tracks verifier-issued challenges so each is accepted at
// most once within its freshness window (§10). Verify consumes a challenge
// through this interface at the locked point in the algorithm: after the
// structural, chain, and challenge-signature checks pass, and before
// authorization evaluation — so a forged presentation cannot burn a
// legitimate challenge, and a cryptographically valid presentation spends
// its challenge even when authorization is subsequently denied.
//
// The bundled implementation is in-memory (NewMemoryChallengeStore).
// Deployments that need issuance state to survive restarts or span
// verifier replicas implement this interface over shared storage; Consume
// MUST remain atomic (compare-and-set) so two concurrent presentations of
// one challenge cannot both succeed.
type ChallengeStore interface {
	// Issue generates a fresh challenge bound to sessionContext (empty =
	// unbound) and valid for ttl. Returns the challenge and its expiry
	// (unix seconds).
	Issue(sessionContext []byte, ttl time.Duration) (challenge []byte, expiresAt int64, err error)

	// Validate reports whether challenge could be consumed right now —
	// issued, unexpired, unconsumed, and bound to sessionContext — WITHOUT
	// consuming it. Verify calls this before any signature work so an
	// unknown challenge is rejected cheaply and a forged presentation
	// cannot spend the record.
	Validate(challenge, sessionContext []byte, now time.Time) error

	// Consume atomically marks challenge used. Exactly one Consume of a
	// given challenge may ever succeed; all later calls (and calls with a
	// mismatched sessionContext, which do NOT consume the record) return
	// ErrUnknownChallenge or an equivalent error.
	Consume(challenge, sessionContext []byte, now time.Time) error
}

type challengeRecord struct {
	sessionContext []byte
	expiresAt      int64
	consumed       bool
}

// MemoryChallengeStore is the bundled in-memory ChallengeStore: mutex-
// guarded map with lazy expiry and a capacity cap. Suitable for a single
// verifier process; state does not survive restarts (an unconsumed
// challenge dies with the process, which fails closed).
type MemoryChallengeStore struct {
	mu      sync.Mutex
	records map[string]*challengeRecord // base64(challenge) -> record
	maxSize int
}

// NewMemoryChallengeStore returns an empty in-memory store holding at most
// maxSize pending challenges.
func NewMemoryChallengeStore(maxSize int) *MemoryChallengeStore {
	return &MemoryChallengeStore{
		records: make(map[string]*challengeRecord),
		maxSize: maxSize,
	}
}

// Issue implements ChallengeStore.
func (s *MemoryChallengeStore) Issue(sessionContext []byte, ttl time.Duration) ([]byte, int64, error) {
	challenge, err := GenerateChallenge()
	if err != nil {
		return nil, 0, err
	}
	now := time.Now()
	expiresAt := now.Add(ttl).Unix()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now.Unix())
	if len(s.records) >= s.maxSize {
		return nil, 0, ErrChallengeStoreFull
	}
	s.records[base64.StdEncoding.EncodeToString(challenge)] = &challengeRecord{
		sessionContext: bytes.Clone(sessionContext),
		expiresAt:      expiresAt,
	}
	return challenge, expiresAt, nil
}

// Validate implements ChallengeStore.
func (s *MemoryChallengeStore) Validate(challenge, sessionContext []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.lookupLocked(challenge, sessionContext, now.Unix())
	return err
}

// Consume implements ChallengeStore. The check and the consumed-flag flip
// happen under one lock, so of two concurrent presentations of the same
// challenge exactly one can succeed.
func (s *MemoryChallengeStore) Consume(challenge, sessionContext []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.lookupLocked(challenge, sessionContext, now.Unix())
	if err != nil {
		return err
	}
	rec.consumed = true
	return nil
}

// lookupLocked resolves a presentable record or returns ErrUnknownChallenge.
// A session-context mismatch fails WITHOUT touching the record, so a
// presentation under the wrong binding cannot burn the legitimate one.
func (s *MemoryChallengeStore) lookupLocked(challenge, sessionContext []byte, nowUnix int64) (*challengeRecord, error) {
	s.expireLocked(nowUnix)
	rec, ok := s.records[base64.StdEncoding.EncodeToString(challenge)]
	if !ok || rec.consumed {
		return nil, ErrUnknownChallenge
	}
	if !bytes.Equal(rec.sessionContext, sessionContext) {
		return nil, ErrUnknownChallenge
	}
	return rec, nil
}

func (s *MemoryChallengeStore) expireLocked(nowUnix int64) {
	for k, rec := range s.records {
		if rec.expiresAt < nowUnix {
			delete(s.records, k)
		}
	}
}
