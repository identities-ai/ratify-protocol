package ratify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrUnknownChallenge is returned by ChallengeStore implementations when a
// presented challenge cannot be consumed: it was never issued, has expired,
// has already been consumed, or was issued under a different session
// binding. The wording is deliberately uniform across those cases so a
// rejection's public detail does not distinguish them. Verify normalizes
// EVERY store failure — including custom-store backend errors — to this
// text in the public result, so implementations cannot leak record state
// through error strings even accidentally.
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
	// Issue generates a fresh challenge bound to sessionContext (which
	// must be empty or exactly 32 bytes; empty = unbound) and valid for
	// ttl (which must be positive). Returns the challenge and its expiry
	// (unix seconds).
	Issue(sessionContext []byte, ttl time.Duration) (challenge []byte, expiresAt int64, err error)

	// Validate reports whether challenge could be consumed right now —
	// issued, unexpired, unconsumed, and bound to sessionContext — WITHOUT
	// consuming it. Verify calls this before any signature work so an
	// unknown challenge is rejected cheaply and a forged presentation
	// cannot spend the record.
	Validate(challenge, sessionContext []byte, now time.Time) error

	// Consume atomically removes the challenge's issuance record. Exactly
	// one Consume of a given challenge may ever succeed; all later calls
	// (and calls with a mismatched sessionContext, which do NOT remove the
	// record) return ErrUnknownChallenge or an equivalent error. Removing
	// the record on success keeps the store's capacity a count of PENDING
	// challenges — a consumed challenge frees its slot immediately.
	Consume(challenge, sessionContext []byte, now time.Time) error
}

type challengeRecord struct {
	sessionContext []byte
	expiresAt      int64
}

// MemoryChallengeStore is the bundled in-memory ChallengeStore: mutex-
// guarded map with lazy expiry and a capacity cap. Single-process only —
// state does not survive restarts (an unconsumed challenge dies with the
// process, which fails closed), and replicas sharing verification traffic
// would each accept the same challenge once. Deployments spanning
// processes or hosts need a ChallengeStore over shared storage whose
// Consume is atomic (e.g. a single-row DELETE ... RETURNING).
type MemoryChallengeStore struct {
	mu      sync.Mutex
	records map[string]*challengeRecord // base64(challenge) -> record
	maxSize int
}

// NewMemoryChallengeStore returns an empty in-memory store holding at most
// maxSize pending challenges. Panics if maxSize < 1 — a store that can
// never hold a challenge is a misconfiguration, not a policy (same
// convention as time.NewTicker). See the MemoryChallengeStore type docs
// for the single-process limitation.
func NewMemoryChallengeStore(maxSize int) *MemoryChallengeStore {
	if maxSize < 1 {
		panic(fmt.Sprintf("ratify: NewMemoryChallengeStore maxSize must be >= 1, got %d", maxSize))
	}
	return &MemoryChallengeStore{
		records: make(map[string]*challengeRecord),
		maxSize: maxSize,
	}
}

// Issue implements ChallengeStore.
func (s *MemoryChallengeStore) Issue(sessionContext []byte, ttl time.Duration) ([]byte, int64, error) {
	if len(sessionContext) != 0 && len(sessionContext) != 32 {
		return nil, 0, fmt.Errorf("session context must be empty or 32 bytes, got %d", len(sessionContext))
	}
	if ttl <= 0 {
		return nil, 0, fmt.Errorf("challenge ttl must be positive, got %v", ttl)
	}
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

// Consume implements ChallengeStore. The check and the record removal
// happen under one lock, so of two concurrent presentations of the same
// challenge exactly one can succeed. Removal frees the record's capacity
// slot immediately; a session-context mismatch leaves the record in place.
func (s *MemoryChallengeStore) Consume(challenge, sessionContext []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.lookupLocked(challenge, sessionContext, now.Unix())
	if err != nil {
		return err
	}
	delete(s.records, key)
	return nil
}

// lookupLocked resolves a presentable record's key or returns
// ErrUnknownChallenge. A session-context mismatch fails WITHOUT touching
// the record, so a presentation under the wrong binding cannot burn the
// legitimate one.
func (s *MemoryChallengeStore) lookupLocked(challenge, sessionContext []byte, nowUnix int64) (string, error) {
	s.expireLocked(nowUnix)
	key := base64.StdEncoding.EncodeToString(challenge)
	rec, ok := s.records[key]
	if !ok {
		return "", ErrUnknownChallenge
	}
	if !bytes.Equal(rec.sessionContext, sessionContext) {
		return "", ErrUnknownChallenge
	}
	return key, nil
}

func (s *MemoryChallengeStore) expireLocked(nowUnix int64) {
	for k, rec := range s.records {
		if rec.expiresAt < nowUnix {
			delete(s.records, k)
		}
	}
}
