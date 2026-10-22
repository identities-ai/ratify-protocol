package ratify

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Challenge issuance helper (SPEC-v2 Part B, §7.3).
//
// A live v2 verification needs an authenticated ExpectedChallengeV2. The
// helper below generates 32 unpredictable challenge bytes, reads the
// authoritative clock, and durably persists the complete issuance record
// BEFORE it returns the challenge. A challenge that is returned is therefore
// always retrievable for verification; a failure at any step returns no
// challenge, and a record persisted without being returned is never
// presented and simply expires.

// ErrV2ChallengeIssuanceConflict is returned by a V2ChallengeIssuanceStore
// when a record already exists for the same (namespace, replay_epoch,
// ChallengeClaimDigestV2). The store never overwrites an existing record.
var ErrV2ChallengeIssuanceConflict = errors.New("v2 challenge issuance record already exists")

// ErrV2ChallengeIssuanceNotFound is returned by LoadV2Challenge when no
// record exists, including after the record's retention ended.
var ErrV2ChallengeIssuanceNotFound = errors.New("v2 challenge issuance record not found")

// V2ChallengeIssuanceStore is the durable issuance record store. It is keyed
// by (verifier namespace, replay epoch, ChallengeClaimDigestV2(challenge)),
// the same key as the claim store, and retains each record at least until
// its expires_at plus the configured clock skew.
//
// PersistV2Challenge inserts the record atomically and returns only after the
// record is durable. An existing key returns ErrV2ChallengeIssuanceConflict
// and changes nothing. Any other error means the challenge must not be
// exposed; the record may or may not have committed.
//
// LoadV2Challenge returns a copy of the record, ErrV2ChallengeIssuanceNotFound,
// or another error when the store is unavailable.
type V2ChallengeIssuanceStore interface {
	PersistV2Challenge(ctx context.Context, record ExpectedChallengeV2) error
	LoadV2Challenge(ctx context.Context, namespace string, replayEpoch int64, claimDigest []byte) (ExpectedChallengeV2, error)
}

// V2ChallengeIssueRequest is the authenticated issuance context. Every
// expected binding comes from the issuer's own authenticated state, never
// from the party that will present the proof.
type V2ChallengeIssueRequest struct {
	VerifierNamespace string
	ReplayEpoch       int64
	VerifierID        string
	// LifetimeSeconds sets expires_at = issued_at + LifetimeSeconds. It is
	// 1..300, the challenge maximum-age bound of SPEC-v2 §2.5.
	LifetimeSeconds        int64
	ExpectedAgentID        string
	ExpectedAgentPublicKey *HybridPublicKey
	ExpectedReceiverID     string
	ExpectedSessionContext []byte
}

// V2ChallengeIssuer issues challenges. Clock and Store are required; Random
// defaults to crypto/rand and exists only so tests can script the bytes.
type V2ChallengeIssuer struct {
	Clock  V2AuthoritativeClock
	Store  V2ChallengeIssuanceStore
	Random io.Reader
}

// maxV2IssuanceAttempts bounds retries after a key conflict. A conflict with
// 32 random bytes indicates a broken random source, so the issuer fails
// rather than looping.
const maxV2IssuanceAttempts = 3

// IssueChallengeV2 generates and durably persists one challenge record and
// returns it. Order: validate the request (configuration_invalid), read the
// authoritative clock as issued_at, draw 32 random bytes, persist the
// complete record, and only then return it. A key conflict draws fresh bytes
// (at most three attempts in total) and never overwrites the existing record.
// On any error no challenge is returned.
func (issuer V2ChallengeIssuer) IssueChallengeV2(ctx context.Context, req V2ChallengeIssueRequest) (*ExpectedChallengeV2, error) {
	if ctx == nil || issuer.Clock == nil || issuer.Store == nil {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge issuer requires a context, authoritative clock and issuance store")
	}
	if err := validateV2ChallengeIssueRequest(req); err != nil {
		return nil, err
	}
	random := issuer.Random
	if random == nil {
		random = rand.Reader
	}
	issuedAt, err := readV2AuthoritativeTime(ctx, issuer.Clock)
	if err != nil {
		return nil, fmt.Errorf("v2 challenge issuance: authoritative clock: %w", err)
	}
	expiresAt, ok := checkedAddV2(issuedAt, req.LifetimeSeconds)
	if !ok || !validV2Timestamp(expiresAt) {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge expiry leaves the timestamp domain")
	}
	for attempt := 0; attempt < maxV2IssuanceAttempts; attempt++ {
		value := make([]byte, 32)
		if _, err := io.ReadFull(random, value); err != nil {
			return nil, fmt.Errorf("v2 challenge issuance: random source: %w", err)
		}
		record := ExpectedChallengeV2{
			Value: value, IssuedAt: issuedAt, ExpiresAt: expiresAt,
			VerifierNamespace: req.VerifierNamespace, ReplayEpoch: req.ReplayEpoch, VerifierID: req.VerifierID,
			ExpectedAgentID: req.ExpectedAgentID, ExpectedReceiverID: req.ExpectedReceiverID,
			ExpectedSessionContext: bytes.Clone(req.ExpectedSessionContext),
		}
		if req.ExpectedAgentPublicKey != nil {
			key := cloneHybridPublicKeyV2(*req.ExpectedAgentPublicKey)
			record.ExpectedAgentPublicKey = &key
		}
		err := persistV2ChallengeSafely(ctx, issuer.Store, cloneExpectedChallengeV2(record))
		if errors.Is(err, ErrV2ChallengeIssuanceConflict) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("v2 challenge issuance: the record was not durably persisted, so the challenge is not exposed: %w", err)
		}
		out := cloneExpectedChallengeV2(record)
		return &out, nil
	}
	return nil, fmt.Errorf("v2 challenge issuance: %d consecutive key conflicts; the random source is not trustworthy", maxV2IssuanceAttempts)
}

// LoadExpectedChallengeV2 retrieves the issuance record for presented
// challenge bytes by ChallengeClaimDigestV2. A missing record is
// expected_challenge_unavailable. The caller still runs the complete
// pre-claim checks of SPEC-v2 §6.2 against the returned record; a public API
// MUST collapse unknown, expired, consumed and wrong-binding challenges into
// one response.
func LoadExpectedChallengeV2(ctx context.Context, store V2ChallengeIssuanceStore, namespace string, replayEpoch int64, challenge []byte) (*ExpectedChallengeV2, error) {
	if ctx == nil || store == nil {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge lookup requires a context and issuance store")
	}
	digest, err := ChallengeClaimDigestV2(challenge)
	if err != nil {
		return nil, v2Errorf(V2ErrExpectedChallengeMissing, "v2 presented challenge is not 32 bytes")
	}
	record, err := loadV2ChallengeSafely(ctx, store, namespace, replayEpoch, digest)
	if err != nil {
		return nil, v2Classify(V2ErrExpectedChallengeMissing, err)
	}
	// The store is keyed by digest; the record must still name these exact
	// bytes and key, or it is not this challenge's record.
	if !bytes.Equal(record.Value, challenge) || record.VerifierNamespace != namespace || record.ReplayEpoch != replayEpoch {
		return nil, v2Errorf(V2ErrExpectedChallengeMissing, "v2 issuance store returned a record for another challenge")
	}
	out := cloneExpectedChallengeV2(record)
	return &out, nil
}

func validateV2ChallengeIssueRequest(req V2ChallengeIssueRequest) error {
	invalid := func(format string, args ...any) error { return v2Errorf(V2ErrConfigurationInvalid, format, args...) }
	if req.VerifierNamespace == "" || !utf8.ValidString(req.VerifierNamespace) {
		return invalid("v2 challenge issuance requires a non-empty UTF-8 verifier namespace")
	}
	if req.ReplayEpoch < 0 || req.ReplayEpoch > maxSafeInteger {
		return invalid("v2 challenge replay epoch must be 0..%d", maxSafeInteger)
	}
	if !validV2ID(req.VerifierID) {
		return invalid("v2 challenge verifier_id must be a v2 key ID")
	}
	if req.LifetimeSeconds < 1 || req.LifetimeSeconds > V2MaxChallengeAgeSeconds {
		return invalid("v2 challenge lifetime must be 1..%d seconds", V2MaxChallengeAgeSeconds)
	}
	if (req.ExpectedAgentID == "") != (req.ExpectedAgentPublicKey == nil) {
		return invalid("v2 expected agent ID and public key must be supplied together")
	}
	if req.ExpectedAgentPublicKey != nil {
		id, err := keyIDV2(*req.ExpectedAgentPublicKey)
		if err != nil || id != req.ExpectedAgentID {
			return invalid("v2 expected agent ID does not match its complete public key")
		}
	}
	if req.ExpectedReceiverID != "" && (!utf8.ValidString(req.ExpectedReceiverID) || len(req.ExpectedReceiverID) > MaxIdentifierLengthBytes) {
		return invalid("v2 expected receiver ID must be valid UTF-8 of at most %d bytes", MaxIdentifierLengthBytes)
	}
	if req.ExpectedSessionContext != nil && len(req.ExpectedSessionContext) != 32 {
		return invalid("v2 expected session context must be absent or exactly 32 bytes")
	}
	return nil
}

func cloneExpectedChallengeV2(e ExpectedChallengeV2) ExpectedChallengeV2 {
	e.Value = bytes.Clone(e.Value)
	e.ExpectedSessionContext = bytes.Clone(e.ExpectedSessionContext)
	if e.ExpectedAgentPublicKey != nil {
		key := cloneHybridPublicKeyV2(*e.ExpectedAgentPublicKey)
		e.ExpectedAgentPublicKey = &key
	}
	e.ContextPolicy = cloneV2ContextPolicy(e.ContextPolicy)
	return e
}

func persistV2ChallengeSafely(ctx context.Context, store V2ChallengeIssuanceStore, record ExpectedChallengeV2) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("issuance store panicked: %v", r)
		}
	}()
	return store.PersistV2Challenge(ctx, record)
}

func loadV2ChallengeSafely(ctx context.Context, store V2ChallengeIssuanceStore, namespace string, epoch int64, digest []byte) (record ExpectedChallengeV2, err error) {
	defer func() {
		if r := recover(); r != nil {
			record, err = ExpectedChallengeV2{}, fmt.Errorf("issuance store panicked: %v", r)
		}
	}()
	return store.LoadV2Challenge(ctx, namespace, epoch, bytes.Clone(digest))
}
