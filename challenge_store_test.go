package ratify_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

const wantUnknown = "challenge was not issued by this verifier or has already been used"

// ----- Store semantics -----

func TestChallengeStoreIssueConsume(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	challenge, expiresAt, err := store.Issue(nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(challenge) != 32 {
		t.Fatalf("challenge length = %d, want 32", len(challenge))
	}
	if until := expiresAt - time.Now().Unix(); until < 290 || until > 310 {
		t.Fatalf("expiresAt %d seconds out, want ~300", until)
	}
	now := time.Now()
	if err := store.Validate(challenge, nil, now); err != nil {
		t.Fatalf("Validate before consume: %v", err)
	}
	if err := store.Consume(challenge, nil, now); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

func TestChallengeStoreDoubleConsume(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	challenge, _, _ := store.Issue(nil, 5*time.Minute)
	now := time.Now()
	if err := store.Consume(challenge, nil, now); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if err := store.Consume(challenge, nil, now); err == nil || err.Error() != wantUnknown {
		t.Fatalf("second Consume = %v, want unknown-challenge error", err)
	}
	if err := store.Validate(challenge, nil, now); err == nil {
		t.Fatal("Validate after consume must fail")
	}
}

func TestChallengeStoreExpiry(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	challenge, _, _ := store.Issue(nil, 5*time.Minute)
	later := time.Now().Add(6 * time.Minute)
	if err := store.Validate(challenge, nil, later); err == nil {
		t.Fatal("Validate past expiry must fail")
	}
	if err := store.Consume(challenge, nil, later); err == nil || err.Error() != wantUnknown {
		t.Fatalf("Consume past expiry = %v, want unknown-challenge error", err)
	}
}

func TestChallengeStoreUnknownChallenge(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	if err := store.Consume(make([]byte, 32), nil, time.Now()); err == nil || err.Error() != wantUnknown {
		t.Fatalf("Consume of never-issued challenge = %v, want unknown-challenge error", err)
	}
}

func TestChallengeStoreWrongContextDoesNotConsume(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	ctx := make([]byte, 32)
	ctx[0] = 1
	challenge, _, _ := store.Issue(ctx, 5*time.Minute)
	now := time.Now()

	other := make([]byte, 32)
	other[0] = 2
	if err := store.Consume(challenge, other, now); err == nil {
		t.Fatal("Consume with wrong session context must fail")
	}
	if err := store.Consume(challenge, nil, now); err == nil {
		t.Fatal("Consume with missing session context must fail")
	}
	// The legitimate record survived both wrong-context presentations.
	if err := store.Consume(challenge, ctx, now); err != nil {
		t.Fatalf("legitimate Consume after wrong-context attempts: %v", err)
	}
}

func TestChallengeStoreCapacity(t *testing.T) {
	store := NewMemoryChallengeStore(2)
	if _, _, err := store.Issue(nil, time.Minute); err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	if _, _, err := store.Issue(nil, time.Minute); err != nil {
		t.Fatalf("Issue 2: %v", err)
	}
	if _, _, err := store.Issue(nil, time.Minute); err != ErrChallengeStoreFull {
		t.Fatalf("Issue at capacity = %v, want ErrChallengeStoreFull", err)
	}
}

func TestChallengeStoreConsumeFreesCapacity(t *testing.T) {
	// Capacity counts PENDING challenges: consuming one frees its slot
	// immediately, so legitimate traffic cannot wedge issuance until
	// records expire.
	store := NewMemoryChallengeStore(2)
	first, _, err := store.Issue(nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue 1: %v", err)
	}
	if _, _, err := store.Issue(nil, 5*time.Minute); err != nil {
		t.Fatalf("Issue 2: %v", err)
	}
	if _, _, err := store.Issue(nil, 5*time.Minute); err != ErrChallengeStoreFull {
		t.Fatalf("Issue at capacity = %v, want ErrChallengeStoreFull", err)
	}
	if err := store.Consume(first, nil, time.Now()); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if _, _, err := store.Issue(nil, 5*time.Minute); err != nil {
		t.Fatalf("Issue after consume must succeed immediately, got %v", err)
	}
}

func TestChallengeStoreWrongContextDoesNotFreeCapacity(t *testing.T) {
	// The flip side of capacity recovery: a wrong-binding presentation
	// must NOT remove the record (or free its slot).
	store := NewMemoryChallengeStore(1)
	ctx := make([]byte, 32)
	ctx[0] = 1
	challenge, _, err := store.Issue(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Consume(challenge, nil, time.Now()); err == nil {
		t.Fatal("Consume with wrong session context must fail")
	}
	if _, _, err := store.Issue(nil, 5*time.Minute); err != ErrChallengeStoreFull {
		t.Fatalf("Issue = %v, want ErrChallengeStoreFull (record must survive wrong-binding consume)", err)
	}
}

func TestChallengeStoreIssueValidatesInputs(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	if _, _, err := store.Issue(make([]byte, 5), 5*time.Minute); err == nil {
		t.Fatal("Issue with 5-byte session context must fail")
	}
	if _, _, err := store.Issue(nil, 0); err == nil {
		t.Fatal("Issue with zero ttl must fail")
	}
	if _, _, err := store.Issue(nil, -time.Minute); err == nil {
		t.Fatal("Issue with negative ttl must fail")
	}
	// 0 and 32 bytes are the two valid session-context lengths.
	if _, _, err := store.Issue(nil, time.Minute); err != nil {
		t.Fatalf("Issue with empty session context: %v", err)
	}
	if _, _, err := store.Issue(make([]byte, 32), time.Minute); err != nil {
		t.Fatalf("Issue with 32-byte session context: %v", err)
	}
}

func TestNewMemoryChallengeStoreRejectsBadCapacity(t *testing.T) {
	for _, size := range []int{0, -1} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewMemoryChallengeStore(%d) must panic", size)
				}
			}()
			NewMemoryChallengeStore(size)
		}()
	}
}

func TestChallengeStoreConcurrentConsumeIsAtomic(t *testing.T) {
	store := NewMemoryChallengeStore(16)
	challenge, _, _ := store.Issue(nil, 5*time.Minute)
	now := time.Now()

	const attempts = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.Consume(challenge, nil, now) == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("%d concurrent consumes succeeded, want exactly 1", successes)
	}
}

// ----- Verify integration: the locked consumption order -----

type storeBundle struct {
	bundle *ProofBundle
	store  *MemoryChallengeStore
}

// newStoreBundle builds a fully valid single-cert bundle whose challenge
// was issued by a fresh store. Constraints, if given, ride on the cert.
func newStoreBundle(t *testing.T, scope []string, constraints []Constraint) storeBundle {
	t.Helper()
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Store Bot", "custom")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "store-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         scope,
		Constraints:   constraints,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}
	store := NewMemoryChallengeStore(16)
	challenge, _, err := store.Issue(nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	challengeAt := now.Unix()
	sig, err := SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	return storeBundle{
		bundle: &ProofBundle{
			AgentID:      agent.ID,
			AgentPubKey:  agent.PublicKey,
			Delegations:  []DelegationCert{*cert},
			Challenge:    challenge,
			ChallengeAt:  challengeAt,
			ChallengeSig: sig,
		},
		store: store,
	}
}

func requireUnknownChallenge(t *testing.T, res VerifyResult) {
	t.Helper()
	if res.Valid {
		t.Fatal("expected rejection")
	}
	if res.IdentityStatus != "invalid" || res.ErrorReason != "unknown_challenge: "+wantUnknown {
		t.Fatalf("got %s / %s, want invalid / unknown_challenge", res.IdentityStatus, res.ErrorReason)
	}
}

func TestVerifyWithStoreReplayIsRejected(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, ChallengeStore: sb.store}

	first := Verify(sb.bundle, opts)
	if !first.Valid {
		t.Fatalf("first presentation must verify: %s / %s", first.IdentityStatus, first.ErrorReason)
	}
	// Identical second presentation: single-use makes it a replay.
	requireUnknownChallenge(t, Verify(sb.bundle, opts))
}

func TestVerifyWithStoreBadSignatureDoesNotConsume(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, ChallengeStore: sb.store}

	// Corrupt the challenge signature: the presentation is forged and MUST
	// NOT spend the challenge.
	forged := *sb.bundle
	forged.ChallengeSig.Ed25519 = append([]byte(nil), sb.bundle.ChallengeSig.Ed25519...)
	forged.ChallengeSig.Ed25519[0] ^= 0xFF
	res := Verify(&forged, opts)
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "bad_challenge_sig") {
		t.Fatalf("forged presentation: got %s / %s", res.IdentityStatus, res.ErrorReason)
	}

	// The legitimate presentation still succeeds afterwards.
	if res := Verify(sb.bundle, opts); !res.Valid {
		t.Fatalf("legitimate presentation after forgery must verify: %s / %s", res.IdentityStatus, res.ErrorReason)
	}
}

func TestVerifyWithStoreScopeDeniedStillConsumes(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	// Require a scope the chain does not grant: cryptographically valid,
	// authorization denied — the challenge is spent anyway.
	opts := VerifyOptions{RequiredScope: ScopeFilesWrite, ChallengeStore: sb.store}
	res := Verify(sb.bundle, opts)
	if res.Valid || res.IdentityStatus != IdentityStatusScopeDenied {
		t.Fatalf("got %s / %s, want scope_denied", res.IdentityStatus, res.ErrorReason)
	}
	// Retrying with the correct scope fails: the challenge is gone.
	requireUnknownChallenge(t, Verify(sb.bundle, VerifyOptions{RequiredScope: ScopeMeetingAttend, ChallengeStore: sb.store}))
}

func TestVerifyWithStoreConstraintDeniedStillConsumes(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeTransactPurchase}, []Constraint{
		{Type: "max_amount", MaxAmount: 100, Currency: "USD"},
	})
	opts := VerifyOptions{
		RequiredScope:  ScopeTransactPurchase,
		ChallengeStore: sb.store,
		Context: VerifierContext{
			RequestedAmount:   500,
			RequestedCurrency: "USD",
			HasAmount:         true,
		},
	}
	res := Verify(sb.bundle, opts)
	if res.Valid || res.IdentityStatus != IdentityStatusConstraintDenied {
		t.Fatalf("got %s / %s, want constraint_denied", res.IdentityStatus, res.ErrorReason)
	}
	// Constraint denial happened AFTER consumption: the challenge is spent.
	requireUnknownChallenge(t, Verify(sb.bundle, VerifyOptions{
		RequiredScope:  ScopeTransactPurchase,
		ChallengeStore: sb.store,
		Context: VerifierContext{
			RequestedAmount:   50,
			RequestedCurrency: "USD",
			HasAmount:         true,
		},
	}))
}

func TestVerifyWithStoreUnknownChallengeRejectedBeforeCrypto(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	// A store that never issued this challenge.
	otherStore := NewMemoryChallengeStore(16)
	requireUnknownChallenge(t, Verify(sb.bundle, VerifyOptions{ChallengeStore: otherStore}))
	// The bundle's own store still holds the unconsumed record.
	if err := sb.store.Validate(sb.bundle.Challenge, nil, time.Now()); err != nil {
		t.Fatalf("record must be untouched: %v", err)
	}
}

// ----- Store-failure normalization: no custom-store text leaks -----

// leakyStore is an adversarial custom ChallengeStore whose errors carry
// backend detail that would distinguish record states. Verify must
// normalize every failure to the canonical unknown_challenge result.
type leakyStore struct {
	inner       *MemoryChallengeStore
	validateErr error
	consumeErr  error
}

func (s *leakyStore) Issue(sessionContext []byte, ttl time.Duration) ([]byte, int64, error) {
	return s.inner.Issue(sessionContext, ttl)
}

func (s *leakyStore) Validate(challenge, sessionContext []byte, now time.Time) error {
	if s.validateErr != nil {
		return s.validateErr
	}
	return s.inner.Validate(challenge, sessionContext, now)
}

func (s *leakyStore) Consume(challenge, sessionContext []byte, now time.Time) error {
	if s.consumeErr != nil {
		return s.consumeErr
	}
	return s.inner.Consume(challenge, sessionContext, now)
}

func TestVerifyNormalizesCustomStoreErrors(t *testing.T) {
	leaks := []error{
		errors.New("pg: relation \"challenges\" does not exist"),
		errors.New("record expired 42s ago"),
		errors.New("challenge already consumed by request 7f3a"),
		errors.New("session binding mismatch: bound to sess-991"),
	}
	for _, leak := range leaks {
		// Failure surfaced at the pre-signature Validate step.
		sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
		store := &leakyStore{inner: sb.store, validateErr: leak}
		res := Verify(sb.bundle, VerifyOptions{ChallengeStore: store})
		requireUnknownChallenge(t, res)
		if strings.Contains(res.ErrorReason, leak.Error()) {
			t.Fatalf("validate leak %q reached the public result: %s", leak, res.ErrorReason)
		}

		// Failure surfaced at the post-signature Consume step.
		sb = newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
		store = &leakyStore{inner: sb.store, consumeErr: leak}
		res = Verify(sb.bundle, VerifyOptions{ChallengeStore: store})
		requireUnknownChallenge(t, res)
		if strings.Contains(res.ErrorReason, leak.Error()) {
			t.Fatalf("consume leak %q reached the public result: %s", leak, res.ErrorReason)
		}
	}
}

// ----- Policy evaluation happens after consumption -----

type stubPolicy struct {
	allow bool
	err   error
}

func (p stubPolicy) EvaluatePolicy(*ProofBundle, VerifierContext) (bool, error) {
	return p.allow, p.err
}

func TestVerifyWithStorePolicyDeniedStillConsumes(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	res := Verify(sb.bundle, VerifyOptions{
		RequiredScope:  ScopeMeetingAttend,
		ChallengeStore: sb.store,
		Policy:         stubPolicy{allow: false},
	})
	if res.Valid || res.IdentityStatus != IdentityStatusScopeDenied {
		t.Fatalf("got %s / %s, want scope_denied", res.IdentityStatus, res.ErrorReason)
	}
	// Policy denial happened AFTER consumption: retrying without the
	// policy gate still fails — the challenge is spent.
	requireUnknownChallenge(t, Verify(sb.bundle, VerifyOptions{
		RequiredScope:  ScopeMeetingAttend,
		ChallengeStore: sb.store,
	}))
}

func TestVerifyWithStorePolicyErrorStillConsumes(t *testing.T) {
	sb := newStoreBundle(t, []string{ScopeMeetingAttend}, nil)
	res := Verify(sb.bundle, VerifyOptions{
		RequiredScope:  ScopeMeetingAttend,
		ChallengeStore: sb.store,
		Policy:         stubPolicy{err: errors.New("policy backend unreachable")},
	})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "policy_error") {
		t.Fatalf("got %s / %s, want policy_error", res.IdentityStatus, res.ErrorReason)
	}
	// The provider error surfaced after the challenge was spent: replay of
	// the same presentation is still rejected.
	requireUnknownChallenge(t, Verify(sb.bundle, VerifyOptions{
		RequiredScope:  ScopeMeetingAttend,
		ChallengeStore: sb.store,
	}))
}
