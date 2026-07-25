package ratify_test

import (
	"strings"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

// streamedFixture builds a verified session token plus the agent key needed
// to sign per-turn challenges.
type streamedFixture struct {
	token     *SessionToken
	secret    []byte
	agentPriv HybridPrivateKey
	now       time.Time
}

func newStreamedFixture(t *testing.T, scope []string) streamedFixture {
	t.Helper()
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Turn Bot", "custom")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "turn-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         scope,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	sig, err := SignChallenge(challenge, now.Unix(), agentPriv)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	bundle := &ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  now.Unix(),
		ChallengeSig: sig,
	}
	res := Verify(bundle, VerifyOptions{Now: now})
	if !res.Valid {
		t.Fatalf("initial Verify: %s — %s", res.IdentityStatus, res.ErrorReason)
	}
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = 0x42
	}
	token, err := IssueSessionToken(bundle, res, "session-turn", now.Unix(), now.Add(30*time.Minute).Unix(), secret)
	if err != nil {
		t.Fatalf("IssueSessionToken: %v", err)
	}
	return streamedFixture{token: token, secret: secret, agentPriv: agentPriv, now: now}
}

// turnFor signs a fresh turn. sessionContext/streamID/streamSeq ride in the
// signable per §6.4.2.
func (f streamedFixture) turnFor(t *testing.T, challenge []byte, sessionContext, streamID []byte, streamSeq int64) StreamedTurn {
	t.Helper()
	at := f.now.Unix()
	var sig HybridSignature
	var err error
	switch {
	case len(streamID) != 0:
		sig, err = SignChallengeWithStream(challenge, at, sessionContext, streamID, streamSeq, f.agentPriv)
	case len(sessionContext) != 0:
		sig, err = SignChallengeWithSessionContext(challenge, at, sessionContext, f.agentPriv)
	default:
		sig, err = SignChallenge(challenge, at, f.agentPriv)
	}
	if err != nil {
		t.Fatalf("sign turn challenge: %v", err)
	}
	return StreamedTurn{
		Challenge:      challenge,
		ChallengeAt:    at,
		ChallengeSig:   sig,
		SessionContext: sessionContext,
		StreamID:       streamID,
		StreamSeq:      streamSeq,
	}
}

func randomChallenge(t *testing.T) []byte {
	t.Helper()
	c, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	return c
}

func TestStreamedTurnWithOptionsRequiredScope(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend, ScopeFilesRead})

	turn := f.turnFor(t, randomChallenge(t), nil, nil, 0)
	res := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		RequiredScope: ScopeMeetingAttend, Now: f.now,
	})
	if !res.Valid {
		t.Fatalf("granted scope must verify: %s — %s", res.IdentityStatus, res.ErrorReason)
	}

	// A scope the token does not carry is denied — the designed check the
	// positional form could never make.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		RequiredScope: ScopeFilesWrite, Now: f.now,
	})
	if res.Valid || res.IdentityStatus != IdentityStatusScopeDenied {
		t.Fatalf("got %s / %s, want scope_denied", res.IdentityStatus, res.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsSingleUse(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	store := NewMemoryChallengeStore(16)
	challenge, _, err := store.Issue(nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	turn := f.turnFor(t, challenge, nil, nil, 0)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, ChallengeStore: store, Now: f.now}

	first := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, opts)
	if !first.Valid {
		t.Fatalf("first presentation: %s — %s", first.IdentityStatus, first.ErrorReason)
	}
	replay := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, opts)
	if replay.Valid || !strings.HasPrefix(replay.ErrorReason, "unknown_challenge") {
		t.Fatalf("replay got %s / %s, want unknown_challenge", replay.IdentityStatus, replay.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsForgeryDoesNotConsume(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	store := NewMemoryChallengeStore(16)
	challenge, _, _ := store.Issue(nil, 5*time.Minute)
	turn := f.turnFor(t, challenge, nil, nil, 0)
	opts := VerifyOptions{ChallengeStore: store, Now: f.now}

	forged := turn
	forged.ChallengeSig.Ed25519 = append([]byte(nil), turn.ChallengeSig.Ed25519...)
	forged.ChallengeSig.Ed25519[0] ^= 0xFF
	res := VerifyStreamedTurnWithOptions(f.token, f.secret, forged, opts)
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "bad_challenge_sig") {
		t.Fatalf("forged turn: got %s / %s", res.IdentityStatus, res.ErrorReason)
	}

	// The legitimate presentation still succeeds afterwards.
	if res := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, opts); !res.Valid {
		t.Fatalf("legitimate turn after forgery: %s — %s", res.IdentityStatus, res.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsScopeDenialStillConsumes(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	store := NewMemoryChallengeStore(16)
	challenge, _, _ := store.Issue(nil, 5*time.Minute)
	turn := f.turnFor(t, challenge, nil, nil, 0)

	denied := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		RequiredScope: ScopeFilesWrite, ChallengeStore: store, Now: f.now,
	})
	if denied.Valid || denied.IdentityStatus != IdentityStatusScopeDenied {
		t.Fatalf("got %s / %s, want scope_denied", denied.IdentityStatus, denied.ErrorReason)
	}
	// The denial happened AFTER consumption: retrying with the granted
	// scope fails — the challenge is spent.
	retry := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		RequiredScope: ScopeMeetingAttend, ChallengeStore: store, Now: f.now,
	})
	if retry.Valid || !strings.HasPrefix(retry.ErrorReason, "unknown_challenge") {
		t.Fatalf("retry got %s / %s, want unknown_challenge", retry.IdentityStatus, retry.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsUnknownChallengeRejectedBeforeCrypto(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	store := NewMemoryChallengeStore(16)
	// Never-issued challenge: rejected with the canonical uniform result.
	turn := f.turnFor(t, randomChallenge(t), nil, nil, 0)
	res := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{ChallengeStore: store, Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "unknown_challenge") {
		t.Fatalf("got %s / %s, want unknown_challenge", res.IdentityStatus, res.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsSessionBinding(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	ctx := make([]byte, 32)
	ctx[0] = 7

	// Bound turn against the matching verifier context verifies.
	turn := f.turnFor(t, randomChallenge(t), ctx, nil, 0)
	res := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{SessionContext: ctx, Now: f.now})
	if !res.Valid {
		t.Fatalf("bound turn: %s — %s", res.IdentityStatus, res.ErrorReason)
	}

	// Wrong verifier context is a mismatch.
	other := make([]byte, 32)
	other[0] = 8
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{SessionContext: other, Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "session_context_mismatch") {
		t.Fatalf("got %s / %s, want session_context_mismatch", res.IdentityStatus, res.ErrorReason)
	}

	// Presented binding with no verifier expectation is unverifiable.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "session_context_unverifiable") {
		t.Fatalf("got %s / %s, want session_context_unverifiable", res.IdentityStatus, res.ErrorReason)
	}

	// Verifier expectation with an unbound turn is missing.
	unbound := f.turnFor(t, randomChallenge(t), nil, nil, 0)
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, unbound, VerifyOptions{SessionContext: ctx, Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "missing_session_context") {
		t.Fatalf("got %s / %s, want missing_session_context", res.IdentityStatus, res.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsStreamTracking(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	streamID := make([]byte, 32)
	streamID[0] = 3

	// Next-in-sequence turn verifies.
	turn := f.turnFor(t, randomChallenge(t), nil, streamID, 4)
	res := VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		Stream: &StreamContext{StreamID: streamID, LastSeenSeq: 3}, Now: f.now,
	})
	if !res.Valid {
		t.Fatalf("in-sequence turn: %s — %s", res.IdentityStatus, res.ErrorReason)
	}

	// Replayed sequence number is rejected.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		Stream: &StreamContext{StreamID: streamID, LastSeenSeq: 4}, Now: f.now,
	})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "stream_seq_replay") {
		t.Fatalf("got %s / %s, want stream_seq_replay", res.IdentityStatus, res.ErrorReason)
	}

	// Skipped sequence number is rejected.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{
		Stream: &StreamContext{StreamID: streamID, LastSeenSeq: 1}, Now: f.now,
	})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "stream_seq_skip") {
		t.Fatalf("got %s / %s, want stream_seq_skip", res.IdentityStatus, res.ErrorReason)
	}

	// Stream-bound turn with no verifier stream context is unverifiable.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "stream_context_unverifiable") {
		t.Fatalf("got %s / %s, want stream_context_unverifiable", res.IdentityStatus, res.ErrorReason)
	}
}

func TestStreamedTurnWithOptionsTokenChecksStillApply(t *testing.T) {
	f := newStreamedFixture(t, []string{ScopeMeetingAttend})
	turn := f.turnFor(t, randomChallenge(t), nil, nil, 0)

	// Nil token.
	res := VerifyStreamedTurnWithOptions(nil, f.secret, turn, VerifyOptions{Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "nil_session_token") {
		t.Fatalf("got %s / %s, want nil_session_token", res.IdentityStatus, res.ErrorReason)
	}

	// Wrong secret fails the HMAC.
	res = VerifyStreamedTurnWithOptions(f.token, []byte("wrong-secret-wrong-secret-wrong!"), turn, VerifyOptions{Now: f.now})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "session_token_invalid") {
		t.Fatalf("got %s / %s, want session_token_invalid", res.IdentityStatus, res.ErrorReason)
	}

	// Expired token window.
	res = VerifyStreamedTurnWithOptions(f.token, f.secret, turn, VerifyOptions{Now: f.now.Add(31 * time.Minute)})
	if res.Valid || !strings.HasPrefix(res.ErrorReason, "session_token_invalid") {
		t.Fatalf("got %s / %s, want session_token_invalid", res.IdentityStatus, res.ErrorReason)
	}
}
