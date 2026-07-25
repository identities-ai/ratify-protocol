package ratify_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	. "github.com/identities-ai/ratify-protocol"
)

// Known-answer vectors (§6.4.9). These exact hex values are duplicated in
// every SDK's test suite — TypeScript, Python, Rust, and C — so the five
// implementations provably produce byte-identical context hashes. Change
// them only with a construction change, and change all five together.
const (
	katEmptyOperationHash = "d135e239f4a5a5a0ad6385b204d6c81f3c10e6b2f5debfa3cc8079488970f82f"
	katFullOperationHash  = "6b70b5f404f61624ab2379fee2756639d8629141ecb3593b53e5a22346e0c3e5"
	katSessionContext     = "788c692b5dafae52dd896eb5f7580f61d42b8c7a2abeed4d4eea9dcd4d7d4dfd"
)

func katOperationContext() OperationContext {
	return OperationContext{
		RequiredScope: "files:write",
		Operation:     "git.push",
		ResourceID:    "git:github.com/acme/api",
		RequestedPath: "/src/handlers",
		PayloadDigest: bytes.Repeat([]byte{0xAB}, 32),
	}
}

func katSessionInputs(t *testing.T) SessionContextInputs {
	t.Helper()
	requestHash, err := OperationContextHash(katOperationContext())
	if err != nil {
		t.Fatalf("OperationContextHash: %v", err)
	}
	return SessionContextInputs{
		VerifierID:   "verifier-1",
		WorkspaceID:  "ws-42",
		AgentID:      "agent-7",
		SessionID:    "sess-9",
		InvocationID: "inv-3",
		RequestHash:  requestHash,
	}
}

func TestOperationContextKnownAnswers(t *testing.T) {
	empty, err := OperationContextHash(OperationContext{})
	if err != nil {
		t.Fatalf("empty OperationContextHash: %v", err)
	}
	if got := hex.EncodeToString(empty); got != katEmptyOperationHash {
		t.Fatalf("empty operation hash = %s, want %s", got, katEmptyOperationHash)
	}

	full, err := OperationContextHash(katOperationContext())
	if err != nil {
		t.Fatalf("full OperationContextHash: %v", err)
	}
	if got := hex.EncodeToString(full); got != katFullOperationHash {
		t.Fatalf("full operation hash = %s, want %s", got, katFullOperationHash)
	}

	session, err := BuildSessionContext(katSessionInputs(t))
	if err != nil {
		t.Fatalf("BuildSessionContext: %v", err)
	}
	if got := hex.EncodeToString(session); got != katSessionContext {
		t.Fatalf("session context = %s, want %s", got, katSessionContext)
	}
	if len(session) != 32 {
		t.Fatalf("session context length = %d, want 32", len(session))
	}
}

func TestOperationContextLengthPrefixingDisambiguates(t *testing.T) {
	// Raw concatenation could not tell ("ab","c") from ("a","bc") in
	// adjacent fields — the length prefixes must.
	a, err := OperationContextHash(OperationContext{Operation: "ab", ResourceID: "c"})
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	b, err := OperationContextHash(OperationContext{Operation: "a", ResourceID: "bc"})
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("shifted field boundary produced the same hash — length prefixing is broken")
	}
}

func TestOperationContextDomainSeparation(t *testing.T) {
	// The two constructions must never collide, even over identical field
	// content: an all-empty operation context and a session context built
	// over empty IDs (with the empty-operation request hash) differ.
	opHash, err := OperationContextHash(OperationContext{})
	if err != nil {
		t.Fatalf("OperationContextHash: %v", err)
	}
	sc, err := BuildSessionContext(SessionContextInputs{RequestHash: opHash})
	if err != nil {
		t.Fatalf("BuildSessionContext: %v", err)
	}
	if bytes.Equal(opHash, sc) {
		t.Fatal("operation and session constructions collided — domain tags are broken")
	}
}

func TestOperationContextRejectsIllFormedUTF8(t *testing.T) {
	// §6.4.9: strings encode as UTF-8 and implementations MUST reject
	// ill-formed text. A Go string is an arbitrary byte sequence, so
	// this is a real input class, not a type-system impossibility.
	bad := string([]byte{0xff, 0xfe})
	fields := []OperationContext{
		{RequiredScope: bad},
		{Operation: bad},
		{ResourceID: bad},
		{RequestedPath: bad},
	}
	for i, ctx := range fields {
		if _, err := OperationContextHash(ctx); err == nil {
			t.Fatalf("operation field %d with invalid UTF-8 must be rejected", i)
		}
	}

	validHash, err := OperationContextHash(OperationContext{})
	if err != nil {
		t.Fatalf("empty OperationContextHash: %v", err)
	}
	sessionFields := []SessionContextInputs{
		{VerifierID: bad, RequestHash: validHash},
		{WorkspaceID: bad, RequestHash: validHash},
		{AgentID: bad, RequestHash: validHash},
		{SessionID: bad, RequestHash: validHash},
		{InvocationID: bad, RequestHash: validHash},
	}
	for i, in := range sessionFields {
		if _, err := BuildSessionContext(in); err == nil {
			t.Fatalf("session field %d with invalid UTF-8 must be rejected", i)
		}
	}
}

func TestOperationContextInputValidation(t *testing.T) {
	if _, err := OperationContextHash(OperationContext{PayloadDigest: make([]byte, 5)}); err == nil {
		t.Fatal("5-byte payload digest must be rejected")
	}
	if _, err := OperationContextHash(OperationContext{PayloadDigest: make([]byte, 32)}); err != nil {
		t.Fatalf("32-byte payload digest must be accepted: %v", err)
	}
	if _, err := BuildSessionContext(SessionContextInputs{}); err == nil {
		t.Fatal("missing request hash must be rejected")
	}
	if _, err := BuildSessionContext(SessionContextInputs{RequestHash: make([]byte, 16)}); err == nil {
		t.Fatal("16-byte request hash must be rejected")
	}
}

func TestOperationContextEveryFieldIsLoadBearing(t *testing.T) {
	base := katOperationContext()
	baseHash, err := OperationContextHash(base)
	if err != nil {
		t.Fatalf("base hash: %v", err)
	}
	mutations := []OperationContext{}
	m := base
	m.RequiredScope = "files:read"
	mutations = append(mutations, m)
	m = base
	m.Operation = "git.pull"
	mutations = append(mutations, m)
	m = base
	m.ResourceID = "git:github.com/acme/api2"
	mutations = append(mutations, m)
	m = base
	m.RequestedPath = "/src"
	mutations = append(mutations, m)
	m = base
	m.PayloadDigest = bytes.Repeat([]byte{0xAC}, 32)
	mutations = append(mutations, m)

	for i, mut := range mutations {
		h, err := OperationContextHash(mut)
		if err != nil {
			t.Fatalf("mutation %d: %v", i, err)
		}
		if bytes.Equal(h, baseHash) {
			t.Fatalf("mutation %d did not change the hash — field is not bound", i)
		}
	}

	sessionBase := katSessionInputs(t)
	sessionBaseHash, err := BuildSessionContext(sessionBase)
	if err != nil {
		t.Fatalf("session base: %v", err)
	}
	sessionMutations := []SessionContextInputs{}
	s := sessionBase
	s.VerifierID = "verifier-2"
	sessionMutations = append(sessionMutations, s)
	s = sessionBase
	s.WorkspaceID = "ws-43"
	sessionMutations = append(sessionMutations, s)
	s = sessionBase
	s.AgentID = "agent-8"
	sessionMutations = append(sessionMutations, s)
	s = sessionBase
	s.SessionID = "sess-10"
	sessionMutations = append(sessionMutations, s)
	s = sessionBase
	s.InvocationID = "inv-4"
	sessionMutations = append(sessionMutations, s)
	s = sessionBase
	otherOp, err := OperationContextHash(OperationContext{Operation: "other"})
	if err != nil {
		t.Fatalf("other op hash: %v", err)
	}
	s.RequestHash = otherOp
	sessionMutations = append(sessionMutations, s)

	for i, mut := range sessionMutations {
		h, err := BuildSessionContext(mut)
		if err != nil {
			t.Fatalf("session mutation %d: %v", i, err)
		}
		if bytes.Equal(h, sessionBaseHash) {
			t.Fatalf("session mutation %d did not change the hash — field is not bound", i)
		}
	}
}

// TestOperationContextBindsTheActionEndToEnd exercises the Middleware
// Custody Profile property through the full verifier: a proof bundle
// session-bound to one operation verifies against that operation's
// reconstructed context and is rejected (session_context_mismatch) when
// the verifier reconstructs the context of a DIFFERENT operation in the
// same session — middleware cannot attach a valid proof to the wrong
// action inside the right session.
func TestOperationContextBindsTheActionEndToEnd(t *testing.T) {
	humanRoot, humanPriv, err := GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("GenerateHumanRootKeypair: %v", err)
	}
	agent, agentPriv, err := GenerateAgentKeypair("Custody Bot", "custom")
	if err != nil {
		t.Fatalf("GenerateAgentKeypair: %v", err)
	}
	now := time.Now()
	cert := &DelegationCert{
		CertID:        "custody-cert-001",
		Version:       ProtocolVersion,
		IssuerID:      humanRoot.ID,
		IssuerPubKey:  humanRoot.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ScopeFilesWrite},
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(24 * time.Hour).Unix(),
	}
	if err := IssueDelegation(cert, humanPriv); err != nil {
		t.Fatalf("IssueDelegation: %v", err)
	}

	// The middleware constructs the context for the intended action…
	intended := katSessionInputs(t)
	sessionContext, err := BuildSessionContext(intended)
	if err != nil {
		t.Fatalf("BuildSessionContext: %v", err)
	}

	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	sig, err := SignChallengeWithSessionContext(challenge, now.Unix(), sessionContext, agentPriv)
	if err != nil {
		t.Fatalf("SignChallengeWithSessionContext: %v", err)
	}
	bundle := &ProofBundle{
		AgentID:        agent.ID,
		AgentPubKey:    agent.PublicKey,
		Delegations:    []DelegationCert{*cert},
		Challenge:      challenge,
		ChallengeAt:    now.Unix(),
		ChallengeSig:   sig,
		SessionContext: sessionContext,
	}

	// …the verifier reconstructing the SAME operation accepts.
	res := Verify(bundle, VerifyOptions{
		RequiredScope:  ScopeFilesWrite,
		SessionContext: sessionContext,
		Now:            now,
	})
	if !res.Valid {
		t.Fatalf("intended operation must verify: %s — %s", res.IdentityStatus, res.ErrorReason)
	}

	// A verifier reconstructing a DIFFERENT operation in the same session
	// rejects: only the request hash differs, and the context diverges.
	wrongOp := katOperationContext()
	wrongOp.Operation = "git.force-push"
	wrongHash, err := OperationContextHash(wrongOp)
	if err != nil {
		t.Fatalf("wrong op hash: %v", err)
	}
	wrongInputs := intended
	wrongInputs.RequestHash = wrongHash
	wrongContext, err := BuildSessionContext(wrongInputs)
	if err != nil {
		t.Fatalf("wrong BuildSessionContext: %v", err)
	}
	res = Verify(bundle, VerifyOptions{
		RequiredScope:  ScopeFilesWrite,
		SessionContext: wrongContext,
		Now:            now,
	})
	if res.Valid || res.IdentityStatus != IdentityStatusInvalid {
		t.Fatalf("wrong operation must be rejected: %s — %s", res.IdentityStatus, res.ErrorReason)
	}
	if want := "session_context_mismatch"; len(res.ErrorReason) < len(want) || res.ErrorReason[:len(want)] != want {
		t.Fatalf("got %q, want session_context_mismatch", res.ErrorReason)
	}
}
