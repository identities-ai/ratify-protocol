// Command ratify-testvectors regenerates the canonical Ratify Protocol v1
// test vectors from fixed seeds. The output is a set of self-contained JSON
// files that other-language implementations (JS, Python, Rust, etc.) can use
// to verify correctness of their canonical serialization, signing, and
// verification logic.
//
// Every fixture is deterministic: private keys derive from hardcoded 32-byte
// seeds, timestamps are fixed, and challenge bytes are derived from the
// fixture name. Re-running this generator MUST produce byte-identical output
// to the committed fixture files.
//
// Usage:
//
//	go run ./cmd/ratify-testvectors                     # default output dir
//	go run ./cmd/ratify-testvectors -out /tmp/vectors    # custom output
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

// Canonical fixed timestamps. 1800000000 is 2027-01-15 08:00:00 UTC — far
// enough in the future that "now" offsets make sense both forward and back.
const (
	fixtureNow       = int64(1800000000)
	fixtureIssuedAt  = int64(1799996400) // now - 1h
	fixtureExpiresAt = int64(1800082800) // now + 23h
)

// ============================================================================
// Entity, cert, bundle, and fixture builders
// ============================================================================

// entity is a keyed participant in a fixture (human root, intermediate, or agent).
// v1 uses hybrid keypairs: one Ed25519 + one ML-DSA-65, each derived from its
// own 32-byte seed. Seeds are chosen per-role for readability:
//
//	human_root   → Ed25519 seed 0x01*32, ML-DSA-65 seed 0xFE*32
//	agent        → Ed25519 seed 0x02*32, ML-DSA-65 seed 0xFD*32
//	intermediate → Ed25519 seed 0x03*32, ML-DSA-65 seed 0xFC*32
//	...etc
//
// (The ML-DSA-65 seed is the bitwise complement of the Ed25519 seed byte, so
// the two are visually distinct in fixture files.)
type entity struct {
	Role           string                 `json:"role"`
	Ed25519SeedHex string                 `json:"ed25519_seed_hex"`
	MLDSA65SeedHex string                 `json:"ml_dsa_65_seed_hex"`
	PublicKey      ratify.HybridPublicKey `json:"public_key"`
	ID             string                 `json:"id"`

	priv ratify.HybridPrivateKey
}

// newEntity derives a deterministic hybrid keypair from a single byte pattern.
// The Ed25519 seed is 32 bytes of `b`; the ML-DSA-65 seed is 32 bytes of ^b.
func newEntity(role string, b byte) entity {
	var edSeed, mlSeed [32]byte
	for i := range edSeed {
		edSeed[i] = b
		mlSeed[i] = ^b
	}
	pub, priv, err := ratify.HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		panic(fmt.Errorf("newEntity(%s): %w", role, err))
	}
	return entity{
		Role:           role,
		Ed25519SeedHex: hex.EncodeToString(edSeed[:]),
		MLDSA65SeedHex: hex.EncodeToString(mlSeed[:]),
		PublicKey:      pub,
		ID:             ratify.DeriveID(pub),
		priv:           priv,
	}
}

// buildCert constructs and signs a DelegationCert with the issuer's hybrid
// private key.
func buildCert(certID string, issuer, subject entity, scope []string, issuedAt, expiresAt int64) ratify.DelegationCert {
	return buildCertWithConstraints(certID, issuer, subject, scope, nil, issuedAt, expiresAt)
}

// buildCertWithConstraints is the constraint-aware variant. Used by the
// constraint conformance fixtures.
func buildCertWithConstraints(certID string, issuer, subject entity, scope []string, constraints []ratify.Constraint, issuedAt, expiresAt int64) ratify.DelegationCert {
	cert := ratify.DelegationCert{
		CertID:        certID,
		Version:       ratify.ProtocolVersion,
		IssuerID:      issuer.ID,
		IssuerPubKey:  issuer.PublicKey,
		SubjectID:     subject.ID,
		SubjectPubKey: subject.PublicKey,
		Scope:         scope,
		Constraints:   constraints,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
	}
	if err := ratify.IssueDelegation(&cert, issuer.priv); err != nil {
		panic(fmt.Errorf("sign cert %s: %w", certID, err))
	}
	return cert
}

// buildBundle constructs a signed ProofBundle.
func buildBundle(agent entity, chain []ratify.DelegationCert, challenge []byte, challengeAt int64) ratify.ProofBundle {
	sig, err := ratify.SignChallenge(challenge, challengeAt, agent.priv)
	if err != nil {
		panic(fmt.Errorf("sign challenge for %s: %w", agent.Role, err))
	}
	return ratify.ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  chain,
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}
}

// buildSessionBoundBundle constructs a v1.1 session-bound ProofBundle. The
// 32-byte session_context is part of the challenge signing bytes and travels
// on the bundle so verifiers can compare it to their reconstructed context.
func buildSessionBoundBundle(agent entity, chain []ratify.DelegationCert, challenge []byte, challengeAt int64, sessionContext []byte) ratify.ProofBundle {
	sig, err := ratify.SignChallengeWithSessionContext(challenge, challengeAt, sessionContext, agent.priv)
	if err != nil {
		panic(fmt.Errorf("sign session-bound challenge for %s: %w", agent.Role, err))
	}
	return ratify.ProofBundle{
		AgentID:        agent.ID,
		AgentPubKey:    agent.PublicKey,
		Delegations:    chain,
		Challenge:      challenge,
		ChallengeAt:    challengeAt,
		ChallengeSig:   sig,
		SessionContext: sessionContext,
	}
}

// buildStreamBoundBundle constructs a v1.1 stream-bound ProofBundle. The
// 32-byte stream_id and 8-byte big-endian stream_seq are appended to the
// challenge signing bytes, so a proxy cannot replay, reorder, or omit bundles
// within the stream without invalidating the signature.
func buildStreamBoundBundle(agent entity, chain []ratify.DelegationCert, challenge []byte, challengeAt int64, streamID []byte, streamSeq int64) ratify.ProofBundle {
	sig, err := ratify.SignChallengeWithStream(challenge, challengeAt, nil, streamID, streamSeq, agent.priv)
	if err != nil {
		panic(fmt.Errorf("sign stream-bound challenge for %s: %w", agent.Role, err))
	}
	return ratify.ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  chain,
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
		StreamID:     streamID,
		StreamSeq:    streamSeq,
	}
}

// deterministicChallenge derives a 32-byte challenge from a fixture-specific
// tag so each fixture has a stable, distinct challenge.
func deterministicChallenge(tag string) []byte {
	h := sha256.Sum256([]byte("ratify-testvector-v1:challenge:" + tag))
	return h[:]
}

// deterministicSessionContext derives a stable 32-byte session_context for
// v1.1 session-binding fixtures.
func deterministicSessionContext(tag string) []byte {
	h := sha256.Sum256([]byte("ratify-testvector-v1:session-context:" + tag))
	return h[:]
}

// deterministicStreamID derives a stable 32-byte stream_id for v1.1
// stream-binding fixtures.
func deterministicStreamID(tag string) []byte {
	h := sha256.Sum256([]byte("ratify-testvector-v1:stream-id:" + tag))
	return h[:]
}

// deterministicSessionSecret derives a stable 32-byte verifier session secret
// for v1.1 session_token fixtures. Real deployments use random secrets — the
// fixtures expose this value only because cross-SDK reproducibility requires
// it.
func deterministicSessionSecret(tag string) []byte {
	h := sha256.Sum256([]byte("ratify-testvector-v1:session-secret:" + tag))
	return h[:]
}

// ============================================================================
// Fixture schema
// ============================================================================

type fixture struct {
	Name            string                       `json:"name"`
	Description     string                       `json:"description"`
	ProtocolVersion int                          `json:"protocol_version"`
	Kind            string                       `json:"kind"` // "verify" | "scope" | "revocation" | "key_rotation" | "session_token" | "transaction_receipt"
	Entities        []entity                     `json:"entities,omitempty"`
	Timestamps      map[string]int64             `json:"timestamps,omitempty"`
	ChallengeHex    string                       `json:"challenge_hex,omitempty"`
	CertChain       []ratify.DelegationCert      `json:"cert_chain,omitempty"`
	Bundle          *ratify.ProofBundle          `json:"bundle,omitempty"`
	Revocation      *ratify.RevocationList       `json:"revocation_list,omitempty"`
	KeyRotation     *ratify.KeyRotationStatement `json:"key_rotation,omitempty"`
	SessionToken    *sessionTokenFixture         `json:"session_token,omitempty"`
	Receipt         *ratify.TransactionReceipt   `json:"transaction_receipt,omitempty"`
	RevocationPush  *ratify.RevocationPush       `json:"revocation_push,omitempty"`
	WitnessEntry    *ratify.WitnessEntry         `json:"witness_entry,omitempty"`
	ScopeInput      []string                     `json:"scope_input,omitempty"`
	// VerifierContext is an optional application-context snapshot the
	// conformance harness must feed into its local VerifierContext before
	// running Verify. Present only on fixtures that exercise first-class
	// Constraints. Callback-typed fields (e.g. invocations_in_window) are
	// expressed as a stubbed numeric value here and wired up in harness.
	VerifierContext *verifierContextInput `json:"verifier_context,omitempty"`
	Expected        expectedBlock         `json:"expected"`
}

type expectedBlock struct {
	// verify kind
	DelegationSignBytesHex []string             `json:"delegation_sign_bytes_hex,omitempty"`
	ChallengeSignBytesHex  string               `json:"challenge_sign_bytes_hex,omitempty"`
	VerifyOptions          *verifyOptionsInput  `json:"verify_options,omitempty"`
	VerifyResult           *ratify.VerifyResult `json:"verify_result,omitempty"`

	// scope kind
	ExpandedScopes []string `json:"expanded_scopes,omitempty"`

	// revocation kind
	RevocationSignBytesHex        string `json:"revocation_sign_bytes_hex,omitempty"`
	RevocationSignatureEd25519Hex string `json:"revocation_signature_ed25519_hex,omitempty"`
	RevocationSignatureMLDSA65Hex string `json:"revocation_signature_ml_dsa_65_hex,omitempty"`

	// key_rotation kind
	KeyRotationSignBytesHex           string `json:"key_rotation_sign_bytes_hex,omitempty"`
	KeyRotationSignatureOldEd25519Hex string `json:"key_rotation_signature_old_ed25519_hex,omitempty"`
	KeyRotationSignatureOldMLDSA65Hex string `json:"key_rotation_signature_old_ml_dsa_65_hex,omitempty"`
	KeyRotationSignatureNewEd25519Hex string `json:"key_rotation_signature_new_ed25519_hex,omitempty"`
	KeyRotationSignatureNewMLDSA65Hex string `json:"key_rotation_signature_new_ml_dsa_65_hex,omitempty"`
	KeyRotationVerifyOK               *bool  `json:"key_rotation_verify_ok,omitempty"`
	KeyRotationErrorReason            string `json:"key_rotation_error_reason,omitempty"`

	// session_token kind
	SessionTokenSignBytesHex string                `json:"session_token_sign_bytes_hex,omitempty"`
	SessionTokenMACHex       string                `json:"session_token_mac_hex,omitempty"`
	StreamedTurn             *streamedTurnExpected `json:"streamed_turn,omitempty"`

	// transaction_receipt kind
	ReceiptSignBytesHex string `json:"receipt_sign_bytes_hex,omitempty"`
	ReceiptValid        *bool  `json:"receipt_valid,omitempty"`
	ReceiptErrorReason  string `json:"receipt_error_reason,omitempty"`

	// revocation_push kind
	RevocationPushSignBytesHex        string `json:"revocation_push_sign_bytes_hex,omitempty"`
	RevocationPushSignatureEd25519Hex string `json:"revocation_push_signature_ed25519_hex,omitempty"`
	RevocationPushSignatureMLDSA65Hex string `json:"revocation_push_signature_ml_dsa_65_hex,omitempty"`

	// witness_entry kind
	WitnessEntrySignBytesHex        string `json:"witness_entry_sign_bytes_hex,omitempty"`
	WitnessEntrySignatureEd25519Hex string `json:"witness_entry_signature_ed25519_hex,omitempty"`
	WitnessEntrySignatureMLDSA65Hex string `json:"witness_entry_signature_ml_dsa_65_hex,omitempty"`
}

// sessionTokenFixture captures the raw data required to reproduce a v1.1
// SessionToken fixture in any SDK. session_secret_hex is exposed only because
// these are test vectors — in real deployments the secret never leaves the
// verifier.
type sessionTokenFixture struct {
	SessionSecretHex string               `json:"session_secret_hex"`
	Token            *ratify.SessionToken `json:"token"`
	// Streamed turn inputs: the per-turn challenge the verifier should
	// accept (happy path) or reject (negative paths).
	Challenge    []byte                 `json:"challenge"`
	ChallengeAt  int64                  `json:"challenge_at"`
	ChallengeSig ratify.HybridSignature `json:"challenge_sig"`
	VerifyNow    int64                  `json:"verify_now"`
}

// streamedTurnExpected is the VerifyStreamedTurn outcome a conformance
// harness must reproduce.
type streamedTurnExpected struct {
	Valid          bool     `json:"valid"`
	IdentityStatus string   `json:"identity_status"`
	HumanID        string   `json:"human_id,omitempty"`
	AgentID        string   `json:"agent_id,omitempty"`
	GrantedScope   []string `json:"granted_scope,omitempty"`
	ErrorReason    string   `json:"error_reason,omitempty"`
}

type verifyOptionsInput struct {
	RequiredScope  string              `json:"required_scope,omitempty"`
	Now            int64               `json:"now"`
	SessionContext []byte              `json:"session_context,omitempty"`
	Stream         *streamContextInput `json:"stream,omitempty"`
}

// streamContextInput is the fixture-side serialized shape of a
// ratify.StreamContext. LastSeenSeq is the verifier's persisted "last
// accepted stream_seq" — zero means no turns accepted yet, so the first valid
// bundle must carry stream_seq == 1.
type streamContextInput struct {
	StreamID    []byte `json:"stream_id"`
	LastSeenSeq int64  `json:"last_seen_seq"`
}

// verifierContextInput is the fixture-side serialized shape of a
// ratify.VerifierContext. Flat JSON so each SDK can construct its native
// VerifierContext without a rich type.
//
// InvocationsInWindowCount stubs the max_rate callback: at test time the
// harness wires a function that returns this value regardless of the
// (certID, windowS) tuple it's asked. Zero means "no invocations yet."
// Absent (nil pointer) means "do not provide a rate counter at all" —
// useful for the constraint_unverifiable path.
type verifierContextInput struct {
	CurrentLat               *float64 `json:"current_lat,omitempty"`
	CurrentLon               *float64 `json:"current_lon,omitempty"`
	CurrentAltM              *float64 `json:"current_alt_m,omitempty"`
	CurrentSpeedMps          *float64 `json:"current_speed_mps,omitempty"`
	RequestedAmount          *float64 `json:"requested_amount,omitempty"`
	RequestedCurrency        string   `json:"requested_currency,omitempty"`
	InvocationsInWindowCount *int     `json:"invocations_in_window_count,omitempty"`
}

func intPtr(v int) *int { return &v }

func f64(v float64) *float64 { return &v }

func boolPtr(v bool) *bool { return &v }

// ============================================================================
// Helpers for shaping the expected VerifyResult block
// ============================================================================

func buildVerifyFixture(
	name, desc string,
	entities []entity,
	chain []ratify.DelegationCert,
	bundle *ratify.ProofBundle,
	opts ratify.VerifyOptions,
) *fixture {
	// Capture signable bytes for each cert in the chain so implementers can
	// cross-check their canonical serialization without reverse-engineering it.
	signBytes := make([]string, len(chain))
	for i := range chain {
		b, err := ratify.DelegationSignBytes(&chain[i])
		if err != nil {
			panic(err)
		}
		signBytes[i] = hex.EncodeToString(b)
	}

	challengeBytes := ratify.ChallengeSignBytesWithStream(bundle.Challenge, bundle.ChallengeAt, bundle.SessionContext, bundle.StreamID, bundle.StreamSeq)

	// Run the actual verifier so the expected VerifyResult matches real behavior.
	// If a fixture's expected result differs from Verify() output, that's a bug
	// in the fixture setup or in the verifier — either way we want to see it.
	result := ratify.Verify(bundle, opts)

	optsCapture := &verifyOptionsInput{
		RequiredScope:  opts.RequiredScope,
		Now:            opts.Now.Unix(),
		SessionContext: opts.SessionContext,
	}
	if opts.Stream != nil {
		optsCapture.Stream = &streamContextInput{
			StreamID:    opts.Stream.StreamID,
			LastSeenSeq: opts.Stream.LastSeenSeq,
		}
	}

	return &fixture{
		Name:            name,
		Description:     desc,
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "verify",
		Entities:        entities,
		Timestamps: map[string]int64{
			"verifier_now": opts.Now.Unix(),
			"challenge_at": bundle.ChallengeAt,
		},
		ChallengeHex: hex.EncodeToString(bundle.Challenge),
		CertChain:    chain,
		Bundle:       bundle,
		Expected: expectedBlock{
			DelegationSignBytesHex: signBytes,
			ChallengeSignBytesHex:  hex.EncodeToString(challengeBytes),
			VerifyOptions:          optsCapture,
			VerifyResult:           &result,
		},
	}
}

// ============================================================================
// Verify-kind fixtures (17)
// ============================================================================

func genHappyPathDepth1() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000001",
		human, agent,
		[]string{ratify.ScopeMeetingAttend, ratify.ScopeMeetingSpeak},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("happy_path_depth_1")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"happy_path_depth_1",
		"Depth-1 delegation: human grants meeting:attend + meeting:speak to agent. "+
			"Required scope meeting:attend is satisfied. All signatures and the "+
			"fresh challenge verify.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

func genSessionBoundChallenge() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000022",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("session_bound_challenge")
	sessionContext := deterministicSessionContext("session_bound_challenge")
	bundle := buildSessionBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, sessionContext)

	return buildVerifyFixture(
		"session_bound_challenge",
		"v1.1 session-bound challenge: ProofBundle.session_context is included "+
			"in the challenge signing bytes and must match VerifyOptions.SessionContext.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope:  ratify.ScopeMeetingAttend,
			Now:            unixTime(fixtureNow),
			SessionContext: sessionContext,
		},
	)
}

// genStreamBoundFirstTurn covers the v1.1 stream-binding happy path: first
// turn of a stream carries stream_id + stream_seq=1, verifier tracks
// LastSeenSeq=0 (no turns yet), signature verifies over the stream-extended
// challenge bytes, verifier accepts.
func genStreamBoundFirstTurn() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000024",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("stream_bound_first_turn")
	streamID := deterministicStreamID("stream_bound_first_turn")
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, streamID, 1)

	return buildVerifyFixture(
		"stream_bound_first_turn",
		"v1.1 stream-binding happy path: first turn of a stream (stream_seq=1, "+
			"LastSeenSeq=0). stream_id and stream_seq are included in the "+
			"challenge signing bytes; verifier accepts and returns "+
			"authorized_agent.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
			Stream:        &ratify.StreamContext{StreamID: streamID, LastSeenSeq: 0},
		},
	)
}

// genStreamBoundNextTurn covers the in-progress stream path: a later turn
// (stream_seq=5) with the verifier's tracked LastSeenSeq=4 — the sequence
// increments exactly by one, so the verifier accepts.
func genStreamBoundNextTurn() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000025",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("stream_bound_next_turn")
	streamID := deterministicStreamID("stream_bound_next_turn")
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, streamID, 5)

	return buildVerifyFixture(
		"stream_bound_next_turn",
		"v1.1 stream-binding mid-stream: stream_seq=5 with verifier's "+
			"LastSeenSeq=4. Increment is exactly one, so the verifier accepts. "+
			"Proves the happy-path sequencing rule across implementations.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
			Stream:        &ratify.StreamContext{StreamID: streamID, LastSeenSeq: 4},
		},
	)
}

// genRejectStreamReplay covers the stream replay path: bundle carries a
// stream_seq the verifier has already recorded. Rejected with
// stream_seq_replay.
func genRejectStreamReplay() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000026",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_stream_replay")
	streamID := deterministicStreamID("reject_stream_replay")
	// Bundle carries stream_seq=3; verifier has already recorded LastSeenSeq=3.
	// A proxy replaying a recorded turn sees this path.
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, streamID, 3)

	return buildVerifyFixture(
		"reject_stream_replay",
		"SECURITY: stream_seq=3 already recorded by the verifier (LastSeenSeq=3). "+
			"A replay of a previously-accepted turn must be rejected with "+
			"identity_status=invalid and error_reason starting stream_seq_replay.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
			Stream:        &ratify.StreamContext{StreamID: streamID, LastSeenSeq: 3},
		},
	)
}

// genRejectStreamSeqSkip covers the stream-skip path: bundle jumps ahead of
// the verifier's expected next seq. Rejected with stream_seq_skip.
func genRejectStreamSeqSkip() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000027",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_stream_seq_skip")
	streamID := deterministicStreamID("reject_stream_seq_skip")
	// Verifier expects next = 3 (LastSeenSeq=2); bundle carries seq=5.
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, streamID, 5)

	return buildVerifyFixture(
		"reject_stream_seq_skip",
		"SECURITY: stream_seq=5 with LastSeenSeq=2 skips the expected next=3. "+
			"An omitted or reordered turn is treated as a break in stream "+
			"integrity and rejected with error_reason starting stream_seq_skip.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
			Stream:        &ratify.StreamContext{StreamID: streamID, LastSeenSeq: 2},
		},
	)
}

// genRejectStreamIDMismatch covers the cross-stream replay path: bundle
// carries stream_id=A but the verifier's tracked stream_id=B. The signature
// would verify only on the exact bytes the agent signed, but identity_status
// still has to clearly name the mismatch so audits know a bundle from stream
// A was presented to a verifier tracking stream B.
func genRejectStreamIDMismatch() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000028",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_stream_id_mismatch")
	bundleStreamID := deterministicStreamID("reject_stream_id_mismatch:bundle")
	verifierStreamID := deterministicStreamID("reject_stream_id_mismatch:verifier")
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, bundleStreamID, 1)

	return buildVerifyFixture(
		"reject_stream_id_mismatch",
		"SECURITY: bundle carries stream_id=A but verifier is tracking stream_id=B. "+
			"Rejected with identity_status=invalid and error_reason "+
			"stream_id_mismatch before sequence or signature checks.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
			Stream:        &ratify.StreamContext{StreamID: verifierStreamID, LastSeenSeq: 0},
		},
	)
}

// genRejectStreamContextUnverifiable covers the asymmetric path where the
// bundle declares itself stream-bound but the verifier has no stream context
// to compare against. Fail-closed.
func genRejectStreamContextUnverifiable() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000029",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_stream_context_unverifiable")
	streamID := deterministicStreamID("reject_stream_context_unverifiable")
	bundle := buildStreamBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, streamID, 1)

	return buildVerifyFixture(
		"reject_stream_context_unverifiable",
		"SECURITY: bundle carries stream_id/stream_seq but the verifier did not "+
			"supply a StreamContext. A verifier that cannot reconstruct stream "+
			"state has no way to detect replay/skip and MUST fail closed with "+
			"stream_context_unverifiable.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope: ratify.ScopeMeetingAttend,
			Now:           unixTime(fixtureNow),
		},
	)
}

// genRejectChallengeForwarding is the dedicated fixture for ROADMAP 3.6
// (challenge forwarding by a malicious verifier). The attack: malicious
// verifier V_mal forwards a challenge from legitimate verifier V_leg to the
// agent, the agent signs it with V_mal's session_context (since the agent
// believes it is authenticating to V_mal), then V_mal presents the resulting
// bundle back to V_leg. V_leg reconstructs its own session_context, which
// differs from V_mal's, so the signature over
// (challenge || ts || V_mal_context) does NOT verify against V_leg's
// expected (challenge || ts || V_leg_context). Defense: session_context
// binding from v1.1 §2.1.
func genRejectChallengeForwarding() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000002b",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_challenge_forwarding")
	// Agent signs with V_mal's session context (the verifier the agent
	// believes it is talking to).
	vMalContext := deterministicSessionContext("reject_challenge_forwarding:v_mal")
	bundle := buildSessionBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, vMalContext)

	// V_leg reconstructs its own session context — differs from V_mal's.
	vLegContext := deterministicSessionContext("reject_challenge_forwarding:v_leg")

	return buildVerifyFixture(
		"reject_challenge_forwarding",
		"SECURITY (ROADMAP 3.6): challenge forwarding by a malicious verifier. "+
			"V_mal forwards V_leg's challenge to the agent; the agent signs it "+
			"with V_mal's session_context. V_mal presents the bundle to V_leg. "+
			"V_leg reconstructs its own session_context, which differs, so the "+
			"challenge signature fails verification. Defense: v1.1 session "+
			"binding (§5.8, §6.4.2) ensures a bundle signed for one verifier "+
			"cannot authenticate at another. Rejected with "+
			"session_context_mismatch.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope:  ratify.ScopeMeetingAttend,
			Now:            unixTime(fixtureNow),
			SessionContext: vLegContext,
		},
	)
}

func genRejectSessionContextMismatch() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000023",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_session_context_mismatch")
	sessionContext := deterministicSessionContext("reject_session_context_mismatch")
	verifierContext := deterministicSessionContext("reject_session_context_mismatch:other-verifier")
	bundle := buildSessionBoundBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow, sessionContext)

	return buildVerifyFixture(
		"reject_session_context_mismatch",
		"v1.1 session binding rejects a bundle whose session_context does not "+
			"match the verifier-reconstructed context.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{
			RequiredScope:  ratify.ScopeMeetingAttend,
			Now:            unixTime(fixtureNow),
			SessionContext: verifierContext,
		},
	)
}

func genHappyPathDepth2() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// cert[1]: human -> intermediate with meeting:*
	// cert[1]: human -> intermediate. Parent of a sub-delegation, so must
	// explicitly grant identity:delegate (SPEC §9.1, verify.go sub-delegation
	// gate).
	cert1 := buildCert(
		"00000000-0000-0000-0000-000000000002",
		human, intermediate,
		[]string{"meeting:*", ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// cert[0]: intermediate -> agent, narrowed to meeting:attend
	cert0 := buildCert(
		"00000000-0000-0000-0000-000000000003",
		intermediate, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("happy_path_depth_2")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"happy_path_depth_2",
		"Depth-2 delegation: human -> intermediate (meeting:*) -> agent (meeting:attend). "+
			"Effective scope = intersection = {meeting:attend}. Verifier requires "+
			"meeting:attend; passes.",
		[]entity{human, intermediate, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

func genHappyPathDepth3() *fixture {
	human := newEntity("human_root", 0x01)
	org := newEntity("org", 0x04)
	dept := newEntity("dept", 0x05)
	agent := newEntity("agent", 0x02)

	// Every non-root parent in a multi-hop chain must carry identity:delegate
	// (SPEC §9.1 sensitive scope; verify.go sub-delegation gate). Org
	// delegates to dept; dept delegates to agent.
	cert2 := buildCert( // human -> org
		"00000000-0000-0000-0000-000000000004",
		human, org,
		[]string{"meeting:*", "comms:*", ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	cert1 := buildCert( // org -> dept (drops comms; keeps delegate for dept to issue cert0)
		"00000000-0000-0000-0000-000000000005",
		org, dept,
		[]string{"meeting:*", ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	cert0 := buildCert( // dept -> agent (narrows to meeting:attend)
		"00000000-0000-0000-0000-000000000006",
		dept, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("happy_path_depth_3")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1, cert2}, challenge, fixtureNow)

	return buildVerifyFixture(
		"happy_path_depth_3",
		"Depth-3 delegation at maximum chain depth. Each level narrows the scope; "+
			"effective = {meeting:attend}. Verifier requires meeting:attend; passes.",
		[]entity{human, org, dept, agent},
		[]ratify.DelegationCert{cert0, cert1, cert2},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

func genScopeNarrowingDepth2Escalation() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// cert[1]: human grants meeting:attend + identity:delegate (so the
	// intermediate CAN sub-delegate — we want the scope-escalation gate,
	// not the sub-delegation gate, to fire).
	cert1 := buildCert(
		"00000000-0000-0000-0000-000000000007",
		human, intermediate,
		[]string{ratify.ScopeMeetingAttend, ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// cert[0]: intermediate attempts to grant files:write (NEVER received
	// from its parent, so it does not appear in the effective intersection).
	cert0 := buildCert(
		"00000000-0000-0000-0000-000000000008",
		intermediate, agent,
		[]string{ratify.ScopeFilesWrite},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("scope_narrowing_depth_2_escalation")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_scope_escalation_depth_2",
		"SECURITY: depth-2 chain where intermediate is authorized to sub-delegate "+
			"(identity:delegate on parent) but attempts to grant files:write despite "+
			"only receiving meeting:attend. Effective scope = intersection = "+
			"{meeting:attend}. Required scope files:write must be rejected with "+
			"identity_status=scope_denied.",
		[]entity{human, intermediate, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeFilesWrite, Now: unixTime(fixtureNow)},
	)
}

func genRejectSensitiveWildcard() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// Parent cert grants meeting:* + identity:delegate so the intermediate
	// is authorized to sub-delegate. This isolates the scope check: the
	// verifier rejects the cert NOT because sub-delegation is blocked but
	// because meeting:record is sensitive and meeting:* does not expand to
	// include it — so the effective intersection is empty of meeting:record.
	cert1 := buildCert(
		"00000000-0000-0000-0000-000000000009",
		human, intermediate,
		[]string{"meeting:*", ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	cert0 := buildCert(
		"00000000-0000-0000-0000-000000000017",
		intermediate, agent,
		[]string{ratify.ScopeMeetingRecord}, // sensitive — cannot ride meeting:*
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("reject_sensitive_wildcard")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_sensitive_wildcard",
		"SECURITY: sensitive scope meeting:record cannot ride meeting:* at the "+
			"parent level. Parent cert explicitly grants identity:delegate so the "+
			"sub-delegation gate passes; the rejection is due to scope-intersection "+
			"semantics (wildcards never expand to sensitive members). Verifier rejects "+
			"with identity_status=scope_denied.",
		[]entity{human, intermediate, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingRecord, Now: unixTime(fixtureNow)},
	)
}

func genRejectExpired() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000000b",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureNow-7200, // issued 2h ago
		fixtureNow-3600, // expired 1h ago
	)
	challenge := deterministicChallenge("reject_expired")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_expired",
		"Expired cert: ExpiresAt is in the past relative to verifier_now. Must be "+
			"rejected with identity_status=expired.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectNotYetValid() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000000c",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureNow+3600, // issued in the future
		fixtureNow+7200,
	)
	challenge := deterministicChallenge("reject_not_yet_valid")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_not_yet_valid",
		"Cert with IssuedAt > verifier_now. Not yet valid — rejected.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectStaleChallenge() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000000d",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_stale_challenge")
	// Challenge signed >300s before verifier_now
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow-600)

	return buildVerifyFixture(
		"reject_stale_challenge",
		"Challenge signed 600s ago; exceeds ChallengeWindowSeconds (300). "+
			"Must be rejected as stale.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectFutureChallenge() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000000e",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_future_challenge")
	// Challenge signed 60s in the future — clock skew beyond tolerance
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow+60)

	return buildVerifyFixture(
		"reject_future_challenge",
		"Challenge signed with a timestamp in the verifier's future. Negative "+
			"challenge age indicates clock skew or forgery — rejected.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectTamperedScope() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000000f",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Tamper: escalate scope after signature was produced
	cert.Scope = append(cert.Scope, ratify.ScopeMeetingRecord)

	challenge := deterministicChallenge("reject_tampered_scope")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_tampered_scope",
		"Attacker appends meeting:record to cert.Scope AFTER the signature was "+
			"produced. Canonical signing bytes no longer match; signature fails to "+
			"verify. Rejected with bad_signature.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectTamperedExpiry() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000010",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Tamper: extend expiry far into the future
	cert.ExpiresAt = fixtureExpiresAt + 1000000

	challenge := deterministicChallenge("reject_tampered_expiry")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_tampered_expiry",
		"Attacker extends cert.ExpiresAt after signing. Signature fails to verify. "+
			"Rejected.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectWrongKey() *fixture {
	human := newEntity("human_root", 0x01)
	imposter := newEntity("imposter", 0x0a)
	agent := newEntity("agent", 0x02)

	// Build a cert that CLAIMS to be issued by `human` but is signed by `imposter`.
	cert := ratify.DelegationCert{
		CertID:        "00000000-0000-0000-0000-000000000011",
		Version:       ratify.ProtocolVersion,
		IssuerID:      human.ID,        // claims human
		IssuerPubKey:  human.PublicKey, // claims human's pubkey
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ratify.ScopeMeetingAttend},
		IssuedAt:      fixtureIssuedAt,
		ExpiresAt:     fixtureExpiresAt,
	}
	// Sign with the IMPOSTER's key instead of human's
	if err := ratify.IssueDelegation(&cert, imposter.priv); err != nil {
		panic(err)
	}

	challenge := deterministicChallenge("reject_wrong_key")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_wrong_key",
		"Cert claims issuer=human but is signed by a different private key. "+
			"Signature does not verify against the declared issuer pubkey. Rejected.",
		[]entity{human, imposter, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectBrokenChain() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	other := newEntity("other_entity", 0x0b)
	agent := newEntity("agent", 0x02)

	// cert[1]: human -> intermediate (correct)
	cert1 := buildCert(
		"00000000-0000-0000-0000-000000000012",
		human, intermediate,
		[]string{"meeting:*"},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// cert[0]: OTHER -> agent (issuer.ID does NOT match cert[1].SubjectID)
	cert0 := buildCert(
		"00000000-0000-0000-0000-000000000013",
		other, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("reject_broken_chain")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_broken_chain",
		"Chain linkage broken: cert[0].IssuerID (other) does not match cert[1].SubjectID "+
			"(intermediate). Rejected with broken_chain.",
		[]entity{human, intermediate, other, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectKeyMismatch() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	otherAgent := newEntity("other_agent", 0x0c)

	cert := buildCert(
		"00000000-0000-0000-0000-000000000014",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_key_mismatch")
	// Build bundle claiming otherAgent's ID/pubkey but cert is for `agent`.
	otherSig, err := ratify.SignChallenge(challenge, fixtureNow, otherAgent.priv)
	if err != nil {
		panic(err)
	}
	bundle := ratify.ProofBundle{
		AgentID:      otherAgent.ID,
		AgentPubKey:  otherAgent.PublicKey,
		Delegations:  []ratify.DelegationCert{cert},
		Challenge:    challenge,
		ChallengeAt:  fixtureNow,
		ChallengeSig: otherSig,
	}

	return buildVerifyFixture(
		"reject_key_mismatch",
		"ProofBundle.AgentPubKey does not match cert[0].SubjectPubKey. An agent is "+
			"trying to present a cert that was not issued to it. Rejected with key_mismatch.",
		[]entity{human, agent, otherAgent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectBadChallengeSig() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000015",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_bad_challenge_sig")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)
	// Corrupt both components of the hybrid challenge signature (last byte of each).
	bundle.ChallengeSig.Ed25519[len(bundle.ChallengeSig.Ed25519)-1] ^= 0xFF
	bundle.ChallengeSig.MLDSA65[len(bundle.ChallengeSig.MLDSA65)-1] ^= 0xFF

	return buildVerifyFixture(
		"reject_bad_challenge_sig",
		"Challenge signature tampered (last byte flipped). Agent liveness proof "+
			"fails to verify. Rejected with bad_challenge_sig.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

// genRejectEd25519OnlyCorrupted proves the hybrid both-must-verify guarantee:
// ML-DSA-65 component is valid but Ed25519 component is corrupted. The
// verifier MUST reject — a valid post-quantum signature alone is insufficient.
func genRejectEd25519OnlyCorrupted() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000002c",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Corrupt ONLY the Ed25519 component of the delegation cert signature.
	// ML-DSA-65 remains valid. The verifier must still reject.
	cert.Signature.Ed25519[len(cert.Signature.Ed25519)-1] ^= 0xFF

	challenge := deterministicChallenge("reject_ed25519_only_corrupted")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_ed25519_only_corrupted",
		"SECURITY (hybrid guarantee): delegation cert has a valid ML-DSA-65 "+
			"signature but a corrupted Ed25519 signature. Both components MUST "+
			"verify for the hybrid signature to be accepted. A valid post-quantum "+
			"component alone is insufficient. Rejected with bad_signature.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

// genRejectMLDSA65OnlyCorrupted proves the other half of the hybrid guarantee:
// Ed25519 component is valid but ML-DSA-65 component is corrupted. The
// verifier MUST reject — a valid classical signature alone is insufficient.
func genRejectMLDSA65OnlyCorrupted() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000002d",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Corrupt ONLY the ML-DSA-65 component of the delegation cert signature.
	// Ed25519 remains valid. The verifier must still reject.
	cert.Signature.MLDSA65[len(cert.Signature.MLDSA65)-1] ^= 0xFF

	challenge := deterministicChallenge("reject_mldsa65_only_corrupted")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_mldsa65_only_corrupted",
		"SECURITY (hybrid guarantee): delegation cert has a valid Ed25519 "+
			"signature but a corrupted ML-DSA-65 signature. Both components MUST "+
			"verify for the hybrid signature to be accepted. A valid classical "+
			"component alone is insufficient — this is what provides quantum "+
			"resistance. Rejected with bad_signature.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRejectChainTooDeep() *fixture {
	human := newEntity("human_root", 0x01)
	l3 := newEntity("level_3", 0x20)
	l2 := newEntity("level_2", 0x21)
	l1 := newEntity("level_1", 0x22)
	agent := newEntity("agent", 0x02)

	cert3 := buildCert("00000000-0000-0000-0000-000000000016", human, l3,
		[]string{"meeting:*"}, fixtureIssuedAt, fixtureExpiresAt)
	cert2 := buildCert("00000000-0000-0000-0000-000000000017", l3, l2,
		[]string{"meeting:*"}, fixtureIssuedAt, fixtureExpiresAt)
	cert1 := buildCert("00000000-0000-0000-0000-000000000018", l2, l1,
		[]string{"meeting:*"}, fixtureIssuedAt, fixtureExpiresAt)
	cert0 := buildCert("00000000-0000-0000-0000-000000000019", l1, agent,
		[]string{ratify.ScopeMeetingAttend}, fixtureIssuedAt, fixtureExpiresAt)

	challenge := deterministicChallenge("reject_chain_too_deep")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1, cert2, cert3}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_chain_too_deep",
		"Four-cert chain exceeds MaxDelegationChainDepth=3. Rejected before any "+
			"signature work is done.",
		[]entity{human, l3, l2, l1, agent},
		[]ratify.DelegationCert{cert0, cert1, cert2, cert3},
		&bundle,
		ratify.VerifyOptions{Now: unixTime(fixtureNow)},
	)
}

func genRevocationMiddleCert() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// Parent cert grants identity:delegate so the intermediate is
	// authorized to sub-delegate. We want the revocation check to be the
	// reason this fixture rejects, not the sub-delegation gate.
	cert1 := buildCert(
		"00000000-0000-0000-0000-00000000001a",
		human, intermediate,
		[]string{"meeting:*", ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	cert0 := buildCert(
		"00000000-0000-0000-0000-00000000001b",
		intermediate, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("revocation_middle_cert")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	revokedCertID := cert1.CertID // revoke the intermediate cert

	// Capture signable bytes
	signBytes := make([]string, 2)
	for i, c := range []ratify.DelegationCert{cert0, cert1} {
		b, _ := ratify.DelegationSignBytes(&c)
		signBytes[i] = hex.EncodeToString(b)
	}
	challengeSignHex := hex.EncodeToString(ratify.ChallengeSignBytesWithStream(bundle.Challenge, bundle.ChallengeAt, bundle.SessionContext, bundle.StreamID, bundle.StreamSeq))

	opts := ratify.VerifyOptions{
		Now:       unixTime(fixtureNow),
		IsRevoked: func(certID string) bool { return certID == revokedCertID },
	}
	result := ratify.Verify(&bundle, opts)

	return &fixture{
		Name: "revocation_middle_cert",
		Description: "Chain of depth 2; intermediate cert (cert_id=" + revokedCertID +
			") is revoked. Entire chain must be rejected with identity_status=revoked.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "verify",
		Entities:        []entity{human, intermediate, agent},
		Timestamps: map[string]int64{
			"verifier_now": fixtureNow,
			"challenge_at": bundle.ChallengeAt,
		},
		ChallengeHex: hex.EncodeToString(bundle.Challenge),
		CertChain:    []ratify.DelegationCert{cert0, cert1},
		Bundle:       &bundle,
		Expected: expectedBlock{
			DelegationSignBytesHex: signBytes,
			ChallengeSignBytesHex:  challengeSignHex,
			VerifyOptions: &verifyOptionsInput{
				RequiredScope: "",
				Now:           fixtureNow,
			},
			VerifyResult: &result,
		},
	}
}

// ============================================================================
// v1.x addition fixtures — no-expiry sentinel + presence:represent
// ============================================================================

// genNoExpiryCert pins the no-expiry sentinel: a cert with
// ExpiresAt == NoExpirySentinel (4070908799 = 2099-12-31 23:59:59 UTC) is a
// valid, verifiable cert. Implementations must accept it and must treat the
// sentinel as "no expiry (until revoked)" in display and policy evaluation,
// not as a literal 2099 expiry.
func genNoExpiryCert() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000040",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, ratify.NoExpirySentinel,
	)
	challenge := deterministicChallenge("no_expiry_cert")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"no_expiry_cert",
		"No-expiry sentinel: expires_at = 4070908799 (2099-12-31 23:59:59 UTC) "+
			"means \"no expiry (until revoked)\" — see SPEC §5.7. The bundle "+
			"verifies normally; revocation is the sole termination mechanism. "+
			"Implementations MUST NOT display or policy-evaluate the sentinel "+
			"as a real 2099 expiry.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

// genPresenceRepresentAllowed pins the presence:represent happy path. The
// cert grants presence:represent alongside an explicit identity:prove —
// presence:represent does NOT imply identity:prove; both are granted
// explicitly when both are needed.
func genPresenceRepresentAllowed() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000041",
		human, agent,
		[]string{ratify.ScopePresenceRepresent, ratify.ScopeIdentityProve},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("presence_represent_allowed")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"presence_represent_allowed",
		"presence:represent (sensitive): the agent is authorized to attend and "+
			"interact as a direct representative of the principal. Granted "+
			"explicitly alongside identity:prove — there is no scope implication. "+
			"Verifiers accepting this scope are expected to surface the "+
			"representation relationship to other participants (platform "+
			"policy; SPEC §9.1).",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePresenceRepresent, Now: unixTime(fixtureNow)},
	)
}

// genRejectPresenceSensitiveWildcard pins — as a full verify-kind rejection —
// that there is deliberately NO presence:* wildcard: presence:represent is
// sensitive, sensitive scopes never ride wildcards, and it is the domain's
// only member. A signed cert granting "presence:*" conveys nothing for
// presence:represent, so the verifier rejects with scope_denied.
func genRejectPresenceSensitiveWildcard() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-000000000042",
		human, agent,
		[]string{"presence:*"},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("reject_presence_sensitive_wildcard")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildVerifyFixture(
		"reject_presence_sensitive_wildcard",
		"SECURITY: there is deliberately no presence:* wildcard — "+
			"presence:represent is sensitive, sensitive scopes are never "+
			"introduced by wildcard expansion, and it is the domain's only "+
			"member. \"presence:*\" is therefore not in the vocabulary at all, "+
			"and the verifier rejects the cert as malformed with invalid_scope "+
			"(SPEC §9: scopes that are not canonical, not a wildcard, and not "+
			"a custom: extension MUST be rejected) — before any effective-scope "+
			"arithmetic. Representation must always be granted explicitly.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePresenceRepresent, Now: unixTime(fixtureNow)},
	)
}

// ============================================================================
// Scope-kind fixture
// ============================================================================

func genWildcardExpansionMeeting() *fixture {
	input := []string{"meeting:*"}
	expanded := ratify.ExpandScopes(input)
	sort.Strings(expanded) // stable output

	return &fixture{
		Name: "wildcard_expansion_meeting",
		Description: "ExpandScopes([\"meeting:*\"]) produces all non-sensitive meeting " +
			"scopes, deterministically, in sorted order. Sensitive scope meeting:record " +
			"is NOT included — it must be granted explicitly.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "scope",
		ScopeInput:      input,
		Expected: expectedBlock{
			ExpandedScopes: expanded,
		},
	}
}

// ============================================================================
// Revocation-kind fixture
// ============================================================================

func genRevocationListSignatureValid() *fixture {
	human := newEntity("human_root", 0x01)
	list := &ratify.RevocationList{
		IssuerID:  human.ID,
		UpdatedAt: fixtureNow,
		RevokedCerts: []string{
			"00000000-0000-0000-0000-000000000001",
			"00000000-0000-0000-0000-000000000007",
			"00000000-0000-0000-0000-00000000001a",
		},
	}
	if err := ratify.IssueRevocationList(list, human.priv); err != nil {
		panic(err)
	}
	signBytes, _ := ratify.RevocationSignBytes(list)

	return &fixture{
		Name: "revocation_list_signature_valid",
		Description: "RevocationList signed by the human root. Implementations must " +
			"produce identical signable bytes and verify the signature against the " +
			"issuer's public key.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "revocation",
		Entities:        []entity{human},
		Timestamps: map[string]int64{
			"updated_at": list.UpdatedAt,
		},
		Revocation: list,
		Expected: expectedBlock{
			RevocationSignBytesHex:        hex.EncodeToString(signBytes),
			RevocationSignatureEd25519Hex: hex.EncodeToString(list.Signature.Ed25519),
			RevocationSignatureMLDSA65Hex: hex.EncodeToString(list.Signature.MLDSA65),
		},
	}
}

// ============================================================================
// Key-rotation-kind fixtures
// ============================================================================

func genKeyRotationValid() *fixture {
	oldRoot := newEntity("old_root", 0x01)
	newRoot := newEntity("new_root", 0x06)
	stmt := ratify.KeyRotationStatement{
		Version:   ratify.ProtocolVersion,
		OldID:     oldRoot.ID,
		OldPubKey: oldRoot.PublicKey,
		NewID:     newRoot.ID,
		NewPubKey: newRoot.PublicKey,
		RotatedAt: fixtureNow,
		Reason:    "routine",
	}
	if err := ratify.IssueKeyRotationStatement(&stmt, oldRoot.priv, newRoot.priv); err != nil {
		panic(fmt.Errorf("sign key rotation: %w", err))
	}
	signBytes, err := ratify.KeyRotationSignBytes(&stmt)
	if err != nil {
		panic(err)
	}
	verifyErr := ratify.VerifyKeyRotationStatement(&stmt)

	return &fixture{
		Name: "key_rotation_valid",
		Description: "v1.1 key rotation: old root endorses new root and new root " +
			"proves possession. Both signatures verify over identical canonical bytes.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "key_rotation",
		Entities:        []entity{oldRoot, newRoot},
		Timestamps: map[string]int64{
			"rotated_at": stmt.RotatedAt,
		},
		KeyRotation: &stmt,
		Expected: expectedBlock{
			KeyRotationSignBytesHex:           hex.EncodeToString(signBytes),
			KeyRotationSignatureOldEd25519Hex: hex.EncodeToString(stmt.SignatureOld.Ed25519),
			KeyRotationSignatureOldMLDSA65Hex: hex.EncodeToString(stmt.SignatureOld.MLDSA65),
			KeyRotationSignatureNewEd25519Hex: hex.EncodeToString(stmt.SignatureNew.Ed25519),
			KeyRotationSignatureNewMLDSA65Hex: hex.EncodeToString(stmt.SignatureNew.MLDSA65),
			KeyRotationVerifyOK:               boolPtr(verifyErr == nil),
		},
	}
}

func genRejectKeyRotationTampered() *fixture {
	oldRoot := newEntity("old_root", 0x01)
	newRoot := newEntity("new_root", 0x06)
	stmt := ratify.KeyRotationStatement{
		Version:   ratify.ProtocolVersion,
		OldID:     oldRoot.ID,
		OldPubKey: oldRoot.PublicKey,
		NewID:     newRoot.ID,
		NewPubKey: newRoot.PublicKey,
		RotatedAt: fixtureNow,
		Reason:    "routine",
	}
	if err := ratify.IssueKeyRotationStatement(&stmt, oldRoot.priv, newRoot.priv); err != nil {
		panic(fmt.Errorf("sign key rotation: %w", err))
	}
	stmt.Reason = "device_lost"
	signBytes, err := ratify.KeyRotationSignBytes(&stmt)
	if err != nil {
		panic(err)
	}
	verifyErr := ratify.VerifyKeyRotationStatement(&stmt)
	errReason := ""
	if verifyErr != nil {
		errReason = verifyErr.Error()
	}

	return &fixture{
		Name: "reject_key_rotation_tampered",
		Description: "SECURITY: key rotation reason is changed after signing. " +
			"Canonical signing bytes no longer match both signatures, so verification rejects.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "key_rotation",
		Entities:        []entity{oldRoot, newRoot},
		Timestamps: map[string]int64{
			"rotated_at": stmt.RotatedAt,
		},
		KeyRotation: &stmt,
		Expected: expectedBlock{
			KeyRotationSignBytesHex: hex.EncodeToString(signBytes),
			KeyRotationVerifyOK:     boolPtr(verifyErr == nil),
			KeyRotationErrorReason:  errReason,
		},
	}
}

// ============================================================================
// Tamper helper variants — already covered by genRejectTampered* generators.
// The reject_unknown_scope fixture is shipped as a scope fixture because the
// protocol's behavior on unknown scopes is about vocabulary, not chain verify.
// ============================================================================

func genRejectUnknownScope() *fixture {
	input := []string{"pretend:unknown:scope"}
	expanded := ratify.ExpandScopes(input) // will just pass through the unknown string

	return &fixture{
		Name: "reject_unknown_scope",
		Description: "ValidateScopes rejects a scope that is not in the canonical " +
			"vocabulary and not a custom: extension (see SPEC.md §9). ExpandScopes " +
			"passes the unknown string through (no wildcard match), and ValidateScopes " +
			"returns an error. Implementations must treat such scopes as invalid " +
			"before issuing a delegation. For app-specific scopes, use the custom: " +
			"prefix (e.g. custom:acme:inventory:read) — those are accepted.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "scope",
		ScopeInput:      input,
		Expected: expectedBlock{
			ExpandedScopes: expanded, // pass-through; validation is a separate call
		},
	}
}

// ============================================================================
// Constraint-bearing fixtures (P0-2 — first-class Constraint semantics)
// ============================================================================

// buildConstraintFixture is buildVerifyFixture with a serialized
// VerifierContext attached so harnesses can feed the right context into their
// native Verify call.
func buildConstraintFixture(
	name, desc string,
	entities []entity,
	chain []ratify.DelegationCert,
	bundle *ratify.ProofBundle,
	opts ratify.VerifyOptions,
	ctxCapture *verifierContextInput,
) *fixture {
	fx := buildVerifyFixture(name, desc, entities, chain, bundle, opts)
	fx.VerifierContext = ctxCapture
	return fx
}

func genConstraintGeoCircleInside() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	// Golden Gate Park-ish, 500m radius; participant is at the center.
	geo := ratify.Constraint{
		Type:    ratify.ConstraintGeoCircle,
		Lat:     37.7694,
		Lon:     -122.4862,
		RadiusM: 500,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-00000000000e",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{geo},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("constraint_geo_circle_inside")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	ctx := ratify.VerifierContext{
		CurrentLat: 37.7694, CurrentLon: -122.4862, HasLocation: true,
	}
	return buildConstraintFixture(
		"constraint_geo_circle_inside",
		"Cert bears a geo_circle constraint (500m radius) and the caller-supplied "+
			"VerifierContext places the agent at the center. Verifier accepts the "+
			"chain and returns granted_scope including physical:enter.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{
			CurrentLat: f64(ctx.CurrentLat),
			CurrentLon: f64(ctx.CurrentLon),
		},
	)
}

func genConstraintGeoCircleOutside() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	geo := ratify.Constraint{
		Type:    ratify.ConstraintGeoCircle,
		Lat:     37.7694,
		Lon:     -122.4862,
		RadiusM: 500,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-00000000000f",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{geo},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_geo_circle_outside")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Position ~5km away from the geofence center — well outside 500m.
	ctx := ratify.VerifierContext{
		CurrentLat: 37.82, CurrentLon: -122.43, HasLocation: true,
	}
	return buildConstraintFixture(
		"constraint_geo_circle_outside",
		"Same geo_circle cert as constraint_geo_circle_inside, but the caller's "+
			"location is outside the 500m radius. Verifier rejects the chain with "+
			"identity_status invalid and reason constraint_denied.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{
			CurrentLat: f64(ctx.CurrentLat),
			CurrentLon: f64(ctx.CurrentLon),
		},
	)
}

func genConstraintTimeWindowDenied() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	// 09:00-17:00 Los Angeles local. fixtureNow = 2027-01-15 08:00 UTC =
	// 00:00 America/Los_Angeles — outside the window.
	timeC := ratify.Constraint{
		Type:  ratify.ConstraintTimeWindow,
		Start: "09:00",
		End:   "17:00",
		TZ:    "America/Los_Angeles",
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000010",
		human, agent,
		[]string{ratify.ScopeInfrastructureMonitor},
		[]ratify.Constraint{timeC},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("constraint_time_window_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	ctx := ratify.VerifierContext{} // time-window ignores location
	return buildConstraintFixture(
		"constraint_time_window_denied",
		"Cert bears a time_window constraint (09:00–17:00 America/Los_Angeles). "+
			"Verifier's current time is 08:00 UTC = midnight Los Angeles — outside "+
			"the window. Verifier rejects with constraint_denied. Exercises IANA "+
			"timezone handling and the non-wrapping window path.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeInfrastructureMonitor, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{},
	)
}

func genConstraintMaxAmountExceeds() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	amt := ratify.Constraint{
		Type:      ratify.ConstraintMaxAmount,
		MaxAmount: 5000,
		Currency:  "USD",
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000011",
		human, agent,
		[]string{ratify.ScopePaymentsSend},
		[]ratify.Constraint{amt},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("constraint_max_amount_exceeds")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Requested $10,000 USD — exceeds max $5,000.
	ctx := ratify.VerifierContext{
		RequestedAmount:   10000,
		RequestedCurrency: "USD",
		HasAmount:         true,
	}
	return buildConstraintFixture(
		"constraint_max_amount_exceeds",
		"Cert caps payments at 5000 USD. Verifier's context reports a requested "+
			"transaction of 10000 USD. Rejected with constraint_denied. Exercises "+
			"both currency matching and amount bound.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePaymentsSend, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{
			RequestedAmount:   f64(ctx.RequestedAmount),
			RequestedCurrency: ctx.RequestedCurrency,
		},
	)
}

// constraint_geo_polygon_inside — exercises the ray-casting check with a
// simple rectangle polygon; caller position is inside.
func genConstraintGeoPolygonInside() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	// ~1km square near the Presidio, SF.
	poly := ratify.Constraint{
		Type: ratify.ConstraintGeoPolygon,
		Points: [][2]float64{
			{37.7860, -122.4740},
			{37.7860, -122.4640},
			{37.7960, -122.4640},
			{37.7960, -122.4740},
		},
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000012",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{poly},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_geo_polygon_inside")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	ctx := ratify.VerifierContext{CurrentLat: 37.7910, CurrentLon: -122.4680, HasLocation: true}
	return buildConstraintFixture(
		"constraint_geo_polygon_inside",
		"geo_polygon (4-point rectangle) constraint with the participant "+
			"positioned inside. Exercises ray-casting inclusion.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{CurrentLat: f64(ctx.CurrentLat), CurrentLon: f64(ctx.CurrentLon)},
	)
}

// constraint_geo_bbox_denied — bounding box with participant outside.
func genConstraintGeoBBoxDenied() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	bbox := ratify.Constraint{
		Type:   ratify.ConstraintGeoBBox,
		MinLat: 37.70, MinLon: -122.50,
		MaxLat: 37.80, MaxLon: -122.40,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000013",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{bbox},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_geo_bbox_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Oakland-ish, outside the SF bbox.
	ctx := ratify.VerifierContext{CurrentLat: 37.80, CurrentLon: -122.25, HasLocation: true}
	return buildConstraintFixture(
		"constraint_geo_bbox_denied",
		"geo_bbox with participant outside the longitude bound. Rejected.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{CurrentLat: f64(ctx.CurrentLat), CurrentLon: f64(ctx.CurrentLon)},
	)
}

// constraint_geo_bbox_antimeridian_inside — Pacific-Rim bbox that wraps
// the 180° meridian. MinLon=170, MaxLon=-170 defines "from 170°E through
// 180 to -170°W" (i.e., MinLon > MaxLon by convention marks wrapping).
// A participant at lon=175 is inside. Exercises the wrap-aware branch
// of the geo_bbox longitude check and forces all SDKs to implement it
// identically, or cross-SDK conformance fails.
func genConstraintGeoBBoxAntimeridianInside() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	bbox := ratify.Constraint{
		Type:   ratify.ConstraintGeoBBox,
		MinLat: -20.0, MinLon: 170.0,
		MaxLat: 20.0, MaxLon: -170.0, // MinLon > MaxLon → wraps 180°
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-00000000001a",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{bbox},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_geo_bbox_antimeridian_inside")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Mid-Pacific, lon=175 — inside the wrapped bbox.
	ctx := ratify.VerifierContext{CurrentLat: 0.0, CurrentLon: 175.0, HasLocation: true}
	return buildConstraintFixture(
		"constraint_geo_bbox_antimeridian_inside",
		"geo_bbox spans the 180° meridian (MinLon=170, MaxLon=-170). The "+
			"caller is at lon=175 — inside the wrapped band. Verifier must "+
			"accept. Exercises the MinLon>MaxLon wrap-aware branch "+
			"(SPEC §5.7.2). Proves cross-SDK parity on anti-meridian handling.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{CurrentLat: f64(ctx.CurrentLat), CurrentLon: f64(ctx.CurrentLon)},
	)
}

// constraint_time_window_wrap_inside — wrap-across-midnight path. Window is
// 22:00–06:00 Asia/Tokyo, participant is at 03:00 Tokyo time.
// fixtureNow = 2027-01-15 08:00 UTC = 2027-01-15 17:00 Tokyo (JST UTC+9).
// So at fixtureNow Tokyo is 17:00 — OUTSIDE the 22:00-06:00 window.
// For an inside fixture we need Tokyo local to be in [22:00,23:59] or
// [00:00,06:00]. Pick verifier_now_override to land Tokyo at 03:00 —
// that's 2027-01-15 18:00 UTC = 1800054000.
func genConstraintTimeWindowWrapInside() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	timeC := ratify.Constraint{
		Type:  ratify.ConstraintTimeWindow,
		Start: "22:00",
		End:   "06:00",
		TZ:    "Asia/Tokyo",
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000014",
		human, agent,
		[]string{ratify.ScopeInfrastructureMonitor},
		[]ratify.Constraint{timeC},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("constraint_time_window_wrap_inside")
	// Tokyo 03:00 = UTC 18:00 on the same day.
	// fixtureNow=1800000000 is 2027-01-15 08:00 UTC. 18:00 UTC that day is
	// fixtureNow + 10h.
	const verifierNow int64 = 1800000000 + 10*3600
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, verifierNow)

	return buildConstraintFixture(
		"constraint_time_window_wrap_inside",
		"time_window spanning 22:00–06:00 Asia/Tokyo. The verifier's current "+
			"time is 18:00 UTC = 03:00 JST — inside the wrapped window. "+
			"Exercises the wrapping-window branch of time_window evaluation.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeInfrastructureMonitor, Now: unixTime(verifierNow)},
		&verifierContextInput{},
	)
}

// constraint_max_speed_mps_denied — exceeds speed limit.
func genConstraintMaxSpeedDenied() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	// Vehicle capped at 15 m/s (~54 km/h).
	speedC := ratify.Constraint{
		Type:   ratify.ConstraintMaxSpeedMps,
		MaxMps: 15.0,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000015",
		human, agent,
		[]string{ratify.ScopeVehicleOperate},
		[]ratify.Constraint{speedC},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_max_speed_mps_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Reporting 22 m/s (~79 km/h) — over the limit.
	ctx := ratify.VerifierContext{CurrentSpeedMps: 22.0, HasSpeed: true}
	return buildConstraintFixture(
		"constraint_max_speed_mps_denied",
		"max_speed_mps cap at 15. Context reports 22. Rejected with "+
			"constraint_denied. Exercises the speed-bound path.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeVehicleOperate, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{CurrentSpeedMps: f64(ctx.CurrentSpeedMps)},
	)
}

// constraint_geo_circle_equator_origin — proves the zero-as-absence fix.
// A geo_circle centered at lat=0, lon=0 (Gulf of Guinea) must emit those
// zero values explicitly, not omit them. If any SDK silently drops zero-
// valued kind-relevant fields, the canonical bytes drift and the
// signature fails. This fixture would break immediately under the old
// omitempty-everywhere behavior.
func genConstraintGeoCircleEquatorOrigin() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	geo := ratify.Constraint{
		Type:    ratify.ConstraintGeoCircle,
		Lat:     0, // equator — intentionally zero
		Lon:     0, // prime meridian — intentionally zero
		RadiusM: 50000,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000019",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{geo},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_geo_circle_equator_origin")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Caller is 10km north of (0,0) — still inside the 50km radius.
	ctx := ratify.VerifierContext{CurrentLat: 0.09, CurrentLon: 0, HasLocation: true}
	return buildConstraintFixture(
		"constraint_geo_circle_equator_origin",
		"Regression fixture for the zero-as-absence fix (P1-8). Cert carries "+
			"a geo_circle centered at lat=0, lon=0 — the one location where "+
			"the old omitempty-based canonical emission would silently drop "+
			"lat and lon from the signed bytes, causing cross-SDK signature "+
			"drift. The canonical shape must emit lat:0, lon:0 explicitly.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{CurrentLat: f64(ctx.CurrentLat), CurrentLon: f64(ctx.CurrentLon)},
	)
}

// constraint_unknown_denied — a cert carries a Constraint whose `type`
// is not in the v1 canonical set. Verifiers MUST fail closed with
// identity_status=constraint_unknown rather than silently ignore the
// constraint. This fixture forces the new status so cross-SDK parity is
// actually proven, not merely claimed.
func genConstraintUnknownDenied() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	// Synthesize a Constraint whose Type is not in the ConstraintType
	// canonical set. v1 rejects any unknown tag; v1.1 may promote this
	// shape to canonical but until then it must fail-closed.
	unknown := ratify.Constraint{
		Type: ratify.ConstraintType("this_kind_does_not_exist_yet"),
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000018",
		human, agent,
		[]string{ratify.ScopePhysicalEnter},
		[]ratify.Constraint{unknown},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("constraint_unknown_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	return buildConstraintFixture(
		"constraint_unknown_denied",
		"Cert carries a Constraint whose type is not in the v1 canonical "+
			"vocabulary. Verifier MUST fail with "+
			"identity_status=constraint_unknown (SPEC §5.9). Prevents a "+
			"verifier silently ignoring an unfamiliar constraint that a "+
			"future version could treat as enforced.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePhysicalEnter, Now: unixTime(fixtureNow)},
		&verifierContextInput{},
	)
}

// constraint_max_rate_denied — rate limit exceeded. The fixture ships a
// pre-computed invocation count that harnesses wire into a stub counter.
func genConstraintMaxRateDenied() *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)

	rate := ratify.Constraint{
		Type:    ratify.ConstraintMaxRate,
		Count:   5,
		WindowS: 300,
	}
	cert := buildCertWithConstraints(
		"00000000-0000-0000-0000-000000000016",
		human, agent,
		[]string{ratify.ScopePaymentsSend},
		[]ratify.Constraint{rate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("constraint_max_rate_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)

	// Pretend the agent has already exercised this cert 5 times in the last
	// 300s — hitting the cap. Fail-closed on rate.
	count := 5
	ctx := ratify.VerifierContext{
		InvocationsInWindow: func(_ string, _ int64) int { return count },
	}
	return buildConstraintFixture(
		"constraint_max_rate_denied",
		"max_rate capped at 5 invocations per 300s. Harness-supplied counter "+
			"returns 5 (at cap). Rejected with constraint_denied.",
		[]entity{human, agent},
		[]ratify.DelegationCert{cert},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopePaymentsSend, Now: unixTime(fixtureNow), Context: ctx},
		&verifierContextInput{InvocationsInWindowCount: intPtr(count)},
	)
}

// ============================================================================
// Sub-delegation fixtures (P0-1 — identity:delegate enforcement)
// ============================================================================

func genSubDelegationAllowed() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// Human → intermediate, granting meeting:attend AND identity:delegate
	// so the intermediate is authorized to sub-delegate.
	cert1 := buildCert(
		"00000000-0000-0000-0000-00000000000a",
		human, intermediate,
		[]string{ratify.ScopeMeetingAttend, ratify.ScopeIdentityDelegate},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Intermediate → agent, passing on meeting:attend.
	cert0 := buildCert(
		"00000000-0000-0000-0000-00000000000b",
		intermediate, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("sub_delegation_allowed")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"sub_delegation_allowed",
		"Depth-2 chain where the intermediate explicitly holds identity:delegate. "+
			"The human granted both meeting:attend and identity:delegate to the "+
			"intermediate, so the cert intermediate → agent is authorized. Verifier "+
			"accepts the proof for required scope meeting:attend.",
		[]entity{human, intermediate, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

func genSubDelegationDenied() *fixture {
	human := newEntity("human_root", 0x01)
	intermediate := newEntity("intermediate", 0x03)
	agent := newEntity("agent", 0x02)

	// Human → intermediate, granting meeting:attend but NOT identity:delegate.
	// The intermediate can exercise meeting:attend itself but must not
	// sub-delegate — the verifier rejects the chain.
	cert1 := buildCert(
		"00000000-0000-0000-0000-00000000000c",
		human, intermediate,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	cert0 := buildCert(
		"00000000-0000-0000-0000-00000000000d",
		intermediate, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	challenge := deterministicChallenge("sub_delegation_denied")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert0, cert1}, challenge, fixtureNow)

	return buildVerifyFixture(
		"sub_delegation_denied",
		"Depth-2 chain where the intermediate does NOT hold identity:delegate. "+
			"Sub-delegation is a separately-granted privilege (SPEC §9.1) and its "+
			"absence must cause the verifier to reject the chain with status invalid "+
			"and reason delegation_not_authorized.",
		[]entity{human, intermediate, agent},
		[]ratify.DelegationCert{cert0, cert1},
		&bundle,
		ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend, Now: unixTime(fixtureNow)},
	)
}

// ============================================================================
// Revocation-push fixtures (ROADMAP 2.4 — push-based revocation)
// ============================================================================

func genRevocationPushValid() *fixture {
	human := newEntity("human_root", 0x01)
	push := &ratify.RevocationPush{
		IssuerID: human.ID,
		SeqNo:    1,
		Entries: []string{
			"00000000-0000-0000-0000-000000000001",
			"00000000-0000-0000-0000-000000000007",
		},
		PushedAt: fixtureNow,
	}
	if err := ratify.IssueRevocationPush(push, human.priv); err != nil {
		panic(err)
	}
	signBytes, _ := ratify.RevocationPushSignBytes(push)

	return &fixture{
		Name: "revocation_push_valid",
		Description: "v1.1 revocation push: issuer sends a signed delta of newly " +
			"revoked cert IDs. Implementations must produce identical signable " +
			"bytes and verify the hybrid signature against the issuer's public key.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "revocation_push",
		Entities:        []entity{human},
		Timestamps: map[string]int64{
			"pushed_at": push.PushedAt,
		},
		RevocationPush: push,
		Expected: expectedBlock{
			RevocationPushSignBytesHex:        hex.EncodeToString(signBytes),
			RevocationPushSignatureEd25519Hex: hex.EncodeToString(push.Signature.Ed25519),
			RevocationPushSignatureMLDSA65Hex: hex.EncodeToString(push.Signature.MLDSA65),
		},
	}
}

// ============================================================================
// Witness-entry fixture (ROADMAP 3.2 — witness append-only log shape)
// ============================================================================

func genWitnessEntryValid() *fixture {
	witness := newEntity("witness", 0x07)
	entry := &ratify.WitnessEntry{
		PrevHash:  make([]byte, 32), // genesis — all zeros
		EntryData: []byte(`{"type":"receipt","id":"tx-sample"}`),
		Timestamp: fixtureNow,
		WitnessID: witness.ID,
	}
	if err := ratify.IssueWitnessEntry(entry, witness.priv); err != nil {
		panic(err)
	}
	signBytes, _ := ratify.WitnessEntrySignBytes(entry)

	return &fixture{
		Name: "witness_entry_valid",
		Description: "v1.1 witness append-only log entry (ROADMAP 3.2). A witness " +
			"operator signs an entry linking prev_hash → entry_data → timestamp. " +
			"Implementations must produce identical signable bytes and verify the " +
			"hybrid signature against the witness operator's public key.",
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "witness_entry",
		Entities:        []entity{witness},
		Timestamps: map[string]int64{
			"timestamp": entry.Timestamp,
		},
		WitnessEntry: entry,
		Expected: expectedBlock{
			WitnessEntrySignBytesHex:        hex.EncodeToString(signBytes),
			WitnessEntrySignatureEd25519Hex: hex.EncodeToString(entry.Signature.Ed25519),
			WitnessEntrySignatureMLDSA65Hex: hex.EncodeToString(entry.Signature.MLDSA65),
		},
	}
}

// ============================================================================
// Session-token fixtures (ROADMAP 2.3 — session cert cache)
// ============================================================================

// buildSessionTokenFixture runs a real Verify → IssueSessionToken →
// VerifyStreamedTurn pipeline with deterministic inputs, then captures the
// resulting token, challenge, signature, and expected streamed-turn outcome.
// Parameters that vary per fixture (verify time, token lifetime, whether the
// fixture mutates the token before verification) are expressed as closures.
func buildSessionTokenFixture(
	name, desc string,
	tokenLifetimeSec int64,
	verifyOffsetSec int64,
	mutateToken func(*ratify.SessionToken),
	overrideSecret []byte,
	corruptChallengeSig bool,
) *fixture {
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"00000000-0000-0000-0000-00000000002a",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	// Issue the bundle at fixtureNow so Verify passes cleanly.
	bundleChallenge := deterministicChallenge("session_token:" + name + ":bundle")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, bundleChallenge, fixtureNow)
	res := ratify.Verify(&bundle, ratify.VerifyOptions{
		Now:           time.Unix(fixtureNow, 0).UTC(),
		RequiredScope: ratify.ScopeMeetingAttend,
	})
	if !res.Valid {
		panic(fmt.Errorf("build %s: initial Verify failed: %s", name, res.ErrorReason))
	}

	secret := deterministicSessionSecret(name)
	issuedAt := fixtureNow
	validUntil := fixtureNow + tokenLifetimeSec
	token, err := ratify.IssueSessionToken(&bundle, res, "sess-"+name, issuedAt, validUntil, secret)
	if err != nil {
		panic(fmt.Errorf("build %s: IssueSessionToken: %w", name, err))
	}
	if mutateToken != nil {
		mutateToken(token)
	}

	// Capture canonical MAC-input bytes for cross-SDK byte-identicality.
	signBytes, err := ratify.SessionTokenSignBytes(token)
	if err != nil {
		panic(fmt.Errorf("build %s: SessionTokenSignBytes: %w", name, err))
	}

	// The streamed-turn challenge is signed only by the agent key (no chain).
	turnChallenge := deterministicChallenge("session_token:" + name + ":turn")
	turnAt := fixtureNow + 60 // one minute after bundle
	turnSig, err := ratify.SignChallenge(turnChallenge, turnAt, agent.priv)
	if err != nil {
		panic(fmt.Errorf("build %s: SignChallenge: %w", name, err))
	}
	if corruptChallengeSig {
		turnSig.Ed25519 = append([]byte(nil), turnSig.Ed25519...)
		turnSig.MLDSA65 = append([]byte(nil), turnSig.MLDSA65...)
		turnSig.Ed25519[len(turnSig.Ed25519)-1] ^= 0xFF
		turnSig.MLDSA65[len(turnSig.MLDSA65)-1] ^= 0xFF
	}

	verifyNow := turnAt + verifyOffsetSec
	verifierSecret := secret
	if overrideSecret != nil {
		verifierSecret = overrideSecret
	}
	result := ratify.VerifyStreamedTurn(
		token, verifierSecret, turnChallenge, turnAt, turnSig, nil, nil, 0,
		time.Unix(verifyNow, 0).UTC(),
	)

	return &fixture{
		Name:            name,
		Description:     desc,
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "session_token",
		Entities:        []entity{human, agent},
		Timestamps: map[string]int64{
			"issued_at":   issuedAt,
			"valid_until": validUntil,
			"verify_now":  verifyNow,
		},
		CertChain: []ratify.DelegationCert{cert},
		SessionToken: &sessionTokenFixture{
			// Capture the VERIFIER's secret (what a replaying conformance
			// harness should pass to VerifyStreamedTurn), not the issuance
			// secret. For the wrong-secret fixture these differ, and the
			// replay must observe the wrong-secret failure mode.
			SessionSecretHex: hex.EncodeToString(verifierSecret),
			Token:            token,
			Challenge:        turnChallenge,
			ChallengeAt:      turnAt,
			ChallengeSig:     turnSig,
			VerifyNow:        verifyNow,
		},
		Expected: expectedBlock{
			SessionTokenSignBytesHex: hex.EncodeToString(signBytes),
			SessionTokenMACHex:       hex.EncodeToString(token.MAC),
			StreamedTurn: &streamedTurnExpected{
				Valid:          result.Valid,
				IdentityStatus: result.IdentityStatus,
				HumanID:        result.HumanID,
				AgentID:        result.AgentID,
				GrantedScope:   result.GrantedScope,
				ErrorReason:    result.ErrorReason,
			},
		},
	}
}

func genSessionTokenValid() *fixture {
	return buildSessionTokenFixture(
		"session_token_valid",
		"v1.1 session_token happy path: verifier issues a token after a full "+
			"chain verify, then VerifyStreamedTurn accepts a fresh per-turn "+
			"challenge signed only by the agent key. HMAC over canonical bytes "+
			"and challenge signature both verify.",
		/*tokenLifetimeSec*/ 30*60,
		/*verifyOffsetSec*/ 0,
		nil, nil, false,
	)
}

func genRejectSessionTokenExpired() *fixture {
	return buildSessionTokenFixture(
		"reject_session_token_expired",
		"v1.1 session_token expired: verifier's clock is past valid_until. "+
			"VerifyStreamedTurn rejects with error_reason "+
			"session_token_invalid: session_token expired.",
		/*tokenLifetimeSec*/ 30, // very short
		/*verifyOffsetSec*/ 3600, // hour later
		nil, nil, false,
	)
}

func genRejectSessionTokenTampered() *fixture {
	return buildSessionTokenFixture(
		"reject_session_token_tampered",
		"v1.1 session_token tampered: the MAC is flipped after issuance. "+
			"VerifyStreamedTurn rejects with error_reason "+
			"session_token_invalid: session_token MAC invalid.",
		30*60, 0,
		func(t *ratify.SessionToken) {
			t.MAC = append([]byte(nil), t.MAC...)
			t.MAC[0] ^= 0xFF
		},
		nil, false,
	)
}

func genRejectSessionTokenWrongSecret() *fixture {
	otherSecret := deterministicSessionSecret("reject_session_token_wrong_secret:other")
	return buildSessionTokenFixture(
		"reject_session_token_wrong_secret",
		"v1.1 session_token wrong secret: the verifier uses a different session "+
			"secret than the one used at issuance. HMAC fails and the token is "+
			"rejected before any challenge-signature work.",
		30*60, 0, nil, otherSecret, false,
	)
}

func genRejectSessionTokenBadChallengeSig() *fixture {
	return buildSessionTokenFixture(
		"reject_session_token_bad_challenge_sig",
		"v1.1 session_token challenge signature tampered: the token MAC is "+
			"valid but the per-turn challenge signature fails. "+
			"VerifyStreamedTurn rejects with bad_challenge_sig.",
		30*60, 0, nil, nil, true,
	)
}

// ============================================================================
// Transaction-receipt fixtures (ROADMAP 3.1 / 3.3 — canonical envelope)
// ============================================================================

// buildTwoPartyReceipt is the shared setup for all receipt fixtures. It
// creates a buyer and a seller, each with a valid depth-1 delegation, and
// assembles a receipt with application-level terms. Callers can mutate the
// receipt before the fixture captures expected output via the `mutate`
// closure. If `mutate` is nil, the fixture captures the unmodified receipt.
func buildTwoPartyReceipt(
	name, desc string,
	mutate func(receipt *ratify.TransactionReceipt, buyerPriv, sellerPriv ratify.HybridPrivateKey),
) *fixture {
	human := newEntity("human_root", 0x01)
	buyer := newEntity("agent", 0x02)         // re-use standard agent seed
	seller := newEntity("intermediate", 0x03) // re-use intermediate seed

	buyerCert := buildCert(
		"00000000-0000-0000-0000-000000000030",
		human, buyer,
		[]string{ratify.ScopePaymentsSend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	sellerCert := buildCert(
		"00000000-0000-0000-0000-000000000031",
		human, seller,
		[]string{ratify.ScopeTransactSell},
		fixtureIssuedAt, fixtureExpiresAt,
	)

	buyerChallenge := deterministicChallenge("receipt:" + name + ":buyer")
	buyerBundle := buildBundle(buyer, []ratify.DelegationCert{buyerCert}, buyerChallenge, fixtureNow)
	sellerChallenge := deterministicChallenge("receipt:" + name + ":seller")
	sellerBundle := buildBundle(seller, []ratify.DelegationCert{sellerCert}, sellerChallenge, fixtureNow)

	terms := []byte(`{"resource":"gpu-a100-8x","hours":10,"currency":"USD","amount":500}`)
	receipt := &ratify.TransactionReceipt{
		Version:            ratify.ProtocolVersion,
		TransactionID:      "tx-" + name,
		CreatedAt:          fixtureNow,
		TermsSchemaURI:     "ratify://schemas/receipt/compute-purchase/v1",
		TermsCanonicalJSON: terms,
		Parties: []ratify.ReceiptParty{
			{PartyID: "party-buyer", Role: "buyer", AgentID: buyer.ID, AgentPubKey: buyer.PublicKey, ProofBundle: buyerBundle},
			{PartyID: "party-seller", Role: "seller", AgentID: seller.ID, AgentPubKey: seller.PublicKey, ProofBundle: sellerBundle},
		},
	}

	// Sign both parties.
	buyerSig, err := ratify.SignTransactionReceiptParty(receipt, "party-buyer", buyer.priv)
	if err != nil {
		panic(fmt.Errorf("buyer sign receipt %s: %w", name, err))
	}
	sellerSig, err := ratify.SignTransactionReceiptParty(receipt, "party-seller", seller.priv)
	if err != nil {
		panic(fmt.Errorf("seller sign receipt %s: %w", name, err))
	}
	receipt.PartySignatures = []ratify.ReceiptPartySignature{buyerSig, sellerSig}

	if mutate != nil {
		mutate(receipt, buyer.priv, seller.priv)
	}

	signBytes, err := ratify.TransactionReceiptSignBytes(receipt)
	if err != nil {
		panic(fmt.Errorf("receipt sign bytes %s: %w", name, err))
	}

	result := ratify.VerifyTransactionReceipt(receipt, ratify.VerifyReceiptOptions{
		Now: unixTime(fixtureNow),
	})

	return &fixture{
		Name:            name,
		Description:     desc,
		ProtocolVersion: ratify.ProtocolVersion,
		Kind:            "transaction_receipt",
		Entities:        []entity{human, buyer, seller},
		Timestamps:      map[string]int64{"created_at": fixtureNow, "verifier_now": fixtureNow},
		Receipt:         receipt,
		Expected: expectedBlock{
			ReceiptSignBytesHex: hex.EncodeToString(signBytes),
			ReceiptValid:        boolPtr(result.Valid),
			ReceiptErrorReason:  result.ErrorReason,
		},
	}
}

func genTransactionReceiptTwoPartyValid() *fixture {
	return buildTwoPartyReceipt(
		"transaction_receipt_two_party_valid",
		"v1.1 two-party receipt happy path: buyer + seller each sign the same "+
			"canonical signable over identical terms, schema URI, sorted party set, "+
			"and transaction ID. Both ProofBundles verify independently; both "+
			"party signatures verify over the atomic signable. Receipt is valid.",
		nil,
	)
}

func genRejectTransactionReceiptMissingPartySignature() *fixture {
	return buildTwoPartyReceipt(
		"reject_transaction_receipt_missing_party_signature",
		"v1.1 receipt missing seller's signature. "+
			"VerifyTransactionReceipt rejects with missing_party_signature.",
		func(r *ratify.TransactionReceipt, _, _ ratify.HybridPrivateKey) {
			r.PartySignatures = r.PartySignatures[:1] // drop seller sig
		},
	)
}

func genRejectTransactionReceiptPartyTampered() *fixture {
	return buildTwoPartyReceipt(
		"reject_transaction_receipt_party_tampered",
		"v1.1 receipt party tampered: seller's role changed after signing. "+
			"The canonical signable includes the full sorted party set, so "+
			"changing any party field invalidates every signature. "+
			"VerifyTransactionReceipt rejects with party_signature_invalid.",
		func(r *ratify.TransactionReceipt, _, _ ratify.HybridPrivateKey) {
			r.Parties[1].Role = "auditor"
		},
	)
}

func genRejectTransactionReceiptTermsTampered() *fixture {
	return buildTwoPartyReceipt(
		"reject_transaction_receipt_terms_tampered",
		"v1.1 receipt terms tampered: terms_canonical_json byte 0 is flipped "+
			"after signing. The canonical signable includes terms, so both "+
			"party signatures fail. VerifyTransactionReceipt rejects with "+
			"party_signature_invalid.",
		func(r *ratify.TransactionReceipt, _, _ ratify.HybridPrivateKey) {
			r.TermsCanonicalJSON = append([]byte(nil), r.TermsCanonicalJSON...)
			r.TermsCanonicalJSON[0] ^= 0xFF
		},
	)
}

func genRejectTransactionReceiptWrongPartyKey() *fixture {
	return buildTwoPartyReceipt(
		"reject_transaction_receipt_wrong_party_key",
		"v1.1 receipt wrong party key: seller's signature slot is signed by "+
			"the buyer's key. The seller's agent_pub_key in the party set does "+
			"not match the signing key, so verifyBoth fails. "+
			"VerifyTransactionReceipt rejects with party_signature_invalid.",
		func(r *ratify.TransactionReceipt, buyerPriv, _ ratify.HybridPrivateKey) {
			// Re-sign the seller slot with the buyer's key.
			wrongSig, err := ratify.SignTransactionReceiptParty(r, "party-seller", buyerPriv)
			if err != nil {
				panic(err)
			}
			r.PartySignatures[1] = wrongSig
		},
	)
}

// ============================================================================
// Registry + main
// ============================================================================

var fixtureGenerators = []func() *fixture{
	genHappyPathDepth1,
	genSessionBoundChallenge,
	genRejectSessionContextMismatch,
	genStreamBoundFirstTurn,
	genStreamBoundNextTurn,
	genRejectStreamReplay,
	genRejectStreamSeqSkip,
	genRejectStreamIDMismatch,
	genRejectStreamContextUnverifiable,
	genRejectChallengeForwarding,
	genHappyPathDepth2,
	genHappyPathDepth3,
	genScopeNarrowingDepth2Escalation,
	genRejectSensitiveWildcard,
	genRejectExpired,
	genRejectNotYetValid,
	genRejectStaleChallenge,
	genRejectFutureChallenge,
	genRejectTamperedScope,
	genRejectTamperedExpiry,
	genRejectWrongKey,
	genRejectBrokenChain,
	genRejectKeyMismatch,
	genRejectBadChallengeSig,
	genRejectEd25519OnlyCorrupted,
	genRejectMLDSA65OnlyCorrupted,
	genRejectChainTooDeep,
	genRevocationMiddleCert,
	genWildcardExpansionMeeting,
	genRejectUnknownScope,
	genRevocationListSignatureValid,
	genKeyRotationValid,
	genRejectKeyRotationTampered,
	genRevocationPushValid,
	genWitnessEntryValid,
	genSessionTokenValid,
	genRejectSessionTokenExpired,
	genRejectSessionTokenTampered,
	genRejectSessionTokenWrongSecret,
	genRejectSessionTokenBadChallengeSig,
	genSubDelegationAllowed,
	genSubDelegationDenied,
	genConstraintGeoCircleInside,
	genConstraintGeoCircleOutside,
	genConstraintGeoPolygonInside,
	genConstraintGeoBBoxDenied,
	genConstraintGeoBBoxAntimeridianInside,
	genConstraintTimeWindowDenied,
	genConstraintTimeWindowWrapInside,
	genConstraintMaxAmountExceeds,
	genConstraintMaxSpeedDenied,
	genConstraintMaxRateDenied,
	genConstraintUnknownDenied,
	genConstraintGeoCircleEquatorOrigin,
	genTransactionReceiptTwoPartyValid,
	genRejectTransactionReceiptMissingPartySignature,
	genRejectTransactionReceiptPartyTampered,
	genRejectTransactionReceiptTermsTampered,
	genRejectTransactionReceiptWrongPartyKey,
	genNoExpiryCert,
	genPresenceRepresentAllowed,
	genRejectPresenceSensitiveWildcard,
}

// unixTime builds a fixed-instant time.Time for use as ratify.VerifyOptions.Now.
// Using time.Unix(unix, 0).UTC() so the instant is timezone-independent.
func unixTime(unix int64) time.Time {
	return time.Unix(unix, 0).UTC()
}

func main() {
	outDir := flag.String("out", "testvectors/v1", "output directory for fixtures")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", *outDir, err)
		os.Exit(1)
	}

	written := 0
	for _, gen := range fixtureGenerators {
		fx := gen()
		if err := writeFixture(*outDir, fx); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", fx.Name, err)
			os.Exit(1)
		}
		fmt.Printf("  ✓ %s\n", fx.Name)
		written++
	}
	fmt.Printf("\nGenerated %d fixtures in %s\n", written, *outDir)

	// Cross-SDK byte-equivalence vectors (SPEC §17.5–§17.6). Single file,
	// outside the per-fixture-file corpus, loaded directly by every SDK's
	// conformance test.
	if err := generateCrossSDKVectors(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "generate cross_sdk_vectors.json: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ cross_sdk_vectors.json (alpha.10 byte-equivalence corpus)\n")
}

func writeFixture(dir string, fx *fixture) error {
	data, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return err
	}
	// Ensure trailing newline for POSIX-friendly diffs.
	data = append(data, '\n')
	path := filepath.Join(dir, fx.Name+".json")
	return os.WriteFile(path, data, 0o644)
}
