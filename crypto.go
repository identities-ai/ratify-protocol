package ratify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ============================================================================
// Hybrid keypairs
//
// Every signed object in Ratify v1 carries a pair of signatures — one Ed25519
// and one ML-DSA-65 (FIPS 204). Both MUST verify for the signature to be
// accepted. This provides:
//
//   - Classical defense in depth: a compromise of Ed25519 alone (e.g. a new
//     algebraic attack) does not forge valid hybrid signatures.
//   - Quantum resistance: ML-DSA-65 is lattice-based (Module-LWE / Module-SIS
//     assumptions) and believed secure against known quantum algorithms.
//   - Forward security of today's records: "harvest now, decrypt later"
//     attacks against archived bundles cannot forge new valid ones even
//     after a cryptographically-relevant quantum computer arrives.
//
// Private keys never travel on the wire. They are kept on-device by the
// principal or inside the agent's process memory.
// ============================================================================

// HybridPrivateKey holds both component private keys. Both are required to
// sign. The public component is derived by Public() and matches what goes
// into a HybridPublicKey.
type HybridPrivateKey struct {
	Ed25519 ed25519.PrivateKey  // 64 bytes (seed || pub)
	MLDSA65 *mldsa65.PrivateKey // internal representation
}

// Public returns the HybridPublicKey component of this private keypair.
func (k HybridPrivateKey) Public() HybridPublicKey {
	edPub, _ := k.Ed25519.Public().(ed25519.PublicKey)
	mlPubRaw, _ := k.MLDSA65.Public().(*mldsa65.PublicKey).MarshalBinary()
	return HybridPublicKey{
		Ed25519: edPub,
		MLDSA65: mlPubRaw,
	}
}

// GenerateHybridKeypair produces a fresh hybrid keypair from secure randomness.
// The two component keys are drawn from independent entropy streams; knowledge
// of one keypair's private material reveals nothing about the other's.
func GenerateHybridKeypair() (HybridPublicKey, HybridPrivateKey, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return HybridPublicKey{}, HybridPrivateKey{}, fmt.Errorf("generating Ed25519 key: %w", err)
	}
	mlPub, mlPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return HybridPublicKey{}, HybridPrivateKey{}, fmt.Errorf("generating ML-DSA-65 key: %w", err)
	}
	mlPubRaw, err := mlPub.MarshalBinary()
	if err != nil {
		return HybridPublicKey{}, HybridPrivateKey{}, fmt.Errorf("marshaling ML-DSA-65 pubkey: %w", err)
	}
	return HybridPublicKey{
			Ed25519: edPub,
			MLDSA65: mlPubRaw,
		}, HybridPrivateKey{
			Ed25519: edPriv,
			MLDSA65: mlPriv,
		}, nil
}

// HybridKeypairFromSeeds derives a hybrid keypair deterministically from two
// 32-byte seeds. For test vector generation. Production code SHOULD use
// GenerateHybridKeypair (which reads from the OS RNG).
func HybridKeypairFromSeeds(edSeed, mlSeed [32]byte) (HybridPublicKey, HybridPrivateKey, error) {
	edPriv := ed25519.NewKeyFromSeed(edSeed[:])
	edPub := edPriv.Public().(ed25519.PublicKey)

	mlPub, mlPriv := mldsa65.NewKeyFromSeed(&mlSeed)
	mlPubRaw, err := mlPub.MarshalBinary()
	if err != nil {
		return HybridPublicKey{}, HybridPrivateKey{}, fmt.Errorf("marshaling ML-DSA-65 pubkey: %w", err)
	}
	return HybridPublicKey{
			Ed25519: edPub,
			MLDSA65: mlPubRaw,
		}, HybridPrivateKey{
			Ed25519: edPriv,
			MLDSA65: mlPriv,
		}, nil
}

// GenerateHumanRootKeypair creates a fresh HumanRoot identity from secure
// randomness, returning the public HumanRoot and the hybrid private key
// (which must stay on-device).
func GenerateHumanRootKeypair() (*HumanRoot, HybridPrivateKey, error) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		return nil, HybridPrivateKey{}, err
	}
	return &HumanRoot{
		ID:        DeriveID(pub),
		PublicKey: pub,
		CreatedAt: time.Now().Unix(),
	}, priv, nil
}

// GenerateAgentKeypair creates a fresh AgentIdentity with a hybrid keypair.
func GenerateAgentKeypair(name, agentType string) (*AgentIdentity, HybridPrivateKey, error) {
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		return nil, HybridPrivateKey{}, err
	}
	return &AgentIdentity{
		ID:        DeriveID(pub),
		PublicKey: pub,
		Name:      name,
		AgentType: agentType,
		CreatedAt: time.Now().Unix(),
	}, priv, nil
}

// DeriveID computes the canonical ID for a hybrid public key as
// hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16]).
//
// 128-bit collision space is sufficient for agent/human identifiers at the
// expected scale; birthday bound is 2^64.
func DeriveID(pub HybridPublicKey) string {
	h := sha256.New()
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum[:16])
}

// ============================================================================
// Signing and verification
//
// Each sign operation produces a HybridSignature by signing the same canonical
// byte sequence independently with both the Ed25519 and ML-DSA-65 private
// components. Each verify operation checks BOTH component signatures against
// the same canonical bytes and the corresponding public components; either
// failure rejects the entire signature.
//
// ML-DSA signing in v1 uses the deterministic mode (FIPS 204 §3.4 without
// additional randomness). This gives:
//   - Reproducible test vectors: regeneration of fixtures produces byte-
//     identical output.
//   - Deterministic audit trails: a principal replaying the same cert
//     parameters produces the same signature bytes.
// Future versions may add a hedged-randomization option for side-channel
// hardening in hostile environments.
// ============================================================================

// signBoth signs msg with both component private keys and returns a
// HybridSignature. The msg bytes MUST be derived from canonical JSON (for
// the cert and revocation paths) or the raw challenge concatenation (for
// the challenge path) — nothing else.
func signBoth(msg []byte, priv HybridPrivateKey) (HybridSignature, error) {
	edSig := ed25519.Sign(priv.Ed25519, msg)

	mlSig := make([]byte, mldsa65.SignatureSize)
	// SignTo(sk, msg, ctx, randomized, sig): randomized=false for deterministic
	// signing; ctx=nil for no domain separator in v1.
	if err := mldsa65.SignTo(priv.MLDSA65, msg, nil, false, mlSig); err != nil {
		return HybridSignature{}, fmt.Errorf("ML-DSA-65 sign: %w", err)
	}
	return HybridSignature{Ed25519: edSig, MLDSA65: mlSig}, nil
}

// verifyBoth checks a HybridSignature against a HybridPublicKey. Returns nil
// iff both component signatures verify against their respective public
// components over the same msg. Any failure of either component causes the
// entire verification to fail (fail-closed).
func verifyBoth(msg []byte, sig HybridSignature, pub HybridPublicKey) error {
	if len(pub.Ed25519) != ed25519.PublicKeySize {
		return fmt.Errorf("Ed25519 public key wrong length: %d", len(pub.Ed25519))
	}
	if len(pub.MLDSA65) != mldsa65.PublicKeySize {
		return fmt.Errorf("ML-DSA-65 public key wrong length: %d", len(pub.MLDSA65))
	}
	if len(sig.Ed25519) != ed25519.SignatureSize {
		return fmt.Errorf("Ed25519 signature wrong length: %d", len(sig.Ed25519))
	}
	if len(sig.MLDSA65) != mldsa65.SignatureSize {
		return fmt.Errorf("ML-DSA-65 signature wrong length: %d", len(sig.MLDSA65))
	}

	if !ed25519.Verify(pub.Ed25519, msg, sig.Ed25519) {
		return fmt.Errorf("Ed25519 signature invalid")
	}

	var mlPub mldsa65.PublicKey
	if err := mlPub.UnmarshalBinary(pub.MLDSA65); err != nil {
		return fmt.Errorf("ML-DSA-65 public key malformed: %w", err)
	}
	if !mldsa65.Verify(&mlPub, msg, nil, sig.MLDSA65) {
		return fmt.Errorf("ML-DSA-65 signature invalid")
	}
	return nil
}

// IssueDelegation signs a DelegationCert with the issuer's hybrid private key.
// The cert must have all fields set except Signature before calling.
//
// Normalizes Constraints from nil to []Constraint{} so the outer cert JSON
// serializes as `"constraints":[]` rather than `"constraints":null`,
// matching the canonical wire format and satisfying strict deserializers in
// TypeScript/Python/Rust SDKs.
func IssueDelegation(cert *DelegationCert, issuerPriv HybridPrivateKey) error {
	if cert.Constraints == nil {
		cert.Constraints = []Constraint{}
	}
	data, err := delegationSignBytes(cert)
	if err != nil {
		return fmt.Errorf("serializing delegation for signing: %w", err)
	}
	sig, err := signBoth(data, issuerPriv)
	if err != nil {
		return fmt.Errorf("signing delegation: %w", err)
	}
	cert.Signature = sig
	return nil
}

// VerifyDelegationSignature verifies both component signatures on a
// DelegationCert against the declared IssuerPubKey. Returns nil iff both
// verify.
func VerifyDelegationSignature(cert *DelegationCert) error {
	data, err := delegationSignBytes(cert)
	if err != nil {
		return fmt.Errorf("serializing delegation for verification: %w", err)
	}
	return verifyBoth(data, cert.Signature, cert.IssuerPubKey)
}

// SignChallenge signs a challenge to prove agent liveness. sign_data =
// challenge_bytes || big-endian uint64(unix_timestamp). Both component
// signatures are produced. Use SignChallengeWithSessionContext for v1.1
// verifier/session-bound challenges.
func SignChallenge(challenge []byte, ts int64, agentPriv HybridPrivateKey) (HybridSignature, error) {
	return signBoth(challengeSignBytes(challenge, ts, nil, nil, 0), agentPriv)
}

// SignChallengeWithSessionContext signs a v1.1 session-bound challenge.
// sessionContext MUST be exactly 32 bytes and is appended to the v1 challenge
// signable bytes: challenge || big-endian uint64(ts) || session_context.
func SignChallengeWithSessionContext(challenge []byte, ts int64, sessionContext []byte, agentPriv HybridPrivateKey) (HybridSignature, error) {
	if len(sessionContext) != 32 {
		return HybridSignature{}, fmt.Errorf("session_context must be 32 bytes, got %d", len(sessionContext))
	}
	return signBoth(challengeSignBytes(challenge, ts, sessionContext, nil, 0), agentPriv)
}

// SignChallengeWithStream signs a v1.1 stream-bound challenge. sessionContext
// may be nil (stream-only binding) or exactly 32 bytes (both session- and
// stream-bound). streamID MUST be exactly 32 bytes; streamSeq MUST be ≥1. The
// signable bytes append streamID and big-endian int64(streamSeq) after the
// session_context position.
func SignChallengeWithStream(challenge []byte, ts int64, sessionContext, streamID []byte, streamSeq int64, agentPriv HybridPrivateKey) (HybridSignature, error) {
	if len(sessionContext) != 0 && len(sessionContext) != 32 {
		return HybridSignature{}, fmt.Errorf("session_context must be 32 bytes, got %d", len(sessionContext))
	}
	if len(streamID) != 32 {
		return HybridSignature{}, fmt.Errorf("stream_id must be 32 bytes, got %d", len(streamID))
	}
	if streamSeq < 1 {
		return HybridSignature{}, fmt.Errorf("stream_seq must be >=1, got %d", streamSeq)
	}
	return signBoth(challengeSignBytes(challenge, ts, sessionContext, streamID, streamSeq), agentPriv)
}

// VerifyChallengeSignature checks the hybrid challenge signature.
func VerifyChallengeSignature(challenge []byte, ts int64, sig HybridSignature, agentPub HybridPublicKey) error {
	return verifyBoth(challengeSignBytes(challenge, ts, nil, nil, 0), sig, agentPub)
}

// VerifyChallengeSignatureWithSessionContext checks a v1.1 session-bound
// challenge signature.
func VerifyChallengeSignatureWithSessionContext(challenge []byte, ts int64, sessionContext []byte, sig HybridSignature, agentPub HybridPublicKey) error {
	if len(sessionContext) != 32 {
		return fmt.Errorf("session_context must be 32 bytes, got %d", len(sessionContext))
	}
	return verifyBoth(challengeSignBytes(challenge, ts, sessionContext, nil, 0), sig, agentPub)
}

// VerifyChallengeSignatureWithStream checks a v1.1 stream-bound challenge
// signature. sessionContext may be nil or 32 bytes; streamID MUST be 32 bytes;
// streamSeq MUST be ≥1.
func VerifyChallengeSignatureWithStream(challenge []byte, ts int64, sessionContext, streamID []byte, streamSeq int64, sig HybridSignature, agentPub HybridPublicKey) error {
	if len(sessionContext) != 0 && len(sessionContext) != 32 {
		return fmt.Errorf("session_context must be 32 bytes, got %d", len(sessionContext))
	}
	if len(streamID) != 32 {
		return fmt.Errorf("stream_id must be 32 bytes, got %d", len(streamID))
	}
	if streamSeq < 1 {
		return fmt.Errorf("stream_seq must be >=1, got %d", streamSeq)
	}
	return verifyBoth(challengeSignBytes(challenge, ts, sessionContext, streamID, streamSeq), sig, agentPub)
}

// IssueRevocationList signs a RevocationList with the issuer's hybrid private
// key. Both component signatures are produced.
func IssueRevocationList(list *RevocationList, issuerPriv HybridPrivateKey) error {
	data, err := revocationSignBytes(list)
	if err != nil {
		return fmt.Errorf("serializing revocation list for signing: %w", err)
	}
	sig, err := signBoth(data, issuerPriv)
	if err != nil {
		return fmt.Errorf("signing revocation list: %w", err)
	}
	list.Signature = sig
	return nil
}

// VerifyRevocationList verifies both component signatures on a RevocationList
// against the issuer's hybrid public key.
func VerifyRevocationList(list *RevocationList, issuerPub HybridPublicKey) error {
	data, err := revocationSignBytes(list)
	if err != nil {
		return fmt.Errorf("serializing revocation list for verification: %w", err)
	}
	return verifyBoth(data, list.Signature, issuerPub)
}

// IssueKeyRotationStatement signs a root-key rotation statement with both the
// old and new private keys. The old signature endorses the new key; the new
// signature proves possession. Both signatures cover identical canonical bytes.
func IssueKeyRotationStatement(stmt *KeyRotationStatement, oldPriv, newPriv HybridPrivateKey) error {
	data, err := keyRotationSignBytes(stmt)
	if err != nil {
		return fmt.Errorf("serializing key rotation for signing: %w", err)
	}
	oldSig, err := signBoth(data, oldPriv)
	if err != nil {
		return fmt.Errorf("signing key rotation with old key: %w", err)
	}
	newSig, err := signBoth(data, newPriv)
	if err != nil {
		return fmt.Errorf("signing key rotation with new key: %w", err)
	}
	stmt.SignatureOld = oldSig
	stmt.SignatureNew = newSig
	return nil
}

// VerifyKeyRotationStatement verifies key continuity, key possession, and
// structural ID/pubkey consistency for a KeyRotationStatement.
func VerifyKeyRotationStatement(stmt *KeyRotationStatement) error {
	if stmt.Version != ProtocolVersion {
		return fmt.Errorf("version_mismatch: unsupported version %d", stmt.Version)
	}
	if stmt.OldID != DeriveID(stmt.OldPubKey) {
		return fmt.Errorf("old_id does not match old_pub_key")
	}
	if stmt.NewID != DeriveID(stmt.NewPubKey) {
		return fmt.Errorf("new_id does not match new_pub_key")
	}
	if stmt.OldID == stmt.NewID {
		return fmt.Errorf("old_id and new_id must differ")
	}
	if !isKeyRotationReasonKnown(stmt.Reason) {
		return fmt.Errorf("unknown key rotation reason: %s", stmt.Reason)
	}
	data, err := keyRotationSignBytes(stmt)
	if err != nil {
		return fmt.Errorf("serializing key rotation for verification: %w", err)
	}
	if err := verifyBoth(data, stmt.SignatureOld, stmt.OldPubKey); err != nil {
		return fmt.Errorf("old signature invalid: %w", err)
	}
	if err := verifyBoth(data, stmt.SignatureNew, stmt.NewPubKey); err != nil {
		return fmt.Errorf("new signature invalid: %w", err)
	}
	return nil
}

// GenerateChallenge returns 32 cryptographically random bytes from the OS RNG.
func GenerateChallenge() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	return b, nil
}

// DelegationSignBytes returns the canonical byte sequence that is signed to
// produce DelegationCert.Signature (for both algorithm components). Other-
// language implementations MUST produce identical bytes for any given cert,
// or signatures will not verify across implementations.
func DelegationSignBytes(cert *DelegationCert) ([]byte, error) {
	return delegationSignBytes(cert)
}

// ChallengeSignBytes returns the canonical byte sequence that is signed to
// produce ProofBundle.ChallengeSig (for both algorithm components). Format:
// challenge || big-endian uint64(ts).
func ChallengeSignBytes(challenge []byte, ts int64) []byte {
	return challengeSignBytes(challenge, ts, nil, nil, 0)
}

// ChallengeSignBytesWithSessionContext returns the v1.1 session-bound
// challenge signable bytes:
// challenge || big-endian uint64(ts) || session_context.
func ChallengeSignBytesWithSessionContext(challenge []byte, ts int64, sessionContext []byte) []byte {
	return challengeSignBytes(challenge, ts, sessionContext, nil, 0)
}

// ChallengeSignBytesWithStream returns the v1.1 stream-bound challenge
// signable bytes. sessionContext may be nil or 32 bytes; streamID is 32 bytes;
// streamSeq is appended as big-endian int64. Layout:
//
//	challenge || big-endian uint64(ts) || [session_context] || stream_id || big-endian int64(stream_seq)
func ChallengeSignBytesWithStream(challenge []byte, ts int64, sessionContext, streamID []byte, streamSeq int64) []byte {
	return challengeSignBytes(challenge, ts, sessionContext, streamID, streamSeq)
}

// RevocationSignBytes returns the canonical byte sequence that is signed to
// produce RevocationList.Signature.
func RevocationSignBytes(list *RevocationList) ([]byte, error) {
	return revocationSignBytes(list)
}

// KeyRotationSignBytes returns the canonical bytes signed by both old and new
// keys in a KeyRotationStatement.
func KeyRotationSignBytes(stmt *KeyRotationStatement) ([]byte, error) {
	return keyRotationSignBytes(stmt)
}

// SessionTokenSignBytes returns the canonical byte sequence that the verifier
// HMACs with session_secret to produce SessionToken.MAC. The signable excludes
// MAC itself — signatures (or MACs) cannot cover themselves.
func SessionTokenSignBytes(token *SessionToken) ([]byte, error) {
	return sessionTokenSignBytes(token)
}

// ChainHash returns the canonical 32-byte hash of a delegation chain, defined
// as SHA-256 of the concatenated delegationSignBytes of each cert in order.
// Used as a stable identity for a verified chain inside SessionToken so a cert
// rotation invalidates any token issued against the old chain.
func ChainHash(chain []DelegationCert) ([]byte, error) {
	h := sha256.New()
	for i := range chain {
		b, err := delegationSignBytes(&chain[i])
		if err != nil {
			return nil, fmt.Errorf("cert %d: %w", i, err)
		}
		h.Write(b)
	}
	return h.Sum(nil), nil
}

// IssueSessionToken constructs a SessionToken from a verified bundle and the
// verifier's session parameters. The caller MUST only invoke this after
// Verify(bundle, opts) returned Valid=true — nothing in this function re-
// checks the chain. sessionSecret MUST be a cryptographically random secret
// (≥32 bytes recommended) known only to the verifier.
func IssueSessionToken(bundle *ProofBundle, result VerifyResult, sessionID string, issuedAt, validUntil int64, sessionSecret []byte) (*SessionToken, error) {
	if len(sessionSecret) == 0 {
		return nil, fmt.Errorf("session_secret must not be empty")
	}
	if sessionID == "" {
		return nil, fmt.Errorf("session_id must not be empty")
	}
	if validUntil <= issuedAt {
		return nil, fmt.Errorf("valid_until must be strictly after issued_at")
	}
	chainHash, err := ChainHash(bundle.Delegations)
	if err != nil {
		return nil, fmt.Errorf("computing chain hash: %w", err)
	}
	// Granted scope is captured in sorted order so the token's canonical
	// bytes are deterministic regardless of how the verifier returned the
	// intersection.
	scope := append([]string(nil), result.GrantedScope...)
	sort.Strings(scope)
	token := &SessionToken{
		Version:      ProtocolVersion,
		SessionID:    sessionID,
		AgentID:      result.AgentID,
		AgentPubKey:  bundle.AgentPubKey,
		HumanID:      result.HumanID,
		GrantedScope: scope,
		IssuedAt:     issuedAt,
		ValidUntil:   validUntil,
		ChainHash:    chainHash,
	}
	signable, err := sessionTokenSignBytes(token)
	if err != nil {
		return nil, fmt.Errorf("serializing session token for MAC: %w", err)
	}
	m := hmac.New(sha256.New, sessionSecret)
	m.Write(signable)
	token.MAC = m.Sum(nil)
	return token, nil
}

// verifierContextSignable is the canonical-byte representation of the
// fields in `VerifierContext` that are hashed into a PolicyVerdict. The
// `InvocationsInWindow` callback is excluded — closures don't serialize.
// Field order matches alphabetical JSON key order.
type verifierContextSignable struct {
	CurrentAltM       float64 `json:"current_alt_m"`
	CurrentLat        float64 `json:"current_lat"`
	CurrentLon        float64 `json:"current_lon"`
	CurrentSpeedMps   float64 `json:"current_speed_mps"`
	HasAmount         bool    `json:"has_amount"`
	HasLocation       bool    `json:"has_location"`
	HasSpeed          bool    `json:"has_speed"`
	RequestedAmount   float64 `json:"requested_amount"`
	RequestedCurrency string  `json:"requested_currency"`
}

// VerifierContextHash returns the SHA-256 of the canonical-byte
// representation of a VerifierContext (SPEC §17.6). Used as the
// `ContextHash` on a PolicyVerdict so a verdict cached for one context
// never accidentally applies to another (different country, different
// amount tier, etc).
func VerifierContextHash(ctx VerifierContext) ([]byte, error) {
	// Normalize: when a Has* flag is false the corresponding numeric fields
	// MUST be zeroed before hashing. Other SDKs derive Has* from field
	// presence (Optional/None/undefined → 0), so a caller-set non-zero
	// number with Has*=false would produce canonical bytes no non-Go SDK
	// could reproduce — silently breaking cross-SDK PolicyVerdict
	// portability. The Has* flag is the authoritative signal; numeric
	// fields are meaningful only when their flag is true.
	s := verifierContextSignable{
		HasAmount:         ctx.HasAmount,
		HasLocation:       ctx.HasLocation,
		HasSpeed:          ctx.HasSpeed,
		RequestedCurrency: ctx.RequestedCurrency,
	}
	if ctx.HasLocation {
		s.CurrentLat = ctx.CurrentLat
		s.CurrentLon = ctx.CurrentLon
		s.CurrentAltM = ctx.CurrentAltM
	}
	if ctx.HasSpeed {
		s.CurrentSpeedMps = ctx.CurrentSpeedMps
	}
	if ctx.HasAmount {
		s.RequestedAmount = ctx.RequestedAmount
	} else {
		s.RequestedCurrency = ""
	}
	data, err := CanonicalJSON(s)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing verifier context: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// policyVerdictSignable is the canonical subset of PolicyVerdict that is
// HMAC-authenticated. Field order is alphabetical by JSON key.
type policyVerdictSignable struct {
	AgentID     string `json:"agent_id"`
	Allow       bool   `json:"allow"`
	ContextHash []byte `json:"context_hash"`
	IssuedAt    int64  `json:"issued_at"`
	Scope       string `json:"scope"`
	ValidUntil  int64  `json:"valid_until"`
	VerdictID   string `json:"verdict_id"`
	Version     int    `json:"version"`
}

func policyVerdictSignBytes(v *PolicyVerdict) ([]byte, error) {
	s := policyVerdictSignable{
		AgentID:     v.AgentID,
		Allow:       v.Allow,
		ContextHash: v.ContextHash,
		IssuedAt:    v.IssuedAt,
		Scope:       v.Scope,
		ValidUntil:  v.ValidUntil,
		VerdictID:   v.VerdictID,
		Version:     v.Version,
	}
	return CanonicalJSON(s)
}

// PolicyVerdictSignBytes returns the canonical byte sequence over which a
// PolicyVerdict's MAC is computed.
func PolicyVerdictSignBytes(v *PolicyVerdict) ([]byte, error) {
	return policyVerdictSignBytes(v)
}

// IssuePolicyVerdict constructs and HMAC-binds a PolicyVerdict. Typically
// called by a commercial policy backend: it makes the allow/deny decision,
// stamps the verdict, and hands it to the verifier — which can then accept
// the verdict locally for the rest of `validUntil` without re-calling the
// backend. `policySecret` MUST be cryptographically random (≥32 bytes) and
// private to the issuing service.
func IssuePolicyVerdict(
	verdictID, agentID, scope string,
	allow bool,
	contextHash []byte,
	issuedAt, validUntil int64,
	policySecret []byte,
) (*PolicyVerdict, error) {
	if len(policySecret) == 0 {
		return nil, fmt.Errorf("policy_secret must not be empty")
	}
	if verdictID == "" {
		return nil, fmt.Errorf("verdict_id must not be empty")
	}
	if agentID == "" {
		return nil, fmt.Errorf("agent_id must not be empty")
	}
	if scope == "" {
		return nil, fmt.Errorf("scope must not be empty")
	}
	if len(contextHash) != sha256.Size {
		return nil, fmt.Errorf("context_hash must be %d bytes, got %d", sha256.Size, len(contextHash))
	}
	if validUntil <= issuedAt {
		return nil, fmt.Errorf("valid_until must be strictly after issued_at")
	}
	v := &PolicyVerdict{
		Version:     ProtocolVersion,
		VerdictID:   verdictID,
		AgentID:     agentID,
		Scope:       scope,
		Allow:       allow,
		ContextHash: contextHash,
		IssuedAt:    issuedAt,
		ValidUntil:  validUntil,
	}
	signable, err := policyVerdictSignBytes(v)
	if err != nil {
		return nil, fmt.Errorf("serializing policy verdict for MAC: %w", err)
	}
	m := hmac.New(sha256.New, policySecret)
	m.Write(signable)
	v.MAC = m.Sum(nil)
	return v, nil
}

// VerifyPolicyVerdict checks a PolicyVerdict's HMAC against `policySecret`,
// confirms the validity window contains `now`, and confirms the verdict's
// (agent_id, scope, context_hash) tuple matches the caller's expectation.
// Returns nil iff everything matches AND `verdict.Allow == true`. A
// verdict whose MAC is fresh but whose `Allow == false` returns a
// descriptive "policy_verdict_denied" error — explicit cached deny.
func VerifyPolicyVerdict(
	v *PolicyVerdict,
	policySecret []byte,
	expectedAgentID, expectedScope string,
	expectedContextHash []byte,
	now time.Time,
) error {
	if v == nil {
		return fmt.Errorf("nil policy verdict")
	}
	if len(policySecret) == 0 {
		return fmt.Errorf("policy_secret must not be empty")
	}
	if v.Version != ProtocolVersion {
		return fmt.Errorf("version_mismatch: unsupported version %d", v.Version)
	}
	if len(v.ContextHash) != sha256.Size {
		return fmt.Errorf("context_hash must be %d bytes, got %d", sha256.Size, len(v.ContextHash))
	}
	if len(v.MAC) != sha256.Size {
		return fmt.Errorf("mac must be %d bytes, got %d", sha256.Size, len(v.MAC))
	}
	signable, err := policyVerdictSignBytes(v)
	if err != nil {
		return fmt.Errorf("serializing policy verdict for MAC check: %w", err)
	}
	m := hmac.New(sha256.New, policySecret)
	m.Write(signable)
	if !hmac.Equal(v.MAC, m.Sum(nil)) {
		return fmt.Errorf("policy_verdict MAC invalid")
	}
	ts := now.Unix()
	if ts < v.IssuedAt {
		return fmt.Errorf("policy_verdict not yet valid")
	}
	if ts > v.ValidUntil {
		return fmt.Errorf("policy_verdict expired")
	}
	if v.AgentID != expectedAgentID {
		return fmt.Errorf("policy_verdict agent_id mismatch")
	}
	if v.Scope != expectedScope {
		return fmt.Errorf("policy_verdict scope mismatch")
	}
	if !bytes.Equal(v.ContextHash, expectedContextHash) {
		return fmt.Errorf("policy_verdict context_hash mismatch")
	}
	if !v.Allow {
		return fmt.Errorf("policy_verdict_denied: cached deny for scope %q", v.Scope)
	}
	return nil
}

// VerifySessionToken checks a SessionToken's HMAC against sessionSecret and
// its validity window against now. Returns nil iff the MAC matches and the
// token is within [IssuedAt, ValidUntil]. This does NOT verify a challenge
// signature; callers who need to verify a streamed turn use VerifyStreamedTurn.
func VerifySessionToken(token *SessionToken, sessionSecret []byte, now time.Time) error {
	if len(sessionSecret) == 0 {
		return fmt.Errorf("session_secret must not be empty")
	}
	if token.Version != ProtocolVersion {
		return fmt.Errorf("version_mismatch: unsupported version %d", token.Version)
	}
	if len(token.ChainHash) != sha256.Size {
		return fmt.Errorf("chain_hash must be %d bytes, got %d", sha256.Size, len(token.ChainHash))
	}
	if len(token.MAC) != sha256.Size {
		return fmt.Errorf("mac must be %d bytes, got %d", sha256.Size, len(token.MAC))
	}
	signable, err := sessionTokenSignBytes(token)
	if err != nil {
		return fmt.Errorf("serializing session token for MAC check: %w", err)
	}
	m := hmac.New(sha256.New, sessionSecret)
	m.Write(signable)
	want := m.Sum(nil)
	if !hmac.Equal(token.MAC, want) {
		return fmt.Errorf("session_token MAC invalid")
	}
	ts := now.Unix()
	if ts < token.IssuedAt {
		return fmt.Errorf("session_token not yet valid")
	}
	if ts > token.ValidUntil {
		return fmt.Errorf("session_token expired")
	}
	return nil
}

// ============================================================================
// Canonical JSON serialization
//
// Signable bytes follow RFC 8785 (JSON Canonicalization Scheme) with one
// project-specific convention: byte arrays are encoded as base64-standard
// strings (Go's default for []byte). Rules enforced below:
//
//   - Object members serialized in lexicographic key order. We achieve this
//     by declaring signable structs with fields in alphabetical order —
//     Go's encoding/json preserves declaration order.
//   - No insignificant whitespace.
//   - SetEscapeHTML(false): do NOT escape '<', '>', '&'.
//   - Numbers serialized as shortest decimal representation.
//   - UTF-8 encoding, minimal string escaping per RFC 8259.
//   - U+2028 / U+2029 escape as \u2028 / \u2029 (matches Go's encoding/json).
//
// Other-language implementations MUST produce byte-identical output. The
// canonical form of a HybridPublicKey is:
//
//	{"ed25519":"<base64>","ml_dsa_65":"<base64>"}
//
// (keys in lex order, byte arrays as base64-standard strings).
// ============================================================================

// CanonicalJSON marshals v into canonical bytes per the rules above. The
// single chokepoint for canonical serialization; all three signable-bytes
// helpers route through it.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// delegationSignable is the canonical signable subset of DelegationCert.
// Field order matches JSON key alphabetical order for determinism.
type delegationSignable struct {
	CertID        string          `json:"cert_id"`
	Constraints   []Constraint    `json:"constraints"`
	ExpiresAt     int64           `json:"expires_at"`
	IssuedAt      int64           `json:"issued_at"`
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	Scope         []string        `json:"scope"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Version       int             `json:"version"`
}

func delegationSignBytes(cert *DelegationCert) ([]byte, error) {
	// Canonical form requires constraints to be serialized as [] when empty,
	// never null. This ensures cross-issuer determinism.
	constraints := cert.Constraints
	if constraints == nil {
		constraints = []Constraint{}
	}
	s := delegationSignable{
		CertID:        cert.CertID,
		Constraints:   constraints,
		ExpiresAt:     cert.ExpiresAt,
		IssuedAt:      cert.IssuedAt,
		IssuerID:      cert.IssuerID,
		IssuerPubKey:  cert.IssuerPubKey,
		Scope:         cert.Scope,
		SubjectID:     cert.SubjectID,
		SubjectPubKey: cert.SubjectPubKey,
		Version:       cert.Version,
	}
	return CanonicalJSON(s)
}

func challengeSignBytes(challenge []byte, ts int64, sessionContext, streamID []byte, streamSeq int64) []byte {
	// sign_data = challenge || big-endian uint64(timestamp) ||
	// optional 32-byte session_context ||
	// optional (32-byte stream_id || big-endian int64(stream_seq))
	//
	// Raw binary concatenation, NOT JSON. The challenge is already opaque
	// random bytes; JSON wrapping would add weight without adding security.
	// Order matters: session_context precedes stream extension so the signable
	// bytes remain well-defined regardless of which optional bindings are in
	// play. A 72-byte signable (session-only), an 80-byte signable (stream-
	// only), and a 112-byte signable (both) are unambiguously distinct.
	streamLen := 0
	if len(streamID) > 0 {
		streamLen = len(streamID) + 8
	}
	buf := make([]byte, len(challenge)+8+len(sessionContext)+streamLen)
	off := 0
	copy(buf[off:], challenge)
	off += len(challenge)
	binary.BigEndian.PutUint64(buf[off:], uint64(ts))
	off += 8
	copy(buf[off:], sessionContext)
	off += len(sessionContext)
	if streamLen > 0 {
		copy(buf[off:], streamID)
		off += len(streamID)
		binary.BigEndian.PutUint64(buf[off:], uint64(streamSeq))
	}
	return buf
}

// revocationSignable is the canonical subset of RevocationList for signing.
type revocationSignable struct {
	IssuerID     string   `json:"issuer_id"`
	RevokedCerts []string `json:"revoked_certs"`
	UpdatedAt    int64    `json:"updated_at"`
}

func revocationSignBytes(list *RevocationList) ([]byte, error) {
	s := revocationSignable{
		IssuerID:     list.IssuerID,
		RevokedCerts: list.RevokedCerts,
		UpdatedAt:    list.UpdatedAt,
	}
	return CanonicalJSON(s)
}

// keyRotationSignable is the canonical subset of KeyRotationStatement. Field
// order matches JSON key alphabetical order for determinism.
type keyRotationSignable struct {
	NewID     string          `json:"new_id"`
	NewPubKey HybridPublicKey `json:"new_pub_key"`
	OldID     string          `json:"old_id"`
	OldPubKey HybridPublicKey `json:"old_pub_key"`
	Reason    string          `json:"reason"`
	RotatedAt int64           `json:"rotated_at"`
	Version   int             `json:"version"`
}

func keyRotationSignBytes(stmt *KeyRotationStatement) ([]byte, error) {
	s := keyRotationSignable{
		NewID:     stmt.NewID,
		NewPubKey: stmt.NewPubKey,
		OldID:     stmt.OldID,
		OldPubKey: stmt.OldPubKey,
		Reason:    stmt.Reason,
		RotatedAt: stmt.RotatedAt,
		Version:   stmt.Version,
	}
	return CanonicalJSON(s)
}

// revocationPushSignable is the canonical subset of RevocationPush. Field
// order matches JSON key alphabetical order for determinism.
type revocationPushSignable struct {
	Entries  []string `json:"entries"`
	IssuerID string   `json:"issuer_id"`
	PushedAt int64    `json:"pushed_at"`
	SeqNo    int64    `json:"seq_no"`
}

func revocationPushSignBytes(push *RevocationPush) ([]byte, error) {
	entries := push.Entries
	if entries == nil {
		entries = []string{}
	}
	s := revocationPushSignable{
		Entries:  entries,
		IssuerID: push.IssuerID,
		PushedAt: push.PushedAt,
		SeqNo:    push.SeqNo,
	}
	return CanonicalJSON(s)
}

// RevocationPushSignBytes returns the canonical byte sequence that is signed
// to produce RevocationPush.Signature.
func RevocationPushSignBytes(push *RevocationPush) ([]byte, error) {
	return revocationPushSignBytes(push)
}

// IssueRevocationPush signs a RevocationPush with the issuer's hybrid private
// key.
func IssueRevocationPush(push *RevocationPush, issuerPriv HybridPrivateKey) error {
	data, err := revocationPushSignBytes(push)
	if err != nil {
		return fmt.Errorf("serializing revocation push for signing: %w", err)
	}
	sig, err := signBoth(data, issuerPriv)
	if err != nil {
		return fmt.Errorf("signing revocation push: %w", err)
	}
	push.Signature = sig
	return nil
}

// VerifyRevocationPush verifies the hybrid signature on a RevocationPush
// against the issuer's public key. Returns nil iff the signature is valid.
func VerifyRevocationPush(push *RevocationPush, issuerPub HybridPublicKey) error {
	data, err := revocationPushSignBytes(push)
	if err != nil {
		return fmt.Errorf("serializing revocation push for verification: %w", err)
	}
	return verifyBoth(data, push.Signature, issuerPub)
}

// witnessEntrySignable is the canonical subset of WitnessEntry. Field
// order matches JSON key alphabetical order for determinism.
type witnessEntrySignable struct {
	EntryData []byte `json:"entry_data"`
	PrevHash  []byte `json:"prev_hash"`
	Timestamp int64  `json:"timestamp"`
	WitnessID string `json:"witness_id"`
}

func witnessEntrySignBytes(entry *WitnessEntry) ([]byte, error) {
	s := witnessEntrySignable{
		EntryData: entry.EntryData,
		PrevHash:  entry.PrevHash,
		Timestamp: entry.Timestamp,
		WitnessID: entry.WitnessID,
	}
	return CanonicalJSON(s)
}

// WitnessEntrySignBytes returns the canonical byte sequence that is signed
// to produce WitnessEntry.Signature.
func WitnessEntrySignBytes(entry *WitnessEntry) ([]byte, error) {
	return witnessEntrySignBytes(entry)
}

// IssueWitnessEntry signs a WitnessEntry with the witness operator's hybrid
// private key.
func IssueWitnessEntry(entry *WitnessEntry, witnessPriv HybridPrivateKey) error {
	data, err := witnessEntrySignBytes(entry)
	if err != nil {
		return fmt.Errorf("serializing witness entry for signing: %w", err)
	}
	sig, err := signBoth(data, witnessPriv)
	if err != nil {
		return fmt.Errorf("signing witness entry: %w", err)
	}
	entry.Signature = sig
	return nil
}

// VerifyWitnessEntry verifies the hybrid signature on a WitnessEntry
// against the witness operator's public key. Returns nil iff the signature
// is valid.
func VerifyWitnessEntry(entry *WitnessEntry, witnessPub HybridPublicKey) error {
	data, err := witnessEntrySignBytes(entry)
	if err != nil {
		return fmt.Errorf("serializing witness entry for verification: %w", err)
	}
	return verifyBoth(data, entry.Signature, witnessPub)
}

// receiptPartySignable is the canonical per-party subset that enters
// TransactionReceipt signable bytes (§6.4.5). `proof_bundle` is excluded —
// per-party bundles are verified independently by the generic verifier.
type receiptPartySignable struct {
	AgentID     string          `json:"agent_id"`
	AgentPubKey HybridPublicKey `json:"agent_pub_key"`
	PartyID     string          `json:"party_id"`
	Role        string          `json:"role"`
}

// transactionReceiptSignable is the canonical signable that every party's
// signature covers. `party_signatures` is excluded (signatures cannot cover
// themselves) and `proof_bundle` is excluded (verified independently). The
// full sorted `parties` set IS inside the signable, so adding, removing, or
// altering any party invalidates every other party's signature.
type transactionReceiptSignable struct {
	CreatedAt          int64                  `json:"created_at"`
	Parties            []receiptPartySignable `json:"parties"`
	TermsCanonicalJSON []byte                 `json:"terms_canonical_json"`
	TermsSchemaURI     string                 `json:"terms_schema_uri"`
	TransactionID      string                 `json:"transaction_id"`
	Version            int                    `json:"version"`
}

// TransactionReceiptSignBytes returns the canonical byte sequence that every
// listed party signs to bind the receipt. Parties are sorted lex by
// PartyID; duplicates are an error (the caller must ensure uniqueness —
// Verify will reject non-unique receipts).
func TransactionReceiptSignBytes(receipt *TransactionReceipt) ([]byte, error) {
	return transactionReceiptSignBytes(receipt)
}

func transactionReceiptSignBytes(receipt *TransactionReceipt) ([]byte, error) {
	parties := make([]receiptPartySignable, len(receipt.Parties))
	for i, p := range receipt.Parties {
		parties[i] = receiptPartySignable{
			AgentID:     p.AgentID,
			AgentPubKey: p.AgentPubKey,
			PartyID:     p.PartyID,
			Role:        p.Role,
		}
	}
	sort.Slice(parties, func(i, j int) bool {
		return parties[i].PartyID < parties[j].PartyID
	})
	s := transactionReceiptSignable{
		CreatedAt:          receipt.CreatedAt,
		Parties:            parties,
		TermsCanonicalJSON: receipt.TermsCanonicalJSON,
		TermsSchemaURI:     receipt.TermsSchemaURI,
		TransactionID:      receipt.TransactionID,
		Version:            receipt.Version,
	}
	return CanonicalJSON(s)
}

// SignTransactionReceiptParty produces a party's hybrid signature over the
// receipt's canonical signable bytes. Use once per party with that party's
// agent private key; collect the resulting ReceiptPartySignature into
// TransactionReceipt.PartySignatures before emitting the receipt.
func SignTransactionReceiptParty(receipt *TransactionReceipt, partyID string, agentPriv HybridPrivateKey) (ReceiptPartySignature, error) {
	data, err := transactionReceiptSignBytes(receipt)
	if err != nil {
		return ReceiptPartySignature{}, fmt.Errorf("serializing receipt for signing: %w", err)
	}
	sig, err := signBoth(data, agentPriv)
	if err != nil {
		return ReceiptPartySignature{}, fmt.Errorf("signing receipt for party %q: %w", partyID, err)
	}
	return ReceiptPartySignature{PartyID: partyID, Signature: sig}, nil
}

// verificationReceiptSignable is the canonical subset of VerificationReceipt
// that gets hybrid-signed. Field order matches JSON key alphabetical order
// for cross-implementation byte determinism (SPEC §17.5). The `signature`
// field is excluded — signatures cannot cover themselves.
type verificationReceiptSignable struct {
	AgentID      string          `json:"agent_id,omitempty"`
	BundleHash   []byte          `json:"bundle_hash"`
	Decision     string          `json:"decision"`
	ErrorReason  string          `json:"error_reason,omitempty"`
	GrantedScope []string        `json:"granted_scope,omitempty"`
	HumanID      string          `json:"human_id,omitempty"`
	PrevHash     []byte          `json:"prev_hash"`
	VerifiedAt   int64           `json:"verified_at"`
	VerifierID   string          `json:"verifier_id"`
	VerifierPub  HybridPublicKey `json:"verifier_pub"`
	Version      int             `json:"version"`
}

// bundleHashSignable is the canonical fixed-shape representation of a
// ProofBundle used as input to BundleHash. Field order is alphabetical
// JSON-key order; NO field uses omitempty so the shape is the same
// regardless of which optionals the caller populated. Every reference
// SDK builds an equivalent fixed shape, producing byte-identical canonical
// JSON for the same logical bundle. Verified against
// `testvectors/v1/cross_sdk_vectors.json`.
type bundleHashSignable struct {
	AgentID        string             `json:"agent_id"`
	AgentPubKey    HybridPublicKey    `json:"agent_pub_key"`
	Challenge      []byte             `json:"challenge"`
	ChallengeAt    int64              `json:"challenge_at"`
	ChallengeSig   HybridSignature    `json:"challenge_sig"`
	Delegations    []bundleHashDelegationSignable `json:"delegations"`
	SessionContext []byte             `json:"session_context"`
	StreamID       []byte             `json:"stream_id"`
	StreamSeq      int64              `json:"stream_seq"`
}

// bundleHashDelegationSignable mirrors DelegationCert with alpha-ordered
// fields and no omitempty. Constraints is always serialized as `[]`
// when empty.
type bundleHashDelegationSignable struct {
	CertID        string          `json:"cert_id"`
	Constraints   []Constraint    `json:"constraints"`
	ExpiresAt     int64           `json:"expires_at"`
	IssuedAt      int64           `json:"issued_at"`
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	Scope         []string        `json:"scope"`
	Signature     HybridSignature `json:"signature"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Version       int             `json:"version"`
}

// BundleHash returns the canonical SHA-256 digest of a ProofBundle. The
// stable identifier of "what was verified" inside a VerificationReceipt.
//
// Every reference SDK (Go, TypeScript, Python, Rust) MUST produce the same
// 32-byte digest for the same logical bundle. The canonical form is a
// fixed alphabetical-key shape with no omitempty so the byte output is
// deterministic regardless of which optional v1.1 fields are set.
//
// Verified against fixtures in `testvectors/v1/cross_sdk_vectors.json`.
// Drift in any SDK is caught by that SDK's cross-SDK test suite.
func BundleHash(bundle *ProofBundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("nil bundle")
	}
	delegations := make([]bundleHashDelegationSignable, len(bundle.Delegations))
	for i, d := range bundle.Delegations {
		constraints := d.Constraints
		if constraints == nil {
			constraints = []Constraint{}
		}
		delegations[i] = bundleHashDelegationSignable{
			CertID:        d.CertID,
			Constraints:   constraints,
			ExpiresAt:     d.ExpiresAt,
			IssuedAt:      d.IssuedAt,
			IssuerID:      d.IssuerID,
			IssuerPubKey:  d.IssuerPubKey,
			Scope:         d.Scope,
			Signature:     d.Signature,
			SubjectID:     d.SubjectID,
			SubjectPubKey: d.SubjectPubKey,
			Version:       d.Version,
		}
	}
	sessionContext := bundle.SessionContext
	if sessionContext == nil {
		sessionContext = []byte{}
	}
	streamID := bundle.StreamID
	if streamID == nil {
		streamID = []byte{}
	}
	challenge := bundle.Challenge
	if challenge == nil {
		challenge = []byte{}
	}
	s := bundleHashSignable{
		AgentID:        bundle.AgentID,
		AgentPubKey:    bundle.AgentPubKey,
		Challenge:      challenge,
		ChallengeAt:    bundle.ChallengeAt,
		ChallengeSig:   bundle.ChallengeSig,
		Delegations:    delegations,
		SessionContext: sessionContext,
		StreamID:       streamID,
		StreamSeq:      bundle.StreamSeq,
	}
	canonical, err := CanonicalJSON(s)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing bundle for hash: %w", err)
	}
	h := sha256.Sum256(canonical)
	return h[:], nil
}

func verificationReceiptSignBytes(r *VerificationReceipt) ([]byte, error) {
	scope := append([]string(nil), r.GrantedScope...)
	sort.Strings(scope)
	s := verificationReceiptSignable{
		AgentID:      r.AgentID,
		BundleHash:   r.BundleHash,
		Decision:     r.Decision,
		ErrorReason:  r.ErrorReason,
		GrantedScope: scope,
		HumanID:      r.HumanID,
		PrevHash:     r.PrevHash,
		VerifiedAt:   r.VerifiedAt,
		VerifierID:   r.VerifierID,
		VerifierPub:  r.VerifierPub,
		Version:      r.Version,
	}
	return CanonicalJSON(s)
}

// VerificationReceiptSignBytes returns the canonical byte sequence that is
// signed to produce VerificationReceipt.Signature.
func VerificationReceiptSignBytes(r *VerificationReceipt) ([]byte, error) {
	return verificationReceiptSignBytes(r)
}

// IssueVerificationReceipt constructs and signs a VerificationReceipt over a
// (bundle, VerifyResult, prev) triple. The verifier's hybrid private key
// authenticates "this verifier saw this bundle, and reached this decision,
// at this time." `prevHash` is the SHA-256 digest of the previous receipt's
// canonical signable bytes — pass 32 zero bytes for genesis. `verifiedAt` is
// unix seconds (use the same clock as the verifier).
//
// The receipt is OPTIONAL — the protocol does not auto-issue. AuditProvider
// implementations that want a tamper-evident chain wrap this around each
// VerifyResult before persisting; implementations that don't, don't.
func IssueVerificationReceipt(
	bundle *ProofBundle,
	result VerifyResult,
	verifierID string,
	verifierPub HybridPublicKey,
	verifierPriv HybridPrivateKey,
	prevHash []byte,
	verifiedAt int64,
) (*VerificationReceipt, error) {
	bundleHash, err := BundleHash(bundle)
	if err != nil {
		return nil, fmt.Errorf("hashing bundle: %w", err)
	}
	prev := prevHash
	if prev == nil {
		prev = make([]byte, sha256.Size)
	}
	if len(prev) != sha256.Size {
		return nil, fmt.Errorf("prev_hash must be %d bytes, got %d", sha256.Size, len(prev))
	}
	r := &VerificationReceipt{
		Version:      ProtocolVersion,
		VerifierID:   verifierID,
		VerifierPub:  verifierPub,
		BundleHash:   bundleHash,
		Decision:     result.IdentityStatus,
		HumanID:      result.HumanID,
		AgentID:      result.AgentID,
		GrantedScope: result.GrantedScope,
		ErrorReason:  result.ErrorReason,
		VerifiedAt:   verifiedAt,
		PrevHash:     prev,
	}
	data, err := verificationReceiptSignBytes(r)
	if err != nil {
		return nil, fmt.Errorf("serializing verification receipt: %w", err)
	}
	sig, err := signBoth(data, verifierPriv)
	if err != nil {
		return nil, fmt.Errorf("signing verification receipt: %w", err)
	}
	r.Signature = sig
	return r, nil
}

// VerifyVerificationReceipt verifies the hybrid signature on a
// VerificationReceipt against the asserted verifier public key. Returns nil
// iff both component signatures verify. Note: this only verifies the
// receipt's *authenticity* — that the named verifier did sign it. Callers
// who need to verify the receipt chain (prev_hash linkage) MUST hash each
// prior receipt's signable bytes and check that the chain is contiguous.
func VerifyVerificationReceipt(r *VerificationReceipt) error {
	if r == nil {
		return fmt.Errorf("nil receipt")
	}
	if r.Version != ProtocolVersion {
		return fmt.Errorf("unsupported version %d", r.Version)
	}
	if len(r.BundleHash) != sha256.Size {
		return fmt.Errorf("bundle_hash must be %d bytes, got %d", sha256.Size, len(r.BundleHash))
	}
	if len(r.PrevHash) != sha256.Size {
		return fmt.Errorf("prev_hash must be %d bytes, got %d", sha256.Size, len(r.PrevHash))
	}
	data, err := verificationReceiptSignBytes(r)
	if err != nil {
		return fmt.Errorf("serializing receipt for verification: %w", err)
	}
	return verifyBoth(data, r.Signature, r.VerifierPub)
}

// ReceiptHash returns the SHA-256 of a receipt's canonical signable bytes.
// Use this as the `prev_hash` for the NEXT receipt in the chain.
func ReceiptHash(r *VerificationReceipt) ([]byte, error) {
	data, err := verificationReceiptSignBytes(r)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// sessionTokenSignable is the canonical subset of SessionToken. Field order
// matches JSON key alphabetical order so every implementation's serde
// preserves the canonical byte sequence.
type sessionTokenSignable struct {
	AgentID      string          `json:"agent_id"`
	AgentPubKey  HybridPublicKey `json:"agent_pub_key"`
	ChainHash    []byte          `json:"chain_hash"` // base64 in JSON per project convention
	GrantedScope []string        `json:"granted_scope"`
	HumanID      string          `json:"human_id"`
	IssuedAt     int64           `json:"issued_at"`
	SessionID    string          `json:"session_id"`
	ValidUntil   int64           `json:"valid_until"`
	Version      int             `json:"version"`
}

func sessionTokenSignBytes(token *SessionToken) ([]byte, error) {
	scope := append([]string(nil), token.GrantedScope...)
	sort.Strings(scope)
	s := sessionTokenSignable{
		AgentID:      token.AgentID,
		AgentPubKey:  token.AgentPubKey,
		ChainHash:    token.ChainHash,
		GrantedScope: scope,
		HumanID:      token.HumanID,
		IssuedAt:     token.IssuedAt,
		SessionID:    token.SessionID,
		ValidUntil:   token.ValidUntil,
		Version:      token.Version,
	}
	return CanonicalJSON(s)
}

func isKeyRotationReasonKnown(reason string) bool {
	switch reason {
	case "routine", "compromise_suspected", "device_lost", "recovery", "other":
		return true
	default:
		return false
	}
}
