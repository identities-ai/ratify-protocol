package ratify

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

const (
	// ChallengeWindowSeconds is the maximum age of a signed challenge.
	// Challenges older than this are rejected to prevent replay attacks.
	ChallengeWindowSeconds = 300 // 5 minutes

	// MaxDelegationChainDepth is the maximum number of certs in a delegation chain.
	MaxDelegationChainDepth = 3
)

// VerifyOptions controls what the verifier checks beyond the cryptographic basics.
type VerifyOptions struct {
	// RequiredScope must be present in the effective scope for the proof to
	// be valid. Empty string skips scope checking.
	RequiredScope string

	// IsRevoked is called for each cert ID during verification. Return true
	// if the cert has been revoked. Can be nil (no revocation check).
	IsRevoked func(certID string) bool

	// ForceRevocationCheck, when true, signals the verifier to bypass its
	// local revocation cache and query the issuer (or registry) for the
	// freshest revocation state before proceeding. This is the v1.1 "force
	// fresh check" path for high-stakes endpoints that cannot tolerate the
	// polling interval's staleness window (ROADMAP §2.4). The actual fresh-
	// fetch is the caller's responsibility — the verifier protocol does not
	// mandate a transport. When ForceRevocationCheck is true and IsRevoked
	// is nil, the verifier returns an error because the caller asked for
	// fresh revocation but provided no callback to check it.
	ForceRevocationCheck bool

	// Now overrides the current time for testing. Zero value uses time.Now().
	Now time.Time

	// SessionContext is the verifier-reconstructed 32-byte v1.1 context that
	// binds a challenge to this verifier/session/request. If set, the bundle
	// MUST carry the same session_context and the challenge signature MUST
	// verify over ChallengeSignBytesWithSessionContext. If empty, legacy v1
	// unbound bundles are accepted and session-bound bundles must still carry
	// a valid 32-byte context.
	SessionContext []byte

	// Stream is the verifier-tracked stream binding for v1.1 stream-bound
	// bundles. If set, the bundle MUST carry stream_id matching Stream.StreamID
	// and stream_seq equal to Stream.LastSeenSeq+1. If nil, bundles carrying
	// stream fields are rejected as stream_context_unverifiable. A verifier
	// that tracks a stream retains Stream.LastSeenSeq across calls; each
	// successful Verify increments it in the caller's persistence layer.
	Stream *StreamContext

	// Context supplies the application inputs required to evaluate first-class
	// constraints on each cert (geo, time-of-day, speed, amount, rate). A cert
	// whose constraint requires a field absent from Context fails closed with
	// `constraint_unverifiable`. Zero value is fine for certs that declare no
	// constraints.
	Context VerifierContext
}

// StreamContext is the verifier state tracked per stream_id for v1.1
// stream-bound bundles. LastSeenSeq is the highest sequence number the
// verifier has already accepted for StreamID; zero means "no turns accepted
// yet" — the first valid bundle must carry stream_seq == 1.
type StreamContext struct {
	StreamID    []byte
	LastSeenSeq int64
}

// VerifyReceiptOptions controls the per-party verification work inside
// VerifyTransactionReceipt. Defaults produce a generic envelope check: each
// party's ProofBundle must fully verify, every declared party must have
// exactly one signature, and every party signature must verify against that
// party's agent_pub_key over the canonical signable. Applications add scope
// routing by setting PartyVerifyOptions.
type VerifyReceiptOptions struct {
	// Now overrides the current time. Zero value uses time.Now().
	Now time.Time

	// PartyVerifyOptions returns the VerifyOptions a party's ProofBundle is
	// checked against, keyed by party role. Callers typically configure
	// required scopes per role (e.g. "buyer" requires payments:send, "seller"
	// requires transact:sell). If nil or returns an empty VerifyOptions, the
	// party's bundle is verified with defaults (no scope requirement) at
	// VerifyReceiptOptions.Now. The option's Now field is ignored — the outer
	// Now propagates for consistency.
	PartyVerifyOptions func(role string) VerifyOptions
}

// TransactionReceiptResult is the generic envelope-verifier outcome. Valid
// iff every envelope check in SPEC §5.14 passes AND every party's ProofBundle
// produced Valid=true from Verify. ErrorReason carries the first envelope- or
// party-level failure encountered; PartyResults captures the per-party
// VerifyResult in Parties-order for callers that want audit detail.
type TransactionReceiptResult struct {
	Valid        bool
	ErrorReason  string
	PartyResults []VerifyResult
}

// VerifyTransactionReceipt runs the canonical envelope verification of
// SPEC §5.14 / TRANSACTION_RECEIPTS.md §5. The envelope is atomic: any
// single-party failure fails the whole receipt, there is no partial-valid
// state.
func VerifyTransactionReceipt(receipt *TransactionReceipt, opts VerifyReceiptOptions) TransactionReceiptResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if receipt == nil {
		return TransactionReceiptResult{ErrorReason: "receipt_nil: receipt must not be nil"}
	}
	if receipt.Version != ProtocolVersion {
		return TransactionReceiptResult{ErrorReason: fmt.Sprintf("version_mismatch: unsupported version %d", receipt.Version)}
	}
	if receipt.TransactionID == "" {
		return TransactionReceiptResult{ErrorReason: "missing_transaction_id: transaction_id must not be empty"}
	}
	if receipt.TermsSchemaURI == "" {
		return TransactionReceiptResult{ErrorReason: "missing_terms_schema_uri: terms_schema_uri must not be empty"}
	}
	if len(receipt.TermsCanonicalJSON) == 0 {
		return TransactionReceiptResult{ErrorReason: "missing_terms_canonical_json: terms_canonical_json must not be empty"}
	}
	if len(receipt.Parties) == 0 {
		return TransactionReceiptResult{ErrorReason: "no_parties: receipt must list at least one party"}
	}

	// Party IDs must be unique; collect an id→index map.
	partyIdx := make(map[string]int, len(receipt.Parties))
	for i, p := range receipt.Parties {
		if p.PartyID == "" {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("empty_party_id: party %d has no party_id", i)}
		}
		if _, dup := partyIdx[p.PartyID]; dup {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("duplicate_party_id: %q listed more than once", p.PartyID)}
		}
		partyIdx[p.PartyID] = i
	}

	// Each listed party must have exactly one signature; every signature's
	// party_id must refer to a listed party.
	sigByParty := make(map[string]int, len(receipt.PartySignatures))
	for i, s := range receipt.PartySignatures {
		if _, ok := partyIdx[s.PartyID]; !ok {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("unknown_party_signature: signature %d references unknown party_id %q", i, s.PartyID)}
		}
		if _, dup := sigByParty[s.PartyID]; dup {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("duplicate_party_signature: party %q has multiple signatures", s.PartyID)}
		}
		sigByParty[s.PartyID] = i
	}
	for _, p := range receipt.Parties {
		if _, ok := sigByParty[p.PartyID]; !ok {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("missing_party_signature: party %q has no signature", p.PartyID)}
		}
	}

	// Canonical signable — every party's signature must verify over these bytes.
	signable, err := transactionReceiptSignBytes(receipt)
	if err != nil {
		return TransactionReceiptResult{ErrorReason: fmt.Sprintf("signable_serialize: %v", err)}
	}

	partyResults := make([]VerifyResult, len(receipt.Parties))
	for i := range receipt.Parties {
		p := &receipt.Parties[i]
		// Proof bundle's agent_id / agent_pub_key MUST match the party's.
		if p.ProofBundle.AgentID != p.AgentID {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("party_agent_id_mismatch: party %q proof_bundle.agent_id=%q != party.agent_id=%q", p.PartyID, p.ProofBundle.AgentID, p.AgentID)}
		}
		if !hybridPubKeyEqual(p.ProofBundle.AgentPubKey, p.AgentPubKey) {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("party_agent_key_mismatch: party %q proof_bundle.agent_pub_key != party.agent_pub_key", p.PartyID)}
		}
		// Bundle verification — each party's authority to commit to the terms.
		var bundleOpts VerifyOptions
		if opts.PartyVerifyOptions != nil {
			bundleOpts = opts.PartyVerifyOptions(p.Role)
		}
		bundleOpts.Now = now
		r := Verify(&p.ProofBundle, bundleOpts)
		partyResults[i] = r
		if !r.Valid {
			return TransactionReceiptResult{
				ErrorReason:  fmt.Sprintf("party_bundle_invalid: party %q status=%s reason=%s", p.PartyID, r.IdentityStatus, r.ErrorReason),
				PartyResults: partyResults,
			}
		}
		// Party signature check over the atomic signable.
		sig := receipt.PartySignatures[sigByParty[p.PartyID]].Signature
		if err := verifyBoth(signable, sig, p.AgentPubKey); err != nil {
			return TransactionReceiptResult{
				ErrorReason:  fmt.Sprintf("party_signature_invalid: party %q: %v", p.PartyID, err),
				PartyResults: partyResults,
			}
		}
	}

	return TransactionReceiptResult{Valid: true, PartyResults: partyResults}
}

// VerifyStreamedTurn is the fast-path verifier for v1.1 session cert cache
// (ROADMAP 2.3). Given a previously issued SessionToken and a per-turn
// challenge signature, it:
//
//  1. Checks the SessionToken's HMAC against sessionSecret.
//  2. Checks the token is within [IssuedAt, ValidUntil] at `now`.
//  3. Verifies the challenge is fresh (within ChallengeWindowSeconds).
//  4. Verifies the hybrid challenge signature against token.AgentPubKey. The
//     signable bytes may be legacy (challenge || ts) or session/stream-bound;
//     callers pass the session_context and stream binding alongside.
//
// On success, VerifyResult.Valid=true, GrantedScope=token.GrantedScope,
// AgentID=token.AgentID, HumanID=token.HumanID. The chain is NOT
// re-verified — that's the point of the token. Callers who need fresh
// revocation semantics should evict the token when the issuer publishes a
// new revocation list or when token.ValidUntil expires.
func VerifyStreamedTurn(token *SessionToken, sessionSecret []byte, challenge []byte, challengeAt int64, challengeSig HybridSignature, sessionContext, streamID []byte, streamSeq int64, now time.Time) VerifyResult {
	if token == nil {
		return invalid("nil_session_token", "session_token must not be nil")
	}
	if err := VerifySessionToken(token, sessionSecret, now); err != nil {
		return invalid("session_token_invalid", err.Error())
	}
	// Basic structure for the streamed turn itself.
	if len(challenge) == 0 {
		return invalid("no_challenge", "streamed turn contains no challenge")
	}
	if len(sessionContext) != 0 && len(sessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("session_context must be 32 bytes, got %d", len(sessionContext)))
	}
	if len(streamID) != 0 && len(streamID) != 32 {
		return invalid("invalid_stream_id", fmt.Sprintf("stream_id must be 32 bytes, got %d", len(streamID)))
	}
	if len(streamID) != 0 && streamSeq < 1 {
		return invalid("invalid_stream_seq", fmt.Sprintf("stream_seq must be >=1, got %d", streamSeq))
	}
	// Challenge freshness — same 5-minute window as a full chain verify.
	challengeAge := now.Unix() - challengeAt
	if challengeAge < 0 || challengeAge > ChallengeWindowSeconds {
		return invalid("stale_challenge", fmt.Sprintf("challenge is %d seconds old (max %d)", challengeAge, ChallengeWindowSeconds))
	}
	// Hybrid challenge signature over the canonical signable bytes.
	signable := challengeSignBytes(challenge, challengeAt, sessionContext, streamID, streamSeq)
	if err := verifyBoth(signable, challengeSig, token.AgentPubKey); err != nil {
		return invalid("bad_challenge_sig", fmt.Sprintf("challenge signature verification failed: %v", err))
	}
	return VerifyResult{
		Valid:          true,
		HumanID:        token.HumanID,
		AgentID:        token.AgentID,
		GrantedScope:   append([]string(nil), token.GrantedScope...),
		IdentityStatus: IdentityStatusAuthorizedAgent,
	}
}

// Identity status values (SPEC §5.9). Success surfaces; granular failure
// statuses surface so audit/policy layers can route on the status enum
// without parsing ErrorReason text.
const (
	IdentityStatusAuthorizedAgent         = "authorized_agent"
	IdentityStatusVerifiedHuman           = "verified_human"
	IdentityStatusExpired                 = "expired"
	IdentityStatusRevoked                 = "revoked"
	IdentityStatusScopeDenied             = "scope_denied"
	IdentityStatusConstraintDenied        = "constraint_denied"
	IdentityStatusConstraintUnverifiable  = "constraint_unverifiable"
	IdentityStatusDelegationNotAuthorized = "delegation_not_authorized"
	// IdentityStatusConstraintUnknown is returned when a cert carries a
	// Constraint with a `type` the verifier does not recognize. Fail-closed
	// — rather than silently ignoring unknown types (which would let a
	// future cert smuggle unenforced constraints past an older verifier)
	// the protocol rejects the cert so each version's verifier sees a
	// consistent supported set.
	IdentityStatusConstraintUnknown = "constraint_unknown"
	// IdentityStatusInvalid is the catch-all for structural / cryptographic
	// failures (bad signature, malformed chain, wrong key, etc).
	IdentityStatusInvalid = "invalid"
)

// Verify validates a ProofBundle against the Ratify Protocol and returns a
// deterministic VerifyResult. Always returns a result; check result.Valid.
//
// The verifier performs these checks in order:
//  1. Structural: non-empty chain, depth ≤ MaxDelegationChainDepth,
//     challenge present, agent pubkey component sizes correct.
//  2. Agent binding: the bundle's agent_pub_key / agent_id match the leaf
//     cert's subject_pub_key / subject_id.
//  3. For each cert in chain:
//     a. version == ProtocolVersion
//     b. now ∈ [issued_at, expires_at]
//     c. not revoked (per opts.IsRevoked)
//     d. hybrid signature valid — BOTH Ed25519 and ML-DSA-65 components
//     verify against declared issuer_pub_key
//     e. chain linkage: cert[i].issuer_{id,pub_key} == cert[i+1].subject_{id,pub_key}
//     f. sub-delegation gate: parent cert held identity:delegate (non-root only)
//     g. constraint evaluation against VerifierContext
//  4. Challenge freshness: challenge age ∈ [0, ChallengeWindowSeconds].
//  5. Challenge signature: hybrid signature valid against agent_pub_key.
//  6. Effective scope: required_scope ∈ IntersectScopes(all cert scopes).
//
// A single component failure (e.g. Ed25519 valid but ML-DSA-65 invalid, or
// vice versa) fails the whole signature — fail-closed is the v1 semantics.
func Verify(bundle *ProofBundle, opts VerifyOptions) VerifyResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// --- Basic structure checks ---
	if len(bundle.Delegations) == 0 {
		return invalid("no_delegations", "proof bundle contains no delegation certificates")
	}
	if len(bundle.Delegations) > MaxDelegationChainDepth {
		return invalid("chain_too_deep", "delegation chain exceeds maximum depth")
	}
	if len(bundle.Challenge) == 0 {
		return invalid("no_challenge", "proof bundle contains no challenge")
	}
	if len(bundle.SessionContext) != 0 && len(bundle.SessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("session_context must be 32 bytes, got %d", len(bundle.SessionContext)))
	}
	if len(opts.SessionContext) != 0 && len(opts.SessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("verify option session_context must be 32 bytes, got %d", len(opts.SessionContext)))
	}
	if len(opts.SessionContext) != 0 {
		if len(bundle.SessionContext) == 0 {
			return invalid("missing_session_context", "verifier requires a session-bound challenge but bundle has no session_context")
		}
		if !bytes.Equal(bundle.SessionContext, opts.SessionContext) {
			return invalid("session_context_mismatch", "bundle session_context does not match verifier context")
		}
	} else if len(bundle.SessionContext) != 0 {
		return invalid("session_context_unverifiable", "bundle has session_context but verifier did not provide one")
	}

	// --- v1.1 stream binding checks (SPEC §5.8, §6.4.2) ---
	// Stream fields are structurally coupled: stream_id present iff the bundle
	// is stream-bound. A stream_seq without a stream_id cannot be signed
	// meaningfully, and a stream_id without a stream_seq is ambiguous.
	if len(bundle.StreamID) != 0 && len(bundle.StreamID) != 32 {
		return invalid("invalid_stream_id", fmt.Sprintf("stream_id must be 32 bytes, got %d", len(bundle.StreamID)))
	}
	if len(bundle.StreamID) == 0 && bundle.StreamSeq != 0 {
		return invalid("invalid_stream_seq", "stream_seq set without stream_id")
	}
	if len(bundle.StreamID) != 0 && bundle.StreamSeq < 1 {
		return invalid("invalid_stream_seq", fmt.Sprintf("stream_seq must be >=1, got %d", bundle.StreamSeq))
	}
	if opts.Stream != nil {
		if len(opts.Stream.StreamID) != 32 {
			return invalid("invalid_stream_id", fmt.Sprintf("verify option stream_id must be 32 bytes, got %d", len(opts.Stream.StreamID)))
		}
		if len(bundle.StreamID) == 0 {
			return invalid("missing_stream_context", "verifier requires a stream-bound challenge but bundle has no stream_id")
		}
		if !bytes.Equal(bundle.StreamID, opts.Stream.StreamID) {
			return invalid("stream_id_mismatch", "bundle stream_id does not match verifier stream context")
		}
		expected := opts.Stream.LastSeenSeq + 1
		if bundle.StreamSeq <= opts.Stream.LastSeenSeq {
			return invalid("stream_seq_replay", fmt.Sprintf("stream_seq %d already seen (last=%d)", bundle.StreamSeq, opts.Stream.LastSeenSeq))
		}
		if bundle.StreamSeq != expected {
			return invalid("stream_seq_skip", fmt.Sprintf("stream_seq %d skips expected %d", bundle.StreamSeq, expected))
		}
	} else if len(bundle.StreamID) != 0 {
		return invalid("stream_context_unverifiable", "bundle has stream_id but verifier did not provide a stream context")
	}
	if err := validateHybridPubKeyLens(bundle.AgentPubKey, "agent"); err != nil {
		return invalid("invalid_agent_key", err.Error())
	}

	// --- Agent binding to leaf cert ---
	firstCert := &bundle.Delegations[0]
	// The human root — issuer of the last cert in the chain. Used consistently
	// across success and failure paths (expired, revoked) so a caller's audit
	// log always reports the principal, not an intermediate.
	humanID := bundle.Delegations[len(bundle.Delegations)-1].IssuerID

	if !hybridPubKeyEqual(bundle.AgentPubKey, firstCert.SubjectPubKey) {
		return invalid("key_mismatch", "agent public key does not match delegation subject")
	}
	if bundle.AgentID != firstCert.SubjectID {
		return invalid("id_mismatch", "agent ID does not match delegation subject ID")
	}

	// --- v1.1 force-fresh revocation check (ROADMAP §2.4) ---
	if opts.ForceRevocationCheck && opts.IsRevoked == nil {
		return invalid("force_revocation_no_callback", "ForceRevocationCheck is true but IsRevoked callback is nil — the caller asked for fresh revocation state but provided no way to check it")
	}

	// --- Per-cert checks ---
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]

		if cert.Version != ProtocolVersion {
			return invalid("version_mismatch", fmt.Sprintf("cert %d has unsupported version %d", i, cert.Version))
		}
		if now.Unix() > cert.ExpiresAt {
			return expired(humanID, bundle.AgentID)
		}
		if now.Unix() < cert.IssuedAt {
			return invalid("not_yet_valid", fmt.Sprintf("cert %d is not yet valid", i))
		}
		if opts.IsRevoked != nil && opts.IsRevoked(cert.CertID) {
			return revoked(humanID, bundle.AgentID)
		}
		if err := VerifyDelegationSignature(cert); err != nil {
			return invalid("bad_signature", fmt.Sprintf("cert %d: %v", i, err))
		}

		// Constraint evaluation: each cert's first-class constraints must all
		// pass against the caller-supplied VerifierContext. Fail-closed — a
		// constraint whose required context field is missing fails the cert,
		// and an unknown constraint Type fails with a distinct status so
		// cross-version deployments surface "this verifier doesn't know
		// what this constraint means" explicitly.
		if err := evaluateConstraints(cert, opts.Context, now); err != nil {
			status := IdentityStatusConstraintDenied
			switch {
			case isConstraintUnverifiable(err):
				status = IdentityStatusConstraintUnverifiable
			case isConstraintUnknown(err):
				status = IdentityStatusConstraintUnknown
			}
			return failWithStatus(status, fmt.Sprintf("cert %d: %v", i, err))
		}

		// Chain linkage: each cert's subject must match the next cert's issuer
		if i+1 < len(bundle.Delegations) {
			next := &bundle.Delegations[i+1]
			if cert.IssuerID != next.SubjectID {
				return invalid("broken_chain", fmt.Sprintf("cert %d issuer does not match cert %d subject", i, i+1))
			}
			if !hybridPubKeyEqual(cert.IssuerPubKey, next.SubjectPubKey) {
				return invalid("broken_chain_keys", fmt.Sprintf("cert %d issuer key does not match cert %d subject key", i, i+1))
			}

			// Sub-delegation gate: cert[i+1] granted authority to the subject
			// that signed cert[i]. For that sub-delegation to be legitimate
			// cert[i+1].Scope MUST contain identity:delegate. Sensitive by
			// spec §9.1, so wildcards never introduce it — the grant has to
			// be explicit. Without this check any intermediate could fork a
			// new chain with any scope its parent held, bypassing the
			// "delegation is a separately-granted privilege" model.
			if !slices.Contains(next.Scope, ScopeIdentityDelegate) {
				return failWithStatus(IdentityStatusDelegationNotAuthorized, fmt.Sprintf(
					"cert %d issued by a subject whose parent cert %d did not grant %q",
					i, i+1, ScopeIdentityDelegate))
			}
		}
	}

	// --- Liveness (challenge freshness + hybrid signature) ---
	challengeAge := now.Unix() - bundle.ChallengeAt
	if challengeAge < 0 || challengeAge > ChallengeWindowSeconds {
		return invalid("stale_challenge", fmt.Sprintf("challenge is %d seconds old (max %d)", challengeAge, ChallengeWindowSeconds))
	}
	if err := verifyBoth(challengeSignBytes(bundle.Challenge, bundle.ChallengeAt, bundle.SessionContext, bundle.StreamID, bundle.StreamSeq), bundle.ChallengeSig, bundle.AgentPubKey); err != nil {
		return invalid("bad_challenge_sig", fmt.Sprintf("challenge signature verification failed: %v", err))
	}

	// --- Effective scope (intersection across the chain) ---
	scopeLists := make([][]string, len(bundle.Delegations))
	for i := range bundle.Delegations {
		scopeLists[i] = bundle.Delegations[i].Scope
	}
	effective := IntersectScopes(scopeLists...)

	if opts.RequiredScope != "" {
		if !slices.Contains(effective, opts.RequiredScope) {
			return failWithStatus(IdentityStatusScopeDenied,
				fmt.Sprintf("required scope %q not in effective delegation scope", opts.RequiredScope))
		}
	}

	return VerifyResult{
		Valid:          true,
		HumanID:        humanID,
		AgentID:        bundle.AgentID,
		GrantedScope:   effective,
		IdentityStatus: "authorized_agent",
	}
}

// ============================================================================
// Hybrid public key helpers
// ============================================================================

// hybridPubKeyEqual returns true iff both component public keys match
// byte-for-byte.
func hybridPubKeyEqual(a, b HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}

// validateHybridPubKeyLens checks that both components of a hybrid pubkey
// have the expected lengths. Returns a descriptive error or nil.
func validateHybridPubKeyLens(pub HybridPublicKey, label string) error {
	if len(pub.Ed25519) != 32 {
		return fmt.Errorf("%s Ed25519 public key has wrong length: %d", label, len(pub.Ed25519))
	}
	if len(pub.MLDSA65) != 1952 {
		return fmt.Errorf("%s ML-DSA-65 public key has wrong length: %d", label, len(pub.MLDSA65))
	}
	return nil
}

// ============================================================================
// Result constructors
// ============================================================================

func invalid(reason, msg string) VerifyResult {
	return VerifyResult{
		Valid:          false,
		IdentityStatus: IdentityStatusInvalid,
		ErrorReason:    fmt.Sprintf("%s: %s", reason, msg),
	}
}

// failWithStatus is used when the failure type has its own top-level
// identity_status (scope_denied, constraint_denied, etc). The reason code
// lives in ErrorReason alongside the human-readable detail.
func failWithStatus(status, msg string) VerifyResult {
	return VerifyResult{
		Valid:          false,
		IdentityStatus: status,
		ErrorReason:    fmt.Sprintf("%s: %s", status, msg),
	}
}

// isConstraintUnverifiable detects the sentinel wrapped by
// errConstraintUnverifiable in constraints.go so we can route to the right
// identity_status without string-matching.
func isConstraintUnverifiable(err error) bool {
	for e := err; e != nil; {
		if _, ok := e.(unverifiableError); ok {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// isConstraintUnknown detects the sentinel wrapped by errConstraintUnknown
// in constraints.go. Mirrors isConstraintUnverifiable's contract — we route
// on the sentinel, not on error text, so message changes don't silently
// re-route identity_status.
func isConstraintUnknown(err error) bool {
	for e := err; e != nil; {
		if _, ok := e.(unknownConstraintError); ok {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func expired(humanID, agentID string) VerifyResult {
	return VerifyResult{
		Valid:          false,
		HumanID:        humanID,
		AgentID:        agentID,
		IdentityStatus: "expired",
		ErrorReason:    "delegation certificate has expired",
	}
}

func revoked(humanID, agentID string) VerifyResult {
	return VerifyResult{
		Valid:          false,
		HumanID:        humanID,
		AgentID:        agentID,
		IdentityStatus: "revoked",
		ErrorReason:    "delegation certificate has been revoked",
	}
}
