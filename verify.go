// Package ratify implements the Ratify Protocol — a cryptographic trust
// protocol for human-agent and agent-agent interactions as agents start
// to transact.
package ratify

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
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

	// IsRevoked is the legacy v1.0 revocation closure. Return true if the
	// cert has been revoked; nil disables the check entirely.
	//
	// Deprecated: Use Revocation (SPEC §17.1) instead. The closure has no
	// way to surface lookup failures — it must collapse "I don't know" to
	// `false` (allow) or `true` (deny), neither of which is correct.
	// Revocation returns `(bool, error)` and the verifier fails closed on
	// error (`revocation_error`). When both are set, Revocation wins. The
	// closure remains supported through v1.0.0-* releases and will be
	// removed in v1.0.0-beta.1.
	IsRevoked func(certID string) bool

	// Revocation is the pluggable provider hook for revocation state
	// (SPEC §17.1). If set, takes precedence over IsRevoked. A provider
	// that returns an error fails the bundle as `revocation_error` —
	// fail-closed semantics: a verifier that cannot determine revocation
	// state MUST NOT report a cert as valid.
	Revocation RevocationProvider

	// Policy is an advanced policy evaluator hook (SPEC §17.2). Evaluated
	// AFTER all cryptographic checks pass. A nil provider is a no-op.
	Policy PolicyProvider

	// Audit is a verification audit logging hook (SPEC §17.3). Called on
	// every Verify invocation (both Valid=true and Valid=false). Errors
	// from the audit provider are ignored — auditing MUST NOT alter the
	// verifier's decision.
	Audit AuditProvider

	// ConstraintEvaluators is the per-Verify registry of extension
	// constraint evaluators (SPEC §17.7). Keys are constraint type strings
	// that are NOT in the built-in set (geo_circle, geo_polygon, geo_bbox,
	// time_window, max_speed_mps, max_amount, max_rate). Built-in types
	// are evaluated by the SDK directly; the registry is only consulted
	// for unknown types. A type with no registered evaluator still fails
	// closed with identity_status="constraint_unknown".
	ConstraintEvaluators map[string]ConstraintEvaluator

	// PolicyVerdict, when non-nil, is a fast-path cached policy decision
	// (SPEC §17.6). When present, Verify skips the Policy provider hook
	// IF the verdict is valid (MAC matches PolicySecret, within validity
	// window, agent/scope/context-hash matches). If the verdict is
	// expired or mismatched, the verifier falls back to Policy provider
	// (or, if Policy is nil, treats the bundle as policy-passing).
	PolicyVerdict *PolicyVerdict

	// PolicySecret is the HMAC secret used to verify the PolicyVerdict's
	// MAC. Required when PolicyVerdict is non-nil; otherwise ignored.
	PolicySecret []byte

	// AnchorResolver, when non-nil, is consulted on successful verifications
	// to populate `VerifyResult.Anchor` (SPEC §17.8). It maps the verified
	// HumanID to its external-identity binding (Okta SSO, government ID,
	// email-verified, etc) so AuditProviders can record an unforgeable
	// chain from the verification event to the identity attestation
	// behind the human root. Errors from the resolver are non-fatal:
	// the bundle still verifies; Anchor is simply left nil. A nil
	// resolver disables the lookup entirely.
	AnchorResolver AnchorResolver

	// ForceRevocationCheck, when true, signals the verifier to bypass its
	// local revocation cache and query the issuer (or registry) for the
	// freshest revocation state before proceeding. This is the v1.1 "force
	// fresh check" path for high-stakes endpoints that cannot tolerate the
	// polling interval's staleness window (ROADMAP §2.4). The actual fresh-
	// fetch is the caller's responsibility — the verifier protocol does not
	// mandate a transport. When ForceRevocationCheck is true and IsRevoked
	// is nil, the verifier returns "force_revocation_no_callback".
	ForceRevocationCheck bool

	// Now overrides the current time for verification (expiry, challenge
	// age). Zero value uses time.Now().
	Now time.Time

	// Context carries the application-supplied inputs needed to evaluate
	// first-class constraints (geo, time, etc).
	Context VerifierContext

	// SessionContext is a verifier-reconstructed 32-byte hash that binds a
	// challenge to this specific verifier/session/request. When set, the
	// bundle MUST carry a byte-equal session_context. Prevents cross-verifier
	// challenge forwarding (SPEC §15.1).
	SessionContext []byte

	// Stream binds a verifier-tracked sequence context for v1.1 stream-bound
	// bundles. Both StreamID and LastSeenSeq must be populated.
	Stream *StreamContext
}

// StreamContext tracks the state of an ordered interaction stream.
type StreamContext struct {
	StreamID    []byte // 32 bytes
	LastSeenSeq int64  // ≥ 0; first expected seq is 1
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
	// IdentityStatusInvalidScope is returned when any cert in the chain
	// grants a scope that is not canonical, not a wildcard, and not a
	// `custom:` extension (SPEC §9). Fail-closed — a cert carrying
	// vocabulary outside the protocol is rejected as malformed rather than
	// silently intersected, so unknown strings can never become effective
	// grants that a confused verifier might match against.
	IdentityStatusInvalidScope = "invalid_scope"
	// IdentityStatusInvalid is the catch-all for structural / cryptographic
	// failures (bad signature, malformed chain, wrong key, etc).
	IdentityStatusInvalid = "invalid"
)

// Verify validates a ProofBundle against the Ratify Protocol and returns a
// deterministic VerifyResult. Always returns a result; check result.Valid.
//
// A single component failure (e.g. Ed25519 valid but ML-DSA-65 invalid, or
// vice versa) fails the whole signature — fail-closed is the v1 semantics.
func Verify(bundle *ProofBundle, opts VerifyOptions) VerifyResult {
	res := verify(bundle, opts)
	// Audit hook: always invoked on every verification (success AND failure)
	// so receipts capture denied attempts. Errors are intentionally swallowed
	// — auditing is observation, not control; an audit-store outage MUST NOT
	// flip a Valid=true bundle to Valid=false. (SPEC §17.3)
	if opts.Audit != nil {
		_ = opts.Audit.LogVerification(res, bundle)
	}
	return res
}

func verify(bundle *ProofBundle, opts VerifyOptions) VerifyResult {
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
	humanID := bundle.Delegations[len(bundle.Delegations)-1].IssuerID

	if !hybridPubKeyEqual(bundle.AgentPubKey, firstCert.SubjectPubKey) {
		return invalid("key_mismatch", "agent public key does not match delegation subject")
	}
	if bundle.AgentID != firstCert.SubjectID {
		return invalid("id_mismatch", "agent ID does not match delegation subject ID")
	}

	// --- v1.1 force-fresh revocation check (ROADMAP §2.4) ---
	// Both legacy IsRevoked and the new RevocationProvider satisfy
	// "has a way to check fresh revocation."
	if opts.ForceRevocationCheck && opts.IsRevoked == nil && opts.Revocation == nil {
		return invalid("force_revocation_no_callback", "ForceRevocationCheck is true but neither IsRevoked nor Revocation provider is set — the caller asked for fresh revocation state but provided no way to check it")
	}

	// --- Per-cert checks ---
	for i := range bundle.Delegations {
		cert := &bundle.Delegations[i]

		if cert.Version != ProtocolVersion {
			return invalid("version_mismatch", fmt.Sprintf("cert %d has unsupported version %d", i, cert.Version))
		}
		// Scope vocabulary validation (SPEC §9): every granted scope must be
		// canonical, a wildcard, or a custom: extension. Checked before any
		// scope arithmetic so invalid vocabulary can never reach the
		// effective-scope intersection.
		if err := ValidateScopes(cert.Scope); err != nil {
			return failWithStatus(IdentityStatusInvalidScope, fmt.Sprintf("cert %d: %v", i, err))
		}
		if now.Unix() > cert.ExpiresAt {
			return expired(humanID, bundle.AgentID)
		}
		if now.Unix() < cert.IssuedAt {
			return invalid("not_yet_valid", fmt.Sprintf("cert %d is not yet valid", i))
		}
		// Revocation check: Revocation provider (SPEC §17.1) takes precedence
		// over the legacy IsRevoked closure. Fail-closed — a provider error
		// surfaces as `revocation_error`, NOT a silent allow.
		if opts.Revocation != nil {
			rev, err := opts.Revocation.IsRevoked(cert.CertID)
			if err != nil {
				return invalid("revocation_error", fmt.Sprintf("cert %d: revocation lookup failed: %v", i, err))
			}
			if rev {
				return revoked(humanID, bundle.AgentID)
			}
		} else if opts.IsRevoked != nil && opts.IsRevoked(cert.CertID) {
			return revoked(humanID, bundle.AgentID)
		}
		if err := VerifyDelegationSignature(cert); err != nil {
			return invalid("bad_signature", fmt.Sprintf("cert %d: %v", i, err))
		}

		if err := evaluateConstraints(cert, opts.Context, now, opts.ConstraintEvaluators); err != nil {
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

	res := VerifyResult{
		Valid:          true,
		HumanID:        humanID,
		AgentID:        bundle.AgentID,
		GrantedScope:   effective,
		IdentityStatus: IdentityStatusAuthorizedAgent,
	}

	// --- Anchor resolution (SPEC §17.8) ---
	// Best-effort: populate Anchor on the success result so downstream
	// AuditProviders observe an identity-bound receipt. Resolver errors
	// are non-fatal — the bundle still verifies.
	if opts.AnchorResolver != nil {
		if anchor, err := opts.AnchorResolver.ResolveAnchor(humanID); err == nil && anchor != nil {
			res.Anchor = anchor
		}
	}

	// --- Advanced Policy Gating (SPEC §17.2 / §17.6) ---
	//
	// Fast path: if a PolicyVerdict is supplied AND verifies cleanly, skip
	// the live Policy provider entirely. This is how commercial backends
	// cut policy-server round-trips on streaming workloads: issue a verdict
	// once, the verifier accepts it locally for the rest of the window.
	if opts.PolicyVerdict != nil && opts.RequiredScope != "" {
		ctxHash, err := VerifierContextHash(opts.Context)
		if err != nil {
			return invalid("policy_error", fmt.Sprintf("verifier context hash failed: %v", err))
		}
		err = VerifyPolicyVerdict(
			opts.PolicyVerdict,
			opts.PolicySecret,
			bundle.AgentID,
			opts.RequiredScope,
			ctxHash,
			now,
		)
		switch {
		case err == nil:
			// Cached allow — skip Policy provider.
			return res
		case strings.HasPrefix(err.Error(), "policy_verdict_denied"):
			return failWithStatus(IdentityStatusScopeDenied, "policy verdict (cached) denied access")
		default:
			// MAC mismatch / expired / scope-mismatch → fall through to
			// live Policy provider (or pass if Policy is nil). Treat
			// transient verdict failures as "verdict unusable," NOT as
			// "policy denied." A stale verdict must not block a session.
		}
	}

	if opts.Policy != nil {
		ok, err := opts.Policy.EvaluatePolicy(bundle, opts.Context)
		if err != nil {
			return invalid("policy_error", fmt.Sprintf("advanced policy evaluation failed: %v", err))
		}
		if !ok {
			return failWithStatus(IdentityStatusScopeDenied, "advanced policy evaluation denied access")
		}
	}

	return res
}

// RevocationProvider determines if a certificate ID is currently revoked.
// (SPEC §17.1)
type RevocationProvider interface {
	IsRevoked(certID string) (bool, error)
}

// PolicyProvider evaluates application-level policy that exceeds the
// deterministic constraint logic defined in SPEC §5.7.2.
type PolicyProvider interface {
	EvaluatePolicy(bundle *ProofBundle, context VerifierContext) (bool, error)
}

// AuditProvider handles the persistence of verification receipts for
// compliance and forensic analysis.
// (SPEC §17.3)
type AuditProvider interface {
	LogVerification(result VerifyResult, bundle *ProofBundle) error
}

// AnchorResolver resolves a verified `human_id` to its external-identity
// binding — the `Anchor` originally registered when the HumanRoot was
// minted (SSO assertion, government ID attestation, email-verified, etc).
// Implementations typically read from a verifier-local identity directory.
// (SPEC §17.8)
//
// Errors are non-fatal: the verifier MUST NOT fail the bundle because the
// resolver errored. The verifier silently leaves `VerifyResult.Anchor` nil
// and continues. A nil resolver disables the lookup entirely.
type AnchorResolver interface {
	ResolveAnchor(humanID string) (*Anchor, error)
}

// ============================================================================
// Hybrid public key helpers
// ============================================================================

func hybridPubKeyEqual(a, b HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}

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

func failWithStatus(status, msg string) VerifyResult {
	return VerifyResult{
		Valid:          false,
		IdentityStatus: status,
		ErrorReason:    fmt.Sprintf("%s: %s", status, msg),
	}
}

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
