// Package ratify implements the Ratify Protocol — a cryptographic trust
// protocol for human-agent and agent-agent interactions as agents start
// to transact.
//
// v1 uses hybrid cryptography: every signature is a pair (Ed25519, ML-DSA-65).
// Both must verify for a signature to be considered valid. This provides
// defense in depth against classical cryptanalytic advances on either algorithm
// and resistance to quantum attacks via ML-DSA-65 (NIST FIPS 204).
//
// Core flow:
//  1. Each party generates a HybridPrivateKey containing one Ed25519 and
//     one ML-DSA-65 keypair. Seeds are independent.
//  2. Humans (or tenant admins, or already-delegated agents) sign Delegation
//     Certs granting another party specific scopes.
//  3. Agents sign a fresh challenge with both algorithms to prove liveness.
//  4. Verifiers check: chain signatures (both algs) + not expired + not
//     revoked + scope intersection valid + challenge fresh.
package ratify

import "encoding/json"

// ProtocolVersion is the current wire format version. v1 mandates hybrid
// Ed25519 + ML-DSA-65 signing on every signed object.
const ProtocolVersion = 1

// NoExpirySentinel is the ExpiresAt value that means "no expiry (until
// revoked)": 4070908799 = 2099-12-31 23:59:59 UTC. DelegationCert.ExpiresAt
// is a required int64 with no null representation, so open-ended delegations
// carry this sentinel in the signed bytes. Conformant implementations MUST
// treat a cert with ExpiresAt == NoExpirySentinel as "no expiry (until
// revoked)" in display and policy evaluation — NOT as a literal 2099 expiry.
// Verification is unchanged: the sentinel is a future timestamp, so the
// temporal check passes; revocation is the sole termination mechanism for
// such certs. See SPEC §5.7.
const NoExpirySentinel int64 = 4070908799

// HybridPublicKey pairs an Ed25519 public key with an ML-DSA-65 public key.
// Both are used for verification; a signature is accepted only if both
// component signatures verify against their respective component public keys.
//
// Canonical JSON form (keys in lex order):
//
//	{"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}
type HybridPublicKey struct {
	Ed25519 []byte `json:"ed25519"`   // 32 bytes
	MLDSA65 []byte `json:"ml_dsa_65"` // 1952 bytes (FIPS 204 ML-DSA-65)
}

// HybridSignature is an Ed25519 signature paired with an ML-DSA-65 signature
// over the same canonical bytes. Both MUST verify for the signature to be
// considered valid. Resists both classical cryptanalytic advances on either
// algorithm and quantum attacks (via ML-DSA-65's lattice-based security).
type HybridSignature struct {
	Ed25519 []byte `json:"ed25519"`   // 64 bytes
	MLDSA65 []byte `json:"ml_dsa_65"` // 3309 bytes (FIPS 204 ML-DSA-65)
}

// HumanRoot is the master identity for a human (or tenant admin, or any
// party that can delegate to agents). Only the public component travels on
// the wire. Private keys SHOULD be stored on the owner's device where
// possible (self-custody mode). Custodial deployments where a registry
// operator holds envelope-encrypted keys are a valid deployment mode with
// different trust assumptions — see SPEC.md §15.2.
type HumanRoot struct {
	// ID is hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16]) — lowercase hex.
	ID        string          `json:"id"`
	PublicKey HybridPublicKey `json:"public_key"`
	CreatedAt int64           `json:"created_at"`
	Anchors   []Anchor        `json:"anchors,omitempty"`
}

// Anchor optionally binds a HumanRoot to an external identity system (SSO,
// email, government ID) for higher assurance at registration time. Opaque
// references only — no PII on the wire.
type Anchor struct {
	Type       string `json:"type"`      // "enterprise_sso" | "email" | "government_id"
	Provider   string `json:"provider"`  // "okta" | "google" | "azure_ad"
	Reference  string `json:"reference"` // Opaque (privacy-preserving), not PII
	VerifiedAt int64  `json:"verified_at"`
}

// AgentIdentity is the keypair for an AI agent. Agents generate their own
// keypairs and request delegation from a principal (human or another agent).
type AgentIdentity struct {
	// ID is hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16]) — lowercase hex.
	ID        string          `json:"id"`
	PublicKey HybridPublicKey `json:"public_key"`
	Name      string          `json:"name"`
	AgentType string          `json:"agent_type"` // "zoom_bot", "voice_agent", "mcp_server", "custom"
	CreatedAt int64           `json:"created_at"`
}

// DelegationCert is a signed certificate granting an agent permission to act
// on behalf of a principal within defined scopes, a time window, and
// optionally an enumerated set of first-class Constraints (geo, time-of-day,
// speed, amount, rate). The scope answers "*what* may the agent do"; the
// constraints answer "*where/when/how much*."
//
// The Signature is a hybrid pair; both component signatures must verify
// independently against the IssuerPubKey for the cert to be accepted.
type DelegationCert struct {
	CertID        string          `json:"cert_id"`
	Version       int             `json:"version"` // = ProtocolVersion
	IssuerID      string          `json:"issuer_id"`
	IssuerPubKey  HybridPublicKey `json:"issuer_pub_key"`
	SubjectID     string          `json:"subject_id"`
	SubjectPubKey HybridPublicKey `json:"subject_pub_key"`
	Scope         []string        `json:"scope"`
	// Constraints may be empty but is always serialized — canonical form
	// requires `"constraints":[]` when none are declared, so signatures are
	// deterministic across issuers.
	Constraints []Constraint    `json:"constraints"`
	IssuedAt    int64           `json:"issued_at"`
	ExpiresAt   int64           `json:"expires_at"`
	Signature   HybridSignature `json:"signature"`
}

// IsNoExpiry reports whether the cert carries the NoExpirySentinel, meaning
// "no expiry (until revoked)". Callers rendering expiry to users or applying
// lifetime policy caps MUST branch on this rather than treating the sentinel
// as a real 2099 timestamp.
func (c *DelegationCert) IsNoExpiry() bool {
	return c.ExpiresAt == NoExpirySentinel
}

// Constraint is an optional, first-class bound on when / where / how much an
// agent may exercise its scopes. Constraints are evaluated at verify time
// against a VerifierContext supplied by the application. Verifiers fail
// closed: if the context lacks the inputs a constraint requires, the cert is
// rejected with `constraint_unverifiable`.
//
// The wire format is a tagged JSON object. Constraint.Type identifies the
// kind; the remaining fields are the kind-specific parameters. Unknown Type
// values MUST be rejected by conformant verifiers (fail-closed is the v1
// semantics).
//
// Constraint is a tagged union on wire. The struct carries every possible
// kind-specific field, but canonical serialization (MarshalJSON below) emits
// ONLY the fields meaningful for the specific Type plus `type` itself. That
// eliminates the v1 "zero-as-absence" ambiguity: a geo_circle
// at lat=0, lon=0 (equator / prime meridian) serializes with lat:0 and lon:0
// explicitly, not by omission, so the canonical bytes are unambiguous.
//
// Unknown Type serializes as `{"type": "<unknown>"}` with no other fields;
// the verifier catches unknown tags via isConstraintUnknown and fails closed.
type Constraint struct {
	Count     int            `json:"count,omitempty"`
	Currency  string         `json:"currency,omitempty"` // ISO 4217
	End       string         `json:"end,omitempty"`      // "HH:MM"
	Lat       float64        `json:"lat,omitempty"`
	Lon       float64        `json:"lon,omitempty"`
	MaxAltM   float64        `json:"max_alt_m,omitempty"`
	MaxAmount float64        `json:"max_amount,omitempty"`
	MaxLat    float64        `json:"max_lat,omitempty"`
	MaxLon    float64        `json:"max_lon,omitempty"`
	MaxMps    float64        `json:"max_mps,omitempty"` // m/s SI
	MinAltM   float64        `json:"min_alt_m,omitempty"`
	MinLat    float64        `json:"min_lat,omitempty"`
	MinLon    float64        `json:"min_lon,omitempty"`
	Points    [][2]float64   `json:"points,omitempty"` // [[lat,lon], ...]
	RadiusM   float64        `json:"radius_m,omitempty"`
	Start     string         `json:"start,omitempty"` // "HH:MM"
	Type      ConstraintType `json:"type"`
	TZ        string         `json:"tz,omitempty"` // IANA zone
	WindowS   int64          `json:"window_s,omitempty"`
}

// MarshalJSON emits the canonical per-kind shape. Keys are alphabetical —
// Go's encoding/json sorts map keys automatically. Zero values of
// kind-relevant fields ARE emitted (lat:0, lon:0 for a geo_circle at the
// equator/prime-meridian intersection); fields irrelevant to this kind
// are not emitted, so downstream parsers never see a stray unused zero.
//
// CROSS-SDK: TypeScript / Python / Rust MUST produce byte-identical output
// for the same input. See sdks/*/src/constraints.* for each SDK's
// canonicalConstraintDict helper.
func (c Constraint) MarshalJSON() ([]byte, error) {
	m := map[string]any{"type": string(c.Type)}
	switch c.Type {
	case ConstraintGeoCircle:
		m["lat"] = c.Lat
		m["lon"] = c.Lon
		m["radius_m"] = c.RadiusM
	case ConstraintGeoPolygon:
		m["points"] = c.Points
	case ConstraintGeoBBox:
		m["max_lat"] = c.MaxLat
		m["max_lon"] = c.MaxLon
		m["min_lat"] = c.MinLat
		m["min_lon"] = c.MinLon
		// Altitude bounds: emit as a pair iff either is set. Avoids
		// wire-format volume when altitude is irrelevant, while keeping
		// the zero-as-absence ambiguity closed for the pair.
		if c.MinAltM != 0 || c.MaxAltM != 0 {
			m["max_alt_m"] = c.MaxAltM
			m["min_alt_m"] = c.MinAltM
		}
	case ConstraintTimeWindow:
		m["end"] = c.End
		m["start"] = c.Start
		m["tz"] = c.TZ
	case ConstraintMaxSpeedMps:
		m["max_mps"] = c.MaxMps
	case ConstraintMaxAmount:
		m["currency"] = c.Currency
		m["max_amount"] = c.MaxAmount
	case ConstraintMaxRate:
		m["count"] = c.Count
		m["window_s"] = c.WindowS
	default:
		// Unknown kind — emit only the tag. Verifier returns
		// constraint_unknown on this shape.
	}
	return stdMarshal(m)
}

// stdMarshal is a trampoline so test code can override if needed; normally
// identical to encoding/json.Marshal.
var stdMarshal = json.Marshal

// ConstraintType is the discriminator for Constraint. Canonical v1 kinds:
type ConstraintType string

const (
	// ConstraintGeoCircle — valid only when the agent is within RadiusM of
	// (Lat, Lon). Haversine distance on WGS-84.
	ConstraintGeoCircle ConstraintType = "geo_circle"
	// ConstraintGeoPolygon — valid only when the agent is inside the polygon
	// defined by Points (at least 3 points, winding order irrelevant).
	ConstraintGeoPolygon ConstraintType = "geo_polygon"
	// ConstraintGeoBBox — valid only when the agent is inside the rectangular
	// bounding box [MinLat, MinLon] × [MaxLat, MaxLon], optionally with an
	// altitude floor/ceiling [MinAltM, MaxAltM]. Altitude bounds are ignored
	// if both are zero.
	ConstraintGeoBBox ConstraintType = "geo_bbox"
	// ConstraintTimeWindow — valid only when the current local time in TZ
	// falls within [Start, End]. Inclusive at both ends. End < Start means
	// the window wraps midnight.
	ConstraintTimeWindow ConstraintType = "time_window"
	// ConstraintMaxSpeedMps — the agent's current velocity must not exceed
	// MaxMps meters per second. Verifier requires current-speed in context.
	ConstraintMaxSpeedMps ConstraintType = "max_speed_mps"
	// ConstraintMaxAmount — the requested transaction amount must not exceed
	// MaxAmount in Currency. Verifier requires (amount, currency) in context.
	ConstraintMaxAmount ConstraintType = "max_amount"
	// ConstraintMaxRate — across a rolling WindowS seconds, at most Count
	// exercises of this cert are allowed. Verifier requires a rate-counter
	// callback in context.
	ConstraintMaxRate ConstraintType = "max_rate"
)

// VerifierContext carries the application-supplied inputs needed to evaluate
// first-class constraints at verify time. Fields are optional individually,
// but a cert bearing a constraint whose required context is absent will be
// rejected (fail-closed, v1 semantics).
type VerifierContext struct {
	// CurrentLat / CurrentLon / CurrentAltM — agent's current position.
	// Required by geo_circle, geo_polygon, geo_bbox.
	CurrentLat  float64
	CurrentLon  float64
	CurrentAltM float64
	HasLocation bool

	// CurrentSpeedMps — agent's current velocity in meters per second.
	// Required by max_speed_mps.
	CurrentSpeedMps float64
	HasSpeed        bool

	// RequestedAmount / RequestedCurrency — the transaction being authorized.
	// Required by max_amount.
	RequestedAmount   float64
	RequestedCurrency string
	HasAmount         bool

	// InvocationsInWindow looks up how many times this cert has been
	// exercised in the most recent `window` seconds. Required by max_rate.
	InvocationsInWindow func(certID string, windowS int64) int
}

// ProofBundle is what an agent presents to a verifier. The challenge
// signature proves the agent's private key is live right now; the delegation
// chain proves the agent was authorized by a principal. Used symmetrically
// in human-agent and agent-agent interactions.
//
// v1.1 optional stream binding: when StreamID and StreamSeq are populated, the
// bundle is "stream-bound" — it belongs to an ordered sequence of interactions
// sharing a StreamID. Both fields are signed into the challenge bytes (§6.4.2)
// so a proxy cannot replay, reorder, or omit bundles within the stream without
// invalidating the signature.
type ProofBundle struct {
	AgentID        string           `json:"agent_id"`
	AgentPubKey    HybridPublicKey  `json:"agent_pub_key"`
	Delegations    []DelegationCert `json:"delegations"` // [leaf, ..., root], depth 1..MaxDelegationChainDepth
	Challenge      []byte           `json:"challenge"`
	ChallengeAt    int64            `json:"challenge_at"`
	ChallengeSig   HybridSignature  `json:"challenge_sig"`
	SessionContext []byte           `json:"session_context,omitempty"` // optional 32-byte verifier/session binding
	StreamID       []byte           `json:"stream_id,omitempty"`       // optional 32-byte opaque stream identifier
	StreamSeq      int64            `json:"stream_seq,omitempty"`      // optional monotonic sequence number (≥1 when StreamID is set)
}

// VerifyResult is the deterministic output of Verify(). Always check Valid
// first; on success, inspect GrantedScope and AgentID.
type VerifyResult struct {
	Valid        bool     `json:"valid"`
	HumanID      string   `json:"human_id,omitempty"`
	AgentID      string   `json:"agent_id,omitempty"`
	AgentName    string   `json:"agent_name,omitempty"`
	AgentType    string   `json:"agent_type,omitempty"`
	GrantedScope []string `json:"granted_scope,omitempty"`
	// IdentityStatus is the closed-enum outcome of Verify. See the full
	// table in SPEC §5.9 and the IdentityStatus* constants in verify.go.
	// The current set is:
	//   authorized_agent, verified_human,
	//   expired, revoked,
	//   scope_denied, constraint_denied, constraint_unverifiable,
	//   constraint_unknown, delegation_not_authorized,
	//   invalid, unauthorized.
	// Adding a new status is a spec change — never invent values locally.
	IdentityStatus string `json:"identity_status"`
	ErrorReason    string `json:"error_reason,omitempty"`
	// Anchor is the resolved external-identity binding for the
	// HumanID (SPEC §17.8). Populated by Verify only when the caller
	// supplies a `VerifyOptions.AnchorResolver` AND the bundle verifies.
	// When set, downstream `AuditProvider`s can record "this verification
	// was tied to an SSO-bound human at Okta," etc., giving compliance
	// auditors a chain from VerificationReceipt → identity attestation.
	// Nil when no resolver is configured or no Anchor was found.
	Anchor *Anchor `json:"anchor,omitempty"`
}

// RevocationList is a signed list of revoked CertIDs, served by the issuer
// (or by a registry acting on the issuer's behalf). Verifiers should cache
// with a short TTL and fail-closed on sustained unreachability.
type RevocationList struct {
	IssuerID     string          `json:"issuer_id"`
	UpdatedAt    int64           `json:"updated_at"`
	RevokedCerts []string        `json:"revoked_certs"`
	Signature    HybridSignature `json:"signature"`
}

// RevocationPush is a v1.1 signed notification payload that a revocation-list
// issuer sends to subscribed verifiers in real time. The payload itself is
// hybrid-signed by the issuer, so a verifier can trust it without re-fetching
// the full revocation list. Verifiers that cannot maintain long-lived
// subscriptions (edge, serverless) continue using the pull model; this is for
// verifiers that need sub-second revocation propagation.
//
// The Entries field carries the delta — cert IDs newly added to the revocation
// list since the previous push. A verifier applies the delta to its local
// revocation cache. The SeqNo field is monotonically increasing per issuer so
// receivers can detect missed pushes and fall back to a full list fetch.
type RevocationPush struct {
	IssuerID  string          `json:"issuer_id"`
	SeqNo     int64           `json:"seq_no"`    // monotonically increasing; first push is 1
	Entries   []string        `json:"entries"`   // cert IDs being revoked in this push
	PushedAt  int64           `json:"pushed_at"` // unix seconds
	Signature HybridSignature `json:"signature"`
}

// WitnessEntry is a v1.1 spec-defined element in a hash-chain append-only
// log. Any party may operate a Witness: Identities AI, an enterprise's own
// audit system, a third-party notary, or a blockchain-anchored system.
// Multiple witnesses MAY independently log the same events (redundancy).
//
// v1.1 defines the shape only. Operating a scalable witness is an
// implementation concern; the spec does not mandate deployment topology.
type WitnessEntry struct {
	PrevHash  []byte          `json:"prev_hash"`  // 32 bytes; zeros for genesis
	EntryData []byte          `json:"entry_data"` // the receipt/cert/revocation being witnessed
	Timestamp int64           `json:"timestamp"`
	WitnessID string          `json:"witness_id"`
	Signature HybridSignature `json:"signature"`
}

// VerificationReceipt is a verifier-signed attestation that a specific
// `ProofBundle` was verified at a specific moment with a specific outcome
// (SPEC §17.5). It is the cryptographic complement of `AuditProvider`: an
// AuditProvider chooses what to do with verification events; a
// VerificationReceipt makes the event itself unforgeable, so any auditor
// — even one that doesn't trust the verifier operator — can independently
// confirm the verifier saw what it claims it saw.
//
// Receipts chain by `prev_hash` so a missing or backdated receipt is
// detectable: an immutable verification log is just a sequence of
// `VerificationReceipt`s where each one's `prev_hash` is the SHA-256 of
// the previous receipt's canonical signable bytes. Genesis uses 32 zero
// bytes.
//
// Receipts are OPTIONAL — the protocol does not auto-issue them. SDKs ship
// `IssueVerificationReceipt` and `VerifyVerificationReceipt` helpers, and
// downstream `AuditProvider` implementations may choose to wrap each
// `VerifyResult` in a receipt before persisting it. Wire format is
// unchanged whether receipts are issued or not.
type VerificationReceipt struct {
	Version      int             `json:"version"`        // = ProtocolVersion
	VerifierID   string          `json:"verifier_id"`    // derived ID of verifier's signing key
	VerifierPub  HybridPublicKey `json:"verifier_pub"`   // the key used to sign this receipt
	BundleHash   []byte          `json:"bundle_hash"`    // SHA-256 of canonical bundle bytes
	Decision     string          `json:"decision"`       // identity_status from VerifyResult
	HumanID      string          `json:"human_id,omitempty"`
	AgentID      string          `json:"agent_id,omitempty"`
	GrantedScope []string        `json:"granted_scope,omitempty"`
	ErrorReason  string          `json:"error_reason,omitempty"`
	VerifiedAt   int64           `json:"verified_at"`     // unix seconds
	PrevHash     []byte          `json:"prev_hash"`       // 32 bytes; zeros for genesis
	Signature    HybridSignature `json:"signature"`       // hybrid sig over canonical bytes
}

// KeyRotationStatement links an old root key to a new root key. Both keys
// sign the same canonical bytes: the old key authorizes continuity, and the
// new key proves possession. This is backward-compatible with v1 certs; it is
// consumed by registries/auditors that need continuity across root rotations.
type KeyRotationStatement struct {
	Version      int             `json:"version"` // = ProtocolVersion
	OldID        string          `json:"old_id"`
	OldPubKey    HybridPublicKey `json:"old_pub_key"`
	NewID        string          `json:"new_id"`
	NewPubKey    HybridPublicKey `json:"new_pub_key"`
	RotatedAt    int64           `json:"rotated_at"`
	Reason       string          `json:"reason"`
	SignatureOld HybridSignature `json:"signature_old"`
	SignatureNew HybridSignature `json:"signature_new"`
}

// TransactionReceipt is the v1.1 canonical envelope for a multi-party,
// atomic transaction. Every listed party signs the same signable (version,
// transaction_id, created_at, terms_schema_uri, terms_canonical_json,
// sorted party set) so altering or omitting any party invalidates every
// other party's signature — no partial-valid receipt state exists.
//
// Ratify does not interpret `TermsCanonicalJSON` (the business terms); the
// application owns that schema. `TermsSchemaURI` identifies which schema a
// specialized verifier would dispatch on. Ratify guarantees the envelope
// atomicity and party signatures.
type TransactionReceipt struct {
	Version            int                     `json:"version"` // = ProtocolVersion
	TransactionID      string                  `json:"transaction_id"`
	CreatedAt          int64                   `json:"created_at"`
	TermsSchemaURI     string                  `json:"terms_schema_uri"`
	TermsCanonicalJSON []byte                  `json:"terms_canonical_json"`
	Parties            []ReceiptParty          `json:"parties"`
	PartySignatures    []ReceiptPartySignature `json:"party_signatures"`
}

// ReceiptParty is one party to a TransactionReceipt. Each party presents
// a ProofBundle that is verified independently by the generic verifier;
// only the identifying fields (`party_id`, `role`, `agent_id`,
// `agent_pub_key`) enter the signable. The proof bundle is therefore
// ambient evidence, not part of the cryptographic binding.
type ReceiptParty struct {
	PartyID     string          `json:"party_id"`
	Role        string          `json:"role"`
	AgentID     string          `json:"agent_id"`
	AgentPubKey HybridPublicKey `json:"agent_pub_key"`
	ProofBundle ProofBundle     `json:"proof_bundle"`
}

// ReceiptPartySignature carries the hybrid signature by party `party_id`'s
// agent key over the canonical signable. The `party_id` acts as the index
// back into the `Parties` array — verifiers MUST reject duplicate party_id
// signatures and signatures for party_ids absent from `Parties`.
type ReceiptPartySignature struct {
	PartyID   string          `json:"party_id"`
	Signature HybridSignature `json:"signature"`
}

// SessionToken is a v1.1 verifier-issued credential that caches the result of
// a full chain verification for the lifetime of a session. After a verifier
// has fully verified a ProofBundle once (hybrid signatures on every cert,
// freshness, scope, constraints, etc.), it MAY issue a SessionToken that
// binds the verified chain and agent to the verifier's session. Subsequent
// turns present the token alongside a fresh ChallengeSig; the verifier
// recomputes and checks the token's HMAC, confirms validity, and verifies the
// hybrid challenge signature — avoiding full chain re-verification.
//
// MAC = HMAC-SHA256(session_secret, SessionTokenSignBytes(token)). Token
// lifetime is bounded by ValidUntil. ChainHash binds the token to the exact
// chain the verifier accepted, so a cert rotation invalidates every previously
// issued token.
//
// The session_secret is private to the verifier (never leaves the verifier's
// trust boundary). Tokens do not travel beyond a single verifier's scope.
type SessionToken struct {
	Version      int             `json:"version"` // = ProtocolVersion
	SessionID    string          `json:"session_id"`
	AgentID      string          `json:"agent_id"`
	AgentPubKey  HybridPublicKey `json:"agent_pub_key"`
	HumanID      string          `json:"human_id"`
	GrantedScope []string        `json:"granted_scope"` // sorted lex
	IssuedAt     int64           `json:"issued_at"`
	ValidUntil   int64           `json:"valid_until"`
	ChainHash    []byte          `json:"chain_hash"` // 32 bytes — SHA-256 of concatenated delegation sign bytes
	MAC          []byte          `json:"mac"`        // 32 bytes — HMAC-SHA256 over canonical signable bytes
}

// PolicyVerdict is a v1.1 verifier-cached policy decision: a short-lived
// HMAC-bound attestation that a given (agent_id, scope, context_hash) tuple
// passed advanced policy evaluation at a specific moment (SPEC §17.6). It is
// the policy equivalent of `SessionToken`: instead of caching the result of
// a full *chain* verification, it caches the result of a `PolicyProvider`
// evaluation — letting subsequent calls within ValidUntil accept the cached
// allow/deny without re-calling the policy backend.
//
// MAC semantics are identical to `SessionToken`:
//
//	mac = HMAC-SHA256(policy_secret, PolicyVerdictSignBytes(verdict))
//
// `policy_secret` is private to whoever issued the verdict — a commercial
// backend typically holds it, gives only public verdict objects to the
// verifier, and rotates the secret to invalidate stale verdicts globally.
//
// `ContextHash` is the canonical SHA-256 of the VerifierContext used during
// the original evaluation. If a verifier later runs with a different context,
// the verdict no longer applies — preventing a verdict cached for one
// context from leaking into another (e.g. different country, different
// amount tier).
type PolicyVerdict struct {
	Version     int    `json:"version"` // = ProtocolVersion
	VerdictID   string `json:"verdict_id"`
	AgentID     string `json:"agent_id"`
	Scope       string `json:"scope"`        // the specific scope this verdict allows
	Allow       bool   `json:"allow"`        // false = explicit cached deny
	ContextHash []byte `json:"context_hash"` // 32 bytes — SHA-256 of canonical VerifierContext
	IssuedAt    int64  `json:"issued_at"`
	ValidUntil  int64  `json:"valid_until"`
	MAC         []byte `json:"mac"` // 32 bytes — HMAC-SHA256 over canonical signable bytes
}
