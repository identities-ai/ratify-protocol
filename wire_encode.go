package ratify

// Wire encoders — the official way to turn protocol structures into their
// canonical wire JSON (SPEC §5.7, §5.8, §16.3): lex-sorted keys, byte
// fields as base64-standard strings, optional v1.1 fields omitted when
// empty. All three route through CanonicalJSON, so integer fields are
// validated against the safe-integer domain (SPEC §6.2) and the encoder
// returns an error rather than emitting a document strict wire decoders
// reject. Direct json.Marshal of the exported structs would emit fields in
// declaration order, not canonical order — always encode wire documents
// through these helpers.

// delegationCertWire mirrors DelegationCert with fields in alphabetical
// JSON-key order (Go marshals in declaration order) and includes the
// signature — unlike delegationSignable, which is the signed subset.
type delegationCertWire struct {
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

type proofBundleWire struct {
	AgentID        string               `json:"agent_id"`
	AgentPubKey    HybridPublicKey      `json:"agent_pub_key"`
	Challenge      []byte               `json:"challenge"`
	ChallengeAt    int64                `json:"challenge_at"`
	ChallengeSig   HybridSignature      `json:"challenge_sig"`
	Delegations    []delegationCertWire `json:"delegations"`
	SessionContext []byte               `json:"session_context,omitempty"`
	StreamID       []byte               `json:"stream_id,omitempty"`
	StreamSeq      int64                `json:"stream_seq,omitempty"`
}

type sessionTokenWire struct {
	AgentID      string          `json:"agent_id"`
	AgentPubKey  HybridPublicKey `json:"agent_pub_key"`
	ChainHash    []byte          `json:"chain_hash"`
	GrantedScope []string        `json:"granted_scope"`
	HumanID      string          `json:"human_id"`
	IssuedAt     int64           `json:"issued_at"`
	MAC          []byte          `json:"mac"`
	SessionID    string          `json:"session_id"`
	ValidUntil   int64           `json:"valid_until"`
	Version      int             `json:"version"`
}

func delegationCertWireOf(cert *DelegationCert) delegationCertWire {
	constraints := cert.Constraints
	if constraints == nil {
		// Canonical form serializes constraints as [] when empty, never null.
		constraints = []Constraint{}
	}
	return delegationCertWire{
		CertID:        cert.CertID,
		Constraints:   constraints,
		ExpiresAt:     cert.ExpiresAt,
		IssuedAt:      cert.IssuedAt,
		IssuerID:      cert.IssuerID,
		IssuerPubKey:  cert.IssuerPubKey,
		Scope:         cert.Scope,
		Signature:     cert.Signature,
		SubjectID:     cert.SubjectID,
		SubjectPubKey: cert.SubjectPubKey,
		Version:       cert.Version,
	}
}

// EncodeDelegationCert marshals cert into its canonical wire JSON
// (SPEC §5.7). Integer fields outside the safe-integer domain are an
// error, never emitted.
func EncodeDelegationCert(cert *DelegationCert) ([]byte, error) {
	w := delegationCertWireOf(cert)
	return CanonicalJSON(w)
}

// EncodeProofBundle marshals bundle into its canonical wire JSON
// (SPEC §5.8). Optional v1.1 fields (session_context, stream_id,
// stream_seq) are omitted when empty, matching the reference wire form.
// Integer fields outside the safe-integer domain are an error, never
// emitted.
func EncodeProofBundle(bundle *ProofBundle) ([]byte, error) {
	delegations := make([]delegationCertWire, len(bundle.Delegations))
	for i := range bundle.Delegations {
		delegations[i] = delegationCertWireOf(&bundle.Delegations[i])
	}
	w := proofBundleWire{
		AgentID:        bundle.AgentID,
		AgentPubKey:    bundle.AgentPubKey,
		Challenge:      bundle.Challenge,
		ChallengeAt:    bundle.ChallengeAt,
		ChallengeSig:   bundle.ChallengeSig,
		Delegations:    delegations,
		SessionContext: bundle.SessionContext,
		StreamID:       bundle.StreamID,
		StreamSeq:      bundle.StreamSeq,
	}
	return CanonicalJSON(w)
}

// EncodeSessionToken marshals token into its canonical wire JSON
// (SPEC §16.3). Integer fields outside the safe-integer domain are an
// error, never emitted.
func EncodeSessionToken(token *SessionToken) ([]byte, error) {
	w := sessionTokenWire{
		AgentID:      token.AgentID,
		AgentPubKey:  token.AgentPubKey,
		ChainHash:    token.ChainHash,
		GrantedScope: token.GrantedScope,
		HumanID:      token.HumanID,
		IssuedAt:     token.IssuedAt,
		MAC:          token.MAC,
		SessionID:    token.SessionID,
		ValidUntil:   token.ValidUntil,
		Version:      token.Version,
	}
	return CanonicalJSON(w)
}
