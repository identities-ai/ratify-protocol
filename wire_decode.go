package ratify

// Wire decoders — the official way to turn untrusted wire JSON back into
// protocol structures, and the VerificationReceipt codec pair (SPEC §17.5).
//
// Every decoder is strict (SPEC §6.2, alpha.15 wire acceptance): the input
// passes CheckWireJSON (UTF-8, duplicate keys, integer domain, canonical
// base64, nesting depth) and unknown fields are rejected. Input bounds
// (SPEC §5.1) are enforced here: DecodeProofBundle rejects an oversized
// payload BEFORE parsing; scope/constraint counts and string lengths are
// checked during decode. Violations are structural failures — callers
// surface them as the existing `invalid` status.

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("wire: %w", err)
	}
	return nil
}

// checkCertBounds enforces the per-cert count and length limits of
// SPEC §5.1 during decode. It does NOT enforce issuance hygiene
// (ValidateResourceConstraints) — decoders accept what issuance rejects;
// verification fails unsatisfiable sets closed.
func checkCertBounds(cert *DelegationCert) error {
	if len(cert.Scope) > MaxScopesPerCert {
		return fmt.Errorf("wire: %d scopes exceeds MAX_SCOPES_PER_CERT (%d)", len(cert.Scope), MaxScopesPerCert)
	}
	if len(cert.Constraints) > MaxConstraintsPerCert {
		return fmt.Errorf("wire: %d constraints exceeds MAX_CONSTRAINTS_PER_CERT (%d)", len(cert.Constraints), MaxConstraintsPerCert)
	}
	for _, s := range cert.Scope {
		if len(s) > MaxScopeLengthBytes {
			return fmt.Errorf("wire: scope of %d bytes exceeds MAX_SCOPE_LENGTH_BYTES (%d)", len(s), MaxScopeLengthBytes)
		}
	}
	for i := range cert.Constraints {
		c := &cert.Constraints[i]
		if len(c.ResourceID) > MaxIdentifierLengthBytes {
			return fmt.Errorf("wire: resource_id of %d bytes exceeds MAX_IDENTIFIER_LENGTH_BYTES (%d)", len(c.ResourceID), MaxIdentifierLengthBytes)
		}
		if c.Params != nil {
			if isCanonicalConstraintType(c.Type) {
				return fmt.Errorf("wire: canonical constraint type %q must not carry params", c.Type)
			}
			if err := ValidateParamsValue(c.Params, 0); err != nil {
				return fmt.Errorf("wire: constraint params: %w", err)
			}
		}
	}
	return nil
}

// DecodeDelegationCert parses canonical wire JSON into a DelegationCert
// under strict wire acceptance and the SPEC §5.1 input bounds.
func DecodeDelegationCert(data []byte) (*DelegationCert, error) {
	if err := CheckWireJSON(data); err != nil {
		return nil, err
	}
	var cert DelegationCert
	if err := strictUnmarshal(data, &cert); err != nil {
		return nil, err
	}
	if err := checkCertBounds(&cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// DecodeProofBundle parses canonical wire JSON into a ProofBundle under
// strict wire acceptance and the SPEC §5.1 input bounds. The
// MaxProofBundleBytes check runs BEFORE any parsing: an oversized payload
// is rejected without being parsed at all.
func DecodeProofBundle(data []byte) (*ProofBundle, error) {
	if len(data) > MaxProofBundleBytes {
		return nil, fmt.Errorf("wire: proof bundle of %d bytes exceeds MAX_PROOF_BUNDLE_BYTES (%d)", len(data), MaxProofBundleBytes)
	}
	if err := CheckWireJSON(data); err != nil {
		return nil, err
	}
	var bundle ProofBundle
	if err := strictUnmarshal(data, &bundle); err != nil {
		return nil, err
	}
	if len(bundle.Delegations) > MaxDelegationChainDepth {
		return nil, fmt.Errorf("wire: delegation chain of depth %d exceeds MAX_DELEGATION_CHAIN_DEPTH (%d)", len(bundle.Delegations), MaxDelegationChainDepth)
	}
	for i := range bundle.Delegations {
		if err := checkCertBounds(&bundle.Delegations[i]); err != nil {
			return nil, err
		}
	}
	return &bundle, nil
}

// DecodeSessionToken parses canonical wire JSON into a SessionToken under
// strict wire acceptance.
func DecodeSessionToken(data []byte) (*SessionToken, error) {
	if err := CheckWireJSON(data); err != nil {
		return nil, err
	}
	var token SessionToken
	if err := strictUnmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// validReceiptDecisions is the closed identity_status vocabulary a receipt
// may attest (SPEC §5.9, §17.5). Receipts record verifier decisions;
// a string outside the enum is structurally invalid on both codec sides.
var validReceiptDecisions = map[string]bool{
	IdentityStatusAuthorizedAgent:         true,
	IdentityStatusVerifiedHuman:           true,
	IdentityStatusExpired:                 true,
	IdentityStatusRevoked:                 true,
	IdentityStatusScopeDenied:             true,
	IdentityStatusConstraintDenied:        true,
	IdentityStatusConstraintUnverifiable:  true,
	IdentityStatusConstraintUnknown:       true,
	IdentityStatusInvalidScope:            true,
	IdentityStatusDelegationNotAuthorized: true,
	IdentityStatusInvalid: true,
	// "unauthorized" is reserved in the §5.9 enum (never emitted by the
	// reference verifier); a receipt carrying it is enum-valid on the wire.
	"unauthorized": true,
}

// checkReceiptStructure enforces the structural invariants of a wire
// VerificationReceipt (SPEC §17.5) — shared by the encoder and decoder so
// the codec pair never emits a document its counterpart rejects.
func checkReceiptStructure(r *VerificationReceipt) error {
	if r == nil {
		return fmt.Errorf("wire: nil verification receipt")
	}
	if r.Version != ProtocolVersion {
		return fmt.Errorf("wire: receipt version %d is not PROTOCOL_VERSION (%d)", r.Version, ProtocolVersion)
	}
	if r.VerifierID == "" {
		return fmt.Errorf("wire: receipt verifier_id must be non-empty")
	}
	if !validReceiptDecisions[r.Decision] {
		return fmt.Errorf("wire: receipt decision %q is not a known identity_status", r.Decision)
	}
	if len(r.BundleHash) != 32 {
		return fmt.Errorf("wire: bundle_hash must be 32 bytes, got %d", len(r.BundleHash))
	}
	if len(r.PrevHash) != 32 {
		return fmt.Errorf("wire: prev_hash must be 32 bytes, got %d", len(r.PrevHash))
	}
	if len(r.VerifierPub.Ed25519) != 32 {
		return fmt.Errorf("wire: verifier_pub.ed25519 must be 32 bytes, got %d", len(r.VerifierPub.Ed25519))
	}
	if len(r.VerifierPub.MLDSA65) != 1952 {
		return fmt.Errorf("wire: verifier_pub.ml_dsa_65 must be 1952 bytes, got %d", len(r.VerifierPub.MLDSA65))
	}
	if len(r.Signature.Ed25519) != 64 {
		return fmt.Errorf("wire: signature.ed25519 must be 64 bytes, got %d", len(r.Signature.Ed25519))
	}
	if len(r.Signature.MLDSA65) != 3309 {
		return fmt.Errorf("wire: signature.ml_dsa_65 must be 3309 bytes, got %d", len(r.Signature.MLDSA65))
	}
	return nil
}

// verificationReceiptWire mirrors VerificationReceipt with fields in
// alphabetical JSON-key order (Go marshals in declaration order); optional
// fields are omitted when empty, matching the signable subset's discipline
// in crypto.go.
type verificationReceiptWire struct {
	AgentID      string          `json:"agent_id,omitempty"`
	BundleHash   []byte          `json:"bundle_hash"`
	Decision     string          `json:"decision"`
	ErrorReason  string          `json:"error_reason,omitempty"`
	GrantedScope []string        `json:"granted_scope,omitempty"`
	HumanID      string          `json:"human_id,omitempty"`
	PrevHash     []byte          `json:"prev_hash"`
	Signature    HybridSignature `json:"signature"`
	VerifiedAt   int64           `json:"verified_at"`
	VerifierID   string          `json:"verifier_id"`
	VerifierPub  HybridPublicKey `json:"verifier_pub"`
	Version      int             `json:"version"`
}

// EncodeVerificationReceipt marshals a VerificationReceipt into its
// canonical wire JSON (SPEC §17.5): lex-sorted keys, byte fields as
// base64-standard strings, optional fields omitted when empty. A
// structurally invalid receipt (wrong hash or key lengths, unknown
// decision, wrong version) is an error, never emitted: the codec pair
// never produces a document its own decoder rejects. Integer fields
// outside the safe-integer domain are an error, never emitted.
func EncodeVerificationReceipt(r *VerificationReceipt) ([]byte, error) {
	if err := checkReceiptStructure(r); err != nil {
		return nil, err
	}
	w := verificationReceiptWire{
		AgentID:      r.AgentID,
		BundleHash:   r.BundleHash,
		Decision:     r.Decision,
		ErrorReason:  r.ErrorReason,
		GrantedScope: r.GrantedScope,
		HumanID:      r.HumanID,
		PrevHash:     r.PrevHash,
		Signature:    r.Signature,
		VerifiedAt:   r.VerifiedAt,
		VerifierID:   r.VerifierID,
		VerifierPub:  r.VerifierPub,
		Version:      r.Version,
	}
	return CanonicalJSON(w)
}

// DecodeVerificationReceipt parses canonical wire JSON into a
// VerificationReceipt under strict wire acceptance and the same
// structural invariants the encoder enforces (hash and key component
// lengths, known decision, protocol version). Signature verification is
// the caller's job via VerifyVerificationReceipt.
func DecodeVerificationReceipt(data []byte) (*VerificationReceipt, error) {
	if err := CheckWireJSON(data); err != nil {
		return nil, err
	}
	var w verificationReceiptWire
	if err := strictUnmarshal(data, &w); err != nil {
		return nil, err
	}
	r := &VerificationReceipt{
		Version:      w.Version,
		VerifierID:   w.VerifierID,
		VerifierPub:  w.VerifierPub,
		BundleHash:   w.BundleHash,
		Decision:     w.Decision,
		HumanID:      w.HumanID,
		AgentID:      w.AgentID,
		GrantedScope: w.GrantedScope,
		ErrorReason:  w.ErrorReason,
		VerifiedAt:   w.VerifiedAt,
		PrevHash:     w.PrevHash,
		Signature:    w.Signature,
	}
	if err := checkReceiptStructure(r); err != nil {
		return nil, err
	}
	return r, nil
}
