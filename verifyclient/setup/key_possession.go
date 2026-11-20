package setup

import (
	"fmt"
	"regexp"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// A key-possession proof (Verify Trust Profile code 0x0114) is how a holder
// enrolls a fresh Protocol v2 hybrid key: the new key itself signs a
// single-use enrollment challenge that names exactly what is being enrolled
// (audience, role, owner, custody) under the Verify signature transcript,
// with both Ed25519 and ML-DSA-65 required. Protocol v2 has no genesis
// enrollment object (SPEC-v2 section 1: v2 requires fresh keys and proof of
// possession), so this Verify object is that proof. It never carries
// authority on its own: Verify also authenticates the requesting person or
// organization, issues and consumes the challenge exactly once, and rejects
// keys or key components already known in any role.
const (
	v2VerifyCodeKeyPossession  = 0x0114
	v2KeyPossessionSchema      = "ratify.verify.key_possession_proof"
	v2MaxKeyPossessionBytes    = 16 << 10
	v2MaxKeyPossessionLifetime = 15 * 60
)

// Enrollable key roles. Each role's key is distinct; one key never serves two
// roles.
var v2KeyRoles = map[string]bool{
	"personal_root": true, "organization_root": true, "issuer": true, "agent": true, "receiver": true, "issuer_status": true, "approver": true,
}

// Custody modes. ratify_custodial is never acceptable for a key that signs
// high-risk grants.
var v2KeyCustody = map[string]bool{"customer_held": true, "ratify_custodial": true}

var (
	v2Hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	v2Hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// V2KeyPossessionProof is the signed body. KeyID must equal KeyIDV2 of
// PublicKey; a verifier recomputes it and never trusts the supplied value.
type V2KeyPossessionProof struct {
	Audience    string                 `json:"audience"`
	Challenge   string                 `json:"challenge"`
	ChallengeID string                 `json:"challenge_id"`
	CustodyMode string                 `json:"custody_mode"`
	ExpiresAt   int64                  `json:"expires_at"`
	IssuedAt    int64                  `json:"issued_at"`
	KeyID       string                 `json:"key_id"`
	OwnerID     string                 `json:"owner_id"`
	PublicKey   ratify.HybridPublicKey `json:"public_key"`
	Role        string                 `json:"role"`
	Schema      string                 `json:"schema"`
	Version     int                    `json:"version"`
	VerifyCode  uint16                 `json:"verify_code"`
}

// V2KeyEnrollmentExpectation is the challenge Verify issued: every field
// comes from the issued challenge, never from the proof.
type V2KeyEnrollmentExpectation struct {
	Audience    string
	Challenge   string
	ChallengeID string
	CustodyMode string
	OwnerID     string
	Role        string
}

func (p *V2KeyPossessionProof) validate() error {
	if p.Schema != v2KeyPossessionSchema || p.Version != v2TrustProfileVersion || p.VerifyCode != v2VerifyCodeKeyPossession {
		return fmt.Errorf("key-possession proof body type or code is invalid")
	}
	if p.Audience == "" || len(p.Audience) > 256 || p.OwnerID == "" || len(p.OwnerID) > 256 ||
		!v2Hex32.MatchString(p.ChallengeID) || !v2Hex64.MatchString(p.Challenge) || !v2Hex64.MatchString(p.KeyID) {
		return fmt.Errorf("key-possession proof identifiers are invalid")
	}
	if !v2KeyRoles[p.Role] || !v2KeyCustody[p.CustodyMode] {
		return fmt.Errorf("key-possession proof role or custody mode is invalid")
	}
	if p.IssuedAt < 0 || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > v2MaxKeyPossessionLifetime {
		return fmt.Errorf("key-possession proof lifetime is invalid")
	}
	id, err := V2KeyID(p.PublicKey)
	if err != nil {
		return fmt.Errorf("key-possession proof public key: %w", err)
	}
	if id != p.KeyID {
		return fmt.Errorf("key-possession proof key ID does not match its public key")
	}
	return nil
}

// SignV2KeyPossessionProof builds the 0x0114 proof for key, signs it with
// that key, and verifies both signature components before returning it.
func SignV2KeyPossessionProof(body V2KeyPossessionProof, key ratify.HybridPrivateKey) ([]byte, error) {
	body.Schema, body.Version, body.VerifyCode = v2KeyPossessionSchema, v2TrustProfileVersion, v2VerifyCodeKeyPossession
	body.PublicKey = key.Public()
	id, err := V2KeyID(body.PublicKey)
	if err != nil {
		return nil, err
	}
	body.KeyID = id
	if err := body.validate(); err != nil {
		return nil, err
	}
	bodyBytes, err := ratify.CanonicalJSON(body)
	if err != nil {
		return nil, err
	}
	signature, err := signV2VerifyObject(v2VerifyCodeKeyPossession, bodyBytes, key)
	if err != nil {
		return nil, err
	}
	if err := verifyV2VerifyObject(v2VerifyCodeKeyPossession, bodyBytes, signature, body.PublicKey); err != nil {
		return nil, fmt.Errorf("key-possession proof signer returned an invalid signature: %w", err)
	}
	return ratify.CanonicalJSON(v2SignedVerifyObject{Body: bodyBytes, ObjectType: v2KeyPossessionSchema,
		ProfileVersion: v2TrustProfileVersion, Signature: signature, SignerKeyID: id, VerifyCode: v2VerifyCodeKeyPossession})
}

// VerifyV2KeyPossessionProof checks exact proof bytes against the
// expectation for the challenge at unix time now, and returns the enrolled
// public key and its recomputed key ID. Single use, owner authentication, and
// duplicate-key rejection are not checked here.
func VerifyV2KeyPossessionProof(data []byte, expected V2KeyEnrollmentExpectation, now int64) (ratify.HybridPublicKey, string, error) {
	if len(data) < 2 || len(data) > v2MaxKeyPossessionBytes {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof size is invalid")
	}
	var envelope v2SignedVerifyObject
	if err := decodeV2Strict(data, &envelope); err != nil {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof envelope: %w", err)
	}
	if envelope.ObjectType != v2KeyPossessionSchema || envelope.VerifyCode != v2VerifyCodeKeyPossession ||
		envelope.ProfileVersion != v2TrustProfileVersion {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof envelope type or code is invalid")
	}
	var proof V2KeyPossessionProof
	if err := decodeV2Strict(envelope.Body, &proof); err != nil {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof body: %w", err)
	}
	if err := proof.validate(); err != nil {
		return ratify.HybridPublicKey{}, "", err
	}
	if envelope.SignerKeyID != proof.KeyID {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof is not signed by the key it enrolls")
	}
	if err := verifyV2VerifyObject(v2VerifyCodeKeyPossession, envelope.Body, envelope.Signature, proof.PublicKey); err != nil {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof signature: %w", err)
	}
	if proof.Audience != expected.Audience || proof.ChallengeID != expected.ChallengeID ||
		proof.Challenge != expected.Challenge || proof.Role != expected.Role ||
		proof.OwnerID != expected.OwnerID || proof.CustodyMode != expected.CustodyMode {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof does not match the issued enrollment challenge")
	}
	if now < proof.IssuedAt-60 || now >= proof.ExpiresAt {
		return ratify.HybridPublicKey{}, "", fmt.Errorf("key-possession proof is not within its validity window")
	}
	return proof.PublicKey, proof.KeyID, nil
}
