package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Combined key setup. The customer's machine writes one request file,
// Verify answers with one challenge bundle, and the machine answers with one
// proof file. These are the three file formats. Every file is canonical
// JSON, so its digest is stable across the crossings.

const (
	V2KeySetupRequestKind = "ratify-key-setup-request"
	V2KeySetupBundleKind  = "ratify-key-setup-bundle"
	V2KeySetupProofsKind  = "ratify-key-setup-proofs"
	v2KeySetupMaxWire     = 65536
)

// V2KeySetupRequest is what `ratify-keys setup issuer --offline` writes:
// public keys only, plus the issuer authorization the root signed locally.
// It names the one organization it is for: Verify refuses it anywhere else,
// and ratify-keys signs only a bundle for that organization.
// With NewRoot false the root is the organization's current root and is not
// enrolled again.
type V2KeySetupRequest struct {
	Epoch               uint64                 `json:"epoch"`
	IssuerAuthorization []byte                 `json:"issuer_authorization"`
	IssuerPublicKey     ratify.HybridPublicKey `json:"issuer_public_key"`
	Kind                string                 `json:"kind"`
	NewRoot             bool                   `json:"new_root"`
	OrganizationID      string                 `json:"organization_id"`
	RootPublicKey       ratify.HybridPublicKey `json:"root_public_key"`
	StatusPublicKey     ratify.HybridPublicKey `json:"status_public_key"`
	Version             int                    `json:"version"`
}

// V2KeySetupChallenge is one enrollment challenge, in the shape the
// single-key challenge route returns, plus the nonce its value is derived
// from (V2KeySetupChallengeValue).
type V2KeySetupChallenge struct {
	Audience    string    `json:"audience"`
	AuthorityID string    `json:"authority_id"`
	Challenge   string    `json:"challenge"`
	ChallengeID string    `json:"challenge_id"`
	CustodyMode string    `json:"custody_mode"`
	ExpiresAt   time.Time `json:"expires_at"`
	KeyID       string    `json:"key_id"`
	Nonce       string    `json:"nonce"`
	Role        string    `json:"role"`
}

// V2KeySetupChallengeValue derives a setup challenge from the organization
// it is issued in, the key and role it names, and a random nonce. The
// possession proof signs the challenge, so ratify-keys recomputes it from
// the organization in its own request and refuses a challenge Verify issued
// in any other organization, even if a bundle relabels it.
func V2KeySetupChallengeValue(organizationID, role, keyID, nonce string) string {
	sum := sha256.Sum256([]byte("ratify-key-setup-challenge-v1\x00" + organizationID + "\x00" + role + "\x00" + keyID + "\x00" + nonce))
	return hex.EncodeToString(sum[:])
}

// V2KeySetupBundle carries every open challenge of one setup.
type V2KeySetupBundle struct {
	Challenges     []V2KeySetupChallenge `json:"challenges"`
	Epoch          uint64                `json:"epoch"`
	ExpiresAt      time.Time             `json:"expires_at"`
	Kind           string                `json:"kind"`
	OrganizationID string                `json:"organization_id"`
	RequestDigest  string                `json:"request_digest"`
	SetupID        string                `json:"setup_id"`
	Version        int                   `json:"version"`
}

// V2KeySetupProof is one signed 0x0114 key-possession proof.
type V2KeySetupProof struct {
	ChallengeID     string `json:"challenge_id"`
	KeyID           string `json:"key_id"`
	PossessionProof []byte `json:"possession_proof"`
	Role            string `json:"role"`
}

// V2KeySetupProofs is what `ratify-keys prove --bundle` writes.
type V2KeySetupProofs struct {
	Kind          string            `json:"kind"`
	Proofs        []V2KeySetupProof `json:"proofs"`
	RequestDigest string            `json:"request_digest"`
	SetupID       string            `json:"setup_id"`
	Version       int               `json:"version"`
}

// V2KeySetupPlan is a checked request: its digest, the key IDs of its three
// keys, and the authorization certificate.
type V2KeySetupPlan struct {
	Request       V2KeySetupRequest
	RequestDigest string
	RootKeyID     string
	IssuerKeyID   string
	StatusKeyID   string
	Authorization *ratify.DelegationCertV2
}

// V2KeySetupDigest is the lowercase hex SHA-256 of a file's exact bytes.
func V2KeySetupDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

// ParseV2KeySetupRequest checks a request file at time now: three distinct
// hybrid keys, a root-signed identity:delegate authorization from exactly
// this root to exactly this issuer that is valid now, and epoch 1 (the
// first binding of a new issuer; Verify never recomputes it).
func ParseV2KeySetupRequest(wire []byte, now int64) (V2KeySetupPlan, error) {
	var request V2KeySetupRequest
	if len(wire) < 2 || len(wire) > v2KeySetupMaxWire || decodeV2Strict(wire, &request) != nil {
		return V2KeySetupPlan{}, fmt.Errorf("the request is not a canonical ratify-keys setup request")
	}
	if request.Version != 1 || request.Kind != V2KeySetupRequestKind {
		return V2KeySetupPlan{}, fmt.Errorf("the request is not a version 1 setup request")
	}
	if !v2ApproverUUID.MatchString(request.OrganizationID) {
		return V2KeySetupPlan{}, fmt.Errorf("the request does not name an organization")
	}
	if request.Epoch != 1 {
		return V2KeySetupPlan{}, fmt.Errorf("a new issuer's first status-key epoch is 1")
	}
	plan := V2KeySetupPlan{Request: request, RequestDigest: V2KeySetupDigest(wire)}
	var err error
	if plan.RootKeyID, err = V2KeyID(request.RootPublicKey); err != nil {
		return V2KeySetupPlan{}, fmt.Errorf("root public key is invalid")
	}
	if plan.IssuerKeyID, err = V2KeyID(request.IssuerPublicKey); err != nil {
		return V2KeySetupPlan{}, fmt.Errorf("issuer public key is invalid")
	}
	if plan.StatusKeyID, err = V2KeyID(request.StatusPublicKey); err != nil {
		return V2KeySetupPlan{}, fmt.Errorf("status public key is invalid")
	}
	keys := []ratify.HybridPublicKey{request.RootPublicKey, request.IssuerPublicKey, request.StatusPublicKey}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i].Ed25519, keys[j].Ed25519) || bytes.Equal(keys[i].MLDSA65, keys[j].MLDSA65) {
				return V2KeySetupPlan{}, fmt.Errorf("root, issuer, and status keys must be three different keys")
			}
		}
	}
	plan.Authorization, err = VerifyV2SigningIssuerAuthorization(request.IssuerAuthorization,
		plan.RootKeyID, plan.IssuerKeyID, request.RootPublicKey, request.IssuerPublicKey, now)
	if err != nil {
		return V2KeySetupPlan{}, err
	}
	return plan, nil
}

// ParseV2KeySetupProofs decodes a proof file strictly. It checks only the
// envelope; each proof is verified against the challenge it answers.
func ParseV2KeySetupProofs(wire []byte) (V2KeySetupProofs, error) {
	var proofs V2KeySetupProofs
	if len(wire) < 2 || len(wire) > 4*v2KeySetupMaxWire || decodeV2Strict(wire, &proofs) != nil ||
		proofs.Version != 1 || proofs.Kind != V2KeySetupProofsKind ||
		len(proofs.Proofs) == 0 || len(proofs.Proofs) > 3 || !v2Hex64.MatchString(proofs.RequestDigest) {
		return V2KeySetupProofs{}, fmt.Errorf("the file is not a ratify-keys setup proof file")
	}
	seen := map[string]bool{}
	for _, p := range proofs.Proofs {
		if seen[p.Role] || !v2Hex32.MatchString(p.ChallengeID) || !v2Hex64.MatchString(p.KeyID) ||
			len(p.PossessionProof) == 0 ||
			(p.Role != "organization_root" && p.Role != "issuer" && p.Role != "issuer_status") {
			return V2KeySetupProofs{}, fmt.Errorf("the proof file names a role twice or an invalid proof")
		}
		seen[p.Role] = true
	}
	return proofs, nil
}
