package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

const (
	defaultStateDir = ".ratify-demo"
	authorizedTool  = "place_order"
)

var validToolName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type seedPair struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"ml_dsa_65"`
}

type agentState struct {
	Agent       ratify.AgentIdentity    `json:"agent"`
	Seeds       seedPair                `json:"seeds"`
	Delegations []ratify.DelegationCert `json:"delegations"`
}

type vendorState struct {
	TrustedHumanID string                 `json:"trusted_human_id"`
	TrustedRootKey ratify.HybridPublicKey `json:"trusted_root_key"`
	UpstreamCertID string                 `json:"upstream_cert_id"`
	AdminToken     string                 `json:"admin_token"`
}

func createArtifacts(dir string) (vendorState, agentState, error) {
	now := time.Now().Unix()
	scope := toolScope(authorizedTool)

	alicePub, alicePriv, _, err := seededKeypair()
	if err != nil {
		return vendorState{}, agentState{}, err
	}
	atlasPub, atlasPriv, _, err := seededKeypair()
	if err != nil {
		return vendorState{}, agentState{}, err
	}
	scoutPub, _, scoutSeeds, err := seededKeypair()
	if err != nil {
		return vendorState{}, agentState{}, err
	}

	aliceID := ratify.DeriveID(alicePub)
	atlasID := ratify.DeriveID(atlasPub)
	scoutID := ratify.DeriveID(scoutPub)
	parent := ratify.DelegationCert{
		CertID: "alice-to-atlas", Version: ratify.ProtocolVersion,
		IssuerID: aliceID, IssuerPubKey: alicePub,
		SubjectID: atlasID, SubjectPubKey: atlasPub,
		Scope:       []string{scope, ratify.ScopeIdentityDelegate},
		Constraints: []ratify.Constraint{{Type: ratify.ConstraintMaxAmount, MaxAmount: 5000, Currency: "USD"}},
		IssuedAt:    now, ExpiresAt: now + 24*60*60,
	}
	if err := ratify.IssueDelegation(&parent, alicePriv); err != nil {
		return vendorState{}, agentState{}, err
	}
	leaf := ratify.DelegationCert{
		CertID: "atlas-to-scout", Version: ratify.ProtocolVersion,
		IssuerID: atlasID, IssuerPubKey: atlasPub,
		SubjectID: scoutID, SubjectPubKey: scoutPub,
		Scope:       []string{scope},
		Constraints: []ratify.Constraint{{Type: ratify.ConstraintMaxAmount, MaxAmount: 500, Currency: "USD"}},
		IssuedAt:    now, ExpiresAt: now + 60*60,
	}
	if err := ratify.IssueDelegation(&leaf, atlasPriv); err != nil {
		return vendorState{}, agentState{}, err
	}

	adminToken := make([]byte, 32)
	if _, err := rand.Read(adminToken); err != nil {
		return vendorState{}, agentState{}, err
	}
	vendor := vendorState{
		TrustedHumanID: aliceID, TrustedRootKey: alicePub,
		UpstreamCertID: parent.CertID,
		AdminToken:     base64.StdEncoding.EncodeToString(adminToken),
	}
	agent := agentState{
		Agent: ratify.AgentIdentity{ID: scoutID, PublicKey: scoutPub, Name: "Scout", AgentType: "purchasing_agent", CreatedAt: now},
		Seeds: scoutSeeds, Delegations: []ratify.DelegationCert{leaf, parent},
	}
	if dir != "" {
		if err := writeState(dir, vendor, agent); err != nil {
			return vendorState{}, agentState{}, err
		}
	}
	return vendor, agent, nil
}

func seededKeypair() (ratify.HybridPublicKey, ratify.HybridPrivateKey, seedPair, error) {
	var ed, ml [32]byte
	if _, err := rand.Read(ed[:]); err != nil {
		return ratify.HybridPublicKey{}, ratify.HybridPrivateKey{}, seedPair{}, err
	}
	if _, err := rand.Read(ml[:]); err != nil {
		return ratify.HybridPublicKey{}, ratify.HybridPrivateKey{}, seedPair{}, err
	}
	pub, priv, err := ratify.HybridKeypairFromSeeds(ed, ml)
	return pub, priv, seedPair{
		Ed25519: base64.StdEncoding.EncodeToString(ed[:]),
		MLDSA65: base64.StdEncoding.EncodeToString(ml[:]),
	}, err
}

func (s seedPair) privateKey() (ratify.HybridPrivateKey, error) {
	var ed, ml [32]byte
	edBytes, err := base64.StdEncoding.DecodeString(s.Ed25519)
	if err != nil || len(edBytes) != 32 {
		return ratify.HybridPrivateKey{}, fmt.Errorf("invalid Ed25519 seed")
	}
	mlBytes, err := base64.StdEncoding.DecodeString(s.MLDSA65)
	if err != nil || len(mlBytes) != 32 {
		return ratify.HybridPrivateKey{}, fmt.Errorf("invalid ML-DSA-65 seed")
	}
	copy(ed[:], edBytes)
	copy(ml[:], mlBytes)
	_, priv, err := ratify.HybridKeypairFromSeeds(ed, ml)
	return priv, err
}

func writeState(dir string, vendor vendorState, agent agentState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "vendor.json"), vendor, 0o600); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "scout.json"), agent, 0o600)
}

func writeJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), mode)
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func toolScope(tool string) string {
	return ratify.CustomScopePrefix + "acme:tool:" + tool
}

func operationSessionContext(agentID, tool string, amount float64) ([]byte, error) {
	if !validToolName.MatchString(tool) {
		return nil, fmt.Errorf("tool must match [a-z][a-z0-9_]*")
	}
	if amount < 0 || math.IsNaN(amount) || math.IsInf(amount, 0) {
		return nil, fmt.Errorf("amount must be a finite non-negative number")
	}
	payload, err := json.Marshal(struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
	}{Amount: amount, Currency: "USD"})
	if err != nil {
		return nil, err
	}
	payloadDigest := sha256.Sum256(payload)
	requestHash, err := ratify.OperationContextHash(ratify.OperationContext{
		RequiredScope: toolScope(tool),
		Operation:     "tool.invoke",
		ResourceID:    "acme-supplies",
		RequestedPath: tool,
		PayloadDigest: payloadDigest[:],
	})
	if err != nil {
		return nil, err
	}
	return ratify.BuildSessionContext(ratify.SessionContextInputs{
		VerifierID:  "acme-supplies",
		AgentID:     agentID,
		RequestHash: requestHash,
	})
}
