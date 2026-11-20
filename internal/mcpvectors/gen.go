// Package mcpvectors generates the Verify MCP signer vectors under
// testvectors/v2/mcp. They pin the managed Verify MCP client contract (the
// tool-call binding, the connect proof of possession, the console
// configuration, and the challenge checks); they are not SPEC-v2
// conformance. Output is deterministic: Ed25519 is deterministic and the
// ML-DSA-65 signatures here are made without hedging.
package mcpvectors

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// Files are the generated file names, in output order.
var Files = []string{"binding.json", "client-config.json", "connect.json", "tool-call.json"}

const (
	connectionID = "3f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
	workspaceID  = "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f"
	receiverID   = "7a1c2d3e-4a5b-5c6d-8e9f-0a1b2c3d4e5f"
	invocationID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	endpoint     = "https://verify.example"
	audience     = endpoint + "/mcp"
	issuedAt     = 1790000100
	expiresAt    = issuedAt + 120
	now          = issuedAt + 50
)

var verifierID = strings.Repeat("1", 64)

type key struct {
	name           string
	edSeed, mlSeed [32]byte
	pub            ratify.HybridPublicKey
	priv           ratify.HybridPrivateKey
	id             string
}

func newKey(name string, ed, ml byte) (*key, error) {
	k := &key{name: name}
	for i := range k.edSeed {
		k.edSeed[i], k.mlSeed[i] = ed, ml
	}
	var err error
	if k.pub, k.priv, err = ratify.HybridKeypairFromSeeds(k.edSeed, k.mlSeed); err != nil {
		return nil, err
	}
	if k.id, err = ratify.KeyIDV2(k.pub); err != nil {
		return nil, err
	}
	return k, nil
}

type keyEntry struct {
	Name           string            `json:"name"`
	Ed25519SeedHex string            `json:"ed25519_seed_hex"`
	MLDSA65SeedHex string            `json:"ml_dsa_65_seed_hex"`
	PublicKey      map[string]string `json:"public_key"`
	KeyIDV2        string            `json:"key_id_v2"`
}

func (k *key) entry() keyEntry {
	return keyEntry{k.name, hex.EncodeToString(k.edSeed[:]), hex.EncodeToString(k.mlSeed[:]),
		map[string]string{"ed25519": b64(k.pub.Ed25519), "ml_dsa_65": b64(k.pub.MLDSA65)}, k.id}
}

// detSigner signs with deterministic ML-DSA-65 so the files reproduce.
type detSigner struct{ k *key }

func (s detSigner) PublicKeyV2() ratify.HybridPublicKey { return s.k.pub }
func (s detSigner) ModeV2() ratify.SignerModeV2         { return ratify.SignerModeDirectV2 }
func (s detSigner) SignV2(_ context.Context, req ratify.SignRequestV2) (ratify.HybridSignature, error) {
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.k.priv.MLDSA65, req.Message, req.MLDSAContext, false, ml); err != nil {
		return ratify.HybridSignature{}, err
	}
	return ratify.HybridSignature{Ed25519: ed25519.Sign(s.k.priv.Ed25519, req.Message), MLDSA65: ml}, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// compact marshals like the hosted service: sorted map keys, no spaces.
func compact(v any) string {
	if raw, ok := v.(rawJSON); ok {
		return string(raw)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

type gen struct {
	root, issuer, agent, other *key
	// The connection's chain, root side first: root -> issuer -> agent.
	issuerWire, certWire []byte
	issuerCert, cert     *ratify.DelegationCertV2
	// A single root-signed certificate to the agent.
	directWire []byte
	directCert *ratify.DelegationCertV2
}

// Generate returns every file's bytes keyed by name.
func Generate() (map[string][]byte, error) {
	g := &gen{}
	var err error
	if g.root, err = newKey("connect_root", 0x51, 0xd1); err != nil {
		return nil, err
	}
	if g.agent, err = newKey("agent", 0x52, 0xd2); err != nil {
		return nil, err
	}
	if g.other, err = newKey("other_agent", 0x53, 0xd3); err != nil {
		return nil, err
	}
	if g.issuer, err = newKey("connect_issuer", 0x54, 0xd4); err != nil {
		return nil, err
	}
	scopes := []string{"custom:verify.decisions:read", "custom:verify.events:read", "custom:verify.metrics:read"}
	sort.Strings(scopes)
	audience := []ratify.ConstraintV2{{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{
		"exact_receiver_ids": []any{receiverID}, "trust_domain_ids": []any{},
	}}}
	issue := func(id string, issuer, subject *key, constraints []ratify.ConstraintV2) (*ratify.DelegationCertV2, []byte, error) {
		cert, err := ratify.SignDelegationCertV2WithSigner(context.Background(), &ratify.DelegationCertV2{
			Version: 2, CertID: id, IssuerID: issuer.id, IssuerPubKey: issuer.pub,
			SubjectID: subject.id, SubjectPubKey: subject.pub, Scope: scopes, Constraints: constraints,
			IssuedAt: 1790000000, ExpiresAt: 1790000000 + 30*86400,
		}, detSigner{issuer})
		if err != nil {
			return nil, nil, fmt.Errorf("delegation %s: %w", id, err)
		}
		wire, err := ratify.EncodeDelegationCertV2(cert)
		return cert, wire, err
	}
	if g.issuerCert, g.issuerWire, err = issue("mcp-issuer-cert-1", g.root, g.issuer, []ratify.ConstraintV2{}); err != nil {
		return nil, err
	}
	if g.cert, g.certWire, err = issue("mcp-connection-cert-1", g.issuer, g.agent, audience); err != nil {
		return nil, err
	}
	if g.directCert, g.directWire, err = issue("mcp-connection-cert-direct", g.root, g.agent, audience); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for name, build := range map[string]func() (any, error){
		"binding.json": g.binding, "client-config.json": g.clientConfig, "connect.json": g.connect, "tool-call.json": g.toolCall,
	} {
		v, err := build()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if out[name], err = encode(v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
