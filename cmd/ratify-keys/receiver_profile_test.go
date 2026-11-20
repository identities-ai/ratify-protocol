package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

// The Verify MCP connect delegation carries a receiver audience naming only
// the organization's MCP receiver, so it is useless at any other receiver.
func TestRatifyKeysDelegateLimitsToReceiver(t *testing.T) {
	dir := t.TempDir()
	rootKey, _, rootID := generateKey(t, dir, "root.key")
	_, agentPub, agentID := generateKey(t, dir, "agent.key")
	agentPubPath := writePublic(t, dir, "agent.pub.json", agentPub)
	certPath := filepath.Join(dir, "mcp-cert.json")
	var out, notes bytes.Buffer
	receiver := "0b9b2d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	if err := run([]string{"delegate", "--key", rootKey, "--subject", agentPubPath, "--cert-id", "mcp-1",
		"--scope", "custom:verify.metrics:read,custom:verify.decisions:read", "--valid-for", "720h",
		"--receiver-id", receiver, "--out", certPath}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	wire, _ := os.ReadFile(certPath)
	cert, err := ratify.DecodeDelegationCertV2(wire)
	if err != nil || ratify.VerifyDelegationCertV2Signature(cert) != nil {
		t.Fatalf("certificate: %v", err)
	}
	if cert.IssuerID != rootID || cert.SubjectID != agentID || len(cert.Constraints) != 1 ||
		cert.Constraints[0].Type != ratify.ConstraintReceiverAudience {
		t.Fatalf("certificate = %+v", cert)
	}
	params, _ := json.Marshal(cert.Constraints[0].Params)
	if string(params) != `{"exact_receiver_ids":["`+receiver+`"],"trust_domain_ids":[]}` {
		t.Fatalf("audience = %s", params)
	}
}

// The profile ratify-keys signs from the console's spec passes Verify's own
// parse, with the signer's key as the configuration signer.
func TestRatifyKeysSignReceiverProfile(t *testing.T) {
	dir := t.TempDir()
	signerKey, signerPub, _ := generateKey(t, dir, "signer.key")
	_, rootPubJSON, rootID := generateKey(t, dir, "root.key")
	var rootPub, signer ratify.HybridPublicKey
	mustDecodePublic(t, rootPubJSON, &rootPub)
	mustDecodePublic(t, signerPub, &signer)
	spec := receiverSpec{Anchors: []setup.V2TrustAnchor{{PublicKey: rootPub, RootID: rootID}},
		Operations: []setup.V2ReceiverOperation{{Action: "mcp.tools/call", OperationID: "get_metrics",
			RequiredScope: "custom:verify.metrics:read", RiskClass: "standard"}},
		ReceiverID: "0b9b2d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e", WorkspaceID: "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
		StatusPolicy: setup.V2StatusPolicy{MaxListLifetimeSeconds: 86400, MaxStatusAgeSeconds: 900}}
	data, _ := json.Marshal(spec)
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	var out, notes bytes.Buffer
	if err := run([]string{"sign-receiver-profile", "--key", signerKey, "--spec", specPath, "--out", profilePath}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	profile, _ := os.ReadFile(profilePath)
	config, err := setup.ParseV2ReceiverConfig(profile, nil, testNow.Unix())
	if err != nil {
		t.Fatalf("Verify refuses the profile: %v", err)
	}
	if config.Head.Sequence != 1 || !bytes.Equal(config.Content.ConfigSignerKey.Ed25519, signer.Ed25519) ||
		config.Content.ReceiverID != spec.ReceiverID || !strings.Contains(notes.String(), "sequence 1") {
		t.Fatalf("profile = %+v", config.Head)
	}
	// A renewal chains to the installed profile.
	next := filepath.Join(dir, "next.json")
	if err := run([]string{"sign-receiver-profile", "--key", signerKey, "--spec", specPath, "--previous", profilePath, "--out", next}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	renewed, _ := os.ReadFile(next)
	if _, err := setup.ParseV2ReceiverConfig(renewed, config, testNow.Unix()); err != nil {
		t.Fatalf("successor refused: %v", err)
	}
	// Unknown spec fields are refused rather than dropped.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"receiver_id":"x","operations":[],"extra":1}`), 0644)
	if err := run([]string{"sign-receiver-profile", "--key", signerKey, "--spec", bad, "--out", filepath.Join(dir, "x.json")}, &out, &notes, fixedNow); err == nil {
		t.Fatal("unknown spec field accepted")
	}
}
