package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

func writePublic(t *testing.T, dir, name string, public []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, public, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The root-signed issuer authorization is exactly what POST
// /v1/orgs/{orgId}/v2/signing-issuers checks before enrolling an issuer,
// and the issuer-signed agent certificate carries the exact cert_id an IAM
// mapping names.
func TestRatifyKeysDelegatePassesIssuerEnrollmentCheck(t *testing.T) {
	dir := t.TempDir()
	rootKey, rootPub, rootID := generateKey(t, dir, "root.key")
	issuerKey, issuerPub, issuerID := generateKey(t, dir, "issuer.key")
	_, agentPub, agentID := generateKey(t, dir, "agent.key")
	issuerPubPath := writePublic(t, dir, "issuer.pub.json", issuerPub)
	agentPubPath := writePublic(t, dir, "agent.pub.json", agentPub)

	authorization := filepath.Join(dir, "issuer-authorization.json")
	var out, notes bytes.Buffer
	if err := run([]string{"delegate", "--key", rootKey, "--subject", issuerPubPath, "--cert-id", "issuer-auth-1",
		"--scope", ratify.ScopeIdentityDelegate, "--valid-for", "2160h", "--out", authorization}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(authorization)
	if err != nil {
		t.Fatal(err)
	}
	var root, issuer ratify.HybridPublicKey
	mustDecodePublic(t, rootPub, &root)
	mustDecodePublic(t, issuerPub, &issuer)
	// The longest allowed authorization (90 days) still passes, including
	// the one-minute backdate.
	if _, err := setup.VerifyV2SigningIssuerAuthorization(wire, rootID, issuerID, root, issuer, testNow.Unix()); err != nil {
		t.Fatalf("issuer authorization refused by Verify's check: %v", err)
	}
	if !strings.Contains(notes.String(), "issuer-auth-1") {
		t.Fatalf("notes do not name the certificate: %s", notes.String())
	}

	agentCert := filepath.Join(dir, "agent-cert.json")
	if err := run([]string{"delegate", "--key", issuerKey, "--subject", agentPubPath, "--cert-id", "okta-alice-2026-11",
		"--scope", "files:read", "--valid-for", "24h", "--out", agentCert}, &out, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	wire, _ = os.ReadFile(agentCert)
	cert, err := ratify.DecodeDelegationCertV2(wire)
	if err != nil || ratify.VerifyDelegationCertV2Signature(cert) != nil {
		t.Fatalf("agent certificate: %v", err)
	}
	canonical, _ := ratify.EncodeDelegationCertV2(cert)
	if !bytes.Equal(canonical, wire) || cert.CertID != "okta-alice-2026-11" || cert.IssuerID != issuerID ||
		cert.SubjectID != agentID || cert.ExpiresAt-cert.IssuedAt != 24*3600 || cert.IssuedAt != testNow.Unix()-60 {
		t.Fatalf("agent certificate fields: %+v", cert)
	}
}

func mustDecodePublic(t *testing.T, data []byte, into *ratify.HybridPublicKey) {
	t.Helper()
	parsed, err := readPublic(data)
	if err != nil {
		t.Fatal(err)
	}
	*into = parsed
}

func TestRatifyKeysDelegateRefusals(t *testing.T) {
	dir := t.TempDir()
	rootKey, _, _ := generateKey(t, dir, "root.key")
	_, subjectPub, _ := generateKey(t, dir, "subject.key")
	subject := writePublic(t, dir, "subject.pub.json", subjectPub)
	existing := filepath.Join(dir, "exists.json")
	_ = os.WriteFile(existing, []byte("x"), 0644)
	base := func(extra ...string) []string {
		args := []string{"delegate", "--key", rootKey, "--subject", subject, "--cert-id", "c1", "--scope", "files:read",
			"--valid-for", "1h", "--out", filepath.Join(dir, "out-"+strings.Join(extra, "")+".json")}
		return append(args, extra...)
	}
	for name, args := range map[string][]string{
		"no cert id":       {"delegate", "--key", rootKey, "--subject", subject, "--scope", "a:b", "--valid-for", "1h", "--out", filepath.Join(dir, "o1")},
		"no scope":         {"delegate", "--key", rootKey, "--subject", subject, "--cert-id", "c", "--valid-for", "1h", "--out", filepath.Join(dir, "o2")},
		"bad scope":        base("--scope", "NOT A SCOPE"),
		"too long":         base("--valid-for", "2161h"),
		"zero validity":    base("--valid-for", "0s"),
		"overwrite":        {"delegate", "--key", rootKey, "--subject", subject, "--cert-id", "c", "--scope", "a:b", "--valid-for", "1h", "--out", existing},
		"subject not key":  {"delegate", "--key", rootKey, "--subject", rootKey, "--cert-id", "c", "--scope", "a:b", "--valid-for", "1h", "--out", filepath.Join(dir, "o3")},
		"unknown argument": base("extra"),
	} {
		var out, notes bytes.Buffer
		if err := run(args, &out, &notes, fixedNow); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if data, _ := os.ReadFile(existing); string(data) != "x" {
		t.Fatal("delegate overwrote an existing file")
	}
}
