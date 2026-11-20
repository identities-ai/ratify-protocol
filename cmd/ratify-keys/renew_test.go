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

// The renewal request is signed by the same root for the same issuer key as
// the setup, and Verify's own parser accepts it.
func TestSetupRenewIssuerSignsSameKeyWithRoot(t *testing.T) {
	dir, plan := runSetup(t)
	out := filepath.Join(t.TempDir(), "renewal.json")
	var stdout, notes bytes.Buffer
	if err := run([]string{"setup", "renew-issuer", "--dir", dir, "--org", testOrg, "--out", out, "--valid-for", "720h"},
		&stdout, &notes, fixedNow); err != nil {
		t.Fatalf("renew-issuer: %v\n%s", err, notes.String())
	}
	wire, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	request, cert, err := setup.ParseV2IssuerRenewalRequest(wire, testNow.Unix())
	if err != nil {
		t.Fatalf("Verify must accept the renewal request ratify-keys writes: %v", err)
	}
	if request.OrganizationID != testOrg || request.IssuerKeyID != plan.IssuerKeyID ||
		cert.IssuerID != plan.RootKeyID || cert.SubjectID != plan.IssuerKeyID ||
		cert.CertID == plan.Authorization.CertID || cert.ExpiresAt-cert.IssuedAt != 720*3600 {
		t.Fatalf("renewal request = %+v cert=%s issuer=%s expires=%d", request, cert.CertID, cert.IssuerID, cert.ExpiresAt)
	}
	if !strings.Contains(notes.String(), "Renew on the console's setup page") {
		t.Fatalf("notes: %s", notes.String())
	}
	// Refusals: an existing output file, a missing organization, too long,
	// and a folder without the root unless --root-key names it.
	for name, args := range map[string][]string{
		"existing file": {"--dir", dir, "--org", testOrg, "--out", out},
		"no org":        {"--dir", dir, "--out", out + "2"},
		"over 90 days":  {"--dir", dir, "--org", testOrg, "--out", out + "3", "--valid-for", "2161h"},
		"no root":       {"--dir", t.TempDir(), "--org", testOrg, "--out", out + "4"},
	} {
		if err := run(append([]string{"setup", "renew-issuer"}, args...), &stdout, &notes, fixedNow); err == nil {
			t.Fatalf("renew-issuer accepted %s", name)
		}
	}
}

// Verify's parser refuses a request whose authorization is for another key.
func TestIssuerRenewalRequestRefusesKeyChange(t *testing.T) {
	_, plan := runSetup(t)
	root, rootPrivate, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	rootID, _ := setup.V2KeyID(root)
	otherID, _ := setup.V2KeyID(other)
	cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2, CertID: "rotation",
		IssuerID: rootID, IssuerPubKey: root, SubjectID: otherID, SubjectPubKey: other,
		Scope: []string{"identity:delegate"}, Constraints: []ratify.ConstraintV2{},
		IssuedAt: testNow.Unix() - 60, ExpiresAt: testNow.Unix() + 3600}, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := ratify.EncodeDelegationCertV2(cert)
	request, _ := ratify.CanonicalJSON(setup.V2IssuerRenewalRequest{IssuerAuthorization: wire,
		IssuerKeyID: plan.IssuerKeyID, Kind: setup.V2IssuerRenewalRequestKind, OrganizationID: testOrg, Version: 1})
	if _, _, err := setup.ParseV2IssuerRenewalRequest(request, testNow.Unix()); err == nil {
		t.Fatal("a renewal request for another issuer key was accepted")
	}
}
