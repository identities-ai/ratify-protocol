package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// A reviewer's revoke becomes effective only through a list the customer
// signs with their own status key. The signed file must be the exact Protocol
// bytes Verify checks, bound to the key that signed it, valid from the
// signing time for the draft's lifetime.
func TestSignStatusListSignsReviewDraftWithCustomerKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, _, keyID := generateKey(t, dir, "status.key")
	otherPath, _, _ := generateKey(t, dir, "other.key")
	issuerID := strings.Repeat("e", 64)
	draft := filepath.Join(dir, "draft.json")
	if err := os.WriteFile(draft, []byte(`{"version":2,"issuer_id":"`+issuerID+`","sequence":8,
		"revoked":[{"cert_id":"cert-a"},{"cert_id":"cert-b"}],"lifetime_seconds":3600}`), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "list.json")
	var notes bytes.Buffer
	if err := run([]string{"sign-status-list", "--key", keyPath, "--draft", draft, "--out", out}, &bytes.Buffer{}, &notes, fixedNow); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(notes.String(), keyID) {
		t.Fatalf("output does not name the signing key: %s", notes.String())
	}
	wire, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ratify.DecodeRevocationListV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	private, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := ratify.VerifyRevocationListV2Signature(list, issuerID, private.Public()); err != nil {
		t.Fatalf("signed list does not verify with the customer's key: %v", err)
	}
	other, err := loadKey(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if ratify.VerifyRevocationListV2Signature(list, issuerID, other.Public()) == nil {
		t.Fatal("signed list verifies with another key")
	}
	if list.Sequence != 8 || list.UpdatedAt != testNow.Unix() || list.NextUpdate != testNow.Unix()+3600 ||
		len(list.Revoked) != 2 || list.Revoked[0].CertID != "cert-a" {
		t.Fatalf("signed list = %+v", list)
	}
	// A stricter receiver policy can shorten the lifetime at signing.
	short := filepath.Join(dir, "short.json")
	if err := run([]string{"sign-status-list", "--key", keyPath, "--draft", draft, "--out", short, "--lifetime-seconds", "30"}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err != nil {
		t.Fatal(err)
	}
	if wire, err := os.ReadFile(short); err != nil {
		t.Fatal(err)
	} else if l, err := ratify.DecodeRevocationListV2(wire); err != nil || l.NextUpdate-l.UpdatedAt != 30 {
		t.Fatalf("lifetime override = %+v (%v)", l, err)
	}
	// It never overwrites an existing file.
	if err := run([]string{"sign-status-list", "--key", keyPath, "--draft", draft, "--out", out}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil {
		t.Fatal("overwrote an existing list")
	}
	// Malformed drafts are refused before signing.
	for name, body := range map[string]string{
		"wrong version":  `{"version":1,"issuer_id":"` + issuerID + `","sequence":8,"revoked":[],"lifetime_seconds":3600}`,
		"no sequence":    `{"version":2,"issuer_id":"` + issuerID + `","sequence":0,"revoked":[],"lifetime_seconds":3600}`,
		"long lifetime":  `{"version":2,"issuer_id":"` + issuerID + `","sequence":8,"revoked":[],"lifetime_seconds":99999999}`,
		"unknown fields": `{"version":2,"issuer_id":"` + issuerID + `","sequence":8,"revoked":[],"lifetime_seconds":3600,"signature":{}}`,
	} {
		bad := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(bad, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"sign-status-list", "--key", keyPath, "--draft", bad, "--out", bad + ".out"}, &bytes.Buffer{}, &bytes.Buffer{}, fixedNow); err == nil {
			t.Fatalf("%s: draft was signed", name)
		}
	}
}
