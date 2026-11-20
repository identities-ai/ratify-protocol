package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/exportsig"
)

// The offline verifier is what a customer's auditor runs: it must accept
// exactly the bytes Verify signed and nothing else.
func TestVerifyExportCommand(t *testing.T) {
	dir := t.TempDir()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	keyID := "export-signing-key-1"
	notBefore := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	// The key set exactly as GET /v1/verify/export-keys serves it.
	keysBody, _ := json.Marshal(map[string]any{"keys": []exportsig.Key{{KeyID: keyID,
		Algorithm: exportsig.AlgorithmP256SHA256, NotBefore: notBefore,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}},
		"digest": "SHA-256(...)"})
	payload := []byte(`{"batch_seq":3,"events":[{"seq":41}]}`)
	at := notBefore.Add(time.Hour)
	digest, _ := exportsig.Digest(exportsig.ArtifactFeedBatch, "1", keyID, at, payload)
	raw, _ := ecdsa.SignASN1(rand.Reader, priv, digest)
	sigBody, _ := json.Marshal(exportsig.Signature{ArtifactType: exportsig.ArtifactFeedBatch, Version: "1",
		KeyID: keyID, Algorithm: exportsig.AlgorithmP256SHA256, SignedAt: at,
		Signature: base64.StdEncoding.EncodeToString(raw)})
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keys, sig := write("keys.json", keysBody), write("sig.json", sigBody)
	good, edited := write("batch.json", payload), write("edited.json", []byte(`{"batch_seq":3,"events":[]}`))

	var out, errOut bytes.Buffer
	if err := run([]string{"verify-export", "--keys", keys, "--signature", sig, "--payload", good}, &out, &errOut, fixedNow); err != nil {
		t.Fatalf("valid export rejected: %v", err)
	}
	if !strings.HasPrefix(out.String(), "verified: feed_batch version 1") {
		t.Fatalf("output = %q", out.String())
	}
	err = run([]string{"verify-export", "--keys", keys, "--signature", sig, "--payload", edited}, &out, &errOut, fixedNow)
	if err == nil || !strings.Contains(err.Error(), "NOT verified") {
		t.Fatalf("edited export: %v", err)
	}
	if err := run([]string{"verify-export", "--keys", keys, "--payload", good}, &out, &errOut, fixedNow); err == nil {
		t.Fatal("missing --signature accepted")
	}
}
