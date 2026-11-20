package exportsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// A customer verifies an export offline with nothing but the published key
// set. Every way an attacker or a bug could pass one artifact off as another
// must fail verification.

func testKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sign(t *testing.T, priv *ecdsa.PrivateKey, typ, version, keyID string, at time.Time, payload []byte) Signature {
	t.Helper()
	digest, err := Digest(typ, version, keyID, at, payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	return Signature{ArtifactType: typ, Version: version, KeyID: keyID, Algorithm: AlgorithmP256SHA256,
		SignedAt: at, Signature: base64.StdEncoding.EncodeToString(raw)}
}

func TestVerifyExportSignature(t *testing.T) {
	priv, pemText := testKey(t, elliptic.P256())
	other, otherPEM := testKey(t, elliptic.P256())
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	retired := start.Add(30 * 24 * time.Hour)
	keys := KeySet{Keys: []Key{
		{KeyID: "k1", Algorithm: AlgorithmP256SHA256, PublicKeyPEM: pemText, NotBefore: start, NotAfter: &retired},
		{KeyID: "k2", Algorithm: AlgorithmP256SHA256, PublicKeyPEM: otherPEM, NotBefore: retired},
	}}
	payload := []byte(`{"batch_seq":7,"events":[]}`)
	at := start.Add(time.Hour)
	good := sign(t, priv, ArtifactFeedBatch, "1", "k1", at, payload)
	if err := Verify(keys, good, payload); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// A retired key still verifies what it signed while it was current.
	if err := Verify(keys, sign(t, other, ArtifactReviewRecord, "1", "k2", retired.Add(time.Minute), payload), payload); err != nil {
		t.Fatalf("current key rejected: %v", err)
	}

	cases := map[string]struct {
		sig     Signature
		payload []byte
		want    string
	}{
		"edited payload":             {good, []byte(`{"batch_seq":8,"events":[]}`), "does not verify"},
		"relabelled artifact type":   {with(good, func(s *Signature) { s.ArtifactType = ArtifactReportBundle }), payload, "does not verify"},
		"relabelled version":         {with(good, func(s *Signature) { s.Version = "2" }), payload, "does not verify"},
		"moved signing time":         {with(good, func(s *Signature) { s.SignedAt = at.Add(time.Hour) }), payload, "does not verify"},
		"claimed by another key":     {with(good, func(s *Signature) { s.KeyID = "k2"; s.SignedAt = retired.Add(time.Hour) }), payload, "does not verify"},
		"unpublished key":            {with(good, func(s *Signature) { s.KeyID = "k9" }), payload, "not published"},
		"other algorithm":            {with(good, func(s *Signature) { s.Algorithm = "HMAC_SHA256" }), payload, "unsupported"},
		"unknown artifact type":      {sign(t, priv, ArtifactFeedBatch, "1", "k1", at, payload), payload, ""},
		"signed after retirement":    {sign(t, priv, ArtifactFeedBatch, "1", "k1", retired.Add(time.Second), payload), payload, "outside the validity"},
		"signed before key existed":  {sign(t, priv, ArtifactFeedBatch, "1", "k1", start.Add(-time.Second), payload), payload, "outside the validity"},
		"garbage signature":          {with(good, func(s *Signature) { s.Signature = "!!" }), payload, "encoding"},
		"signature from another key": {sign(t, other, ArtifactFeedBatch, "1", "k1", at, payload), payload, "does not verify"},
	}
	cases["unknown artifact type"] = struct {
		sig     Signature
		payload []byte
		want    string
	}{with(good, func(s *Signature) { s.ArtifactType = "audit_row" }), payload, "unknown export artifact type"}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := Verify(keys, c.sig, c.payload)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestVerifyRejectsAmbiguousOrWeakKeys(t *testing.T) {
	priv, pemText := testKey(t, elliptic.P256())
	_, p384 := testKey(t, elliptic.P384())
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	payload := []byte("x")
	sig := sign(t, priv, ArtifactFeedBatch, "1", "k1", at, payload)
	dup := KeySet{Keys: []Key{
		{KeyID: "k1", Algorithm: AlgorithmP256SHA256, PublicKeyPEM: pemText, NotBefore: at.Add(-time.Hour)},
		{KeyID: "k1", Algorithm: AlgorithmP256SHA256, PublicKeyPEM: pemText, NotBefore: at.Add(-time.Hour)},
	}}
	if err := Verify(dup, sig, payload); err == nil || !strings.Contains(err.Error(), "published twice") {
		t.Fatalf("duplicate key IDs: %v", err)
	}
	weak := KeySet{Keys: []Key{{KeyID: "k1", Algorithm: AlgorithmP256SHA256, PublicKeyPEM: p384, NotBefore: at.Add(-time.Hour)}}}
	if err := Verify(weak, sig, payload); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("P-384 key accepted: %v", err)
	}
}

func TestDigestIsDomainSeparated(t *testing.T) {
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	a, _ := Digest(ArtifactFeedBatch, "1", "k", at, []byte("p"))
	b, _ := Digest(ArtifactReportBundle, "1", "k", at, []byte("p"))
	if string(a) == string(b) {
		t.Fatal("artifact types share a digest")
	}
	// Field boundaries are fixed by NUL separators, so moving bytes between
	// fields changes the digest.
	c, _ := Digest(ArtifactFeedBatch, "1", "k", at, []byte("p"))
	d, _ := Digest(ArtifactFeedBatch, "1", "k\x00", at, []byte("p"))
	if string(a) != string(c) || d != nil {
		t.Fatal("digest is not deterministic or accepts NUL in the key ID")
	}
	for _, v := range []string{"", "0", "01", "1.0", "12345"} {
		if _, err := Digest(ArtifactFeedBatch, v, "k", at, nil); err == nil {
			t.Fatalf("version %q accepted", v)
		}
	}
}

func with(s Signature, f func(*Signature)) Signature { f(&s); return s }
