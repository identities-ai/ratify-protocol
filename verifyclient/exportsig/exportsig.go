// Package exportsig defines the customer-verifiable signature on everything
// Verify exports: feed batches, report bundles, and review records.
// Signatures are asymmetric, made with a dedicated export key, and checked
// offline against the keys published at GET /v1/verify/export-keys.
package exportsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Domain separates export signatures from every other Ratify signature.
const Domain = "ratify-verify-export"

// AlgorithmP256SHA256 is the algorithm name of the export key: ECDSA P-256
// over a SHA-256 digest.
const AlgorithmP256SHA256 = "EC_SIGN_P256_SHA256"

// Artifact types an export signature may cover.
const (
	ArtifactFeedBatch    = "feed_batch"
	ArtifactReportBundle = "report_bundle"
	ArtifactReviewRecord = "review_record"
)

var artifactTypes = map[string]bool{ArtifactFeedBatch: true, ArtifactReportBundle: true, ArtifactReviewRecord: true}

var versionPattern = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

// Signature accompanies an exported artifact. SignedAt and KeyID are inside
// the signed digest, so neither can be swapped after signing.
type Signature struct {
	ArtifactType string    `json:"artifact_type"`
	Version      string    `json:"version"`
	KeyID        string    `json:"key_id"`
	Algorithm    string    `json:"algorithm"`
	SignedAt     time.Time `json:"signed_at"`
	Signature    string    `json:"signature"` // base64 (standard) DER ECDSA
}

// Key is one published export key. A key signs only inside
// [NotBefore, NotAfter); NotAfter is set when a newer key replaces it, and the
// retired key stays published so earlier exports still verify.
type Key struct {
	KeyID        string     `json:"key_id"`
	Algorithm    string     `json:"algorithm"`
	PublicKeyPEM string     `json:"public_key_pem"`
	NotBefore    time.Time  `json:"not_before"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	// ArtifactTypes, when present, are the only artifact types the key may
	// sign. A key bound to one type (the evidence feed's) cannot sign any
	// other export.
	ArtifactTypes []string `json:"artifact_types,omitempty"`
}

// KeySet is the body of GET /v1/verify/export-keys.
type KeySet struct {
	Keys []Key `json:"keys"`
}

// Digest is SHA-256 over
// Domain 0x00 artifact_type 0x00 version 0x00 key_id 0x00 signed_at 0x00 payload,
// with signed_at as RFC 3339 UTC to the second.
func Digest(artifactType, version, keyID string, signedAt time.Time, payload []byte) ([]byte, error) {
	if !artifactTypes[artifactType] {
		return nil, fmt.Errorf("unknown export artifact type %q", artifactType)
	}
	if !versionPattern.MatchString(version) {
		return nil, fmt.Errorf("invalid export artifact version %q", version)
	}
	if keyID == "" || strings.ContainsRune(keyID, 0) {
		return nil, errors.New("invalid export key ID")
	}
	if signedAt.IsZero() {
		return nil, errors.New("export signature has no signing time")
	}
	h := sha256.New()
	for _, part := range []string{Domain, artifactType, version, keyID, FormatTime(signedAt)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(payload)
	return h.Sum(nil), nil
}

// FormatTime is the signed representation of a signing time.
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// ParsePublicKey accepts only a PEM P-256 ECDSA public key.
func ParsePublicKey(pemText string) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("export key is not a single PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse export key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("export key is not a P-256 ECDSA key")
	}
	return pub, nil
}

// Verify checks sig over payload against the published key set: the key must
// be published, its algorithm must match, the signing time must fall inside
// the key's validity window, and the signature must verify over the digest.
func Verify(keys KeySet, sig Signature, payload []byte) error {
	if sig.Algorithm != AlgorithmP256SHA256 {
		return fmt.Errorf("unsupported export signature algorithm %q", sig.Algorithm)
	}
	var key *Key
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == sig.KeyID {
			if key != nil {
				return fmt.Errorf("export key %q is published twice", sig.KeyID)
			}
			key = &keys.Keys[i]
		}
	}
	if key == nil {
		return fmt.Errorf("export key %q is not published", sig.KeyID)
	}
	if len(key.ArtifactTypes) > 0 {
		allowed := false
		for _, t := range key.ArtifactTypes {
			allowed = allowed || t == sig.ArtifactType
		}
		if !allowed {
			return fmt.Errorf("export key %q may not sign %s", sig.KeyID, sig.ArtifactType)
		}
	}
	if key.Algorithm != sig.Algorithm {
		return fmt.Errorf("export key %q is %s, signature claims %s", sig.KeyID, key.Algorithm, sig.Algorithm)
	}
	signedAt := sig.SignedAt.UTC().Truncate(time.Second)
	if signedAt.Before(key.NotBefore.UTC().Truncate(time.Second)) ||
		(key.NotAfter != nil && !signedAt.Before(key.NotAfter.UTC())) {
		return fmt.Errorf("export signed at %s outside the validity of key %q", FormatTime(signedAt), sig.KeyID)
	}
	pub, err := ParsePublicKey(key.PublicKeyPEM)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("export signature encoding: %w", err)
	}
	digest, err := Digest(sig.ArtifactType, sig.Version, sig.KeyID, signedAt, payload)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, digest, raw) {
		return errors.New("export signature does not verify")
	}
	return nil
}
