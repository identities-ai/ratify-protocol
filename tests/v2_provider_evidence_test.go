package ratify_test

// Provider evidence (testvectors/v2/provider-evidence/<platform>-<provider>.json).
// Each record carries objects a device key provider signed on real hardware.
// The record's key must issue its delegation certificate, prove possession in
// its key rotation statement, and sign its revocation list.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type v2ProviderEvidenceFile struct {
	Version     int    `json:"version"`
	Description string `json:"description"`
	Platform    string `json:"platform"`
	Provider    string `json:"provider"`
	SDK         string `json:"sdk"`
	DeviceModel string `json:"device_model"`
	OSVersion   string `json:"os_version"`
	OSBuild     string `json:"os_build"`
	Custody     struct {
		Ed25519 string `json:"ed25519"`
		MLDSA65 string `json:"ml_dsa_65"`
	} `json:"custody"`
	PublicKey ratify.HybridPublicKey `json:"public_key"`
	KeyIDV2   string                 `json:"key_id_v2"`
	Objects   []struct {
		Kind    string `json:"kind"`
		Role    string `json:"role"`
		WireB64 string `json:"wire_b64"`
	} `json:"objects"`
}

var v2ProviderEvidenceRoles = map[string]string{
	"delegation_certificate": "issuer",
	"key_rotation_statement": "new_key",
	"revocation_list":        "status_key",
}

func TestV2ProviderEvidence(t *testing.T) {
	dir := filepath.Join("..", "testvectors", "v2", "provider-evidence")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files, checks := 0, 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		files++
		name := e.Name()
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			checks += v2CheckProviderEvidence(t, filepath.Join(dir, name), name)
		})
	}
	if files == 0 || checks == 0 {
		t.Fatalf("provider-evidence ran %d files and %d checks", files, checks)
	}
	t.Logf("provider-evidence: %d files, %d checks", files, checks)
}

func v2CheckProviderEvidence(t *testing.T, path, name string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f v2ProviderEvidenceFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("decode: %v", err)
	}
	checks := 0
	check := func(ok bool, format string, args ...any) {
		t.Helper()
		checks++
		if !ok {
			t.Errorf(format, args...)
		}
	}
	check(f.Version == 1, "version %d, want 1", f.Version)
	check(name == f.Platform+"-"+f.Provider+".json", "file name %q, want %s-%s.json", name, f.Platform, f.Provider)
	check(v2MustKeyID(t, f.PublicKey) == f.KeyIDV2, "key_id_v2 does not match public_key")
	check(independentKeyIDV2(f.PublicKey) == f.KeyIDV2, "independent key ID does not match key_id_v2")
	key, id := f.PublicKey, f.KeyIDV2
	seen := map[string]bool{}
	for _, o := range f.Objects {
		check(!seen[o.Kind], "%s appears more than once", o.Kind)
		seen[o.Kind] = true
		check(v2ProviderEvidenceRoles[o.Kind] == o.Role, "%s role %q, want %q", o.Kind, o.Role, v2ProviderEvidenceRoles[o.Kind])
		wire := unb64(t, o.WireB64)
		check(bytes.Equal(v2Reencode(t, o.Kind, wire), wire), "%s: re-encoding is not byte-identical", o.Kind)
		switch o.Kind {
		case "delegation_certificate":
			c, err := ratify.DecodeDelegationCertV2(wire)
			if err != nil {
				t.Fatalf("%s: %v", o.Kind, err)
			}
			check(ratify.VerifyDelegationCertV2Signature(c) == nil, "delegation certificate signature does not verify")
			check(v2SameKey(c.IssuerPubKey, key), "issuer_pub_key is not the record key")
			check(c.IssuerID == id, "issuer_id %s, want %s", c.IssuerID, id)
			bad, _ := ratify.DecodeDelegationCertV2(wire)
			bad.Signature.MLDSA65[0] ^= 1
			err = ratify.VerifyDelegationCertV2Signature(bad)
			check(ratify.V2ErrorClassOf(err) == ratify.V2ErrInvalidSignature, "flipped ML-DSA-65 signature byte: error %v, want invalid_signature", err)
		case "key_rotation_statement":
			s, err := ratify.DecodeKeyRotationStatementV2(wire)
			if err != nil {
				t.Fatalf("%s: %v", o.Kind, err)
			}
			check(v2SameKey(s.NewKey, key), "new_key is not the record key")
			signable := v2Projection(t, wire, "old_signature")
			check(v2VerifyTranscript(0x0004, signable, s.OldSignature, s.OldKey) == nil, "old_signature does not verify under KeyRotationAuthorization with old_key")
			check(v2VerifyTranscript(0x0009, signable, s.NewSignature, s.NewKey) == nil, "new_signature does not verify under KeyRotationProofOfPossession with new_key")
			_, err = ratify.VerifyArchivalKeyRotationStatementV2(wire)
			check(err == nil, "archival key rotation verification: %v", err)
		case "revocation_list":
			l, err := ratify.DecodeRevocationListV2(wire)
			if err != nil {
				t.Fatalf("%s: %v", o.Kind, err)
			}
			err = ratify.VerifyRevocationListV2Signature(l, id, key)
			check(err == nil, "revocation list signature: %v", err)
		default:
			t.Fatalf("unknown kind %q", o.Kind)
		}
	}
	for kind := range v2ProviderEvidenceRoles {
		check(seen[kind], "no %s object", kind)
	}
	return checks
}

func v2SameKey(a, b ratify.HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}

// v2VerifyTranscript verifies both hybrid components over the SPEC-v2
// signature transcript for one object type code, independently of the SDK.
func v2VerifyTranscript(code uint16, signable []byte, sig ratify.HybridSignature, pub ratify.HybridPublicKey) error {
	m := v2Message(code, signable)
	if len(pub.Ed25519) != ed25519.PublicKeySize || !ed25519.Verify(pub.Ed25519, m, sig.Ed25519) {
		return fmt.Errorf("Ed25519 component does not verify")
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pub.MLDSA65); err != nil {
		return err
	}
	if !mldsa65.Verify(&pk, m, []byte(fmt.Sprintf("ratify-protocol/2/%04x", code)), sig.MLDSA65) {
		return fmt.Errorf("ML-DSA-65 component does not verify")
	}
	return nil
}
