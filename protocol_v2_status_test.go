package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestRevocationListV2CodecAndAuthenticatedStatusKey(t *testing.T) {
	issuerID := strings.Repeat("a", 64)
	statusPub, statusPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	list := &RevocationListV2{
		Version: 2, IssuerID: issuerID, UpdatedAt: 100, NextUpdate: 160,
		Sequence: 1, Revoked: []RevokedCertV2{{CertID: "grant-1"}},
	}
	unsignedList := list
	list, err = SignRevocationListV2(unsignedList, issuerID, statusPub, statusPriv)
	if err != nil {
		t.Fatal(err)
	}
	unsignedList.Revoked[0].CertID = "mutated-after-signing"
	if list.Revoked[0].CertID != "grant-1" {
		t.Fatal("signed list aliases mutable input data")
	}
	if _, err := SignRevocationListV2(list, strings.Repeat("f", 64), statusPub, statusPriv); err == nil {
		t.Fatal("signed a revocation list outside the caller-authenticated issuer binding")
	}
	otherStatusPub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRevocationListV2(list, issuerID, otherStatusPub, statusPriv); err == nil {
		t.Fatal("signed a revocation list with a key outside the caller-authenticated status-key binding")
	}
	malformedStatusKey := statusPriv
	malformedStatusKey.Ed25519 = append([]byte(nil), statusPriv.Ed25519...)
	malformedStatusKey.Ed25519[63] ^= 1
	if _, err := SignRevocationListV2(list, issuerID, statusPub, malformedStatusKey); err == nil {
		t.Fatal("accepted an Ed25519 status private key whose public half does not match its seed")
	}
	wire, err := EncodeRevocationListV2(list)
	if err != nil {
		t.Fatal(err)
	}
	assertV2JSONKeyOrder(t, string(wire), []string{"issuer_id", "next_update", "revoked", "sequence", "signature", "updated_at", "version"})
	decoded, err := DecodeRevocationListV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationListV2Signature(decoded, issuerID, statusPub); err != nil {
		t.Fatalf("authenticated status signature rejected: %v", err)
	}
	if err := VerifyRevocationListV2Signature(decoded, strings.Repeat("b", 64), statusPub); err == nil {
		t.Fatal("accepted a status object under a different authenticated issuer")
	}
	decoded.Sequence++
	if err := VerifyRevocationListV2Signature(decoded, issuerID, statusPub); err == nil {
		t.Fatal("accepted a tampered signed status list")
	}
}

func TestStatusEvidenceDigestBindsCompleteCanonicalObject(t *testing.T) {
	list := &RevocationListV2{
		Version: 2, IssuerID: strings.Repeat("e", 64), UpdatedAt: 10, NextUpdate: 20,
		Sequence: 1, Revoked: []RevokedCertV2{},
		Signature: HybridSignature{Ed25519: bytes.Repeat([]byte{1}, 64), MLDSA65: bytes.Repeat([]byte{2}, 3309)},
	}
	encoded, err := EncodeRevocationListV2(list)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), list)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("ratify-protocol-status-evidence-v2\x00"), 0, 3)
	input = append(input, encoded...)
	expected := sha512.Sum384(input)
	if !bytes.Equal(digest, expected[:]) {
		t.Fatalf("digest mismatch: got %s, want %s", hex.EncodeToString(digest), hex.EncodeToString(expected[:]))
	}
	if _, err := StatusEvidenceDigest(uint16(v2RevocationPush), list); err == nil {
		t.Fatal("accepted an object whose type does not match the status code")
	}
	if _, err := StatusEvidenceDigest(uint16(v2DelegationCertificate), list); err == nil {
		t.Fatal("accepted a non-status object code")
	}
	list.Signature.Ed25519[0] ^= 1
	mutated, err := StatusEvidenceDigest(uint16(v2RevocationList), list)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest, mutated) {
		t.Fatal("digest did not bind the complete signed object")
	}
	var code [2]byte
	binary.BigEndian.PutUint16(code[:], uint16(v2RevocationList))
	if !bytes.Equal(code[:], []byte{0, 3}) {
		t.Fatal("test assumption about big-endian object code is invalid")
	}
}

func TestRevocationPushV2CodecAndAuthenticatedStatusKey(t *testing.T) {
	issuerID := strings.Repeat("c", 64)
	statusPub, statusPriv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	push := &RevocationPushV2{
		Version: 2, IssuerID: issuerID, Sequence: 2, PushedAt: 101,
		Revoked: []RevokedCertV2{{CertID: "grant-2"}},
	}
	unsignedPush := push
	push, err = SignRevocationPushV2(unsignedPush, issuerID, statusPub, statusPriv)
	if err != nil {
		t.Fatal(err)
	}
	unsignedPush.Revoked[0].CertID = "mutated-after-signing"
	if push.Revoked[0].CertID != "grant-2" {
		t.Fatal("signed push aliases mutable input data")
	}
	if _, err := SignRevocationPushV2(push, strings.Repeat("f", 64), statusPub, statusPriv); err == nil {
		t.Fatal("signed a revocation push outside the caller-authenticated issuer binding")
	}
	otherStatusPub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignRevocationPushV2(push, issuerID, otherStatusPub, statusPriv); err == nil {
		t.Fatal("signed a revocation push with a key outside the caller-authenticated status-key binding")
	}
	wire, err := EncodeRevocationPushV2(push)
	if err != nil {
		t.Fatal(err)
	}
	assertV2JSONKeyOrder(t, string(wire), []string{"issuer_id", "pushed_at", "revoked", "sequence", "signature", "version"})
	decoded, err := DecodeRevocationPushV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocationPushV2Signature(decoded, issuerID, statusPub); err != nil {
		t.Fatalf("authenticated push signature rejected: %v", err)
	}
	decoded.Revoked[0].CertID = "grant-tampered"
	if err := VerifyRevocationPushV2Signature(decoded, issuerID, statusPub); err == nil {
		t.Fatal("accepted a tampered signed status push")
	}
}

func TestV2StatusDecodersRejectMalformedAndV1Objects(t *testing.T) {
	invalidList := []string{
		`{"version":1,"issuer_id":"` + strings.Repeat("a", 64) + `","updated_at":1,"next_update":2,"sequence":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`,
		`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","updated_at":2,"next_update":2,"sequence":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`,
		`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","updated_at":1,"next_update":2,"sequence":0,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`,
		`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","updated_at":1,"next_update":2,"Sequence":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`,
	}
	for _, raw := range invalidList {
		if _, err := DecodeRevocationListV2([]byte(raw)); err == nil {
			t.Errorf("accepted invalid v2 revocation list: %s", raw)
		}
	}
	invalidPush := []string{
		`{"version":1,"issuer_id":"` + strings.Repeat("a", 64) + `","sequence":1,"pushed_at":1,"revoked":[],"signature":{"ed25519":"","ml_dsa_65":""}}`,
		`{"version":2,"issuer_id":"` + strings.Repeat("a", 64) + `","sequence":1,"pushed_at":1,"revoked":[{"cert_id":"x"},{"cert_id":"x"}],"signature":{"ed25519":"","ml_dsa_65":""}}`,
	}
	for _, raw := range invalidPush {
		if _, err := DecodeRevocationPushV2([]byte(raw)); err == nil {
			t.Errorf("accepted invalid v2 revocation push: %s", raw)
		}
	}
	valid, err := EncodeRevocationPushV2(&RevocationPushV2{
		Version: 2, IssuerID: strings.Repeat("d", 64), Sequence: 1, PushedAt: 1,
		Revoked: []RevokedCertV2{}, Signature: HybridSignature{Ed25519: bytes.Repeat([]byte{1}, 64), MLDSA65: bytes.Repeat([]byte{1}, 3309)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(valid, &obj); err != nil {
		t.Fatal(err)
	}
	obj["unknown"] = json.RawMessage(`true`)
	unknown, _ := json.Marshal(obj)
	if _, err := DecodeRevocationPushV2(unknown); err == nil {
		t.Fatal("accepted unknown signed status field")
	}
}

func assertV2JSONKeyOrder(t *testing.T, wire string, names []string) {
	t.Helper()
	previous := -1
	for _, name := range names {
		index := strings.Index(wire, `"`+name+`":`)
		if index <= previous {
			t.Fatalf("canonical JSON key %q is missing or out of order in %s", name, wire)
		}
		previous = index
	}
}
