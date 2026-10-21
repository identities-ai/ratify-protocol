package ratify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestV2SharedDelegationSignatureVector(t *testing.T) {
	type vector struct {
		Version               int    `json:"version"`
		ObjectTypeCode        int    `json:"object_type_code"`
		KeyIDV2               string `json:"key_id_v2"`
		SignableBytes         string `json:"signable_bytes"`
		Message               string `json:"message"`
		MLDSAContext          string `json:"mldsa_context"`
		MLDSATr               string `json:"mldsa_tr"`
		MLDSAMu               string `json:"mldsa_mu"`
		AlternateMLDSAContext string `json:"alternate_mldsa_context"`
		IssuerSeeds           struct {
			Ed25519 string `json:"ed25519"`
			MLDSA65 string `json:"ml_dsa_65"`
		} `json:"issuer_seeds"`
		NegativeMutations struct {
			XORMask byte     `json:"xor_mask"`
			Targets []string `json:"targets"`
		} `json:"negative_mutations"`
		IssuerPublicKey struct {
			Ed25519 string `json:"ed25519"`
			MLDSA65 string `json:"ml_dsa_65"`
		} `json:"issuer_public_key"`
		Signature struct {
			Ed25519 string `json:"ed25519"`
			MLDSA65 string `json:"ml_dsa_65"`
		} `json:"signature"`
	}
	encoded, err := os.ReadFile("testvectors/v2/delegation-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture vector
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 2 || fixture.ObjectTypeCode != int(v2DelegationCertificate) {
		t.Fatalf("shared vector version/type = %d/%04x", fixture.Version, fixture.ObjectTypeCode)
	}
	decode := func(value string) []byte {
		t.Helper()
		result, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	signable := decode(fixture.SignableBytes)
	var signableValue any
	if err := json.Unmarshal(signable, &signableValue); err != nil {
		t.Fatal(err)
	}
	canonicalSignable, err := CanonicalJSON(signableValue)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signable, canonicalSignable) {
		t.Fatal("shared v2 signable bytes are not RatifyCanonicalJSON")
	}
	message, err := v2SigningMessage(v2DelegationCertificate, signable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decode(fixture.Message)) {
		t.Fatal("Go transcript does not match shared v2 vector")
	}
	context, err := v2MLDSAContext(v2DelegationCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(context, decode(fixture.MLDSAContext)) {
		t.Fatal("Go ML-DSA context does not match shared v2 vector")
	}
	pub := HybridPublicKey{Ed25519: decode(fixture.IssuerPublicKey.Ed25519), MLDSA65: decode(fixture.IssuerPublicKey.MLDSA65)}
	if len(pub.MLDSA65) != mldsa65.PublicKeySize || len(context) != 22 || len(message) != 77 {
		t.Fatal("invalid external-mu fixture input lengths")
	}
	tr := sha3.SumSHAKE256(pub.MLDSA65, 64)
	if !bytes.Equal(tr, decode(fixture.MLDSATr)) {
		t.Fatal("Go external-mu tr does not match shared vector")
	}
	muInput := append(append(append([]byte(nil), tr...), 0, byte(len(context))), context...)
	muInput = append(muInput, message...)
	if mu := sha3.SumSHAKE256(muInput, 64); !bytes.Equal(mu, decode(fixture.MLDSAMu)) {
		t.Fatal("Go external-mu mu does not match shared vector")
	}
	sig := HybridSignature{Ed25519: decode(fixture.Signature.Ed25519), MLDSA65: decode(fixture.Signature.MLDSA65)}
	if err := verifyV2Statement(v2DelegationCertificate, signable, sig, pub); err != nil {
		t.Fatalf("Go rejected shared TypeScript signature vector: %v", err)
	}
	var edSeed, mlSeed [32]byte
	seedBytes := decode(fixture.IssuerSeeds.Ed25519)
	if len(seedBytes) != len(edSeed) {
		t.Fatalf("fixture Ed25519 seed length = %d", len(seedBytes))
	}
	copy(edSeed[:], seedBytes)
	seedBytes = decode(fixture.IssuerSeeds.MLDSA65)
	if len(seedBytes) != len(mlSeed) {
		t.Fatalf("fixture ML-DSA seed length = %d", len(seedBytes))
	}
	copy(mlSeed[:], seedBytes)
	derivedPub, derivedPriv, err := HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedPub.Ed25519, pub.Ed25519) || !bytes.Equal(derivedPub.MLDSA65, pub.MLDSA65) {
		t.Fatal("Go seeded key generation does not match shared TypeScript vector")
	}
	keyID, err := keyIDV2(derivedPub)
	if err != nil {
		t.Fatal(err)
	}
	if keyID != fixture.KeyIDV2 {
		t.Fatalf("shared vector key ID = %s, got %s", fixture.KeyIDV2, keyID)
	}
	if !bytes.Equal(ed25519.Sign(derivedPriv.Ed25519, message), sig.Ed25519) {
		t.Fatal("Go Ed25519 signature does not match the deterministic vector")
	}
	deterministicMLDSA := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(derivedPriv.MLDSA65, message, context, false, deterministicMLDSA); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(deterministicMLDSA, sig.MLDSA65) {
		t.Fatal("Go deterministic ML-DSA signature does not match the TypeScript vector")
	}
	wrongContextSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(derivedPriv.MLDSA65, message, decode(fixture.AlternateMLDSAContext), false, wrongContextSignature); err != nil {
		t.Fatal(err)
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, HybridSignature{Ed25519: sig.Ed25519, MLDSA65: wrongContextSignature}, pub); err == nil {
		t.Fatal("v2 verifier accepted an ML-DSA signature made with a different object context")
	}
	if err := verifyV2Statement(v2DelegationCertificate, append(signable, 0), sig, pub); err == nil {
		t.Fatal("Go accepted the shared signature vector over a modified signable body")
	}
	for _, target := range fixture.NegativeMutations.Targets {
		mutatedSignable := append([]byte(nil), signable...)
		mutatedSig := HybridSignature{Ed25519: append([]byte(nil), sig.Ed25519...), MLDSA65: append([]byte(nil), sig.MLDSA65...)}
		mutatedPub := HybridPublicKey{Ed25519: append([]byte(nil), pub.Ed25519...), MLDSA65: append([]byte(nil), pub.MLDSA65...)}
		switch target {
		case "signable_bytes":
			mutatedSignable[0] ^= fixture.NegativeMutations.XORMask
		case "signature.ed25519":
			mutatedSig.Ed25519[0] ^= fixture.NegativeMutations.XORMask
		case "signature.ml_dsa_65":
			mutatedSig.MLDSA65[0] ^= fixture.NegativeMutations.XORMask
		case "issuer_public_key.ed25519":
			mutatedPub.Ed25519[0] ^= fixture.NegativeMutations.XORMask
		case "issuer_public_key.ml_dsa_65":
			mutatedPub.MLDSA65[0] ^= fixture.NegativeMutations.XORMask
		default:
			t.Fatalf("unknown shared vector mutation target %q", target)
		}
		if err := verifyV2Statement(v2DelegationCertificate, mutatedSignable, mutatedSig, mutatedPub); err == nil {
			t.Errorf("Go accepted shared vector mutation %q", target)
		}
	}
}

func TestV2KeyIDUsesVersionedDomainAndBothKeys(t *testing.T) {
	pub, _, err := HybridKeypairFromSeeds([32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := keyIDV2(pub)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2\x00"))
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	want := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Fatalf("keyIDV2() = %q, want %q", got, want)
	}
	const expectedKeyID = "31e31007b20edf49d044f5413f952d94e3d95f51a3cd85f131aa5856ef0bfa2f"
	if got != expectedKeyID {
		t.Fatalf("keyIDV2() = %q, want known answer %q", got, expectedKeyID)
	}
	if got == DeriveID(pub) {
		t.Fatal("v2 key ID unexpectedly matches the unversioned v1 ID")
	}
	if _, err := keyIDV2(HybridPublicKey{Ed25519: pub.Ed25519}); err == nil {
		t.Fatal("keyIDV2 accepted a missing ML-DSA key")
	}
	if _, err := keyIDV2(HybridPublicKey{Ed25519: pub.Ed25519[:31], MLDSA65: pub.MLDSA65}); err == nil {
		t.Fatal("keyIDV2 accepted an Ed25519 key with the wrong length")
	}
	if _, err := keyIDV2(HybridPublicKey{Ed25519: pub.MLDSA65, MLDSA65: pub.Ed25519}); err == nil {
		t.Fatal("keyIDV2 accepted swapped hybrid key components")
	}
}

func TestV2SigningTranscriptAndContextAreTyped(t *testing.T) {
	signable := []byte(`{"version":2}`)
	message, err := v2SigningMessage(v2DelegationCertificate, signable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384(signable)
	want := append([]byte("ratify-protocol-signature\x00\x02\x00\x01"), digest[:]...)
	if len(message) != 77 || !bytes.Equal(message, want) {
		t.Fatalf("v2 signing transcript mismatch: length=%d", len(message))
	}
	context, err := v2MLDSAContext(v2DelegationCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if string(context) != "ratify-protocol/2/0001" || len(context) != 22 {
		t.Fatalf("v2 ML-DSA context = %q", context)
	}
	if _, err := v2SigningMessage(v2ObjectType(0x9999), signable); err == nil {
		t.Fatal("v2 signing accepted an unregistered object type")
	}
}

func TestV2StatementSignsBothComponentsAndBindsType(t *testing.T) {
	pub, priv, err := HybridKeypairFromSeeds([32]byte{3}, [32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	signable := []byte(`{"version":2,"cert_id":"test"}`)
	sig, err := signV2Statement(v2DelegationCertificate, signable, priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Ed25519) != ed25519.SignatureSize || len(sig.MLDSA65) == 0 {
		t.Fatal("v2 signing did not produce both signature components")
	}
	malformedPrivate := priv
	malformedPrivate.Ed25519 = append(ed25519.PrivateKey(nil), priv.Ed25519...)
	malformedPrivate.Ed25519[len(malformedPrivate.Ed25519)-1] ^= 1
	if _, err := signV2Statement(v2DelegationCertificate, signable, malformedPrivate); err == nil {
		t.Fatal("v2 signing accepted inconsistent Ed25519 private-key components")
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, sig, pub); err != nil {
		t.Fatalf("verify signed statement: %v", err)
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, HybridSignature{Ed25519: sig.Ed25519[:63], MLDSA65: sig.MLDSA65}, pub); err == nil {
		t.Fatal("v2 verifier accepted a truncated Ed25519 signature")
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, HybridSignature{Ed25519: sig.Ed25519, MLDSA65: sig.MLDSA65[:len(sig.MLDSA65)-1]}, pub); err == nil {
		t.Fatal("v2 verifier accepted a truncated ML-DSA signature")
	}
	modified, err := v2SigningMessage(v2DelegationCertificate, append(signable, ' '))
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub.Ed25519, modified, sig.Ed25519) {
		t.Fatal("Ed25519 accepted a modified signable projection")
	}
	otherType, err := v2SigningMessage(v2ObjectType(0x000a), signable)
	if err == nil {
		t.Fatalf("unregistered object type unexpectedly produced transcript %x", otherType)
	}
	if err := verifyV2Statement(v2DelegationCertificate, append(signable, ' '), sig, pub); err == nil {
		t.Fatal("v2 verifier accepted a modified signable projection")
	}

	identity := edwards25519.NewIdentityPoint().Bytes()
	identityPub := pub
	identityPub.Ed25519 = identity
	if err := verifyV2Statement(v2DelegationCertificate, signable, sig, identityPub); err == nil {
		t.Fatal("v2 verifier accepted an identity public point")
	}

	// Add the order-two point (0,-1) to a valid key to construct a canonical,
	// mixed-order point. A cofactor-only check would miss this case.
	torsion, err := new(edwards25519.Point).SetBytes([]byte{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	})
	if err != nil {
		t.Fatalf("decode order-two test point: %v", err)
	}
	validPoint, err := new(edwards25519.Point).SetBytes(pub.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	mixedOrder := new(edwards25519.Point).Add(validPoint, torsion).Bytes()
	mixedPub := pub
	mixedPub.Ed25519 = mixedOrder
	if validV2Ed25519Point(mixedOrder) {
		t.Fatal("strict point check accepted a mixed-order point")
	}
	if err := verifyV2Statement(v2DelegationCertificate, signable, sig, mixedPub); err == nil {
		t.Fatal("v2 verifier accepted a mixed-order public key")
	}

	nonCanonical := bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)
	nonCanonical[0] = 0xed
	nonCanonical[31] = 0x7f // y = p reduces to y = 0 and decodes to an order-four point.
	if validV2Ed25519Point(nonCanonical) {
		t.Fatal("strict point check accepted a non-canonical field encoding")
	}
	negativeZero := bytes.Repeat([]byte{0}, ed25519.PublicKeySize)
	negativeZero[0] = 1
	negativeZero[31] = 0x80 // y = 1 with the forbidden negative-zero sign bit decodes to identity.
	for name, invalidPoint := range map[string][]byte{"y=p": nonCanonical, "negative zero": negativeZero} {
		if validV2Ed25519Point(invalidPoint) {
			t.Fatalf("strict point check accepted %s", name)
		}
		badPub := pub
		badPub.Ed25519 = invalidPoint
		if err := verifyV2Statement(v2DelegationCertificate, signable, sig, badPub); err == nil {
			t.Fatalf("v2 verifier accepted %s public key", name)
		}
		badR := sig
		badR.Ed25519 = append([]byte(nil), sig.Ed25519...)
		copy(badR.Ed25519[:ed25519.PublicKeySize], invalidPoint)
		if err := verifyV2Statement(v2DelegationCertificate, signable, badR, pub); err == nil {
			t.Fatalf("v2 verifier accepted %s R point", name)
		}
	}
	badR := sig
	badR.Ed25519 = append([]byte(nil), sig.Ed25519...)
	copy(badR.Ed25519[:ed25519.PublicKeySize], identity)
	if err := verifyV2Statement(v2DelegationCertificate, signable, badR, pub); err == nil {
		t.Fatal("v2 verifier accepted an identity R component")
	}
	badR.Ed25519 = append([]byte(nil), sig.Ed25519...)
	copy(badR.Ed25519[:ed25519.PublicKeySize], mixedOrder)
	if err := verifyV2Statement(v2DelegationCertificate, signable, badR, pub); err == nil {
		t.Fatal("v2 verifier accepted a mixed-order R component")
	}
	badS := sig
	badS.Ed25519 = append([]byte(nil), sig.Ed25519...)
	copy(badS.Ed25519[ed25519.PublicKeySize:], v2Ed25519Order[:])
	if err := verifyV2Statement(v2DelegationCertificate, signable, badS, pub); err == nil {
		t.Fatal("v2 verifier accepted S equal to the subgroup order")
	}
	badS.Ed25519 = append([]byte(nil), sig.Ed25519...)
	copy(badS.Ed25519[ed25519.PublicKeySize:], v2Ed25519Order[:])
	badS.Ed25519[ed25519.PublicKeySize]++
	if err := verifyV2Statement(v2DelegationCertificate, signable, badS, pub); err == nil {
		t.Fatal("v2 verifier accepted S greater than the subgroup order")
	}

	// These are the complete canonical encodings of the Ed25519 8-torsion
	// subgroup. Every key and R point must be rejected, not only the identity.
	for _, encoded := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	} {
		point, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if validV2Ed25519Point(point) {
			t.Fatalf("strict point check accepted torsion point %s", encoded)
		}
		badPub := pub
		badPub.Ed25519 = point
		if err := verifyV2Statement(v2DelegationCertificate, signable, sig, badPub); err == nil {
			t.Fatalf("v2 verifier accepted torsion public key %s", encoded)
		}
		badR := sig
		badR.Ed25519 = append([]byte(nil), sig.Ed25519...)
		copy(badR.Ed25519[:ed25519.PublicKeySize], point)
		if err := verifyV2Statement(v2DelegationCertificate, signable, badR, pub); err == nil {
			t.Fatalf("v2 verifier accepted torsion R %s", encoded)
		}
	}
	badMLDSA := sig
	badMLDSA.MLDSA65 = append([]byte(nil), sig.MLDSA65...)
	badMLDSA.MLDSA65[0] ^= 1
	if err := verifyV2Statement(v2DelegationCertificate, signable, badMLDSA, pub); err == nil {
		t.Fatal("v2 verifier accepted an invalid ML-DSA component")
	}
}

func TestV2ObjectRegistryUsesFixedDistinctContexts(t *testing.T) {
	for code := uint16(1); code <= 9; code++ {
		context, err := v2MLDSAContext(v2ObjectType(code))
		if err != nil {
			t.Fatalf("context for registered code %04x: %v", code, err)
		}
		if got, want := string(context), fmt.Sprintf("ratify-protocol/2/%04x", code); got != want {
			t.Fatalf("context for %04x = %q, want %q", code, got, want)
		}
	}
	if _, err := v2MLDSAContext(v2ObjectType(0)); err == nil {
		t.Fatal("reserved code 0000 accepted")
	}
	if _, err := v2MLDSAContext(v2ObjectType(10)); err == nil {
		t.Fatal("unregistered code 000a accepted")
	}
}
