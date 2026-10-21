package ratify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// v2ObjectType is deliberately closed: v2 callers cannot choose a signing
// context independently of the schema being signed.
type v2ObjectType uint16

const (
	v2DelegationCertificate        v2ObjectType = 0x0001
	v2ChallengePresentation        v2ObjectType = 0x0002
	v2RevocationList               v2ObjectType = 0x0003
	v2KeyRotationAuthorization     v2ObjectType = 0x0004
	v2RevocationPush               v2ObjectType = 0x0005
	v2WitnessEntry                 v2ObjectType = 0x0006
	v2TransactionPartyStatement    v2ObjectType = 0x0007
	v2VerificationReceipt          v2ObjectType = 0x0008
	v2KeyRotationProofOfPossession v2ObjectType = 0x0009
)

func validV2ObjectType(objectType v2ObjectType) bool {
	return objectType >= v2DelegationCertificate && objectType <= v2KeyRotationProofOfPossession
}

func keyIDV2(pub HybridPublicKey) (string, error) {
	if len(pub.Ed25519) != ed25519.PublicKeySize {
		return "", fmt.Errorf("Ed25519 public key wrong length: %d", len(pub.Ed25519))
	}
	if len(pub.MLDSA65) != mldsa65.PublicKeySize {
		return "", fmt.Errorf("ML-DSA-65 public key wrong length: %d", len(pub.MLDSA65))
	}
	h := sha256.New()
	h.Write([]byte("ratify-key-id-v2\x00"))
	h.Write(pub.Ed25519)
	h.Write(pub.MLDSA65)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func v2SigningMessage(objectType v2ObjectType, signable []byte) ([]byte, error) {
	if !validV2ObjectType(objectType) {
		return nil, fmt.Errorf("unsupported v2 object type: %04x", uint16(objectType))
	}
	digest := sha512.Sum384(signable)
	message := make([]byte, 0, len("ratify-protocol-signature\x00\x02")+2+len(digest))
	message = append(message, "ratify-protocol-signature\x00\x02"...)
	var encodedType [2]byte
	binary.BigEndian.PutUint16(encodedType[:], uint16(objectType))
	message = append(message, encodedType[:]...)
	message = append(message, digest[:]...)
	return message, nil
}

func v2MLDSAContext(objectType v2ObjectType) ([]byte, error) {
	if !validV2ObjectType(objectType) {
		return nil, fmt.Errorf("unsupported v2 object type: %04x", uint16(objectType))
	}
	return []byte(fmt.Sprintf("ratify-protocol/2/%04x", uint16(objectType))), nil
}

func signV2Statement(objectType v2ObjectType, signable []byte, priv HybridPrivateKey) (HybridSignature, error) {
	if err := validateV2PrivateKey(priv); err != nil {
		return HybridSignature{}, err
	}
	message, err := v2SigningMessage(objectType, signable)
	if err != nil {
		return HybridSignature{}, err
	}
	context, err := v2MLDSAContext(objectType)
	if err != nil {
		return HybridSignature{}, err
	}
	edSignature := ed25519.Sign(priv.Ed25519, message)
	mlSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(priv.MLDSA65, message, context, true, mlSignature); err != nil {
		return HybridSignature{}, fmt.Errorf("ML-DSA-65 v2 sign: %w", err)
	}
	return HybridSignature{Ed25519: edSignature, MLDSA65: mlSignature}, nil
}

func validateV2PrivateKey(priv HybridPrivateKey) error {
	if len(priv.Ed25519) != ed25519.PrivateKeySize || priv.MLDSA65 == nil {
		return fmt.Errorf("incomplete hybrid private key")
	}
	derivedEdPrivate := ed25519.NewKeyFromSeed(priv.Ed25519[:ed25519.SeedSize])
	if !bytes.Equal(derivedEdPrivate, priv.Ed25519) {
		return fmt.Errorf("Ed25519 private key seed and public component do not match")
	}
	return nil
}

// v2Ed25519Order is the Ed25519 subgroup order L, encoded little-endian.
var v2Ed25519Order = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

func validV2Ed25519Scalar(s []byte) bool {
	if len(s) != len(v2Ed25519Order) {
		return false
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != v2Ed25519Order[i] {
			return s[i] < v2Ed25519Order[i]
		}
	}
	return false
}

func validV2Ed25519Point(encoded []byte) bool {
	if len(encoded) != ed25519.PublicKeySize {
		return false
	}
	point, err := new(edwards25519.Point).SetBytes(encoded)
	if err != nil || !bytes.Equal(point.Bytes(), encoded) {
		return false
	}

	return v2Ed25519PrimeOrder(point)
}

// v2Ed25519PrimeOrder checks [L]P = identity and rejects the identity. This
// excludes both small-order and mixed-order points; cofactor multiplication
// alone would not reject mixed-order points.
func v2Ed25519PrimeOrder(point *edwards25519.Point) bool {
	multiple := edwards25519.NewIdentityPoint()
	for bit := 252; bit >= 0; bit-- {
		multiple.Add(multiple, multiple)
		if (v2Ed25519Order[bit/8]>>(bit%8))&1 == 1 {
			multiple.Add(multiple, point)
		}
	}
	return multiple.Equal(edwards25519.NewIdentityPoint()) == 1 &&
		point.Equal(edwards25519.NewIdentityPoint()) != 1
}

// verifyV2Statement classifies every failure: an unregistered object code is
// unsupported_object_type and every other failure is invalid_signature.
func verifyV2Statement(objectType v2ObjectType, signable []byte, sig HybridSignature, pub HybridPublicKey) error {
	if !validV2ObjectType(objectType) {
		return v2Errorf(V2ErrUnsupportedObjectType, "unsupported v2 object type: %04x", uint16(objectType))
	}
	return v2Classify(V2ErrInvalidSignature, verifyV2StatementUnclassified(objectType, signable, sig, pub))
}

func verifyV2StatementUnclassified(objectType v2ObjectType, signable []byte, sig HybridSignature, pub HybridPublicKey) error {
	if len(pub.Ed25519) != ed25519.PublicKeySize || len(pub.MLDSA65) != mldsa65.PublicKeySize {
		return fmt.Errorf("hybrid public key has invalid component length")
	}
	if len(sig.Ed25519) != ed25519.SignatureSize || len(sig.MLDSA65) != mldsa65.SignatureSize {
		return fmt.Errorf("hybrid signature has invalid component length")
	}
	if !validV2Ed25519Point(pub.Ed25519) || !validV2Ed25519Point(sig.Ed25519[:ed25519.PublicKeySize]) {
		return fmt.Errorf("Ed25519 v2 public key or R component is not a canonical non-identity prime-order point")
	}
	if !validV2Ed25519Scalar(sig.Ed25519[ed25519.PublicKeySize:]) {
		return fmt.Errorf("Ed25519 v2 S component is not a canonical scalar")
	}
	message, err := v2SigningMessage(objectType, signable)
	if err != nil {
		return err
	}
	context, err := v2MLDSAContext(objectType)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub.Ed25519, message, sig.Ed25519) {
		return fmt.Errorf("Ed25519 v2 signature invalid")
	}
	var mlPublic mldsa65.PublicKey
	if err := mlPublic.UnmarshalBinary(pub.MLDSA65); err != nil {
		return fmt.Errorf("ML-DSA-65 public key malformed: %w", err)
	}
	if !mldsa65.Verify(&mlPublic, message, context, sig.MLDSA65) {
		return fmt.Errorf("ML-DSA-65 v2 signature invalid")
	}
	return nil
}
