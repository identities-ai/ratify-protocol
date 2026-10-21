package ratify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha3"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// KeyIDV2 returns the Protocol v2 key ID of a complete hybrid public key:
// lowercase_hex(SHA-256("ratify-key-id-v2" || 0x00 || ed25519 || ml_dsa_65)).
// It fails with the malformed class unless both components have their exact
// lengths.
func KeyIDV2(pub HybridPublicKey) (string, error) {
	id, err := keyIDV2(pub)
	return id, v2Classify(V2ErrMalformed, err)
}

// SignerModeV2 selects which ML-DSA-65 input an external signer receives.
type SignerModeV2 uint8

const (
	// SignerModeDirectV2: the provider signs Message with ML-DSA-65 under
	// MLDSAContext (FIPS 204 pure mode with a context string).
	SignerModeDirectV2 SignerModeV2 = 1
	// SignerModeExternalMuV2: the provider signs the 64-byte MLDSAMu that the
	// SDK derived as SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64), with
	// tr = SHAKE256(ml_dsa_65_public_key, 64).
	SignerModeExternalMuV2 SignerModeV2 = 2
)

// SignRequestV2 is everything an external signer receives for one typed v2
// statement. The SDK computes every field; the provider never chooses an
// object type, context or message. Ed25519 always signs Message.
type SignRequestV2 struct {
	// ObjectType is the registered SPEC-v2 object code being signed.
	ObjectType uint16
	Mode       SignerModeV2
	// Message is the 77-byte M: "ratify-protocol-signature" || 0x00 || 0x02 ||
	// u16be(ObjectType) || SHA-384(signable).
	Message []byte
	// MLDSAContext is the 22-byte FIPS 204 context "ratify-protocol/2/XXXX"
	// in direct mode, and nil in external-mu mode.
	MLDSAContext []byte
	// MLDSAMu is the 64-byte external mu in external-mu mode, and nil in
	// direct mode.
	MLDSAMu []byte
	// PublicKey is the complete hybrid public key the provider must sign
	// under, and KeyID its v2 key ID. A provider holding any other key must
	// refuse.
	PublicKey HybridPublicKey
	KeyID     string
}

// SignerV2 is an external signing provider, for example a remote signing
// service. The SDK never trusts its output: every returned hybrid signature is
// verified with the ordinary v2 verifier against PublicKeyV2 before use, and a
// signature that does not verify is an error. Signing errors and context
// cancellation are returned to the caller and nothing is signed; a signature
// returned after the context was cancelled is discarded.
//
// ML-DSA-65 signing is hedged, so retries may legitimately return different
// valid signature bytes for the same statement. Idempotency, replay and fork
// checks compare StatementBodyDigestV2 (or the bundle hash), never signature
// bytes. This interface makes no claim about any particular KMS or HSM.
type SignerV2 interface {
	// PublicKeyV2 returns the complete hybrid public key the provider signs
	// under. It must be stable for the lifetime of the signer.
	PublicKeyV2() HybridPublicKey
	// ModeV2 returns the ML-DSA-65 input mode the provider implements.
	ModeV2() SignerModeV2
	// SignV2 signs one SDK-prepared request.
	SignV2(ctx context.Context, req SignRequestV2) (HybridSignature, error)
}

// localSignerV2 adapts an in-process private key to SignerV2. The typed
// private-key signing functions use it, so local and external signing share
// one code path, including verification of the produced signature.
type localSignerV2 struct{ priv HybridPrivateKey }

// NewLocalSignerV2 returns a direct-mode SignerV2 backed by an in-process
// hybrid private key. ML-DSA-65 signatures are hedged.
func NewLocalSignerV2(priv HybridPrivateKey) (SignerV2, error) {
	if err := validateV2PrivateKey(priv); err != nil {
		return nil, err
	}
	return localSignerV2{priv: priv}, nil
}

func (s localSignerV2) PublicKeyV2() HybridPublicKey { return s.priv.Public() }

func (s localSignerV2) ModeV2() SignerModeV2 { return SignerModeDirectV2 }

func (s localSignerV2) SignV2(ctx context.Context, req SignRequestV2) (HybridSignature, error) {
	if err := ctx.Err(); err != nil {
		return HybridSignature{}, err
	}
	if req.Mode != SignerModeDirectV2 || len(req.Message) != v2SigningMessageSize || len(req.MLDSAContext) == 0 {
		return HybridSignature{}, fmt.Errorf("local v2 signer supports only direct-mode requests")
	}
	edSignature := ed25519.Sign(s.priv.Ed25519, req.Message)
	mlSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.priv.MLDSA65, req.Message, req.MLDSAContext, true, mlSignature); err != nil {
		return HybridSignature{}, fmt.Errorf("ML-DSA-65 v2 sign: %w", err)
	}
	return HybridSignature{Ed25519: edSignature, MLDSA65: mlSignature}, nil
}

// v2SigningMessageSize is len("ratify-protocol-signature\x00\x02") + 2 + 48.
const v2SigningMessageSize = 77

// signerPublicKeyV2 returns the complete public key a signer signs under. A
// local signer's private key is validated first; an external signer's key
// must have exact component lengths.
func signerPublicKeyV2(signer SignerV2) (HybridPublicKey, error) {
	if signer == nil {
		return HybridPublicKey{}, fmt.Errorf("v2 signer is required")
	}
	if local, ok := signer.(localSignerV2); ok {
		if err := validateV2PrivateKey(local.priv); err != nil {
			return HybridPublicKey{}, err
		}
		return local.priv.Public(), nil
	}
	pub := signer.PublicKeyV2()
	if _, err := keyIDV2(pub); err != nil {
		return HybridPublicKey{}, fmt.Errorf("v2 signer public key: %w", err)
	}
	return HybridPublicKey{Ed25519: bytes.Clone(pub.Ed25519), MLDSA65: bytes.Clone(pub.MLDSA65)}, nil
}

// externalMuV2 derives the FIPS 204 external mu for a v2 statement.
func externalMuV2(mlPub, mlContext, message []byte) []byte {
	tr := sha3.SumSHAKE256(mlPub, 64)
	pre := make([]byte, 0, len(tr)+2+len(mlContext)+len(message))
	pre = append(pre, tr...)
	pre = append(pre, 0x00, byte(len(mlContext)))
	pre = append(pre, mlContext...)
	pre = append(pre, message...)
	return sha3.SumSHAKE256(pre, 64)
}

// signV2StatementWithSigner prepares the typed request, calls the signer and
// verifies the returned signature under pub before returning it.
func signV2StatementWithSigner(ctx context.Context, objectType v2ObjectType, signable []byte, signer SignerV2, pub HybridPublicKey) (HybridSignature, error) {
	if ctx == nil {
		return HybridSignature{}, fmt.Errorf("v2 signing requires a context")
	}
	if err := ctx.Err(); err != nil {
		return HybridSignature{}, err
	}
	message, err := v2SigningMessage(objectType, signable)
	if err != nil {
		return HybridSignature{}, err
	}
	mlContext, err := v2MLDSAContext(objectType)
	if err != nil {
		return HybridSignature{}, err
	}
	keyID, err := keyIDV2(pub)
	if err != nil {
		return HybridSignature{}, err
	}
	req := SignRequestV2{
		ObjectType: uint16(objectType), Mode: signer.ModeV2(), Message: message,
		PublicKey: HybridPublicKey{Ed25519: bytes.Clone(pub.Ed25519), MLDSA65: bytes.Clone(pub.MLDSA65)},
		KeyID:     keyID,
	}
	switch req.Mode {
	case SignerModeDirectV2:
		req.MLDSAContext = mlContext
	case SignerModeExternalMuV2:
		req.MLDSAMu = externalMuV2(pub.MLDSA65, mlContext, message)
	default:
		return HybridSignature{}, fmt.Errorf("v2 signer reports an unsupported mode %d", req.Mode)
	}
	signature, err := signer.SignV2(ctx, req)
	if err != nil {
		return HybridSignature{}, fmt.Errorf("v2 signer: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return HybridSignature{}, err
	}
	signature = HybridSignature{Ed25519: bytes.Clone(signature.Ed25519), MLDSA65: bytes.Clone(signature.MLDSA65)}
	if err := verifyV2Statement(objectType, signable, signature, pub); err != nil {
		return HybridSignature{}, fmt.Errorf("v2 signer returned a signature that does not verify: %w", err)
	}
	return signature, nil
}
