package ratify_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// v2TestKeyProvider is a test-only external signing provider that holds its
// own key, as an HSM or KMS would. The SDK exports no local SignerV2 (SPEC-v2
// §3.2), so a provider that signs whatever it is handed is the provider's own
// capability; the SDK still prepares every request and verifies every
// returned signature.
type v2TestKeyProvider struct{ priv ratify.HybridPrivateKey }

func (p v2TestKeyProvider) PublicKeyV2() ratify.HybridPublicKey { return p.priv.Public() }

func (p v2TestKeyProvider) ModeV2() ratify.SignerModeV2 { return ratify.SignerModeDirectV2 }

func (p v2TestKeyProvider) SignV2(ctx context.Context, req ratify.SignRequestV2) (ratify.HybridSignature, error) {
	if req.Mode != ratify.SignerModeDirectV2 {
		return ratify.HybridSignature{}, errors.New("test provider signs direct-mode requests only")
	}
	ml := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(p.priv.MLDSA65, req.Message, req.MLDSAContext, true, ml); err != nil {
		return ratify.HybridSignature{}, err
	}
	return ratify.HybridSignature{Ed25519: ed25519.Sign(p.priv.Ed25519, req.Message), MLDSA65: ml}, nil
}

// v2CountingSigner wraps a provider as an external signer and counts every
// method call, so a vector can require that no signer method ran.
type v2CountingSigner struct {
	inner ratify.SignerV2
	calls int
}

func (s *v2CountingSigner) PublicKeyV2() ratify.HybridPublicKey {
	s.calls++
	return s.inner.PublicKeyV2()
}

func (s *v2CountingSigner) ModeV2() ratify.SignerModeV2 {
	s.calls++
	return s.inner.ModeV2()
}

func (s *v2CountingSigner) SignV2(ctx context.Context, req ratify.SignRequestV2) (ratify.HybridSignature, error) {
	s.calls++
	return s.inner.SignV2(ctx, req)
}

func TestV2ConformanceIssuerDuties(t *testing.T) {
	var f struct {
		Version     int    `json:"version"`
		Description string `json:"description"`
		Procedure   string `json:"procedure"`
		Vectors     []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Issuer      string `json:"issuer"`
			UnsignedB64 string `json:"unsigned_certificate_b64"`
			Expected    string `json:"expected"`
		} `json:"vectors"`
	}
	loadV2Vector(t, "issuer-duties.json", &f)
	_, fx := loadV2Keys(t)
	if len(f.Vectors) == 0 {
		t.Fatal("no issuer-duty vectors")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			cert, err := ratify.DecodeDelegationCertV2(unb64(t, v.UnsignedB64))
			if err != nil {
				t.Fatalf("unsigned certificate must decode: %v", err)
			}
			signer := &v2CountingSigner{inner: v2TestKeyProvider{fx.priv[v.Issuer]}}
			signed, err := ratify.SignDelegationCertV2WithSigner(context.Background(), cert, signer)
			switch v.Expected {
			case "sign":
				if err != nil {
					t.Fatalf("expected the certificate to sign: %v", err)
				}
				if err := ratify.VerifyDelegationCertV2Signature(signed); err != nil {
					t.Fatal(err)
				}
			case "reject":
				if err == nil || signed != nil {
					t.Fatal("expected the issuer duty to refuse signing")
				}
				if signer.calls != 0 {
					t.Fatalf("signer was invoked %d times before the refusal", signer.calls)
				}
			default:
				t.Fatalf("unknown expectation %q", v.Expected)
			}
		})
	}
}
