package ratify

import (
	"context"
	"testing"
)

// countingSignerV2Test records every signer method call, so a test can prove
// that issuer-duty validation runs before the signer is touched at all.
type countingSignerV2Test struct {
	inner      remoteSignerV2Test
	publicKeys int
	modes      int
}

func (s *countingSignerV2Test) PublicKeyV2() HybridPublicKey {
	s.publicKeys++
	return s.inner.PublicKeyV2()
}
func (s *countingSignerV2Test) ModeV2() SignerModeV2 { s.modes++; return s.inner.ModeV2() }
func (s *countingSignerV2Test) SignV2(ctx context.Context, req SignRequestV2) (HybridSignature, error) {
	return s.inner.SignV2(ctx, req)
}

func (s *countingSignerV2Test) touched() int { return s.publicKeys + s.modes + s.inner.calls }

// TestSignDelegationCertV2EnforcesIssuerDutiesBeforeSigning pins SPEC-v2
// §5.1 and §5.2: a v2 issuer never emits a certificate that is already
// invalid by time bounds or whose resource_path set can never pass. Each
// case is rejected before any signer method runs, so an HSM is never asked
// to sign it; the verifier rules for such certificates are unchanged.
func TestSignDelegationCertV2EnforcesIssuerDutiesBeforeSigning(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	rp := func(id, prefix string) ConstraintV2 {
		return ConstraintV2{Type: ConstraintResourcePath, ResourceID: id, PathPrefix: prefix}
	}
	rejected := map[string]func(*DelegationCertV2){
		"issued_at equals expires_at":   func(c *DelegationCertV2) { c.IssuedAt, c.ExpiresAt = 100, 100 },
		"issued_at after expires_at":    func(c *DelegationCertV2) { c.IssuedAt, c.ExpiresAt = 101, 100 },
		"lifetime one past the bound":   func(c *DelegationCertV2) { c.IssuedAt, c.ExpiresAt = 1, 1+V2MaxDelegationLifetimeSeconds+1 },
		"distinct resource IDs":         func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", ""), rp("repo/b", "")} },
		"disjoint path prefixes":        func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/docs")} },
		"segment, not string, prefixes": func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/srcx")} },
		"path prefix outside the model": func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", "/src/../etc")} },
	}
	for name, mutate := range rejected {
		t.Run(name, func(t *testing.T) {
			cert := unsignedCertV2Test(t, pub)
			mutate(cert)
			signer := &countingSignerV2Test{inner: remoteSignerV2Test{priv: priv, mode: SignerModeDirectV2}}
			if signed, err := SignDelegationCertV2WithSigner(context.Background(), cert, signer); err == nil || signed != nil {
				t.Fatalf("issuer signed a certificate that violates an issuer duty")
			}
			if signer.touched() != 0 {
				t.Fatalf("signer was invoked %d times before issuer-duty validation failed", signer.touched())
			}
			if _, err := SignDelegationCertV2(cert, priv); err == nil {
				t.Fatal("local-key signing skipped issuer-duty validation")
			}
		})
	}
	accepted := map[string]func(*DelegationCertV2){
		"lifetime exactly at the bound": func(c *DelegationCertV2) { c.IssuedAt, c.ExpiresAt = 1, 1+V2MaxDelegationLifetimeSeconds },
		"nested prefixes": func(c *DelegationCertV2) {
			c.Constraints = []ConstraintV2{rp("repo/a", "/src"), rp("repo/a", "/src/lib/")}
		},
		"absent prefix nests with any": func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", ""), rp("repo/a", "/docs")} },
		"root prefix nests with any":   func(c *DelegationCertV2) { c.Constraints = []ConstraintV2{rp("repo/a", "/"), rp("repo/a", "/docs")} },
	}
	for name, mutate := range accepted {
		t.Run(name, func(t *testing.T) {
			cert := unsignedCertV2Test(t, pub)
			mutate(cert)
			signed, err := SignDelegationCertV2(cert, priv)
			if err != nil {
				t.Fatalf("issuer rejected a satisfiable certificate: %v", err)
			}
			if err := VerifyDelegationCertV2Signature(signed); err != nil {
				t.Fatal(err)
			}
		})
	}
}
