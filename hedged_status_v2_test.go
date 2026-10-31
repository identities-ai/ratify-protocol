package ratify

import (
	"bytes"
	"strings"
	"testing"
)

// TestStatusReducerTreatsHedgedReSigningAsSameSnapshot: re-signing an
// identical revocation list (new ML-DSA bytes) is not a fork.
func TestStatusReducerTreatsHedgedReSigningAsSameSnapshot(t *testing.T) {
	pub, priv, _ := GenerateHybridKeypair()
	issuer := strings.Repeat("b", 64)
	unsigned := &RevocationListV2{Version: 2, IssuerID: issuer, UpdatedAt: 90, NextUpdate: 200, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "c"}}}
	first, err := SignRevocationListV2(unsigned, issuer, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignRevocationListV2(unsigned, issuer, pub, priv)
	if err != nil || bytes.Equal(first.Signature.MLDSA65, second.Signature.MLDSA65) {
		t.Fatalf("expected a distinct hedged signature: %v", err)
	}
	policy := RevocationStatusPolicyV2{MaxListLifetimeSeconds: 1000, MaxStatusAgeSeconds: 1000, ClockSkewSeconds: 5}
	state, err := ApplyRevocationListV2(RevocationStatusStateV2{}, first, issuer, 1, pub, policy, 100)
	if err != nil {
		t.Fatal(err)
	}
	state, err = ApplyRevocationListV2(state, second, issuer, 1, pub, policy, 100)
	if err != nil || state.ForkSequence != 0 || state.ReconciliationRequired {
		t.Fatalf("hedged re-signing of the same snapshot was treated as a conflict: fork=%d reconcile=%t err=%v", state.ForkSequence, state.ReconciliationRequired, err)
	}
}
