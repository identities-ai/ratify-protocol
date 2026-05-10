package ratify

import (
	"testing"
	"time"
)

// Benchmarks the hot path of the verifier — the function marketing materials
// promise runs "in under a millisecond." Committed results live in
// docs/BENCHMARKS.md; re-run with:
//
//   go test -bench=BenchmarkVerify -benchmem ./...
//
// These are NOT conformance tests. They're here to (a) catch verifier-path
// regressions across SDK changes and (b) give us published numbers to back
// the <1ms claim on the website and in pitch decks.

// benchBundle builds a signed depth-N bundle whose leaf is authorized for
// meeting:attend. Returns the bundle and the "now" instant to use at verify.
func benchBundle(b *testing.B, depth int, withConstraints bool) (*ProofBundle, time.Time) {
	b.Helper()
	if depth < 1 || depth > MaxDelegationChainDepth {
		b.Fatalf("unsupported depth %d", depth)
	}
	human, humanPriv, _ := GenerateHumanRootKeypair()
	leaf, leafPriv, _ := GenerateAgentKeypair("BenchAgent", "custom")

	// Intermediates + leaf.
	type keyed struct {
		id, name string
		// only depth-2+ uses an intermediate signer priv here
	}
	_ = keyed{}

	now := time.Unix(1800000000, 0).UTC()
	issuedAt := now.Add(-time.Hour).Unix()
	expiresAt := now.Add(23 * time.Hour).Unix()

	// For depth N, build chain [leaf, mid_{N-2}, ..., mid_0, human].
	// For depth 1: [human->leaf].
	// Keys per intermediate are generated from fresh seeds.
	var certs []DelegationCert

	switch depth {
	case 1:
		var constraints []Constraint
		if withConstraints {
			constraints = []Constraint{{
				Type:    ConstraintGeoCircle,
				Lat:     37.77,
				Lon:     -122.41,
				RadiusM: 500,
			}}
		}
		cert := DelegationCert{
			CertID: "bench-1",
			Version: ProtocolVersion,
			IssuerID: human.ID, IssuerPubKey: human.PublicKey,
			SubjectID: leaf.ID, SubjectPubKey: leaf.PublicKey,
			Scope:       []string{ScopeMeetingAttend},
			Constraints: constraints,
			IssuedAt:    issuedAt,
			ExpiresAt:   expiresAt,
		}
		if err := IssueDelegation(&cert, humanPriv); err != nil {
			b.Fatal(err)
		}
		certs = []DelegationCert{cert}
	case 2:
		mid, midPriv, _ := GenerateAgentKeypair("BenchMid", "custom")
		parent := DelegationCert{
			CertID: "bench-2-root", Version: ProtocolVersion,
			IssuerID: human.ID, IssuerPubKey: human.PublicKey,
			SubjectID: mid.ID, SubjectPubKey: mid.PublicKey,
			Scope:     []string{ScopeMeetingAttend, ScopeIdentityDelegate},
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		}
		if err := IssueDelegation(&parent, humanPriv); err != nil {
			b.Fatal(err)
		}
		child := DelegationCert{
			CertID: "bench-2-leaf", Version: ProtocolVersion,
			IssuerID: mid.ID, IssuerPubKey: mid.PublicKey,
			SubjectID: leaf.ID, SubjectPubKey: leaf.PublicKey,
			Scope:     []string{ScopeMeetingAttend},
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
		}
		if err := IssueDelegation(&child, midPriv); err != nil {
			b.Fatal(err)
		}
		certs = []DelegationCert{child, parent}
	case 3:
		mid1, mid1Priv, _ := GenerateAgentKeypair("BenchMid1", "custom")
		mid2, mid2Priv, _ := GenerateAgentKeypair("BenchMid2", "custom")
		root := DelegationCert{
			CertID: "bench-3-root", Version: ProtocolVersion,
			IssuerID: human.ID, IssuerPubKey: human.PublicKey,
			SubjectID: mid1.ID, SubjectPubKey: mid1.PublicKey,
			Scope:     []string{ScopeMeetingAttend, ScopeIdentityDelegate},
			IssuedAt:  issuedAt, ExpiresAt: expiresAt,
		}
		if err := IssueDelegation(&root, humanPriv); err != nil {
			b.Fatal(err)
		}
		mid := DelegationCert{
			CertID: "bench-3-mid", Version: ProtocolVersion,
			IssuerID: mid1.ID, IssuerPubKey: mid1.PublicKey,
			SubjectID: mid2.ID, SubjectPubKey: mid2.PublicKey,
			Scope:     []string{ScopeMeetingAttend, ScopeIdentityDelegate},
			IssuedAt:  issuedAt, ExpiresAt: expiresAt,
		}
		if err := IssueDelegation(&mid, mid1Priv); err != nil {
			b.Fatal(err)
		}
		child := DelegationCert{
			CertID: "bench-3-leaf", Version: ProtocolVersion,
			IssuerID: mid2.ID, IssuerPubKey: mid2.PublicKey,
			SubjectID: leaf.ID, SubjectPubKey: leaf.PublicKey,
			Scope:     []string{ScopeMeetingAttend},
			IssuedAt:  issuedAt, ExpiresAt: expiresAt,
		}
		if err := IssueDelegation(&child, mid2Priv); err != nil {
			b.Fatal(err)
		}
		certs = []DelegationCert{child, mid, root}
	}

	challenge, _ := GenerateChallenge()
	challengeAt := now.Unix()
	sig, err := SignChallenge(challenge, challengeAt, leafPriv)
	if err != nil {
		b.Fatal(err)
	}
	bundle := &ProofBundle{
		AgentID:      leaf.ID,
		AgentPubKey:  leaf.PublicKey,
		Delegations:  certs,
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: sig,
	}
	return bundle, now
}

func BenchmarkVerifyDepth1(b *testing.B) {
	bundle, now := benchBundle(b, 1, false)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, Now: now}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Verify(bundle, opts)
		if !r.Valid {
			b.Fatalf("verify failed: %s", r.ErrorReason)
		}
	}
}

func BenchmarkVerifyDepth2(b *testing.B) {
	bundle, now := benchBundle(b, 2, false)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, Now: now}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Verify(bundle, opts)
		if !r.Valid {
			b.Fatalf("verify failed: %s", r.ErrorReason)
		}
	}
}

func BenchmarkVerifyDepth3(b *testing.B) {
	bundle, now := benchBundle(b, 3, false)
	opts := VerifyOptions{RequiredScope: ScopeMeetingAttend, Now: now}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Verify(bundle, opts)
		if !r.Valid {
			b.Fatalf("verify failed: %s", r.ErrorReason)
		}
	}
}

func BenchmarkVerifyDepth1_WithConstraint(b *testing.B) {
	bundle, now := benchBundle(b, 1, true)
	opts := VerifyOptions{
		RequiredScope: ScopeMeetingAttend,
		Now:           now,
		Context: VerifierContext{
			CurrentLat: 37.77, CurrentLon: -122.41, HasLocation: true,
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := Verify(bundle, opts)
		if !r.Valid {
			b.Fatalf("verify failed: %s", r.ErrorReason)
		}
	}
}
