package ratify

import (
	"context"
	"testing"
)

// SPEC-v2 §6.2: bounded strict decode (step 1) precedes the configuration
// and request-context checks (step 2), so a request that is both malformed
// and misconfigured reports malformed.
func TestVerifyProofBundleV2DecodeFailurePrecedesConfiguration(t *testing.T) {
	req := V2VerifyRequest{Bundle: []byte("{"), Now: -1, MaxChallengeAgeSeconds: 0, FutureSkewSeconds: 999}
	outcome, err := VerifyProofBundleV2(context.Background(), req, V2VerifyCallbacks{ClaimStore: &recordingClaimStoreV2{}})
	if err != nil || outcome.Stage != V2StagePreflight || outcome.ErrorClass != V2ErrMalformed {
		t.Fatalf("stage %s class %s err %v", outcome.Stage, outcome.ErrorClass, err)
	}
	bundle := signedV2TestBundle(t)
	wire, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	req.Bundle = wire
	outcome, _ = VerifyProofBundleV2(context.Background(), req, V2VerifyCallbacks{ClaimStore: &recordingClaimStoreV2{}})
	if outcome.ErrorClass != V2ErrConfigurationInvalid {
		t.Fatalf("well-formed bundle with invalid configuration: %s", outcome.ErrorClass)
	}
}

// SPEC-v2 §2.5, §6.1 and §6.2 step 2: configuration that is out of bounds or
// internally inconsistent is configuration_invalid before any later
// pre-claim step and before the claim store is consulted.
func TestVerifyProofBundleV2ConfigurationRejectedAtStepTwo(t *testing.T) {
	bundle := signedV2TestBundle(t)
	wire, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	base := func() V2VerifyRequest {
		return V2VerifyRequest{Bundle: wire, Now: 1800000000, MaxChallengeAgeSeconds: 60, FutureSkewSeconds: 5, VerifierNamespace: "ns", VerifierID: bundle.VerifierID,
			StatusPolicy: RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5}}
	}
	cases := []struct {
		name string
		edit func(*V2VerifyRequest)
	}{
		// Without the fault each request stops later (expected challenge
		// missing, or an invalid required scope), so the class proves where
		// the check runs.
		{"status skew below future skew", func(r *V2VerifyRequest) { r.StatusPolicy.ClockSkewSeconds = 0 }},
		{"status skew above future skew", func(r *V2VerifyRequest) { r.FutureSkewSeconds = 0 }},
		{"replay epoch above 2^53-1", func(r *V2VerifyRequest) { r.ReplayEpoch = 1 << 53 }},
		{"replay epoch negative", func(r *V2VerifyRequest) { r.ReplayEpoch = -1 }},
		{"31-byte expected session context without a policy", func(r *V2VerifyRequest) {
			r.Expected = &ExpectedChallengeV2{ExpectedSessionContext: make([]byte, 31)}
		}},
		{"empty expected session context without a policy", func(r *V2VerifyRequest) {
			r.Expected = &ExpectedChallengeV2{ExpectedSessionContext: []byte{}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := base()
			c.edit(&req)
			store := &recordingClaimStoreV2{}
			outcome, err := VerifyProofBundleV2(context.Background(), req, V2VerifyCallbacks{ClaimStore: store})
			if err != nil || outcome.Stage != V2StagePreflight || outcome.ErrorClass != V2ErrConfigurationInvalid || store.calls != 0 {
				t.Fatalf("stage %s class %s err %v claims %d", outcome.Stage, outcome.ErrorClass, err, store.calls)
			}
		})
	}
}

// The standalone preflight entry points apply the same §6.2 step 2 bound on
// the configured replay epoch as VerifyProofBundleV2, so a caller that runs
// preflight itself sees configuration_invalid, not stale_replay_epoch.
func TestValidateProofBundleV2PreflightReplayEpochBound(t *testing.T) {
	bundle := signedV2TestBundle(t)
	for _, epoch := range []int64{-1, 1 << 53} {
		err := ValidateProofBundleV2Preflight(bundle, ExpectedChallengeV2{ReplayEpoch: epoch}, "data:read", "ns", epoch, bundle.VerifierID, 1800000000, 60, 5)
		if V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Fatalf("epoch %d: %v", epoch, err)
		}
	}
}
