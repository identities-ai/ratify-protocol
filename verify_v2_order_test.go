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
