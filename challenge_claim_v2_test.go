package ratify

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestChallengeClaimV2KnownAnswer(t *testing.T) {
	var fixture struct {
		ChallengeHex   string `json:"challenge_hex"`
		ExpectedDigest string `json:"expected_challenge_claim_digest_hex"`
		ClaimInput     struct {
			Namespace   string `json:"verifier_namespace"`
			ReplayEpoch int64  `json:"replay_epoch"`
		} `json:"claim_id_input"`
		ExpectedClaimID        string `json:"expected_claim_id"`
		AdditionalClaimIDCases []struct {
			Namespace       string `json:"verifier_namespace"`
			ReplayEpoch     int64  `json:"replay_epoch"`
			ExpectedClaimID string `json:"expected_claim_id"`
		} `json:"additional_claim_id_cases"`
	}
	data, err := os.ReadFile("testvectors/v2/challenge-claim.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	challenge, err := hex.DecodeString(fixture.ChallengeHex)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ChallengeClaimDigestV2(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest); got != fixture.ExpectedDigest {
		t.Fatalf("challenge claim digest = %s, want %s", got, fixture.ExpectedDigest)
	}
	claimID, err := ProtocolClaimIDV2(fixture.ClaimInput.Namespace, fixture.ClaimInput.ReplayEpoch, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if claimID != fixture.ExpectedClaimID {
		t.Fatalf("claim ID = %s, want %s", claimID, fixture.ExpectedClaimID)
	}
	fromDigest, err := ProtocolClaimIDFromDigestV2(fixture.ClaimInput.Namespace, fixture.ClaimInput.ReplayEpoch, digest)
	if err != nil || fromDigest != claimID {
		t.Fatalf("claim ID from canonical digest = %s, err=%v, want %s", fromDigest, err, claimID)
	}
	if _, err := ProtocolClaimIDFromDigestV2(fixture.ClaimInput.Namespace, fixture.ClaimInput.ReplayEpoch, digest[:47]); err == nil {
		t.Fatal("accepted a truncated challenge claim digest")
	}
	for _, test := range fixture.AdditionalClaimIDCases {
		got, err := ProtocolClaimIDV2(test.Namespace, test.ReplayEpoch, challenge)
		if err != nil || got != test.ExpectedClaimID {
			t.Fatalf("claim ID for %q at epoch %d = %s, err=%v, want %s", test.Namespace, test.ReplayEpoch, got, err, test.ExpectedClaimID)
		}
	}
}

func TestProtocolClaimIDV2SeparatesNamespaceAndEpoch(t *testing.T) {
	challenge := make([]byte, 32)
	base, err := ProtocolClaimIDV2("tenant-a", 0, challenge)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		namespace string
		epoch     int64
	}{
		{name: "namespace", namespace: "tenant-b", epoch: 0},
		{name: "epoch", namespace: "tenant-a", epoch: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ProtocolClaimIDV2(test.namespace, test.epoch, challenge)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatalf("claim ID did not bind %s", test.name)
			}
		})
	}
}

func TestChallengeClaimV2RejectsInvalidInputs(t *testing.T) {
	if _, err := ChallengeClaimDigestV2(make([]byte, 31)); err == nil {
		t.Fatal("accepted a challenge with the wrong length")
	}
	for _, test := range []struct {
		name      string
		namespace string
		epoch     int64
	}{
		{name: "empty namespace", namespace: "", epoch: 0},
		{name: "negative epoch", namespace: "test", epoch: -1},
		{name: "unsafe epoch", namespace: "test", epoch: maxSafeInteger + 1},
		{name: "invalid utf8 namespace", namespace: string([]byte{0xff}), epoch: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ProtocolClaimIDV2(test.namespace, test.epoch, make([]byte, 32)); err == nil {
				t.Fatal("accepted invalid claim ID input")
			}
		})
	}
}
