package v2reference

import (
	"crypto/sha512"
	"encoding/hex"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// KeyedClaimForTest gives a hand-built test claim the challenge digest of
// label (when it has none) and the claim ID derived from its replay key, as
// the store requires (SPEC-v2 §7.3).
func KeyedClaimForTest(label string, c ratify.V2ChallengeClaim) ratify.V2ChallengeClaim {
	if c.ChallengeDigest == "" {
		sum := sha512.Sum384([]byte(label))
		c.ChallengeDigest = "sha384:" + hex.EncodeToString(sum[:])
	}
	digest, err := hex.DecodeString(c.ChallengeDigest[len("sha384:"):])
	if err != nil {
		panic(err)
	}
	if c.ClaimID, err = ratify.ProtocolClaimIDFromDigestV2(c.Namespace, c.ReplayEpoch, digest); err != nil {
		panic(err)
	}
	return c
}
