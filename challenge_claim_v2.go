package ratify

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

// ChallengeClaimDigestV2 returns the replay key digest for one decoded
// 32-byte challenge. It is independent of the proof bundle so a different
// signed proof cannot claim the same challenge a second time.
func ChallengeClaimDigestV2(challenge []byte) ([]byte, error) {
	if len(challenge) != 32 {
		return nil, fmt.Errorf("v2 challenge claim requires exactly 32 challenge bytes")
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-challenge-claim-v2\x00"))
	h.Write(challenge)
	return h.Sum(nil), nil
}

// ProtocolClaimIDV2 returns the stable identifier for a challenge claim in a
// locally configured replay namespace and epoch. It does not implement claim
// storage, freshness checks, or atomicity.
func ProtocolClaimIDV2(verifierNamespace string, replayEpoch int64, challenge []byte) (string, error) {
	if verifierNamespace == "" || !utf8.ValidString(verifierNamespace) {
		return "", fmt.Errorf("v2 verifier namespace must be non-empty valid UTF-8")
	}
	if replayEpoch < 0 || replayEpoch > maxSafeInteger {
		return "", fmt.Errorf("v2 replay epoch is outside the safe integer range")
	}
	claimDigest, err := ChallengeClaimDigestV2(challenge)
	if err != nil {
		return "", err
	}
	return ProtocolClaimIDFromDigestV2(verifierNamespace, replayEpoch, claimDigest)
}

// ProtocolClaimIDFromDigestV2 returns the stable claim identifier when the
// caller already has the canonical 48-byte ChallengeClaimDigestV2 value.
func ProtocolClaimIDFromDigestV2(verifierNamespace string, replayEpoch int64, claimDigest []byte) (string, error) {
	if verifierNamespace == "" || !utf8.ValidString(verifierNamespace) {
		return "", fmt.Errorf("v2 verifier namespace must be non-empty valid UTF-8")
	}
	if replayEpoch < 0 || replayEpoch > maxSafeInteger {
		return "", fmt.Errorf("v2 replay epoch is outside the safe integer range")
	}
	if len(claimDigest) != 48 {
		return "", fmt.Errorf("v2 challenge claim digest must be exactly 48 bytes")
	}
	h := sha256.New()
	h.Write([]byte("ratify-protocol-claim-id-v2\x00"))
	h.Write(uint64Bytes(uint64(len([]byte(verifierNamespace)))))
	h.Write([]byte(verifierNamespace))
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(replayEpoch))
	h.Write(epoch[:])
	h.Write(claimDigest)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func uint64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}
