package ratify

import (
	"fmt"
	"time"
)

// VerifyStreamedTurn is the fast-path verifier for v1.1 session cert cache
// (ROADMAP 2.3). Given a previously issued SessionToken and a per-turn
// challenge signature, it:
//
//  1. Checks the SessionToken's HMAC against sessionSecret.
//  2. Checks the token is within [IssuedAt, ValidUntil] at `now`.
//  3. Verifies the challenge is fresh (within ChallengeWindowSeconds).
//  4. Verifies the hybrid challenge signature against token.AgentPubKey. The
//     signable bytes may be legacy (challenge || ts) or session/stream-bound;
//     callers pass the session_context and stream binding alongside.
//
// On success, VerifyResult.Valid=true, GrantedScope=token.GrantedScope,
// AgentID=token.AgentID, HumanID=token.HumanID. The chain is NOT
// re-verified — that's the point of the token. Callers who need fresh
// revocation semantics should evict the token when the issuer publishes a
// new revocation list or when token.ValidUntil expires.
func VerifyStreamedTurn(token *SessionToken, sessionSecret []byte, challenge []byte, challengeAt int64, challengeSig HybridSignature, sessionContext, streamID []byte, streamSeq int64, now time.Time) VerifyResult {
	if token == nil {
		return invalid("nil_session_token", "session_token must not be nil")
	}
	if err := VerifySessionToken(token, sessionSecret, now); err != nil {
		return invalid("session_token_invalid", err.Error())
	}
	// Basic structure for the streamed turn itself.
	if len(challenge) == 0 {
		return invalid("no_challenge", "streamed turn contains no challenge")
	}
	if len(sessionContext) != 0 && len(sessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("session_context must be 32 bytes, got %d", len(sessionContext)))
	}
	if len(streamID) != 0 && len(streamID) != 32 {
		return invalid("invalid_stream_id", fmt.Sprintf("stream_id must be 32 bytes, got %d", len(streamID)))
	}
	if len(streamID) != 0 && streamSeq < 1 {
		return invalid("invalid_stream_seq", fmt.Sprintf("stream_seq must be >=1, got %d", streamSeq))
	}
	// Challenge freshness — same 5-minute window as a full chain verify.
	challengeAge := now.Unix() - challengeAt
	if challengeAge < 0 || challengeAge > ChallengeWindowSeconds {
		return invalid("stale_challenge", fmt.Sprintf("challenge is %d seconds old (max %d)", challengeAge, ChallengeWindowSeconds))
	}
	// Hybrid challenge signature over the canonical signable bytes.
	signable := challengeSignBytes(challenge, challengeAt, sessionContext, streamID, streamSeq)
	if err := verifyBoth(signable, challengeSig, token.AgentPubKey); err != nil {
		return invalid("bad_challenge_sig", fmt.Sprintf("challenge signature verification failed: %v", err))
	}
	return VerifyResult{
		Valid:          true,
		HumanID:        token.HumanID,
		AgentID:        token.AgentID,
		GrantedScope:   append([]string(nil), token.GrantedScope...),
		IdentityStatus: IdentityStatusAuthorizedAgent,
	}
}
