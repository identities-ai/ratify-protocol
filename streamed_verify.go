package ratify

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

// StreamedTurn carries the presentation-side inputs of one streamed turn:
// the fresh challenge the agent signed and the bindings it signed it under
// (§6.4.2). It is the streamed-turn analog of the ProofBundle's challenge
// fields — presented values, distinct from the verifier-side expectations
// carried in VerifyOptions.
type StreamedTurn struct {
	// Challenge is the fresh challenge bytes for this turn.
	Challenge []byte

	// ChallengeAt is the unix timestamp the challenge was signed at.
	ChallengeAt int64

	// ChallengeSig is the agent's hybrid signature over the canonical
	// challenge signable bytes (§6.4.2).
	ChallengeSig HybridSignature

	// SessionContext is the presented session binding (empty = unbound;
	// otherwise 32 bytes). Checked against VerifyOptions.SessionContext.
	SessionContext []byte

	// StreamID / StreamSeq are the presented stream binding (StreamID
	// empty = unbound; otherwise 32 bytes with StreamSeq >= 1). Checked
	// against VerifyOptions.Stream.
	StreamID  []byte
	StreamSeq int64
}

// VerifyStreamedTurnWithOptions is the options-object form of the streamed
// fast path (§5.13): it verifies one turn against a previously issued
// SessionToken and enforces the same verifier-side controls as the full
// Verify where they apply to a token presentation.
//
// Consulted VerifyOptions fields:
//
//   - RequiredScope — must be present in token.GrantedScope, else
//     scope_denied. The token stores the effective scope sorted for
//     exactly this check.
//   - ChallengeStore — makes the per-turn challenge single-use with the
//     §10 consumption order: validated (without consuming) before any
//     signature work, atomically consumed after the challenge signature
//     verifies, before authorization. All store failures normalize to the
//     canonical unknown_challenge result.
//   - SessionContext — verifier-side session binding; turn.SessionContext
//     must match byte-for-byte (same statuses as the full verifier).
//   - Stream — verifier-side stream tracking; turn.StreamID must match
//     and turn.StreamSeq must be exactly LastSeenSeq+1 (stream_seq_replay
//     / stream_seq_skip on violation).
//   - Now — clock override; zero value uses time.Now().
//
// All other VerifyOptions fields (revocation, policy, constraints, audit,
// anchor resolution) are ignored: a streamed turn re-verifies liveness and
// bindings, not the chain — that's the point of the token. Callers who
// need fresh revocation or policy semantics run full Verify instead.
func VerifyStreamedTurnWithOptions(token *SessionToken, sessionSecret []byte, turn StreamedTurn, opts VerifyOptions) VerifyResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// --- Token authenticity and validity window ---
	if token == nil {
		return invalid("nil_session_token", "session_token must not be nil")
	}
	if err := VerifySessionToken(token, sessionSecret, now); err != nil {
		return invalid("session_token_invalid", err.Error())
	}

	// --- Basic structure ---
	if len(turn.Challenge) == 0 {
		return invalid("no_challenge", "streamed turn contains no challenge")
	}

	// --- Session context validation (mirrors §10 step 2) ---
	if len(turn.SessionContext) != 0 && len(turn.SessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("session_context must be 32 bytes, got %d", len(turn.SessionContext)))
	}
	if len(opts.SessionContext) != 0 && len(opts.SessionContext) != 32 {
		return invalid("invalid_session_context", fmt.Sprintf("verify option session_context must be 32 bytes, got %d", len(opts.SessionContext)))
	}
	if len(opts.SessionContext) != 0 {
		if len(turn.SessionContext) == 0 {
			return invalid("missing_session_context", "verifier requires a session-bound challenge but turn has no session_context")
		}
		if !bytes.Equal(turn.SessionContext, opts.SessionContext) {
			return invalid("session_context_mismatch", "turn session_context does not match verifier context")
		}
	} else if len(turn.SessionContext) != 0 {
		return invalid("session_context_unverifiable", "turn has session_context but verifier did not provide one")
	}

	// --- Single-use challenge: locate WITHOUT consuming (§10 step 2b) ---
	if opts.ChallengeStore != nil {
		if err := opts.ChallengeStore.Validate(turn.Challenge, opts.SessionContext, now); err != nil {
			return invalid("unknown_challenge", ErrUnknownChallenge.Error())
		}
	}

	// --- Stream binding validation (mirrors §10 step 3) ---
	if len(turn.StreamID) != 0 && len(turn.StreamID) != 32 {
		return invalid("invalid_stream_id", fmt.Sprintf("stream_id must be 32 bytes, got %d", len(turn.StreamID)))
	}
	if len(turn.StreamID) == 0 && turn.StreamSeq != 0 {
		return invalid("invalid_stream_seq", "stream_seq set without stream_id")
	}
	if len(turn.StreamID) != 0 && turn.StreamSeq < 1 {
		return invalid("invalid_stream_seq", fmt.Sprintf("stream_seq must be >=1, got %d", turn.StreamSeq))
	}
	if opts.Stream != nil {
		if len(opts.Stream.StreamID) != 32 {
			return invalid("invalid_stream_id", fmt.Sprintf("verify option stream_id must be 32 bytes, got %d", len(opts.Stream.StreamID)))
		}
		if len(turn.StreamID) == 0 {
			return invalid("missing_stream_context", "verifier requires a stream-bound challenge but turn has no stream_id")
		}
		if !bytes.Equal(turn.StreamID, opts.Stream.StreamID) {
			return invalid("stream_id_mismatch", "turn stream_id does not match verifier stream context")
		}
		expected := opts.Stream.LastSeenSeq + 1
		if turn.StreamSeq <= opts.Stream.LastSeenSeq {
			return invalid("stream_seq_replay", fmt.Sprintf("stream_seq %d already seen (last=%d)", turn.StreamSeq, opts.Stream.LastSeenSeq))
		}
		if turn.StreamSeq != expected {
			return invalid("stream_seq_skip", fmt.Sprintf("stream_seq %d skips expected %d", turn.StreamSeq, expected))
		}
	} else if len(turn.StreamID) != 0 {
		return invalid("stream_context_unverifiable", "turn has stream_id but verifier did not provide a stream context")
	}

	// --- Liveness (challenge freshness + hybrid signature) ---
	challengeAge := now.Unix() - turn.ChallengeAt
	if challengeAge < 0 || challengeAge > ChallengeWindowSeconds {
		return invalid("stale_challenge", fmt.Sprintf("challenge is %d seconds old (max %d)", challengeAge, ChallengeWindowSeconds))
	}
	signable := challengeSignBytes(turn.Challenge, turn.ChallengeAt, turn.SessionContext, turn.StreamID, turn.StreamSeq)
	if err := verifyBoth(signable, turn.ChallengeSig, token.AgentPubKey); err != nil {
		return invalid("bad_challenge_sig", fmt.Sprintf("challenge signature verification failed: %v", err))
	}

	// --- Single-use challenge: atomic consume (§10 step 9b) ---
	// The signature has verified, so this presentation is
	// cryptographically the agent's. Consume before the scope check so a
	// denied caller cannot probe authorization with one liveness proof.
	if opts.ChallengeStore != nil {
		if err := opts.ChallengeStore.Consume(turn.Challenge, opts.SessionContext, now); err != nil {
			return invalid("unknown_challenge", ErrUnknownChallenge.Error())
		}
	}

	// --- Required scope against the token's cached effective scope ---
	if opts.RequiredScope != "" && !slices.Contains(token.GrantedScope, opts.RequiredScope) {
		return failWithStatus(IdentityStatusScopeDenied,
			fmt.Sprintf("required scope %q not in session token granted scope", opts.RequiredScope))
	}

	return VerifyResult{
		Valid:          true,
		HumanID:        token.HumanID,
		AgentID:        token.AgentID,
		GrantedScope:   append([]string(nil), token.GrantedScope...),
		IdentityStatus: IdentityStatusAuthorizedAgent,
	}
}

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
//
// This form verifies the presentation only — it cannot enforce a required
// scope, single-use challenges, or verifier-side session/stream tracking.
// Prefer VerifyStreamedTurnWithOptions, which adds those controls through
// the same VerifyOptions used by Verify.
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
