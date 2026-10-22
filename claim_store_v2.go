package ratify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

var ErrV2ClaimProofConflict = errors.New("v2 challenge was already claimed by a different proof")

// V2ChallengeClaim is the immutable identity a verifier persists when it
// consumes a fresh challenge. A ClaimStoreV2 implementation must atomically
// enforce uniqueness on (namespace, replay_epoch, challenge_digest), store
// proof_digest and every other V2ChallengeClaim field as immutable claim
// values, and return the existing state only for an exact retry without
// starting another evaluation. A changed scope or context policy is not an
// exact retry even when the signed proof bytes are identical.
type V2ChallengeClaim struct {
	ClaimID             string
	Namespace           string
	ReplayEpoch         int64
	ChallengeDigest     string
	ProofDigest         string
	BundleHash          string
	IssuerIDs           []string
	RequiredScope       string
	ContextPolicyDigest string
	VerifierID          string
	AgentID             string
	RequiresRate        bool
	RateBatch           []V2RateReservation
	IssuedAt            int64
	ExpiresAt           int64
	MaxAgeSeconds       int64
	ClockSkewSeconds    int64
	StreamID            []byte
	StreamSeq           *int64
	// ConstraintEvaluators is the sealed extension evaluator snapshot for the
	// chain (SPEC-v2 §5.2, §6.3), sorted by type; every terminal receipt for
	// the claim, including evaluation_interrupted, carries it.
	ConstraintEvaluators []ConstraintEvaluatorRefV2
}

// V2EvaluationToken grants one local evaluation attempt for a newly created
// claim. It is single-use and is never returned for an exact retry.
type V2EvaluationToken struct {
	state *v2EvaluationTokenState
}

type v2EvaluationTokenState struct {
	claimID             string
	proofDigest         string
	requiredScope       string
	futureSkew          int64
	expected            *expectedChallengeStateV2
	used                atomic.Bool
	evaluationComplete  atomic.Bool
	finalizationMu      sync.Mutex
	finalizationDigest  [32]byte
	finalizationStarted bool
	claimTimeValid      bool
	claimedAt           int64
	evaluatedAt         int64
	rateBatch           []V2RateReservation
	rateAtFinalization  bool
	allowValidUntil     int64
	ownerToken          []byte
	evaluationStatus    string
	evaluationReason    string
	pendingAssessment   *V2LocalAuthorizationAssessment
}

type V2ClaimDisposition string

// V2ClaimResult includes the claim transaction's authoritative timestamp.
// The store, not the caller, chooses this value from its configured security clock.
type V2ClaimResult struct {
	Disposition V2ClaimDisposition
	ClaimedAt   int64
	// OwnerToken is returned only to the process that atomically created the
	// claim. Stores must persist only a one-way hash of this unpredictable value.
	OwnerToken []byte
}

const (
	V2ClaimCreated        V2ClaimDisposition = "created"
	V2ClaimInProgress     V2ClaimDisposition = "in_progress"
	V2ClaimTerminalReplay V2ClaimDisposition = "terminal_replay"
)

// ClaimStoreV2 is the storage boundary for challenge consumption. Implementors
// must make ClaimV2 atomic across processes and durable across restart, advance
// any stream sequence in the same transaction, and recheck expiry and maximum
// age using their authoritative clock inside that transaction. Retain claims
// strictly beyond expires_at plus configured clock skew. ClaimedAt must come
// from the same authoritative clock used for expiry and maximum-age checks. A
// different proof_digest or any other immutable claim field for the same
// replay key must return an error without disclosing the existing result. A
// created result includes a cryptographically
// random 32-byte owner token; the store atomically persists only its SHA-256
// digest and returns the raw token only to the winning creator. A ClaimV2 error
// can be ambiguous if the claim committed but its response was lost. Callers
// must treat that claim as possibly created, retry the exact immutable input,
// and allow expired-lease recovery to terminalize it; retries never return the
// lost owner capability. Stores must roll back when they know creation failed
// before commit.
// FinalizeV2Claim compares all token bytes against the stored digest without an
// early exit and performs a state-and-live-lease CAS. Inside that same CAS it
// reads its authoritative clock as T_final and records it with the terminal
// result (SPEC-v2 §7.2): a reading below the greatest reading the store has
// returned, or below the claim's T_claim, fails with clock_regressed; a
// non-zero allowValidUntil (an allow) commits only while T_final <
// allowValidUntil and T_final < the sealed challenge expiry, else it fails
// with allow_horizon_passed. Either failure commits nothing and leaves the
// claim evaluating. Externally anchored stores return success only after a
// confirmed barrier projects the terminal result.
// It returns true when it commits the terminal result, false when the same
// owner already committed the identical result and receipt body, and an error
// for owner mismatch, a competing terminal result, or a lost lease. The
// evaluator wrapper permits retry only with the identical result and receipt
// bytes.
// RecordV2EvaluationProgress persists the evaluator's per-dimension progress
// (V2EvaluationProgress) under the same owner token and live lease; it fails
// with claim_lease_lost or claim_already_terminal otherwise. The verifier
// records progress before every external lookup starts and after it
// completes, and never calls a provider whose start it could not record.
// LoadV2InterruptedClaim returns the sealed claim, T_claim and the last
// recorded progress for lease-expiry recovery. It fails with
// claim_lease_live while an evaluating claim's lease is live, so the progress
// it returns can no longer change. For a terminal claim it returns the same
// record, and RecoverInterruptedV2Claim then accepts only the identical
// interrupted result (idempotent recovery).
// RecoverInterruptedV2Claim returns true when it commits the canonical
// indeterminate/evaluation_interrupted result and false when that same
// interrupted result and receipt body are already committed. It errors while
// the lease is live, when an external attempt remains unresolved, when another
// terminal result won, or when either JSON
// object lacks string decision/reason fields exactly equal to
// indeterminate/evaluation_interrupted. Recovery never creates a claim or
// returns Created; ClaimV2 returns Created only to the transaction that
// inserted the row, and exact retries return InProgress until publication.
// AuthoritativeTimeV2 returns the store's security clock, the same clock that
// produced ClaimedAt. The store records the greatest reading it has returned;
// a reading below it is a clock regression (SPEC-v2 §7.2): ClaimV2 then
// creates nothing and fails with claim_store_unavailable, FinalizeV2Claim
// fails with clock_regressed, and AuthoritativeTimeV2 itself fails with
// clock_regressed, which release reports as withheld/clock_regressed.
// This interface does not make a memory-only implementation safe for production.
type ClaimStoreV2 interface {
	V2AuthoritativeClock
	ClaimV2(context.Context, V2ChallengeClaim) (V2ClaimResult, error)
	FinalizeV2Claim(ctx context.Context, claimID string, ownerToken, terminalResult, receiptBody []byte, allowValidUntil int64) (bool, error)
	RecordV2EvaluationProgress(ctx context.Context, claimID string, ownerToken []byte, progress V2EvaluationProgress) error
	LoadV2InterruptedClaim(ctx context.Context, claimID string) (V2InterruptedClaim, error)
	RecoverInterruptedV2Claim(ctx context.Context, claimID string, terminalResult, receiptBody []byte) (bool, error)
}

// V2AuthoritativeClock is a Part B authoritative security clock in integer
// seconds (0..V2MaxTimestampSeconds).
type V2AuthoritativeClock interface {
	AuthoritativeTimeV2(context.Context) (int64, error)
}

// ChallengeClaimTimeCurrentV2 reports whether an authoritative time is inside
// the claim's sealed challenge bounds using exclusive deadlines. Claim stores
// use it to recheck freshness inside the claim transaction.
func ChallengeClaimTimeCurrentV2(claim V2ChallengeClaim, now int64) bool {
	return v2ChallengeTimeCurrent(now, claim.IssuedAt, claim.ExpiresAt, claim.MaxAgeSeconds, claim.ClockSkewSeconds)
}

// V2RateAtFinalizationStore admits the sealed rate batch atomically during
// external barrier preparation. The capability must remain active for the
// claim's lifetime and must reject a claim with a legacy reservation. Its
// FinalizeV2Claim may return the exact ErrV2RateLimitExceeded sentinel only
// after definitive rollback: that preparation created no attempt, and no
// earlier attempt for the claim remains unresolved or committed. Other stores
// keep the provisional reservation stage before finalization.
type V2RateAtFinalizationStore interface {
	ClaimStoreV2
	V2RateReservationStore
	AdmitsV2RateAtFinalization()
}

// ClaimProofBundleV2 repeats the security-relevant freshness and binding
// checks immediately before invoking the atomic claim store. Callers must run
// PreflightProofBundleV2 first. No trust, status, or
// policy callback runs before this function succeeds.
func ClaimProofBundleV2(ctx context.Context, store ClaimStoreV2, bundle *ProofBundleV2, preflight *V2PreflightResult, configuredNamespace string, configuredReplayEpoch, nowUnix int64) (V2ChallengeClaim, V2ClaimDisposition, *V2EvaluationToken, error) {
	var zero V2ChallengeClaim
	if store == nil || ctx == nil {
		return zero, "", nil, fmt.Errorf("v2 claim store and context are required")
	}
	if preflight == nil || preflight.state == nil || preflight.state.ContextPolicy == nil && !preflight.state.NoContextPolicy {
		return zero, "", nil, fmt.Errorf("v2 successful preflight state is required before claim")
	}
	sealed := cloneExpectedChallengeStateV2(preflight.state)
	bundleHash, err := BundleHashV2(bundle)
	if err != nil || bundleHash != sealed.BundleHash {
		return zero, "", nil, fmt.Errorf("v2 proof bundle differs from successful preflight")
	}
	expected := ExpectedChallengeV2{Value: sealed.Value, IssuedAt: sealed.IssuedAt, ExpiresAt: sealed.ExpiresAt,
		VerifierNamespace: sealed.VerifierNamespace, ReplayEpoch: sealed.ReplayEpoch, VerifierID: sealed.VerifierID,
		ExpectedAgentID: sealed.ExpectedAgentID, ExpectedAgentPublicKey: sealed.ExpectedAgentPublicKey,
		ExpectedReceiverID: sealed.ExpectedReceiverID, ExpectedSessionContext: sealed.ExpectedSessionContext,
		ContextPolicy: sealed.ContextPolicy}
	if err := ValidateProofBundleV2Preflight(bundle, expected, sealed.RequiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, sealed.MaxAge, sealed.FutureSkew); err != nil {
		return zero, "", nil, fmt.Errorf("v2 claim-time preflight: %w", err)
	}
	requiredScope, maxAgeSeconds, futureSkewSeconds := sealed.RequiredScope, sealed.MaxAge, sealed.FutureSkew
	challengeDigest, err := ChallengeClaimDigestV2(sealed.Value)
	if err != nil {
		return zero, "", nil, err
	}
	claimID, err := ProtocolClaimIDV2(sealed.VerifierNamespace, sealed.ReplayEpoch, sealed.Value)
	if err != nil {
		return zero, "", nil, err
	}
	var streamID []byte
	if bundle.StreamID != nil {
		streamID = append([]byte(nil), (*bundle.StreamID)...)
	}
	var streamSeq *int64
	if bundle.StreamSeq != nil {
		seq := *bundle.StreamSeq
		streamSeq = &seq
	}
	claim := V2ChallengeClaim{
		ClaimID: claimID, Namespace: sealed.VerifierNamespace, ReplayEpoch: sealed.ReplayEpoch,
		ChallengeDigest: fmt.Sprintf("sha384:%x", challengeDigest), ProofDigest: bundleHash,
		BundleHash:    sealed.BundleHash,
		IssuerIDs:     append([]string{}, sealed.IssuerIDs...),
		RequiredScope: requiredScope, ContextPolicyDigest: sealed.ContextPolicyDigest,
		VerifierID: sealed.VerifierID, AgentID: bundle.AgentID,
		IssuedAt: sealed.IssuedAt, ExpiresAt: sealed.ExpiresAt,
		MaxAgeSeconds: maxAgeSeconds, ClockSkewSeconds: futureSkewSeconds,
		StreamID: streamID, StreamSeq: streamSeq,
		ConstraintEvaluators: cloneConstraintEvaluatorRefsV2(sealed.EvaluatorRefs),
	}
	claim.RateBatch, err = signedV2RateReservationBatch(bundle)
	if err != nil {
		return zero, "", nil, v2Classify(V2ErrMalformed, fmt.Errorf("v2 signed rate batch: %w", err))
	}
	claim.RequiresRate = len(claim.RateBatch) != 0
	result, err := store.ClaimV2(ctx, cloneV2ChallengeClaim(claim))
	if err != nil {
		return zero, "", nil, err
	}
	switch result.Disposition {
	case V2ClaimCreated:
		if len(result.OwnerToken) != 32 {
			return zero, "", nil, fmt.Errorf("v2 claim store returned an invalid evaluator owner token")
		}
		// The store's authoritative claim time must itself satisfy the
		// exclusive challenge deadlines; otherwise evaluation is interrupted.
		claimTimeValid := v2ChallengeTimeCurrent(result.ClaimedAt, sealed.IssuedAt, sealed.ExpiresAt, maxAgeSeconds, futureSkewSeconds)
		return claim, result.Disposition, &V2EvaluationToken{state: &v2EvaluationTokenState{
			claimID: claim.ClaimID, proofDigest: claim.ProofDigest,
			rateBatch:     append([]V2RateReservation{}, claim.RateBatch...),
			requiredScope: requiredScope, futureSkew: futureSkewSeconds,
			ownerToken:     append([]byte(nil), result.OwnerToken...),
			claimedAt:      result.ClaimedAt,
			claimTimeValid: claimTimeValid,
			expected:       sealed,
		}}, nil
	case V2ClaimInProgress, V2ClaimTerminalReplay:
		if len(result.OwnerToken) != 0 {
			return zero, "", nil, fmt.Errorf("v2 exact retry must not receive evaluator ownership")
		}
		return claim, result.Disposition, nil, nil
	default:
		return zero, "", nil, fmt.Errorf("v2 claim store returned an invalid disposition")
	}
}

func cloneV2ChallengeClaim(claim V2ChallengeClaim) V2ChallengeClaim {
	claim.IssuerIDs = append([]string{}, claim.IssuerIDs...)
	claim.RateBatch = append([]V2RateReservation{}, claim.RateBatch...)
	claim.StreamID = bytes.Clone(claim.StreamID)
	if claim.StreamSeq != nil {
		sequence := *claim.StreamSeq
		claim.StreamSeq = &sequence
	}
	claim.ConstraintEvaluators = cloneConstraintEvaluatorRefsV2(claim.ConstraintEvaluators)
	return claim
}

// FinalizeClaimProofBundleV2 commits a terminal local evaluation through the
// same opaque capability that won the atomic claim. Results that still need
// status or rate-limit checks cannot be finalized by this helper. An ambiguous
// store failure can be retried only with the identical result and receipt.
// A barrier store's exact rate-capacity exhaustion error is the sole exception:
// it proves rollback, changes the token to constraint_denied, and requires a
// new deny result and receipt; an earlier authorized assessment is then stale.
func FinalizeClaimProofBundleV2(ctx context.Context, store ClaimStoreV2, token *V2EvaluationToken, terminalResult, receiptBody []byte) (bool, error) {
	if ctx == nil || store == nil || token == nil || token.state == nil || len(token.state.ownerToken) != 32 || token.state.claimID == "" {
		return false, fmt.Errorf("v2 claim store and valid evaluator capability are required")
	}
	terminalResult = bytes.Clone(terminalResult)
	receiptBody = bytes.Clone(receiptBody)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	token.state.finalizationMu.Lock()
	defer token.state.finalizationMu.Unlock()
	if !token.state.evaluationComplete.Load() {
		return false, fmt.Errorf("v2 proof evaluation has not completed")
	}
	decision, ok := terminalDecisionForV2Evaluation(token.state.evaluationStatus, token.state.evaluationReason)
	if !ok {
		return false, fmt.Errorf("v2 proof evaluation has not reached a terminal local result")
	}
	if !terminalPayloadMatchesV2(terminalResult, receiptBody, decision, token.state.evaluationReason) {
		return false, fmt.Errorf("v2 terminal result does not match the completed local evaluation")
	}
	if decision == "allow" && token.state.allowValidUntil <= 0 || decision != "allow" && token.state.allowValidUntil != 0 {
		return false, fmt.Errorf("v2 terminal result lacks a valid allow freshness horizon")
	}
	if token.state.rateAtFinalization {
		if _, ok := store.(V2RateAtFinalizationStore); !ok {
			return false, fmt.Errorf("v2 rate-at-finalization requires an atomic rate store")
		}
	}
	payloadDigest := v2FinalizationPayloadDigest(terminalResult, receiptBody)
	if token.state.finalizationStarted && token.state.finalizationDigest != payloadDigest {
		return false, fmt.Errorf("v2 evaluator capability cannot change its terminal result or receipt body")
	}
	token.state.finalizationStarted = true
	token.state.finalizationDigest = payloadDigest
	finalized, err := store.FinalizeV2Claim(ctx, token.state.claimID, append([]byte(nil), token.state.ownerToken...), terminalResult, receiptBody, token.state.allowValidUntil)
	if !finalized && token.state.rateAtFinalization && decision == "allow" && err == ErrV2RateLimitExceeded {
		if _, ok := store.(V2RateAtFinalizationStore); ok {
			token.state.evaluationStatus, token.state.evaluationReason = "constraint_denied", "constraint_denied"
			token.state.allowValidUntil = 0
			token.state.rateAtFinalization = false
			token.state.finalizationStarted = false
			token.state.finalizationDigest = [32]byte{}
		}
	}
	return finalized, err
}

func terminalDecisionForV2Evaluation(status, reason string) (string, bool) {
	if reason == "evaluation_interrupted" {
		return "indeterminate", status == "authorization_unverified"
	}
	switch status {
	case "authorization_unverified":
		return "indeterminate", reason == "trust_unavailable" || reason == "action_context_unverified" || reason == "status_unavailable" || reason == "status_stale"
	case "authorized_agent":
		return "allow", reason == "authorized"
	case "constraint_denied", "constraint_unverifiable", "constraint_unknown", "unauthorized", "invalid_scope", "scope_denied":
		return "deny", reason == status
	case "revoked":
		return "deny", reason == "delegation_revoked"
	case "invalid":
		return "deny", reason == "proof_invalid"
	case "delegation_not_authorized":
		return "deny", reason == "not_delegated" || reason == "delegation_not_authorized"
	case "expired":
		return "deny", reason == "delegation_expired"
	default:
		return "", false
	}
}

func terminalPayloadMatchesV2(terminalResult, receiptBody []byte, wantDecision, wantReason string) bool {
	read := func(value []byte) (string, string, bool) {
		if !utf8.Valid(value) {
			return "", "", false
		}
		decoder := json.NewDecoder(bytes.NewReader(value))
		root, err := decoder.Token()
		if err != nil || root != json.Delim('{') || validateUniqueJSONObjectV2(decoder) != nil {
			return "", "", false
		}
		if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
			return "", "", false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil || fields == nil {
			return "", "", false
		}
		var decision, reason string
		if json.Unmarshal(fields["decision"], &decision) != nil || json.Unmarshal(fields["decision_reason"], &reason) != nil {
			return "", "", false
		}
		return decision, reason, true
	}
	resultDecision, resultReason, resultOK := read(terminalResult)
	bodyDecision, bodyReason, bodyOK := read(receiptBody)
	return resultOK && bodyOK && resultDecision == wantDecision && bodyDecision == wantDecision && resultReason == wantReason && bodyReason == wantReason
}

// validateUniqueJSONObjectV2 consumes a root object whose opening delimiter
// has already been read, rejecting duplicate keys at every nesting level.
func validateUniqueJSONObjectV2(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("JSON object key is not a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON object key %q", key)
		}
		seen[key] = struct{}{}
		if err := validateUniqueJSONValueV2(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return fmt.Errorf("invalid JSON object ending")
	}
	return nil
}

func validateUniqueJSONValueV2(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return validateUniqueJSONObjectV2(decoder)
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValueV2(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array ending")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func v2FinalizationPayloadDigest(terminalResult, receiptBody []byte) [32]byte {
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(terminalResult)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(terminalResult)
	binary.BigEndian.PutUint64(length[:], uint64(len(receiptBody)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(receiptBody)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}
