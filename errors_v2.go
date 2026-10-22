package ratify

import (
	"errors"
	"fmt"
)

// V2ErrorClass is a language-neutral failure class shared by the Protocol v2
// conformance corpus. Messages are diagnostic only; conformance compares
// classes. A class never changes Protocol behavior by itself.
type V2ErrorClass string

const (
	V2ErrUnclassified V2ErrorClass = "unclassified"

	// Wire and structure.
	V2ErrMalformed                V2ErrorClass = "malformed"
	V2ErrUnsupportedObjectType    V2ErrorClass = "unsupported_object_type"
	V2ErrKeyIDMismatch            V2ErrorClass = "key_id_mismatch"
	V2ErrDelegationDigestMismatch V2ErrorClass = "delegation_digest_mismatch"
	V2ErrChainLinkageMismatch     V2ErrorClass = "chain_linkage_mismatch"
	V2ErrDuplicateCertificateRef  V2ErrorClass = "duplicate_certificate_ref"
	V2ErrInvalidSignature         V2ErrorClass = "invalid_signature"
	V2ErrInvalidRequiredScope     V2ErrorClass = "invalid_required_scope"

	// Challenge preflight and pure receiver binding.
	V2ErrConfigurationInvalid       V2ErrorClass = "configuration_invalid"
	V2ErrExpectedChallengeMissing   V2ErrorClass = "expected_challenge_unavailable"
	V2ErrNamespaceMismatch          V2ErrorClass = "namespace_mismatch"
	V2ErrStaleReplayEpoch           V2ErrorClass = "stale_replay_epoch"
	V2ErrVerifierIDMismatch         V2ErrorClass = "verifier_id_mismatch"
	V2ErrChallengeMismatch          V2ErrorClass = "challenge_mismatch"
	V2ErrChallengeNotFresh          V2ErrorClass = "challenge_not_fresh"
	V2ErrExpectedAgentMismatch      V2ErrorClass = "expected_agent_mismatch"
	V2ErrSessionContextMismatch     V2ErrorClass = "session_context_mismatch"
	V2ErrReceiverAudienceRequired   V2ErrorClass = "receiver_audience_required"
	V2ErrReceiverAudienceMismatch   V2ErrorClass = "receiver_audience_mismatch"
	V2ErrReceiverBindingRejected    V2ErrorClass = "receiver_binding_rejected"
	V2ErrClaimReplay                V2ErrorClass = "claim_replay"
	V2ErrClaimStoreUnavailable      V2ErrorClass = "claim_store_unavailable"
	V2ErrStatusKeyBindingMismatch   V2ErrorClass = "status_key_binding_mismatch"
	V2ErrReceiptBundleMismatch      V2ErrorClass = "receipt_bundle_mismatch"
	V2ErrBundleHashMismatch         V2ErrorClass = "bundle_hash_mismatch"
	V2ErrTransactionPartyMismatch   V2ErrorClass = "transaction_party_mismatch"
	V2ErrTransactionContextMismatch V2ErrorClass = "transaction_context_mismatch"
	V2ErrTransactionSignatureSetBad V2ErrorClass = "transaction_signature_set_invalid"
	V2ErrRotationStateMismatch      V2ErrorClass = "rotation_state_mismatch"
	V2ErrRotationKeyReused          V2ErrorClass = "rotation_key_reused"
	V2ErrRotationFutureDated        V2ErrorClass = "rotation_future_dated"
	V2ErrRotationFork               V2ErrorClass = "rotation_fork"
	V2ErrRotationFrozen             V2ErrorClass = "rotation_frozen"
	V2ErrRotationRecoveryInvalid    V2ErrorClass = "rotation_recovery_invalid"
	V2ErrLogStateMismatch           V2ErrorClass = "log_state_mismatch"
	V2ErrLogGap                     V2ErrorClass = "log_gap"
	V2ErrLogOrphan                  V2ErrorClass = "log_orphan"
	V2ErrLogFork                    V2ErrorClass = "log_fork"
	V2ErrLogFrozen                  V2ErrorClass = "log_frozen"
	V2ErrStatusObjectRejected       V2ErrorClass = "status_object_rejected"

	// Part B stream sequence (SPEC-v2 §7.4): gap, duplicate and reorder all
	// fail before claim with this one class.
	V2ErrStreamSequenceMismatch V2ErrorClass = "stream_sequence_mismatch"

	// V2ErrClockRegressed: an authoritative clock reading below the
	// store's high-water mark or below T_claim (SPEC-v2 §7.2).
	V2ErrClockRegressed V2ErrorClass = "clock_regressed"
	// V2ErrEvaluationCancelled: the caller's context ended after the claim;
	// nothing was committed and the claim remains recoverable.
	V2ErrEvaluationCancelled V2ErrorClass = "evaluation_cancelled"

	// Part B claim lifecycle.
	V2ErrClaimLeaseLive       V2ErrorClass = "claim_lease_live"
	V2ErrClaimLeaseLost       V2ErrorClass = "claim_lease_lost"
	V2ErrClaimAlreadyTerminal V2ErrorClass = "claim_already_terminal"
	V2ErrClaimNotFound        V2ErrorClass = "claim_not_found"
	// V2ErrReceiptAbandoned: an exact retry of a claim whose receipt was
	// abandoned (SPEC-v2 §7.7); a fresh challenge is required.
	V2ErrReceiptAbandoned V2ErrorClass = "receipt_abandoned"

	// An allow reached finalization at or after its allow horizon or the
	// challenge expiry; nothing was committed (SPEC-v2 §7.2, §7.5).
	V2ErrAllowHorizonPassed V2ErrorClass = "allow_horizon_passed"
)

// V2Error attaches a conformance class to a diagnostic error. Error returns
// the wrapped message unchanged so existing diagnostics remain stable.
type V2Error struct {
	Class V2ErrorClass
	Err   error
}

func (e *V2Error) Error() string { return e.Err.Error() }
func (e *V2Error) Unwrap() error { return e.Err }

func v2Errorf(class V2ErrorClass, format string, args ...any) error {
	return &V2Error{Class: class, Err: fmt.Errorf(format, args...)}
}

func v2Classify(class V2ErrorClass, err error) error {
	if err == nil {
		return nil
	}
	var classified *V2Error
	if errors.As(err, &classified) {
		return err
	}
	return &V2Error{Class: class, Err: err}
}

// V2ErrorClassOf returns the conformance class of err. Errors that were not
// classified by this package return V2ErrUnclassified so conformance tests fail
// loudly instead of guessing.
func V2ErrorClassOf(err error) V2ErrorClass {
	if err == nil {
		return ""
	}
	var classified *V2Error
	if errors.As(err, &classified) {
		return classified.Class
	}
	switch {
	case errors.Is(err, ErrWitnessLogFork):
		return V2ErrLogFork
	case errors.Is(err, ErrWitnessLogGap):
		return V2ErrLogGap
	case errors.Is(err, ErrWitnessLogOrphan):
		return V2ErrLogOrphan
	case errors.Is(err, ErrWitnessLogFrozen):
		return V2ErrLogFrozen
	case errors.Is(err, ErrV2ClaimProofConflict):
		return V2ErrClaimReplay
	case errors.Is(err, ErrKeyRotationForkV2):
		return V2ErrRotationFork
	case errors.Is(err, ErrKeyRotationFrozenV2):
		return V2ErrRotationFrozen
	}
	return V2ErrUnclassified
}
