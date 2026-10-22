package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"sort"
)

// RevocationStatusPolicyV2 contains finite freshness bounds for one verifier
// deployment. A zero maximum means that the corresponding bound is not
// configured; status can then never be reported as current.
type RevocationStatusPolicyV2 struct {
	MaxListLifetimeSeconds int64
	MaxStatusAgeSeconds    int64
	ClockSkewSeconds       int64
}

// RevocationObservationV2 records authenticated status evidence. EvidenceDigest
// includes the signature; BodyDigest excludes it and is used to detect
// same-sequence semantic conflicts despite randomized signatures.
type RevocationObservationV2 struct {
	ObjectType       uint16   `json:"object_type"`
	StatusKeyEpoch   uint64   `json:"status_key_epoch"`
	StatusKeyID      string   `json:"status_key_id"`
	Sequence         int64    `json:"sequence"`
	EvidenceDigest   []byte   `json:"evidence_digest"`
	BodyDigest       []byte   `json:"body_digest"`
	RevokedSetDigest []byte   `json:"revoked_set_digest"`
	RevokedCertIDs   []string `json:"revoked_cert_ids"`
	FutureDated      bool     `json:"future_dated"`
	Fork             bool     `json:"fork"`
	Gap              bool     `json:"gap"`
	Accepted         bool     `json:"accepted"`
}

type RevocationStatusResultV2 struct {
	Status     string                  `json:"status"`
	Reason     string                  `json:"reason,omitempty"`
	Evidence   []StatusEvidenceEntryV2 `json:"evidence"`
	FreshUntil int64                   `json:"fresh_until,omitempty"`
}

type StatusEvidenceEntryV2 struct {
	IssuerID    string `json:"issuer_id"`
	StatusKeyID string `json:"status_key_id"`
	Sequence    int64  `json:"sequence"`
	ObjectType  uint16 `json:"object_type_code"`
	Digest      string `json:"digest"`
}

// TransitionRevocationStatusEpochV2 applies an already-authenticated trust
// configuration transition. It preserves issuer-wide denials and prior
// authenticated evidence, while making old accepted state unusable.
func TransitionRevocationStatusEpochV2(state RevocationStatusStateV2, issuerID string, nextEpoch uint64, nextStatusKey HybridPublicKey) (_ RevocationStatusStateV2, err error) {
	defer func() { err = v2Classify(V2ErrConfigurationInvalid, err) }()
	if issuerID == "" || nextEpoch == 0 || nextEpoch > uint64(maxSafeInteger) {
		return state, fmt.Errorf("status-key epoch transition has invalid issuer or epoch")
	}
	if state.IssuerID != issuerID || state.StatusKeyEpoch == 0 || state.StatusKeyEpoch >= uint64(maxSafeInteger) || nextEpoch != state.StatusKeyEpoch+1 {
		return state, fmt.Errorf("status-key epoch transition must advance exactly one configured issuer epoch")
	}
	if err := validateStatusStateBindingV2(state, issuerID, state.StatusKeyEpoch); err != nil {
		return state, fmt.Errorf("cannot transition malformed status state: %w", err)
	}
	if err := validateAcceptedStatusStateV2(state); err != nil {
		return state, fmt.Errorf("cannot transition invalid accepted status state: %w", err)
	}
	statusKeyID, err := keyIDV2(nextStatusKey)
	if err != nil {
		return state, err
	}
	if statusKeyID == state.StatusKeyID || containsAllStringSetV2(state.RetiredStatusKeyIDs, []string{statusKeyID}) {
		return state, fmt.Errorf("status-key epoch transition cannot reuse a current or retired status key")
	}
	next, err := cloneRevocationStatusStateV2(state)
	if err != nil {
		return state, err
	}
	next.RetiredStatusKeyIDs = sortedUniqueStringsV2(append(next.RetiredStatusKeyIDs, state.StatusKeyID))
	next.StatusKeyEpoch = nextEpoch
	next.StatusKeyID = statusKeyID
	next.HasFloor = false
	next.Floor = 0
	next.AcceptedSnapshot = nil
	next.AcceptedCertIDs = []string{}
	next.HasPrecedingCheckpoint = false
	next.PrecedingFloor = 0
	next.PrecedingAcceptedCertIDs = []string{}
	next.MaxObservedSequence = 0
	next.ForkSequence = 0
	// There is no current-epoch accepted state yet, so the result is unavailable
	// without carrying stale reconciliation flags across the trust transition.
	next.ReconciliationRequired = false
	next.FutureDatedObjectObserved = false
	return next, nil
}

// RevocationStatusForCertV2 derives a fail-closed answer and its deterministic
// authenticated evidence from one issuer's rollback-protected reducer state.
func RevocationStatusForCertV2(state RevocationStatusStateV2, issuerID, certID string, statusKeyEpoch uint64, statusKey HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (RevocationStatusResultV2, error) {
	unavailable := RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
	if err := validateRevocationStatusPolicyV2(policy); err != nil {
		return unavailable, err
	}
	if err := validateStatusStateBindingV2(state, issuerID, statusKeyEpoch); err != nil {
		return unavailable, err
	}
	if err := validateAcceptedStatusStateV2(state); err != nil {
		return unavailable, err
	}
	if certID == "" || !validV2Timestamp(now) {
		return unavailable, fmt.Errorf("status query has invalid certificate ID or time")
	}
	statusKeyID, err := keyIDV2(statusKey)
	if err != nil {
		return unavailable, err
	}
	if state.IssuerID != issuerID || state.StatusKeyEpoch != statusKeyEpoch || state.StatusKeyID != statusKeyID {
		return unavailable, fmt.Errorf("status query does not match the configured issuer status-key binding")
	}
	if state.AcceptedSnapshot != nil {
		if err := VerifyRevocationListV2Signature(state.AcceptedSnapshot, issuerID, statusKey); err != nil {
			return unavailable, fmt.Errorf("accepted status snapshot signature is invalid: %w", err)
		}
	}
	result := RevocationStatusResultV2{Evidence: []StatusEvidenceEntryV2{}}
	if containsAllStringSetV2(state.DenyUnionCertIDs, []string{certID}) {
		result.Status = "revoked"
		result.Evidence = acceptedStatusEvidenceV2(state, issuerID, statusKeyID)
		result.Evidence = statusEvidenceForV2(state, result.Evidence, issuerID, statusKeyID, func(o RevocationObservationV2) bool {
			return containsAllStringSetV2(o.RevokedCertIDs, []string{certID})
		})
		return result, nil
	}
	if !state.HasFloor || state.AcceptedSnapshot == nil || policy.MaxListLifetimeSeconds == 0 || policy.MaxStatusAgeSeconds == 0 || state.FutureDatedObjectObserved || state.ReconciliationRequired || state.Floor < state.MaxObservedSequence || !containsAllStringSetV2(state.AcceptedCertIDs, state.DenyUnionCertIDs) {
		result.Status, result.Reason = "indeterminate", "unavailable"
		result.Evidence = unavailableStatusEvidenceV2(state, issuerID, statusKeyID)
		return result, nil
	}
	if !revocationListFreshV2(state.AcceptedSnapshot, policy, now) {
		result.Status, result.Reason = "indeterminate", "stale"
		result.Evidence = acceptedStatusEvidenceV2(state, issuerID, statusKeyID)
		return result, nil
	}
	result.Status = "not_revoked"
	result.Evidence = acceptedStatusEvidenceV2(state, issuerID, statusKeyID)
	result.FreshUntil = min(state.AcceptedSnapshot.NextUpdate, state.AcceptedSnapshot.UpdatedAt+policy.MaxStatusAgeSeconds)
	return result, nil
}

// RevocationStatusStateV2 is one issuer's rollback-protected reducer state.
// Callers must serialize ApplyRevocation* calls and atomically persist the
// returned value with their security journal. This value alone is not durable.
type RevocationStatusStateV2 struct {
	IssuerID                  string                    `json:"issuer_id"`
	StatusKeyEpoch            uint64                    `json:"status_key_epoch"`
	StatusKeyID               string                    `json:"status_key_id"`
	RetiredStatusKeyIDs       []string                  `json:"retired_status_key_ids"`
	HasFloor                  bool                      `json:"has_floor"`
	Floor                     int64                     `json:"floor"`
	AcceptedSnapshot          *RevocationListV2         `json:"accepted_snapshot"`
	AcceptedCertIDs           []string                  `json:"accepted_cert_ids"`
	HasPrecedingCheckpoint    bool                      `json:"has_preceding_checkpoint"`
	PrecedingFloor            int64                     `json:"preceding_floor"`
	PrecedingAcceptedCertIDs  []string                  `json:"preceding_accepted_cert_ids"`
	DenyUnionCertIDs          []string                  `json:"deny_union_cert_ids"`
	Observations              []RevocationObservationV2 `json:"observations"`
	MaxObservedSequence       int64                     `json:"max_observed_sequence"`
	ForkSequence              int64                     `json:"fork_sequence"`
	ReconciliationRequired    bool                      `json:"reconciliation_required"`
	FutureDatedObjectObserved bool                      `json:"future_dated_object_observed"`
}

// ApplyRevocationListV2 verifies caller-authenticated status-key binding and
// applies one full snapshot. Invalid or unauthenticated input leaves state
// untouched. The reducer intentionally returns a copy for atomic persistence.
func ApplyRevocationListV2(state RevocationStatusStateV2, list *RevocationListV2, boundIssuerID string, statusKeyEpoch uint64, statusKey HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (result RevocationStatusStateV2, resultErr error) {
	defer func() {
		if resultErr == nil && result.IssuerID != "" {
			result = compactRevocationStatusObservationsV2(result)
		}
		resultErr = v2Classify(V2ErrStatusObjectRejected, resultErr)
	}()
	if err := validateRevocationStatusPolicyV2(policy); err != nil {
		return state, err
	}
	if !validV2Timestamp(now) || statusKeyEpoch == 0 || statusKeyEpoch > uint64(maxSafeInteger) {
		return state, fmt.Errorf("revocation list application has invalid time or status-key epoch")
	}
	if err := VerifyRevocationListV2Signature(list, boundIssuerID, statusKey); err != nil {
		return state, err
	}
	if err := validateStatusStateBindingV2(state, boundIssuerID, statusKeyEpoch); err != nil {
		return state, err
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), list)
	if err != nil {
		return state, err
	}
	body, err := revocationListSignableBytesV2(list)
	if err != nil {
		return state, err
	}
	bodyDigest := sha512.Sum384(body)
	setDigest, err := revokedSetDigestV2(list.Revoked)
	if err != nil {
		return state, err
	}

	next, err := cloneRevocationStatusStateV2(state)
	if err != nil {
		return state, err
	}
	initializeRevocationStatusStateV2(&next, boundIssuerID, statusKeyEpoch)
	statusKeyID, err := keyIDV2(statusKey)
	if err != nil {
		return state, err
	}
	if next.StatusKeyID != "" && next.StatusKeyID != statusKeyID {
		return state, fmt.Errorf("revocation list status key does not match configured epoch binding")
	}
	next.StatusKeyID = statusKeyID
	duplicateIndex := findStatusObservationV2(next.Observations, statusKeyEpoch, uint16(v2RevocationList), list.Sequence, digest)
	duplicate := duplicateIndex >= 0

	future := timestampBeyondSkewV2(list.UpdatedAt, now, policy.ClockSkewSeconds)
	obs := RevocationObservationV2{
		ObjectType: uint16(v2RevocationList), StatusKeyEpoch: statusKeyEpoch, StatusKeyID: statusKeyID, Sequence: list.Sequence,
		EvidenceDigest: bytes.Clone(digest), BodyDigest: bytes.Clone(bodyDigest[:]), RevokedSetDigest: setDigest,
		RevokedCertIDs: revokedCertIDsV2(list.Revoked), FutureDated: future,
	}
	if !duplicate {
		if prior, found := findStatusSetObservationV2(next.Observations, obs); found {
			if prior.Fork {
				return next, nil
			}
			if (prior.FutureDated || prior.Gap) && !future && revocationListFreshV2(list, policy, now) {
				if next.HasFloor && list.Sequence < next.Floor || hasForkedStatusSequenceV2(next.Observations, statusKeyEpoch, 0, list.Sequence) {
					return next, nil
				}
				// A future-dated or stale/gapped snapshot may be re-evaluated once fresh.
			} else if !prior.Accepted && !prior.Fork && next.HasFloor && list.Sequence == next.Floor &&
				next.AcceptedSnapshot != nil && next.AcceptedSnapshot.Sequence < next.Floor && !future && revocationListFreshV2(list, policy, now) {
				// A fresh same-set snapshot at a push-advanced floor becomes the new base.
			} else if prior.Accepted && next.HasFloor && list.Sequence == next.Floor &&
				heartbeatPreferredV2(list, digest, next.AcceptedSnapshot) {
				// A newer same-set current-floor heartbeat may refresh freshness.
			} else {
				return next, nil
			}
		}
	}
	if duplicate {
		prior := next.Observations[duplicateIndex]
		if prior.Accepted || (!prior.FutureDated && !prior.Gap) || future || !revocationListFreshV2(list, policy, now) {
			return next, nil
		}
		if next.HasFloor && list.Sequence < next.Floor {
			// A recovered later floor dominates this replay; it cannot be accepted again.
			return next, nil
		}
		if hasForkedStatusSequenceV2(next.Observations, statusKeyEpoch, 0, list.Sequence) {
			return next, nil
		}
		// Re-evaluate only an exact object previously withheld for freshness or a gap.
	} else {
		addRevocationsV2(&next, obs.RevokedCertIDs)
		if list.Sequence > next.MaxObservedSequence {
			next.MaxObservedSequence = list.Sequence
		}
	}
	if future {
		next.FutureDatedObjectObserved = true
		next.ReconciliationRequired = true
	}

	conflict := findStatusSequenceConflictV2(next.Observations, obs)
	if conflict {
		markStatusForkV2(&next, &obs, list.Sequence)
	} else if next.HasFloor && list.Sequence == next.Floor && !equalStringSetsV2(obs.RevokedCertIDs, next.AcceptedCertIDs) {
		markStatusForkV2(&next, &obs, list.Sequence)
	} else if next.HasFloor && list.Sequence < next.Floor && containsNovelRevocationV2(obs.RevokedCertIDs, next.AcceptedCertIDs) {
		markStatusForkV2(&next, &obs, list.Sequence)
	}
	applicable := requiredRevocationsForSnapshotV2(next.Observations, statusKeyEpoch, list.Sequence)
	if !containsAllStringSetV2(obs.RevokedCertIDs, applicable) {
		markStatusForkV2(&next, &obs, list.Sequence)
	}
	if snapshotConflictsWithObservedPushV2(next, statusKeyEpoch, list.Sequence, obs.RevokedCertIDs) {
		markStatusForkV2(&next, &obs, list.Sequence)
	}

	fresh := revocationListFreshV2(list, policy, now)
	if !fresh {
		// A consistent stale replay at or below the accepted floor cannot
		// change current state. Contradictions were classified above.
		if next.HasFloor && list.Sequence <= next.Floor {
			if !duplicate {
				next.Observations = append(next.Observations, obs)
			}
			return next, nil
		}
		next.ReconciliationRequired = true
		obs.Gap = true
		if !duplicate {
			next.Observations = append(next.Observations, obs)
		}
		return next, nil
	}
	if obs.Fork {
		if !duplicate {
			next.Observations = append(next.Observations, obs)
		}
		return next, nil
	}
	if !next.HasFloor && !containsAllStringSetV2(obs.RevokedCertIDs, next.DenyUnionCertIDs) {
		// A new status-key epoch cannot bootstrap from a snapshot that drops
		// issuer-wide denials retained from earlier epochs.
		next.ReconciliationRequired = true
		obs.Gap = true
		if !duplicate {
			next.Observations = append(next.Observations, obs)
		}
		return next, nil
	}
	if !next.HasFloor && list.Sequence < next.MaxObservedSequence {
		next.ReconciliationRequired = true
		obs.Gap = true
		if !duplicate {
			next.Observations = append(next.Observations, obs)
		}
		return next, nil
	}

	if next.HasFloor && list.Sequence < next.Floor {
		if !duplicate {
			next.Observations = append(next.Observations, obs)
		}
		return next, nil
	}

	if next.HasFloor && list.Sequence == next.Floor {
		// A current-floor snapshot is only a heartbeat when it exactly matches
		// the accepted cumulative set. It can reconcile a gap, never a fork.
		if !equalStringSetsV2(obs.RevokedCertIDs, next.AcceptedCertIDs) {
			markStatusForkV2(&next, &obs, list.Sequence)
			if !duplicate {
				next.Observations = append(next.Observations, obs)
			}
			return next, nil
		}
		if next.AcceptedSnapshot == nil || next.AcceptedSnapshot.Sequence < list.Sequence || heartbeatPreferredV2(list, digest, next.AcceptedSnapshot) {
			copyList, err := cloneRevocationListV2(list)
			if err != nil {
				return state, err
			}
			next.AcceptedSnapshot = copyList
		}
		obs.Accepted = true
	} else {
		copyList, err := cloneRevocationListV2(list)
		if err != nil {
			return state, err
		}
		if next.HasFloor && list.Sequence == next.Floor+1 {
			next.HasPrecedingCheckpoint = true
			next.PrecedingFloor = next.Floor
			next.PrecedingAcceptedCertIDs = sortedUniqueStringsV2(next.AcceptedCertIDs)
		} else {
			next.HasPrecedingCheckpoint = false
			next.PrecedingFloor = 0
			next.PrecedingAcceptedCertIDs = []string{}
		}
		next.AcceptedSnapshot = copyList
		next.AcceptedCertIDs = sortedUniqueStringsV2(obs.RevokedCertIDs)
		next.HasFloor = true
		next.Floor = list.Sequence
		obs.Accepted = true
	}

	if next.ReconciliationRequired {
		recoverableFork := next.ForkSequence == 0 || (list.Sequence > next.ForkSequence && list.Sequence >= next.MaxObservedSequence)
		fullyObserved := containsAllStringSetV2(obs.RevokedCertIDs, next.DenyUnionCertIDs)
		if recoverableFork && fullyObserved && list.Sequence >= next.MaxObservedSequence {
			next.ReconciliationRequired = false
			next.FutureDatedObjectObserved = false
			next.ForkSequence = 0
		}
	} else if list.Sequence >= next.MaxObservedSequence && containsAllStringSetV2(obs.RevokedCertIDs, next.DenyUnionCertIDs) {
		next.ReconciliationRequired = false
	}
	if !duplicate || (obs.Accepted && !next.Observations[duplicateIndex].Accepted) {
		next.Observations = append(next.Observations, obs)
	}
	return next, nil
}

// ApplyRevocationPushV2 verifies caller-authenticated status-key binding and
// applies one signed push. Noncontiguous or future pushes contribute to
// deny_union but make current status unavailable until a full snapshot repairs
// the gap or conflict.
func ApplyRevocationPushV2(state RevocationStatusStateV2, push *RevocationPushV2, boundIssuerID string, statusKeyEpoch uint64, statusKey HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (result RevocationStatusStateV2, resultErr error) {
	defer func() {
		if resultErr == nil && result.IssuerID != "" {
			result = compactRevocationStatusObservationsV2(result)
		}
		resultErr = v2Classify(V2ErrStatusObjectRejected, resultErr)
	}()
	if err := validateRevocationStatusPolicyV2(policy); err != nil {
		return state, err
	}
	if !validV2Timestamp(now) || statusKeyEpoch == 0 || statusKeyEpoch > uint64(maxSafeInteger) {
		return state, fmt.Errorf("revocation push application has invalid time or status-key epoch")
	}
	if err := VerifyRevocationPushV2Signature(push, boundIssuerID, statusKey); err != nil {
		return state, err
	}
	if err := validateStatusStateBindingV2(state, boundIssuerID, statusKeyEpoch); err != nil {
		return state, err
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationPush), push)
	if err != nil {
		return state, err
	}
	body, err := revocationPushSignableBytesV2(push)
	if err != nil {
		return state, err
	}
	bodyDigest := sha512.Sum384(body)
	setDigest, err := revokedSetDigestV2(push.Revoked)
	if err != nil {
		return state, err
	}

	next, err := cloneRevocationStatusStateV2(state)
	if err != nil {
		return state, err
	}
	initializeRevocationStatusStateV2(&next, boundIssuerID, statusKeyEpoch)
	statusKeyID, err := keyIDV2(statusKey)
	if err != nil {
		return state, err
	}
	if next.StatusKeyID != "" && next.StatusKeyID != statusKeyID {
		return state, fmt.Errorf("revocation push status key does not match configured epoch binding")
	}
	next.StatusKeyID = statusKeyID
	if hasStatusObservationV2(next.Observations, statusKeyEpoch, uint16(v2RevocationPush), push.Sequence, digest) ||
		hasStatusPushBodyV2(next.Observations, statusKeyEpoch, push.Sequence, bodyDigest[:]) {
		return next, nil
	}

	future := timestampBeyondSkewV2(push.PushedAt, now, policy.ClockSkewSeconds)
	obs := RevocationObservationV2{
		ObjectType: uint16(v2RevocationPush), StatusKeyEpoch: statusKeyEpoch, StatusKeyID: statusKeyID, Sequence: push.Sequence,
		EvidenceDigest: bytes.Clone(digest), BodyDigest: bytes.Clone(bodyDigest[:]), RevokedSetDigest: setDigest,
		RevokedCertIDs: revokedCertIDsV2(push.Revoked), FutureDated: future,
	}
	addRevocationsV2(&next, obs.RevokedCertIDs)
	if push.Sequence > next.MaxObservedSequence {
		next.MaxObservedSequence = push.Sequence
	}
	if future {
		next.FutureDatedObjectObserved = true
		next.ReconciliationRequired = true
	}
	if findStatusSequenceConflictV2(next.Observations, obs) {
		markStatusForkV2(&next, &obs, push.Sequence)
	}
	if conflictingSequence, conflict := snapshotOmissionForPushV2(next, statusKeyEpoch, obs); conflict {
		markStatusForkV2(&next, &obs, conflictingSequence)
	}

	expected := int64(1)
	if next.HasFloor {
		expected = next.Floor + 1
	}
	if next.HasFloor && push.Sequence <= next.Floor {
		if push.Sequence == next.Floor {
			if next.HasPrecedingCheckpoint && next.PrecedingFloor == push.Sequence-1 && !equalStringSetsV2(next.AcceptedCertIDs, append(append([]string{}, next.PrecedingAcceptedCertIDs...), obs.RevokedCertIDs...)) {
				markStatusForkV2(&next, &obs, push.Sequence)
			} else if containsNovelRevocationV2(obs.RevokedCertIDs, next.AcceptedCertIDs) {
				markStatusForkV2(&next, &obs, push.Sequence)
			} else if !obs.Fork && containsAllStringSetV2(next.AcceptedCertIDs, obs.RevokedCertIDs) {
				// The accepted full set already proves these entries, so delivery
				// order with the same-sequence push cannot make status unavailable.
			} else {
				obs.Gap = true
				next.ReconciliationRequired = true
			}
			next.Observations = append(next.Observations, obs)
			return next, nil
		}
		if containsNovelRevocationV2(obs.RevokedCertIDs, next.AcceptedCertIDs) {
			markStatusForkV2(&next, &obs, push.Sequence)
		}
		next.Observations = append(next.Observations, obs)
		return next, nil
	}
	if !next.HasFloor || push.Sequence != expected || next.ReconciliationRequired || future {
		obs.Gap = !obs.Fork
		next.ReconciliationRequired = true
		next.Observations = append(next.Observations, obs)
		return next, nil
	}

	next.AcceptedCertIDs = sortedUniqueStringsV2(append(next.AcceptedCertIDs, obs.RevokedCertIDs...))
	next.HasPrecedingCheckpoint = false
	next.PrecedingFloor = 0
	next.PrecedingAcceptedCertIDs = []string{}
	next.HasFloor = true
	next.Floor = push.Sequence
	obs.Accepted = true
	next.Observations = append(next.Observations, obs)
	return next, nil
}

func validateRevocationStatusPolicyV2(policy RevocationStatusPolicyV2) error {
	// Zero lifetime or age means "not configured" (status is then never
	// current); configured values are bounded by SPEC-v2 §2.5.
	if policy.MaxListLifetimeSeconds < 0 || policy.MaxStatusAgeSeconds < 0 || policy.ClockSkewSeconds < 0 ||
		policy.MaxListLifetimeSeconds > V2MaxStatusLifetimeSeconds || policy.MaxStatusAgeSeconds > V2MaxStatusLifetimeSeconds || policy.ClockSkewSeconds > V2MaxFutureSkewSeconds {
		return fmt.Errorf("revocation status policy contains invalid time bounds")
	}
	return nil
}

func validateStatusStateBindingV2(state RevocationStatusStateV2, issuerID string, epoch uint64) error {
	if state.IssuerID != "" && state.IssuerID != issuerID {
		return fmt.Errorf("revocation status state belongs to a different issuer")
	}
	if state.IssuerID != "" && state.StatusKeyEpoch != epoch {
		return fmt.Errorf("revocation status state belongs to a different status-key epoch")
	}
	if state.Floor < 0 || state.MaxObservedSequence < 0 || state.ForkSequence < 0 {
		return fmt.Errorf("revocation status state has negative sequence state")
	}
	if state.PrecedingFloor < 0 || state.PrecedingFloor > maxSafeInteger || (state.PrecedingFloor == 0 && len(state.PrecedingAcceptedCertIDs) != 0) || len(sortedUniqueStringsV2(state.PrecedingAcceptedCertIDs)) != len(state.PrecedingAcceptedCertIDs) {
		return fmt.Errorf("revocation status state has invalid preceding checkpoint")
	}
	if state.HasFloor && (state.Floor == 0 || state.Floor > maxSafeInteger || state.AcceptedSnapshot == nil || state.AcceptedSnapshot.Sequence <= 0 || state.AcceptedSnapshot.Sequence > state.Floor) {
		return fmt.Errorf("revocation status state has inconsistent accepted floor")
	}
	if !state.HasFloor && (state.Floor != 0 || state.AcceptedSnapshot != nil || len(state.AcceptedCertIDs) != 0) {
		return fmt.Errorf("revocation status state has accepted data without a floor")
	}
	if state.MaxObservedSequence > maxSafeInteger || state.ForkSequence > maxSafeInteger || epoch == 0 || epoch > uint64(maxSafeInteger) {
		return fmt.Errorf("revocation status state has invalid sequence or epoch")
	}
	if state.IssuerID != "" && !validV2ID(state.StatusKeyID) {
		return fmt.Errorf("revocation status state has an invalid status-key ID")
	}
	if len(sortedUniqueStringsV2(state.RetiredStatusKeyIDs)) != len(state.RetiredStatusKeyIDs) || containsAllStringSetV2(state.RetiredStatusKeyIDs, []string{state.StatusKeyID}) {
		return fmt.Errorf("revocation status state has invalid retired status-key history")
	}
	for _, keyID := range state.RetiredStatusKeyIDs {
		if !validV2ID(keyID) {
			return fmt.Errorf("revocation status state has an invalid retired status-key ID")
		}
	}
	return nil
}

func initializeRevocationStatusStateV2(state *RevocationStatusStateV2, issuerID string, epoch uint64) {
	if state.IssuerID == "" {
		state.IssuerID = issuerID
		state.StatusKeyEpoch = epoch
	}
	state.AcceptedCertIDs = sortedUniqueStringsV2(state.AcceptedCertIDs)
	state.DenyUnionCertIDs = sortedUniqueStringsV2(state.DenyUnionCertIDs)
}

func cloneRevocationStatusStateV2(state RevocationStatusStateV2) (RevocationStatusStateV2, error) {
	copyState := state
	copyState.AcceptedCertIDs = append([]string{}, state.AcceptedCertIDs...)
	copyState.DenyUnionCertIDs = append([]string{}, state.DenyUnionCertIDs...)
	copyState.Observations = make([]RevocationObservationV2, len(state.Observations))
	for i, observation := range state.Observations {
		copyState.Observations[i] = observation
		copyState.Observations[i].EvidenceDigest = bytes.Clone(observation.EvidenceDigest)
		copyState.Observations[i].BodyDigest = bytes.Clone(observation.BodyDigest)
		copyState.Observations[i].RevokedCertIDs = append([]string{}, observation.RevokedCertIDs...)
	}
	if state.AcceptedSnapshot != nil {
		list, err := cloneRevocationListV2(state.AcceptedSnapshot)
		if err != nil {
			return state, err
		}
		copyState.AcceptedSnapshot = list
	}
	return copyState, nil
}

func cloneRevocationListV2(list *RevocationListV2) (*RevocationListV2, error) {
	wire, err := EncodeRevocationListV2(list)
	if err != nil {
		return nil, err
	}
	return DecodeRevocationListV2(wire)
}

func timestampBeyondSkewV2(timestamp, now, skew int64) bool {
	return timestamp > now && timestamp-now > skew
}

func revocationListFreshV2(list *RevocationListV2, policy RevocationStatusPolicyV2, now int64) bool {
	if policy.MaxListLifetimeSeconds == 0 || policy.MaxStatusAgeSeconds == 0 ||
		list.NextUpdate-list.UpdatedAt > policy.MaxListLifetimeSeconds ||
		timestampBeyondSkewV2(list.UpdatedAt, now, policy.ClockSkewSeconds) || now >= list.NextUpdate {
		// Exclusive deadline: a list is fresh only while now < next_update.
		return false
	}
	// Exclusive age deadline: fresh only while now < updated_at + max_status_age.
	return now < list.UpdatedAt || now-list.UpdatedAt < policy.MaxStatusAgeSeconds
}

func revokedCertIDsV2(refs []RevokedCertV2) []string {
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = ref.CertID
	}
	return out
}

func sortedUniqueStringsV2(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	write := 0
	for _, value := range out {
		if write == 0 || out[write-1] != value {
			out[write] = value
			write++
		}
	}
	return out[:write]
}

func containsAllStringSetV2(have, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, value := range have {
		set[value] = struct{}{}
	}
	for _, value := range want {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func equalStringSetsV2(a, b []string) bool {
	return len(sortedUniqueStringsV2(a)) == len(sortedUniqueStringsV2(b)) && containsAllStringSetV2(a, b)
}

func addRevocationsV2(state *RevocationStatusStateV2, values []string) {
	state.DenyUnionCertIDs = sortedUniqueStringsV2(append(state.DenyUnionCertIDs, values...))
}

func revokedSetDigestV2(revoked []RevokedCertV2) ([]byte, error) {
	// RevokedSetDigest (SPEC-v2 §4): SHA-384("ratify-protocol-revoked-set-v2" ||
	// 0x00 || RatifyCanonicalJSON(sorted, deduplicated cert_ids)).
	canonical, err := CanonicalJSON(sortedUniqueStringsV2(revokedCertIDsV2(revoked)))
	if err != nil {
		return nil, fmt.Errorf("encode revoked certificate set: %w", err)
	}
	h := sha512.New384()
	_, _ = h.Write([]byte("ratify-protocol-revoked-set-v2"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canonical)
	return h.Sum(nil), nil
}

func containsNovelRevocationV2(values, accepted []string) bool {
	return !containsAllStringSetV2(accepted, values)
}

func requiredRevocationsForSnapshotV2(observations []RevocationObservationV2, epoch uint64, sequence int64) []string {
	var values []string
	for _, observation := range observations {
		if observation.StatusKeyEpoch == epoch && observation.Sequence <= sequence {
			values = append(values, observation.RevokedCertIDs...)
		}
	}
	return sortedUniqueStringsV2(values)
}

func hasStatusObservationV2(observations []RevocationObservationV2, epoch uint64, objectType uint16, sequence int64, digest []byte) bool {
	return findStatusObservationV2(observations, epoch, objectType, sequence, digest) >= 0
}

func findStatusObservationV2(observations []RevocationObservationV2, epoch uint64, objectType uint16, sequence int64, digest []byte) int {
	for i := len(observations) - 1; i >= 0; i-- {
		observation := observations[i]
		if observation.StatusKeyEpoch == epoch && observation.ObjectType == objectType && observation.Sequence == sequence && bytes.Equal(observation.EvidenceDigest, digest) {
			return i
		}
	}
	return -1
}

func snapshotConflictsWithObservedPushV2(state RevocationStatusStateV2, epoch uint64, sequence int64, snapshotIDs []string) bool {
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch != epoch || observation.ObjectType != uint16(v2RevocationPush) || observation.Sequence != sequence {
			continue
		}
		if state.HasFloor && state.Floor == sequence-1 {
			if !equalStringSetsV2(snapshotIDs, append(append([]string{}, state.AcceptedCertIDs...), observation.RevokedCertIDs...)) {
				return true
			}
		} else if !containsAllStringSetV2(snapshotIDs, observation.RevokedCertIDs) {
			return true
		}
	}
	return false
}

func findStatusSetObservationV2(observations []RevocationObservationV2, incoming RevocationObservationV2) (RevocationObservationV2, bool) {
	for i := len(observations) - 1; i >= 0; i-- {
		observation := observations[i]
		if observation.StatusKeyEpoch == incoming.StatusKeyEpoch && observation.ObjectType == incoming.ObjectType &&
			observation.Sequence == incoming.Sequence && bytes.Equal(observation.RevokedSetDigest, incoming.RevokedSetDigest) {
			return observation, true
		}
	}
	return RevocationObservationV2{}, false
}

func hasForkedStatusSequenceV2(observations []RevocationObservationV2, epoch uint64, objectType uint16, sequence int64) bool {
	for _, observation := range observations {
		if observation.StatusKeyEpoch == epoch && (objectType == 0 || observation.ObjectType == objectType) && observation.Sequence == sequence && observation.Fork {
			return true
		}
	}
	return false
}

func hasStatusPushBodyV2(observations []RevocationObservationV2, epoch uint64, sequence int64, bodyDigest []byte) bool {
	for _, observation := range observations {
		if observation.StatusKeyEpoch == epoch && observation.ObjectType == uint16(v2RevocationPush) && observation.Sequence == sequence && bytes.Equal(observation.BodyDigest, bodyDigest) {
			return true
		}
	}
	return false
}

func findStatusSequenceConflictV2(observations []RevocationObservationV2, incoming RevocationObservationV2) bool {
	for _, observation := range observations {
		if observation.StatusKeyEpoch != incoming.StatusKeyEpoch || observation.Sequence != incoming.Sequence || observation.ObjectType != incoming.ObjectType {
			continue
		}
		if incoming.ObjectType == uint16(v2RevocationList) && !bytes.Equal(observation.RevokedSetDigest, incoming.RevokedSetDigest) {
			return true
		}
		if incoming.ObjectType == uint16(v2RevocationPush) && !bytes.Equal(observation.BodyDigest, incoming.BodyDigest) {
			return true
		}
	}
	return false
}

func snapshotOmissionForPushV2(state RevocationStatusStateV2, epoch uint64, push RevocationObservationV2) (int64, bool) {
	var conflictingSequence int64
	check := func(sequence int64, revoked []string) {
		if sequence >= push.Sequence && !containsAllStringSetV2(revoked, push.RevokedCertIDs) && sequence > conflictingSequence {
			conflictingSequence = sequence
		}
	}
	if state.AcceptedSnapshot != nil && state.StatusKeyEpoch == epoch {
		check(state.AcceptedSnapshot.Sequence, revokedCertIDsV2(state.AcceptedSnapshot.Revoked))
	}
	if state.ReconciliationRequired {
		for _, observation := range state.Observations {
			if observation.StatusKeyEpoch == epoch && observation.ObjectType == uint16(v2RevocationList) && observation.Sequence > state.Floor && observation.Sequence >= push.Sequence &&
				(observation.Fork || observation.Gap || observation.FutureDated) {
				check(observation.Sequence, observation.RevokedCertIDs)
			}
		}
	}
	return conflictingSequence, conflictingSequence != 0
}

func markStatusForkV2(state *RevocationStatusStateV2, observation *RevocationObservationV2, sequence int64) {
	observation.Fork = true
	state.ReconciliationRequired = true
	state.ForkSequence = maxInt64(state.ForkSequence, state.Floor, sequence)
}

func heartbeatPreferredV2(incoming *RevocationListV2, incomingDigest []byte, accepted *RevocationListV2) bool {
	if incoming.UpdatedAt != accepted.UpdatedAt {
		return incoming.UpdatedAt > accepted.UpdatedAt
	}
	acceptedDigest, err := StatusEvidenceDigest(uint16(v2RevocationList), accepted)
	return err == nil && bytes.Compare(incomingDigest, acceptedDigest) < 0
}

func maxInt64(values ...int64) int64 {
	var max int64
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func acceptedStatusEvidenceV2(state RevocationStatusStateV2, issuerID, statusKeyID string) []StatusEvidenceEntryV2 {
	evidence := includeAcceptedBaseEvidenceV2(nil, state, issuerID, statusKeyID)
	if state.AcceptedSnapshot == nil {
		return evidence
	}
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch == state.StatusKeyEpoch && observation.ObjectType == uint16(v2RevocationPush) && observation.Accepted && observation.Sequence > state.AcceptedSnapshot.Sequence && observation.Sequence <= state.Floor {
			evidence = appendStatusEvidenceV2(evidence, issuerID, statusKeyID, observation)
		}
	}
	return sortStatusEvidenceV2(evidence)
}

func unavailableStatusEvidenceV2(state RevocationStatusStateV2, issuerID, statusKeyID string) []StatusEvidenceEntryV2 {
	evidence := acceptedStatusEvidenceV2(state, issuerID, statusKeyID)
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch != state.StatusKeyEpoch {
			continue
		}
		if observation.Sequence > state.Floor || observation.Fork || observation.Gap || observation.FutureDated || (state.ReconciliationRequired && !observation.Accepted) {
			evidence = appendStatusEvidenceV2(evidence, issuerID, statusKeyID, observation)
		}
	}
	return sortStatusEvidenceV2(evidence)
}

func includeAcceptedBaseEvidenceV2(evidence []StatusEvidenceEntryV2, state RevocationStatusStateV2, issuerID, statusKeyID string) []StatusEvidenceEntryV2 {
	if state.AcceptedSnapshot == nil {
		return sortStatusEvidenceV2(evidence)
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), state.AcceptedSnapshot)
	if err == nil {
		evidence = append(evidence, StatusEvidenceEntryV2{IssuerID: issuerID, StatusKeyID: statusKeyID, Sequence: state.AcceptedSnapshot.Sequence, ObjectType: uint16(v2RevocationList), Digest: "sha384:" + hex.EncodeToString(digest)})
	}
	return sortStatusEvidenceV2(evidence)
}

func statusEvidenceForV2(state RevocationStatusStateV2, evidence []StatusEvidenceEntryV2, issuerID, statusKeyID string, include func(RevocationObservationV2) bool) []StatusEvidenceEntryV2 {
	for _, observation := range state.Observations {
		if include(observation) {
			evidence = appendStatusEvidenceV2(evidence, issuerID, statusKeyID, observation)
		}
	}
	return sortStatusEvidenceV2(evidence)
}

func appendStatusEvidenceV2(evidence []StatusEvidenceEntryV2, issuerID, statusKeyID string, observation RevocationObservationV2) []StatusEvidenceEntryV2 {
	if observation.StatusKeyID != "" {
		statusKeyID = observation.StatusKeyID
	}
	entry := StatusEvidenceEntryV2{IssuerID: issuerID, StatusKeyID: statusKeyID, Sequence: observation.Sequence, ObjectType: observation.ObjectType, Digest: "sha384:" + hex.EncodeToString(observation.EvidenceDigest)}
	for _, prior := range evidence {
		if prior == entry {
			return evidence
		}
	}
	return append(evidence, entry)
}

func sortStatusEvidenceV2(evidence []StatusEvidenceEntryV2) []StatusEvidenceEntryV2 {
	if evidence == nil {
		return []StatusEvidenceEntryV2{}
	}
	sort.Slice(evidence, func(i, j int) bool {
		a, b := evidence[i], evidence[j]
		if a.IssuerID != b.IssuerID {
			return a.IssuerID < b.IssuerID
		}
		if a.StatusKeyID != b.StatusKeyID {
			return a.StatusKeyID < b.StatusKeyID
		}
		if a.Sequence != b.Sequence {
			return a.Sequence < b.Sequence
		}
		if a.ObjectType != b.ObjectType {
			return a.ObjectType < b.ObjectType
		}
		return a.Digest < b.Digest
	})
	return evidence
}
