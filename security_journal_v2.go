package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

// securityJournalVersionV2 is the current record version: canonical
// snapshot digest (security_journal_snapshot_v2.go). Version 1 records use the
// legacy json.Marshal digest and must be migrated before use.
const securityJournalVersionV2 = 2

// SecurityJournalHeadV2 is the independently anchored head of a deployment's
// security journal. A backend must not derive its rollback protection solely
// from the journal records it stores.
type SecurityJournalHeadV2 struct {
	Generation uint64 `json:"generation"`
	Digest     string `json:"digest"`
}

// SecurityJournalV2 contains the state whose loss or rollback can make
// verification unsafe. It is a logical record; durability and anti-rollback
// guarantees come from SecurityJournalStoreV2.
type SecurityJournalV2 struct {
	Version          uint16                             `json:"version"`
	Generation       uint64                             `json:"generation"`
	PreviousDigest   string                             `json:"previous_digest"`
	Digest           string                             `json:"digest"`
	StatusByIssuer   map[string]RevocationStatusStateV2 `json:"status_by_issuer"`
	KeyRoleHistory   []KeyRoleBindingV2                 `json:"key_role_history"`
	StatusKeyHistory []StatusKeyBindingV2               `json:"status_key_history"`
}

// SecurityJournalStoreV2 is an atomic compare-and-swap store backed by an
// independent, rollback-resistant head. Load must return the record matching
// that head or fail closed. CompareAndSwap must atomically advance both the
// durable record and its independent head, reject stale writers, and preserve
// enough history to recover the anchored head after a crash. A normal file,
// database transaction, or checksum chain does not by itself satisfy this
// contract. No production backend is provided by this protocol library.
//
// Load returns the record together with the independently anchored head it
// was read against. A record whose generation or digest differs from the
// returned head is unanchored and is never used to derive not_revoked.
type SecurityJournalStoreV2 interface {
	Load(context.Context) (SecurityJournalV2, SecurityJournalHeadV2, error)
	CompareAndSwap(context.Context, SecurityJournalHeadV2, SecurityJournalV2) error
}

// KeyRoleBindingV2 permanently assigns a key ID and both hybrid key
// components to one role for a verifier deployment.
type KeyRoleBindingV2 struct {
	KeyID         string `json:"key_id"`
	Ed25519Digest string `json:"ed25519_digest"`
	MLDSA65Digest string `json:"ml_dsa_65_digest"`
	Role          string `json:"role"`
}

// StatusKeyBindingV2 preserves every authenticated status-key epoch, including
// retired epochs, for one issuer.
type StatusKeyBindingV2 struct {
	IssuerID      string `json:"issuer_id"`
	Epoch         uint64 `json:"epoch"`
	StatusKeyID   string `json:"status_key_id"`
	Ed25519Digest string `json:"ed25519_digest"`
	MLDSA65Digest string `json:"ml_dsa_65_digest"`
}

// ErrSecurityJournalConflictV2 means another writer advanced the anchored
// journal. The operation must be reloaded and re-evaluated, not blindly
// retried with a stale state transition.
var ErrSecurityJournalConflictV2 = errors.New("security journal compare-and-swap conflict")

// EmptySecurityJournalV2 constructs the only valid genesis record.
func EmptySecurityJournalV2() SecurityJournalV2 {
	journal := SecurityJournalV2{
		Version:          securityJournalVersionV2,
		StatusByIssuer:   map[string]RevocationStatusStateV2{},
		KeyRoleHistory:   []KeyRoleBindingV2{},
		StatusKeyHistory: []StatusKeyBindingV2{},
	}
	journal.Digest, _ = securityJournalDigestV2(journal)
	return journal
}

// UpdateSecurityJournalV2 performs one validated journal transition. The
// backend's anchored CAS is the serialization point for concurrent callers.
func updateSecurityJournalV2(ctx context.Context, store SecurityJournalStoreV2, update func(*SecurityJournalV2) error) (SecurityJournalV2, error) {
	if store == nil || update == nil {
		return SecurityJournalV2{}, fmt.Errorf("security journal store and update are required")
	}
	current, err := loadAnchoredSecurityJournalV2(ctx, store)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	next, err := cloneSecurityJournalV2(current)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	if err := update(&next); err != nil {
		return SecurityJournalV2{}, err
	}
	return commitSecurityJournalTransitionV2(ctx, store, current, next)
}

// commitSecurityJournalTransitionV2 compacts and canonicalizes next, returns
// current unchanged when the canonical content is identical (no-op), and
// otherwise chains, validates, and commits it by compare-and-swap against
// current's head. A conflict is returned, never retried.
func commitSecurityJournalTransitionV2(ctx context.Context, store SecurityJournalStoreV2, current, next SecurityJournalV2) (SecurityJournalV2, error) {
	pruneSecurityJournalObservationsV2(&next)
	canonicalizeSecurityJournalV2(&next)
	if sameSecurityJournalContentV2(next, current) {
		return current, nil
	}
	next.Generation = current.Generation + 1
	if next.Generation == 0 || next.Generation > uint64(maxSafeInteger) {
		return SecurityJournalV2{}, fmt.Errorf("security journal generation exhausted")
	}
	next.Version = securityJournalVersionV2
	next.PreviousDigest = current.Digest
	next.Digest = ""
	var err error
	next.Digest, err = securityJournalDigestV2(next)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	if err := ValidateSecurityJournalTransitionV2(current, next); err != nil {
		return SecurityJournalV2{}, fmt.Errorf("invalid security journal transition: %w", err)
	}
	head := SecurityJournalHeadV2{Generation: current.Generation, Digest: current.Digest}
	if err := store.CompareAndSwap(ctx, head, next); err != nil {
		if errors.Is(err, ErrSecurityJournalConflictV2) {
			return SecurityJournalV2{}, err
		}
		return SecurityJournalV2{}, fmt.Errorf("commit rollback-protected security journal: %w", err)
	}
	return next, nil
}

// loadAnchoredSecurityJournalV2 loads a version 2 record and requires it to
// match the anchored head returned with it.
func loadAnchoredSecurityJournalV2(ctx context.Context, store SecurityJournalStoreV2) (SecurityJournalV2, error) {
	current, head, err := store.Load(ctx)
	if err != nil {
		return SecurityJournalV2{}, fmt.Errorf("load rollback-protected security journal: %w", err)
	}
	if head.Generation != current.Generation || head.Digest == "" || head.Digest != current.Digest {
		return SecurityJournalV2{}, fmt.Errorf("loaded security journal is not anchored by the store head")
	}
	if current.Version != securityJournalVersionV2 {
		return SecurityJournalV2{}, fmt.Errorf("security journal version %d requires migration", current.Version)
	}
	if err := ValidateSecurityJournalV2(current); err != nil {
		return SecurityJournalV2{}, fmt.Errorf("validate loaded security journal: %w", err)
	}
	return current, nil
}

// RecordSecurityKeyRoleV2 durably adds a non-status key role after the caller
// has authenticated the trust-configuration event that admits that key.
func RecordSecurityKeyRoleV2(ctx context.Context, store SecurityJournalStoreV2, role string, pub HybridPublicKey) (SecurityJournalV2, error) {
	if role == "status" {
		return SecurityJournalV2{}, fmt.Errorf("status keys must be recorded with their issuer and epoch")
	}
	return updateSecurityJournalV2(ctx, store, func(journal *SecurityJournalV2) error {
		return RegisterKeyRoleV2(journal, role, pub)
	})
}

// ConfigureStatusKeyEpochV2 persists an authenticated status-key binding. A
// first binding starts at epoch 1; later bindings must advance exactly one
// epoch and preserve prior-epoch denials and authenticated evidence.
func ConfigureStatusKeyEpochV2(ctx context.Context, store SecurityJournalStoreV2, issuerID string, epoch uint64, pub HybridPublicKey) (SecurityJournalV2, error) {
	return updateSecurityJournalV2(ctx, store, func(journal *SecurityJournalV2) error {
		if err := RegisterStatusKeyEpochV2(journal, issuerID, epoch, pub); err != nil {
			return err
		}
		if prior, ok := journal.StatusByIssuer[issuerID]; ok {
			if epoch == prior.StatusKeyEpoch {
				return requireJournalStatusKeyV2(journal, issuerID, epoch, pub)
			}
			updated, err := TransitionRevocationStatusEpochV2(prior, issuerID, epoch, pub)
			if err != nil {
				return err
			}
			journal.StatusByIssuer[issuerID] = updated
			return nil
		}
		if epoch != 1 {
			return fmt.Errorf("first status-key epoch must be 1")
		}
		keyID, err := keyIDV2(pub)
		if err != nil {
			return err
		}
		journal.StatusByIssuer[issuerID] = RevocationStatusStateV2{
			IssuerID: issuerID, StatusKeyEpoch: epoch, StatusKeyID: keyID,
			AcceptedCertIDs: []string{}, DenyUnionCertIDs: []string{}, Observations: []RevocationObservationV2{},
		}
		return nil
	})
}

// ApplyRevocationListToJournalV2 authenticates, reduces, and atomically
// persists a full status snapshot under the configured issuer key epoch.
func ApplyRevocationListToJournalV2(ctx context.Context, store SecurityJournalStoreV2, list *RevocationListV2, issuerID string, epoch uint64, pub HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (SecurityJournalV2, error) {
	return updateSecurityJournalV2(ctx, store, func(journal *SecurityJournalV2) error {
		if err := requireJournalStatusKeyV2(journal, issuerID, epoch, pub); err != nil {
			return err
		}
		state, err := ApplyRevocationListV2(journal.StatusByIssuer[issuerID], list, issuerID, epoch, pub, policy, now)
		if err != nil {
			return err
		}
		journal.StatusByIssuer[issuerID] = state
		return nil
	})
}

// ApplyRevocationPushToJournalV2 authenticates, reduces, and atomically
// persists one push under the configured issuer key epoch.
func ApplyRevocationPushToJournalV2(ctx context.Context, store SecurityJournalStoreV2, push *RevocationPushV2, issuerID string, epoch uint64, pub HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (SecurityJournalV2, error) {
	return updateSecurityJournalV2(ctx, store, func(journal *SecurityJournalV2) error {
		if err := requireJournalStatusKeyV2(journal, issuerID, epoch, pub); err != nil {
			return err
		}
		state, err := ApplyRevocationPushV2(journal.StatusByIssuer[issuerID], push, issuerID, epoch, pub, policy, now)
		if err != nil {
			return err
		}
		journal.StatusByIssuer[issuerID] = state
		return nil
	})
}

// RevocationStatusFromJournalV2 reads an anchored state and returns a
// fail-closed status decision for one issuer-scoped certificate reference.
func RevocationStatusFromJournalV2(ctx context.Context, store SecurityJournalStoreV2, issuerID, certID string, epoch uint64, pub HybridPublicKey, policy RevocationStatusPolicyV2, now int64) (RevocationStatusResultV2, error) {
	if store == nil {
		return RevocationStatusResultV2{}, fmt.Errorf("security journal store is required")
	}
	journal, err := loadAnchoredSecurityJournalV2(ctx, store)
	if err != nil {
		return RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}, err
	}
	if err := requireJournalStatusKeyV2(&journal, issuerID, epoch, pub); err != nil {
		return RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}, err
	}
	result, err := RevocationStatusForCertV2(journal.StatusByIssuer[issuerID], issuerID, certID, epoch, pub, policy, now)
	if err != nil {
		return RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}, err
	}
	return result, nil
}

func requireJournalStatusKeyV2(journal *SecurityJournalV2, issuerID string, epoch uint64, pub HybridPublicKey) error {
	if journal == nil || issuerID == "" || epoch == 0 {
		return fmt.Errorf("issuer and status-key epoch are required")
	}
	binding, ok := statusBindingAtEpochV2(journal.StatusKeyHistory, issuerID, epoch)
	if !ok {
		return fmt.Errorf("issuer status key is not present in the retained trust history")
	}
	actual, err := statusKeyBindingV2(issuerID, epoch, pub)
	if err != nil {
		return err
	}
	if binding != actual {
		return fmt.Errorf("status key does not match the retained issuer and epoch binding")
	}
	state, ok := journal.StatusByIssuer[issuerID]
	if !ok || state.StatusKeyEpoch != epoch || state.StatusKeyID != binding.StatusKeyID {
		return fmt.Errorf("status key is not the current issuer epoch")
	}
	return nil
}

// ValidateSecurityJournalV2 validates record integrity and internal indexes.
func ValidateSecurityJournalV2(journal SecurityJournalV2) error {
	if (journal.Version != securityJournalVersionV2 && journal.Version != securityJournalLegacyVersion) || journal.StatusByIssuer == nil || journal.KeyRoleHistory == nil || journal.StatusKeyHistory == nil {
		return fmt.Errorf("security journal has unsupported or incomplete shape")
	}
	if journal.Generation == 0 && journal.PreviousDigest != "" {
		return fmt.Errorf("security journal genesis has a predecessor")
	}
	if journal.Generation == 0 && (len(journal.StatusByIssuer) != 0 || len(journal.KeyRoleHistory) != 0 || len(journal.StatusKeyHistory) != 0) {
		return fmt.Errorf("security journal genesis must be empty")
	}
	if journal.Generation > 0 && (journal.PreviousDigest == "" || len(journal.PreviousDigest) != 96) {
		return fmt.Errorf("security journal record is missing its predecessor digest")
	}
	digest, err := securityJournalDigestV2(journal)
	if err != nil {
		return err
	}
	if journal.Digest != digest {
		return fmt.Errorf("security journal digest mismatch")
	}
	for issuerID, state := range journal.StatusByIssuer {
		if issuerID == "" || state.IssuerID != issuerID || state.StatusKeyEpoch == 0 {
			return fmt.Errorf("security journal contains a misbound issuer status state")
		}
		if err := validateStatusStateBindingV2(state, issuerID, state.StatusKeyEpoch); err != nil {
			return fmt.Errorf("invalid status state for issuer %q: %w", issuerID, err)
		}
		if err := validateAcceptedStatusStateV2(state); err != nil {
			return fmt.Errorf("invalid accepted status state for issuer %q: %w", issuerID, err)
		}
		binding, ok := statusBindingAtEpochV2(journal.StatusKeyHistory, issuerID, state.StatusKeyEpoch)
		if !ok || binding.StatusKeyID != state.StatusKeyID {
			return fmt.Errorf("current status state has no matching retained key binding")
		}
		var maxObserved int64
		var retiredKeyIDs []string
		for _, oldBinding := range journal.StatusKeyHistory {
			if oldBinding.IssuerID == issuerID && oldBinding.Epoch < state.StatusKeyEpoch {
				retiredKeyIDs = append(retiredKeyIDs, oldBinding.StatusKeyID)
			}
		}
		for _, observation := range state.Observations {
			observationBinding, exists := statusBindingAtEpochV2(journal.StatusKeyHistory, issuerID, observation.StatusKeyEpoch)
			if !exists || observation.StatusKeyID != observationBinding.StatusKeyID || observation.Sequence <= 0 || observation.Sequence > maxSafeInteger ||
				(len(observation.EvidenceDigest) != 48) || len(observation.BodyDigest) != 48 ||
				(observation.ObjectType != uint16(v2RevocationList) && observation.ObjectType != uint16(v2RevocationPush)) {
				return fmt.Errorf("security journal contains malformed or misbound status evidence")
			}
			if observation.StatusKeyEpoch == state.StatusKeyEpoch && observation.Sequence > maxObserved {
				maxObserved = observation.Sequence
			}
		}
		if state.MaxObservedSequence != maxObserved || !equalStringSetsV2(state.RetiredStatusKeyIDs, retiredKeyIDs) {
			return fmt.Errorf("status state does not match retained sequence and key history")
		}
	}
	if err := validateKeyRoleHistoryV2(journal.KeyRoleHistory); err != nil {
		return err
	}
	if err := validateStatusKeyHistoryV2(journal.StatusKeyHistory, journal.KeyRoleHistory); err != nil {
		return err
	}
	latestEpoch := map[string]uint64{}
	for _, binding := range journal.StatusKeyHistory {
		if binding.Epoch > latestEpoch[binding.IssuerID] {
			latestEpoch[binding.IssuerID] = binding.Epoch
		}
	}
	for issuerID, epoch := range latestEpoch {
		state, ok := journal.StatusByIssuer[issuerID]
		if !ok || state.StatusKeyEpoch != epoch {
			return fmt.Errorf("security journal status state is not at the latest retained issuer epoch")
		}
	}
	return nil
}

// ValidateSecurityJournalTransitionV2 enforces generation continuity and
// append-only key histories. Status-state evolution itself is performed by
// ApplyRevocationListV2, ApplyRevocationPushV2, and
// TransitionRevocationStatusEpochV2 before this validation.
func ValidateSecurityJournalTransitionV2(current, next SecurityJournalV2) error {
	if err := ValidateSecurityJournalV2(current); err != nil {
		return fmt.Errorf("invalid current journal: %w", err)
	}
	if err := ValidateSecurityJournalV2(next); err != nil {
		return fmt.Errorf("invalid next journal: %w", err)
	}
	if next.Generation != current.Generation+1 || next.PreviousDigest != current.Digest {
		return fmt.Errorf("journal generation or predecessor is not contiguous")
	}
	if next.Version != securityJournalVersionV2 {
		return fmt.Errorf("journal transitions must produce a version %d record", securityJournalVersionV2)
	}
	if current.Version == securityJournalLegacyVersion && !sameSecurityJournalContentV2(current, next) {
		return fmt.Errorf("journal migration must not change logical content")
	}
	if !appendOnlyKeyRolesV2(current.KeyRoleHistory, next.KeyRoleHistory) || !appendOnlyStatusBindingsV2(current.StatusKeyHistory, next.StatusKeyHistory) {
		return fmt.Errorf("journal key binding history was removed or rewritten")
	}
	for issuerID, state := range current.StatusByIssuer {
		nextState, ok := next.StatusByIssuer[issuerID]
		if !ok || !containsAllStringSetV2(nextState.DenyUnionCertIDs, state.DenyUnionCertIDs) {
			return fmt.Errorf("journal transition removed issuer status or a retained revocation")
		}
		nextObservations := make(map[string]RevocationObservationV2, len(nextState.Observations))
		for _, observation := range nextState.Observations {
			nextObservations[securityObservationKeyV2(observation)] = observation
		}
		nextSemanticObservations := make(map[string]RevocationObservationV2, len(nextState.Observations))
		for _, observation := range nextState.Observations {
			nextSemanticObservations[securityObservationSemanticKeyV2(observation)] = observation
		}
		for _, old := range state.Observations {
			if _, found := nextObservations[securityObservationKeyV2(old)]; found {
				continue
			}
			if !mustRetainStatusObservationV2(nextState, old) {
				continue
			}
			compacted, found := nextSemanticObservations[securityObservationSemanticKeyV2(old)]
			if !found || !containsAllStringSetV2(compacted.RevokedCertIDs, old.RevokedCertIDs) ||
				(old.Fork && !compacted.Fork) || (old.Gap && nextState.ReconciliationRequired && !compacted.Gap) ||
				(old.FutureDated && nextState.FutureDatedObjectObserved && !compacted.FutureDated) {
				return fmt.Errorf("journal transition removed authenticated status evidence")
			}
		}
		if nextState.StatusKeyEpoch < state.StatusKeyEpoch {
			return fmt.Errorf("journal transition rolled back a status-key epoch")
		}
		if nextState.StatusKeyEpoch > state.StatusKeyEpoch {
			if nextState.StatusKeyID == state.StatusKeyID || containsAllStringSetV2(state.RetiredStatusKeyIDs, []string{nextState.StatusKeyID}) ||
				!equalStringSetsV2(nextState.RetiredStatusKeyIDs, append(state.RetiredStatusKeyIDs, state.StatusKeyID)) ||
				nextState.HasFloor || nextState.Floor != 0 || nextState.AcceptedSnapshot != nil || len(nextState.AcceptedCertIDs) != 0 || nextState.HasPrecedingCheckpoint || nextState.PrecedingFloor != 0 || len(nextState.PrecedingAcceptedCertIDs) != 0 ||
				nextState.MaxObservedSequence != 0 || nextState.ForkSequence != 0 || nextState.ReconciliationRequired || nextState.FutureDatedObjectObserved {
				return fmt.Errorf("status-key epoch transition did not perform the required fail-closed reset")
			}
			for _, observation := range nextState.Observations {
				if observation.StatusKeyEpoch >= nextState.StatusKeyEpoch {
					return fmt.Errorf("status-key epoch transition contains evidence from the new epoch before bootstrap")
				}
			}
		}
		if nextState.StatusKeyEpoch == state.StatusKeyEpoch && state.HasFloor && (!nextState.HasFloor || nextState.Floor < state.Floor) {
			return fmt.Errorf("journal transition rolled back the accepted status floor")
		}
		if nextState.StatusKeyEpoch == state.StatusKeyEpoch && nextState.MaxObservedSequence < state.MaxObservedSequence {
			return fmt.Errorf("journal transition rolled back the observed status sequence")
		}
		if nextState.StatusKeyEpoch == state.StatusKeyEpoch && state.ReconciliationRequired && !nextState.ReconciliationRequired {
			if !hasAcceptedSnapshotAfterV2(nextState, state.StatusKeyEpoch, state.MaxObservedSequence, state.ForkSequence, state.DenyUnionCertIDs) ||
				!containsAllStringSetV2(nextState.AcceptedCertIDs, state.DenyUnionCertIDs) {
				return fmt.Errorf("journal transition cleared reconciliation without a caught-up full snapshot")
			}
		}
	}
	for issuerID := range next.StatusByIssuer {
		if _, exists := current.StatusByIssuer[issuerID]; !exists {
			if _, hasHistory := statusBindingAtEpochV2(next.StatusKeyHistory, issuerID, next.StatusByIssuer[issuerID].StatusKeyEpoch); !hasHistory {
				return fmt.Errorf("new issuer status state lacks authenticated key history")
			}
		}
	}
	return nil
}

func validateAcceptedStatusStateV2(state RevocationStatusStateV2) error {
	if len(sortedUniqueStringsV2(state.DenyUnionCertIDs)) != len(state.DenyUnionCertIDs) ||
		len(sortedUniqueStringsV2(state.AcceptedCertIDs)) != len(state.AcceptedCertIDs) {
		return fmt.Errorf("revocation status sets are not canonical")
	}
	observedRevocations := make([]string, 0)
	forkRecorded := false
	for _, observation := range state.Observations {
		if observation.Sequence <= 0 || observation.Sequence > maxSafeInteger || !validV2ID(observation.StatusKeyID) ||
			(observation.ObjectType != uint16(v2RevocationList) && observation.ObjectType != uint16(v2RevocationPush)) ||
			len(observation.EvidenceDigest) != sha512.Size384 || len(observation.BodyDigest) != sha512.Size384 || len(observation.RevokedSetDigest) != sha512.Size384 ||
			len(sortedUniqueStringsV2(observation.RevokedCertIDs)) != len(observation.RevokedCertIDs) {
			return fmt.Errorf("security journal contains a malformed status observation")
		}
		for _, certID := range observation.RevokedCertIDs {
			if certID == "" || !utf8.ValidString(certID) {
				return fmt.Errorf("status observation contains an invalid certificate ID")
			}
		}
		forkRecorded = forkRecorded || (observation.StatusKeyEpoch == state.StatusKeyEpoch && observation.Fork)
		observedRevocations = append(observedRevocations, observation.RevokedCertIDs...)
		if observation.StatusKeyEpoch == state.StatusKeyEpoch {
			if observation.Sequence > state.MaxObservedSequence {
				return fmt.Errorf("observed sequence exceeds its high-water mark")
			}
		}
		if !containsAllStringSetV2(state.DenyUnionCertIDs, observation.RevokedCertIDs) {
			return fmt.Errorf("deny union omits a revocation from authenticated evidence")
		}
	}
	if !containsAllStringSetV2(observedRevocations, state.DenyUnionCertIDs) {
		return fmt.Errorf("deny union contains a revocation without a retained authenticated witness")
	}
	if state.ForkSequence > 0 && (!state.ReconciliationRequired || !forkRecorded) {
		return fmt.Errorf("unresolved fork state lacks its retained fork marker")
	}
	if state.HasFloor && state.Floor > state.MaxObservedSequence {
		return fmt.Errorf("accepted floor exceeds the observed sequence high-water mark")
	}
	if !state.HasFloor {
		return nil
	}
	if state.AcceptedSnapshot.IssuerID != state.IssuerID || state.AcceptedSnapshot.Sequence > state.Floor {
		return fmt.Errorf("accepted snapshot does not match issuer or floor")
	}
	digest, err := StatusEvidenceDigest(uint16(v2RevocationList), state.AcceptedSnapshot)
	if err != nil {
		return err
	}
	if !hasAcceptedStatusObservationV2(state.Observations, state.StatusKeyEpoch, uint16(v2RevocationList), state.AcceptedSnapshot.Sequence, digest) {
		return fmt.Errorf("accepted snapshot has no matching authenticated observation")
	}
	accepted := revokedCertIDsV2(state.AcceptedSnapshot.Revoked)
	var acceptedPushes []RevocationObservationV2
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch == state.StatusKeyEpoch && observation.ObjectType == uint16(v2RevocationPush) && observation.Accepted && observation.Sequence > state.AcceptedSnapshot.Sequence && observation.Sequence <= state.Floor {
			acceptedPushes = append(acceptedPushes, observation)
			accepted = append(accepted, observation.RevokedCertIDs...)
		}
	}
	sort.Slice(acceptedPushes, func(i, j int) bool { return acceptedPushes[i].Sequence < acceptedPushes[j].Sequence })
	expectedSequence := state.AcceptedSnapshot.Sequence
	for _, push := range acceptedPushes {
		if expectedSequence >= maxSafeInteger || push.Sequence != expectedSequence+1 {
			return fmt.Errorf("accepted push observations are not contiguous after the accepted snapshot")
		}
		expectedSequence = push.Sequence
	}
	if expectedSequence != state.Floor {
		return fmt.Errorf("accepted push history does not reach the recorded floor")
	}
	if !equalStringSetsV2(accepted, state.AcceptedCertIDs) {
		return fmt.Errorf("accepted certificate set does not follow the accepted snapshot and pushes")
	}
	return nil
}

func compactRevocationStatusObservationsV2(state RevocationStatusStateV2) RevocationStatusStateV2 {
	journal := SecurityJournalV2{StatusByIssuer: map[string]RevocationStatusStateV2{state.IssuerID: state}}
	pruneSecurityJournalObservationsV2(&journal)
	return journal.StatusByIssuer[state.IssuerID]
}

func pruneSecurityJournalObservationsV2(journal *SecurityJournalV2) {
	for issuerID, state := range journal.StatusByIssuer {
		baseDigest := []byte(nil)
		if state.AcceptedSnapshot != nil {
			baseDigest, _ = StatusEvidenceDigest(uint16(v2RevocationList), state.AcceptedSnapshot)
		}
		observations := append([]RevocationObservationV2(nil), state.Observations...)
		sort.SliceStable(observations, func(i, j int) bool {
			a, b := observations[i], observations[j]
			if a.StatusKeyEpoch != b.StatusKeyEpoch {
				return a.StatusKeyEpoch < b.StatusKeyEpoch
			}
			if a.Sequence != b.Sequence {
				return a.Sequence < b.Sequence
			}
			if a.ObjectType != b.ObjectType {
				return a.ObjectType < b.ObjectType
			}
			if c := bytes.Compare(a.RevokedSetDigest, b.RevokedSetDigest); c != 0 {
				return c < 0
			}
			return bytes.Compare(a.BodyDigest, b.BodyDigest) < 0
		})
		retained := make([]RevocationObservationV2, 0, len(observations))
		witnessed := map[string]struct{}{}
		semanticSeen := map[string]int{}
		for _, observation := range observations {
			acceptedBase := len(baseDigest) != 0 && observation.StatusKeyEpoch == state.StatusKeyEpoch &&
				observation.ObjectType == uint16(v2RevocationList) && observation.Sequence == state.AcceptedSnapshot.Sequence &&
				bytes.Equal(observation.EvidenceDigest, baseDigest)
			fullRecord := acceptedBase || mustRetainStatusObservationV2(state, observation)
			newWitnesses := make([]string, 0, len(observation.RevokedCertIDs))
			for _, certID := range observation.RevokedCertIDs {
				if _, exists := witnessed[certID]; !exists {
					witnessed[certID] = struct{}{}
					newWitnesses = append(newWitnesses, certID)
				}
			}
			if !fullRecord {
				observation.RevokedCertIDs = newWitnesses
			}
			semanticKey := securityObservationSemanticKeyV2(observation)
			if index, exists := semanticSeen[semanticKey]; exists {
				prior := retained[index]
				prior.Accepted = prior.Accepted || observation.Accepted
				prior.Fork = prior.Fork || observation.Fork
				prior.Gap = prior.Gap || observation.Gap
				prior.FutureDated = (prior.FutureDated || observation.FutureDated) && !prior.Accepted
				prior.RevokedCertIDs = sortedUniqueStringsV2(append(prior.RevokedCertIDs, observation.RevokedCertIDs...))
				if acceptedBase {
					prior.EvidenceDigest = observation.EvidenceDigest
					prior.Accepted = true
					if !state.ReconciliationRequired {
						prior.Gap = false
					}
					prior.FutureDated = false
				}
				retained[index] = prior
				continue
			}
			semanticSeen[semanticKey] = len(retained)
			retained = append(retained, observation)
		}
		if !state.ReconciliationRequired && state.AcceptedSnapshot != nil {
			for index := range retained {
				observation := &retained[index]
				if observation.StatusKeyEpoch == state.StatusKeyEpoch && observation.ObjectType == uint16(v2RevocationList) &&
					observation.Sequence == state.AcceptedSnapshot.Sequence && observation.Accepted && !observation.FutureDated &&
					bytes.Equal(observation.EvidenceDigest, baseDigest) {
					observation.Gap = false
					break
				}
			}
		}
		state.Observations = retained
		journal.StatusByIssuer[issuerID] = canonicalizeRevocationStatusStateV2(state)
	}
}

func mustRetainStatusObservationV2(state RevocationStatusStateV2, observation RevocationObservationV2) bool {
	if observation.StatusKeyEpoch != state.StatusKeyEpoch {
		return false
	}
	if state.AcceptedSnapshot != nil && observation.ObjectType == uint16(v2RevocationPush) && observation.Accepted &&
		observation.Sequence > state.AcceptedSnapshot.Sequence && observation.Sequence <= state.Floor {
		return true
	}
	return state.ReconciliationRequired && (observation.Sequence > state.Floor || observation.Fork || observation.Gap || observation.FutureDated)
}

func securityObservationSemanticKeyV2(observation RevocationObservationV2) string {
	var digest []byte
	if observation.ObjectType == uint16(v2RevocationList) {
		digest = observation.RevokedSetDigest
	} else {
		digest = observation.BodyDigest
	}
	return fmt.Sprintf("%d:%d:%d:%x:future=%t:fork=%t", observation.StatusKeyEpoch, observation.ObjectType, observation.Sequence, digest, observation.FutureDated, observation.Fork)
}

func securityObservationKeyV2(observation RevocationObservationV2) string {
	wire, _ := json.Marshal(observation)
	return string(wire)
}

func hasAcceptedStatusObservationV2(observations []RevocationObservationV2, epoch uint64, objectType uint16, sequence int64, digest []byte) bool {
	for _, observation := range observations {
		if observation.StatusKeyEpoch == epoch && observation.ObjectType == objectType && observation.Sequence == sequence &&
			hex.EncodeToString(observation.EvidenceDigest) == hex.EncodeToString(digest) && observation.Accepted && !observation.Fork && !observation.FutureDated {
			return true
		}
	}
	return false
}

func hasAcceptedSnapshotAfterV2(state RevocationStatusStateV2, epoch uint64, minSequence, forkSequence int64, denyUnion []string) bool {
	for _, observation := range state.Observations {
		if observation.StatusKeyEpoch == epoch && observation.ObjectType == uint16(v2RevocationList) && observation.Accepted &&
			observation.Sequence >= minSequence && (forkSequence == 0 || observation.Sequence > forkSequence) &&
			containsAllStringSetV2(observation.RevokedCertIDs, denyUnion) {
			return true
		}
	}
	return false
}

// RegisterKeyRoleV2 records a permanent global role assignment. Repeating the
// identical assignment is idempotent; any key-ID or component reuse is denied.
func RegisterKeyRoleV2(journal *SecurityJournalV2, role string, pub HybridPublicKey) error {
	if journal == nil || !validSecurityKeyRoleV2(role) || role == "status" {
		return fmt.Errorf("security key role is invalid")
	}
	return registerKeyRoleV2(journal, role, pub)
}

func registerKeyRoleV2(journal *SecurityJournalV2, role string, pub HybridPublicKey) error {
	binding, err := keyRoleBindingV2(role, pub)
	if err != nil {
		return err
	}
	for _, existing := range journal.KeyRoleHistory {
		if existing == binding {
			return nil
		}
		if existing.KeyID == binding.KeyID || existing.Ed25519Digest == binding.Ed25519Digest || existing.MLDSA65Digest == binding.MLDSA65Digest || existing.Ed25519Digest == binding.MLDSA65Digest || existing.MLDSA65Digest == binding.Ed25519Digest {
			return fmt.Errorf("hybrid key ID or component is already permanently assigned to role %q", existing.Role)
		}
	}
	journal.KeyRoleHistory = append(journal.KeyRoleHistory, binding)
	sortKeyRoleHistoryV2(journal.KeyRoleHistory)
	return nil
}

// RegisterStatusKeyEpochV2 records caller-authenticated status-key history and
// the corresponding permanent global status role before status objects apply.
func RegisterStatusKeyEpochV2(journal *SecurityJournalV2, issuerID string, epoch uint64, pub HybridPublicKey) error {
	if journal == nil || issuerID == "" || epoch == 0 || epoch > uint64(maxSafeInteger) {
		return fmt.Errorf("status-key binding has invalid issuer or epoch")
	}
	binding, err := statusKeyBindingV2(issuerID, epoch, pub)
	if err != nil {
		return err
	}
	for _, existing := range journal.StatusKeyHistory {
		if existing.IssuerID == issuerID && existing.Epoch == epoch {
			if existing == binding {
				return nil
			}
			return fmt.Errorf("status-key epoch is permanently bound to a different key")
		}
		if existing.StatusKeyID == binding.StatusKeyID || existing.Ed25519Digest == binding.Ed25519Digest || existing.MLDSA65Digest == binding.MLDSA65Digest {
			return fmt.Errorf("status key was previously bound in this deployment")
		}
	}
	var highest uint64
	for _, existing := range journal.StatusKeyHistory {
		if existing.IssuerID == issuerID && existing.Epoch > highest {
			highest = existing.Epoch
		}
	}
	if epoch != highest+1 {
		return fmt.Errorf("status-key epoch must advance by one from retained issuer history")
	}
	if err := registerKeyRoleV2(journal, "status", pub); err != nil {
		return err
	}
	journal.StatusKeyHistory = append(journal.StatusKeyHistory, binding)
	sortStatusKeyHistoryV2(journal.StatusKeyHistory)
	return nil
}

func keyRoleBindingV2(role string, pub HybridPublicKey) (KeyRoleBindingV2, error) {
	id, err := keyIDV2(pub)
	if err != nil {
		return KeyRoleBindingV2{}, err
	}
	ed := sha512.Sum384(pub.Ed25519)
	ml := sha512.Sum384(pub.MLDSA65)
	return KeyRoleBindingV2{KeyID: id, Ed25519Digest: hex.EncodeToString(ed[:]), MLDSA65Digest: hex.EncodeToString(ml[:]), Role: role}, nil
}

func statusKeyBindingV2(issuerID string, epoch uint64, pub HybridPublicKey) (StatusKeyBindingV2, error) {
	role, err := keyRoleBindingV2("status", pub)
	if err != nil {
		return StatusKeyBindingV2{}, err
	}
	return StatusKeyBindingV2{IssuerID: issuerID, Epoch: epoch, StatusKeyID: role.KeyID, Ed25519Digest: role.Ed25519Digest, MLDSA65Digest: role.MLDSA65Digest}, nil
}

func validateKeyRoleHistoryV2(history []KeyRoleBindingV2) error {
	seenIDs, seenComponents := map[string]KeyRoleBindingV2{}, map[string]KeyRoleBindingV2{}
	for _, binding := range history {
		if binding.KeyID == "" || !validSecurityKeyRoleV2(binding.Role) || !validDigestHexV2(binding.Ed25519Digest) || !validDigestHexV2(binding.MLDSA65Digest) {
			return fmt.Errorf("security journal contains malformed key-role history")
		}
		if prior, ok := seenIDs[binding.KeyID]; ok && prior != binding {
			return fmt.Errorf("security journal reuses a key ID across roles")
		}
		seenIDs[binding.KeyID] = binding
		for _, component := range []string{binding.Ed25519Digest, binding.MLDSA65Digest} {
			if prior, ok := seenComponents[component]; ok && prior != binding {
				return fmt.Errorf("security journal reuses key material across roles")
			}
			seenComponents[component] = binding
		}
	}
	return nil
}

func validateStatusKeyHistoryV2(history []StatusKeyBindingV2, roles []KeyRoleBindingV2) error {
	lastEpoch := map[string]uint64{}
	seenIDs, seenComponents := map[string]struct{}{}, map[string]struct{}{}
	for _, binding := range history {
		if binding.IssuerID == "" || binding.Epoch == 0 || binding.StatusKeyID == "" || !validDigestHexV2(binding.Ed25519Digest) || !validDigestHexV2(binding.MLDSA65Digest) {
			return fmt.Errorf("security journal contains malformed status-key history")
		}
		if binding.Epoch != lastEpoch[binding.IssuerID]+1 {
			return fmt.Errorf("security journal status-key epochs are missing or out of order")
		}
		lastEpoch[binding.IssuerID] = binding.Epoch
		role, ok := roleForStatusBindingV2(roles, binding)
		if !ok || role.Role != "status" {
			return fmt.Errorf("status-key history lacks its global status role assignment")
		}
		if _, ok := seenIDs[binding.StatusKeyID]; ok {
			return fmt.Errorf("security journal reuses a status key ID")
		}
		seenIDs[binding.StatusKeyID] = struct{}{}
		for _, component := range []string{binding.Ed25519Digest, binding.MLDSA65Digest} {
			if _, ok := seenComponents[component]; ok {
				return fmt.Errorf("security journal reuses a status-key component")
			}
			seenComponents[component] = struct{}{}
		}
	}
	return nil
}

func roleForStatusBindingV2(roles []KeyRoleBindingV2, binding StatusKeyBindingV2) (KeyRoleBindingV2, bool) {
	for _, role := range roles {
		if role.KeyID == binding.StatusKeyID && role.Ed25519Digest == binding.Ed25519Digest && role.MLDSA65Digest == binding.MLDSA65Digest {
			return role, true
		}
	}
	return KeyRoleBindingV2{}, false
}

func statusBindingAtEpochV2(history []StatusKeyBindingV2, issuerID string, epoch uint64) (StatusKeyBindingV2, bool) {
	for _, binding := range history {
		if binding.IssuerID == issuerID && binding.Epoch == epoch {
			return binding, true
		}
	}
	return StatusKeyBindingV2{}, false
}

func appendOnlyKeyRolesV2(before, after []KeyRoleBindingV2) bool {
	for _, binding := range before {
		found := false
		for _, candidate := range after {
			if binding == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func appendOnlyStatusBindingsV2(before, after []StatusKeyBindingV2) bool {
	for _, binding := range before {
		found := false
		for _, candidate := range after {
			if binding == candidate {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsObservationV2(haystack []RevocationObservationV2, needle RevocationObservationV2) bool {
	for _, candidate := range haystack {
		if candidate.ObjectType == needle.ObjectType && candidate.StatusKeyEpoch == needle.StatusKeyEpoch && candidate.StatusKeyID == needle.StatusKeyID && candidate.Sequence == needle.Sequence && candidate.FutureDated == needle.FutureDated && candidate.Fork == needle.Fork && candidate.Gap == needle.Gap && candidate.Accepted == needle.Accepted && string(candidate.EvidenceDigest) == string(needle.EvidenceDigest) && string(candidate.BodyDigest) == string(needle.BodyDigest) && equalStringSlicesV2(candidate.RevokedCertIDs, needle.RevokedCertIDs) {
			return true
		}
	}
	return false
}

func equalStringSlicesV2(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validSecurityKeyRoleV2(role string) bool {
	switch role {
	case "status", "delegation", "rotation", "verifier", "witness", "receiver", "issuer", "other":
		return true
	default:
		return false
	}
}

func validDigestHexV2(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 48 && hex.EncodeToString(decoded) == value
}

func cloneSecurityJournalV2(journal SecurityJournalV2) (SecurityJournalV2, error) {
	wire, err := json.Marshal(journal)
	if err != nil {
		return SecurityJournalV2{}, fmt.Errorf("encode security journal copy: %w", err)
	}
	var copyJournal SecurityJournalV2
	if err := json.Unmarshal(wire, &copyJournal); err != nil {
		return SecurityJournalV2{}, fmt.Errorf("decode security journal copy: %w", err)
	}
	return copyJournal, nil
}

func sortKeyRoleHistoryV2(history []KeyRoleBindingV2) {
	sort.Slice(history, func(i, j int) bool {
		if history[i].KeyID != history[j].KeyID {
			return history[i].KeyID < history[j].KeyID
		}
		return history[i].Role < history[j].Role
	})
}

func sortStatusKeyHistoryV2(history []StatusKeyBindingV2) {
	sort.Slice(history, func(i, j int) bool {
		if history[i].IssuerID != history[j].IssuerID {
			return history[i].IssuerID < history[j].IssuerID
		}
		return history[i].Epoch < history[j].Epoch
	})
}
