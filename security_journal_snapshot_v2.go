package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// SecurityJournalV2 logical snapshot (SPEC-v2 §6.6).
//
// The snapshot is the portable, canonical projection of a SecurityJournalV2.
// Its bytes are RatifyCanonicalJSON of the object below and its digest is
//
//	SecurityJournalDigest = SHA-384("ratify-protocol-security-journal-v2" || 0x00 || snapshot)
//
// rendered as 96 lowercase hex characters. Projection rules (§6.6):
//   - members are never omitted: an absent value is null, an empty set is [].
//   - version is 2; version 1 records (unlabelled SHA-384 over Go
//     encoding/json) are migrated with MigrateSecurityJournalV2.
//   - previous_digest is 96 "0" characters at genesis.
//   - key_role_history is sorted by key_id then role; status_key_history by
//     issuer_id then epoch; issuers by issuer_id; string sets ascending bytes.
//   - observations keep compaction order (stable sort by status_key_epoch,
//     sequence, object_type_code, revoked_set_digest, body_digest).
//   - observation digests are standard base64 of 48 raw bytes; component
//     digests are 96 lowercase hex; accepted_snapshot is the complete
//     canonical RevocationList object or null; floor is null before any
//     accepted state; preceding_checkpoint is null or {accepted_cert_ids, floor}.
//
// A valid digest chain is not rollback protection: the head must be anchored
// independently and advanced by atomic compare-and-swap (§7.10).

const (
	securityJournalDigestLabelV2 = "ratify-protocol-security-journal-v2"
	securityJournalLegacyVersion = 1
	// MaxSecurityJournalSnapshotBytes bounds an imported snapshot.
	MaxSecurityJournalSnapshotBytes = 64 << 20
)

var genesisPreviousDigestV2 = strings.Repeat("0", 96)

type securityJournalSnapshotV2 struct {
	Generation       uint64                         `json:"generation"`
	Issuers          []securityJournalIssuerStateV2 `json:"issuers"`
	KeyRoleHistory   []securityJournalKeyRoleV2     `json:"key_role_history"`
	PreviousDigest   string                         `json:"previous_digest"`
	StatusKeyHistory []securityJournalStatusKeyV2   `json:"status_key_history"`
	Version          uint16                         `json:"version"`
}

type securityJournalKeyRoleV2 struct {
	Ed25519Digest string `json:"ed25519_digest"`
	KeyID         string `json:"key_id"`
	MLDSA65Digest string `json:"ml_dsa_65_digest"`
	Role          string `json:"role"`
}

type securityJournalStatusKeyV2 struct {
	Ed25519Digest string `json:"ed25519_digest"`
	Epoch         uint64 `json:"epoch"`
	IssuerID      string `json:"issuer_id"`
	MLDSA65Digest string `json:"ml_dsa_65_digest"`
	StatusKeyID   string `json:"status_key_id"`
}

type securityJournalCheckpointV2 struct {
	AcceptedCertIDs []string `json:"accepted_cert_ids"`
	Floor           int64    `json:"floor"`
}

type securityJournalIssuerStateV2 struct {
	AcceptedCertIDs           []string                       `json:"accepted_cert_ids"`
	AcceptedSnapshot          json.RawMessage                `json:"accepted_snapshot"`
	DenyUnionCertIDs          []string                       `json:"deny_union_cert_ids"`
	Floor                     *int64                         `json:"floor"`
	ForkSequence              int64                          `json:"fork_sequence"`
	FutureDatedObjectObserved bool                           `json:"future_dated_object_observed"`
	IssuerID                  string                         `json:"issuer_id"`
	MaxObservedSequence       int64                          `json:"max_observed_sequence"`
	Observations              []securityJournalObservationV2 `json:"observations"`
	PrecedingCheckpoint       *securityJournalCheckpointV2   `json:"preceding_checkpoint"`
	ReconciliationRequired    bool                           `json:"reconciliation_required"`
	RetiredStatusKeyIDs       []string                       `json:"retired_status_key_ids"`
	StatusKeyEpoch            uint64                         `json:"status_key_epoch"`
	StatusKeyID               string                         `json:"status_key_id"`
}

type securityJournalObservationV2 struct {
	Accepted         bool     `json:"accepted"`
	BodyDigest       []byte   `json:"body_digest"`
	EvidenceDigest   []byte   `json:"evidence_digest"`
	Fork             bool     `json:"fork"`
	FutureDated      bool     `json:"future_dated"`
	Gap              bool     `json:"gap"`
	ObjectTypeCode   uint16   `json:"object_type_code"`
	RevokedCertIDs   []string `json:"revoked_cert_ids"`
	RevokedSetDigest []byte   `json:"revoked_set_digest"`
	Sequence         int64    `json:"sequence"`
	StatusKeyEpoch   uint64   `json:"status_key_epoch"`
	StatusKeyID      string   `json:"status_key_id"`
}

func snapshotObservationV2(o RevocationObservationV2) securityJournalObservationV2 {
	return securityJournalObservationV2{
		Accepted: o.Accepted, BodyDigest: bytes.Clone(o.BodyDigest), EvidenceDigest: bytes.Clone(o.EvidenceDigest),
		Fork: o.Fork, FutureDated: o.FutureDated, Gap: o.Gap, ObjectTypeCode: o.ObjectType, RevokedCertIDs: sortedUniqueStringsV2(o.RevokedCertIDs),
		RevokedSetDigest: bytes.Clone(o.RevokedSetDigest), Sequence: o.Sequence, StatusKeyEpoch: o.StatusKeyEpoch, StatusKeyID: o.StatusKeyID,
	}
}

// compareCompactionOrderV2 is the §6.6 compaction sort key.
func compareCompactionOrderV2(a, b RevocationObservationV2) int {
	switch {
	case a.StatusKeyEpoch != b.StatusKeyEpoch:
		return cmpV2(a.StatusKeyEpoch < b.StatusKeyEpoch)
	case a.Sequence != b.Sequence:
		return cmpV2(a.Sequence < b.Sequence)
	case a.ObjectType != b.ObjectType:
		return cmpV2(a.ObjectType < b.ObjectType)
	}
	if c := bytes.Compare(a.RevokedSetDigest, b.RevokedSetDigest); c != 0 {
		return c
	}
	return bytes.Compare(a.BodyDigest, b.BodyDigest)
}

func cmpV2(less bool) int {
	if less {
		return -1
	}
	return 1
}

// canonicalizeSecurityJournalV2 puts every set and history of the in-memory
// record into snapshot order. Observation order is compaction order and is
// produced by the reducer; it is not changed here.
func canonicalizeSecurityJournalV2(journal *SecurityJournalV2) {
	if journal.KeyRoleHistory == nil {
		journal.KeyRoleHistory = []KeyRoleBindingV2{}
	}
	if journal.StatusKeyHistory == nil {
		journal.StatusKeyHistory = []StatusKeyBindingV2{}
	}
	if journal.StatusByIssuer == nil {
		journal.StatusByIssuer = map[string]RevocationStatusStateV2{}
	}
	sortKeyRoleHistoryV2(journal.KeyRoleHistory)
	sortStatusKeyHistoryV2(journal.StatusKeyHistory)
	for issuerID, state := range journal.StatusByIssuer {
		journal.StatusByIssuer[issuerID] = canonicalizeRevocationStatusStateV2(state)
	}
}

func canonicalizeRevocationStatusStateV2(state RevocationStatusStateV2) RevocationStatusStateV2 {
	state.RetiredStatusKeyIDs = sortedUniqueStringsV2(state.RetiredStatusKeyIDs)
	state.AcceptedCertIDs = sortedUniqueStringsV2(state.AcceptedCertIDs)
	state.PrecedingAcceptedCertIDs = sortedUniqueStringsV2(state.PrecedingAcceptedCertIDs)
	state.DenyUnionCertIDs = sortedUniqueStringsV2(state.DenyUnionCertIDs)
	observations := make([]RevocationObservationV2, len(state.Observations))
	for i, observation := range state.Observations {
		observation.RevokedCertIDs = sortedUniqueStringsV2(observation.RevokedCertIDs)
		observations[i] = observation
	}
	state.Observations = observations
	return state
}

func securityJournalSnapshotStructV2(journal SecurityJournalV2) (securityJournalSnapshotV2, error) {
	// Canonicalize a private copy; the caller's map and slices are not mutated.
	journal.KeyRoleHistory = append([]KeyRoleBindingV2{}, journal.KeyRoleHistory...)
	journal.StatusKeyHistory = append([]StatusKeyBindingV2{}, journal.StatusKeyHistory...)
	states := make(map[string]RevocationStatusStateV2, len(journal.StatusByIssuer))
	for issuerID, state := range journal.StatusByIssuer {
		states[issuerID] = state
	}
	journal.StatusByIssuer = states
	canonicalizeSecurityJournalV2(&journal)
	if journal.Generation == 0 && journal.PreviousDigest != "" {
		return securityJournalSnapshotV2{}, fmt.Errorf("security journal genesis has a predecessor")
	}
	snapshot := securityJournalSnapshotV2{
		Generation: journal.Generation, PreviousDigest: journal.PreviousDigest, Version: journal.Version,
		KeyRoleHistory: make([]securityJournalKeyRoleV2, 0, len(journal.KeyRoleHistory)), Issuers: []securityJournalIssuerStateV2{},
		StatusKeyHistory: make([]securityJournalStatusKeyV2, 0, len(journal.StatusKeyHistory)),
	}
	if journal.Generation == 0 {
		snapshot.PreviousDigest = genesisPreviousDigestV2
	}
	for _, role := range journal.KeyRoleHistory {
		snapshot.KeyRoleHistory = append(snapshot.KeyRoleHistory, securityJournalKeyRoleV2{Ed25519Digest: role.Ed25519Digest, KeyID: role.KeyID, MLDSA65Digest: role.MLDSA65Digest, Role: role.Role})
	}
	for _, binding := range journal.StatusKeyHistory {
		snapshot.StatusKeyHistory = append(snapshot.StatusKeyHistory, securityJournalStatusKeyV2{Ed25519Digest: binding.Ed25519Digest, Epoch: binding.Epoch, IssuerID: binding.IssuerID, MLDSA65Digest: binding.MLDSA65Digest, StatusKeyID: binding.StatusKeyID})
	}
	issuerIDs := make([]string, 0, len(journal.StatusByIssuer))
	for issuerID := range journal.StatusByIssuer {
		issuerIDs = append(issuerIDs, issuerID)
	}
	sort.Strings(issuerIDs)
	for _, issuerID := range issuerIDs {
		state := journal.StatusByIssuer[issuerID]
		projected := securityJournalIssuerStateV2{
			AcceptedCertIDs: state.AcceptedCertIDs, DenyUnionCertIDs: state.DenyUnionCertIDs,
			ForkSequence: state.ForkSequence, FutureDatedObjectObserved: state.FutureDatedObjectObserved,
			IssuerID: state.IssuerID, MaxObservedSequence: state.MaxObservedSequence,
			Observations:           make([]securityJournalObservationV2, 0, len(state.Observations)),
			ReconciliationRequired: state.ReconciliationRequired, RetiredStatusKeyIDs: state.RetiredStatusKeyIDs,
			StatusKeyEpoch: state.StatusKeyEpoch, StatusKeyID: state.StatusKeyID,
		}
		if state.HasFloor != (state.AcceptedSnapshot != nil) {
			return securityJournalSnapshotV2{}, fmt.Errorf("security journal issuer %q has an accepted snapshot inconsistent with its floor", issuerID)
		}
		if state.HasFloor {
			floor := state.Floor
			projected.Floor = &floor
			wire, err := EncodeRevocationListV2(state.AcceptedSnapshot)
			if err != nil {
				return securityJournalSnapshotV2{}, fmt.Errorf("encode accepted snapshot for issuer %q: %w", issuerID, err)
			}
			projected.AcceptedSnapshot = wire
		}
		if state.HasPrecedingCheckpoint {
			projected.PrecedingCheckpoint = &securityJournalCheckpointV2{AcceptedCertIDs: state.PrecedingAcceptedCertIDs, Floor: state.PrecedingFloor}
		}
		for _, observation := range state.Observations {
			projected.Observations = append(projected.Observations, snapshotObservationV2(observation))
		}
		snapshot.Issuers = append(snapshot.Issuers, projected)
	}
	return snapshot, nil
}

// securityJournalSnapshotBytesV2 returns the canonical snapshot bytes of a
// version 2 journal without validating it.
func securityJournalSnapshotBytesV2(journal SecurityJournalV2) ([]byte, error) {
	snapshot, err := securityJournalSnapshotStructV2(journal)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(snapshot)
}

// SecurityJournalSnapshotDigestV2 returns the labelled SHA-384 digest of
// canonical snapshot bytes as 96 lowercase hex characters.
func SecurityJournalSnapshotDigestV2(snapshot []byte) string {
	h := sha512.New384()
	_, _ = h.Write([]byte(securityJournalDigestLabelV2))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(snapshot)
	return hex.EncodeToString(h.Sum(nil))
}

func securityJournalDigestV2(journal SecurityJournalV2) (string, error) {
	switch journal.Version {
	case securityJournalVersionV2:
		snapshot, err := securityJournalSnapshotBytesV2(journal)
		if err != nil {
			return "", err
		}
		return SecurityJournalSnapshotDigestV2(snapshot), nil
	case securityJournalLegacyVersion:
		return legacySecurityJournalDigestV1(journal)
	default:
		return "", fmt.Errorf("security journal version %d is unsupported", journal.Version)
	}
}

// legacySecurityJournalDigestV1 is the pre-snapshot digest: unlabelled
// SHA-384 over Go encoding/json of the record with an empty digest field.
// It is retained only to validate a record before migration.
func legacySecurityJournalDigestV1(journal SecurityJournalV2) (string, error) {
	journal.Digest = ""
	wire, err := json.Marshal(journal)
	if err != nil {
		return "", fmt.Errorf("encode legacy security journal: %w", err)
	}
	digest := sha512.Sum384(wire)
	return hex.EncodeToString(digest[:]), nil
}

// ExportSecurityJournalSnapshotV2 validates a version 2 journal and returns
// its canonical snapshot bytes. The journal's digest is
// SecurityJournalSnapshotDigestV2 of the returned bytes.
func ExportSecurityJournalSnapshotV2(journal SecurityJournalV2) (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if journal.Version != securityJournalVersionV2 {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "only version %d security journals can be exported; migrate first", securityJournalVersionV2)
	}
	if err := ValidateSecurityJournalV2(journal); err != nil {
		return nil, v2Classify(V2ErrConfigurationInvalid, err)
	}
	return securityJournalSnapshotBytesV2(journal)
}

// ImportSecurityJournalSnapshotV2 decodes canonical snapshot bytes, checks
// that they are exactly canonical, that their digest and generation equal the
// independently anchored head, and that the record is valid. A snapshot that
// fails any check is rejected; there is no partial import.
func ImportSecurityJournalSnapshotV2(snapshot []byte, head SecurityJournalHeadV2) (_ SecurityJournalV2, err error) {
	defer func() { err = v2Classify(V2ErrMalformed, err) }()
	if len(snapshot) > MaxSecurityJournalSnapshotBytes {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot exceeds %d bytes", MaxSecurityJournalSnapshotBytes)
	}
	if !utf8.Valid(snapshot) {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot is not UTF-8")
	}
	// The snapshot is RatifyCanonicalJSON (§6.6), so every §2.1 strict-decode
	// rule applies, including the safe-integer range for generation, epochs,
	// and sequences.
	if err := checkWireJSONV2(snapshot); err != nil {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot))
	root, err := decoder.Token()
	if err != nil || root != json.Delim('{') || validateUniqueJSONObjectV2(decoder) != nil {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot is not a single object with unique keys")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot has trailing data")
	}
	var decoded securityJournalSnapshotV2
	strict := json.NewDecoder(bytes.NewReader(snapshot))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&decoded); err != nil {
		return SecurityJournalV2{}, fmt.Errorf("decode security journal snapshot: %w", err)
	}
	if err := requireV2RoundTrip(snapshot, &decoded); err != nil {
		return SecurityJournalV2{}, err
	}
	if decoded.Version != securityJournalVersionV2 {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot version %d is unsupported", decoded.Version)
	}
	previous := decoded.PreviousDigest
	if decoded.Generation == 0 {
		if previous != genesisPreviousDigestV2 {
			return SecurityJournalV2{}, fmt.Errorf("security journal genesis must have the all-zero predecessor")
		}
		previous = ""
	}
	journal := SecurityJournalV2{
		Version: decoded.Version, Generation: decoded.Generation, PreviousDigest: previous,
		StatusByIssuer: map[string]RevocationStatusStateV2{}, KeyRoleHistory: []KeyRoleBindingV2{}, StatusKeyHistory: []StatusKeyBindingV2{},
	}
	for _, role := range decoded.KeyRoleHistory {
		journal.KeyRoleHistory = append(journal.KeyRoleHistory, KeyRoleBindingV2{KeyID: role.KeyID, Ed25519Digest: role.Ed25519Digest, MLDSA65Digest: role.MLDSA65Digest, Role: role.Role})
	}
	for _, binding := range decoded.StatusKeyHistory {
		journal.StatusKeyHistory = append(journal.StatusKeyHistory, StatusKeyBindingV2{IssuerID: binding.IssuerID, Epoch: binding.Epoch, StatusKeyID: binding.StatusKeyID, Ed25519Digest: binding.Ed25519Digest, MLDSA65Digest: binding.MLDSA65Digest})
	}
	for _, projected := range decoded.Issuers {
		if _, duplicate := journal.StatusByIssuer[projected.IssuerID]; duplicate {
			return SecurityJournalV2{}, fmt.Errorf("security journal snapshot repeats issuer %q", projected.IssuerID)
		}
		state := RevocationStatusStateV2{
			IssuerID: projected.IssuerID, StatusKeyEpoch: projected.StatusKeyEpoch, StatusKeyID: projected.StatusKeyID,
			RetiredStatusKeyIDs: projected.RetiredStatusKeyIDs, AcceptedCertIDs: projected.AcceptedCertIDs,
			PrecedingAcceptedCertIDs: []string{}, DenyUnionCertIDs: projected.DenyUnionCertIDs, MaxObservedSequence: projected.MaxObservedSequence,
			ForkSequence: projected.ForkSequence, ReconciliationRequired: projected.ReconciliationRequired,
			FutureDatedObjectObserved: projected.FutureDatedObjectObserved, Observations: []RevocationObservationV2{},
		}
		if projected.Floor != nil {
			state.HasFloor, state.Floor = true, *projected.Floor
		}
		if len(projected.AcceptedSnapshot) != 0 && !bytes.Equal(projected.AcceptedSnapshot, []byte("null")) {
			list, err := DecodeRevocationListV2(projected.AcceptedSnapshot)
			if err != nil {
				return SecurityJournalV2{}, fmt.Errorf("accepted snapshot for issuer %q: %w", projected.IssuerID, err)
			}
			state.AcceptedSnapshot = list
		}
		if checkpoint := projected.PrecedingCheckpoint; checkpoint != nil {
			state.HasPrecedingCheckpoint, state.PrecedingFloor, state.PrecedingAcceptedCertIDs = true, checkpoint.Floor, checkpoint.AcceptedCertIDs
		}
		for _, o := range projected.Observations {
			if len(o.EvidenceDigest) != 48 || len(o.BodyDigest) != 48 || len(o.RevokedSetDigest) != 48 {
				return SecurityJournalV2{}, fmt.Errorf("observation digest for issuer %q is not 48 bytes", projected.IssuerID)
			}
			state.Observations = append(state.Observations, RevocationObservationV2{
				ObjectType: o.ObjectTypeCode, StatusKeyEpoch: o.StatusKeyEpoch, StatusKeyID: o.StatusKeyID, Sequence: o.Sequence,
				EvidenceDigest: o.EvidenceDigest, BodyDigest: o.BodyDigest, RevokedSetDigest: o.RevokedSetDigest, RevokedCertIDs: o.RevokedCertIDs,
				FutureDated: o.FutureDated, Fork: o.Fork, Gap: o.Gap, Accepted: o.Accepted,
			})
		}
		for i := 1; i < len(state.Observations); i++ {
			if compareCompactionOrderV2(state.Observations[i-1], state.Observations[i]) > 0 {
				return SecurityJournalV2{}, fmt.Errorf("observations for issuer %q are not in compaction order", projected.IssuerID)
			}
		}
		journal.StatusByIssuer[projected.IssuerID] = state
	}
	canonical, err := securityJournalSnapshotBytesV2(journal)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	if !bytes.Equal(canonical, snapshot) {
		return SecurityJournalV2{}, fmt.Errorf("security journal snapshot is not in canonical form")
	}
	journal.Digest = SecurityJournalSnapshotDigestV2(snapshot)
	if head.Generation != journal.Generation || head.Digest != journal.Digest {
		return SecurityJournalV2{}, v2Errorf(V2ErrLogStateMismatch, "security journal snapshot does not match the anchored head")
	}
	if err := ValidateSecurityJournalV2(journal); err != nil {
		return SecurityJournalV2{}, err
	}
	return journal, nil
}

// MigrateSecurityJournalV2 converts a valid version 1 record (legacy
// json.Marshal digest) into its version 2 successor: the same logical
// content at generation+1, previous_digest set to the legacy digest, and the
// canonical snapshot digest. The caller commits it with the store's anchored
// compare-and-swap from the legacy head, like any other transition.
func MigrateSecurityJournalV2(legacy SecurityJournalV2) (_ SecurityJournalV2, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if legacy.Version != securityJournalLegacyVersion {
		return SecurityJournalV2{}, v2Errorf(V2ErrConfigurationInvalid, "security journal migration requires a version %d record", securityJournalLegacyVersion)
	}
	if err := ValidateSecurityJournalV2(legacy); err != nil {
		return SecurityJournalV2{}, v2Classify(V2ErrConfigurationInvalid, err)
	}
	next, err := cloneSecurityJournalV2(legacy)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	if legacy.Generation >= uint64(maxSafeInteger) {
		return SecurityJournalV2{}, v2Errorf(V2ErrConfigurationInvalid, "security journal generation exhausted")
	}
	next.Version = securityJournalVersionV2
	next.Generation = legacy.Generation + 1
	next.PreviousDigest = legacy.Digest
	canonicalizeSecurityJournalV2(&next)
	next.Digest, err = securityJournalDigestV2(next)
	if err != nil {
		return SecurityJournalV2{}, err
	}
	if err := ValidateSecurityJournalTransitionV2(legacy, next); err != nil {
		return SecurityJournalV2{}, v2Classify(V2ErrConfigurationInvalid, err)
	}
	return next, nil
}

// sameSecurityJournalContentV2 compares two journals' logical content,
// ignoring version, generation and digests.
func sameSecurityJournalContentV2(a, b SecurityJournalV2) bool {
	a.Version, b.Version = securityJournalVersionV2, securityJournalVersionV2
	a.Generation, b.Generation = 1, 1
	a.PreviousDigest, b.PreviousDigest = "", ""
	left, err1 := securityJournalSnapshotBytesV2(a)
	right, err2 := securityJournalSnapshotBytesV2(b)
	return err1 == nil && err2 == nil && slices.Equal(left, right)
}
