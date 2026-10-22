package ratify

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// V2StatusAssessment is the deterministic aggregate of one result for every
// issuer-scoped certificate in a verified delegation chain. It is not a
// terminal decision; callers must stop on non-current status and must not
// reserve rate capacity until this assessment is current.
type V2StatusAssessment struct {
	Assessment string
	Reason     string
	Evidence   []StatusEvidenceEntryV2
	FreshUntil int64
}

// V2StatusRoleBindings must be built from caller-authenticated trust state.
// ReservedKeyIDs must include every non-status role admitted by deployment
// trust history that is not present in the evaluated delegation chain.
// Historical keys may authenticate revoked evidence; current keys alone may
// authenticate current or stale state.
type V2StatusRoleBindings struct {
	StatusKeyIssuers    map[string]string
	CurrentStatusKeyIDs map[string]string
	ReservedKeyIDs      map[string]struct{}
}

// aggregateCertificateStatusResultsV2 (internal; SPEC-v2 §6.5) requires exactly one reducer result for each
// requested CertificateRef, in the same order. Revocation takes precedence
// over unavailable, which takes precedence over stale, independent of chain
// order. Authenticated evidence is deduplicated and sorted; malformed rows are
// excluded and make their result unavailable.
func aggregateCertificateStatusResultsV2(checks []V2CertificateStatusCheck, results []RevocationStatusResultV2, roles V2StatusRoleBindings) (V2StatusAssessment, error) {
	return aggregateCertificateStatusV2(checks, results, roles, false)
}

// aggregateCertificateStatusV2 is the shared aggregator. allowUnboundIssuers is
// used only by the live verifier, which derives results from its own journal
// and reports an issuer without authenticated status configuration as
// unavailable instead of aborting the evaluation.
func aggregateCertificateStatusV2(checks []V2CertificateStatusCheck, results []RevocationStatusResultV2, roles V2StatusRoleBindings, allowUnboundIssuers bool) (V2StatusAssessment, error) {
	if len(checks) == 0 || len(checks) != len(results) {
		return V2StatusAssessment{}, fmt.Errorf("v2 status aggregation requires one result for every non-empty certificate list")
	}
	if err := validateV2StatusRoleBindings(roles, checks, allowUnboundIssuers); err != nil {
		return V2StatusAssessment{}, err
	}
	assessment := V2StatusAssessment{Assessment: "current", Evidence: []StatusEvidenceEntryV2{}}
	seen := make(map[StatusEvidenceEntryV2]struct{})
	digestBindings := make(map[string]StatusEvidenceEntryV2)
	invalidDigests := make(map[string]struct{})
	issuerIDs := make([]string, 0, len(checks))
	seenIssuers := make(map[string]struct{}, len(checks))
	seenCertificates := make(map[string]struct{}, len(checks))
	issuerSet := make(map[string]struct{}, len(checks))
	subjectSet := make(map[string]struct{}, len(checks))
	for i, check := range checks {
		if check.DelegationIndex != i || !validV2ID(check.IssuerID) || !validV2ID(check.SubjectID) || check.CertID == "" {
			return V2StatusAssessment{}, fmt.Errorf("v2 status check %d has an invalid delegation index or CertificateRef", i)
		}
		ref := check.IssuerID + "\x00" + check.CertID
		if _, duplicate := seenCertificates[ref]; duplicate {
			return V2StatusAssessment{}, fmt.Errorf("v2 status checks contain a duplicate CertificateRef")
		}
		seenCertificates[ref] = struct{}{}
		subjectSet[check.SubjectID] = struct{}{}
		if _, ok := seenIssuers[check.IssuerID]; !ok {
			seenIssuers[check.IssuerID] = struct{}{}
			issuerSet[check.IssuerID] = struct{}{}
			issuerIDs = append(issuerIDs, check.IssuerID)
		}
	}
	invalidResult, anyRevoked, anyUnavailable, anyStale := false, false, false, false
	revokedCandidates := make([]int, 0, len(results))
	issuerHistory := make(map[string][]StatusEvidenceEntryV2)
	for i, check := range checks {
		result := results[i]
		resultValid := true
		for _, evidence := range result.Evidence {
			if evidence.IssuerID != check.IssuerID || !validV2ID(evidence.StatusKeyID) || evidence.Sequence <= 0 || evidence.Sequence > maxSafeInteger || !validV2StatusEvidenceDigest(evidence.Digest) || (evidence.ObjectType != uint16(v2RevocationList) && evidence.ObjectType != uint16(v2RevocationPush)) {
				resultValid = false
				continue
			}
			_, isIssuer := issuerSet[evidence.StatusKeyID]
			_, isSubject := subjectSet[evidence.StatusKeyID]
			if isIssuer || isSubject {
				resultValid = false
				continue
			}
			if _, reserved := roles.ReservedKeyIDs[evidence.StatusKeyID]; reserved || roles.StatusKeyIssuers[evidence.StatusKeyID] != evidence.IssuerID || (result.Status != "revoked" && roles.CurrentStatusKeyIDs[evidence.IssuerID] != evidence.StatusKeyID) {
				resultValid = false
				continue
			}
			if prior, ok := digestBindings[evidence.Digest]; ok && prior != evidence {
				invalidDigests[evidence.Digest] = struct{}{}
			}
			digestBindings[evidence.Digest] = evidence
			if _, ok := seen[evidence]; !ok {
				seen[evidence] = struct{}{}
				assessment.Evidence = append(assessment.Evidence, evidence)
			}
		}
		switch result.Status {
		case "not_revoked":
			resultValid = resultValid && result.Reason == "" && result.FreshUntil > 0 && result.FreshUntil <= maxSafeInteger && validCurrentStatusEvidenceV2(result.Evidence, check.IssuerID)
			if resultValid {
				if assessment.FreshUntil == 0 || result.FreshUntil < assessment.FreshUntil {
					assessment.FreshUntil = result.FreshUntil
				}
				resultValid = addIssuerHistoryV2(issuerHistory, check.IssuerID, result.Evidence)
			}
		case "revoked":
			resultValid = resultValid && result.Reason == "" && len(result.Evidence) > 0
			if resultValid {
				revokedCandidates = append(revokedCandidates, i)
			}
		case "indeterminate":
			switch result.Reason {
			case "unavailable":
				anyUnavailable = true
			case "stale":
				resultValid = resultValid && validCurrentStatusEvidenceV2(result.Evidence, check.IssuerID)
				if resultValid {
					resultValid = addIssuerHistoryV2(issuerHistory, check.IssuerID, result.Evidence)
				}
				anyStale = true
			default:
				resultValid = false
			}
		default:
			resultValid = false
		}
		invalidResult = invalidResult || !resultValid
	}
	if len(invalidDigests) != 0 {
		filtered := assessment.Evidence[:0]
		for _, evidence := range assessment.Evidence {
			if _, conflict := invalidDigests[evidence.Digest]; !conflict {
				filtered = append(filtered, evidence)
			}
		}
		assessment.Evidence = filtered
		invalidResult = true
	}
	for _, i := range revokedCandidates {
		valid := len(results[i].Evidence) > 0
		for _, evidence := range results[i].Evidence {
			if _, conflict := invalidDigests[evidence.Digest]; conflict {
				valid = false
				break
			}
		}
		anyRevoked = anyRevoked || valid
	}
	assessment.Evidence = sortStatusEvidenceV2(assessment.Evidence)
	switch {
	case anyRevoked:
		assessment.Assessment, assessment.Reason = "revoked", "delegation_revoked"
	case invalidResult || anyUnavailable:
		assessment.Assessment, assessment.Reason = "unavailable", "status_unavailable"
	case anyStale:
		assessment.Assessment, assessment.Reason = "stale", "status_stale"
	case !hasAcceptedStatusHistoryPerIssuerV2(assessment.Evidence, sortedUniqueStringsV2(issuerIDs)):
		assessment.Assessment, assessment.Reason = "unavailable", "status_unavailable"
	}
	if assessment.Assessment != "current" {
		assessment.FreshUntil = 0
	}
	return assessment, nil
}

func validateV2StatusRoleBindings(roles V2StatusRoleBindings, checks []V2CertificateStatusCheck, allowUnboundIssuers bool) error {
	if roles.StatusKeyIssuers == nil || roles.CurrentStatusKeyIDs == nil || roles.ReservedKeyIDs == nil {
		return fmt.Errorf("v2 status aggregation requires authenticated status-key role bindings")
	}
	issuers := make(map[string]struct{}, len(checks))
	for _, check := range checks {
		issuers[check.IssuerID] = struct{}{}
	}
	for keyID, issuerID := range roles.StatusKeyIssuers {
		if !validV2ID(keyID) || !validV2ID(issuerID) {
			return fmt.Errorf("authenticated status-key binding is malformed")
		}
		if _, collision := roles.ReservedKeyIDs[keyID]; collision {
			return fmt.Errorf("status key collides with a reserved non-status key role")
		}
	}
	for issuerID := range issuers {
		keyID, bound := roles.CurrentStatusKeyIDs[issuerID]
		if !bound && allowUnboundIssuers {
			continue
		}
		if roles.StatusKeyIssuers[keyID] != issuerID {
			return fmt.Errorf("issuer lacks an authenticated current status-key binding")
		}
	}
	for keyID := range roles.ReservedKeyIDs {
		if !validV2ID(keyID) {
			return fmt.Errorf("reserved non-status key ID is malformed")
		}
	}
	return nil
}

func addIssuerHistoryV2(histories map[string][]StatusEvidenceEntryV2, issuerID string, evidence []StatusEvidenceEntryV2) bool {
	canonical := sortStatusEvidenceV2(append([]StatusEvidenceEntryV2(nil), evidence...))
	prior, exists := histories[issuerID]
	if !exists {
		histories[issuerID] = canonical
		return true
	}
	if len(prior) != len(canonical) {
		return false
	}
	for i := range prior {
		if prior[i] != canonical[i] {
			return false
		}
	}
	return true
}

func validCurrentStatusEvidenceV2(evidence []StatusEvidenceEntryV2, issuerID string) bool {
	if len(evidence) == 0 {
		return false
	}
	baseCount := 0
	var base StatusEvidenceEntryV2
	pushes := make([]StatusEvidenceEntryV2, 0, len(evidence)-1)
	for _, entry := range evidence {
		if entry.IssuerID != issuerID {
			return false
		}
		switch entry.ObjectType {
		case uint16(v2RevocationList):
			baseCount++
			base = entry
		case uint16(v2RevocationPush):
			pushes = append(pushes, entry)
		default:
			return false
		}
	}
	if baseCount != 1 {
		return false
	}
	sort.Slice(pushes, func(i, j int) bool { return pushes[i].Sequence < pushes[j].Sequence })
	for i, push := range pushes {
		if push.StatusKeyID != base.StatusKeyID || push.Sequence != base.Sequence+int64(i)+1 {
			return false
		}
	}
	return true
}

func validV2StatusEvidenceDigest(value string) bool {
	if !strings.HasPrefix(value, "sha384:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha384:")
	if len(encoded) != 96 || encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}
