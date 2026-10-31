package ratify

import (
	"strings"
	"testing"
)

// Tests construct authenticated role bindings from fixture evidence.
func aggregateTestStatus(checks []V2CertificateStatusCheck, results []RevocationStatusResultV2) (V2StatusAssessment, error) {
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	for i := range checks {
		if checks[i].SubjectID == "" {
			checks[i].SubjectID = testV2IssuerID("agent")
		}
	}
	for i, result := range results {
		if i >= len(checks) {
			break
		}
		for _, e := range result.Evidence {
			if prior, exists := roles.StatusKeyIssuers[e.StatusKeyID]; !exists || prior == e.IssuerID {
				roles.StatusKeyIssuers[e.StatusKeyID] = e.IssuerID
			}
			if result.Status != "revoked" && e.IssuerID == checks[i].IssuerID {
				roles.CurrentStatusKeyIDs[checks[i].IssuerID] = e.StatusKeyID
			}
		}
	}
	for i, check := range checks {
		if check.DelegationIndex != i {
			continue
		}
		if roles.StatusKeyIssuers[roles.CurrentStatusKeyIDs[check.IssuerID]] != check.IssuerID {
			key := strings.Repeat("f", 63) + "0123456789abcdef"[i%16:i%16+1]
			roles.CurrentStatusKeyIDs[check.IssuerID] = key
			roles.StatusKeyIssuers[key] = check.IssuerID
		}
	}
	return aggregateCertificateStatusResultsV2(checks, results, roles)
}

func testV2StatusEvidence(issuer, key string, sequence int64, objectType uint16, digit string) StatusEvidenceEntryV2 {
	return StatusEvidenceEntryV2{IssuerID: testV2IssuerID(issuer), StatusKeyID: strings.Repeat(key, 64), Sequence: sequence, ObjectType: objectType, Digest: "sha384:" + strings.Repeat(digit, 96)}
}

func testV2IssuerID(label string) string {
	if len(label) == 64 {
		return label
	}
	switch label {
	case "issuer-a":
		return strings.Repeat("a", 64)
	case "issuer-b":
		return strings.Repeat("b", 64)
	case "issuer-c":
		return strings.Repeat("c", 64)
	case "other":
		return strings.Repeat("e", 64)
	default:
		return strings.Repeat("d", 64)
	}
}

func TestAggregateCertificateStatusV2UsesProtocolPrecedenceAndEvidence(t *testing.T) {
	checks := []V2CertificateStatusCheck{
		{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer-a"), CertID: "leaf"},
		{DelegationIndex: 1, IssuerID: testV2IssuerID("issuer-b"), CertID: "parent"},
		{DelegationIndex: 2, IssuerID: testV2IssuerID("issuer-c"), CertID: "root"},
	}
	current := func(issuer, key, listDigit, pushDigit string) []StatusEvidenceEntryV2 {
		return []StatusEvidenceEntryV2{
			testV2StatusEvidence(issuer, key, 10, uint16(v2RevocationList), listDigit),
			testV2StatusEvidence(issuer, key, 11, uint16(v2RevocationPush), pushDigit),
		}
	}
	tests := []struct {
		name                       string
		results                    []RevocationStatusResultV2
		wantAssessment, wantReason string
		wantEvidence               int
	}{
		{"current", []RevocationStatusResultV2{{Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-a", "1", "a", "d")}, {Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-b", "2", "b", "e")}, {Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-c", "3", "c", "f")}}, "current", "", 6},
		{"stale", []RevocationStatusResultV2{{Status: "indeterminate", Reason: "stale", Evidence: current("issuer-a", "1", "a", "d")}, {Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-b", "2", "b", "e")}, {Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-c", "3", "c", "f")}}, "stale", "status_stale", 6},
		{"unavailable outranks stale", []RevocationStatusResultV2{{Status: "indeterminate", Reason: "stale", Evidence: current("issuer-a", "1", "a", "d")}, {Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}, {Status: "not_revoked", FreshUntil: 100, Evidence: current("issuer-c", "3", "c", "f")}}, "unavailable", "status_unavailable", 4},
		{"revoked outranks unavailable", []RevocationStatusResultV2{{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}, {Status: "revoked", Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-b", "2", 12, uint16(v2RevocationPush), "b")}}, {Status: "indeterminate", Reason: "stale", Evidence: current("issuer-c", "3", "c", "f")}}, "revoked", "delegation_revoked", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := aggregateTestStatus(checks, tt.results)
			if err != nil {
				t.Fatal(err)
			}
			if got.Assessment != tt.wantAssessment || got.Reason != tt.wantReason || len(got.Evidence) != tt.wantEvidence {
				t.Fatalf("aggregate = %+v", got)
			}
		})
	}
}

func TestAggregateCertificateStatusV2RequiresEveryCurrentFreshnessHorizon(t *testing.T) {
	checks := []V2CertificateStatusCheck{
		{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer-a"), CertID: "leaf"},
		{DelegationIndex: 1, IssuerID: testV2IssuerID("issuer-b"), CertID: "parent"},
	}
	results := []RevocationStatusResultV2{
		{Status: "not_revoked", FreshUntil: 120, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-a", "1", 1, uint16(v2RevocationList), "a")}},
		{Status: "not_revoked", FreshUntil: 109, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-b", "2", 1, uint16(v2RevocationList), "b")}},
	}
	got, err := aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "current" || got.FreshUntil != 109 {
		t.Fatalf("current status did not retain the earliest authenticated horizon: %+v err=%v", got, err)
	}
	results[1].FreshUntil = 0
	got, err = aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "unavailable" || got.FreshUntil != 0 {
		t.Fatalf("missing status freshness horizon was allowed: %+v err=%v", got, err)
	}
}

func TestAggregateCertificateStatusV2EvidenceUsesReceiptCanonicalOrder(t *testing.T) {
	issuerA, issuerB := testV2IssuerID("issuer-a"), testV2IssuerID("issuer-b")
	checks := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: issuerA, SubjectID: testV2IssuerID("agent"), CertID: "a"}, {DelegationIndex: 1, IssuerID: issuerB, SubjectID: testV2IssuerID("agent"), CertID: "b"}}
	results := []RevocationStatusResultV2{
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-a", "1", 1, uint16(v2RevocationList), "a")}},
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-b", "2", 1, uint16(v2RevocationList), "b")}},
	}
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{}, CurrentStatusKeyIDs: map[string]string{}, ReservedKeyIDs: map[string]struct{}{}}
	for _, result := range results {
		for _, e := range result.Evidence {
			roles.StatusKeyIssuers[e.StatusKeyID] = e.IssuerID
			roles.CurrentStatusKeyIDs[e.IssuerID] = e.StatusKeyID
		}
	}
	got, err := aggregateCertificateStatusResultsV2(checks, results, roles)
	if err != nil || got.Assessment != "current" || !sortedEvidenceV2(got.Evidence, []string{issuerA, issuerB}, strings.Repeat("c", 64), strings.Repeat("d", 64)) {
		t.Fatalf("assessment evidence is not receipt-compatible: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2RejectsMalformedOrIncompleteResults(t *testing.T) {
	check := V2CertificateStatusCheck{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer"), CertID: "cert"}
	validList := testV2StatusEvidence("issuer", "1", 1, uint16(v2RevocationList), "a")
	for name, result := range map[string]RevocationStatusResultV2{
		"unknown status":             {Status: "maybe"},
		"unknown unavailable reason": {Status: "indeterminate", Reason: "unknown"},
		"wrong issuer evidence":      {Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("other", "1", 1, uint16(v2RevocationList), "a")}},
		"malformed digest":           {Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{{IssuerID: testV2IssuerID("issuer"), StatusKeyID: strings.Repeat("1", 64), Sequence: 1, ObjectType: uint16(v2RevocationList), Digest: "sha384:xyz"}}},
		"missing current evidence":   {Status: "not_revoked"},
		"push without base":          {Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer", "1", 2, uint16(v2RevocationPush), "b")}},
		"stale without base":         {Status: "indeterminate", Reason: "stale", Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer", "1", 2, uint16(v2RevocationPush), "b")}},
		"wrong push sequence":        {Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{validList, testV2StatusEvidence("issuer", "1", 3, uint16(v2RevocationPush), "b")}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := aggregateTestStatus([]V2CertificateStatusCheck{check}, []RevocationStatusResultV2{result})
			if err != nil || got.Assessment != "unavailable" || got.Reason != "status_unavailable" {
				t.Fatalf("malformed result did not fail closed as unavailable: %+v, %v", got, err)
			}
		})
	}
	if _, err := aggregateTestStatus([]V2CertificateStatusCheck{check}, nil); err == nil {
		t.Fatal("missing result accepted")
	}
}

func TestAggregateCertificateStatusV2DeduplicatesExactEntriesAndRejectsDigestConflict(t *testing.T) {
	entry := testV2StatusEvidence("issuer", "1", 1, uint16(v2RevocationList), "a")
	checks := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer"), CertID: "child"}, {DelegationIndex: 1, IssuerID: testV2IssuerID("issuer"), CertID: "parent"}}
	results := []RevocationStatusResultV2{{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{entry}}, {Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{entry}}}
	got, err := aggregateTestStatus(checks, results)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != 1 || got.Evidence[0] != entry {
		t.Fatalf("exact duplicate evidence was not deduplicated: %+v", got.Evidence)
	}

	conflict := entry
	conflict.Sequence = 2
	results[1].Evidence = []StatusEvidenceEntryV2{conflict}
	got, err = aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "unavailable" {
		t.Fatalf("digest conflict did not fail closed as unavailable: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2RejectsReceiptIncompatibleHistories(t *testing.T) {
	checks := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer"), CertID: "child"}, {DelegationIndex: 1, IssuerID: testV2IssuerID("issuer"), CertID: "parent"}}
	results := []RevocationStatusResultV2{
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer", "1", 10, uint16(v2RevocationList), "a")}},
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer", "1", 11, uint16(v2RevocationList), "b")}},
	}
	got, err := aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "unavailable" {
		t.Fatalf("inconsistent issuer histories did not become unavailable: %+v, %v", got, err)
	}

	checks[1].IssuerID = testV2IssuerID("other")
	results[1].Evidence = []StatusEvidenceEntryV2{testV2StatusEvidence("other", "1", 10, uint16(v2RevocationList), "b")}
	got, err = aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "unavailable" {
		t.Fatalf("cross-issuer status key reuse did not become unavailable: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2ValidRevocationOutranksMalformedOtherResult(t *testing.T) {
	checks := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer-a"), CertID: "revoked"}, {DelegationIndex: 1, IssuerID: testV2IssuerID("issuer-b"), CertID: "unknown"}}
	results := []RevocationStatusResultV2{
		{Status: "revoked", Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-a", "1", 4, uint16(v2RevocationPush), "a")}},
		{Status: "not_revoked", FreshUntil: 100, Evidence: nil},
	}
	got, err := aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "revoked" || got.Reason != "delegation_revoked" {
		t.Fatalf("authenticated revocation did not outrank malformed peer result: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2RequiresSameIssuerHistoryAcrossRefs(t *testing.T) {
	issuer := testV2IssuerID("issuer")
	checks := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: issuer, CertID: "a"}, {DelegationIndex: 1, IssuerID: issuer, CertID: "b"}}
	list := testV2StatusEvidence("issuer", "1", 10, uint16(v2RevocationList), "a")
	push := testV2StatusEvidence("issuer", "1", 11, uint16(v2RevocationPush), "b")
	results := []RevocationStatusResultV2{
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{list, push}},
		{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{list}},
	}
	got, err := aggregateTestStatus(checks, results)
	if err != nil || got.Assessment != "unavailable" {
		t.Fatalf("mixed status floors for one issuer did not fail closed: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2UnauthenticatedEvidenceCannotPoisonIssuerBinding(t *testing.T) {
	issuerA, issuerB := testV2IssuerID("issuer-a"), testV2IssuerID("issuer-b")
	keyA, keyB := strings.Repeat("1", 64), strings.Repeat("2", 64)
	roles := V2StatusRoleBindings{
		StatusKeyIssuers:    map[string]string{keyA: issuerA, keyB: issuerB},
		CurrentStatusKeyIDs: map[string]string{issuerA: keyA, issuerB: keyB},
		ReservedKeyIDs:      map[string]struct{}{},
	}
	checks := []V2CertificateStatusCheck{
		{DelegationIndex: 0, IssuerID: issuerA, SubjectID: testV2IssuerID("agent"), CertID: "unknown"},
		{DelegationIndex: 1, IssuerID: issuerB, SubjectID: testV2IssuerID("agent"), CertID: "revoked"},
	}
	malicious := RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence(issuerA, "2", 7, uint16(v2RevocationPush), "a")}}
	revoked := RevocationStatusResultV2{Status: "revoked", Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence(issuerB, "2", 8, uint16(v2RevocationPush), "b")}}
	for _, pair := range []struct {
		checks  []V2CertificateStatusCheck
		results []RevocationStatusResultV2
	}{{checks, []RevocationStatusResultV2{malicious, revoked}}, {[]V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: issuerB, SubjectID: testV2IssuerID("agent"), CertID: "revoked"}, {DelegationIndex: 1, IssuerID: issuerA, SubjectID: testV2IssuerID("agent"), CertID: "unknown"}}, []RevocationStatusResultV2{revoked, malicious}}} {
		got, err := aggregateCertificateStatusResultsV2(pair.checks, pair.results, roles)
		if err != nil || got.Assessment != "revoked" || got.Reason != "delegation_revoked" || len(got.Evidence) != 1 || got.Evidence[0].IssuerID != issuerB {
			t.Fatalf("unauthenticated evidence affected valid revocation: %+v, %v", got, err)
		}
	}
}

func TestAggregateCertificateStatusV2RejectsStatusKeyRoleCollision(t *testing.T) {
	issuer, key := testV2IssuerID("issuer-a"), strings.Repeat("1", 64)
	check := V2CertificateStatusCheck{DelegationIndex: 0, IssuerID: issuer, SubjectID: testV2IssuerID("agent"), CertID: "cert"}
	roles := V2StatusRoleBindings{StatusKeyIssuers: map[string]string{key: issuer}, CurrentStatusKeyIDs: map[string]string{issuer: key}, ReservedKeyIDs: map[string]struct{}{key: {}}}
	if _, err := aggregateCertificateStatusResultsV2([]V2CertificateStatusCheck{check}, []RevocationStatusResultV2{{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence(issuer, "1", 1, uint16(v2RevocationList), "a")}}}, roles); err == nil {
		t.Fatal("status key reused for a reserved non-status role was accepted")
	}
}

func TestAggregateCertificateStatusV2RejectsSubjectKeyAsStatusKey(t *testing.T) {
	agentID := testV2IssuerID("agent")
	issuer := testV2IssuerID("issuer-a")
	check := V2CertificateStatusCheck{DelegationIndex: 0, IssuerID: issuer, SubjectID: agentID, CertID: "cert"}
	roles := V2StatusRoleBindings{
		StatusKeyIssuers:    map[string]string{agentID: issuer},
		CurrentStatusKeyIDs: map[string]string{issuer: agentID},
		ReservedKeyIDs:      map[string]struct{}{},
	}
	result := RevocationStatusResultV2{Status: "not_revoked", FreshUntil: 100, Evidence: []StatusEvidenceEntryV2{testV2StatusEvidence("issuer-a", "1", 1, uint16(v2RevocationList), "a")}}
	got, err := aggregateCertificateStatusResultsV2([]V2CertificateStatusCheck{check}, []RevocationStatusResultV2{result}, roles)
	if err != nil || got.Assessment != "unavailable" {
		t.Fatalf("subject key was accepted as an issuer status key: %+v, %v", got, err)
	}
}

func TestAggregateCertificateStatusV2RejectsChainRoleKeyAsRevokedStatusKey(t *testing.T) {
	issuerID := testV2IssuerID("issuer-a")
	subjectID := testV2IssuerID("agent")
	check := V2CertificateStatusCheck{DelegationIndex: 0, IssuerID: issuerID, SubjectID: subjectID, CertID: "cert"}
	for _, roleID := range []string{issuerID, subjectID} {
		t.Run(roleID[:4], func(t *testing.T) {
			roles := V2StatusRoleBindings{
				StatusKeyIssuers:    map[string]string{roleID: issuerID},
				CurrentStatusKeyIDs: map[string]string{issuerID: roleID},
				ReservedKeyIDs:      map[string]struct{}{},
			}
			evidence := testV2StatusEvidence("issuer-a", "1", 2, uint16(v2RevocationPush), "a")
			evidence.StatusKeyID = roleID
			result := RevocationStatusResultV2{Status: "revoked", Evidence: []StatusEvidenceEntryV2{evidence}}
			got, err := aggregateCertificateStatusResultsV2([]V2CertificateStatusCheck{check}, []RevocationStatusResultV2{result}, roles)
			if err != nil || got.Assessment != "unavailable" {
				t.Fatalf("chain role key was accepted as revoked status evidence: %+v, %v", got, err)
			}
		})
	}
}

func TestAggregateCertificateStatusV2RejectsDuplicateRefsAndMisorderedChecks(t *testing.T) {
	result := RevocationStatusResultV2{Status: "indeterminate", Reason: "unavailable", Evidence: []StatusEvidenceEntryV2{}}
	duplicate := []V2CertificateStatusCheck{{DelegationIndex: 0, IssuerID: testV2IssuerID("issuer"), CertID: "cert"}, {DelegationIndex: 1, IssuerID: testV2IssuerID("issuer"), CertID: "cert"}}
	if _, err := aggregateTestStatus(duplicate, []RevocationStatusResultV2{result, result}); err == nil {
		t.Fatal("duplicate CertificateRef was accepted")
	}
	misordered := []V2CertificateStatusCheck{{DelegationIndex: 1, IssuerID: testV2IssuerID("issuer"), CertID: "cert"}}
	if _, err := aggregateTestStatus(misordered, []RevocationStatusResultV2{result}); err == nil {
		t.Fatal("misordered delegation status check was accepted")
	}
}
