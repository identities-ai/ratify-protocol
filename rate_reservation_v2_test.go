package ratify

import (
	"reflect"
	"strings"
	"testing"
)

func rateConstraintV2Test(t *testing.T, issuer, cert string, index, count int, window int64) V2DeferredConstraint {
	t.Helper()
	encoded, err := CanonicalJSON(ConstraintV2{Type: ConstraintMaxRate, Count: int64(count), WindowS: window})
	if err != nil {
		t.Fatal(err)
	}
	return V2DeferredConstraint{IssuerID: issuer, CertID: cert, ConstraintIndex: index, Type: ConstraintMaxRate, CanonicalJSON: encoded}
}

func TestBuildV2RateReservationBatchGroupsSignedLimitsWithoutIssuerCollision(t *testing.T) {
	issuerA := strings.Repeat("a", 64)
	issuerB := strings.Repeat("b", 64)
	deferred := []V2DeferredConstraint{
		rateConstraintV2Test(t, issuerB, "shared-cert", 0, 7, 60),
		rateConstraintV2Test(t, issuerA, "shared-cert", 0, 5, 60),
		rateConstraintV2Test(t, issuerA, "shared-cert", 1, 2, 60),
		rateConstraintV2Test(t, issuerA, "shared-cert", 2, 3, 120),
	}
	deferred[0].DelegationIndex = 1
	want := []V2RateReservation{
		{IssuerID: issuerA, CertID: "shared-cert", WindowS: 60, Limit: 2},
		{IssuerID: issuerA, CertID: "shared-cert", WindowS: 120, Limit: 3},
		{IssuerID: issuerB, CertID: "shared-cert", WindowS: 60, Limit: 7},
	}
	for _, input := range [][]V2DeferredConstraint{deferred, {deferred[3], deferred[2], deferred[1], deferred[0]}} {
		got, err := BuildV2RateReservationBatch(input)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("rate batch lost issuer isolation, minimum limit, or ordering: %+v, %v", got, err)
		}
	}
}

func TestBuildV2RateReservationBatchRejectsMalformedOrDuplicatedSignedConstraints(t *testing.T) {
	issuer := strings.Repeat("a", 64)
	valid := rateConstraintV2Test(t, issuer, "cert", 0, 2, 60)
	for _, input := range []V2DeferredConstraint{
		{IssuerID: issuer, CertID: "cert", Type: ConstraintMaxRate, CanonicalJSON: []byte(`{"count":0,"type":"max_rate","window_s":60}`)},
		{IssuerID: issuer, CertID: "cert", Type: ConstraintMaxRate, CanonicalJSON: []byte(`{"count":2,"type":"max_rate","window_s":0}`)},
		{IssuerID: issuer, CertID: "cert", Type: ConstraintMaxRate, CanonicalJSON: []byte(`{"count":2,"type":"max_rate","window_s":86401}`)},
		{IssuerID: strings.Repeat("a", 32), CertID: "cert", Type: ConstraintMaxRate, CanonicalJSON: valid.CanonicalJSON},
		{IssuerID: issuer, CertID: "", Type: ConstraintMaxRate, CanonicalJSON: valid.CanonicalJSON},
		{IssuerID: issuer, CertID: strings.Repeat("x", MaxIdentifierLengthBytes+1), Type: ConstraintMaxRate, CanonicalJSON: valid.CanonicalJSON},
	} {
		if got, err := BuildV2RateReservationBatch([]V2DeferredConstraint{input}); err == nil {
			t.Fatalf("malformed rate constraint created batch: %+v", got)
		}
	}
	if got, err := BuildV2RateReservationBatch([]V2DeferredConstraint{valid, valid}); err == nil {
		t.Fatalf("duplicate signed rate position created batch: %+v", got)
	}
	mutated := valid
	mutated.CanonicalJSON = []byte(`{"COUNT":2,"type":"max_rate","window_s":60}`)
	if got, err := BuildV2RateReservationBatch([]V2DeferredConstraint{mutated}); err == nil {
		t.Fatalf("case-variant rate field created batch: %+v", got)
	}
	mutated = valid
	mutated.Type = ConstraintReceiverAudience
	if got, err := BuildV2RateReservationBatch([]V2DeferredConstraint{mutated}); err == nil {
		t.Fatalf("outer type mismatch silently omitted signed rate constraint: %+v", got)
	}
	mutated = valid
	mutated.CanonicalJSON = []byte(`{"type":""}`)
	mutated.Type = ""
	if got, err := BuildV2RateReservationBatch([]V2DeferredConstraint{mutated}); err == nil {
		t.Fatalf("missing signed rate type was accepted: %+v", got)
	}
}
