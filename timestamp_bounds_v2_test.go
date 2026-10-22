package ratify

import (
	"bytes"
	"strconv"
	"testing"
)

// Wire timestamps are bounded at decode (SPEC-v2 §2.5): the last second of
// year 9999 decodes, one second later and negative values are malformed
// before any signature or claim work.
func TestV2WireTimestampDomainAtDecode(t *testing.T) {
	issuerPub, issuerKey, _ := GenerateHybridKeypair()
	subjectPub, _, _ := GenerateHybridKeypair()
	issuerID, _ := KeyIDV2(issuerPub)
	subjectID, _ := KeyIDV2(subjectPub)
	cert, err := SignDelegationCertV2(&DelegationCertV2{Version: 2, CertID: "c", IssuerID: issuerID, IssuerPubKey: issuerPub,
		SubjectID: subjectID, SubjectPubKey: subjectPub, Scope: []string{"data:read"}, Constraints: []ConstraintV2{},
		IssuedAt: 1, ExpiresAt: V2MaxTimestampSeconds}, issuerKey)
	if err != nil {
		t.Fatalf("certificate at the timestamp bound must sign: %v", err)
	}
	wire, err := EncodeDelegationCertV2(cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDelegationCertV2(wire); err != nil {
		t.Fatalf("expires_at = %d must decode: %v", V2MaxTimestampSeconds, err)
	}
	maxText := []byte(`"expires_at":` + strconv.FormatInt(V2MaxTimestampSeconds, 10))
	for _, replacement := range []string{strconv.FormatInt(V2MaxTimestampSeconds+1, 10), "-1"} {
		mutated := bytes.Replace(wire, maxText, []byte(`"expires_at":`+replacement), 1)
		if _, err := DecodeDelegationCertV2(mutated); V2ErrorClassOf(err) != V2ErrMalformed {
			t.Fatalf("expires_at %s: class %q (%v), want malformed", replacement, V2ErrorClassOf(err), err)
		}
	}
}

// Request context is validated with the verification request before claim
// (SPEC-v2 §5.2); invalid supplied values are configuration_invalid.
func TestV2RequestContextValidation(t *testing.T) {
	cases := []struct {
		name string
		ctx  ConstraintContextV2
		ok   bool
	}{
		{"absent", ConstraintContextV2{}, true},
		{"amount zero", ConstraintContextV2{HasAmount: true, RequestedCurrency: "USD"}, true},
		{"amount at safe bound", ConstraintContextV2{HasAmount: true, RequestedAmountMicros: maxSafeInteger, RequestedCurrency: "EUR"}, true},
		{"amount negative", ConstraintContextV2{HasAmount: true, RequestedAmountMicros: -1, RequestedCurrency: "USD"}, false},
		{"amount above safe bound", ConstraintContextV2{HasAmount: true, RequestedAmountMicros: maxSafeInteger + 1, RequestedCurrency: "USD"}, false},
		{"currency lowercase", ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 1, RequestedCurrency: "usd"}, false},
		{"currency missing", ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 1}, false},
		{"amount without flag", ConstraintContextV2{RequestedAmountMicros: 1, RequestedCurrency: "USD"}, false},
		{"resource", ConstraintContextV2{HasResource: true, RequestedResourceID: "customer/1", RequestedPath: "/a/../b"}, true},
		{"resource invalid utf-8", ConstraintContextV2{HasResource: true, RequestedResourceID: "\xff"}, false},
		{"resource too long", ConstraintContextV2{HasResource: true, RequestedResourceID: string(bytes.Repeat([]byte("r"), MaxIdentifierLengthBytes+1))}, false},
		{"path without flag", ConstraintContextV2{RequestedPath: "/a"}, false},
	}
	for _, tc := range cases {
		err := validateV2RequestContext(tc.ctx)
		if tc.ok != (err == nil) || err != nil && V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Errorf("%s: err = %v (class %q)", tc.name, err, V2ErrorClassOf(err))
		}
	}
}
