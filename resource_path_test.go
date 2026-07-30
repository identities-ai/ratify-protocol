package ratify

import (
	"bytes"
	"strings"
	"testing"
)

type testEntity struct {
	id   string
	pub  HybridPublicKey
	priv HybridPrivateKey
}

func testKeypair(t *testing.T, _ byte) testEntity {
	t.Helper()
	pub, priv, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return testEntity{id: DeriveID(pub), pub: pub, priv: priv}
}

func signHybridForTest(data []byte, priv HybridPrivateKey) (HybridSignature, error) {
	return signBoth(data, priv)
}

func TestNormalizeResourcePath(t *testing.T) {
	valid := map[string]string{
		"/":                  "/",
		"/docs":              "/docs",
		"/docs/":             "/docs",
		"/docs/setup/g.md":   "/docs/setup/g.md",
		"/docs/%2e%2e/notes": "/docs/%2e%2e/notes", // % is a literal byte
		"/a b/c":             "/a b/c",
		"/UPPER/Case":        "/UPPER/Case", // byte-exact; no case folding
	}
	for in, want := range valid {
		got, err := NormalizeResourcePath(in)
		if err != nil {
			t.Errorf("NormalizeResourcePath(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeResourcePath(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"",             // empty
		"docs",         // no leading slash
		"docs/",        // no leading slash
		"/docs/../x",   // dot-segment
		"/./x",         // dot-segment
		"/..",          // dot-segment
		"/a//b",        // empty interior segment
		"/docs//",      // empty segment after one-trailing-slash trim
		"//",           // empty segment
		"/a\\b",        // backslash
		"\\docs",       // backslash, no leading slash
		"/a\x00b",      // NUL
		"/docs/./g.md", // dot-segment mid-path
	}
	for _, in := range invalid {
		if _, err := NormalizeResourcePath(in); err == nil {
			t.Errorf("NormalizeResourcePath(%q): expected error, got nil", in)
		}
	}
}

func TestResourcePathMatches(t *testing.T) {
	cases := []struct {
		prefix, path string
		want         bool
	}{
		{"/docs", "/docs", true},
		{"/docs", "/docs/a.md", true},
		{"/docs/", "/docs", true},   // trailing slash trims
		{"/docs", "/docs/", true},   // both directions
		{"/", "/anything", true},    // root matches everything
		{"/", "/", true},            // root matches root
		{"/docs", "/docs-old", false},  // segment boundary, not string prefix
		{"/docs", "/docsx/a", false},   // segment boundary
		{"/docs", "/doc", false},       // shorter
		{"/docs", "/", false},          // parent of prefix
		{"/src/security", "/src", false}, // narrower prefix does not match wider path
		{"/docs", "/docs/../x", false},   // invalid path never matches
		{"/docs/../x", "/docs", false},   // invalid prefix never matches
	}
	for _, c := range cases {
		if got := ResourcePathMatches(c.prefix, c.path); got != c.want {
			t.Errorf("ResourcePathMatches(%q, %q) = %v, want %v", c.prefix, c.path, got, c.want)
		}
	}
}

func TestValidateResourceConstraints(t *testing.T) {
	rp := func(id, prefix string) Constraint {
		return Constraint{Type: ConstraintResourcePath, ResourceID: id, PathPrefix: prefix}
	}

	ok := [][]Constraint{
		{},
		{rp("git:github.com/acme/widgets", "/docs")},
		{rp("git:github.com/acme/widgets", "")}, // whole resource
		{rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/src/security")}, // nested
		{rp("git:github.com/acme/widgets", ""), rp("git:github.com/acme/widgets", "/docs")},             // absent orders as /
		{{Type: ConstraintGeoCircle, Lat: 1, Lon: 1, RadiusM: 5}},                                       // non-resource untouched
	}
	for i, cs := range ok {
		if err := ValidateResourceConstraints(cs); err != nil {
			t.Errorf("case %d: unexpected issuance rejection: %v", i, err)
		}
	}

	bad := [][]Constraint{
		{rp("", "/docs")}, // empty resource_id
		{rp(strings.Repeat("x", MaxIdentifierLengthBytes+1), "")},                                    // oversized id
		{rp("git:github.com/acme/widgets", "docs")},                                                  // invalid prefix
		{rp("git:github.com/acme/widgets", "/docs"), rp("git:github.com/acme/other", "/docs")},       // different resources
		{rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/docs")},      // incomparable prefixes
	}
	for i, cs := range bad {
		if err := ValidateResourceConstraints(cs); err == nil {
			t.Errorf("bad case %d: expected issuance rejection, got nil", i)
		}
	}
}

func TestValidateParamsValue(t *testing.T) {
	ok := []any{
		nil, true, "s", int64(5), float64(42), // integral float64 = wire integer
		float64(-9007199254740991),
		[]any{int64(1), "two", nil},
		map[string]any{"a": int64(1), "b": []any{true}},
	}
	for i, v := range ok {
		if err := ValidateParamsValue(v, 0); err != nil {
			t.Errorf("ok case %d (%v): unexpected error %v", i, v, err)
		}
	}

	bad := []any{
		float64(1.5),                  // non-integer number
		float64(9007199254740993),     // beyond safe range
		int64(9007199254740992),       // beyond safe range
		uint64(1) << 60,               // beyond safe range
		[]byte{1},                     // raw bytes
		map[string]any{"a": 1.25},     // nested float
		[]any{[]any{[]any{1.5}}},      // nested float in arrays
	}
	for i, v := range bad {
		if err := ValidateParamsValue(v, 0); err == nil {
			t.Errorf("bad case %d (%v): expected error, got nil", i, v)
		}
	}

	// Nesting bound: a chain of arrays deeper than MaxJSONNestingDepth.
	deep := any("leaf")
	for i := 0; i < MaxJSONNestingDepth+1; i++ {
		deep = []any{deep}
	}
	if err := ValidateParamsValue(deep, 0); err == nil {
		t.Errorf("expected nesting-depth rejection")
	}
}

func TestIssueDelegationRejectsUnsatisfiableAndParamsOnCanonical(t *testing.T) {
	root, agent := testKeypair(t, 0x51), testKeypair(t, 0x52)

	base := DelegationCert{
		CertID: "t-issue-1", Version: ProtocolVersion,
		IssuerID: root.id, IssuerPubKey: root.pub,
		SubjectID: agent.id, SubjectPubKey: agent.pub,
		Scope: []string{ScopeFilesWrite}, IssuedAt: 1000, ExpiresAt: 2000,
	}

	cert := base
	cert.Constraints = []Constraint{
		{Type: ConstraintResourcePath, ResourceID: "r1", PathPrefix: "/docs"},
		{Type: ConstraintResourcePath, ResourceID: "r2", PathPrefix: "/docs"},
	}
	if err := IssueDelegation(&cert, root.priv); err == nil {
		t.Fatal("expected rejection of different-resource constraint pair")
	}
	if err := IssueDelegationUnchecked(&cert, root.priv); err != nil {
		t.Fatalf("unchecked issuance should sign anything structurally signable: %v", err)
	}

	cert2 := base
	cert2.Constraints = []Constraint{{Type: ConstraintGeoCircle, Lat: 1, Lon: 1, RadiusM: 5, Params: map[string]any{"x": int64(1)}}}
	if err := IssueDelegation(&cert2, root.priv); err == nil {
		t.Fatal("expected rejection of params on a canonical constraint type")
	}

	cert3 := base
	cert3.Constraints = []Constraint{{Type: "com.example.limit", Params: map[string]any{"max": 1.5}}}
	if err := IssueDelegation(&cert3, root.priv); err == nil {
		t.Fatal("expected rejection of a float params value")
	}
}

func TestDecodeProofBundleLimits(t *testing.T) {
	// Oversized payload is rejected before parsing: even garbage bytes of
	// the right size never reach the JSON parser, and the error names the
	// bundle limit.
	oversized := bytes.Repeat([]byte("x"), MaxProofBundleBytes+1)
	if _, err := DecodeProofBundle(oversized); err == nil || !strings.Contains(err.Error(), "MAX_PROOF_BUNDLE_BYTES") {
		t.Fatalf("expected pre-parse size rejection, got %v", err)
	}

	// Nesting beyond MaxJSONNestingDepth is rejected during parse.
	deep := strings.Repeat("[", MaxJSONNestingDepth+1) + strings.Repeat("]", MaxJSONNestingDepth+1)
	if err := CheckWireJSON([]byte(deep)); err == nil || !strings.Contains(err.Error(), "MAX_JSON_NESTING_DEPTH") {
		t.Fatalf("expected nesting-depth rejection, got %v", err)
	}
}

func TestVerificationReceiptCodecRoundTrip(t *testing.T) {
	verifier := testKeypair(t, 0x53)

	r := &VerificationReceipt{
		Version:     ProtocolVersion,
		VerifierID:  verifier.id,
		VerifierPub: verifier.pub,
		BundleHash:  bytes.Repeat([]byte{0xAB}, 32),
		Decision:    "revoked",
		AgentID:     "b4a4c71795d676b69f454881a8300000",
		ErrorReason: "delegation certificate has been revoked",
		VerifiedAt:  1800000000,
		PrevHash:    make([]byte, 32),
	}
	signBytes, err := VerificationReceiptSignBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signHybridForTest(signBytes, verifier.priv)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = sig

	encoded, err := EncodeVerificationReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeVerificationReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reEncoded, err := EncodeVerificationReceipt(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reEncoded) {
		t.Fatal("receipt round-trip is not byte-identical")
	}

	// Negative wire: truncated hash.
	bad := *r
	bad.BundleHash = bad.BundleHash[:16]
	badBytes, err := EncodeVerificationReceipt(&bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeVerificationReceipt(badBytes); err == nil {
		t.Fatal("expected rejection of a 16-byte bundle_hash")
	}

	// Negative wire: unknown field.
	tampered := bytes.Replace(encoded, []byte(`"version":`), []byte(`"versionx":1,"version":`), 1)
	if _, err := DecodeVerificationReceipt(tampered); err == nil {
		t.Fatal("expected rejection of an unknown field")
	}
}
