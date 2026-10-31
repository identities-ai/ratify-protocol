package ratify

import (
	"slices"
	"sort"
	"strings"
	"testing"
)

// Vocabulary is the public face of validScopes: complete, sorted, and a
// defensive copy. UI consumers derive their scope lists from it, so any
// mismatch with the internal vocabulary is a real drift bug.
func TestVocabularyMatchesValidScopes(t *testing.T) {
	v := Vocabulary()

	if len(v) != len(validScopes) {
		t.Fatalf("Vocabulary() has %d scopes, validScopes has %d", len(v), len(validScopes))
	}
	if !sort.StringsAreSorted(v) {
		t.Error("Vocabulary() must be sorted")
	}
	for _, s := range v {
		if !validScopes[s] {
			t.Errorf("Vocabulary() contains %q which is not in validScopes", s)
		}
	}

	// Defensive copy: mutating the returned slice must not affect a fresh call.
	v[0] = "tampered:scope"
	if Vocabulary()[0] == "tampered:scope" {
		t.Error("Vocabulary() must return a fresh copy, not shared backing storage")
	}
}

func TestV2ScopeValidationKeepsV1RulesStable(t *testing.T) {
	if err := ValidateScopes([]string{"custom:*"}); err != nil {
		t.Fatalf("v1 scope validation changed unexpectedly: %v", err)
	}
	if err := ValidateScopesV2([]string{"custom:*"}); err == nil {
		t.Fatal("v2 accepted custom:*")
	}
	if err := ValidateScopesV2([]string{"custom:inventory:read"}); err != nil {
		t.Fatalf("v2 rejected a custom extension scope: %v", err)
	}
	if err := ValidateScopesV2([]string{"execute:tool", "execute:tool"}); err == nil {
		t.Fatal("v2 accepted a duplicate scope")
	}
	if err := ValidateRequiredScopeV2("execute:tool"); err != nil {
		t.Fatalf("v2 rejected a canonical required scope: %v", err)
	}
	for _, scope := range []string{"", "custom:", "custom:*", "data:*", "data:read:all", "custom:\xff", "custom:" + strings.Repeat("a", MaxScopeLengthBytes-len("custom:")+1)} {
		if err := ValidateRequiredScopeV2(scope); err == nil {
			t.Errorf("v2 accepted invalid required scope %q", scope)
		}
	}
}

// TestV2CustomRequiredScopeIsExact pins SPEC-v2 §2.4: one exact custom:
// scope may be requested, matched by byte equality against the effective
// delegation scope. It is never a wildcard family, never case-folded, and
// never satisfied by a canonical grant.
func TestV2CustomRequiredScopeIsExact(t *testing.T) {
	for _, scope := range []string{"custom:invoice:read", "custom:infra:provision", "custom:" + strings.Repeat("a", MaxScopeLengthBytes-len("custom:"))} {
		if err := ValidateRequiredScopeV2(scope); err != nil {
			t.Errorf("v2 rejected exact custom required scope %q: %v", scope, err)
		}
	}
	effective := IntersectScopes([]string{"custom:infra:provision", "data:read"}, []string{"custom:infra:provision", "data:*"})
	if !slices.Contains(effective, "custom:infra:provision") {
		t.Fatal("exact custom grant did not survive the chain intersection")
	}
	for _, other := range []string{"custom:infra:Provision", "custom:infra", "custom:infra:provision:all"} {
		if slices.Contains(effective, other) {
			t.Errorf("custom required scope %q matched a differently spelled grant", other)
		}
	}
	if slices.Contains(IntersectScopes([]string{"data:*"}), "custom:infra:provision") {
		t.Fatal("a canonical wildcard granted a custom scope")
	}
}
