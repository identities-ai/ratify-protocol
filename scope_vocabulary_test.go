package ratify

import (
	"sort"
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
