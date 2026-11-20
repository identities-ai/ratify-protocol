package toolversion

import "testing"

// A release build's stamped version always wins; without it the tool must
// still print something, so go install users can tell which release they run.
func TestString(t *testing.T) {
	if got := String("v2.0.0-beta.9"); got != "v2.0.0-beta.9" {
		t.Fatalf("stamped version not used: %q", got)
	}
	if got := String("dev"); got == "" {
		t.Fatal("empty version")
	}
}
