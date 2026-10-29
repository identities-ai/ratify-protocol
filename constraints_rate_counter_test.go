package ratify

import (
	"errors"
	"testing"
	"time"
)

// A rate counter that cannot answer (a negative count, for example a storage
// error mapped to -1) must fail closed as constraint_unverifiable, never be
// read as "no invocations in the window". The Rust, C, TypeScript and Python
// v1 SDKs apply the same rule.
func TestMaxRateNegativeCounterFailsClosed(t *testing.T) {
	c := Constraint{Type: ConstraintMaxRate, Count: 1, WindowS: 60}
	for _, n := range []int{-1, -1 << 31} {
		ctx := VerifierContext{InvocationsInWindow: func(string, int64) int { return n }}
		err := evaluateConstraint(c, "cert", ctx, time.Unix(1800000000, 0))
		// verify.go routes to constraint_unverifiable on this error type.
		var u unverifiableError
		if !errors.As(err, &u) {
			t.Fatalf("count %d: got %v, want constraint_unverifiable", n, err)
		}
	}
	ctx := VerifierContext{InvocationsInWindow: func(string, int64) int { return 0 }}
	if err := evaluateConstraint(c, "cert", ctx, time.Unix(1800000000, 0)); err != nil {
		t.Fatalf("count 0 under a limit of 1: %v", err)
	}
}
