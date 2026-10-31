package ratify_test

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// The released decision is the only actionable value (SPEC-v2 §6.9). These
// tests pin the API surface that keeps it unforgeable: if a change exports a
// field, adds an accessor that could carry a decision out of a committed
// outcome, or adds another constructor, they fail.

func exportedFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		if t.Field(i).IsExported() {
			out = append(out, t.Field(i).Name)
		}
	}
	return out
}

func exportedMethods(t reflect.Type) []string {
	var out []string
	for i := range t.NumMethod() {
		out = append(out, t.Method(i).Name)
	}
	return out
}

func TestV2ReleasedDecisionAndCommittedOutcomeAreOpaque(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[ratify.V2ReleasedDecision](), reflect.TypeFor[ratify.CommittedV2Outcome]()} {
		if fields := exportedFields(typ); len(fields) != 0 {
			t.Errorf("%s exports fields %v; it must be opaque", typ.Name(), fields)
		}
	}
	wantReleased := []string{"AllowHorizon", "Allowed", "ChallengeExpiresAt", "ClaimID", "Decision", "GrantedScope", "IdentityStatus", "Reason", "Receipt", "ReceiptWire", "ReleaseTime"}
	if got := exportedMethods(reflect.TypeFor[*ratify.V2ReleasedDecision]()); !slices.Equal(got, wantReleased) {
		t.Errorf("V2ReleasedDecision methods %v, want exactly %v", got, wantReleased)
	}
	// A committed outcome carries no decision: no accessor may expose one.
	wantCommitted := []string{"AllowHorizon", "ChallengeExpiresAt", "ClaimID", "ReceiptBody", "ReceiptBodyDigest"}
	if got := exportedMethods(reflect.TypeFor[*ratify.CommittedV2Outcome]()); !slices.Equal(got, wantCommitted) {
		t.Errorf("CommittedV2Outcome methods %v, want exactly %v", got, wantCommitted)
	}
}

// TestV2ReleasedDecisionHasOneConstructor scans the package source: the only
// exported function returning a released decision (directly or inside
// V2ReleaseResult) is ReleaseV2Decision, and only it builds one.
func TestV2ReleasedDecisionHasOneConstructor(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	sealed := map[string]bool{"V2ReleasedDecision": true, "V2ReleaseResult": true}
	mentions := func(n ast.Node) bool {
		found := false
		ast.Inspect(n, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && sealed[id.Name] {
				found = true
			}
			return !found
		})
		return found
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Recv == nil && fn.Name.Name == "ReleaseV2Decision" {
				continue
			}
			if fn.Name.IsExported() && fn.Type.Results != nil && mentions(fn.Type.Results) {
				t.Errorf("%s: exported %s returns a released decision; only ReleaseV2Decision may", fset.Position(fn.Pos()), fn.Name.Name)
			}
			if fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				if id, ok := lit.Type.(*ast.Ident); ok && id.Name == "V2ReleasedDecision" {
					t.Errorf("%s: %s builds a V2ReleasedDecision; only ReleaseV2Decision may", fset.Position(lit.Pos()), fn.Name.Name)
				}
				return true
			})
		}
	}
}

type v2TestClock struct {
	now   int64
	err   error
	panic bool
}

func (c v2TestClock) AuthoritativeTimeV2(context.Context) (int64, error) {
	if c.panic {
		panic("clock")
	}
	return c.now, c.err
}

func TestV2ReleasedDecisionForgeriesAreNeverAllowed(t *testing.T) {
	ctx := context.Background()
	clock := v2TestClock{now: 1800000000}
	var zero ratify.V2ReleasedDecision
	var nilDecision *ratify.V2ReleasedDecision
	if zero.Allowed(ctx, clock) || nilDecision.Allowed(ctx, clock) {
		t.Fatal("a zero or nil released decision is Allowed")
	}
	// Decoding data into the type sets nothing: it has no exported fields.
	var decoded ratify.V2ReleasedDecision
	forged := `{"ClaimID":"c","Decision":"allow","decision":"allow","Receipt":{},"ReceiptWire":"AA==","ReleaseTime":1,"ChallengeExpiresAt":9999999999,"AllowHorizon":9999999999}`
	if err := json.Unmarshal([]byte(forged), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Allowed(ctx, clock) || decoded.Decision() != "" {
		t.Fatal("a JSON-decoded released decision is Allowed")
	}
	var result ratify.V2ReleaseResult
	if err := json.Unmarshal([]byte(`{"Status":"released","Decision":`+forged+`}`), &result); err != nil {
		t.Fatal(err)
	}
	if result.Decision == nil || result.Decision.Allowed(ctx, clock) {
		t.Fatal("a JSON-decoded release result carries an Allowed decision")
	}
	if _, err := zero.Receipt(); err == nil {
		t.Fatal("a zero released decision returned a receipt")
	}
}
