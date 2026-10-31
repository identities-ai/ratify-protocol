package ratify

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Unregistered codes can never select a signing transcript or ML-DSA context,
// and verification under one is classified as unsupported_object_type.
func TestV2UnregisteredObjectCodesAreRejected(t *testing.T) {
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig := HybridSignature{Ed25519: make([]byte, 64), MLDSA65: make([]byte, 3309)}
	for _, code := range []uint16{0x0000, 0x000a, 0xffff} {
		if _, err := v2SigningMessage(v2ObjectType(code), []byte("{}")); err == nil {
			t.Errorf("code %04x produced a signing message", code)
		}
		if _, err := v2MLDSAContext(v2ObjectType(code)); err == nil {
			t.Errorf("code %04x produced an ML-DSA context", code)
		}
		if got := V2ErrorClassOf(verifyV2Statement(v2ObjectType(code), []byte("{}"), sig, pub)); got != V2ErrUnsupportedObjectType {
			t.Errorf("code %04x verify class %q", code, got)
		}
	}
}

func TestV2ErrorClassOfPreservesMessagesAndWrapping(t *testing.T) {
	base := v2Errorf(V2ErrKeyIDMismatch, "key ID does not match complete public key")
	wrapped := fmt.Errorf("delegation 1: %w", base)
	if got := V2ErrorClassOf(wrapped); got != V2ErrKeyIDMismatch {
		t.Fatalf("wrapped class %q", got)
	}
	if wrapped.Error() != "delegation 1: key ID does not match complete public key" {
		t.Fatalf("message changed: %q", wrapped.Error())
	}
	if got := V2ErrorClassOf(v2Classify(V2ErrMalformed, wrapped)); got != V2ErrKeyIDMismatch {
		t.Fatalf("an existing class was overwritten: %q", got)
	}
	if got := V2ErrorClassOf(errors.New("plain")); got != V2ErrUnclassified {
		t.Fatalf("unclassified error reported %q", got)
	}
	if got := V2ErrorClassOf(fmt.Errorf("x: %w", ErrV2ClaimProofConflict)); got != V2ErrClaimReplay {
		t.Fatalf("claim conflict class %q", got)
	}
	if V2ErrorClassOf(nil) != "" {
		t.Fatal("nil error must have no class")
	}
}

// SPEC-v2 §2.7 is the closed, shared error-class list. The classes declared
// in errors_v2.go (other than the local "unclassified" sentinel) must equal
// the classes named in the first column of that table, and the stated count.
func TestV2ErrorClassesMatchSpecTable(t *testing.T) {
	spec, err := os.ReadFile("SPEC-v2.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)
	start := strings.Index(text, "### 2.7 Error classes")
	end := strings.Index(text, "## 3. Typed signing contract")
	if start < 0 || end < start {
		t.Fatal("SPEC-v2.md has no §2.7 error-class table")
	}
	section := text[start:end]
	fromSpec := map[string]bool{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		first := strings.Split(line, "|")[1]
		for _, m := range regexp.MustCompile("`([a-z_0-9]+)`").FindAllStringSubmatch(first, -1) {
			fromSpec[m[1]] = true
		}
	}
	source, err := os.ReadFile("errors_v2.go")
	if err != nil {
		t.Fatal(err)
	}
	fromCode := map[string]bool{}
	for _, m := range regexp.MustCompile(`V2ErrorClass = "([a-z_0-9]+)"`).FindAllStringSubmatch(string(source), -1) {
		if m[1] != string(V2ErrUnclassified) {
			fromCode[m[1]] = true
		}
	}
	for class := range fromCode {
		if !fromSpec[class] {
			t.Errorf("class %q is declared in errors_v2.go but missing from SPEC-v2 §2.7", class)
		}
	}
	for class := range fromSpec {
		if !fromCode[class] {
			t.Errorf("class %q is in SPEC-v2 §2.7 but not declared in errors_v2.go", class)
		}
	}
	if want := fmt.Sprintf("The list has %d classes.", len(fromCode)); !strings.Contains(section, want) {
		t.Errorf("SPEC-v2 §2.7 does not state %q", want)
	}
}
