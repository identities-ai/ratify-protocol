package ratify

import (
	"errors"
	"fmt"
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
