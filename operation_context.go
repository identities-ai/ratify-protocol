package ratify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Domain tags for the §6.4.9 canonical constructions. Raw ASCII prefixes:
// a hash computed for one construction can never collide with the other or
// with any future tagged construction.
const (
	operationContextDomainTag = "ratify/operation-context/v1"
	sessionContextDomainTag   = "ratify/session-context/v1"
)

// OperationContext carries the inputs that identify one specific action a
// presentation authorizes (§6.4.9). Which fields are populated is
// deployment-defined — empty fields encode as zero-length and the
// construction stays well-defined.
type OperationContext struct {
	// RequiredScope is the scope the action requires (e.g. "files:write").
	RequiredScope string

	// Operation is the action/operation type (e.g. "git.push",
	// "tool.invoke").
	Operation string

	// ResourceID identifies the target resource.
	ResourceID string

	// RequestedPath is the path within the resource.
	RequestedPath string

	// PayloadDigest is empty, or exactly 32 bytes: the SHA-256 of the
	// canonical request payload, where one exists.
	PayloadDigest []byte
}

// SessionContextInputs carries the inputs that identify the session a
// presentation belongs to, plus the RequestHash binding the specific
// operation (§6.4.9). The Middleware Custody Profile (§15.2.1) requires
// all of them; other deployments populate what they have — empty string
// fields encode as zero-length.
type SessionContextInputs struct {
	// VerifierID is the verifier's identity (e.g. its public key ID).
	// Including it makes cross-verifier challenge forwarding detectable
	// at the cryptographic layer (§15.1).
	VerifierID string

	// WorkspaceID is the deployment's workspace/tenant identifier.
	WorkspaceID string

	// AgentID is the presenting agent's identity.
	AgentID string

	// SessionID identifies the session.
	SessionID string

	// InvocationID identifies the specific invocation within the session.
	InvocationID string

	// RequestHash is exactly 32 bytes — the OperationContextHash of the
	// action being authorized. A deployment with no operation-specific
	// inputs derives it from an all-empty OperationContext (still
	// well-defined, still domain-separated). Binding the session but not
	// the operation would let an intermediary attach a valid proof to
	// the wrong action inside the right session.
	RequestHash []byte
}

// lengthPrefixed appends big-endian uint64 len(field) || field to buf.
// The prefix removes concatenation ambiguity: "ab"||"c" and "a"||"bc"
// produce identical raw bytes but distinct length-prefixed bytes.
func lengthPrefixed(buf []byte, field []byte) []byte {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(field)))
	buf = append(buf, l[:]...)
	return append(buf, field...)
}

// OperationContextBytes returns the §6.4.9 operation-context preimage:
// the domain tag followed by every field length-prefixed, in canonical
// order. Errors if PayloadDigest is neither empty nor exactly 32 bytes.
func OperationContextBytes(ctx OperationContext) ([]byte, error) {
	if len(ctx.PayloadDigest) != 0 && len(ctx.PayloadDigest) != 32 {
		return nil, fmt.Errorf("payload digest must be empty or 32 bytes, got %d", len(ctx.PayloadDigest))
	}
	buf := []byte(operationContextDomainTag)
	buf = lengthPrefixed(buf, []byte(ctx.RequiredScope))
	buf = lengthPrefixed(buf, []byte(ctx.Operation))
	buf = lengthPrefixed(buf, []byte(ctx.ResourceID))
	buf = lengthPrefixed(buf, []byte(ctx.RequestedPath))
	buf = lengthPrefixed(buf, ctx.PayloadDigest)
	return buf, nil
}

// OperationContextHash returns the 32-byte request_hash: SHA-256 over the
// §6.4.9 operation-context bytes.
func OperationContextHash(ctx OperationContext) ([]byte, error) {
	b, err := OperationContextBytes(ctx)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// SessionContextBytes returns the §6.4.9 session-context preimage: the
// domain tag followed by every field length-prefixed, in canonical order.
// Errors unless RequestHash is exactly 32 bytes — use
// OperationContextHash to derive it, over an all-empty OperationContext
// when the deployment has no operation-specific inputs.
func SessionContextBytes(in SessionContextInputs) ([]byte, error) {
	if len(in.RequestHash) != 32 {
		return nil, fmt.Errorf("request hash must be exactly 32 bytes, got %d", len(in.RequestHash))
	}
	buf := []byte(sessionContextDomainTag)
	buf = lengthPrefixed(buf, []byte(in.VerifierID))
	buf = lengthPrefixed(buf, []byte(in.WorkspaceID))
	buf = lengthPrefixed(buf, []byte(in.AgentID))
	buf = lengthPrefixed(buf, []byte(in.SessionID))
	buf = lengthPrefixed(buf, []byte(in.InvocationID))
	buf = lengthPrefixed(buf, in.RequestHash)
	return buf, nil
}

// BuildSessionContext returns the 32-byte session_context: SHA-256 over
// the §6.4.9 session-context bytes. The result is what a session-bound
// deployment passes as VerifyOptions.SessionContext (and what the agent
// side includes in the challenge signing bytes, §6.4.2). Verification
// receipts and audit records bind this hash, never the preimage.
func BuildSessionContext(in SessionContextInputs) ([]byte, error) {
	b, err := SessionContextBytes(in)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}
