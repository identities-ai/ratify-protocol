package ratify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	operationContextV2DomainTag = "ratify/operation-context/v2"
	sessionContextV2DomainTag   = "ratify/session-context/v2"
)

var (
	protocolV2KeyIDPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	protocolV2WorkspacePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// DecodePayloadDigest converts the Verify API's canonical sha256: text form
// into the raw 32-byte digest used by Protocol v2 operation contexts. The
// nil represents an absent payload digest; an empty string is invalid.
func DecodePayloadDigest(encoded *string) (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	if encoded == nil {
		return nil, nil
	}
	const prefix = "sha256:"
	if !strings.HasPrefix(*encoded, prefix) || len(*encoded) != len(prefix)+2*sha256.Size || strings.ToLower(*encoded) != *encoded {
		return nil, fmt.Errorf("payload digest must be sha256: followed by 64 lowercase hexadecimal characters")
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(*encoded, prefix))
	if err != nil {
		return nil, fmt.Errorf("decode payload digest: %w", err)
	}
	return digest, nil
}

// OperationContextV2Inputs binds a requested action to a Protocol v2 proof.
// PayloadDigest is empty or the raw 32-byte SHA-256 digest, never its text form.
type OperationContextV2Inputs struct {
	RequiredScope string
	Operation     string
	ResourceID    string
	RequestedPath string
	PayloadDigest []byte
}

// SessionContextV2Inputs identifies the authenticated verifier session and
// invocation to which a Protocol v2 proof is bound.
type SessionContextV2Inputs struct {
	VerifierID   string
	WorkspaceID  string
	AgentID      string
	SessionID    string
	InvocationID string
	RequestHash  []byte
}

// BuildOperationContextV2 returns SHA-256 of the §2.2 operation-context
// preimage. It uses the v2 domain tag and leaves v1 construction unchanged.
func BuildOperationContextV2(in OperationContextV2Inputs) (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if err := ValidateRequiredScopeV2(in.RequiredScope); err != nil {
		return nil, fmt.Errorf("required scope: %w", err)
	}
	if !validProtocolV2Text(in.RequiredScope, in.Operation, in.ResourceID, in.RequestedPath) {
		return nil, fmt.Errorf("text inputs must be valid UTF-8")
	}
	if len(in.PayloadDigest) != 0 && len(in.PayloadDigest) != sha256.Size {
		return nil, fmt.Errorf("payload digest must be empty or 32 bytes")
	}
	fields := [][]byte{[]byte(in.RequiredScope), []byte(in.Operation), []byte(in.ResourceID), []byte(in.RequestedPath), in.PayloadDigest}
	preimage := protocolV2Preimage(operationContextV2DomainTag, fields)
	digest := sha256.Sum256(preimage)
	return digest[:], nil
}

// BuildSessionContextV2 returns the 32-byte §2.2 session-context digest.
func BuildSessionContextV2(in SessionContextV2Inputs) (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if !validProtocolV2Text(in.VerifierID, in.WorkspaceID, in.AgentID, in.SessionID, in.InvocationID) {
		return nil, fmt.Errorf("text inputs must be valid UTF-8")
	}
	if !protocolV2KeyIDPattern.MatchString(in.VerifierID) {
		return nil, fmt.Errorf("verifier ID must be 64 lowercase hexadecimal characters")
	}
	if !protocolV2WorkspacePattern.MatchString(in.WorkspaceID) {
		return nil, fmt.Errorf("workspace ID must be a canonical lowercase UUID")
	}
	if !protocolV2KeyIDPattern.MatchString(in.AgentID) {
		return nil, fmt.Errorf("agent ID must be 64 lowercase hexadecimal characters")
	}
	if len(in.RequestHash) != sha256.Size {
		return nil, fmt.Errorf("request hash must be 32 bytes")
	}
	fields := [][]byte{[]byte(in.VerifierID), []byte(in.WorkspaceID), []byte(in.AgentID), []byte(in.SessionID), []byte(in.InvocationID), in.RequestHash}
	preimage := protocolV2Preimage(sessionContextV2DomainTag, fields)
	digest := sha256.Sum256(preimage)
	return digest[:], nil
}

func protocolV2Preimage(domain string, fields [][]byte) []byte {
	// Domain tags are ASCII and are not length-prefixed; each following field is.
	preimage := make([]byte, 0, len(domain)+8*len(fields)+128)
	preimage = append(preimage, domain...)
	for _, field := range fields {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		preimage = append(preimage, length[:]...)
		preimage = append(preimage, field...)
	}
	return preimage
}

func validProtocolV2Text(values ...string) bool {
	for _, value := range values {
		if !utf8.ValidString(value) {
			return false
		}
	}
	return true
}
