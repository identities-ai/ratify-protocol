// Package mcp is the client side of the Ratify Verify MCP server: it signs
// the delegated-authority proof each tool call carries, answers the console's
// connect challenge with a proof of possession of the agent key, and parses
// the configuration the console hands out.
//
// Preview. This package talks to the managed Verify service. It is not part
// of SPEC-v2 conformance, and its API may change before it is declared
// stable. Every hash is the normative SPEC-v2 operation and session context
// construction; this package only decides which values go in.
//
// Nothing here signs caller-chosen bytes. A tool-call proof is a SPEC-v2
// challenge presentation whose session context the signer recomputes from
// the call it was asked to make and the pinned configuration, never from a
// hash the server supplies.
package mcp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

const (
	// Action is the receiver-configuration action of every tool operation.
	Action = "mcp.tools/call"
	// ProofMetaKey is the params._meta key that carries the proof envelope.
	ProofMetaKey = "com.ratifyprotocol/proof"
	// ProtocolVersion is the MCP revision the hosted endpoint speaks.
	ProtocolVersion = "2026-07-28"
	// MinChallengeSecondsLeft is the least lifetime a challenge must have
	// left, by the signer's clock, for the signer to sign it.
	MinChallengeSecondsLeft = 10
	// ConnectPossessionDomain separates the connect proof of possession from
	// every per-call session context.
	ConnectPossessionDomain = "ratify-verify-mcp/connect-possession/v1"
)

// Tool is one hosted tool and the exact custom scope it requires.
type Tool struct {
	Name  string
	Scope string
}

var tools = []Tool{
	{"get_metrics", "custom:verify.metrics:read"},
	{"list_decisions", "custom:verify.decisions:read"},
	{"get_decision", "custom:verify.decisions:read"},
	{"list_events", "custom:verify.events:read"},
	{"list_agents", "custom:verify.agents:read"},
	{"list_evidence", "custom:verify.evidence:read"},
	{"get_evidence_package", "custom:verify.evidence:read"},
}

// Tools returns the hosted tools in a fixed order.
func Tools() []Tool { return append([]Tool(nil), tools...) }

// ToolScope returns the scope a tool requires.
func ToolScope(name string) (string, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t.Scope, true
		}
	}
	return "", false
}

// PayloadDigest is SHA-256 of the canonical argument bytes.
func PayloadDigest(canonicalArguments []byte) []byte {
	sum := sha256.Sum256(canonicalArguments)
	return sum[:]
}

// PayloadDigestText is the sha256:<hex> form the challenge request carries.
func PayloadDigestText(digest []byte) string {
	return "sha256:" + hex.EncodeToString(digest)
}

// RequestHash is the SPEC-v2 operation context of one tool call: the tool's
// scope, the operation "mcp.tools/call:<tool>", the connection ID as
// resource, the endpoint audience as requested path, and the argument
// digest.
func RequestHash(tool, connectionID, audience string, payloadDigest []byte) ([]byte, error) {
	scope, ok := ToolScope(tool)
	if !ok {
		return nil, fmt.Errorf("mcp: unknown tool")
	}
	return ratify.BuildOperationContextV2(ratify.OperationContextV2Inputs{
		RequiredScope: scope, Operation: Action + ":" + tool, ResourceID: connectionID,
		RequestedPath: audience, PayloadDigest: payloadDigest,
	})
}

// SessionContext is the SPEC-v2 session context a tool-call proof signs.
// The session ID is the connection ID.
func SessionContext(verifierID, workspaceID, agentID, connectionID, invocationID string, requestHash []byte) ([]byte, error) {
	return ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{
		VerifierID: verifierID, WorkspaceID: workspaceID, AgentID: agentID,
		SessionID: connectionID, InvocationID: invocationID, RequestHash: requestHash,
	})
}

// ConnectPossessionContext is the 32-byte session context of the connect
// proof of possession: SHA-256 of ConnectPossessionDomain followed by the
// workspace ID, receiver ID, audience, challenge ID, and agent key ID, each
// prefixed with its 8-byte big-endian length.
func ConnectPossessionContext(workspaceID, receiverID, audience, challengeID, agentID string) []byte {
	h := sha256.New()
	h.Write([]byte(ConnectPossessionDomain))
	for _, field := range []string{workspaceID, receiverID, audience, challengeID, agentID} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		h.Write(n[:])
		h.Write([]byte(field))
	}
	return h.Sum(nil)
}
