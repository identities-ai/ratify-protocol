package mcp

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"unicode/utf8"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ErrChallengeRefused means the challenge response does not match the pinned
// configuration or the call, or expires too soon. Nothing is signed.
var ErrChallengeRefused = errors.New("mcp: challenge refused")

// ToolCall is one validated tool call: the tool and its canonical arguments.
// Send CanonicalArguments as params.arguments so the server computes the same
// payload digest.
type ToolCall struct {
	Tool               string
	CanonicalArguments []byte
	PayloadDigest      []byte
}

// NewToolCall validates the tool name and the JSON text of its arguments.
func NewToolCall(tool string, arguments []byte) (*ToolCall, error) {
	if _, ok := ToolScope(tool); !ok {
		return nil, ErrInvalidArguments
	}
	canonical, err := CanonicalArguments(arguments)
	if err != nil {
		return nil, err
	}
	return &ToolCall{Tool: tool, CanonicalArguments: canonical, PayloadDigest: PayloadDigest(canonical)}, nil
}

// verifiedDigest re-derives the payload digest from the call's canonical
// arguments, so a ToolCall whose fields were changed after NewToolCall can
// never make the signer bind one argument set and send another.
func (call *ToolCall) verifiedDigest() ([]byte, error) {
	if call == nil {
		return nil, ErrInvalidArguments
	}
	if _, ok := ToolScope(call.Tool); !ok {
		return nil, ErrInvalidArguments
	}
	canonical, err := CanonicalArguments(call.CanonicalArguments)
	if err != nil || !bytes.Equal(canonical, call.CanonicalArguments) || len(call.CanonicalArguments) == 0 {
		return nil, ErrInvalidArguments
	}
	digest := PayloadDigest(canonical)
	if !bytes.Equal(digest, call.PayloadDigest) {
		return nil, ErrInvalidArguments
	}
	return digest, nil
}

// ChallengeRequest is the JSON body of POST <endpoint>/challenge for call.
func (c *ClientConfig) ChallengeRequest(call *ToolCall) ([]byte, error) {
	digest, err := call.verifiedDigest()
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ConnectionID  string `json:"connection_id"`
		Tool          string `json:"tool"`
		PayloadDigest string `json:"payload_digest"`
	}{c.ConnectionID, call.Tool, PayloadDigestText(digest)})
}

// Challenge is a challenge response that CheckChallenge accepted. It can
// sign only a call to the tool, and under the configuration (verifier,
// workspace, connection), it was checked for.
type Challenge struct {
	tool         string
	verifierID   string
	workspaceID  string
	connectionID string
	challenge    []byte
	invocationID string
	issuedAt     int64
	expiresAt    int64
}

// InvocationID is the server-generated invocation the proof binds.
func (ch *Challenge) InvocationID() string { return ch.invocationID }

// ExpiresAt is the challenge expiry in Unix seconds.
func (ch *Challenge) ExpiresAt() int64 { return ch.expiresAt }

// CheckChallenge accepts the JSON response (valid UTF-8) of POST <endpoint>/challenge only
// if verifier_id and workspace_id equal the pinned values, required_scope is
// the tool's scope, invocation_id is a lowercase UUID, challenge is 32 bytes
// in canonical standard base64, issued_at and expires_at are integers with
// 0 < issued_at <= expires_at, and at least MinChallengeSecondsLeft seconds
// remain at now (Unix seconds).
func (c *ClientConfig) CheckChallenge(tool string, response []byte, now int64) (*Challenge, error) {
	scope, ok := ToolScope(tool)
	if !ok {
		return nil, ErrChallengeRefused
	}
	var msg map[string]json.RawMessage
	if !utf8.Valid(response) || json.Unmarshal(response, &msg) != nil || msg == nil {
		return nil, ErrChallengeRefused
	}
	verifier, ok1 := jsonString(msg["verifier_id"])
	workspace, ok2 := jsonString(msg["workspace_id"])
	gotScope, ok3 := jsonString(msg["required_scope"])
	invocation, ok4 := jsonString(msg["invocation_id"])
	challengeText, ok5 := jsonString(msg["challenge"])
	issued, ok6 := jsonInteger(msg["issued_at"])
	expires, ok7 := jsonInteger(msg["expires_at"])
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return nil, ErrChallengeRefused
	}
	if verifier != c.VerifierID || workspace != c.WorkspaceID || gotScope != scope || !uuidPattern.MatchString(invocation) {
		return nil, ErrChallengeRefused
	}
	challenge, ok := decodeStdBase64(challengeText)
	if !ok || len(challenge) != 32 {
		return nil, ErrChallengeRefused
	}
	// expires is within the safe range here, so the subtraction cannot wrap.
	if issued <= 0 || issued > expires || now > expires-MinChallengeSecondsLeft {
		return nil, ErrChallengeRefused
	}
	return &Challenge{tool: tool, verifierID: c.VerifierID, workspaceID: c.WorkspaceID, connectionID: c.ConnectionID,
		challenge: challenge, invocationID: invocation, issuedAt: issued, expiresAt: expires}, nil
}

// ProofEnvelope is the value of params._meta[ProofMetaKey] on tools/call.
type ProofEnvelope struct {
	ConnectionID string `json:"connection_id"`
	InvocationID string `json:"invocation_id"`
	Challenge    string `json:"challenge"`
	Bundle       string `json:"bundle"`
}

// SignToolCall signs the tool-call proof with an in-process agent key.
func SignToolCall(c *ClientConfig, agentKey ratify.HybridPrivateKey, call *ToolCall, ch *Challenge) (*ProofEnvelope, error) {
	return signToolCall(c, agentKey.Public(), call, ch, func(b *ratify.ProofBundleV2) (*ratify.ProofBundleV2, error) {
		return ratify.SignProofBundleV2(b, agentKey)
	})
}

// SignToolCallWithSigner signs the tool-call proof with an external signer.
func SignToolCallWithSigner(ctx context.Context, c *ClientConfig, signer ratify.SignerV2, call *ToolCall, ch *Challenge) (*ProofEnvelope, error) {
	return signToolCall(c, signer.PublicKeyV2(), call, ch, func(b *ratify.ProofBundleV2) (*ratify.ProofBundleV2, error) {
		return ratify.SignProofBundleV2WithSigner(ctx, b, signer)
	})
}

func signToolCall(c *ClientConfig, pub ratify.HybridPublicKey, call *ToolCall, ch *Challenge,
	sign func(*ratify.ProofBundleV2) (*ratify.ProofBundleV2, error)) (*ProofEnvelope, error) {
	if c == nil || call == nil || ch == nil || ch.tool != call.Tool || len(c.Delegations) == 0 ||
		ch.verifierID != c.VerifierID || ch.workspaceID != c.WorkspaceID || ch.connectionID != c.ConnectionID {
		return nil, ErrChallengeRefused
	}
	digest, err := call.verifiedDigest()
	if err != nil {
		return nil, err
	}
	agentID, err := ratify.KeyIDV2(pub)
	if err != nil {
		return nil, err
	}
	if c.Delegations[len(c.Delegations)-1].SubjectID != agentID {
		return nil, errors.New("mcp: the last delegation certificate is not issued to this agent key")
	}
	requestHash, err := RequestHash(call.Tool, c.ConnectionID, c.Audience, digest)
	if err != nil {
		return nil, err
	}
	session, err := SessionContext(c.VerifierID, c.WorkspaceID, agentID, c.ConnectionID, ch.invocationID, requestHash)
	if err != nil {
		return nil, err
	}
	// The configuration lists the chain root side first; a SPEC-v2 bundle
	// carries it leaf first.
	leafFirst := make([]ratify.DelegationCertV2, len(c.Delegations))
	for i, cert := range c.Delegations {
		leafFirst[len(c.Delegations)-1-i] = cert
	}
	wire, err := signPresentation(c.VerifierID, agentID, pub, leafFirst, ch.challenge, ch.issuedAt, session, sign)
	if err != nil {
		return nil, err
	}
	return &ProofEnvelope{
		ConnectionID: c.ConnectionID, InvocationID: ch.invocationID,
		Challenge: base64.StdEncoding.EncodeToString(ch.challenge), Bundle: base64.StdEncoding.EncodeToString(wire),
	}, nil
}

func signPresentation(verifierID, agentID string, pub ratify.HybridPublicKey, delegations []ratify.DelegationCertV2,
	challenge []byte, challengeAt int64, session []byte, sign func(*ratify.ProofBundleV2) (*ratify.ProofBundleV2, error)) ([]byte, error) {
	sessionCopy := append([]byte(nil), session...)
	unsigned := &ratify.ProofBundleV2{
		Version: 2, VerifierID: verifierID, AgentID: agentID, AgentPubKey: pub,
		Delegations: append([]ratify.DelegationCertV2{}, delegations...), DelegationDigest: make([]byte, sha512.Size384),
		Challenge: append([]byte(nil), challenge...), ChallengeAt: challengeAt, SessionContext: &sessionCopy,
	}
	signed, err := sign(unsigned)
	if err != nil {
		return nil, err
	}
	return ratify.EncodeProofBundleV2(signed)
}
