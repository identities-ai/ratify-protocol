package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ConnectTokenPrefix starts the one-line connect challenge the console
// issues to the owner or admin connecting an agent.
const ConnectTokenPrefix = "ratify-mcp-connect-1."

// MaxConnectTokenLength bounds a connect token.
const MaxConnectTokenLength = 4096

// ErrInvalidConnectToken means the text is not a well-formed connect token.
var ErrInvalidConnectToken = errors.New("mcp: not a ratify-mcp-connect-1 token from the console")

var base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

var connectTokenFields = []string{"audience", "challenge", "challenge_id", "issued_at", "receiver_id", "verifier_id", "workspace_id"}

// ConnectToken is a parsed connect challenge.
type ConnectToken struct {
	ChallengeID string
	Challenge   []byte
	IssuedAt    int64
	WorkspaceID string
	ReceiverID  string
	Audience    string
	VerifierID  string
}

// ParseConnectToken parses ConnectTokenPrefix followed by unpadded base64url
// of a JSON object with exactly the fields challenge_id, challenge,
// issued_at, workspace_id, receiver_id, audience, and verifier_id. IDs are
// lowercase UUIDs, verifier_id is 64 lowercase hex characters, issued_at is
// a positive integer, challenge is 32 bytes in canonical standard base64,
// and audience is an endpoint (as in ParseClientConfig) followed by "/mcp".
func ParseConnectToken(token string) (*ConnectToken, error) {
	if len(token) > MaxConnectTokenLength || !strings.HasPrefix(token, ConnectTokenPrefix) {
		return nil, ErrInvalidConnectToken
	}
	body := token[len(ConnectTokenPrefix):]
	if !base64URLPattern.MatchString(body) {
		return nil, ErrInvalidConnectToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != body {
		return nil, ErrInvalidConnectToken
	}
	var msg map[string]json.RawMessage
	if !utf8.Valid(raw) || json.Unmarshal(raw, &msg) != nil || len(msg) != len(connectTokenFields) {
		return nil, ErrInvalidConnectToken
	}
	t := &ConnectToken{}
	strs := map[string]*string{
		"challenge_id": &t.ChallengeID, "workspace_id": &t.WorkspaceID, "receiver_id": &t.ReceiverID,
		"audience": &t.Audience, "verifier_id": &t.VerifierID,
	}
	var challengeText string
	strs["challenge"] = &challengeText
	for _, name := range connectTokenFields {
		if _, ok := msg[name]; !ok {
			return nil, ErrInvalidConnectToken
		}
		if dst, ok := strs[name]; ok {
			s, ok := jsonString(msg[name])
			if !ok {
				return nil, ErrInvalidConnectToken
			}
			*dst = s
		}
	}
	issued, ok := jsonInteger(msg["issued_at"])
	if !ok || issued <= 0 {
		return nil, ErrInvalidConnectToken
	}
	t.IssuedAt = issued
	if !uuidPattern.MatchString(t.ChallengeID) || !uuidPattern.MatchString(t.WorkspaceID) ||
		!uuidPattern.MatchString(t.ReceiverID) || !hex64Pattern.MatchString(t.VerifierID) ||
		!strings.HasSuffix(t.Audience, "/mcp") || !validEndpoint(strings.TrimSuffix(t.Audience, "/mcp"), t.Audience) {
		return nil, ErrInvalidConnectToken
	}
	challenge, ok := decodeStdBase64(challengeText)
	if !ok || len(challenge) != 32 {
		return nil, ErrInvalidConnectToken
	}
	t.Challenge = challenge
	return t, nil
}

// PossessionProof is what the connect request carries besides the
// certificate: the challenge ID and the proof bundle in standard base64.
type PossessionProof struct {
	ConnectChallengeID string `json:"connect_challenge_id"`
	PossessionProof    string `json:"possession_proof"`
}

// ProvePossession signs the connect challenge with the agent key being
// connected: a SPEC-v2 proof bundle with no delegations whose challenge and
// challenge_at are the token's, and whose session context is
// ConnectPossessionContext. It never contacts the network.
func ProvePossession(token string, agentKey ratify.HybridPrivateKey) (*PossessionProof, error) {
	return provePossession(token, agentKey.Public(), func(b *ratify.ProofBundleV2) (*ratify.ProofBundleV2, error) {
		return ratify.SignProofBundleV2(b, agentKey)
	})
}

// ProvePossessionWithSigner is ProvePossession with an external signer.
func ProvePossessionWithSigner(ctx context.Context, token string, signer ratify.SignerV2) (*PossessionProof, error) {
	return provePossession(token, signer.PublicKeyV2(), func(b *ratify.ProofBundleV2) (*ratify.ProofBundleV2, error) {
		return ratify.SignProofBundleV2WithSigner(ctx, b, signer)
	})
}

func provePossession(token string, pub ratify.HybridPublicKey, sign func(*ratify.ProofBundleV2) (*ratify.ProofBundleV2, error)) (*PossessionProof, error) {
	t, err := ParseConnectToken(token)
	if err != nil {
		return nil, err
	}
	agentID, err := ratify.KeyIDV2(pub)
	if err != nil {
		return nil, err
	}
	session := ConnectPossessionContext(t.WorkspaceID, t.ReceiverID, t.Audience, t.ChallengeID, agentID)
	wire, err := signPresentation(t.VerifierID, agentID, pub, nil, t.Challenge, t.IssuedAt, session, sign)
	if err != nil {
		return nil, err
	}
	return &PossessionProof{ConnectChallengeID: t.ChallengeID, PossessionProof: base64.StdEncoding.EncodeToString(wire)}, nil
}
