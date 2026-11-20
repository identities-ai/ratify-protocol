package mcpvectors

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/mcp"
)

type contextCase struct {
	Name           string `json:"name"`
	WorkspaceID    string `json:"workspace_id"`
	ReceiverID     string `json:"receiver_id"`
	Audience       string `json:"audience"`
	ChallengeID    string `json:"challenge_id"`
	AgentID        string `json:"agent_id"`
	SessionContext string `json:"session_context"`
}

type parsedToken struct {
	ChallengeID string `json:"challenge_id"`
	Challenge   string `json:"challenge"`
	IssuedAt    int64  `json:"issued_at"`
	WorkspaceID string `json:"workspace_id"`
	ReceiverID  string `json:"receiver_id"`
	Audience    string `json:"audience"`
	VerifierID  string `json:"verifier_id"`
}

type possession struct {
	ConnectChallengeID string `json:"connect_challenge_id"`
	PossessionProof    string `json:"possession_proof"`
}

type proofCase struct {
	Name           string      `json:"name"`
	Token          string      `json:"token"`
	Parsed         parsedToken `json:"parsed"`
	SessionContext string      `json:"session_context"`
	Expected       possession  `json:"expected"`
}

type invalidToken struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

type connectFile struct {
	Version       int            `json:"version"`
	Description   string         `json:"description"`
	Domain        string         `json:"domain"`
	TokenPrefix   string         `json:"token_prefix"`
	Contexts      []contextCase  `json:"contexts"`
	AgentKey      keyEntry       `json:"agent_key"`
	Proofs        []proofCase    `json:"proofs"`
	InvalidTokens []invalidToken `json:"invalid_tokens"`
}

func token(payload any) string {
	return mcp.ConnectTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(compact(payload)))
}

func decodeB64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil
}

func (g *gen) connect() (any, error) {
	f := connectFile{
		Version: 1,
		Description: "Verify MCP connect proof of possession (preview). session_context = SHA-256(domain || lp(workspace_id) || " +
			"lp(receiver_id) || lp(audience) || lp(challenge_id) || lp(agent_id)), lp = 8-byte big-endian length then UTF-8 bytes. " +
			"For each proof: parse token to parsed, sign with agent_key, and compare expected.possession_proof as in tool-call.json " +
			"(replace the ml_dsa_65 component of challenge_sig, then require identical bytes; both must verify). The bundle has no " +
			"delegations, challenge and challenge_at from the token, and verifier_id from the token. Every invalid_tokens entry must be refused.",
		Domain: mcp.ConnectPossessionDomain, TokenPrefix: mcp.ConnectTokenPrefix, AgentKey: g.agent.entry(),
	}
	for _, c := range []contextCase{
		{Name: "documentation-audience", WorkspaceID: workspaceID, ReceiverID: receiverID, Audience: audience,
			ChallengeID: "8b1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f", AgentID: strings.Repeat("2", 64)},
		{Name: "fixture-agent-key", WorkspaceID: "00000000-0000-4000-8000-000000000001", ReceiverID: "00000000-0000-5000-8000-000000000002",
			Audience: "https://verify.example:8443/mcp", ChallengeID: "00000000-0000-4000-8000-000000000003", AgentID: g.agent.id},
	} {
		c.SessionContext = hex.EncodeToString(mcp.ConnectPossessionContext(c.WorkspaceID, c.ReceiverID, c.Audience, c.ChallengeID, c.AgentID))
		f.Contexts = append(f.Contexts, c)
	}
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	payload := map[string]any{
		"challenge_id": "8b1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f", "challenge": b64(challenge), "issued_at": int64(1790000000),
		"workspace_id": workspaceID, "receiver_id": receiverID, "audience": audience, "verifier_id": verifierID,
	}
	for _, c := range []struct {
		name string
		p    map[string]any
	}{
		{"console-token", payload},
		{"port-audience", with(with(payload, "audience", "https://verify.example:8443/mcp"), "challenge_id", "00000000-0000-4000-8000-000000000003")},
	} {
		tok := token(c.p)
		parsed, err := mcp.ParseConnectToken(tok)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		proof, err := mcp.ProvePossessionWithSigner(context.Background(), tok, detSigner{g.agent})
		if err != nil {
			return nil, err
		}
		sess := mcp.ConnectPossessionContext(parsed.WorkspaceID, parsed.ReceiverID, parsed.Audience, parsed.ChallengeID, g.agent.id)
		if err := checkBundle(proof.PossessionProof, g.agent.id, sess, 0); err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		f.Proofs = append(f.Proofs, proofCase{c.name, tok,
			parsedToken{parsed.ChallengeID, b64(parsed.Challenge), parsed.IssuedAt, parsed.WorkspaceID, parsed.ReceiverID, parsed.Audience, parsed.VerifierID},
			hex.EncodeToString(sess), possession{proof.ConnectChallengeID, proof.PossessionProof}})
	}
	valid := token(payload)
	body := strings.TrimPrefix(valid, mcp.ConnectTokenPrefix)
	if len(body)%4 == 0 || len(body)%4 == 1 {
		return nil, fmt.Errorf("token body length leaves no trailing bits")
	}
	// Flip the lowest bit of the last character: same leading bytes, but the
	// discarded trailing bits are no longer zero.
	last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", body[len(body)-1])
	nonCanonical := mcp.ConnectTokenPrefix + body[:len(body)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last^1])
	invalid := []invalidToken{
		{"wrong-prefix", "ratify-mcp-connect-2." + body},
		{"no-prefix", body},
		{"padded-body", valid + strings.Repeat("=", (4-len(body)%4)%4)},
		{"standard-alphabet", mcp.ConnectTokenPrefix + "+" + body[1:]},
		{"non-canonical-trailing-bits", nonCanonical},
		{"too-long", mcp.ConnectTokenPrefix + strings.Repeat("A", mcp.MaxConnectTokenLength)},
		{"body-not-json", mcp.ConnectTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte("not json"))},
		{"body-array", token([]any{payload})},
		{"extra-field", token(with(payload, "expires_at", "2026-11-19T00:00:00Z"))},
	}
	for _, field := range []string{"challenge_id", "challenge", "issued_at", "workspace_id", "receiver_id", "audience", "verifier_id"} {
		invalid = append(invalid, invalidToken{"missing-" + strings.ReplaceAll(field, "_", "-"), token(with(payload, field, nil))})
	}
	for _, c := range []struct {
		name, field string
		value       any
	}{
		{"issued-at-zero", "issued_at", 0},
		{"issued-at-negative", "issued_at", -1},
		{"issued-at-string", "issued_at", "1790000000"},
		{"challenge-31-bytes", "challenge", b64(challenge[:31])},
		{"challenge-url-alphabet", "challenge", base64.URLEncoding.EncodeToString(append([]byte{0xfb, 0xff}, challenge[2:]...))},
		{"audience-without-mcp-path", "audience", endpoint},
		{"audience-http", "audience", "http://verify.example/mcp"},
		{"audience-uppercase-host", "audience", "https://Verify.example/mcp"},
		{"verifier-uppercase", "verifier_id", strings.Repeat("A", 64)},
		{"receiver-not-uuid", "receiver_id", "ratify-verify-mcp"},
		{"workspace-uppercase", "workspace_id", strings.ToUpper(workspaceID)},
		{"challenge-id-number", "challenge_id", 8},
	} {
		invalid = append(invalid, invalidToken{c.name, token(with(payload, c.field, c.value))})
	}
	for _, c := range invalid {
		if _, err := mcp.ParseConnectToken(c.Token); err == nil {
			return nil, fmt.Errorf("invalid token %s was accepted", c.Name)
		}
	}
	f.InvalidTokens = invalid
	return f, nil
}
