package mcpvectors

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/mcp"
)

type envelope struct {
	ConnectionID string `json:"connection_id"`
	InvocationID string `json:"invocation_id"`
	Challenge    string `json:"challenge"`
	Bundle       string `json:"bundle"`
}

type toolCallCase struct {
	Name               string    `json:"name"`
	Tool               string    `json:"tool"`
	ArgumentsJSON      string    `json:"arguments_json"`
	Now                int64     `json:"now"`
	ChallengeResponse  string    `json:"challenge_response"`
	CanonicalArguments string    `json:"canonical_arguments"`
	ChallengeRequest   string    `json:"challenge_request"`
	RequestHash        string    `json:"request_hash"`
	SessionContext     string    `json:"session_context"`
	Envelope           *envelope `json:"envelope,omitempty"`
}

type refusedChallenge struct {
	Name              string `json:"name"`
	Tool              string `json:"tool"`
	Now               int64  `json:"now"`
	ChallengeResponse string `json:"challenge_response"`
}

// refusedSigning is a challenge that was checked and accepted for one call
// and configuration but must not sign another.
type refusedSigning struct {
	Name                 string `json:"name"`
	CheckedTool          string `json:"checked_tool"`
	Now                  int64  `json:"now"`
	ChallengeResponse    string `json:"challenge_response"`
	SigningTool          string `json:"signing_tool"`
	SigningArgumentsJSON string `json:"signing_arguments_json"`
	SigningConfigJSON    string `json:"signing_config_json"`
}

type toolCallFile struct {
	Version           int                `json:"version"`
	Description       string             `json:"description"`
	AgentKey          keyEntry           `json:"agent_key"`
	WrongAgentKey     keyEntry           `json:"wrong_agent_key"`
	ClientConfigJSON  string             `json:"client_config_json"`
	Cases             []toolCallCase     `json:"cases"`
	RefusedChallenges []refusedChallenge `json:"refused_challenges"`
	RefusedSignings   []refusedSigning   `json:"refused_signings"`
}

func challengeBytes(seed byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)*3
	}
	return b
}

func challengeResponse(scope, invocation string, challenge []byte, issued, expires int64) map[string]any {
	return map[string]any{
		"challenge": b64(challenge), "invocation_id": invocation, "verifier_id": verifierID, "workspace_id": workspaceID,
		"required_scope": scope, "issued_at": issued, "expires_at": expires,
	}
}

func (g *gen) toolCall() (any, error) {
	cfgText := compact(g.baseConfig())
	cfg, err := mcp.ParseClientConfig([]byte(cfgText))
	if err != nil {
		return nil, err
	}
	f := toolCallFile{
		Version: 1,
		Description: "Verify MCP tool-call proofs (preview). Parse client_config_json, load agent_key from its seeds, and for each case: " +
			"canonicalize arguments_json, build challenge_request byte for byte, accept challenge_response at now, and sign. " +
			"envelope.bundle is the standard base64 of the SPEC-v2 proof bundle wire. ML-DSA-65 signing is hedged in SDKs, so compare " +
			"the produced wire with the ml_dsa_65 component of challenge_sig replaced by the expected one: the rest, including the " +
			"deterministic Ed25519 signature, must be identical; the produced and expected bundles must both verify. " +
			"The configuration's delegations are root side first; the signed bundle carries them leaf first. " +
			"Every refused_challenges response must be refused, and signing with wrong_agent_key must fail because the last " +
			"delegation is not issued to it. For each refused_signings entry: check challenge_response for checked_tool under " +
			"client_config_json at now (it is accepted), then signing a call to signing_tool with signing_arguments_json under " +
			"signing_config_json (client_config_json when empty) must fail: a checked challenge signs only the tool and the " +
			"configuration it was checked for.",
		AgentKey: g.agent.entry(), WrongAgentKey: g.other.entry(), ClientConfigJSON: cfgText,
	}
	for i, c := range []struct {
		name, tool, args, invocation string
		now                          int64
		extra                        string
	}{
		{"metrics", "get_metrics", `{}`, invocationID, now, ""},
		{"decisions-reordered", "list_decisions", `{ "limit": 20, "decision": "deny" }`, "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e", now, ""},
		{"events-unicode", "list_events", `{"types":["café \"q\" \\ b"],"limit":5}`, "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f", now, ""},
		{"exactly-minimum-lifetime-left", "get_metrics", `null`, "2d3e4f5a-6b7c-4d8e-9fa0-1b2c3d4e5f60", expiresAt - mcp.MinChallengeSecondsLeft, ""},
		{"unknown-response-field-ignored", "list_agents", `{"limit":3}`, "3e4f5a6b-7c8d-4e9f-a0b1-2c3d4e5f6071", now, "unknown"},
		{"server-supplied-hashes-ignored", "get_decision", `{"decision_id":"d-1"}`, "4f5a6b7c-8d9e-4fa0-b1c2-3d4e5f607182", now, "hashes"},
	} {
		scope, _ := mcp.ToolScope(c.tool)
		resp := challengeResponse(scope, c.invocation, challengeBytes(byte(0x10*(i+1))), issuedAt, expiresAt)
		switch c.extra {
		case "unknown":
			resp["retry_hint"] = "none"
		case "hashes":
			// A signer never uses hashes a server suggests: the expected
			// proof is computed from the call and the pinned values only.
			resp["request_hash"] = strings.Repeat("00", 32)
			resp["session_context"] = strings.Repeat("ff", 32)
			resp["payload_digest"] = "sha256:" + strings.Repeat("ab", 32)
		}
		respText := compact(resp)
		call, err := mcp.NewToolCall(c.tool, []byte(c.args))
		if err != nil {
			return nil, err
		}
		ch, err := cfg.CheckChallenge(c.tool, []byte(respText), c.now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		env, err := mcp.SignToolCallWithSigner(context.Background(), cfg, detSigner{g.agent}, call, ch)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		if _, err := mcp.SignToolCall(cfg, g.other.priv, call, ch); err == nil {
			return nil, fmt.Errorf("%s: wrong agent key signed", c.name)
		}
		req, _ := mcp.RequestHash(c.tool, connectionID, audience, call.PayloadDigest)
		sess, _ := mcp.SessionContext(verifierID, workspaceID, g.agent.id, connectionID, c.invocation, req)
		if err := checkBundle(env.Bundle, g.agent.id, sess, len(cfg.Delegations)); err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		reqBody, err := cfg.ChallengeRequest(call)
		if err != nil {
			return nil, err
		}
		f.Cases = append(f.Cases, toolCallCase{c.name, c.tool, c.args, c.now, respText, string(call.CanonicalArguments),
			string(reqBody), hex.EncodeToString(req), hex.EncodeToString(sess),
			&envelope{env.ConnectionID, env.InvocationID, env.Challenge, env.Bundle}})
	}
	metrics, _ := mcp.ToolScope("get_metrics")
	good := challengeResponse(metrics, invocationID, challengeBytes(0x10), issuedAt, expiresAt)
	refused := []struct {
		name string
		resp any
		now  int64
	}{
		{"other-verifier", with(good, "verifier_id", strings.Repeat("3", 64)), now},
		{"other-workspace", with(good, "workspace_id", "6f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e60"), now},
		{"other-scope", with(good, "required_scope", "custom:verify.decisions:read"), now},
		{"missing-scope", with(good, "required_scope", nil), now},
		{"invocation-uppercase", with(good, "invocation_id", strings.ToUpper(invocationID)), now},
		{"invocation-missing", with(good, "invocation_id", nil), now},
		{"challenge-31-bytes", with(good, "challenge", b64(challengeBytes(0x10)[:31])), now},
		{"challenge-33-bytes", with(good, "challenge", b64(append(challengeBytes(0x10), 0))), now},
		{"challenge-unpadded", with(good, "challenge", strings.TrimRight(b64(challengeBytes(0x10)), "=")), now},
		{"challenge-not-base64", with(good, "challenge", "!"+b64(challengeBytes(0x10))[1:]), now},
		{"issued-after-expiry", with(good, "issued_at", int64(expiresAt+1)), now},
		{"issued-at-zero", with(with(good, "issued_at", 0), "expires_at", 120), 50},
		{"issued-at-string", with(good, "issued_at", fmt.Sprint(issuedAt)), now},
		{"expires-at-boolean", with(good, "expires_at", true), now},
		{"expires-at-missing", with(good, "expires_at", nil), now},
		{"expires-too-soon", good, expiresAt - mcp.MinChallengeSecondsLeft + 1},
		{"expired", good, expiresAt + 1},
		{"issued-at-fraction", rawJSON(strings.Replace(compact(good), fmt.Sprintf(`"issued_at":%d`, issuedAt), fmt.Sprintf(`"issued_at":%d.0`, issuedAt), 1)), now},
		{"expires-at-exponent", rawJSON(strings.Replace(compact(good), fmt.Sprintf(`"expires_at":%d`, expiresAt), `"expires_at":1.79000022e9`, 1)), now},
		{"not-an-object", []any{good}, now},
		{"not-json", rawJSON(`{"challenge":`), now},
	}
	for _, c := range refused {
		text := compact(c.resp)
		if _, err := cfg.CheckChallenge("get_metrics", []byte(text), c.now); err == nil {
			return nil, fmt.Errorf("refused challenge %s was accepted", c.name)
		}
		f.RefusedChallenges = append(f.RefusedChallenges, refusedChallenge{c.name, "get_metrics", c.now, text})
	}
	decisions, _ := mcp.ToolScope("list_decisions")
	decisionsResp := compact(challengeResponse(decisions, invocationID, challengeBytes(0x70), issuedAt, expiresAt))
	otherConnection := compact(with(g.baseConfig(), "connection_id", "3f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e60"))
	otherVerifier := compact(with(g.baseConfig(), "verifier_id", strings.Repeat("3", 64)))
	for _, c := range []refusedSigning{
		{Name: "same-scope-other-tool", CheckedTool: "list_decisions", ChallengeResponse: decisionsResp,
			SigningTool: "get_decision", SigningArgumentsJSON: `{}`},
		{Name: "other-scope-tool", CheckedTool: "list_decisions", ChallengeResponse: decisionsResp,
			SigningTool: "list_agents", SigningArgumentsJSON: `{}`},
		{Name: "other-connection", CheckedTool: "list_decisions", ChallengeResponse: decisionsResp,
			SigningTool: "list_decisions", SigningArgumentsJSON: `{}`, SigningConfigJSON: otherConnection},
		{Name: "other-verifier", CheckedTool: "list_decisions", ChallengeResponse: decisionsResp,
			SigningTool: "list_decisions", SigningArgumentsJSON: `{}`, SigningConfigJSON: otherVerifier},
	} {
		c.Now = now
		ch, err := cfg.CheckChallenge(c.CheckedTool, []byte(c.ChallengeResponse), c.Now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		signCfg := cfg
		if c.SigningConfigJSON != "" {
			if signCfg, err = mcp.ParseClientConfig([]byte(c.SigningConfigJSON)); err != nil {
				return nil, fmt.Errorf("%s: %w", c.Name, err)
			}
		}
		call, err := mcp.NewToolCall(c.SigningTool, []byte(c.SigningArgumentsJSON))
		if err != nil {
			return nil, err
		}
		if _, err := mcp.SignToolCall(signCfg, g.agent.priv, call, ch); err == nil {
			return nil, fmt.Errorf("refused signing %s was signed", c.Name)
		}
		f.RefusedSignings = append(f.RefusedSignings, c)
	}
	return f, nil
}

// checkBundle decodes and verifies a produced bundle and its binding.
func checkBundle(bundleB64, agentID string, session []byte, delegations int) error {
	wire, ok := decodeB64(bundleB64)
	if !ok {
		return fmt.Errorf("bundle is not base64")
	}
	b, err := ratify.DecodeProofBundleV2(wire)
	if err != nil {
		return err
	}
	if err := ratify.VerifyProofBundleV2Signatures(b); err != nil {
		return err
	}
	if b.AgentID != agentID || b.SessionContext == nil || hex.EncodeToString(*b.SessionContext) != hex.EncodeToString(session) ||
		len(b.Delegations) != delegations || b.StreamSeq != nil {
		return fmt.Errorf("bundle binds other values")
	}
	return nil
}
