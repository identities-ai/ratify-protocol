package mcpvectors

import (
	"fmt"
	"strings"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/mcp"
)

type configExpected struct {
	Endpoint     string   `json:"endpoint"`
	Audience     string   `json:"audience"`
	VerifierID   string   `json:"verifier_id"`
	WorkspaceID  string   `json:"workspace_id"`
	ConnectionID string   `json:"connection_id"`
	CertIDs      []string `json:"delegation_cert_ids"`
}

type configCase struct {
	Name       string          `json:"name"`
	ConfigJSON string          `json:"config_json"`
	Expected   *configExpected `json:"expected,omitempty"`
}

type configFile struct {
	Version     int          `json:"version"`
	Description string       `json:"description"`
	Valid       []configCase `json:"valid"`
	Invalid     []configCase `json:"invalid"`
}

// baseConfig is the console's client_config as the hosted service writes it.
func (g *gen) baseConfig() map[string]any {
	return map[string]any{
		"endpoint": endpoint, "audience": audience, "verifier_id": verifierID, "workspace_id": workspaceID,
		"connection_id": connectionID, "delegations": []any{b64(g.certWire)},
	}
}

func with(base map[string]any, key string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	if value == nil {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func (g *gen) clientConfig() (any, error) {
	f := configFile{Version: 1, Description: "Verify MCP console client configuration (preview). Each valid config_json must " +
		"parse to expected (delegation_cert_ids lists the decoded certificates' cert_id, in order); each invalid one must be refused. " +
		"A top-level client_config object is unwrapped; unknown fields are ignored."}
	base := g.baseConfig()
	expected := func(ep string) *configExpected {
		return &configExpected{ep, ep + "/mcp", verifierID, workspaceID, connectionID, []string{g.cert.CertID}}
	}
	for _, c := range []struct {
		name string
		cfg  any
		ep   string
	}{
		{"console-client-config", base, endpoint},
		{"console-connect-response", map[string]any{
			"connection":         map[string]any{"id": connectionID, "scopes": []any{"custom:verify.metrics:read"}},
			"client_config":      base,
			"mcp_client_snippet": map[string]any{"mcpServers": map[string]any{}},
		}, endpoint},
		{"signer-file-with-key-reference", with(base, "key", map[string]any{"kind": "file", "path": "/var/lib/ratify-mcp/agent.key"}), endpoint},
		{"endpoint-with-port", with(with(base, "endpoint", "https://verify.example:8443"), "audience", "https://verify.example:8443/mcp"), "https://verify.example:8443"},
	} {
		text := compact(c.cfg)
		if _, err := mcp.ParseClientConfig([]byte(text)); err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		f.Valid = append(f.Valid, configCase{c.name, text, expected(c.ep)})
	}
	invalid := []struct {
		name string
		cfg  any
	}{
		{"not-json", rawJSON(`{"endpoint":`)},
		{"top-level-array", []any{base}},
		{"top-level-string", "config"},
		{"http-endpoint", with(with(base, "endpoint", "http://verify.example"), "audience", "http://verify.example/mcp")},
		{"uppercase-endpoint", with(with(base, "endpoint", "https://Verify.example"), "audience", "https://Verify.example/mcp")},
		{"endpoint-trailing-slash", with(with(base, "endpoint", endpoint+"/"), "audience", endpoint+"//mcp")},
		{"endpoint-with-path", with(with(base, "endpoint", endpoint+"/v1"), "audience", endpoint+"/v1/mcp")},
		{"endpoint-with-query", with(with(base, "endpoint", endpoint+"?a=1"), "audience", endpoint+"?a=1/mcp")},
		{"endpoint-with-credentials", with(with(base, "endpoint", "https://user@verify.example"), "audience", "https://user@verify.example/mcp")},
		{"endpoint-port-zero-prefixed", with(with(base, "endpoint", "https://verify.example:0443"), "audience", "https://verify.example:0443/mcp")},
		{"audience-trailing-slash", with(base, "audience", audience+"/")},
		{"audience-other-host", with(base, "audience", "https://other.example/mcp")},
		{"audience-other-path", with(base, "audience", endpoint+"/sse")},
		{"verifier-uppercase", with(base, "verifier_id", strings.Repeat("A", 64))},
		{"verifier-63-characters", with(base, "verifier_id", strings.Repeat("1", 63))},
		{"workspace-uppercase", with(base, "workspace_id", strings.ToUpper(workspaceID))},
		{"workspace-not-uuid", with(base, "workspace_id", "workspace")},
		{"workspace-number", with(base, "workspace_id", 7)},
		{"connection-uppercase", with(base, "connection_id", strings.ToUpper(connectionID))},
		{"connection-braced", with(base, "connection_id", "{"+connectionID+"}")},
		{"delegations-empty", with(base, "delegations", []any{})},
		{"delegations-not-array", with(base, "delegations", b64(g.certWire))},
		{"delegation-not-string", with(base, "delegations", []any{7})},
		{"delegation-unpadded-base64", with(base, "delegations", []any{strings.TrimRight(b64(g.certWire[:len(g.certWire)-1]), "=")})},
		{"delegation-with-newline", with(base, "delegations", []any{b64(g.certWire)[:40] + "\n" + b64(g.certWire)[40:]})},
		{"delegation-not-a-certificate", with(base, "delegations", []any{b64([]byte(`{}`))})},
		{"endpoint-null", with(base, "endpoint", rawJSON("null"))},
	}
	for _, field := range []string{"endpoint", "audience", "verifier_id", "workspace_id", "connection_id", "delegations"} {
		invalid = append(invalid, struct {
			name string
			cfg  any
		}{"missing-" + strings.ReplaceAll(field, "_", "-"), with(base, field, nil)})
	}
	for _, c := range invalid {
		text := compact(c.cfg)
		if _, err := mcp.ParseClientConfig([]byte(text)); err == nil {
			return nil, fmt.Errorf("invalid config %s was accepted", c.name)
		}
		f.Invalid = append(f.Invalid, configCase{Name: c.name, ConfigJSON: text})
	}
	return f, nil
}
