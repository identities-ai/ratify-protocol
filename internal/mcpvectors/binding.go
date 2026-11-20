package mcpvectors

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/identities-ai/ratify-protocol/v2/verifyclient/mcp"
)

type bindingCase struct {
	Name               string `json:"name"`
	Tool               string `json:"tool"`
	ConnectionID       string `json:"connection_id"`
	Audience           string `json:"audience"`
	VerifierID         string `json:"verifier_id"`
	WorkspaceID        string `json:"workspace_id"`
	AgentID            string `json:"agent_id"`
	InvocationID       string `json:"invocation_id"`
	ArgumentsJSON      string `json:"arguments_json"`
	CanonicalArguments string `json:"canonical_arguments"`
	PayloadDigest      string `json:"payload_digest"`
	RequestHash        string `json:"request_hash"`
	SessionContext     string `json:"session_context"`
}

// invalidArguments carries the input as text, or as base64 when the bytes
// are not valid UTF-8 and so cannot be a JSON string.
type invalidArguments struct {
	Name            string `json:"name"`
	ArgumentsJSON   string `json:"arguments_json,omitempty"`
	ArgumentsBase64 string `json:"arguments_base64,omitempty"`
}

type tool struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

type bindingFile struct {
	Version          int                `json:"version"`
	Description      string             `json:"description"`
	Action           string             `json:"action"`
	ProofMetaKey     string             `json:"proof_meta_key"`
	Tools            []tool             `json:"tools"`
	Cases            []bindingCase      `json:"cases"`
	InvalidArguments []invalidArguments `json:"invalid_arguments"`
}

func (g *gen) binding() (any, error) {
	f := bindingFile{
		Version: 1,
		Description: "Verify MCP tool-call binding (preview; a managed-service contract, not SPEC-v2 conformance). " +
			"Parse arguments_json under the restricted value model and require canonical_arguments byte for byte; " +
			"payload_digest is sha256: plus the hex SHA-256 of those bytes; request_hash is the SPEC-v2 operation context " +
			"(required scope = the tool's scope, operation = action + \":\" + tool, resource = connection_id, requested path = audience, " +
			"payload digest = the raw 32 bytes); session_context is the SPEC-v2 session context with session = connection_id. " +
			"Every invalid_arguments input must be refused before anything is signed.",
		Action: mcp.Action, ProofMetaKey: mcp.ProofMetaKey,
	}
	for _, t := range mcp.Tools() {
		f.Tools = append(f.Tools, tool{t.Name, t.Scope})
	}
	agentID := strings.Repeat("2", 64)
	for _, c := range []struct{ name, tool, args string }{
		{"metrics-empty", "get_metrics", `{}`},
		{"decisions-filters", "list_decisions", `{"to":"2026-11-17T00:00:00Z","decision":"deny","limit":20,"from":"2026-11-10T00:00:00Z"}`},
		{"events-unicode", "list_events", `{"types":["certificate.admitted","café \"q\" \\ b"],"limit":5}`},
		{"absent-arguments", "get_metrics", ``},
		{"null-arguments", "list_agents", `null`},
		{"whitespace-and-escapes", "get_decision", " {\n\t\"decision_id\" : \"d\\u00e9c\\/1\" ,\r\n \"include\" : [ true , false ] } "},
		{"keys-sorted-by-utf8-bytes", "list_evidence", `{"😀":1,"ｚ":2,"z":3,"Z":4,"zz":5,"":6}`},
		{"safe-integer-bounds", "list_decisions", `{"max":9007199254740991,"min":-9007199254740991,"zero":0,"neg":-7}`},
		{"maximum-depth", "get_evidence_package", `{"a":[[["x"]]],"b":{"c":{"d":{"e":[]}}}}`},
		{"empty-containers", "list_events", `{"types":[],"filter":{}}`},
	} {
		canonical, err := mcp.CanonicalArguments([]byte(c.args))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.name, err)
		}
		digest := mcp.PayloadDigest(canonical)
		req, err := mcp.RequestHash(c.tool, connectionID, audience, digest)
		if err != nil {
			return nil, err
		}
		sess, err := mcp.SessionContext(verifierID, workspaceID, agentID, connectionID, invocationID, req)
		if err != nil {
			return nil, err
		}
		f.Cases = append(f.Cases, bindingCase{c.name, c.tool, connectionID, audience, verifierID, workspaceID, agentID,
			invocationID, c.args, string(canonical), mcp.PayloadDigestText(digest), hex.EncodeToString(req), hex.EncodeToString(sess)})
	}
	for _, c := range []struct{ name, args string }{
		{"fraction", `{"limit":1.5}`},
		{"integral-fraction", `{"limit":1.0}`},
		{"exponent", `{"limit":1e3}`},
		{"upper-exponent", `{"limit":1E3}`},
		{"null-member", `{"x":null}`},
		{"duplicate-key", `{"a":1,"a":2}`},
		{"duplicate-key-after-unescape", `{"a":1,"a":2}`},
		{"nested-duplicate-key", `{"o":{"k":1,"k":1}}`},
		{"escaped-control", `{"s":"a\u0001b"}`},
		{"escaped-newline", `{"s":"a\nb"}`},
		{"raw-tab", "{\"s\":\"a\tb\"}"},
		{"delete-character", `{"s":"a\u007fb"}`},
		{"c1-control", `{"s":"a\u0085b"}`},
		{"line-separator", `{"s":"a b"}`},
		{"raw-paragraph-separator", "{\"s\":\"a b\"}"},
		{"control-in-key", `{"k\u0000":1}`},
		{"lone-high-surrogate", `{"s":"\ud800"}`},
		{"lone-low-surrogate", `{"s":"\udc00"}`},
		{"high-surrogate-then-letter", `{"s":"\ud800A"}`},
		{"above-safe-integer", `{"n":9007199254740992}`},
		{"below-safe-integer", `{"n":-9007199254740992}`},
		{"huge-integer", `{"n":123456789012345678901}`},
		{"negative-zero", `{"n":-0}`},
		{"leading-zero", `{"n":01}`},
		{"plus-sign", `{"n":+1}`},
		{"nan", `{"n":NaN}`},
		{"too-deep-array", `{"a":[[[["x"]]]]}`},
		{"too-deep-object", `{"a":{"b":{"c":{"d":{"e":1}}}}}`},
		{"top-level-array", `[1]`},
		{"top-level-string", `"x"`},
		{"top-level-number", `1`},
		{"top-level-true", `true`},
		{"trailing-value", `{} {}`},
		{"trailing-comma-object", `{"a":1,}`},
		{"trailing-comma-array", `{"a":[1,]}`},
		{"unquoted-key", `{a:1}`},
		{"single-quotes", `{'a':1}`},
		{"invalid-escape", `{"s":"\x41"}`},
		{"short-unicode-escape", `{"s":"\u12"}`},
		{"unterminated-string", `{"a":"x`},
		{"unterminated-object", `{"a":1`},
		{"empty-key-value", `{"a":}`},
	} {
		if _, err := mcp.CanonicalArguments([]byte(c.args)); err == nil {
			return nil, fmt.Errorf("invalid case %s was accepted", c.name)
		}
		f.InvalidArguments = append(f.InvalidArguments, invalidArguments{Name: c.name, ArgumentsJSON: c.args})
	}
	for _, c := range []struct {
		name string
		raw  []byte
	}{
		{"invalid-utf8", []byte("{\"s\":\"a\xffb\"}")},
		{"overlong-utf8", []byte("{\"s\":\"\xc0\xaf\"}")},
		{"encoded-surrogate", []byte("{\"s\":\"\xed\xa0\x80\"}")},
	} {
		if _, err := mcp.CanonicalArguments(c.raw); err == nil {
			return nil, fmt.Errorf("invalid case %s was accepted", c.name)
		}
		f.InvalidArguments = append(f.InvalidArguments, invalidArguments{Name: c.name, ArgumentsBase64: b64(c.raw)})
	}
	return f, nil
}
