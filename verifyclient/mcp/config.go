package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"unicode/utf8"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// ErrInvalidConfig means the console configuration is missing a field or a
// field has the wrong form.
var ErrInvalidConfig = errors.New("mcp: invalid client configuration")

var (
	endpointPattern = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex64Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	integerPattern  = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

// ClientConfig is the configuration the console shows when an agent is
// connected: the pinned endpoint and audience, the verifier and workspace,
// the connection, and the delegation chain ending at the agent key.
type ClientConfig struct {
	Endpoint     string
	Audience     string
	VerifierID   string
	WorkspaceID  string
	ConnectionID string
	// Delegations are the decoded certificates, root side first; the last
	// one is issued to the agent key. A proof bundle carries them in the
	// reverse order (leaf first).
	Delegations []ratify.DelegationCertV2
}

// ParseClientConfig parses the console's client configuration: either the
// client_config object itself or a JSON object that carries it under
// "client_config" (the console's connect response). Fields other than the
// six below are ignored, so a signer configuration file that also holds a
// key reference parses too.
//
//   - endpoint: "https://" and a lowercase host name with an optional port,
//     nothing else (no path, query, fragment, credentials, or trailing slash)
//   - audience: exactly endpoint + "/mcp"
//   - verifier_id: 64 lowercase hex characters
//   - workspace_id, connection_id: lowercase UUIDs
//   - delegations: a non-empty array of canonical standard base64 strings,
//     each a SPEC-v2 delegation certificate, root side first: each
//     certificate's subject is the next one's issuer (ID and key)
//
// The input must be valid UTF-8.
func ParseClientConfig(data []byte) (*ClientConfig, error) {
	var top map[string]json.RawMessage
	if !utf8.Valid(data) {
		return nil, ErrInvalidConfig
	}
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return nil, ErrInvalidConfig
	}
	if inner, ok := top["client_config"]; ok {
		var nested map[string]json.RawMessage
		if json.Unmarshal(inner, &nested) == nil && nested != nil {
			top = nested
		}
	}
	cfg := &ClientConfig{}
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"endpoint", &cfg.Endpoint}, {"audience", &cfg.Audience}, {"verifier_id", &cfg.VerifierID},
		{"workspace_id", &cfg.WorkspaceID}, {"connection_id", &cfg.ConnectionID},
	} {
		s, ok := jsonString(top[f.name])
		if !ok {
			return nil, ErrInvalidConfig
		}
		*f.dst = s
	}
	if !validEndpoint(cfg.Endpoint, cfg.Audience) || !hex64Pattern.MatchString(cfg.VerifierID) ||
		!uuidPattern.MatchString(cfg.WorkspaceID) || !uuidPattern.MatchString(cfg.ConnectionID) {
		return nil, ErrInvalidConfig
	}
	raw, ok := top["delegations"]
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return nil, ErrInvalidConfig
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 {
		return nil, ErrInvalidConfig
	}
	for _, item := range items {
		s, ok := jsonString(item)
		if !ok {
			return nil, ErrInvalidConfig
		}
		wire, ok := decodeStdBase64(s)
		if !ok {
			return nil, ErrInvalidConfig
		}
		cert, err := ratify.DecodeDelegationCertV2(wire)
		if err != nil {
			return nil, ErrInvalidConfig
		}
		cfg.Delegations = append(cfg.Delegations, *cert)
	}
	for i := 0; i+1 < len(cfg.Delegations); i++ {
		parent, child := cfg.Delegations[i], cfg.Delegations[i+1]
		if parent.SubjectID != child.IssuerID || !bytes.Equal(parent.SubjectPubKey.Ed25519, child.IssuerPubKey.Ed25519) ||
			!bytes.Equal(parent.SubjectPubKey.MLDSA65, child.IssuerPubKey.MLDSA65) {
			return nil, ErrInvalidConfig
		}
	}
	return cfg, nil
}

// validEndpoint checks the endpoint grammar and that audience is the
// endpoint followed by "/mcp".
func validEndpoint(endpoint, audience string) bool {
	return endpointPattern.MatchString(endpoint) && audience == endpoint+"/mcp"
}

func jsonString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// jsonInteger reads a JSON integer (no fraction, exponent, or boolean) in
// the safe range.
func jsonInteger(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if !integerPattern.Match(raw) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
		return 0, false
	}
	return n, true
}

// decodeStdBase64 accepts only canonical padded standard base64: the text
// must be exactly what encoding the decoded bytes produces.
func decodeStdBase64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}
