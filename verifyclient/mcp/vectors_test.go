package mcp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

// The hosted service recomputes every value below from the call it
// receives. A signer that differs in one byte produces proofs the service
// rejects, or, worse, a proof that binds something other than the call the
// client asked for. Every SDK runs these same files.

func vectorFile(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testvectors", "v2", "mcp", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

type vectorKey struct {
	EdSeed string `json:"ed25519_seed_hex"`
	MLSeed string `json:"ml_dsa_65_seed_hex"`
	KeyID  string `json:"key_id_v2"`
}

func (k vectorKey) load(t *testing.T) ratify.HybridPrivateKey {
	t.Helper()
	var ed, ml [32]byte
	a, _ := hex.DecodeString(k.EdSeed)
	b, _ := hex.DecodeString(k.MLSeed)
	copy(ed[:], a)
	copy(ml[:], b)
	pub, priv, err := ratify.HybridKeypairFromSeeds(ed, ml)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := ratify.KeyIDV2(pub); id != k.KeyID {
		t.Fatalf("key id %s, want %s", id, k.KeyID)
	}
	return priv
}

// sameBundle requires that got and want are the same proof except for the
// hedged ML-DSA-65 component of challenge_sig, and that both verify.
func sameBundle(t *testing.T, name, gotB64, wantB64 string) {
	t.Helper()
	decode := func(s string) (*ratify.ProofBundleV2, []byte) {
		wire, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, err := ratify.DecodeProofBundleV2(wire)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ratify.VerifyProofBundleV2Signatures(b); err != nil {
			t.Fatalf("%s: does not verify: %v", name, err)
		}
		return b, wire
	}
	got, gotWire := decode(gotB64)
	want, wantWire := decode(wantB64)
	masked := strings.Replace(string(gotWire), base64.StdEncoding.EncodeToString(got.ChallengeSig.MLDSA65),
		base64.StdEncoding.EncodeToString(want.ChallengeSig.MLDSA65), 1)
	if masked != string(wantWire) {
		t.Fatalf("%s: proof differs from the vector beyond the hedged ML-DSA-65 signature", name)
	}
}

func TestBindingVectors(t *testing.T) {
	var f struct {
		Action, ProofMetaKey string
		Tools                []struct{ Name, Scope string }
		Cases                []map[string]string `json:"cases"`
		Invalid              []map[string]string `json:"invalid_arguments"`
	}
	vectorFile(t, "binding.json", &f)
	if Action != "mcp.tools/call" || ProofMetaKey != "com.ratifyprotocol/proof" || len(f.Tools) != len(Tools()) {
		t.Fatal("constants differ from the vectors")
	}
	for i, tool := range f.Tools {
		if Tools()[i].Name != tool.Name || Tools()[i].Scope != tool.Scope {
			t.Fatalf("tool table differs at %d", i)
		}
	}
	for _, c := range f.Cases {
		canonical, err := CanonicalArguments([]byte(c["arguments_json"]))
		if err != nil || string(canonical) != c["canonical_arguments"] {
			t.Fatalf("%s: canonical %q, %v", c["name"], canonical, err)
		}
		digest := PayloadDigest(canonical)
		if PayloadDigestText(digest) != c["payload_digest"] {
			t.Fatalf("%s: payload digest", c["name"])
		}
		req, err := RequestHash(c["tool"], c["connection_id"], c["audience"], digest)
		if err != nil || hex.EncodeToString(req) != c["request_hash"] {
			t.Fatalf("%s: request hash", c["name"])
		}
		sess, err := SessionContext(c["verifier_id"], c["workspace_id"], c["agent_id"], c["connection_id"], c["invocation_id"], req)
		if err != nil || hex.EncodeToString(sess) != c["session_context"] {
			t.Fatalf("%s: session context", c["name"])
		}
	}
	for _, c := range f.Invalid {
		in := []byte(c["arguments_json"])
		if c["arguments_base64"] != "" {
			in, _ = base64.StdEncoding.DecodeString(c["arguments_base64"])
		}
		if _, err := CanonicalArguments(in); err == nil {
			t.Fatalf("%s: accepted", c["name"])
		}
	}
}

func TestClientConfigVectors(t *testing.T) {
	var f struct {
		Valid []struct {
			Name       string `json:"name"`
			ConfigJSON string `json:"config_json"`
			Expected   struct {
				Endpoint     string   `json:"endpoint"`
				Audience     string   `json:"audience"`
				VerifierID   string   `json:"verifier_id"`
				WorkspaceID  string   `json:"workspace_id"`
				ConnectionID string   `json:"connection_id"`
				CertIDs      []string `json:"delegation_cert_ids"`
			} `json:"expected"`
		} `json:"valid"`
		Invalid []map[string]string `json:"invalid"`
	}
	vectorFile(t, "client-config.json", &f)
	for _, c := range f.Valid {
		cfg, err := ParseClientConfig([]byte(c.ConfigJSON))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		e := c.Expected
		if cfg.Endpoint != e.Endpoint || cfg.Audience != e.Audience || cfg.VerifierID != e.VerifierID ||
			cfg.WorkspaceID != e.WorkspaceID || cfg.ConnectionID != e.ConnectionID || len(cfg.Delegations) != len(e.CertIDs) {
			t.Fatalf("%s: parsed %+v", c.Name, cfg)
		}
		for i, id := range e.CertIDs {
			if cfg.Delegations[i].CertID != id {
				t.Fatalf("%s: delegation %d", c.Name, i)
			}
		}
	}
	for _, c := range f.Invalid {
		if _, err := ParseClientConfig([]byte(c["config_json"])); err == nil {
			t.Fatalf("%s: accepted", c["name"])
		}
	}
}

func TestToolCallVectors(t *testing.T) {
	var f struct {
		AgentKey      vectorKey `json:"agent_key"`
		WrongAgentKey vectorKey `json:"wrong_agent_key"`
		ConfigJSON    string    `json:"client_config_json"`
		Cases         []struct {
			Name               string        `json:"name"`
			Tool               string        `json:"tool"`
			ArgumentsJSON      string        `json:"arguments_json"`
			Now                int64         `json:"now"`
			ChallengeResponse  string        `json:"challenge_response"`
			CanonicalArguments string        `json:"canonical_arguments"`
			ChallengeRequest   string        `json:"challenge_request"`
			Envelope           ProofEnvelope `json:"envelope"`
		} `json:"cases"`
		Refused []struct {
			Name              string `json:"name"`
			Tool              string `json:"tool"`
			Now               int64  `json:"now"`
			ChallengeResponse string `json:"challenge_response"`
		} `json:"refused_challenges"`
	}
	vectorFile(t, "tool-call.json", &f)
	if len(f.Cases) == 0 || len(f.Refused) == 0 {
		t.Fatal("tool-call.json shape")
	}
	cases, refused := f.Cases, f.Refused
	cfg, err := ParseClientConfig([]byte(f.ConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	agent, wrong := f.AgentKey.load(t), f.WrongAgentKey.load(t)
	for _, c := range cases {
		call, err := NewToolCall(c.Tool, []byte(c.ArgumentsJSON))
		if err != nil || string(call.CanonicalArguments) != c.CanonicalArguments {
			t.Fatalf("%s: arguments: %v", c.Name, err)
		}
		if string(cfg.ChallengeRequest(call)) != c.ChallengeRequest {
			t.Fatalf("%s: challenge request %s", c.Name, cfg.ChallengeRequest(call))
		}
		ch, err := cfg.CheckChallenge(c.Tool, []byte(c.ChallengeResponse), c.Now)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		env, err := SignToolCall(cfg, agent, call, ch)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if env.ConnectionID != c.Envelope.ConnectionID || env.InvocationID != c.Envelope.InvocationID || env.Challenge != c.Envelope.Challenge {
			t.Fatalf("%s: envelope %+v", c.Name, env)
		}
		sameBundle(t, c.Name, env.Bundle, c.Envelope.Bundle)
		if _, err := SignToolCall(cfg, wrong, call, ch); err == nil {
			t.Fatalf("%s: a key the delegation does not name signed", c.Name)
		}
	}
	for _, c := range refused {
		if _, err := cfg.CheckChallenge(c.Tool, []byte(c.ChallengeResponse), c.Now); err == nil {
			t.Fatalf("%s: accepted", c.Name)
		}
	}
}

func TestConnectVectors(t *testing.T) {
	var f struct {
		Domain      string              `json:"domain"`
		TokenPrefix string              `json:"token_prefix"`
		Contexts    []map[string]string `json:"contexts"`
		AgentKey    vectorKey           `json:"agent_key"`
		Proofs      []struct {
			Name   string `json:"name"`
			Token  string `json:"token"`
			Parsed struct {
				ChallengeID string `json:"challenge_id"`
				Challenge   string `json:"challenge"`
				IssuedAt    int64  `json:"issued_at"`
				WorkspaceID string `json:"workspace_id"`
				ReceiverID  string `json:"receiver_id"`
				Audience    string `json:"audience"`
				VerifierID  string `json:"verifier_id"`
			} `json:"parsed"`
			SessionContext string          `json:"session_context"`
			Expected       PossessionProof `json:"expected"`
		} `json:"proofs"`
		Invalid []map[string]string `json:"invalid_tokens"`
	}
	vectorFile(t, "connect.json", &f)
	if f.Domain != ConnectPossessionDomain || f.TokenPrefix != ConnectTokenPrefix {
		t.Fatal("constants differ from the vectors")
	}
	for _, c := range f.Contexts {
		got := ConnectPossessionContext(c["workspace_id"], c["receiver_id"], c["audience"], c["challenge_id"], c["agent_id"])
		if hex.EncodeToString(got) != c["session_context"] {
			t.Fatalf("%s: context", c["name"])
		}
	}
	agent := f.AgentKey.load(t)
	agentID, _ := ratify.KeyIDV2(agent.Public())
	for _, c := range f.Proofs {
		tok, err := ParseConnectToken(c.Token)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		p := c.Parsed
		if tok.ChallengeID != p.ChallengeID || base64.StdEncoding.EncodeToString(tok.Challenge) != p.Challenge || tok.IssuedAt != p.IssuedAt ||
			tok.WorkspaceID != p.WorkspaceID || tok.ReceiverID != p.ReceiverID || tok.Audience != p.Audience || tok.VerifierID != p.VerifierID {
			t.Fatalf("%s: parsed %+v", c.Name, tok)
		}
		sess := ConnectPossessionContext(tok.WorkspaceID, tok.ReceiverID, tok.Audience, tok.ChallengeID, agentID)
		if hex.EncodeToString(sess) != c.SessionContext {
			t.Fatalf("%s: session context", c.Name)
		}
		proof, err := ProvePossession(c.Token, agent)
		if err != nil || proof.ConnectChallengeID != c.Expected.ConnectChallengeID {
			t.Fatalf("%s: %v", c.Name, err)
		}
		sameBundle(t, c.Name, proof.PossessionProof, c.Expected.PossessionProof)
	}
	for _, c := range f.Invalid {
		if _, err := ParseConnectToken(c["token"]); err == nil {
			t.Fatalf("%s: accepted", c["name"])
		}
		if _, err := ProvePossession(c["token"], agent); err == nil {
			t.Fatalf("%s: signed", c["name"])
		}
	}
}
