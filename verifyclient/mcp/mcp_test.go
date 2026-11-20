package mcp

import (
	"testing"
)

// A challenge is issued for one tool's scope and request hash. Letting it
// sign a call to another tool would hand the server a proof whose binding
// the signer never checked against the challenge it accepted.
func TestChallengeSignsOnlyTheToolItWasCheckedFor(t *testing.T) {
	var f struct {
		AgentKey   vectorKey `json:"agent_key"`
		ConfigJSON string    `json:"client_config_json"`
		Cases      []struct {
			Tool              string `json:"tool"`
			Now               int64  `json:"now"`
			ChallengeResponse string `json:"challenge_response"`
		} `json:"cases"`
	}
	vectorFile(t, "tool-call.json", &f)
	cfg, err := ParseClientConfig([]byte(f.ConfigJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := f.Cases[0]
	ch, err := cfg.CheckChallenge(c.Tool, []byte(c.ChallengeResponse), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewToolCall("list_agents", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignToolCall(cfg, f.AgentKey.load(t), other, ch); err == nil {
		t.Fatal("a challenge checked for one tool signed a call to another")
	}
}

// The signer never signs a tool the hosted table does not name: the scope
// it would bind is unknown, so the server could not recompute the hash.
func TestUnknownToolIsRefusedBeforeAnyRequest(t *testing.T) {
	if _, err := NewToolCall("delete_everything", []byte(`{}`)); err == nil {
		t.Fatal("unknown tool accepted")
	}
}
