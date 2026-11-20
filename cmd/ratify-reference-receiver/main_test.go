package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

const testWorkspace = "6098e7e5-bca6-4f41-8f69-d0cca4e56bd0"

var testNow = time.Unix(1_800_000_000, 0)

func writeKey(t *testing.T, dir, name string) (string, ratify.HybridPrivateKey) {
	t.Helper()
	_, private, err := ratify.GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ml, _ := private.MLDSA65.MarshalBinary()
	data, _ := json.Marshal(map[string][]byte{"ed25519_private_key": private.Ed25519, "mldsa65_private_key": ml})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path, private
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testSpec(t *testing.T, root, status ratify.HybridPublicKey, issuerID string) spec {
	rootID, _ := setup.V2KeyID(root)
	return spec{Anchors: []setup.V2TrustAnchor{{PublicKey: root, RootID: rootID}},
		IssuerStatusKeys: []setup.V2IssuerStatusKey{{Epoch: 1, IssuerID: issuerID, StatusKey: status}},
		Operations:       []setup.V2ReceiverOperation{{Action: "read", OperationID: "files", RequiredScope: "files:read", RiskClass: "standard"}},
		ReceiverID:       "01f7fcf6-ffdb-43e0-9dbb-10c174d5bc0e",
		StatusPolicy:     setup.V2StatusPolicy{MaxListLifetimeSeconds: 300, MaxStatusAgeSeconds: 150},
		WorkspaceID:      testWorkspace}
}

// The first profile and a status-key-rotation successor are the exact
// bytes Verify's receiver-config parser accepts, chained by head digest.
func TestConfigSignsProfilesVerifyAccepts(t *testing.T) {
	dir := t.TempDir()
	signerPath, signer := writeKey(t, dir, "signer.key")
	_, root := writeKey(t, dir, "root.key")
	_, status := writeKey(t, dir, "status.key")
	_, status2 := writeKey(t, dir, "status2.key")
	issuerID := strings.Repeat("ab", 32)
	specPath := writeJSON(t, dir, "spec.json", testSpec(t, root.Public(), status.Public(), issuerID))
	first := filepath.Join(dir, "profile-1.json")
	var stderr bytes.Buffer
	now := func() time.Time { return testNow }
	if err := run([]string{"config", "--key", signerPath, "--spec", specPath, "--out", first}, io.Discard, &stderr, os.Getenv, now, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(first)
	installed, err := setup.ParseV2ReceiverConfig(data, nil, testNow.Unix())
	if err != nil {
		t.Fatalf("first profile refused: %v", err)
	}
	signerID, _ := setup.V2KeyID(signer.Public())
	if installed.Head.Sequence != 1 || installed.Content.WorkspaceID != testWorkspace {
		t.Fatalf("first profile: %+v signer %s", installed.Head, signerID)
	}

	rotated := testSpec(t, root.Public(), status2.Public(), issuerID)
	rotated.IssuerStatusKeys[0].Epoch = 2
	specPath2 := writeJSON(t, dir, "spec2.json", rotated)
	second := filepath.Join(dir, "profile-2.json")
	later := func() time.Time { return testNow.Add(40 * 24 * time.Hour) } // first head has expired
	if err := run([]string{"config", "--key", signerPath, "--spec", specPath2, "--previous", first, "--out", second},
		io.Discard, &stderr, os.Getenv, later, nil); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(second)
	successor, err := setup.ParseV2ReceiverConfig(data2, installed, later().Unix())
	if err != nil || successor.Head.Sequence != 2 || successor.StatusKeys()[issuerID].Epoch != 2 {
		t.Fatalf("successor refused: %v", err)
	}

	// An invalid spec or another signer for a successor is refused before
	// anything is written.
	otherPath, _ := writeKey(t, dir, "other.key")
	for name, args := range map[string][]string{
		"unknown spec field": {"config", "--key", signerPath, "--spec", writeJSON(t, dir, "bad.json", map[string]any{"receiver": "x"}), "--out", filepath.Join(dir, "x1")},
		"other signer":       {"config", "--key", otherPath, "--spec", specPath2, "--previous", first, "--out", filepath.Join(dir, "x2")},
		"too long":           {"config", "--key", signerPath, "--spec", specPath, "--valid-for", "721h", "--out", filepath.Join(dir, "x3")},
		"overwrite":          {"config", "--key", signerPath, "--spec", specPath, "--out", first},
	} {
		if err := run(args, io.Discard, io.Discard, os.Getenv, now, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "x2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused profile was written")
	}
}

// decide is the receiver's two calls: a challenge for the exact action,
// then a signed proof bundle carrying the agent's certificate chain. The
// fake Verify checks the bundle's signatures and session context.
func TestDecideSendsAValidProofAndMapsTheDecision(t *testing.T) {
	dir := t.TempDir()
	agentPath, agent := writeKey(t, dir, "agent.key")
	_, issuer := writeKey(t, dir, "issuer.key")
	agentID, _ := setup.V2KeyID(agent.Public())
	issuerID, _ := setup.V2KeyID(issuer.Public())
	signed, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2, CertID: "okta-alice",
		IssuerID: issuerID, IssuerPubKey: issuer.Public(), SubjectID: agentID, SubjectPubKey: agent.Public(),
		Scope: []string{"files:read"}, Constraints: []ratify.ConstraintV2{}, IssuedAt: time.Now().Unix() - 60,
		ExpiresAt: time.Now().Unix() + 3600}, issuer)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := ratify.EncodeDelegationCertV2(signed)
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, wire, 0644)

	verifierID := strings.Repeat("cd", 32)
	decision := "allow"
	var horizon any = time.Now().Unix() + 60
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.Header.Get("X-Ratify-API-Key") != "rat_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/v1/verify/v2/challenges":
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": bytes.Repeat([]byte{7}, 32),
				"verifier_id": verifierID, "issued_at": time.Now().Unix(), "expires_at": time.Now().Unix() + 60})
		case "/v1/verify/v2/proofs":
			result := ratify.VerifyArchivalProofBundleV2(body["proof_bundle"])
			bundle, err := ratify.DecodeProofBundleV2(body["proof_bundle"])
			if result.Err != nil || err != nil || bundle.AgentID != agentID || bundle.VerifierID != verifierID ||
				len(bundle.Delegations) != 1 || bundle.Delegations[0].CertID != "okta-alice" || bundle.SessionContext == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var invocation string
			var hash []byte
			_ = json.Unmarshal(body["invocation_id"], &invocation)
			_ = json.Unmarshal(body["request_hash"], &hash)
			want, _ := ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{VerifierID: verifierID,
				WorkspaceID: testWorkspace, AgentID: agentID, SessionID: "acceptance-session",
				InvocationID: invocation, RequestHash: hash})
			if !bytes.Equal(*bundle.SessionContext, want) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"decision": decision, "decision_reason": "x", "claim_id": "c1",
				"challenge_expires_at": time.Now().Unix() + 60, "allow_horizon": horizon})
		}
	}))
	defer server.Close()
	env := map[string]string{"RATIFY_RECEIVER_API_KEY": "rat_test"}
	args := []string{"decide", "--agent-key", agentPath, "--chain", certPath, "--workspace", testWorkspace,
		"--operation", "files", "--action", "read", "--api", server.URL}
	var out bytes.Buffer
	if err := run(args, &out, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); err != nil {
		t.Fatalf("allow: %v (%v)", err, seen)
	}
	if !strings.Contains(out.String(), `"decision":"allow"`) || !strings.Contains(out.String(), `"cert_id":"okta-alice"`) {
		t.Fatalf("output %s", out.String())
	}
	// An allow past its horizon, or without one, is not acted on.
	for _, h := range []any{time.Now().Unix() - 1, nil} {
		horizon = h
		var expired bytes.Buffer
		if err := run(args, &expired, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); err == nil ||
			strings.Contains(expired.String(), `"decision":"allow"`) {
			t.Fatalf("accepted or printed an allow with horizon %v: %s", h, expired.String())
		}
	}
	horizon = time.Now().Unix() + 60
	decision = "deny"
	if err := run(args, io.Discard, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); !errors.Is(err, errDenied) {
		t.Fatalf("deny mapped to %v", err)
	}
	decision = ""
	if err := run(args, io.Discard, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); err == nil || errors.Is(err, errDenied) {
		t.Fatalf("withheld mapped to %v", err)
	}
	delete(env, "RATIFY_RECEIVER_API_KEY")
	if err := run(args, io.Discard, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); err == nil {
		t.Fatal("ran without a receiver API key")
	}
	// The released binary has no default Verify host, so the operator always
	// chooses the environment their API key belongs to.
	env["RATIFY_RECEIVER_API_KEY"] = "rat_test"
	noAPI := args[:len(args)-2] // drops "--api", server.URL
	if err := run(noAPI, io.Discard, io.Discard, func(k string) string { return env[k] }, time.Now, server.Client()); err == nil || !strings.Contains(err.Error(), "--api") {
		t.Fatalf("ran without --api: %v", err)
	}
}

// A redirect from the Verify URL is not followed, so the receiver API key
// never reaches another host.
func TestDecideDoesNotFollowRedirectsWithTheAPIKey(t *testing.T) {
	dir := t.TempDir()
	agentPath, agent := writeKey(t, dir, "agent.key")
	agentID, _ := setup.V2KeyID(agent.Public())
	signed, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{Version: 2, CertID: "c", IssuerID: agentID,
		IssuerPubKey: agent.Public(), SubjectID: agentID, SubjectPubKey: agent.Public(), Scope: []string{"files:read"},
		Constraints: []ratify.ConstraintV2{}, IssuedAt: time.Now().Unix() - 60, ExpiresAt: time.Now().Unix() + 60}, agent)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := ratify.EncodeDelegationCertV2(signed)
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, wire, 0644)
	leaked := false
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked = leaked || r.Header.Get("X-Ratify-API-Key") != ""
	}))
	defer elsewhere.Close()
	verify := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer verify.Close()
	client := verify.Client()
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(elsewhere.Certificate())
	err = run([]string{"decide", "--agent-key", agentPath, "--chain", certPath, "--workspace", testWorkspace,
		"--operation", "files", "--action", "read", "--api", verify.URL}, io.Discard, io.Discard,
		func(string) string { return "rat_secret" }, time.Now, client)
	if err == nil || leaked {
		t.Fatalf("redirect followed: err=%v leaked=%v", err, leaked)
	}
}

// A customer matches a downloaded binary to its release notes by version, so
// --version must print the version the release build embedded.
func TestVersionPrintsEmbeddedVersion(t *testing.T) {
	defer func(old string) { version = old }(version)
	version = "v1.2.3"
	var stdout bytes.Buffer
	if err := run([]string{"--version"}, &stdout, io.Discard, os.Getenv, time.Now, http.DefaultClient); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "ratify-reference-receiver v1.2.3\n" {
		t.Fatalf("stdout %q", stdout.String())
	}
}
