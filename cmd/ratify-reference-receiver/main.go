// ratify-reference-receiver is a minimal customer-run receiver for Verify
// v2 acceptance runs. It signs a receiver configuration with the receiver's
// own config-signer key, and asks Verify for a decision on one agent action
// the way a protected API would before acting.
//
//	ratify-reference-receiver config --key SIGNER.key --spec SPEC.json --out PROFILE.json [--previous PROFILE.json] [--valid-for 720h]
//	ratify-reference-receiver decide --agent-key AGENT.key --chain LEAF.json[,PARENT.json] --workspace ORG_ID \
//	    --operation OP --action ACTION --api https://VERIFY_API_HOST
//
// decide reads the receiver API key from RATIFY_RECEIVER_API_KEY. It prints
// one JSON line and exits 0 for allow, 2 for deny, and 1 for any error or
// withheld decision. Install PROFILE.json with
// PUT /v1/verify/v2/receiver-config using the same receiver API key.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/internal/toolversion"
	"github.com/identities-ai/ratify-protocol/v2/verifyclient/setup"
)

const maxFileBytes = 1 << 20

var errDenied = errors.New("Verify denied the action")

// version is set at release build time with -ldflags "-X main.version=...";
// otherwise toolversion falls back to the module version from go install.
var version = "dev"

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv, time.Now, &http.Client{Timeout: 30 * time.Second})
	switch {
	case err == nil:
	case errors.Is(err, errDenied):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "ratify-reference-receiver:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string, now func() time.Time, client *http.Client) error {
	if len(args) == 0 {
		return errors.New("a command is required: config or decide")
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, "ratify-reference-receiver", toolversion.String(version))
		return nil
	}
	switch args[0] {
	case "config":
		return configCommand(args[1:], stderr, now())
	case "decide":
		return decideCommand(args[1:], stdout, getenv, client)
	default:
		return fmt.Errorf("unknown command %q (use config or decide)", args[0])
	}
}

// spec is the receiver configuration content the operator writes; the
// signer key and the schema fields are filled in when it is signed.
type spec struct {
	Anchors          []setup.V2TrustAnchor       `json:"anchors"`
	IssuerStatusKeys []setup.V2IssuerStatusKey   `json:"issuer_status_keys"`
	Operations       []setup.V2ReceiverOperation `json:"operations"`
	ReceiverID       string                      `json:"receiver_id"`
	StatusPolicy     setup.V2StatusPolicy        `json:"status_policy"`
	WorkspaceID      string                      `json:"workspace_id"`
}

func configCommand(args []string, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "config-signer private key file")
	specPath := fs.String("spec", "", "configuration spec JSON")
	previousPath := fs.String("previous", "", "the currently installed profile, for a successor")
	outPath := fs.String("out", "", "profile file to create")
	validFor := fs.Duration("valid-for", 30*24*time.Hour, "head lifetime (at most 30 days)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *keyPath == "" || *specPath == "" || *outPath == "" {
		return errors.New("config needs --key, --spec, and --out")
	}
	if *validFor <= 0 || *validFor > 30*24*time.Hour {
		return errors.New("--valid-for must be more than 0 and at most 720h")
	}
	signer, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	var s spec
	if err := readStrict(*specPath, &s); err != nil {
		return err
	}
	content := setup.V2ReceiverConfigContent{Anchors: s.Anchors, ConfigSignerKey: signer.Public(),
		IssuerStatusKeys: s.IssuerStatusKeys, Operations: s.Operations, ReceiverID: s.ReceiverID,
		StatusPolicy: s.StatusPolicy, WorkspaceID: s.WorkspaceID}
	if content.Anchors == nil {
		content.Anchors = []setup.V2TrustAnchor{}
	}
	if content.IssuerStatusKeys == nil {
		content.IssuerStatusKeys = []setup.V2IssuerStatusKey{}
	}
	head := setup.V2ReceiverConfigHead{IssuedAt: now.Unix() - 30, NotAfter: now.Add(*validFor).Unix() - 30,
		ReceiverID: s.ReceiverID, Sequence: 1}
	var previous *setup.V2ReceiverConfig
	if *previousPath != "" {
		data, err := readFile(*previousPath)
		if err != nil {
			return err
		}
		// An expired predecessor may still be extended.
		var priorHead []byte
		previous, priorHead, err = parsePrevious(data)
		if err != nil {
			return fmt.Errorf("--previous: %v", err)
		}
		sum := sha512.Sum384(priorHead)
		head.Sequence, head.PriorHeadDigest = previous.Head.Sequence+1, "sha384:"+hex.EncodeToString(sum[:])
	}
	profile, err := setup.SignV2ReceiverConfig(content, head, signer)
	if err != nil {
		return err
	}
	// Check it exactly as Verify will before writing it.
	if _, err := setup.ParseV2ReceiverConfig(profile, previous, now.Unix()); err != nil {
		return fmt.Errorf("the signed profile does not pass Verify's check: %v", err)
	}
	if err := writeNew(*outPath, profile); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stderr, "Wrote receiver profile %s, sequence %d, for receiver %s.\n", *outPath, head.Sequence, s.ReceiverID)
	return err
}

// parsePrevious reads the installed profile, even after its head expired,
// and returns it with its exact head body. Verify checks the full chain
// when the successor is installed; this only builds the link to it.
func parsePrevious(data []byte) (*setup.V2ReceiverConfig, []byte, error) {
	var document struct {
		Content struct {
			Body json.RawMessage `json:"body"`
		} `json:"content"`
		Head struct {
			Body json.RawMessage `json:"body"`
		} `json:"head"`
	}
	config := &setup.V2ReceiverConfig{Bytes: data}
	if err := json.Unmarshal(data, &document); err != nil ||
		json.Unmarshal(document.Content.Body, &config.Content) != nil ||
		json.Unmarshal(document.Head.Body, &config.Head) != nil || config.Head.Sequence < 1 {
		return nil, nil, errors.New("not a signed receiver profile")
	}
	return config, document.Head.Body, nil
}

func decideCommand(args []string, stdout io.Writer, getenv func(string) string, client *http.Client) error {
	fs := flag.NewFlagSet("decide", flag.ContinueOnError)
	agentPath := fs.String("agent-key", "", "agent private key file")
	chainPaths := fs.String("chain", "", "comma-separated certificate files, agent's certificate first")
	workspace := fs.String("workspace", "", "the receiver's workspace (organization) ID")
	operation := fs.String("operation", "", "operation ID in the receiver configuration")
	action := fs.String("action", "", "action in the receiver configuration")
	// No default: a published binary must never pick a Verify environment
	// on the operator's behalf.
	api := fs.String("api", "", "Verify API base URL (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	apiKey := getenv("RATIFY_RECEIVER_API_KEY")
	if fs.NArg() != 0 || *agentPath == "" || *chainPaths == "" || *workspace == "" || *operation == "" || *action == "" || *api == "" {
		return errors.New("decide needs --agent-key, --chain, --workspace, --operation, --action, and --api")
	}
	if apiKey == "" {
		return errors.New("RATIFY_RECEIVER_API_KEY is required")
	}
	base, err := url.Parse(*api)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return errors.New("--api must be an HTTPS URL")
	}
	agent, err := loadKey(*agentPath)
	if err != nil {
		return err
	}
	agentID, err := setup.V2KeyID(agent.Public())
	if err != nil {
		return err
	}
	var chain []ratify.DelegationCertV2
	for _, path := range strings.Split(*chainPaths, ",") {
		data, err := readFile(path)
		if err != nil {
			return err
		}
		cert, err := ratify.DecodeDelegationCertV2(data)
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		chain = append(chain, *cert)
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	invocation := "acceptance-" + hex.EncodeToString(random)
	requestHash := sha256.Sum256([]byte(*operation + " " + *action + " " + invocation))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var issued struct {
		Challenge  []byte `json:"challenge"`
		VerifierID string `json:"verifier_id"`
		IssuedAt   int64  `json:"issued_at"`
	}
	if err := post(ctx, client, base.JoinPath("/v1/verify/v2/challenges").String(), apiKey, map[string]any{
		"operation_id": *operation, "action": *action, "agent_public_key": agent.Public(),
		"session_id": "acceptance-session", "invocation_id": invocation, "request_hash": requestHash[:]}, &issued); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	session, err := ratify.BuildSessionContextV2(ratify.SessionContextV2Inputs{VerifierID: issued.VerifierID,
		WorkspaceID: *workspace, AgentID: agentID, SessionID: "acceptance-session", InvocationID: invocation,
		RequestHash: requestHash[:]})
	if err != nil {
		return err
	}
	bundle, err := ratify.SignProofBundleV2(&ratify.ProofBundleV2{Version: 2, VerifierID: issued.VerifierID,
		AgentID: agentID, AgentPubKey: agent.Public(), Delegations: chain, Challenge: issued.Challenge,
		ChallengeAt: issued.IssuedAt, SessionContext: &session}, agent)
	if err != nil {
		return err
	}
	wire, err := ratify.EncodeProofBundleV2(bundle)
	if err != nil {
		return err
	}
	var decision struct {
		Decision           string `json:"decision"`
		DecisionReason     string `json:"decision_reason"`
		ClaimID            string `json:"claim_id"`
		ChallengeExpiresAt *int64 `json:"challenge_expires_at"`
		AllowHorizon       *int64 `json:"allow_horizon"`
	}
	if err := post(ctx, client, base.JoinPath("/v1/verify/v2/proofs").String(), apiKey, map[string]any{
		"operation_id": *operation, "action": *action, "challenge": issued.Challenge,
		"proof_bundle": json.RawMessage(wire), "session_id": "acceptance-session",
		"invocation_id": invocation, "request_hash": requestHash[:]}, &decision); err != nil {
		return fmt.Errorf("proof: %w", err)
	}
	// Act on an allow only before both deadlines, by this receiver's clock;
	// otherwise it is reported as allow_expired, never as allow.
	outcome := decision.Decision
	if outcome == "allow" {
		now := time.Now().Unix()
		if decision.ChallengeExpiresAt == nil || decision.AllowHorizon == nil ||
			now >= *decision.ChallengeExpiresAt || now >= *decision.AllowHorizon {
			outcome = "allow_expired"
		}
	}
	line, _ := json.Marshal(map[string]string{"decision": outcome, "reason": decision.DecisionReason,
		"claim_id": decision.ClaimID, "invocation_id": invocation, "cert_id": chain[0].CertID})
	fmt.Fprintln(stdout, string(line))
	switch outcome {
	case "allow":
		return nil
	case "allow_expired":
		return errors.New("the allow arrived without a current challenge expiry and allow horizon; do not act on it")
	case "deny":
		return errDenied
	default:
		return fmt.Errorf("Verify returned no terminal decision")
	}
}

func post(ctx context.Context, base *http.Client, target, apiKey string, body, into any) error {
	// Never follow a redirect: it would carry the receiver API key elsewhere.
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ratify-API-Key", apiKey)
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxFileBytes))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	return json.Unmarshal(payload, into)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s could not be read", path)
	}
	return data, nil
}

func readStrict(path string, into any) error {
	data, err := readFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	return nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("refusing to write %s: %w", path, err)
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// loadKey reads an owner-only ratify-keys private key file.
func loadKey(path string) (ratify.HybridPrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return ratify.HybridPrivateKey{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file %s must be readable only by you", path)
	}
	var file struct {
		Ed25519 []byte `json:"ed25519_private_key"`
		MLDSA65 []byte `json:"mldsa65_private_key"`
	}
	if err := readStrict(path, &file); err != nil || len(file.Ed25519) != ed25519.PrivateKeySize {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file %s is not a ratify-keys private key", path)
	}
	ml := new(mldsa65.PrivateKey)
	if ml.UnmarshalBinary(file.MLDSA65) != nil {
		return ratify.HybridPrivateKey{}, fmt.Errorf("key file %s is not a ratify-keys private key", path)
	}
	return ratify.HybridPrivateKey{Ed25519: ed25519.PrivateKey(file.Ed25519), MLDSA65: ml}, nil
}
