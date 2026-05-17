// ratify-cli — Ratify Protocol command-line tool.
//
// Runs on the delegator's device. Private key material never leaves this
// machine. v1 uses hybrid Ed25519 + ML-DSA-65 keys stored as two 32-byte
// seeds plus a public JSON file:
//
//	~/.ratify/root.ed25519.seed   (32 bytes, mode 0600)
//	~/.ratify/root.mldsa65.seed   (32 bytes, mode 0600)
//	~/.ratify/root.json           (public HumanRoot metadata, mode 0644)
//
// Keypairs are deterministically derived from the seed files on every load.
//
// Commands:
//
//	ratify init                           Generate a new hybrid human root keypair
//	ratify delegate --agent-pubkey-file <path>
//	                --scope <scopes> [--days 7]
//	                                      Issue a signed delegation certificate
//	ratify verify --bundle <path>         Verify a proof bundle locally (no API)
//	ratify scopes                         Print the canonical scope vocabulary
//	ratify status                         Show this device's identity state
//
// Quickstart (two machines; no server required):
//
//	ratify init                                                 # delegator side
//	# agent on its machine runs a hybrid keygen, outputs pubkey.json
//	ratify delegate --agent-pubkey-file pubkey.json \
//	                --scope "meeting:*"  \
//	                --days 7
//	# send delegation.json to the agent
//	# agent produces bundle.json using its private key
//	ratify verify --bundle bundle.json --scope meeting:attend
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

// ============================================================================
// Key store — seeds on disk, mode 0600. The hybrid keypair is reconstructed
// on every load via ratify.HybridKeypairFromSeeds.
// ============================================================================

const keyDirName = ".ratify"

type keyStore struct {
	dir string
}

func newKeyStore() *keyStore {
	home, err := os.UserHomeDir()
	if err != nil {
		fatalf("cannot find home directory: %v", err)
	}
	dir := filepath.Join(home, keyDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatalf("cannot create key store at %s: %v", dir, err)
	}
	return &keyStore{dir: dir}
}

func (ks *keyStore) path(name string) string { return filepath.Join(ks.dir, name) }

func (ks *keyStore) exists(name string) bool {
	_, err := os.Stat(ks.path(name))
	return err == nil
}

func (ks *keyStore) writeFile(name string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(ks.path(name), data, mode); err != nil {
		fatalf("cannot save %s: %v", name, err)
	}
}

func (ks *keyStore) readFile(name string) ([]byte, error) {
	return os.ReadFile(ks.path(name))
}

// hasRoot returns true iff all three root artifacts exist.
func (ks *keyStore) hasRoot() bool {
	return ks.exists("root.ed25519.seed") && ks.exists("root.mldsa65.seed") && ks.exists("root.json")
}

// saveRootKeypair writes the two seeds + public JSON to disk.
func (ks *keyStore) saveRootKeypair(edSeed, mlSeed [32]byte, root *ratify.HumanRoot) {
	ks.writeFile("root.ed25519.seed", edSeed[:], 0o600)
	ks.writeFile("root.mldsa65.seed", mlSeed[:], 0o600)
	rootJSON, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		fatalf("marshal root.json: %v", err)
	}
	ks.writeFile("root.json", rootJSON, 0o644)
}

// loadRoot returns the public HumanRoot and the reconstructed hybrid private key.
func (ks *keyStore) loadRoot() (*ratify.HumanRoot, ratify.HybridPrivateKey) {
	if !ks.hasRoot() {
		fatalf("no root identity found. Run 'ratify init' first.")
	}
	edSeedBytes, err := ks.readFile("root.ed25519.seed")
	if err != nil {
		fatalf("read ed25519 seed: %v", err)
	}
	if len(edSeedBytes) != 32 {
		fatalf("root.ed25519.seed is corrupt (expected 32 bytes, got %d)", len(edSeedBytes))
	}
	mlSeedBytes, err := ks.readFile("root.mldsa65.seed")
	if err != nil {
		fatalf("read ml-dsa-65 seed: %v", err)
	}
	if len(mlSeedBytes) != 32 {
		fatalf("root.mldsa65.seed is corrupt (expected 32 bytes, got %d)", len(mlSeedBytes))
	}
	var edSeed, mlSeed [32]byte
	copy(edSeed[:], edSeedBytes)
	copy(mlSeed[:], mlSeedBytes)
	_, priv, err := ratify.HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		fatalf("reconstruct hybrid keypair: %v", err)
	}

	rootJSON, err := ks.readFile("root.json")
	if err != nil {
		fatalf("read root.json: %v", err)
	}
	var root ratify.HumanRoot
	if err := json.Unmarshal(rootJSON, &root); err != nil {
		fatalf("parse root.json: %v", err)
	}
	return &root, priv
}

// ============================================================================
// main / dispatch
// ============================================================================

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		cmdInit(args)
	case "delegate":
		cmdDelegate(args)
	case "verify":
		cmdVerify(args)
	case "status":
		cmdStatus(args)
	case "scopes":
		cmdScopes(args)
	case "agent-init":
		cmdAgentInit(args)
	case "agent-bundle":
		cmdAgentBundle(args)
	case "challenge":
		cmdChallenge(args)
	case "help", "--help", "-h":
		printUsage()
	default:
		fatalf("unknown command: %q\nRun 'ratify help' for usage.", cmd)
	}
}

// ============================================================================
// ratify init — generate a hybrid human root keypair from OS randomness
// ============================================================================

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite existing keypair")
	_ = fs.Parse(args)

	ks := newKeyStore()
	if ks.hasRoot() && !*force {
		fatalf("keypair already exists at %s\nUse --force to overwrite.", ks.dir)
	}

	// Draw two fresh 32-byte seeds from the OS RNG, then derive deterministic
	// keys from them. Seeds are stored; keys are reconstructed on load.
	var edSeed, mlSeed [32]byte
	if _, err := osRandRead(edSeed[:]); err != nil {
		fatalf("ed25519 seed: %v", err)
	}
	if _, err := osRandRead(mlSeed[:]); err != nil {
		fatalf("ml-dsa-65 seed: %v", err)
	}

	pub, _, err := ratify.HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		fatalf("keygen from seeds: %v", err)
	}
	root := &ratify.HumanRoot{
		ID:        ratify.DeriveID(pub),
		PublicKey: pub,
		CreatedAt: time.Now().Unix(),
	}
	ks.saveRootKeypair(edSeed, mlSeed, root)

	fmt.Println("Hybrid human root identity created.")
	fmt.Printf("  Root ID:            %s\n", root.ID)
	fmt.Printf("  Ed25519 public:     %s\n", hex.EncodeToString(root.PublicKey.Ed25519))
	fmt.Printf("  ML-DSA-65 public:   %s... (%d bytes)\n",
		hex.EncodeToString(root.PublicKey.MLDSA65[:16]), len(root.PublicKey.MLDSA65))
	fmt.Printf("  Stored at:          %s/\n", ks.dir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  - Receive the agent's hybrid public key (JSON file).")
	fmt.Println("  - Run 'ratify delegate --agent-pubkey-file <path> --scope ...'")
}

// ============================================================================
// ratify delegate — issue a signed DelegationCert to an agent
// ============================================================================

func cmdDelegate(args []string) {
	fs := flag.NewFlagSet("delegate", flag.ExitOnError)
	agentPubKeyFile := fs.String("agent-pubkey-file", "",
		"Path to a JSON file containing the agent's HybridPublicKey")
	scopeStr := fs.String("scope", "meeting:attend,meeting:speak",
		"Comma-separated scopes to grant (see 'ratify scopes')")
	days := fs.Int("days", 7, "Validity period in days")
	outFile := fs.String("out", "delegation.json", "Output file for the signed delegation cert")
	_ = fs.Parse(args)

	if *agentPubKeyFile == "" {
		fatalf("--agent-pubkey-file is required\nThe file must contain a HybridPublicKey JSON: " +
			`{"ed25519":"<base64>","ml_dsa_65":"<base64>"}`)
	}

	pubBytes, err := os.ReadFile(*agentPubKeyFile)
	if err != nil {
		fatalf("read agent pubkey: %v", err)
	}
	var agentPub ratify.HybridPublicKey
	if err := json.Unmarshal(pubBytes, &agentPub); err != nil {
		fatalf("parse agent pubkey: %v (expected HybridPublicKey JSON)", err)
	}
	if len(agentPub.Ed25519) != 32 {
		fatalf("agent Ed25519 pubkey has wrong length: %d (want 32)", len(agentPub.Ed25519))
	}
	if len(agentPub.MLDSA65) != 1952 {
		fatalf("agent ML-DSA-65 pubkey has wrong length: %d (want 1952)", len(agentPub.MLDSA65))
	}

	ks := newKeyStore()
	root, priv := ks.loadRoot()

	scopes := strings.Split(*scopeStr, ",")
	for i, s := range scopes {
		scopes[i] = strings.TrimSpace(s)
	}
	if err := ratify.ValidateScopes(scopes); err != nil {
		fatalf("invalid scope: %v\nRun 'ratify scopes' to see the canonical vocabulary.", err)
	}

	now := time.Now()
	cert := &ratify.DelegationCert{
		CertID:        fmt.Sprintf("cert-%x", now.UnixNano()),
		Version:       ratify.ProtocolVersion,
		IssuerID:      root.ID,
		IssuerPubKey:  root.PublicKey,
		SubjectID:     ratify.DeriveID(agentPub),
		SubjectPubKey: agentPub,
		Scope:         scopes,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(time.Duration(*days) * 24 * time.Hour).Unix(),
	}
	if err := ratify.IssueDelegation(cert, priv); err != nil {
		fatalf("signing failed: %v", err)
	}

	certJSON, _ := json.MarshalIndent(cert, "", "  ")
	if err := os.WriteFile(*outFile, certJSON, 0o644); err != nil {
		fatalf("write delegation: %v", err)
	}
	fmt.Println("Signed hybrid delegation certificate issued.")
	fmt.Printf("  Cert ID:  %s\n", cert.CertID)
	fmt.Printf("  Issuer:   %s (you)\n", cert.IssuerID)
	fmt.Printf("  Agent:    %s\n", cert.SubjectID)
	fmt.Printf("  Scope:    %s\n", strings.Join(cert.Scope, ", "))
	fmt.Printf("  Expires:  %s (%d days)\n", time.Unix(cert.ExpiresAt, 0).Format(time.RFC3339), *days)
	fmt.Printf("  File:     %s\n", *outFile)
	fmt.Println()
	fmt.Println("Give this file to the agent. They will include it in proof bundles.")
}

// ============================================================================
// ratify verify — verify a proof bundle locally (no server required)
// ============================================================================

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	bundleFile := fs.String("bundle", "", "Path to proof bundle JSON")
	scope := fs.String("scope", "", "Required scope (empty = skip scope check)")
	_ = fs.Parse(args)

	if *bundleFile == "" {
		fatalf("--bundle is required")
	}
	data, err := os.ReadFile(*bundleFile)
	if err != nil {
		fatalf("read bundle: %v", err)
	}
	var bundle ratify.ProofBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		fatalf("parse bundle: %v", err)
	}

	result := ratify.Verify(&bundle, ratify.VerifyOptions{RequiredScope: *scope})

	if result.Valid {
		fmt.Println("VALID")
		fmt.Printf("  Human ID:  %s\n", result.HumanID)
		fmt.Printf("  Agent ID:  %s\n", result.AgentID)
		fmt.Printf("  Status:    %s\n", result.IdentityStatus)
		if len(result.GrantedScope) > 0 {
			fmt.Printf("  Scope:     %s\n", strings.Join(result.GrantedScope, ", "))
		}
	} else {
		fmt.Println("INVALID")
		fmt.Printf("  Status:    %s\n", result.IdentityStatus)
		fmt.Printf("  Reason:    %s\n", result.ErrorReason)
		os.Exit(1)
	}
}

// ============================================================================
// ratify status — print this device's identity state
// ============================================================================

func cmdStatus(args []string) {
	ks := newKeyStore()
	if !ks.hasRoot() {
		fmt.Println("No root identity. Run 'ratify init' to create one.")
		return
	}
	rootJSON, err := ks.readFile("root.json")
	if err != nil {
		fatalf("read root.json: %v", err)
	}
	var root ratify.HumanRoot
	if err := json.Unmarshal(rootJSON, &root); err != nil {
		fatalf("parse root.json: %v", err)
	}
	fmt.Println("Hybrid root identity:")
	fmt.Printf("  Root ID:           %s\n", root.ID)
	fmt.Printf("  Created:           %s\n", time.Unix(root.CreatedAt, 0).Format(time.RFC3339))
	fmt.Printf("  Ed25519 pubkey:    %s\n", hex.EncodeToString(root.PublicKey.Ed25519))
	fmt.Printf("  ML-DSA-65 pubkey:  %s... (%d bytes)\n",
		hex.EncodeToString(root.PublicKey.MLDSA65[:16]), len(root.PublicKey.MLDSA65))
	fmt.Printf("  Storage:           %s/\n", ks.dir)
	fmt.Println()
	fmt.Println("Signing algorithms: Ed25519 + ML-DSA-65 (FIPS 204)")
	fmt.Println("Both signatures are produced on every operation; both must verify.")
}

// ============================================================================
// ratify scopes — list the canonical scope vocabulary
// ============================================================================

func cmdScopes(args []string) {
	fmt.Println("Canonical Ratify v1 scope vocabulary (53 scopes + 14 wildcards + custom: pattern)")
	fmt.Println()
	fmt.Println("Meeting:")
	fmt.Println("  meeting:attend")
	fmt.Println("  meeting:speak")
	fmt.Println("  meeting:video")
	fmt.Println("  meeting:chat")
	fmt.Println("  meeting:share_screen")
	fmt.Println("  meeting:record             (sensitive)")
	fmt.Println()
	fmt.Println("Communication:")
	fmt.Println("  comms:message:read")
	fmt.Println("  comms:message:send")
	fmt.Println("  comms:message:delete       (sensitive)")
	fmt.Println("  comms:email:read")
	fmt.Println("  comms:email:send")
	fmt.Println("  comms:email:delete         (sensitive)")
	fmt.Println("  comms:calendar:read")
	fmt.Println("  comms:calendar:write")
	fmt.Println()
	fmt.Println("Files:")
	fmt.Println("  files:read")
	fmt.Println("  files:write                (sensitive)")
	fmt.Println()
	fmt.Println("Identity:")
	fmt.Println("  identity:prove")
	fmt.Println("  identity:delegate          (sensitive)")
	fmt.Println()
	fmt.Println("Transactions:")
	fmt.Println("  transact:purchase")
	fmt.Println("  transact:sell")
	fmt.Println("  payments:send")
	fmt.Println("  payments:receive")
	fmt.Println("  payments:authorize         (sensitive)")
	fmt.Println()
	fmt.Println("Contracts:")
	fmt.Println("  contract:read")
	fmt.Println("  contract:sign              (sensitive)")
	fmt.Println()
	fmt.Println("Data (structured records, distinct from files):")
	fmt.Println("  data:read")
	fmt.Println("  data:write                 (sensitive)")
	fmt.Println("  data:delete                (sensitive)")
	fmt.Println("  data:export                (sensitive — exfiltration)")
	fmt.Println("  data:share")
	fmt.Println()
	fmt.Println("Execute:")
	fmt.Println("  execute:tool")
	fmt.Println("  execute:code               (sensitive)")
	fmt.Println()
	fmt.Println("Generate (AI content):")
	fmt.Println("  generate:content")
	fmt.Println("  generate:deepfake          (sensitive — audit trail)")
	fmt.Println()
	fmt.Println("Wildcards (expand only to non-sensitive scopes):")
	fmt.Println("  meeting:*         attend + speak + video + chat + share_screen")
	fmt.Println("  comms:*           all non-sensitive comms")
	fmt.Println("  comms:message:*   message:read + message:send")
	fmt.Println("  comms:email:*     email:read + email:send")
	fmt.Println("  transact:*        purchase + sell")
	fmt.Println("  payments:*        send + receive (NOT authorize)")
	fmt.Println("  data:*            read + share (NOT write/delete/export)")
	fmt.Println("  execute:*         tool (NOT code)")
	fmt.Println("  generate:*        content (NOT deepfake)")
	fmt.Println()
	fmt.Println("Custom extension pattern:")
	fmt.Println("  custom:<anything>          App-specific scope; never expanded;")
	fmt.Println("                             non-sensitive unless app enforces policy.")
	fmt.Println("                             Example: custom:acme:inventory:read")
}

// ============================================================================
// ratify agent-init — generate a hybrid agent keypair (for demo/testing)
//
// In production, agents are typically created and managed by their platform
// (Retell, Bland, Vapi, Agentforce, MCP server). This command exists so a
// developer testing the protocol locally can produce a full end-to-end flow
// without writing any code.
// ============================================================================

func cmdAgentInit(args []string) {
	fs := flag.NewFlagSet("agent-init", flag.ExitOnError)
	pubOut := fs.String("out", "agent-pubkey.json", "Output file for the agent's hybrid public key JSON")
	privOut := fs.String("priv-out", "agent.priv", "Output file for the agent's hybrid private key (two 32-byte seeds concatenated)")
	_ = fs.Parse(args)

	// Generate two independent 32-byte seeds and derive the hybrid keypair.
	var edSeed, mlSeed [32]byte
	if _, err := rand.Read(edSeed[:]); err != nil {
		fatalf("ed25519 seed: %v", err)
	}
	if _, err := rand.Read(mlSeed[:]); err != nil {
		fatalf("ml-dsa-65 seed: %v", err)
	}
	pub, _, err := ratify.HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		fatalf("keygen: %v", err)
	}
	agentID := ratify.DeriveID(pub)

	pubJSON, _ := json.MarshalIndent(pub, "", "  ")
	if err := os.WriteFile(*pubOut, pubJSON, 0o644); err != nil {
		fatalf("write pubkey: %v", err)
	}

	// Private file: 64 bytes (32 Ed25519 seed || 32 ML-DSA-65 seed).
	privBytes := append(edSeed[:], mlSeed[:]...)
	if err := os.WriteFile(*privOut, privBytes, 0o600); err != nil {
		fatalf("write priv: %v", err)
	}

	fmt.Println("Hybrid agent keypair generated.")
	fmt.Printf("  Agent ID:            %s\n", agentID)
	fmt.Printf("  Ed25519 pubkey:      %s\n", hex.EncodeToString(pub.Ed25519))
	fmt.Printf("  ML-DSA-65 pubkey:    %s... (%d bytes)\n",
		hex.EncodeToString(pub.MLDSA65[:16]), len(pub.MLDSA65))
	fmt.Printf("  Public key JSON:     %s\n", *pubOut)
	fmt.Printf("  Private key file:    %s (0600)\n", *privOut)
	fmt.Println()
	fmt.Println("Give the public key JSON to the delegator. Keep the private file secret.")
}

// ============================================================================
// ratify challenge — generate 32 random bytes, print as hex
//
// In production, the VERIFIER issues challenges. This helper exists so a
// developer testing locally can simulate the verifier handing a challenge to
// the agent for bundle construction.
// ============================================================================

func cmdChallenge(args []string) {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	format := fs.String("format", "hex", "Output format: hex or base64")
	_ = fs.Parse(args)

	b, err := ratify.GenerateChallenge()
	if err != nil {
		fatalf("generate challenge: %v", err)
	}
	switch *format {
	case "hex":
		fmt.Println(hex.EncodeToString(b))
	case "base64", "b64":
		fmt.Println(base64.StdEncoding.EncodeToString(b))
	default:
		fatalf("unknown --format: %s", *format)
	}
}

// ============================================================================
// ratify agent-bundle — assemble a signed ProofBundle
//
// Reads the delegation cert the agent received, the agent's private key, and
// a challenge provided by the verifier. Produces a ProofBundle JSON ready to
// hand back to the verifier.
// ============================================================================

func cmdAgentBundle(args []string) {
	fs := flag.NewFlagSet("agent-bundle", flag.ExitOnError)
	certPath := fs.String("cert", "", "Path to delegation cert JSON (received from delegator)")
	privPath := fs.String("priv", "agent.priv", "Path to agent private key file (from 'ratify agent-init')")
	challengeHex := fs.String("challenge-hex", "", "Challenge bytes from the verifier (hex-encoded)")
	challengeAt := fs.Int64("challenge-at", time.Now().Unix(), "Unix seconds when the challenge is being signed (default: now)")
	outFile := fs.String("out", "bundle.json", "Output file for the signed proof bundle")
	_ = fs.Parse(args)

	if *certPath == "" {
		fatalf("--cert is required (path to delegation.json)")
	}
	if *challengeHex == "" {
		fatalf("--challenge-hex is required (get one with 'ratify challenge')")
	}

	// Load the delegation cert.
	certBytes, err := os.ReadFile(*certPath)
	if err != nil {
		fatalf("read cert: %v", err)
	}
	var cert ratify.DelegationCert
	if err := json.Unmarshal(certBytes, &cert); err != nil {
		fatalf("parse cert: %v", err)
	}

	// Load the agent private key (two 32-byte seeds concatenated).
	privBytes, err := os.ReadFile(*privPath)
	if err != nil {
		fatalf("read priv: %v", err)
	}
	if len(privBytes) != 64 {
		fatalf("agent.priv must be 64 bytes (32 Ed25519 seed + 32 ML-DSA-65 seed); got %d", len(privBytes))
	}
	var edSeed, mlSeed [32]byte
	copy(edSeed[:], privBytes[:32])
	copy(mlSeed[:], privBytes[32:])
	agentPub, agentPriv, err := ratify.HybridKeypairFromSeeds(edSeed, mlSeed)
	if err != nil {
		fatalf("reconstruct agent keypair: %v", err)
	}

	// Sanity check: agent pubkey matches the cert's subject pubkey.
	if !bytes.Equal(agentPub.Ed25519, cert.SubjectPubKey.Ed25519) ||
		!bytes.Equal(agentPub.MLDSA65, cert.SubjectPubKey.MLDSA65) {
		fatalf("agent key does not match cert subject (wrong --priv for this cert?)")
	}

	// Decode challenge.
	challenge, err := hex.DecodeString(*challengeHex)
	if err != nil {
		fatalf("--challenge-hex is not valid hex: %v", err)
	}

	// Sign the challenge.
	sig, err := ratify.SignChallenge(challenge, *challengeAt, agentPriv)
	if err != nil {
		fatalf("sign challenge: %v", err)
	}

	bundle := &ratify.ProofBundle{
		AgentID:      cert.SubjectID,
		AgentPubKey:  agentPub,
		Delegations:  []ratify.DelegationCert{cert},
		Challenge:    challenge,
		ChallengeAt:  *challengeAt,
		ChallengeSig: sig,
	}

	bundleJSON, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(*outFile, bundleJSON, 0o644); err != nil {
		fatalf("write bundle: %v", err)
	}

	fmt.Println("Proof bundle assembled.")
	fmt.Printf("  Agent ID:      %s\n", bundle.AgentID)
	fmt.Printf("  Cert ID:       %s\n", cert.CertID)
	fmt.Printf("  Scope:         %s\n", strings.Join(cert.Scope, ", "))
	fmt.Printf("  Challenge:     %s... (%d bytes)\n", hex.EncodeToString(challenge[:8]), len(challenge))
	fmt.Printf("  Signed at:     %s\n", time.Unix(*challengeAt, 0).Format(time.RFC3339))
	fmt.Printf("  Output:        %s\n", *outFile)
}

// ============================================================================
// helpers
// ============================================================================

func printUsage() {
	fmt.Print(`ratify — Ratify Protocol v1 CLI

Usage:
  ratify <command> [flags]

Commands:
  init                              Generate a new hybrid human root keypair
  delegate --agent-pubkey-file P    Issue a delegation cert to an agent
           --scope "<scopes>"
           [--days 7]
           [--out delegation.json]
  verify   --bundle PATH            Verify a proof bundle (no API required)
           [--scope SCOPE]
  status                            Show this device's identity state
  scopes                            Print the canonical scope vocabulary

Testing / demo (agent-side commands for bash-only end-to-end):
  agent-init [--out PATH]           Generate a hybrid agent keypair
             [--priv-out PATH]
  challenge  [--format hex|base64]  Generate 32 random bytes (simulate verifier)
  agent-bundle --cert PATH          Assemble a signed ProofBundle
               --priv PATH
               --challenge-hex HEX
               [--challenge-at UNIX]
               [--out bundle.json]

  help                              This message

Bash-only end-to-end demo:
  mkdir -p /tmp/fab && cd /tmp/fab
  HOME=$PWD ratify init
  HOME=$PWD ratify agent-init
  HOME=$PWD ratify delegate --agent-pubkey-file agent-pubkey.json \\
    --scope "meeting:attend" --out delegation.json
  C=$(HOME=$PWD ratify challenge)
  HOME=$PWD ratify agent-bundle --cert delegation.json \\
    --priv agent.priv --challenge-hex $C --out bundle.json
  HOME=$PWD ratify verify --bundle bundle.json --scope meeting:attend
`)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

// osRandRead reads from the OS cryptographically-secure RNG.
func osRandRead(p []byte) (int, error) {
	return rand.Read(p)
}
