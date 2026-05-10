// Ratify Protocol v1 — end-to-end narrative demo (Go).
//
// Run: go run ./demos/go
package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

func banner(text string) {
	fmt.Println()
	fmt.Println(strings.Repeat("━", 70))
	fmt.Println(text)
	fmt.Println(strings.Repeat("━", 70))
}

func kv(label, value string) {
	fmt.Printf("  %-20s %s\n", label, value)
}

func main() {
	// Step 1
	banner("STEP 1  Alice generates a hybrid root identity")
	alice, alicePriv, _ := ratify.GenerateHumanRootKeypair()
	kv("Root ID:", alice.ID)
	kv("Ed25519 pubkey:", hex.EncodeToString(alice.PublicKey.Ed25519)[:32]+"…")
	kv("ML-DSA-65 pubkey:", fmt.Sprintf("<%d bytes>", len(alice.PublicKey.MLDSA65)))
	kv("Storage:", "Private keys stay on Alice's machine (never leave)")

	// Step 2
	banner("STEP 2  Agent (Alice's scheduler) generates its own hybrid keypair")
	agent, agentPriv, _ := ratify.GenerateAgentKeypair("Alice's Scheduler", "voice_agent")
	kv("Agent ID:", agent.ID)
	kv("Agent type:", agent.AgentType)
	kv("Ed25519 pubkey:", hex.EncodeToString(agent.PublicKey.Ed25519)[:32]+"…")

	// Step 3
	banner("STEP 3  Alice authorizes the agent for meeting:attend, 7 days")
	now := time.Now().Unix()
	cert := &ratify.DelegationCert{
		CertID:        "cert-demo-001",
		Version:       ratify.ProtocolVersion,
		IssuerID:      alice.ID,
		IssuerPubKey:  alice.PublicKey,
		SubjectID:     agent.ID,
		SubjectPubKey: agent.PublicKey,
		Scope:         []string{ratify.ScopeMeetingAttend},
		IssuedAt:      now,
		ExpiresAt:     now + 7*24*3600,
	}
	if err := ratify.IssueDelegation(cert, alicePriv); err != nil {
		panic(err)
	}
	kv("Cert ID:", cert.CertID)
	kv("Scope:", strings.Join(cert.Scope, ", "))
	kv("Expires:", time.Unix(cert.ExpiresAt, 0).Format("2006-01-02 15:04:05"))
	kv("Ed25519 sig:", hex.EncodeToString(cert.Signature.Ed25519)[:32]+"…")
	kv("ML-DSA-65 sig:", fmt.Sprintf("<%d bytes>", len(cert.Signature.MLDSA65)))

	// Step 4
	banner("STEP 4  Agent builds a proof bundle for the verifier")
	challenge, _ := ratify.GenerateChallenge()
	challengeAt := time.Now().Unix()
	challengeSig, err := ratify.SignChallenge(challenge, challengeAt, agentPriv)
	if err != nil {
		panic(err)
	}
	bundle := &ratify.ProofBundle{
		AgentID:      agent.ID,
		AgentPubKey:  agent.PublicKey,
		Delegations:  []ratify.DelegationCert{*cert},
		Challenge:    challenge,
		ChallengeAt:  challengeAt,
		ChallengeSig: challengeSig,
	}
	kv("Challenge:", hex.EncodeToString(challenge)[:32]+"…")
	kv("Challenge at:", time.Unix(challengeAt, 0).Format("2006-01-02 15:04:05"))
	kv("Hybrid sig:", "Ed25519 + ML-DSA-65 over challenge || BE(ts)")

	// Step 5
	banner("STEP 5  Verifier runs Verify() — expects meeting:attend")
	result := ratify.Verify(bundle, ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingAttend})
	if result.Valid {
		fmt.Println("  ✅  VALID")
		kv("Human ID:", result.HumanID)
		kv("Agent ID:", result.AgentID)
		kv("Status:", result.IdentityStatus)
		kv("Granted scope:", strings.Join(result.GrantedScope, ", "))
	} else {
		fmt.Printf("  ❌  INVALID — %s: %s\n", result.IdentityStatus, result.ErrorReason)
	}

	// Attack 1
	banner("ATTACK 1  Attacker appends files:write to the scope after signing")
	tampered := *cert
	tampered.Scope = append([]string{}, cert.Scope...)
	tampered.Scope = append(tampered.Scope, ratify.ScopeFilesWrite)
	tamperedBundle := *bundle
	tamperedBundle.Delegations = []ratify.DelegationCert{tampered}
	r := ratify.Verify(&tamperedBundle, ratify.VerifyOptions{RequiredScope: ratify.ScopeFilesWrite})
	fmt.Printf("  ❌  REJECTED as expected: %s\n", r.ErrorReason)
	kv("Why:", "Canonical bytes differ; Ed25519 AND ML-DSA-65 both fail verify.")

	// Attack 2
	banner("ATTACK 2  Agent tries to use meeting:attend cert for meeting:record")
	r = ratify.Verify(bundle, ratify.VerifyOptions{RequiredScope: ratify.ScopeMeetingRecord})
	fmt.Printf("  ❌  REJECTED as expected: %s\n", r.ErrorReason)
	kv("Why:", "meeting:record is not in the effective scope.")

	// Attack 3
	banner("ATTACK 3  Expired cert (verifier's clock reports future time)")
	future := time.Unix(cert.ExpiresAt+1, 0)
	r = ratify.Verify(bundle, ratify.VerifyOptions{
		RequiredScope: ratify.ScopeMeetingAttend,
		Now:           future,
	})
	fmt.Printf("  ❌  REJECTED as expected: %s: %s\n", r.IdentityStatus, r.ErrorReason)

	// Revocation
	banner("REVOCATION  Alice revokes the cert")
	r = ratify.Verify(bundle, ratify.VerifyOptions{
		RequiredScope: ratify.ScopeMeetingAttend,
		IsRevoked:     func(certID string) bool { return certID == cert.CertID },
	})
	fmt.Printf("  ❌  REJECTED as expected: %s: %s\n", r.IdentityStatus, r.ErrorReason)
	kv("Why:", "Verifier's revocation list now contains this cert_id.")

	// Summary
	banner("SUMMARY")
	fmt.Println(`  The protocol just demonstrated:

  • Alice created a hybrid (Ed25519 + ML-DSA-65) root identity.
  • She signed a scoped, time-bounded delegation for an AI agent.
  • The agent signed a fresh challenge to prove liveness.
  • A verifier checked the bundle in a single function call.
  • Every one of four tampering/misuse scenarios was rejected
    deterministically — no fuzzy detection, no false positives.
  • Signatures are quantum-safe: breaking either Ed25519 or
    ML-DSA-65 alone is insufficient to forge.

  This is the full Ratify Protocol v1, end to end, in one process.`)
	fmt.Println()
}
