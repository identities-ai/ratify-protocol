// Bounded tool-call demo — portable authority across a two-agent workflow.
//
// Run from the repository root:
//
//	go run ./demos/bounded-tool-call
package main

import (
	"fmt"
	"strings"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

func main() {
	now := time.Now().Unix()

	alice, alicePrivate, err := ratify.GenerateHumanRootKeypair()
	must(err)
	lead, leadPrivate, err := ratify.GenerateAgentKeypair("Atlas", "orchestrator")
	must(err)
	buyer, buyerPrivate, err := ratify.GenerateAgentKeypair("Scout", "purchasing_agent")
	must(err)

	parent := ratify.DelegationCert{
		CertID:        "alice-to-atlas",
		Version:       ratify.ProtocolVersion,
		IssuerID:      alice.ID,
		IssuerPubKey:  alice.PublicKey,
		SubjectID:     lead.ID,
		SubjectPubKey: lead.PublicKey,
		Scope:         []string{ratify.ScopeExecuteTool, ratify.ScopeIdentityDelegate},
		Constraints: []ratify.Constraint{{
			Type:      ratify.ConstraintMaxAmount,
			MaxAmount: 5000,
			Currency:  "USD",
		}},
		IssuedAt:  now,
		ExpiresAt: now + 24*60*60,
	}
	must(ratify.IssueDelegation(&parent, alicePrivate))

	leaf := ratify.DelegationCert{
		CertID:        "atlas-to-scout",
		Version:       ratify.ProtocolVersion,
		IssuerID:      lead.ID,
		IssuerPubKey:  lead.PublicKey,
		SubjectID:     buyer.ID,
		SubjectPubKey: buyer.PublicKey,
		Scope:         []string{ratify.ScopeExecuteTool},
		Constraints: []ratify.Constraint{{
			Type:      ratify.ConstraintMaxAmount,
			MaxAmount: 500,
			Currency:  "USD",
		}},
		IssuedAt:  now,
		ExpiresAt: now + 60*60,
	}
	must(ratify.IssueDelegation(&leaf, leadPrivate))

	challenge, err := ratify.GenerateChallenge()
	must(err)
	challengeSignature, err := ratify.SignChallenge(challenge, now, buyerPrivate)
	must(err)
	bundle := ratify.ProofBundle{
		AgentID:      buyer.ID,
		AgentPubKey:  buyer.PublicKey,
		Delegations:  []ratify.DelegationCert{leaf, parent},
		Challenge:    challenge,
		ChallengeAt:  now,
		ChallengeSig: challengeSignature,
	}

	fmt.Println()
	fmt.Println("RATIFY — PORTABLE AUTHORITY AT THE POINT OF ACTION")
	fmt.Println()
	fmt.Println("Alice")
	fmt.Println("  └─ authorizes Atlas to call purchasing tools up to $5,000 for 24 hours")
	fmt.Println("       └─ Atlas authorizes Scout up to $500 for 1 hour")
	fmt.Println()

	printDecision(
		`Scout calls place_order(amount: $200)`,
		verifyToolCall(&bundle, 200, nil),
		"the complete human → lead agent → worker agent chain is valid",
	)
	printDecision(
		`Scout calls place_order(amount: $2,000)`,
		verifyToolCall(&bundle, 2000, nil),
		"Scout only received authority up to $500",
	)

	tamperedLeaf := leaf
	tamperedLeaf.Constraints = append([]ratify.Constraint(nil), leaf.Constraints...)
	tamperedLeaf.Constraints[0].MaxAmount = 5000
	tamperedBundle := bundle
	tamperedBundle.Delegations = append([]ratify.DelegationCert(nil), bundle.Delegations...)
	tamperedBundle.Delegations[0] = tamperedLeaf
	printDecision(
		"Scout edits its signed limit from $500 to $5,000",
		verifyToolCall(&tamperedBundle, 2000, nil),
		"changing the authorization invalidates its signature",
	)

	printDecision(
		"Alice revokes Atlas while Scout is still running",
		verifyToolCall(&bundle, 200, func(certID string) bool {
			return certID == parent.CertID
		}),
		"revoking the upstream grant invalidates the full chain",
	)

	fmt.Println("Any API can run the same deterministic check locally.")
	fmt.Println("No shared identity provider. No call to Ratify.")
	fmt.Println("Ratify authorizes the tool call; the vendor processes the order.")
	fmt.Println()
}

func verifyToolCall(bundle *ratify.ProofBundle, amount float64, revoked func(string) bool) ratify.VerifyResult {
	return ratify.Verify(bundle, ratify.VerifyOptions{
		RequiredScope: ratify.ScopeExecuteTool,
		IsRevoked:     revoked,
		Context: ratify.VerifierContext{
			RequestedAmount:   amount,
			RequestedCurrency: "USD",
			HasAmount:         true,
		},
	})
}

func printDecision(action string, result ratify.VerifyResult, explanation string) {
	fmt.Printf("%s\n", action)
	if result.Valid {
		fmt.Printf("  ALLOW  %s\n", result.IdentityStatus)
		fmt.Printf("  Why:   %s\n\n", explanation)
		return
	}
	fmt.Printf("  DENY   %s\n", decisionCode(result))
	fmt.Printf("  Why:   %s\n\n", explanation)
}

func decisionCode(result ratify.VerifyResult) string {
	if result.IdentityStatus != "invalid" {
		return result.IdentityStatus
	}
	code, _, ok := strings.Cut(result.ErrorReason, ":")
	if !ok {
		return result.IdentityStatus
	}
	return code
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
