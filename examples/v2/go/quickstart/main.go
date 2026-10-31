// Ratify Protocol v2 quickstart: delegate, present, verify, publish, release.
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// package v2reference (claim store, receipt log, checkpoint, journal and
// challenge issuance store). They exist for tests and examples. A production
// verifier supplies durable Part B stores and an independent checkpoint
// (SPEC-v2 §7).
//
// Run from the repository root: go run ./examples/v2/go/quickstart
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

const (
	start     = int64(1800000000) // fixed clock so the output is reproducible
	namespace = "quickstart"
	epoch     = int64(1)
	logID     = "00000000000000000000000000000001"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	fmt.Println("Ratify Protocol v2 quickstart")
	fmt.Println("development only: in-memory reference stores")

	// 1. Keys. Every party holds a hybrid Ed25519 + ML-DSA-65 key. The status
	// key is separate from the root key that issues delegations.
	rootPub, rootPriv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	agentPub, agentPriv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	statusPub, statusPriv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	verifierPub, verifierPriv, err := ratify.GenerateHybridKeypair()
	if err != nil {
		return err
	}
	rootID, _ := ratify.KeyIDV2(rootPub)
	agentID, _ := ratify.KeyIDV2(agentPub)
	verifierID, _ := ratify.KeyIDV2(verifierPub)
	fmt.Printf("keys: root, agent, status and verifier generated (key IDs are %d hex characters)\n", len(rootID))

	// 2. The root delegates payments:send to the agent, capped at 50.00 USD
	// per action (amounts are integer micro-units in v2).
	cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{
		Version: 2, CertID: "quickstart-cert-1",
		IssuerID: rootID, IssuerPubKey: rootPub,
		SubjectID: agentID, SubjectPubKey: agentPub,
		Scope: []string{"payments:send"},
		Constraints: []ratify.ConstraintV2{
			{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 50_000_000},
		},
		IssuedAt: start, ExpiresAt: start + 86400,
	}, rootPriv)
	if err != nil {
		return err
	}
	fmt.Println("delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s")

	// 3. Verifier state: the reference store is the claim store, receipt log,
	// checkpoint and authoritative clock. The journal records key roles and
	// the root's status key.
	store, err := v2reference.NewStore(start, 30, logID, verifierPriv)
	if err != nil {
		return err
	}
	journal, err := v2reference.NewJournalStore()
	if err != nil {
		return err
	}
	for role, pub := range map[string]ratify.HybridPublicKey{"issuer": rootPub, "delegation": agentPub, "verifier": verifierPub} {
		if _, err := ratify.RecordSecurityKeyRoleV2(ctx, journal, role, pub); err != nil {
			return err
		}
	}
	if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, rootID, 1, statusPub); err != nil {
		return err
	}

	// 4. The root's status publisher signs a genesis revocation list (no
	// revocations) under the separate status key.
	publisher, err := ratify.NewV2StatusPublisherWithKey(ctx, journal, rootPub, statusPriv, 3600)
	if err != nil {
		return err
	}
	genesis, err := publisher.Genesis(ctx, start)
	if err != nil {
		return err
	}
	statusWire, err := ratify.EncodeRevocationListV2(genesis.List)
	if err != nil {
		return err
	}
	fmt.Printf("status: genesis list signed by the status key (sequence %d, %d revoked)\n", genesis.State.Sequence, len(genesis.State.Revoked))

	// 5. The verifier issues a challenge. The helper persists the record
	// before it returns the challenge.
	issuance := v2reference.NewTestOnlyChallengeIssuanceStore()
	issuer := ratify.V2ChallengeIssuer{Clock: store, Store: issuance}
	challenge, err := issuer.IssueChallengeV2(ctx, ratify.V2ChallengeIssueRequest{
		VerifierNamespace: namespace, ReplayEpoch: epoch, VerifierID: verifierID,
		LifetimeSeconds: 120, ExpectedAgentID: agentID, ExpectedAgentPublicKey: &agentPub,
	})
	if err != nil {
		return err
	}
	fmt.Printf("challenge: issued and persisted, expires in %ds\n", challenge.ExpiresAt-challenge.IssuedAt)

	// 6. The agent signs a proof bundle over the challenge.
	store.SetTime(start + 2)
	bundle, err := ratify.SignProofBundleV2(&ratify.ProofBundleV2{
		Version: 2, VerifierID: verifierID, AgentID: agentID, AgentPubKey: agentPub,
		Delegations: []ratify.DelegationCertV2{*cert},
		Challenge:   challenge.Value, ChallengeAt: challenge.IssuedAt,
	}, agentPriv)
	if err != nil {
		return err
	}
	bundleWire, err := ratify.EncodeProofBundleV2(bundle)
	if err != nil {
		return err
	}
	fmt.Printf("proof: agent signed the presentation (%d delegation)\n", len(bundle.Delegations))

	// 7. Verify. The verifier loads the issuance record for the presented
	// challenge, then runs the full v2 decision path.
	verify := func() (ratify.V2VerifyOutcome, error) {
		expected, err := ratify.LoadExpectedChallengeV2(ctx, issuance, namespace, epoch, bundle.Challenge)
		if err != nil {
			return ratify.V2VerifyOutcome{}, err
		}
		policy, err := ratify.NewV2ContextPolicy("example.quickstart/v1", false, nil, nil)
		if err != nil {
			return ratify.V2VerifyOutcome{}, err
		}
		req := ratify.V2VerifyRequest{
			Bundle: bundleWire, Expected: expected, ContextPolicy: policy,
			RequiredScope: "payments:send", VerifierNamespace: namespace, ReplayEpoch: epoch, VerifierID: verifierID,
			Now: store.Now(), MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5,
			Context:      ratify.ConstraintContextV2{HasAmount: true, RequestedAmountMicros: 12_500_000, RequestedCurrency: "USD"},
			TZDBVersion:  ratify.TZDBVersionV2,
			StatusKeys:   map[string]ratify.V2StatusKeyConfig{rootID: {Epoch: 1, Key: statusPub}},
			StatusPolicy: ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5},
		}
		cb := ratify.V2VerifyCallbacks{
			ClaimStore: store,
			// Trust is pinned to the complete root public key, never a key ID.
			Trust: func(_ context.Context, chain []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
				if last := chain[len(chain)-1]; last.IssuerID == rootID {
					return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: rootPub}, nil
				}
				return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
			},
			StatusEvidence: func(context.Context, ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
				return ratify.V2StatusEvidenceBatch{Objects: []ratify.V2StatusEvidenceObject{{ObjectType: 3, Wire: statusWire}}}, nil
			},
			StatusJournal: journal,
		}
		return ratify.VerifyProofBundleV2(ctx, req, cb)
	}
	outcome, err := verify()
	if err != nil {
		return err
	}
	if outcome.Stage != ratify.V2StageCommitted {
		return fmt.Errorf("verify stopped at %s: %v", outcome.Stage, outcome.Error)
	}
	fmt.Println("verify: stage=committed (not actionable until released)")

	// 8. Publish the signed receipt to the log; the checkpoint acknowledges it.
	receiptWire, err := store.PublishV2Receipt(ctx, outcome.Committed.ClaimID(), outcome.Committed.ReceiptBody())
	if err != nil {
		return err
	}
	receipt, err := ratify.DecodeVerificationReceiptV2(receiptWire)
	if err != nil {
		return err
	}
	fmt.Printf("receipt: published at log sequence %d\n", receipt.Sequence)
	ack, err := store.GetV2Acknowledgement(ctx, logID, receipt.Sequence)
	if err != nil {
		return err
	}
	fmt.Printf("checkpoint: acknowledged sequence %d\n", ack.Sequence)

	// 9. Release. Only a released decision is actionable.
	result := ratify.ReleaseV2Decision(ctx, outcome.Committed, receiptWire, ratify.V2ReleaseConfig{
		VerifierPublicKey: verifierPub, LogID: logID, ClaimStore: store, Checkpoint: store,
	})
	if result.Status != ratify.V2ReleaseReleased {
		return fmt.Errorf("release %s: %s", result.Status, result.Reason)
	}
	decision := result.Decision
	fmt.Printf("release: status=%s decision=%s reason=%s\n", result.Status, decision.Decision(), decision.Reason())
	fmt.Printf("granted scope: %s\n", strings.Join(decision.GrantedScope(), ","))

	// 10. Gate the side effect on Allowed at the receiver's authoritative time.
	fmt.Printf("allowed now: %t\n", decision.Allowed(ctx, store))

	// 11. Presenting the same proof again is a replay and is never evaluated.
	store.SetTime(start + 3)
	replay, _ := verify()
	fmt.Printf("replay: stage=%s disposition=%s\n", replay.Stage, replay.Disposition)

	// 12. The released allow ends at the challenge expiry (an exclusive deadline).
	store.SetTime(challenge.ExpiresAt)
	fmt.Printf("allowed at challenge expiry: %t\n", decision.Allowed(ctx, store))
	return nil
}
