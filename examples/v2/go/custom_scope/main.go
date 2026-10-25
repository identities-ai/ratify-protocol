// Ratify Protocol v2 custom scope and the standard max_count evaluator
// profile (com.ratifyprotocol.max_count/v1).
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// package v2reference. A production verifier supplies durable Part B stores
// and an independent checkpoint (SPEC-v2 §7).
//
// Run from the repository root: go run ./examples/v2/go/custom_scope
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

const (
	start       = int64(1800000000)
	namespace   = "custom-scope"
	epoch       = int64(1)
	logID       = "00000000000000000000000000000003"
	customScope = "custom:acme:deploy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	fmt.Println("Ratify Protocol v2 custom scope and max_count profile")
	fmt.Println("development only: in-memory reference stores")

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

	template := ratify.DelegationCertV2{
		Version: 2, CertID: "custom-scope-cert-1",
		IssuerID: rootID, IssuerPubKey: rootPub, SubjectID: agentID, SubjectPubKey: agentPub,
		IssuedAt: start, ExpiresAt: start + 86400,
	}

	// A custom scope is one exact name. Wildcards are invalid.
	wildcard := template
	wildcard.Scope, wildcard.Constraints = []string{"custom:*"}, []ratify.ConstraintV2{}
	_, err = ratify.SignDelegationCertV2(&wildcard, rootPriv)
	fmt.Printf("issue scope custom:*: refused (%s)\n", ratify.V2ErrorClassOf(err))

	// The certificate carries an extension constraint. Only a verifier that
	// registered the max_count/v1 profile for this type can evaluate it.
	template.Scope = []string{customScope}
	template.Constraints = []ratify.ConstraintV2{{
		Type:   ratify.ConstraintMaxCountV2,
		Params: map[string]any{"counter": "nodes", "max": int64(5)},
	}}
	cert, err := ratify.SignDelegationCertV2(&template, rootPriv)
	if err != nil {
		return err
	}
	fmt.Printf("delegation: scope=%s constraint=%s(counter=nodes, max=5)\n", customScope, ratify.ConstraintMaxCountV2)

	maxCount := ratify.StandardMaxCountEvaluatorV2()
	digest, err := ratify.ConstraintProfileDigestV2(maxCount.Descriptor)
	if err != nil {
		return err
	}
	fmt.Printf("profile: %s digest=%s\n", ratify.ProfileMaxCountV2, digest)
	registry, err := ratify.NewConstraintEvaluatorRegistryV2(time.Second, maxCount)
	if err != nil {
		return err
	}

	journal, err := v2reference.NewJournalStore()
	if err != nil {
		return err
	}
	if _, err := ratify.RecordSecurityKeyRoleV2(ctx, journal, "issuer", rootPub); err != nil {
		return err
	}
	if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, rootID, 1, statusPub); err != nil {
		return err
	}
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

	store, err := v2reference.NewStore(start, 30, logID, verifierPriv)
	if err != nil {
		return err
	}
	issuance := v2reference.NewTestOnlyChallengeIssuanceStore()

	// attempt verifies one request for `nodes` nodes and releases the result.
	attempt := func(label string, nodes int64, evaluators *ratify.ConstraintEvaluatorRegistryV2) error {
		store.SetTime(store.Now() + 1)
		challenge, err := ratify.V2ChallengeIssuer{Clock: store, Store: issuance}.IssueChallengeV2(ctx, ratify.V2ChallengeIssueRequest{
			VerifierNamespace: namespace, ReplayEpoch: epoch, VerifierID: verifierID,
			LifetimeSeconds: 120, ExpectedAgentID: agentID, ExpectedAgentPublicKey: &agentPub,
		})
		if err != nil {
			return err
		}
		bundle, err := ratify.SignProofBundleV2(&ratify.ProofBundleV2{
			Version: 2, VerifierID: verifierID, AgentID: agentID, AgentPubKey: agentPub,
			Delegations: []ratify.DelegationCertV2{*cert}, Challenge: challenge.Value, ChallengeAt: challenge.IssuedAt,
		}, agentPriv)
		if err != nil {
			return err
		}
		wire, err := ratify.EncodeProofBundleV2(bundle)
		if err != nil {
			return err
		}
		expected, err := ratify.LoadExpectedChallengeV2(ctx, issuance, namespace, epoch, bundle.Challenge)
		if err != nil {
			return err
		}
		contextPolicy, err := ratify.NewV2ContextPolicy("example.custom-scope/v1", false, nil, nil)
		if err != nil {
			return err
		}
		outcome, err := ratify.VerifyProofBundleV2(ctx, ratify.V2VerifyRequest{
			Bundle: wire, Expected: expected, ContextPolicy: contextPolicy, RequiredScope: customScope,
			VerifierNamespace: namespace, ReplayEpoch: epoch, VerifierID: verifierID, Now: store.Now(),
			MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5, TZDBVersion: ratify.TZDBVersionV2,
			// The requested quantity comes from the authenticated request,
			// never from the proof.
			Context:              ratify.ConstraintContextV2{ExtensionCounts: map[string]int64{"nodes": nodes}},
			ConstraintEvaluators: evaluators,
			StatusKeys:           map[string]ratify.V2StatusKeyConfig{rootID: {Epoch: 1, Key: statusPub}},
			StatusPolicy:         ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5},
		}, ratify.V2VerifyCallbacks{
			ClaimStore: store,
			Trust: func(_ context.Context, chain []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
				if chain[len(chain)-1].IssuerID == rootID {
					return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: rootPub}, nil
				}
				return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
			},
			StatusEvidence: func(context.Context, ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
				return ratify.V2StatusEvidenceBatch{Objects: []ratify.V2StatusEvidenceObject{{ObjectType: 3, Wire: statusWire}}}, nil
			},
			StatusJournal: journal,
		})
		if err != nil {
			return err
		}
		if outcome.Stage != ratify.V2StageCommitted {
			return fmt.Errorf("verify stopped at %s: %v", outcome.Stage, outcome.Error)
		}
		receiptWire, err := store.PublishV2Receipt(ctx, outcome.Committed.ClaimID(), outcome.Committed.ReceiptBody())
		if err != nil {
			return err
		}
		result := ratify.ReleaseV2Decision(ctx, outcome.Committed, receiptWire, ratify.V2ReleaseConfig{
			VerifierPublicKey: verifierPub, LogID: logID, ClaimStore: store, Checkpoint: store,
		})
		if result.Status != ratify.V2ReleaseReleased {
			return fmt.Errorf("release %s: %s", result.Status, result.Reason)
		}
		receipt, err := result.Decision.Receipt()
		if err != nil {
			return err
		}
		fmt.Printf("%s: decision=%s reason=%s allowed=%t\n", label, result.Decision.Decision(), result.Decision.Reason(), result.Decision.Allowed(ctx, store))
		for _, ref := range receipt.ConstraintEvaluators {
			fmt.Printf("  receipt constraint_evaluators: %s %s\n", ref.Type, ref.ProfileDigest)
		}
		return nil
	}

	if err := attempt("request nodes=3", 3, registry); err != nil {
		return err
	}
	if err := attempt("request nodes=8", 8, registry); err != nil {
		return err
	}
	return attempt("request nodes=3 without the profile registered", 3, nil)
}
