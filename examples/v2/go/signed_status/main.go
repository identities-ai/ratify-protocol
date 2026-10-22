// Ratify Protocol v2 signed status: a status publisher under a separate
// status key, journal ingestion, and a revocation that turns a later
// verification into deny.
//
// DEVELOPMENT ONLY. This program uses the in-memory reference stores from
// package v2reference. A production verifier supplies durable Part B stores,
// an anchored journal store and an independent checkpoint (SPEC-v2 §7).
//
// Run from the repository root: go run ./examples/v2/go/signed_status
package main

import (
	"context"
	"fmt"
	"os"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

const (
	start     = int64(1800000000)
	namespace = "signed-status"
	epoch     = int64(1)
	logID     = "00000000000000000000000000000002"
	certID    = "status-demo-cert-1"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	fmt.Println("Ratify Protocol v2 signed status")
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

	cert, err := ratify.SignDelegationCertV2(&ratify.DelegationCertV2{
		Version: 2, CertID: certID,
		IssuerID: rootID, IssuerPubKey: rootPub, SubjectID: agentID, SubjectPubKey: agentPub,
		Scope: []string{"data:read"}, Constraints: []ratify.ConstraintV2{},
		IssuedAt: start, ExpiresAt: start + 86400,
	}, rootPriv)
	if err != nil {
		return err
	}
	fmt.Printf("delegation: %s scope=data:read\n", certID)

	// The journal is the verifier's anchored record of key roles, status-key
	// epochs and accepted status. Roles are recorded once, when the
	// deployment authenticates its trust configuration.
	journal, err := v2reference.NewJournalStore()
	if err != nil {
		return err
	}
	for _, r := range []struct {
		role string
		pub  ratify.HybridPublicKey
	}{{"issuer", rootPub}, {"delegation", agentPub}, {"verifier", verifierPub}} {
		if _, err := ratify.RecordSecurityKeyRoleV2(ctx, journal, r.role, r.pub); err != nil {
			return err
		}
	}
	if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, rootID, 1, statusPub); err != nil {
		return err
	}
	fmt.Println("journal: key roles recorded; status key configured for the root at epoch 1")

	// Role separation: the root key can never sign status for itself.
	_, err = ratify.NewV2StatusPublisherWithKey(ctx, journal, rootPub, rootPriv, 3600)
	fmt.Printf("publisher with the root key as status key: refused (%s)\n", ratify.V2ErrorClassOf(err))

	publisher, err := ratify.NewV2StatusPublisherWithKey(ctx, journal, rootPub, statusPriv, 3600)
	if err != nil {
		return err
	}
	policy := ratify.RevocationStatusPolicyV2{MaxListLifetimeSeconds: 3600, MaxStatusAgeSeconds: 3600, ClockSkewSeconds: 5}

	// Genesis: sequence 1, nothing revoked. The caller persists the returned
	// state before publishing the signed list.
	genesis, err := publisher.Genesis(ctx, start)
	if err != nil {
		return err
	}
	genesisWire, err := ratify.EncodeRevocationListV2(genesis.List)
	if err != nil {
		return err
	}
	fmt.Printf("publisher: genesis list sequence %d\n", genesis.List.Sequence)
	if _, err := ratify.ApplyRevocationListToJournalV2(ctx, journal, genesis.List, rootID, 1, statusPub, policy, start); err != nil {
		return err
	}
	status, err := ratify.RevocationStatusFromJournalV2(ctx, journal, rootID, certID, 1, statusPub, policy, start)
	if err != nil {
		return err
	}
	fmt.Printf("journal: ingested list sequence %d; %s is %s\n", genesis.List.Sequence, certID, status.Status)

	store, err := v2reference.NewStore(start, 30, logID, verifierPriv)
	if err != nil {
		return err
	}
	issuance := v2reference.NewTestOnlyChallengeIssuanceStore()
	evidence := []ratify.V2StatusEvidenceObject{{ObjectType: 3, Wire: genesisWire}}

	// verifyAndRelease runs one complete live verification at the store's
	// current time and returns the released decision.
	verifyAndRelease := func(label string) error {
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
		contextPolicy, err := ratify.NewV2ContextPolicy("example.signed-status/v1", false, nil, nil)
		if err != nil {
			return err
		}
		outcome, err := ratify.VerifyProofBundleV2(ctx, ratify.V2VerifyRequest{
			Bundle: wire, Expected: expected, ContextPolicy: contextPolicy, RequiredScope: "data:read",
			VerifierNamespace: namespace, ReplayEpoch: epoch, Now: store.Now(),
			MaxChallengeAgeSeconds: 300, FutureSkewSeconds: 5, TZDBVersion: ratify.TZDBVersionV2,
			StatusKeys:   map[string]ratify.V2StatusKeyConfig{rootID: {Epoch: 1, Key: statusPub}},
			StatusPolicy: policy,
		}, ratify.V2VerifyCallbacks{
			ClaimStore: store,
			Trust: func(_ context.Context, chain []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
				if chain[len(chain)-1].IssuerID == rootID {
					return ratify.V2TrustResolution{Outcome: ratify.V2TrustTrusted, RootKey: rootPub}, nil
				}
				return ratify.V2TrustResolution{Outcome: ratify.V2TrustUntrusted}, nil
			},
			// The provider returns signed objects only; the verifier checks
			// each signature against the configured status key and applies
			// it to the journal before it derives a status.
			StatusEvidence: func(context.Context, ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
				return ratify.V2StatusEvidenceBatch{Objects: evidence}, nil
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
		fmt.Printf("%s: decision=%s reason=%s status_assessment=%s allowed=%t\n", label,
			result.Decision.Decision(), result.Decision.Reason(), receipt.StatusAssessment, result.Decision.Allowed(ctx, store))
		return nil
	}

	store.SetTime(start + 5)
	if err := verifyAndRelease("verify before revocation"); err != nil {
		return err
	}

	// Revoke: a push with the newly revoked ID and the cumulative list, both
	// at sequence 2.
	revoked, err := publisher.Revoke(ctx, genesis.State, []string{certID}, start+10)
	if err != nil {
		return err
	}
	pushWire, err := ratify.EncodeRevocationPushV2(revoked.Push)
	if err != nil {
		return err
	}
	listWire, err := ratify.EncodeRevocationListV2(revoked.List)
	if err != nil {
		return err
	}
	fmt.Printf("publisher: revoked %s (push sequence %d, list sequence %d)\n", certID, revoked.Push.Sequence, revoked.List.Sequence)
	if _, err := ratify.ApplyRevocationPushToJournalV2(ctx, journal, revoked.Push, rootID, 1, statusPub, policy, start+10); err != nil {
		return err
	}
	status, err = ratify.RevocationStatusFromJournalV2(ctx, journal, rootID, certID, 1, statusPub, policy, start+10)
	if err != nil {
		return err
	}
	fmt.Printf("journal: ingested push sequence %d; %s is %s\n", revoked.Push.Sequence, certID, status.Status)

	evidence = []ratify.V2StatusEvidenceObject{{ObjectType: 5, Wire: pushWire}, {ObjectType: 3, Wire: listWire}}
	store.SetTime(start + 15)
	return verifyAndRelease("verify after revocation")
}
