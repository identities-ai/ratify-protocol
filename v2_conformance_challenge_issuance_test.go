package ratify_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

type v2IssuanceScenario struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RandomB64   []string `json:"random_b64"`
	Steps       []struct {
		Op      string `json:"op"`
		At      int64  `json:"at"`
		Request *struct {
			VerifierNamespace         string  `json:"verifier_namespace"`
			ReplayEpoch               int64   `json:"replay_epoch"`
			VerifierID                string  `json:"verifier_id"`
			LifetimeSeconds           int64   `json:"lifetime_seconds"`
			ExpectedAgent             *string `json:"expected_agent"`
			ExpectedReceiverID        *string `json:"expected_receiver_id"`
			ExpectedSessionContextB64 *string `json:"expected_session_context_b64"`
		} `json:"request"`
		PersistFault string   `json:"persist_fault"`
		ChallengeB64 string   `json:"challenge_b64"`
		Bundles      []string `json:"bundles_b64"`
		Expect       struct {
			Result       string   `json:"result"`
			ErrorClass   string   `json:"error_class"`
			ChallengeB64 string   `json:"challenge_b64"`
			IssuedAt     int64    `json:"issued_at"`
			ExpiresAt    int64    `json:"expires_at"`
			RecordsAfter *int     `json:"records_after"`
			Dispositions []string `json:"dispositions"`
		} `json:"expect"`
	} `json:"steps"`
}

// Fixture namespace and replay epoch shared with the other corpus files.
const (
	v2IssuanceNamespace = "verify-test"
	v2IssuanceEpoch     = 3
)

func TestV2ConformanceChallengeIssuance(t *testing.T) {
	var f struct {
		Version     int                  `json:"version"`
		Description string               `json:"description"`
		Operations  map[string]string    `json:"operations"`
		Scenarios   []v2IssuanceScenario `json:"scenarios"`
	}
	loadV2Vector(t, "challenge-issuance.json", &f)
	_, fx := loadV2Keys(t)
	if len(f.Scenarios) == 0 {
		t.Fatal("no challenge issuance scenarios")
	}
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) { runV2IssuanceScenario(t, sc, fx) })
	}
}

func runV2IssuanceScenario(t *testing.T, sc v2IssuanceScenario, fx v2Fixture) {
	ctx := context.Background()
	var random bytes.Buffer
	for _, r := range sc.RandomB64 {
		random.Write(unb64(t, r))
	}
	claims, err := v2reference.NewStore(sc.Steps[0].At, 60, "0123456789abcdef0123456789abcdef", fx.priv["verifier"])
	if err != nil {
		t.Fatal(err)
	}
	issuance := v2reference.NewTestOnlyChallengeIssuanceStore()
	issuer := ratify.V2ChallengeIssuer{Clock: claims, Store: issuance, Random: &random}
	for i, step := range sc.Steps {
		if step.At != 0 {
			claims.SetTime(step.At)
		}
		exp := step.Expect
		switch step.Op {
		case "issue":
			r := step.Request
			req := ratify.V2ChallengeIssueRequest{VerifierNamespace: r.VerifierNamespace, ReplayEpoch: r.ReplayEpoch, VerifierID: r.VerifierID, LifetimeSeconds: r.LifetimeSeconds}
			if r.ExpectedAgent != nil {
				key := fx.pub[*r.ExpectedAgent]
				req.ExpectedAgentID, req.ExpectedAgentPublicKey = fx.id[*r.ExpectedAgent], &key
			}
			if r.ExpectedReceiverID != nil {
				req.ExpectedReceiverID = *r.ExpectedReceiverID
			}
			if r.ExpectedSessionContextB64 != nil {
				req.ExpectedSessionContext = unb64(t, *r.ExpectedSessionContextB64)
			}
			switch step.PersistFault {
			case "fail_before_commit":
				issuance.FailNextPersist(v2reference.PersistFailBeforeCommit)
			case "fail_after_commit":
				issuance.FailNextPersist(v2reference.PersistFailAfterCommit)
			}
			got, err := issuer.IssueChallengeV2(ctx, req)
			switch exp.Result {
			case "issued":
				if err != nil {
					t.Fatalf("step %d: issuance failed: %v", i, err)
				}
				if !bytes.Equal(got.Value, unb64(t, exp.ChallengeB64)) || got.IssuedAt != exp.IssuedAt || got.ExpiresAt != exp.ExpiresAt {
					t.Fatalf("step %d: issued %x %d..%d, want %s %d..%d", i, got.Value, got.IssuedAt, got.ExpiresAt, exp.ChallengeB64, exp.IssuedAt, exp.ExpiresAt)
				}
				stored, err := ratify.LoadExpectedChallengeV2(ctx, issuance, req.VerifierNamespace, req.ReplayEpoch, got.Value)
				if err != nil || stored.ExpectedAgentID != req.ExpectedAgentID || !bytes.Equal(stored.ExpectedSessionContext, req.ExpectedSessionContext) {
					t.Fatalf("step %d: a returned challenge must already be durably retrievable: %v", i, err)
				}
			case "error":
				if err == nil || got != nil {
					t.Fatalf("step %d: issuance returned a challenge, want an error", i)
				}
				if exp.ErrorClass != "" && string(ratify.V2ErrorClassOf(err)) != exp.ErrorClass {
					t.Fatalf("step %d: class %q (%v), want %q", i, ratify.V2ErrorClassOf(err), err, exp.ErrorClass)
				}
			default:
				t.Fatalf("step %d: unknown issue result %q", i, exp.Result)
			}
			if exp.RecordsAfter != nil && issuance.Len() != *exp.RecordsAfter {
				t.Fatalf("step %d: %d stored records, want %d", i, issuance.Len(), *exp.RecordsAfter)
			}
		case "load":
			got, err := ratify.LoadExpectedChallengeV2(ctx, issuance, v2IssuanceNamespace, v2IssuanceEpoch, unb64(t, step.ChallengeB64))
			if exp.Result == "found" {
				if err != nil || got.IssuedAt != exp.IssuedAt || got.ExpiresAt != exp.ExpiresAt {
					t.Fatalf("step %d: load = %+v, %v", i, got, err)
				}
			} else if string(ratify.V2ErrorClassOf(err)) != exp.Result {
				t.Fatalf("step %d: load class %q, want %q", i, ratify.V2ErrorClassOf(err), exp.Result)
			}
		case "present", "present_concurrent":
			outcomes := make([]string, len(step.Bundles))
			var wg sync.WaitGroup
			for j, b := range step.Bundles {
				wg.Add(1)
				go func(j int, wire []byte) {
					defer wg.Done()
					outcomes[j] = v2PresentIssued(ctx, issuance, claims, wire, step.At)
				}(j, unb64(t, b))
			}
			wg.Wait()
			slices.Sort(outcomes)
			var want []string
			switch exp.Result {
			case "preflight":
				want = []string{"preflight:" + exp.ErrorClass}
			case "claimed":
				want = append([]string(nil), exp.Dispositions...)
				slices.Sort(want)
			default:
				t.Fatalf("step %d: unknown present result %q", i, exp.Result)
			}
			if !slices.Equal(outcomes, want) {
				t.Fatalf("step %d: outcomes %v, want %v", i, outcomes, want)
			}
		default:
			t.Fatalf("step %d: unknown op %q", i, step.Op)
		}
	}
}

// v2PresentIssued runs retrieval, pre-claim checks and the atomic claim for
// one presented bundle and names the outcome.
func v2PresentIssued(ctx context.Context, issuance ratify.V2ChallengeIssuanceStore, claims ratify.ClaimStoreV2, wire []byte, now int64) string {
	bundle, err := ratify.DecodeProofBundleV2(wire)
	if err != nil {
		return "preflight:" + string(ratify.V2ErrorClassOf(err))
	}
	expected, err := ratify.LoadExpectedChallengeV2(ctx, issuance, v2IssuanceNamespace, v2IssuanceEpoch, bundle.Challenge)
	if err != nil {
		return "preflight:" + string(ratify.V2ErrorClassOf(err))
	}
	var policy *ratify.V2ContextPolicy
	if expected.ExpectedSessionContext != nil {
		policy, err = ratify.NewV2ContextPolicy("ratify.verify.session-context/v1", true,
			[]string{"verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"}, expected.ExpectedSessionContext)
	} else {
		policy, err = ratify.NewV2ContextPolicy("ratify.conformance.context-not-required/v1", false, []string{}, nil)
	}
	if err != nil {
		return fmt.Sprintf("policy error: %v", err)
	}
	preflight, err := ratify.PreflightProofBundleV2(bundle, expected, policy, "data:read", v2IssuanceNamespace, v2IssuanceEpoch, expected.VerifierID, now, 300, 5)
	if err != nil {
		return "preflight:" + string(ratify.V2ErrorClassOf(err))
	}
	_, disposition, _, err := ratify.ClaimProofBundleV2(ctx, claims, bundle, preflight, v2IssuanceNamespace, v2IssuanceEpoch, now)
	if errors.Is(err, ratify.ErrV2ClaimProofConflict) {
		return "proof_conflict"
	}
	if err != nil {
		return fmt.Sprintf("claim error: %v", err)
	}
	return string(disposition)
}
