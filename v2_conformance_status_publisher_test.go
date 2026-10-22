package ratify_test

import (
	"context"
	"slices"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

type v2PublisherList struct {
	Sequence   int64    `json:"sequence"`
	UpdatedAt  int64    `json:"updated_at"`
	NextUpdate int64    `json:"next_update"`
	Revoked    []string `json:"revoked"`
}

type v2PublisherPush struct {
	Sequence int64    `json:"sequence"`
	PushedAt int64    `json:"pushed_at"`
	Revoked  []string `json:"revoked"`
}

type v2PublisherScenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Issuer      string `json:"issuer"`
	StatusKey   string `json:"status_key"`
	RoleKeys    []struct {
		Key  string `json:"key"`
		Role string `json:"role"`
	} `json:"role_keys"`
	StatusConfiguredFor string `json:"status_configured_for"`
	LifetimeSeconds     int64  `json:"lifetime_seconds"`
	Publisher           string `json:"publisher"`
	JournalSetup        string `json:"journal_setup"`
	Steps               []struct {
		Op          string   `json:"op"`
		At          int64    `json:"at"`
		CertIDs     []string `json:"cert_ids"`
		CertID      string   `json:"cert_id"`
		Publication *int     `json:"publication"`
		Object      string   `json:"object"`
		Expect      struct {
			Result string           `json:"result"`
			List   *v2PublisherList `json:"list"`
			Push   *v2PublisherPush `json:"push"`
			Status string           `json:"status"`
			Reason string           `json:"reason"`
		} `json:"expect"`
	} `json:"steps"`
}

func revokedIDsV2Test(refs []ratify.RevokedCertV2) []string {
	out := []string{}
	for _, r := range refs {
		out = append(out, r.CertID)
	}
	return out
}

func TestV2ConformanceStatusPublisher(t *testing.T) {
	var f struct {
		Version      int                   `json:"version"`
		Description  string                `json:"description"`
		StatusPolicy v2StatusPolicy        `json:"status_policy"`
		Operations   map[string]string     `json:"operations"`
		Scenarios    []v2PublisherScenario `json:"scenarios"`
	}
	loadV2Vector(t, "status-publisher.json", &f)
	_, fx := loadV2Keys(t)
	if len(f.Scenarios) == 0 {
		t.Fatal("no status publisher scenarios")
	}
	policy := f.StatusPolicy.lib()
	for _, sc := range f.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			ctx := context.Background()
			issuerKey, statusKey := fx.pub[sc.Issuer], fx.pub[sc.StatusKey]
			issuerID := fx.id[sc.Issuer]
			journal, err := v2reference.NewJournalStore()
			if err != nil {
				t.Fatal(err)
			}
			for _, rk := range sc.RoleKeys {
				if _, err := ratify.RecordSecurityKeyRoleV2(ctx, journal, rk.Role, fx.pub[rk.Key]); err != nil {
					t.Fatal(err)
				}
			}
			setup := "not_configured"
			if sc.StatusConfiguredFor != "" {
				setup = "configured"
				if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, journal, fx.id[sc.StatusConfiguredFor], 1, statusKey); err != nil {
					setup = "rejected"
				}
			}
			if setup != sc.JournalSetup {
				t.Fatalf("journal setup %q, want %q", setup, sc.JournalSetup)
			}
			signer, err := ratify.NewLocalSignerV2(fx.priv[sc.StatusKey])
			if err != nil {
				t.Fatal(err)
			}
			counting := &v2CountingSigner{inner: signer}
			publisher, err := ratify.NewV2StatusPublisher(ctx, journal, issuerKey, counting, sc.LifetimeSeconds)
			switch sc.Publisher {
			case "ok":
				if err != nil {
					t.Fatalf("publisher refused: %v", err)
				}
			case "refused":
				if err == nil || publisher != nil {
					t.Fatal("publisher accepted a status key outside the authenticated role configuration")
				}
				if ratify.V2ErrorClassOf(err) != ratify.V2ErrConfigurationInvalid {
					t.Fatalf("refusal class %q", ratify.V2ErrorClassOf(err))
				}
			}
			if sc.Publisher != "ok" {
				if counting.calls > 1 {
					t.Fatalf("a refused publisher invoked the signer %d times", counting.calls)
				}
				return
			}

			var state ratify.V2StatusPublisherState
			var publications []ratify.V2StatusPublication
			for i, step := range sc.Steps {
				exp := step.Expect
				var pubn ratify.V2StatusPublication
				var err error
				switch step.Op {
				case "genesis":
					pubn, err = publisher.Genesis(ctx, step.At)
				case "heartbeat":
					pubn, err = publisher.Heartbeat(ctx, state, step.At)
				case "revoke":
					pubn, err = publisher.Revoke(ctx, state, step.CertIDs, step.At)
				case "ingest":
					p := publications[*step.Publication]
					if step.Object == "push" {
						_, err = ratify.ApplyRevocationPushToJournalV2(ctx, journal, p.Push, issuerID, 1, statusKey, policy, step.At)
					} else {
						_, err = ratify.ApplyRevocationListToJournalV2(ctx, journal, p.List, issuerID, 1, statusKey, policy, step.At)
					}
					if err != nil {
						t.Fatalf("step %d: ingest: %v", i, err)
					}
					continue
				case "status":
					result, err := ratify.RevocationStatusFromJournalV2(ctx, journal, issuerID, step.CertID, 1, statusKey, policy, step.At)
					if err != nil {
						t.Fatalf("step %d: status: %v", i, err)
					}
					if result.Status != exp.Status || result.Reason != exp.Reason {
						t.Fatalf("step %d: %s status %s/%s, want %s/%s", i, step.CertID, result.Status, result.Reason, exp.Status, exp.Reason)
					}
					continue
				default:
					t.Fatalf("step %d: unknown op %q", i, step.Op)
				}
				if exp.Result == "refused" {
					if err == nil {
						t.Fatalf("step %d: %s was not refused", i, step.Op)
					}
					continue
				}
				if err != nil {
					t.Fatalf("step %d: %s: %v", i, step.Op, err)
				}
				l := pubn.List
				if err := ratify.VerifyRevocationListV2Signature(l, issuerID, statusKey); err != nil {
					t.Fatalf("step %d: list signature: %v", i, err)
				}
				if l.Sequence != exp.List.Sequence || l.UpdatedAt != exp.List.UpdatedAt || l.NextUpdate != exp.List.NextUpdate || !slices.Equal(revokedIDsV2Test(l.Revoked), exp.List.Revoked) {
					t.Fatalf("step %d: list %+v, want %+v", i, l, exp.List)
				}
				if (pubn.Push != nil) != (exp.Push != nil) {
					t.Fatalf("step %d: push presence mismatch", i)
				}
				if p := pubn.Push; p != nil {
					if err := ratify.VerifyRevocationPushV2Signature(p, issuerID, statusKey); err != nil {
						t.Fatalf("step %d: push signature: %v", i, err)
					}
					if p.Sequence != exp.Push.Sequence || p.PushedAt != exp.Push.PushedAt || !slices.Equal(revokedIDsV2Test(p.Revoked), exp.Push.Revoked) {
						t.Fatalf("step %d: push %+v, want %+v", i, p, exp.Push)
					}
				}
				state = pubn.State
				publications = append(publications, pubn)
			}
		})
	}
}
