package ratify_test

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	ratify "github.com/identities-ai/ratify-protocol/v2"
	"github.com/identities-ai/ratify-protocol/v2/v2reference"
)

// ---------------------------------------------------------------------------
// Verifier ordering (testvectors/v2/verifier-ordering.json)

type v2Evidence struct {
	IssuerID       string `json:"issuer_id"`
	StatusKeyID    string `json:"status_key_id"`
	Sequence       int64  `json:"sequence"`
	ObjectTypeCode uint16 `json:"object_type_code"`
	Digest         string `json:"digest"`
}

func (e v2Evidence) lib() ratify.StatusEvidenceEntryV2 {
	return ratify.StatusEvidenceEntryV2{IssuerID: e.IssuerID, StatusKeyID: e.StatusKeyID, Sequence: e.Sequence, ObjectType: e.ObjectTypeCode, Digest: e.Digest}
}

type v2Counts struct {
	ReceiverBinding int `json:"receiver_binding"`
	Claim           int `json:"claim"`
	Trust           int `json:"trust"`
	Status          int `json:"status"`
	Audience        int `json:"audience"`
	Rate            int `json:"rate"`
	Finalize        int `json:"finalize"`
	Progress        int `json:"progress"`
}

type v2Rate struct {
	IssuerID string `json:"issuer_id"`
	CertID   string `json:"cert_id"`
	WindowS  int64  `json:"window_s"`
	Limit    int64  `json:"limit"`
}

type v2ExpectedChallengeJSON struct {
	ValueB64                  string                  `json:"value_b64"`
	IssuedAt                  int64                   `json:"issued_at"`
	ExpiresAt                 int64                   `json:"expires_at"`
	VerifierNamespace         string                  `json:"verifier_namespace"`
	ReplayEpoch               int64                   `json:"replay_epoch"`
	VerifierID                string                  `json:"verifier_id"`
	ExpectedAgentID           *string                 `json:"expected_agent_id"`
	ExpectedAgentPublicKey    *ratify.HybridPublicKey `json:"expected_agent_public_key"`
	ExpectedReceiverID        *string                 `json:"expected_receiver_id"`
	ExpectedSessionContextB64 *string                 `json:"expected_session_context_b64"`
}

type v2ContextPolicyJSON struct {
	Profile                   string   `json:"profile"`
	RequireBound              bool     `json:"require_bound"`
	RequiredFields            []string `json:"required_fields"`
	ExpectedSessionContextB64 *string  `json:"expected_session_context_b64"`
	Digest                    string   `json:"digest"`
}

type v2StatusKeyJSON struct {
	Epoch       uint64                 `json:"epoch"`
	StatusKeyID string                 `json:"status_key_id"`
	PublicKey   ratify.HybridPublicKey `json:"public_key"`
}

type v2EvidenceObjectJSON struct {
	ObjectTypeCode uint16 `json:"object_type_code"`
	WireB64        string `json:"wire_b64"`
}

type v2JournalJSON struct {
	Mode    string `json:"mode"`
	Preload []struct {
		IssuerID       string `json:"issuer_id"`
		ObjectTypeCode uint16 `json:"object_type_code"`
		WireB64        string `json:"wire_b64"`
		Now            int64  `json:"now"`
	} `json:"preload"`
}

type v2MembershipJSON struct {
	DelegationIndex int      `json:"delegation_index"`
	ConstraintIndex int      `json:"constraint_index"`
	ReceiverID      string   `json:"receiver_id"`
	TrustDomainIDs  []string `json:"trust_domain_ids"`
	IssuedAt        int64    `json:"issued_at"`
	ExpiresAt       int64    `json:"expires_at"`
	EvidenceDigest  string   `json:"evidence_digest"`
}

type v2OrderingInputs struct {
	RequiredScope          string                   `json:"required_scope"`
	ExpectedChallenge      *v2ExpectedChallengeJSON `json:"expected_challenge"`
	ContextPolicy          *v2ContextPolicyJSON     `json:"context_policy"`
	ConfiguredNamespace    string                   `json:"configured_namespace"`
	ConfiguredReplayEpoch  int64                    `json:"configured_replay_epoch"`
	Now                    int64                    `json:"now"`
	MaxChallengeAgeSeconds int64                    `json:"max_challenge_age_seconds"`
	FutureSkewSeconds      int64                    `json:"future_skew_seconds"`
	RequestContext         *struct {
		HasResource           bool   `json:"has_resource"`
		RequestedResourceID   string `json:"requested_resource_id"`
		RequestedPath         string `json:"requested_path"`
		HasAmount             bool   `json:"has_amount"`
		RequestedAmountMicros int64  `json:"requested_amount_micros"`
		RequestedCurrency     string `json:"requested_currency"`
	} `json:"request_context"`
	ReceiverBindingHook string `json:"receiver_binding_hook"`
	Trust               *struct {
		Mode          string                  `json:"mode"`
		Outcome       string                  `json:"outcome"`
		RootPublicKey *ratify.HybridPublicKey `json:"root_public_key"`
	} `json:"trust"`
	StatusKeys     map[string]v2StatusKeyJSON `json:"status_keys"`
	StatusPolicy   v2StatusPolicy             `json:"status_policy"`
	Journal        v2JournalJSON              `json:"journal"`
	StatusEvidence map[string]struct {
		Mode    string                 `json:"mode"`
		Objects []v2EvidenceObjectJSON `json:"objects"`
	} `json:"status_evidence"`
	AudienceMode        string             `json:"audience_mode"`
	AudienceMemberships []v2MembershipJSON `json:"audience_memberships"`
	Rate                string             `json:"rate"`
}

type v2OrderingVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Bundle      string `json:"bundle"`
	v2OrderingInputs
	ClaimStore         string `json:"claim_store"`
	ClaimTimeOffset    int64  `json:"claim_time_offset"`
	FinalizeTimeOffset int64  `json:"finalize_time_offset"`
	Expected           struct {
		Stage               string       `json:"stage"`
		VerifiedAt          int64        `json:"verified_at"`
		ErrorClass          string       `json:"error_class"`
		Disposition         string       `json:"disposition"`
		Decision            string       `json:"decision"`
		DecisionReason      string       `json:"decision_reason"`
		IdentityStatus      string       `json:"identity_status"`
		TrustAssessment     string       `json:"trust_assessment"`
		StatusAssessment    string       `json:"status_assessment"`
		ContextAssessment   string       `json:"context_assessment"`
		ContextPolicyDigest *string      `json:"context_policy_digest"`
		GrantedScope        []string     `json:"granted_scope"`
		StatusEvidence      []v2Evidence `json:"status_evidence"`
		ReceiptBodyB64      string       `json:"receipt_body_b64"`
		AllowValidUntil     int64        `json:"allow_valid_until"`
		RateBatch           []v2Rate     `json:"rate_batch"`
		CallbackCounts      v2Counts     `json:"callback_counts"`
	} `json:"expected"`
}

// v2ScriptedClaimStore is a single-claim, in-memory test double used by the
// ordering vectors. It is not a durable or concurrent-safe store.
type v2ScriptedClaimStore struct {
	mode           string
	claimedAt      int64
	finalizationAt int64
	counts         *v2Counts
	finalBody      []byte
	expiresAt      int64
	progress       ratify.V2EvaluationProgress
}

func (s *v2ScriptedClaimStore) AuthoritativeTimeV2(context.Context) (int64, error) {
	return s.finalizationAt, nil
}

func (s *v2ScriptedClaimStore) ClaimV2(_ context.Context, claim ratify.V2ChallengeClaim) (ratify.V2ClaimResult, error) {
	s.counts.Claim++
	s.expiresAt = claim.ExpiresAt
	switch s.mode {
	case "create":
		return ratify.V2ClaimResult{Disposition: ratify.V2ClaimCreated, ClaimedAt: s.claimedAt, OwnerToken: bytes.Repeat([]byte{7}, 32)}, nil
	case "proof_conflict":
		return ratify.V2ClaimResult{}, ratify.ErrV2ClaimProofConflict
	case "in_progress":
		return ratify.V2ClaimResult{Disposition: ratify.V2ClaimInProgress, ClaimedAt: s.claimedAt}, nil
	case "terminal_replay":
		return ratify.V2ClaimResult{Disposition: ratify.V2ClaimTerminalReplay, ClaimedAt: s.claimedAt}, nil
	}
	return ratify.V2ClaimResult{}, fmt.Errorf("scripted claim store unavailable")
}

// FinalizeV2Claim applies the claim-store side of SPEC-v2 §7.2: T_final is
// the scripted finalization reading, a reading below T_claim is
// clock_regressed, and an allow commits only while T_final is before both
// its horizon and the challenge expiry.
func (s *v2ScriptedClaimStore) FinalizeV2Claim(_ context.Context, _ string, _ []byte, _ []byte, receiptBody []byte, allowValidUntil int64) (bool, error) {
	s.counts.Finalize++
	if s.finalizationAt < s.claimedAt {
		return false, &ratify.V2Error{Class: ratify.V2ErrClockRegressed, Err: fmt.Errorf("scripted finalization clock regressed")}
	}
	if allowValidUntil > 0 && (s.finalizationAt >= allowValidUntil || s.finalizationAt >= s.expiresAt) {
		return false, &ratify.V2Error{Class: ratify.V2ErrAllowHorizonPassed, Err: fmt.Errorf("scripted allow at or beyond its deadline")}
	}
	s.finalBody = bytes.Clone(receiptBody)
	return true, nil
}

func (s *v2ScriptedClaimStore) RecoverInterruptedV2Claim(context.Context, string, []byte, []byte) (bool, error) {
	return false, fmt.Errorf("not used by ordering vectors")
}

func (s *v2ScriptedClaimStore) RecordV2EvaluationProgress(_ context.Context, _ string, _ []byte, progress ratify.V2EvaluationProgress) error {
	s.counts.Progress++
	s.progress = progress
	return nil
}

func (s *v2ScriptedClaimStore) LoadV2InterruptedClaim(context.Context, string) (ratify.V2InterruptedClaim, error) {
	return ratify.V2InterruptedClaim{}, fmt.Errorf("not used by ordering vectors")
}

type v2ScriptedRateStore struct {
	mode   string
	counts *v2Counts
	batch  []ratify.V2RateReservation
}

func (r *v2ScriptedRateStore) ReserveV2RateBatch(_ context.Context, _ string, _ []byte, _ string, batch []ratify.V2RateReservation) error {
	r.counts.Rate++
	r.batch = append([]ratify.V2RateReservation(nil), batch...)
	switch r.mode {
	case "reserve":
		return nil
	case "exceeded":
		return ratify.ErrV2RateLimitExceeded
	case "panic":
		panic("scripted rate store panic")
	}
	return fmt.Errorf("scripted rate store unavailable")
}

// v2ModalJournalStore wraps the reference journal with the scripted failure
// modes of the vectors.
type v2ModalJournalStore struct {
	inner *v2reference.JournalStore
	mode  string
}

func (s *v2ModalJournalStore) Load(ctx context.Context) (ratify.SecurityJournalV2, ratify.SecurityJournalHeadV2, error) {
	switch s.mode {
	case "load_error":
		return ratify.SecurityJournalV2{}, ratify.SecurityJournalHeadV2{}, fmt.Errorf("scripted journal load failure")
	case "unanchored":
		journal, head, err := s.inner.Load(ctx)
		head.Digest = strings.Repeat("e", 96)
		return journal, head, err
	}
	return s.inner.Load(ctx)
}

func (s *v2ModalJournalStore) CompareAndSwap(ctx context.Context, head ratify.SecurityJournalHeadV2, next ratify.SecurityJournalV2) error {
	if s.mode == "cas_conflict" {
		return ratify.ErrSecurityJournalConflictV2
	}
	return s.inner.CompareAndSwap(ctx, head, next)
}

// v2BuildStatusJournal performs the documented journal setup: genesis, every
// status_keys entry configured at its epoch in ascending issuer order, then
// each preload object applied at its time.
func v2BuildStatusJournal(t *testing.T, in v2OrderingInputs) *v2reference.JournalStore {
	t.Helper()
	ctx := context.Background()
	store, err := v2reference.NewJournalStore()
	if err != nil {
		t.Fatal(err)
	}
	issuers := make([]string, 0, len(in.StatusKeys))
	for issuer := range in.StatusKeys {
		issuers = append(issuers, issuer)
	}
	sort.Strings(issuers)
	for _, issuer := range issuers {
		key := in.StatusKeys[issuer]
		if _, err := ratify.ConfigureStatusKeyEpochV2(ctx, store, issuer, key.Epoch, key.PublicKey); err != nil {
			t.Fatalf("configure status key for %s: %v", issuer, err)
		}
	}
	for _, p := range in.Journal.Preload {
		key := in.StatusKeys[p.IssuerID]
		wire := unb64(t, p.WireB64)
		switch p.ObjectTypeCode {
		case 3:
			list, err := ratify.DecodeRevocationListV2(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ratify.ApplyRevocationListToJournalV2(ctx, store, list, p.IssuerID, key.Epoch, key.PublicKey, in.StatusPolicy.lib(), p.Now); err != nil {
				t.Fatalf("preload list: %v", err)
			}
		case 5:
			push, err := ratify.DecodeRevocationPushV2(wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ratify.ApplyRevocationPushToJournalV2(ctx, store, push, p.IssuerID, key.Epoch, key.PublicKey, in.StatusPolicy.lib(), p.Now); err != nil {
				t.Fatalf("preload push: %v", err)
			}
		}
	}
	return store
}

// v2BuildVerifyRequest builds the request and callbacks shared by the
// ordering and lifecycle runners. The claim store is supplied by the caller.
func v2BuildVerifyRequest(t *testing.T, in v2OrderingInputs, bundle []byte, counts *v2Counts) (ratify.V2VerifyRequest, ratify.V2VerifyCallbacks, *v2ScriptedRateStore) {
	t.Helper()
	req := ratify.V2VerifyRequest{
		Bundle: bundle, RequiredScope: in.RequiredScope, VerifierNamespace: in.ConfiguredNamespace,
		ReplayEpoch: in.ConfiguredReplayEpoch, Now: in.Now, MaxChallengeAgeSeconds: in.MaxChallengeAgeSeconds, FutureSkewSeconds: in.FutureSkewSeconds,
		StatusPolicy: in.StatusPolicy.lib(), StatusKeys: map[string]ratify.V2StatusKeyConfig{},
	}
	for issuer, key := range in.StatusKeys {
		req.StatusKeys[issuer] = ratify.V2StatusKeyConfig{Epoch: key.Epoch, Key: key.PublicKey}
	}
	if e := in.ExpectedChallenge; e != nil {
		exp := &ratify.ExpectedChallengeV2{Value: unb64(t, e.ValueB64), IssuedAt: e.IssuedAt, ExpiresAt: e.ExpiresAt, VerifierNamespace: e.VerifierNamespace, ReplayEpoch: e.ReplayEpoch, VerifierID: e.VerifierID}
		if e.ExpectedAgentID != nil {
			exp.ExpectedAgentID = *e.ExpectedAgentID
			exp.ExpectedAgentPublicKey = e.ExpectedAgentPublicKey
		}
		if e.ExpectedReceiverID != nil {
			exp.ExpectedReceiverID = *e.ExpectedReceiverID
		}
		if e.ExpectedSessionContextB64 != nil {
			exp.ExpectedSessionContext = unb64(t, *e.ExpectedSessionContextB64)
		}
		req.Expected = exp
	}
	if p := in.ContextPolicy; p != nil {
		var expected []byte
		if p.ExpectedSessionContextB64 != nil {
			expected = unb64(t, *p.ExpectedSessionContextB64)
		}
		policy, err := ratify.NewV2ContextPolicy(p.Profile, p.RequireBound, p.RequiredFields, expected)
		if err != nil {
			t.Fatal(err)
		}
		req.ContextPolicy = policy
	}
	if c := in.RequestContext; c != nil {
		req.Context = ratify.ConstraintContextV2{HasResource: c.HasResource, RequestedResourceID: c.RequestedResourceID, RequestedPath: c.RequestedPath,
			HasAmount: c.HasAmount, RequestedAmountMicros: c.RequestedAmountMicros, RequestedCurrency: c.RequestedCurrency}
	}
	cb := ratify.V2VerifyCallbacks{
		Trust: func(context.Context, []ratify.DelegationCertV2) (ratify.V2TrustResolution, error) {
			counts.Trust++
			if in.Trust == nil {
				return ratify.V2TrustResolution{Outcome: ratify.V2TrustUnavailable}, nil
			}
			switch in.Trust.Mode {
			case "error":
				return ratify.V2TrustResolution{}, fmt.Errorf("scripted trust provider failure")
			case "panic":
				panic("scripted trust provider panic")
			}
			out := ratify.V2TrustResolution{Outcome: ratify.V2TrustOutcome(in.Trust.Outcome)}
			if in.Trust.RootPublicKey != nil {
				out.RootKey = *in.Trust.RootPublicKey
			}
			return out, nil
		},
		StatusEvidence: func(_ context.Context, r ratify.V2StatusEvidenceRequest) (ratify.V2StatusEvidenceBatch, error) {
			counts.Status++
			script, ok := in.StatusEvidence[r.IssuerID]
			if !ok {
				return ratify.V2StatusEvidenceBatch{}, nil
			}
			switch script.Mode {
			case "error":
				return ratify.V2StatusEvidenceBatch{}, fmt.Errorf("scripted status provider failure")
			case "panic":
				panic("scripted status provider panic")
			}
			out := ratify.V2StatusEvidenceBatch{}
			for _, o := range script.Objects {
				out.Objects = append(out.Objects, ratify.V2StatusEvidenceObject{ObjectType: o.ObjectTypeCode, Wire: unb64(t, o.WireB64)})
			}
			return out, nil
		},
		Audience: func(_ context.Context, _ []ratify.V2DeferredConstraint, _ string) ([]ratify.V2AudienceMembership, error) {
			counts.Audience++
			switch in.AudienceMode {
			case "error":
				return nil, fmt.Errorf("scripted audience provider failure")
			case "panic":
				panic("scripted audience provider panic")
			}
			out := []ratify.V2AudienceMembership{}
			for _, m := range in.AudienceMemberships {
				out = append(out, ratify.V2AudienceMembership{DelegationIndex: m.DelegationIndex, ConstraintIndex: m.ConstraintIndex, ReceiverID: m.ReceiverID, TrustDomainIDs: m.TrustDomainIDs, IssuedAt: m.IssuedAt, ExpiresAt: m.ExpiresAt, EvidenceDigest: m.EvidenceDigest})
			}
			return out, nil
		},
	}
	if in.Journal.Mode != "absent" {
		cb.StatusJournal = &v2ModalJournalStore{inner: v2BuildStatusJournal(t, in), mode: in.Journal.Mode}
	}
	switch in.ReceiverBindingHook {
	case "accept", "reject":
		cb.ReceiverBinding = func(*ratify.ProofBundleV2, ratify.ExpectedChallengeV2) error {
			counts.ReceiverBinding++
			if in.ReceiverBindingHook == "reject" {
				return fmt.Errorf("application receiver binding rejected")
			}
			return nil
		}
	}
	var rate *v2ScriptedRateStore
	if in.Rate != "absent" && in.Rate != "" {
		rate = &v2ScriptedRateStore{mode: in.Rate, counts: counts}
		cb.Rate = rate
	}
	return req, cb, rate
}

func TestV2ConformanceVerifierOrdering(t *testing.T) {
	var f struct {
		Version     int                `json:"version"`
		Description string             `json:"description"`
		Semantics   map[string]string  `json:"semantics"`
		Bundles     map[string]string  `json:"bundles_b64"`
		Vectors     []v2OrderingVector `json:"vectors"`
	}
	loadV2Vector(t, "verifier-ordering.json", &f)
	if len(f.Vectors) == 0 {
		t.Fatal("no ordering vectors")
	}
	for _, v := range f.Vectors {
		bundle, ok := f.Bundles[v.Bundle]
		if !ok {
			t.Fatalf("%s: unknown bundle %q", v.Name, v.Bundle)
		}
		t.Run(v.Name, func(t *testing.T) { runV2OrderingVector(t, v, unb64(t, bundle)) })
	}
}

func runV2OrderingVector(t *testing.T, v v2OrderingVector, bundle []byte) {
	counts := &v2Counts{}
	req, cb, rate := v2BuildVerifyRequest(t, v.v2OrderingInputs, bundle, counts)
	claimedAt := v.Now + v.ClaimTimeOffset
	store := &v2ScriptedClaimStore{mode: v.ClaimStore, claimedAt: claimedAt, finalizationAt: claimedAt + v.FinalizeTimeOffset, counts: counts}
	cb.ClaimStore = store

	outcome, err := ratify.VerifyProofBundleV2(context.Background(), req, cb)
	want := v.Expected
	if string(outcome.Stage) != want.Stage {
		t.Fatalf("stage %q (class %q, err %v), want %q", outcome.Stage, outcome.ErrorClass, outcome.Error, want.Stage)
	}
	if (err != nil) != (want.Stage == "evaluating") {
		t.Fatalf("returned error %v does not match stage %s", err, want.Stage)
	}
	if string(outcome.ErrorClass) != want.ErrorClass {
		t.Errorf("error class %q (%v), want %q", outcome.ErrorClass, outcome.Error, want.ErrorClass)
	}
	if want.Disposition != "" && string(outcome.Disposition) != want.Disposition {
		t.Errorf("disposition %q, want %q", outcome.Disposition, want.Disposition)
	}
	if *counts != want.CallbackCounts {
		t.Errorf("callback counts %+v, want %+v", *counts, want.CallbackCounts)
	}
	if want.Stage != "committed" {
		if outcome.Committed != nil {
			t.Fatal("a non-committed stage carried a committed outcome")
		}
		return
	}
	committed := outcome.Committed
	if committed == nil {
		t.Fatal("committed stage without a committed outcome")
	}
	body := committed.ReceiptBody()
	r, err := ratify.DecodeVerificationReceiptBodyV2(body)
	if err != nil {
		t.Fatalf("committed receipt body does not decode: %v", err)
	}
	got := []string{r.Decision, r.DecisionReason, r.IdentityStatus, r.TrustAssessment, r.StatusAssessment, r.ContextAssessment}
	exp := []string{want.Decision, want.DecisionReason, want.IdentityStatus, want.TrustAssessment, want.StatusAssessment, want.ContextAssessment}
	if strings.Join(got, "|") != strings.Join(exp, "|") {
		t.Errorf("committed tuple %v, want %v", got, exp)
	}
	if r.VerifiedAt != want.VerifiedAt {
		t.Errorf("verified_at %d, want %d (authoritative claim time)", r.VerifiedAt, want.VerifiedAt)
	}
	if !bytes.Equal(body, unb64(t, want.ReceiptBodyB64)) || !bytes.Equal(store.finalBody, body) {
		t.Errorf("receipt body differs:\n got %s\nwant %s", body, unb64(t, want.ReceiptBodyB64))
	}
	if committed.ReceiptBodyDigest() != ratify.ReceiptOutboxDigestV2(unb64(t, want.ReceiptBodyB64)) || committed.ClaimID() == "" {
		t.Error("committed handoff digest or claim ID is wrong")
	}
	horizon, ok := committed.AllowHorizon()
	if ok != (want.Decision == "allow") || horizon != want.AllowValidUntil {
		t.Errorf("allow horizon %d (%t), want %d", horizon, ok, want.AllowValidUntil)
	}
	if len(want.RateBatch) != 0 {
		if rate == nil || len(rate.batch) != len(want.RateBatch) {
			t.Fatalf("rate batch %+v, want %+v", rate, want.RateBatch)
		}
		for i, w := range want.RateBatch {
			g := rate.batch[i]
			if g.IssuerID != w.IssuerID || g.CertID != w.CertID || g.WindowS != w.WindowS || g.Limit != w.Limit {
				t.Errorf("rate batch[%d] %+v, want %+v", i, g, w)
			}
		}
	}
}
