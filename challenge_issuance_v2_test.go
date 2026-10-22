package ratify

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type issuanceClockV2Test struct {
	now int64
	err error
}

func (c issuanceClockV2Test) AuthoritativeTimeV2(context.Context) (int64, error) { return c.now, c.err }

// issuanceStoreV2Test records whether a persisted challenge was later
// exposed, so the test can prove persistence precedes the return.
type issuanceStoreV2Test struct {
	records map[string]ExpectedChallengeV2
	err     error
	panics  bool
}

func (s *issuanceStoreV2Test) PersistV2Challenge(_ context.Context, record ExpectedChallengeV2) error {
	if s.panics {
		panic("store exploded")
	}
	if s.err != nil {
		return s.err
	}
	digest, _ := ChallengeClaimDigestV2(record.Value)
	if _, ok := s.records[string(digest)]; ok {
		return ErrV2ChallengeIssuanceConflict
	}
	s.records[string(digest)] = record
	return nil
}

func (s *issuanceStoreV2Test) LoadV2Challenge(_ context.Context, _ string, _ int64, digest []byte) (ExpectedChallengeV2, error) {
	record, ok := s.records[string(digest)]
	if !ok {
		return ExpectedChallengeV2{}, ErrV2ChallengeIssuanceNotFound
	}
	return record, nil
}

func TestIssueChallengeV2PersistsBeforeExposure(t *testing.T) {
	pub, _, _ := GenerateHybridKeypair()
	agentID, _ := KeyIDV2(pub)
	verifierID := strings.Repeat("ab", 32)
	req := V2ChallengeIssueRequest{VerifierNamespace: "ns", ReplayEpoch: 2, VerifierID: verifierID, LifetimeSeconds: 60,
		ExpectedAgentID: agentID, ExpectedAgentPublicKey: &pub, ExpectedReceiverID: "receiver-1", ExpectedSessionContext: bytes.Repeat([]byte{7}, 32)}
	store := &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}
	issuer := V2ChallengeIssuer{Clock: issuanceClockV2Test{now: 1000}, Store: store}
	got, err := issuer.IssueChallengeV2(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Value) != 32 || got.IssuedAt != 1000 || got.ExpiresAt != 1060 || got.ExpectedAgentID != agentID || got.ExpectedReceiverID != "receiver-1" {
		t.Fatalf("issued record = %+v", got)
	}
	loaded, err := LoadExpectedChallengeV2(context.Background(), store, "ns", 2, got.Value)
	if err != nil || !bytes.Equal(loaded.Value, got.Value) || !bytes.Equal(loaded.ExpectedSessionContext, req.ExpectedSessionContext) {
		t.Fatalf("returned challenge is not retrievable: %v", err)
	}
	// The returned record is a copy: changing it changes nothing stored.
	got.Value[0] ^= 1
	if _, err := LoadExpectedChallengeV2(context.Background(), store, "ns", 2, loaded.Value); err != nil {
		t.Fatal("caller mutation reached the stored record")
	}

	for name, issuer := range map[string]V2ChallengeIssuer{
		"store error":  {Clock: issuanceClockV2Test{now: 1000}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}, err: errors.New("disk full")}},
		"store panic":  {Clock: issuanceClockV2Test{now: 1000}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}, panics: true}},
		"clock error":  {Clock: issuanceClockV2Test{err: errors.New("clock down")}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}},
		"clock domain": {Clock: issuanceClockV2Test{now: V2MaxTimestampSeconds + 1}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}},
		"expiry past":  {Clock: issuanceClockV2Test{now: V2MaxTimestampSeconds - 10}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}},
		"no store":     {Clock: issuanceClockV2Test{now: 1000}},
		"no clock":     {Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}},
		"short random": {Clock: issuanceClockV2Test{now: 1000}, Store: &issuanceStoreV2Test{records: map[string]ExpectedChallengeV2{}}, Random: bytes.NewReader(make([]byte, 31))},
	} {
		if got, err := issuer.IssueChallengeV2(context.Background(), req); err == nil || got != nil {
			t.Errorf("%s: a challenge was exposed without durable persistence", name)
		}
	}

	bad := map[string]func(*V2ChallengeIssueRequest){
		"empty namespace":      func(r *V2ChallengeIssueRequest) { r.VerifierNamespace = "" },
		"negative epoch":       func(r *V2ChallengeIssueRequest) { r.ReplayEpoch = -1 },
		"bad verifier":         func(r *V2ChallengeIssueRequest) { r.VerifierID = "abc" },
		"zero lifetime":        func(r *V2ChallengeIssueRequest) { r.LifetimeSeconds = 0 },
		"long lifetime":        func(r *V2ChallengeIssueRequest) { r.LifetimeSeconds = V2MaxChallengeAgeSeconds + 1 },
		"agent ID without key": func(r *V2ChallengeIssueRequest) { r.ExpectedAgentPublicKey = nil },
		"agent ID mismatch":    func(r *V2ChallengeIssueRequest) { r.ExpectedAgentID = verifierID },
		"short session":        func(r *V2ChallengeIssueRequest) { r.ExpectedSessionContext = make([]byte, 31) },
		"receiver not UTF-8":   func(r *V2ChallengeIssueRequest) { r.ExpectedReceiverID = "\xff" },
	}
	for name, mutate := range bad {
		r := req
		mutate(&r)
		if _, err := issuer.IssueChallengeV2(context.Background(), r); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Errorf("%s: class %q, want configuration_invalid", name, V2ErrorClassOf(err))
		}
	}
	if _, err := LoadExpectedChallengeV2(context.Background(), store, "ns", 2, make([]byte, 32)); V2ErrorClassOf(err) != V2ErrExpectedChallengeMissing {
		t.Fatalf("unknown challenge: %v", err)
	}
	if _, err := LoadExpectedChallengeV2(context.Background(), store, "ns", 2, make([]byte, 31)); V2ErrorClassOf(err) != V2ErrExpectedChallengeMissing {
		t.Fatalf("short challenge: %v", err)
	}
}
