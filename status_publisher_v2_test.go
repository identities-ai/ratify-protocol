package ratify

import (
	"context"
	"testing"
)

func TestV2StatusPublisherRejectsForeignStateAndBadConfiguration(t *testing.T) {
	ctx := context.Background()
	issuerPub, _, _ := GenerateHybridKeypair()
	_, statusPriv, _ := GenerateHybridKeypair()
	signer, _ := NewLocalSignerV2(statusPriv)
	statusPub := statusPriv.Public()
	otherPub, _, _ := GenerateHybridKeypair()
	roles := newMemorySecurityJournalStoreV2()
	if _, err := RecordSecurityKeyRoleV2(ctx, roles, "issuer", issuerPub); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordSecurityKeyRoleV2(ctx, roles, "verifier", otherPub); err != nil {
		t.Fatal(err)
	}
	issuerID, _ := KeyIDV2(issuerPub)
	if _, err := ConfigureStatusKeyEpochV2(ctx, roles, issuerID, 1, statusPub); err != nil {
		t.Fatal(err)
	}
	for _, lifetime := range []int64{0, V2MaxStatusLifetimeSeconds + 1} {
		if _, err := NewV2StatusPublisher(ctx, roles, issuerPub, signer, lifetime); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
			t.Errorf("lifetime %d accepted: %v", lifetime, err)
		}
	}
	if _, err := NewV2StatusPublisher(ctx, roles, issuerPub, nil, 60); err == nil {
		t.Error("nil signer accepted")
	}
	// Without the authenticated role configuration the publisher cannot know
	// every non-status key, so construction is refused.
	if _, err := NewV2StatusPublisher(ctx, nil, issuerPub, signer, 60); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Errorf("missing role configuration accepted: %v", err)
	}
	// A recorded key sharing one component with the status key is role reuse.
	mixedRoles := newMemorySecurityJournalStoreV2()
	mixed := HybridPublicKey{Ed25519: statusPub.Ed25519, MLDSA65: otherPub.MLDSA65}
	if _, err := RecordSecurityKeyRoleV2(ctx, mixedRoles, "issuer", issuerPub); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordSecurityKeyRoleV2(ctx, mixedRoles, "delegation", mixed); err != nil {
		t.Fatal(err)
	}
	if _, err := NewV2StatusPublisher(ctx, mixedRoles, issuerPub, signer, 60); err == nil {
		t.Error("a status key sharing one component with a recorded role key was accepted")
	}
	publisher, err := NewV2StatusPublisher(ctx, roles, issuerPub, signer, 60)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := publisher.Genesis(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.IssuerID() != genesis.List.IssuerID || genesis.State.Sequence != 1 || len(genesis.State.Revoked) != 0 {
		t.Fatalf("genesis state = %+v", genesis.State)
	}
	foreign := genesis.State
	foreign.StatusKeyID = publisher.IssuerID()
	if _, err := publisher.Heartbeat(ctx, foreign, 2000); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Errorf("foreign state accepted: %v", err)
	}
	unsorted := genesis.State
	unsorted.Revoked = []string{"b", "a"}
	if _, err := publisher.Revoke(ctx, unsorted, []string{"c"}, 2000); V2ErrorClassOf(err) != V2ErrConfigurationInvalid {
		t.Errorf("unsorted state accepted: %v", err)
	}
	revoked, err := publisher.Revoke(ctx, genesis.State, []string{"z", "a"}, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State.Sequence != 2 || revoked.Push.Revoked[0].CertID != "a" || revoked.List.Revoked[1].CertID != "z" {
		t.Fatalf("revocation output is not sorted: %+v", revoked.State)
	}
	if genesis.State.Revoked == nil || len(genesis.State.Revoked) != 0 {
		t.Fatal("a later transition mutated the earlier state")
	}
	if _, err := publisher.Heartbeat(ctx, revoked.State, V2MaxTimestampSeconds); err == nil {
		t.Fatal("a list whose next_update leaves the timestamp domain was signed")
	}
}
