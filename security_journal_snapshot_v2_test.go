package ratify

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// The genesis snapshot and digest are pinned by SPEC-v2 §6.6 so every SDK
// starts its journal chain from the same anchored head.
func TestSecurityJournalV2GenesisSnapshotMatchesSpec(t *testing.T) {
	genesis := EmptySecurityJournalV2()
	snapshot, err := ExportSecurityJournalSnapshotV2(genesis)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"generation":0,"issuers":[],"key_role_history":[],"previous_digest":"` + strings.Repeat("0", 96) + `","status_key_history":[],"version":2}`
	if string(snapshot) != want {
		t.Fatalf("genesis snapshot\n got %s\nwant %s", snapshot, want)
	}
	const wantDigest = "85dae29143ca6d02b5254b5dcb237596e5c5e1e2009cdd4d6cb4a20a8c72a54a3101fa72c419f7c4b76d66e90cb61d96"
	if genesis.Digest != wantDigest || SecurityJournalSnapshotDigestV2(snapshot) != wantDigest {
		t.Fatalf("genesis digest %s, want %s", genesis.Digest, wantDigest)
	}
}

// A committed journal must survive export and import byte for byte, and the
// import must refuse any snapshot that is not exactly canonical or does not
// match the anchored head: a portable snapshot is only as good as its head.
func TestSecurityJournalV2SnapshotRoundTripAndRejections(t *testing.T) {
	ctx := context.Background()
	store := newMemorySecurityJournalStoreV2()
	issuerID := strings.Repeat("d", 64)
	pub, private, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ConfigureStatusKeyEpochV2(ctx, store, issuerID, 1, pub); err != nil {
		t.Fatal(err)
	}
	list, err := SignRevocationListV2(&RevocationListV2{Version: 2, IssuerID: issuerID, UpdatedAt: 99, NextUpdate: 120, Sequence: 1, Revoked: []RevokedCertV2{{CertID: "known"}}}, issuerID, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := ApplyRevocationListToJournalV2(ctx, store, list, issuerID, 1, pub, RevocationStatusPolicyV2{MaxListLifetimeSeconds: 100, MaxStatusAgeSeconds: 50}, 100)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ExportSecurityJournalSnapshotV2(journal)
	if err != nil {
		t.Fatal(err)
	}
	head := SecurityJournalHeadV2{Generation: journal.Generation, Digest: journal.Digest}
	imported, err := ImportSecurityJournalSnapshotV2(snapshot, head)
	if err != nil {
		t.Fatalf("import of an exported snapshot failed: %v", err)
	}
	again, err := ExportSecurityJournalSnapshotV2(imported)
	if err != nil || !bytes.Equal(again, snapshot) {
		t.Fatalf("snapshot did not round-trip: %v", err)
	}
	if _, err := ImportSecurityJournalSnapshotV2(snapshot, SecurityJournalHeadV2{Generation: head.Generation + 1, Digest: head.Digest}); err == nil {
		t.Fatal("imported a snapshot whose generation differs from the anchored head")
	}
	spaced := append([]byte(" "), snapshot...)
	if _, err := ImportSecurityJournalSnapshotV2(spaced, SecurityJournalHeadV2{Generation: head.Generation, Digest: SecurityJournalSnapshotDigestV2(spaced)}); err == nil {
		t.Fatal("imported a noncanonical snapshot")
	}
	unknown := bytes.Replace(snapshot, []byte(`{"generation"`), []byte(`{"extra":1,"generation"`), 1)
	if _, err := ImportSecurityJournalSnapshotV2(unknown, SecurityJournalHeadV2{Generation: head.Generation, Digest: SecurityJournalSnapshotDigestV2(unknown)}); err == nil {
		t.Fatal("imported a snapshot with an unknown member")
	}
}

// Migration turns a version 1 record into its version 2 successor as one
// contiguous transition, so the anchored head advances by compare-and-swap
// and the logical content is unchanged.
func TestSecurityJournalV2MigratesLegacyVersion1Record(t *testing.T) {
	legacy := SecurityJournalV2{Version: securityJournalLegacyVersion, StatusByIssuer: map[string]RevocationStatusStateV2{}, KeyRoleHistory: []KeyRoleBindingV2{}, StatusKeyHistory: []StatusKeyBindingV2{}}
	pub, _, err := GenerateHybridKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterKeyRoleV2(&legacy, "verifier", pub); err != nil {
		t.Fatal(err)
	}
	legacy.Generation, legacy.PreviousDigest = 1, strings.Repeat("a", 96)
	legacy.Digest, err = legacySecurityJournalDigestV1(legacy)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateSecurityJournalV2(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Version != securityJournalVersionV2 || migrated.Generation != 2 || migrated.PreviousDigest != legacy.Digest || !sameSecurityJournalContentV2(legacy, migrated) {
		t.Fatalf("migration produced %+v", migrated)
	}
	if _, err := MigrateSecurityJournalV2(migrated); err == nil {
		t.Fatal("migrated a record that is already version 2")
	}
	tampered := legacy
	tampered.Generation = 5
	if _, err := MigrateSecurityJournalV2(tampered); err == nil {
		t.Fatal("migrated a version 1 record whose legacy digest does not verify")
	}
}
