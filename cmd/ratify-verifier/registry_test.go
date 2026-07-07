package main

// Tests for the SPEC §13.1 reference resolver. The spec forbids plain-HTTP
// registries with no test carveout, so these use httptest.NewTLSServer and
// inject the test server's TLS-trusting client.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

type testPrincipal struct {
	root *ratify.HumanRoot
	priv ratify.HybridPrivateKey
}

func newPrincipal(t *testing.T) testPrincipal {
	t.Helper()
	root, priv, err := ratify.GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	return testPrincipal{root: root, priv: priv}
}

// rotate produces a verified KeyRotationStatement from old to a fresh key,
// returning the statement and the new key material.
func rotate(t *testing.T, old testPrincipal) (ratify.KeyRotationStatement, testPrincipal) {
	t.Helper()
	newRoot, newPriv, err := ratify.GenerateHumanRootKeypair()
	if err != nil {
		t.Fatalf("generate new root: %v", err)
	}
	stmt := ratify.KeyRotationStatement{
		Version:   ratify.ProtocolVersion,
		OldID:     old.root.ID,
		OldPubKey: old.root.PublicKey,
		NewID:     newRoot.ID,
		NewPubKey: newRoot.PublicKey,
		RotatedAt: time.Now().Unix(),
		Reason:    "routine",
	}
	if err := ratify.IssueKeyRotationStatement(&stmt, old.priv, newPriv); err != nil {
		t.Fatalf("issue rotation: %v", err)
	}
	return stmt, testPrincipal{root: newRoot, priv: newPriv}
}

// serveRecord starts a TLS registry serving exactly one record and returns a
// resolver pointed at it.
func serveRecord(t *testing.T, rec *registryRecord) (*RegistryResolver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec == nil || r.URL.Path != "/v1/registry/principals/"+rec.HumanID {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("{}"))
			return
		}
		json.NewEncoder(w).Encode(rec)
	}))
	t.Cleanup(srv.Close)
	resolver, err := NewRegistryResolver(srv.URL, time.Minute, srv.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	return resolver, srv
}

func TestResolverRefusesPlainHTTP(t *testing.T) {
	if _, err := NewRegistryResolver("http://registry.example.com", time.Minute, nil); err == nil {
		t.Fatal("plain-http registry URL must be refused at construction (SPEC §13.1)")
	}
}

func TestResolverRejectsMalformedHumanID(t *testing.T) {
	p := newPrincipal(t)
	resolver, _ := serveRecord(t, &registryRecord{HumanID: p.root.ID, PublicKey: p.root.PublicKey})
	for _, id := range []string{"", "xyz", "ABCDEF00112233445566778899AABBCC", p.root.ID + "00"} {
		if _, err := resolver.ResolveRoot(id); err == nil {
			t.Fatalf("human_id %q must be rejected", id)
		}
	}
}

func TestResolverHappyPathNoRotations(t *testing.T) {
	p := newPrincipal(t)
	resolver, _ := serveRecord(t, &registryRecord{HumanID: p.root.ID, PublicKey: p.root.PublicKey})
	key, err := resolver.ResolveRoot(p.root.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !pubKeyEqual(key, p.root.PublicKey) {
		t.Fatal("resolved key does not match")
	}
}

func TestResolverHappyPathWithRotationChain(t *testing.T) {
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	stmt2, p2 := rotate(t, p1)
	// §13.1 identifier semantics: ids are key-derived, so rotation changes
	// the principal's id — the registry addresses the record by the CURRENT
	// id, and that is the id a current-key bundle presents as its root issuer.
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p2.root.ID,
		PublicKey: p2.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1, stmt2},
	})
	key, err := resolver.ResolveRoot(p2.root.ID)
	if err != nil {
		t.Fatalf("resolve with chain: %v", err)
	}
	if !pubKeyEqual(key, p2.root.PublicKey) {
		t.Fatal("resolved key must be the post-rotation current key")
	}
}

func TestResolverRejectsRecordNotAddressedByCurrentKey(t *testing.T) {
	// A record served under a rotated-away id (public_key does not derive
	// the id it is addressed by) is malformed — DeriveID(public_key) must
	// equal human_id. This pins the §13.1 identifier semantics.
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p0.root.ID, // WRONG: addressed by the original id
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})
	if _, err := resolver.ResolveRoot(p0.root.ID); err == nil {
		t.Fatal("record addressed by a rotated-away id must be rejected (DeriveID(public_key) != human_id)")
	}
}

func TestResolverRejectsUnknownPrincipal(t *testing.T) {
	p := newPrincipal(t)
	other := newPrincipal(t)
	resolver, _ := serveRecord(t, &registryRecord{HumanID: p.root.ID, PublicKey: p.root.PublicKey})
	if _, err := resolver.ResolveRoot(other.root.ID); err == nil {
		t.Fatal("unknown principal (404) must fail resolution")
	}
}

func TestResolverRejectsBrokenChainLink(t *testing.T) {
	p0 := newPrincipal(t)
	stmt1, _ := rotate(t, p0)
	// A second statement NOT chained from stmt1's new key.
	q0 := newPrincipal(t)
	stmtX, q1 := rotate(t, q0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   q1.root.ID, // correctly addressed by the current key's id
		PublicKey: q1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1, stmtX},
	})
	if _, err := resolver.ResolveRoot(q1.root.ID); err == nil {
		t.Fatal("non-contiguous rotation chain must be rejected")
	}
}

func TestResolverRejectsTamperedRotation(t *testing.T) {
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	stmt1.Reason = "tampered-after-signing"
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p1.root.ID,
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})
	if _, err := resolver.ResolveRoot(p1.root.ID); err == nil {
		t.Fatal("rotation statement with invalid signatures must be rejected")
	}
}

func TestResolverRejectsFinalKeyMismatch(t *testing.T) {
	p0 := newPrincipal(t)
	stmt1, _ := rotate(t, p0)
	impostor := newPrincipal(t)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   impostor.root.ID, // id derives from public_key, so the
		PublicKey: impostor.root.PublicKey, // final-key check is what trips
		Rotations: []ratify.KeyRotationStatement{stmt1}, // stmt1's new key ≠ public_key
	})
	if _, err := resolver.ResolveRoot(impostor.root.ID); err == nil {
		t.Fatal("public_key not produced by the final rotation must be rejected")
	}
}

func TestResolverHistoricalPinRealisticSequence(t *testing.T) {
	// The realistic caller model: the verifier pinned Alice BEFORE the
	// rotation, so its pin is keyed by the OLD key's own derived id — it
	// cannot know the post-rotation id in advance. A post-rotation bundle
	// presents the NEW id; resolving it must still engage the pin via the
	// chain, with no old-id → new-id mapping supplied by the caller.
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p1.root.ID,
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})
	resolver.Pin(p0.root.PublicKey) // stored under p0's own id — pin-time knowledge only

	// General resolution: the chain passes through the pinned id with the
	// pinned key — engages and passes.
	if _, err := resolver.ResolveRoot(p1.root.ID); err != nil {
		t.Fatalf("resolving the post-rotation id with a pre-rotation pin must work: %v", err)
	}

	// Descent-required resolution: this is the check with teeth. The same
	// record descends from the pin — passes.
	if _, err := resolver.ResolveRootDescendedFrom(p1.root.ID, p0.root.PublicKey); err != nil {
		t.Fatalf("descent from the pinned key must be provable from the chain: %v", err)
	}
}

func TestResolverDescentRequirementCatchesLineageSubstitution(t *testing.T) {
	// A registry serving an internally consistent but UNRELATED lineage for
	// an id the caller believes succeeds a known principal: plain
	// ResolveRoot passes (the record is valid and touches no pinned id),
	// but the descent-required call must fail — that distinction is the
	// point of ResolveRootDescendedFrom.
	p0 := newPrincipal(t)
	q0 := newPrincipal(t)
	stmtQ, q1 := rotate(t, q0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   q1.root.ID,
		PublicKey: q1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmtQ},
	})
	resolver.Pin(p0.root.PublicKey)

	if _, err := resolver.ResolveRoot(q1.root.ID); err != nil {
		t.Fatalf("unrelated principal must still resolve under registry trust: %v", err)
	}
	if _, err := resolver.ResolveRootDescendedFrom(q1.root.ID, p0.root.PublicKey); err == nil {
		t.Fatal("descent requirement must reject a lineage that does not contain the pinned key")
	}
}

func TestResolverPinRecordedAfterCacheIsEnforced(t *testing.T) {
	// SPEC §13.1: pin checks apply to every resolution, including cache
	// hits — a pin recorded after a record was cached must be enforced
	// against it, not bypassed by the cache.
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p1.root.ID,
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})

	if _, err := resolver.ResolveRoot(p1.root.ID); err != nil {
		t.Fatalf("first resolve (caches record): %v", err)
	}

	// Pin recorded AFTER caching: the cached record's chain passes through
	// the pinned id with the pinned key — engages on the cache hit and
	// passes (no refetch).
	resolver.Pin(p0.root.PublicKey)
	if _, err := resolver.ResolveRoot(p1.root.ID); err != nil {
		t.Fatalf("pin recorded after caching must be evaluated on cache hits: %v", err)
	}

	// Descent requirement against the CACHED record: unrelated key fails,
	// genuine historical key passes — both served from cache.
	stranger := newPrincipal(t)
	if _, err := resolver.ResolveRootDescendedFrom(p1.root.ID, stranger.root.PublicKey); err == nil {
		t.Fatal("descent from an unrelated key must fail on cached records too")
	}
	if _, err := resolver.ResolveRootDescendedFrom(p1.root.ID, p0.root.PublicKey); err != nil {
		t.Fatalf("descent from the genuine pinned key must pass on cached records: %v", err)
	}
}

func TestResolverDescendedFromAnyPin(t *testing.T) {
	// Pin-plus-registry mode: only pinned principals and their rotation
	// successors resolve; everything else is a continuity failure, and an
	// empty pin store is a misconfiguration, not a pass-through.
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p1.root.ID,
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})

	// Empty pin store fails closed.
	if _, err := resolver.ResolveRootDescendedFromAnyPin(p1.root.ID); err == nil {
		t.Fatal("pin-required mode with no pins must fail closed")
	}

	// An unrelated pin does not admit this lineage.
	stranger := newPrincipal(t)
	resolver.Pin(stranger.root.PublicKey)
	if _, err := resolver.ResolveRootDescendedFromAnyPin(p1.root.ID); err == nil {
		t.Fatal("record descending from no configured pin must be rejected")
	}

	// Adding the genuine historical pin admits the successor.
	resolver.Pin(p0.root.PublicKey)
	key, err := resolver.ResolveRootDescendedFromAnyPin(p1.root.ID)
	if err != nil {
		t.Fatalf("successor of a pinned principal must resolve: %v", err)
	}
	if !pubKeyEqual(key, p1.root.PublicKey) {
		t.Fatal("resolved key must be the current key")
	}
}

func TestLoadPinsFile(t *testing.T) {
	p0 := newPrincipal(t)
	p1 := newPrincipal(t)
	dir := t.TempDir()

	good := dir + "/pins.json"
	data, err := json.Marshal([]ratify.HybridPublicKey{p0.root.PublicKey, p1.root.PublicKey})
	if err != nil {
		t.Fatalf("marshal pins: %v", err)
	}
	if err := os.WriteFile(good, data, 0o600); err != nil {
		t.Fatalf("write pins: %v", err)
	}

	resolver, _ := serveRecord(t, &registryRecord{HumanID: p0.root.ID, PublicKey: p0.root.PublicKey})
	n, err := resolver.LoadPinsFile(good)
	if err != nil || n != 2 {
		t.Fatalf("load pins: n=%d err=%v", n, err)
	}
	// The loaded pin admits its principal in pin-required mode.
	if _, err := resolver.ResolveRootDescendedFromAnyPin(p0.root.ID); err != nil {
		t.Fatalf("loaded pin must admit its principal: %v", err)
	}

	// Empty array and malformed keys fail closed.
	empty := dir + "/empty.json"
	os.WriteFile(empty, []byte("[]"), 0o600)
	if _, err := resolver.LoadPinsFile(empty); err == nil {
		t.Fatal("empty pins file must be rejected")
	}
	bad := dir + "/bad.json"
	os.WriteFile(bad, []byte(`[{"ed25519":"AAECAw==","ml_dsa_65":"AAECAw=="}]`), 0o600)
	if _, err := resolver.LoadPinsFile(bad); err == nil {
		t.Fatal("pins with wrong key sizes must be rejected")
	}
}

func TestResolverRejectsMalformedJSON(t *testing.T) {
	p := newPrincipal(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"human_id": 42, not json`))
	}))
	t.Cleanup(srv.Close)
	resolver, err := NewRegistryResolver(srv.URL, time.Minute, srv.Client())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	if _, err := resolver.ResolveRoot(p.root.ID); err == nil {
		t.Fatal("malformed JSON must fail resolution")
	}
}

func TestResolverStaleCacheRefetchesAndFailsClosed(t *testing.T) {
	p := newPrincipal(t)
	rec := &registryRecord{HumanID: p.root.ID, PublicKey: p.root.PublicKey}
	resolver, srv := serveRecord(t, rec)

	if _, err := resolver.ResolveRoot(p.root.ID); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Within TTL: served from cache even with the registry down.
	srv.Close()
	if _, err := resolver.ResolveRoot(p.root.ID); err != nil {
		t.Fatalf("within-TTL cache must serve: %v", err)
	}
	// Beyond TTL: stale data is never served — refetch fails, resolution fails.
	resolver.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := resolver.ResolveRoot(p.root.ID); err == nil {
		t.Fatal("stale cache with unreachable registry must fail closed")
	}
}
