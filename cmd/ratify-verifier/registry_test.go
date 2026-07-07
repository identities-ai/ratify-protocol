package main

// Tests for the SPEC §13.1 reference resolver. The spec forbids plain-HTTP
// registries with no test carveout, so these use httptest.NewTLSServer and
// inject the test server's TLS-trusting client.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestResolverPinnedKeyContinuity(t *testing.T) {
	p0 := newPrincipal(t)
	stmt1, p1 := rotate(t, p0)

	// Pin the ORIGINAL key; a chain connecting it to the current key (which
	// is what the current id resolves to) must pass.
	resolver, _ := serveRecord(t, &registryRecord{
		HumanID:   p1.root.ID,
		PublicKey: p1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmt1},
	})
	resolver.Pin(p1.root.ID, p0.root.PublicKey)
	if _, err := resolver.ResolveRoot(p1.root.ID); err != nil {
		t.Fatalf("pinned historical key connected by the chain must resolve: %v", err)
	}

	// A registry answer whose chain does NOT include the pinned key fails —
	// even if internally consistent (registry substituted a different lineage).
	q0 := newPrincipal(t)
	stmtQ, q1 := rotate(t, q0)
	resolver2, _ := serveRecord(t, &registryRecord{
		HumanID:   q1.root.ID,
		PublicKey: q1.root.PublicKey,
		Rotations: []ratify.KeyRotationStatement{stmtQ},
	})
	resolver2.Pin(q1.root.ID, p0.root.PublicKey)
	if _, err := resolver2.ResolveRoot(q1.root.ID); err == nil {
		t.Fatal("chain that does not connect the pinned key must be a continuity failure")
	}
}

func TestResolverPinRecordedAfterCacheIsEnforced(t *testing.T) {
	// SPEC §13.1: pin continuity applies to every resolution, including
	// cache hits — a pin recorded after a record was cached must be
	// enforced against it, not bypassed by the cache.
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

	// Pin a key from an UNRELATED lineage after caching: the cached record
	// cannot connect it, so the next resolution must fail.
	stranger := newPrincipal(t)
	resolver.Pin(p1.root.ID, stranger.root.PublicKey)
	if _, err := resolver.ResolveRoot(p1.root.ID); err == nil {
		t.Fatal("pin recorded after caching must be enforced on cache hits (continuity failure expected)")
	}

	// Re-pin with the genuine historical key: the same cached record
	// connects it, so resolution succeeds again.
	resolver.Pin(p1.root.ID, p0.root.PublicKey)
	if _, err := resolver.ResolveRoot(p1.root.ID); err != nil {
		t.Fatalf("genuine pin connected by the cached chain must resolve: %v", err)
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
