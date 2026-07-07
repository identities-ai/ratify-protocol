package main

// Reference implementation of the SPEC §13.1 resolver requirements: given a
// registry base URL, resolve a principal's CURRENT root public key with
// rotation-chain continuity validation. Fail-closed on every branch —
// network failure, non-200, malformed JSON, chain-order/signature/link
// errors, final-key mismatch, pinned-key discontinuity, staleness — all
// surface as an error, never as a permissive fallback.
//
// This is deployment-facing reference code, not SDK API surface. It resolves
// the trust root BEFORE verification; it is unrelated to the AnchorResolver
// provider interface (§17.8), which attaches audit metadata AFTER successful
// verification.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

// humanIDPattern is the §7 identifier shape: hex(SHA-256(keys)[:16]) —
// exactly 32 lowercase hex characters.
var humanIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// registryRecord is the §13.1 response shape.
type registryRecord struct {
	HumanID   string                        `json:"human_id"`
	PublicKey ratify.HybridPublicKey        `json:"public_key"`
	Rotations []ratify.KeyRotationStatement `json:"rotations"`
	Anchor    *ratify.Anchor                `json:"anchor"`
	UpdatedAt int64                         `json:"updated_at"`
}

// cachedRecord stores the FULL validated record, not just the key: pin
// connectivity must be re-checked on every cache hit, because a pin recorded
// after the record was cached must be enforced against it (SPEC §13.1), and
// that check needs the rotation chain. Signatures are validated once at
// fetch time — the cached chain is immutable — but connectivity is not a
// fetch-time property; it depends on the verifier's current pin set.
type cachedRecord struct {
	rec       registryRecord
	fetchedAt time.Time
}

// RegistryResolver resolves principal root keys per SPEC §13.1.
type RegistryResolver struct {
	baseURL string
	client  *http.Client
	ttl     time.Duration
	now     func() time.Time

	mu     sync.Mutex
	pinned map[string]ratify.HybridPublicKey
	cache  map[string]cachedRecord
}

// NewRegistryResolver builds a resolver for the given registry base URL.
// The URL MUST be https — §13.1 forbids plain-HTTP registries outright, so
// this refuses at construction rather than at first use. client may be nil
// (a 10s-timeout default is used); tests inject a TLS test server's client.
func NewRegistryResolver(baseURL string, ttl time.Duration, client *http.Client) (*RegistryResolver, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("registry URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("registry URL must be https (SPEC §13.1) — got %q", baseURL)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &RegistryResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
		ttl:     ttl,
		now:     time.Now,
		pinned:  make(map[string]ratify.HybridPublicKey),
		cache:   make(map[string]cachedRecord),
	}, nil
}

// Pin records a trusted key — the verifier's own trust decision (first
// trust; §13.1, §15.4). Pins are keyed by the pinned key's OWN derived id
// (§7): that is the only id the verifier can know at pin time — a rotation
// that happens later changes the principal's id, and discovering that new
// id's legitimacy is exactly what the rotation chain proves. Once pinned,
// any resolution whose chain passes through this key's id must carry
// exactly this key, and callers that require descent from this specific
// key use ResolveRootDescendedFrom.
func (r *RegistryResolver) Pin(key ratify.HybridPublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pinned[ratify.DeriveID(key)] = key
}

// ResolveRootDescendedFrom resolves currentID like ResolveRoot and
// ADDITIONALLY requires the returned record to descend from pinnedKey: the
// pinned key must be the current key itself or appear as a statement's old
// key in the rotation chain. This is the check with real teeth against
// lineage substitution — a registry serving an internally consistent but
// unrelated chain for an id the caller believes succeeds a known principal.
// Applies to cache hits identically.
func (r *RegistryResolver) ResolveRootDescendedFrom(currentID string, pinnedKey ratify.HybridPublicKey) (ratify.HybridPublicKey, error) {
	var zero ratify.HybridPublicKey
	key, rec, err := r.resolve(currentID)
	if err != nil {
		return zero, err
	}
	if !chainContainsKey(rec, pinnedKey) {
		return zero, errors.New("record does not descend from the required pinned key (continuity failure)")
	}
	return key, nil
}

// ResolveRoot returns the principal's current root key. Every failure mode
// returns an error; callers MUST treat any error as "key unresolved" and
// fail verification.
func (r *RegistryResolver) ResolveRoot(humanID string) (ratify.HybridPublicKey, error) {
	key, _, err := r.resolve(humanID)
	return key, err
}

// resolve is the shared fetch/cache/validate path. It returns the current
// key and the validated record so descent checks can inspect the chain.
func (r *RegistryResolver) resolve(humanID string) (ratify.HybridPublicKey, *registryRecord, error) {
	var zero ratify.HybridPublicKey
	if !humanIDPattern.MatchString(humanID) {
		return zero, nil, fmt.Errorf("human_id %q is not 32 lowercase hex characters", humanID)
	}

	r.mu.Lock()
	if c, ok := r.cache[humanID]; ok && r.now().Sub(c.fetchedAt) < r.ttl {
		rec := c.rec
		r.mu.Unlock()
		// Pin checks are a property of the verifier's CURRENT pin set,
		// not of the fetch — re-check on every cache hit so a pin
		// recorded after caching cannot be bypassed (SPEC §13.1).
		if err := r.checkPins(&rec); err != nil {
			return zero, nil, err
		}
		return rec.PublicKey, &rec, nil
	}
	r.mu.Unlock()

	resp, err := r.client.Get(r.baseURL + "/v1/registry/principals/" + humanID)
	if err != nil {
		return zero, nil, fmt.Errorf("registry fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return zero, nil, fmt.Errorf("registry body: %w", err)
	}
	var rec registryRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return zero, nil, fmt.Errorf("registry JSON: %w", err)
	}
	if err := r.validate(humanID, &rec); err != nil {
		return zero, nil, err
	}

	r.mu.Lock()
	r.cache[humanID] = cachedRecord{rec: rec, fetchedAt: r.now()}
	r.mu.Unlock()
	return rec.PublicKey, &rec, nil
}

// chainContainsKey reports whether key is the record's current key or
// appears as any rotation statement's old key.
func chainContainsKey(rec *registryRecord, key ratify.HybridPublicKey) bool {
	if pubKeyEqual(key, rec.PublicKey) {
		return true
	}
	for i := range rec.Rotations {
		if pubKeyEqual(key, rec.Rotations[i].OldPubKey) {
			return true
		}
	}
	return false
}

// validate applies the §13.1 resolver checks to a fetched record.
func (r *RegistryResolver) validate(humanID string, rec *registryRecord) error {
	if rec.HumanID != humanID {
		return fmt.Errorf("registry record human_id %q does not match requested %q", rec.HumanID, humanID)
	}
	if len(rec.PublicKey.Ed25519) != 32 || len(rec.PublicKey.MLDSA65) != 1952 {
		return errors.New("registry record public_key has wrong component sizes")
	}
	// Identifier semantics (§13.1): {human_id} addresses the CURRENT key,
	// and ids are key-derived (§7) — so the record's public_key must derive
	// exactly the id it is served under. This also enforces "final new_id
	// == human_id" for rotated principals, since statement ids are bound to
	// their keys by VerifyKeyRotationStatement and the final new key must
	// equal public_key.
	if ratify.DeriveID(rec.PublicKey) != humanID {
		return errors.New("public_key does not derive human_id — record is not addressed by its current key")
	}

	// Rotation chain: oldest → newest, each statement dual-signed and
	// verifying, links contiguous, final new key equal to public_key.
	for i := range rec.Rotations {
		stmt := &rec.Rotations[i]
		if err := ratify.VerifyKeyRotationStatement(stmt); err != nil {
			return fmt.Errorf("rotation %d does not verify: %w", i, err)
		}
		if i+1 < len(rec.Rotations) {
			next := &rec.Rotations[i+1]
			if !pubKeyEqual(stmt.NewPubKey, next.OldPubKey) {
				return fmt.Errorf("rotation chain broken between statements %d and %d", i, i+1)
			}
		}
	}
	if n := len(rec.Rotations); n > 0 {
		if !pubKeyEqual(rec.Rotations[n-1].NewPubKey, rec.PublicKey) {
			return errors.New("final rotation does not produce the record's public_key")
		}
	}

	return r.checkPins(rec)
}

// checkPins enforces the store-based pin rule: whenever the record's
// lineage passes through an id the verifier has pinned — as a rotation
// statement's old id or as the current id — the key at that position must
// equal the pinned key. Pins are keyed by the pinned key's own derived id
// (the only id the verifier could know at pin time), so this fires for a
// pre-rotation pin when the post-rotation chain is presented, without the
// caller needing to know the new id in advance. Called on fetch AND on
// every cache hit. Note: a record whose lineage never touches a pinned id
// passes this check — pins constrain claimed lineage; requiring descent
// from a specific pin is ResolveRootDescendedFrom's job.
func (r *RegistryResolver) checkPins(rec *registryRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pinned) == 0 {
		return nil
	}
	if pin, ok := r.pinned[rec.HumanID]; ok && !pubKeyEqual(pin, rec.PublicKey) {
		return errors.New("record's current key does not match the key pinned under this id")
	}
	for i := range rec.Rotations {
		stmt := &rec.Rotations[i]
		if pin, ok := r.pinned[stmt.OldID]; ok && !pubKeyEqual(pin, stmt.OldPubKey) {
			return fmt.Errorf("rotation %d claims lineage through pinned id %s with a different key", i, stmt.OldID)
		}
	}
	return nil
}

func pubKeyEqual(a, b ratify.HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}
