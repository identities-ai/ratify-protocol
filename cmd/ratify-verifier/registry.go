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

type cachedKey struct {
	key       ratify.HybridPublicKey
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
	cache  map[string]cachedKey
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
		cache:   make(map[string]cachedKey),
	}, nil
}

// Pin records a trusted key for humanID — the verifier's own trust decision
// (first trust; §13.1, §15.4). Once pinned, ResolveRoot additionally requires
// the registry's rotation chain to connect this key to the current key.
func (r *RegistryResolver) Pin(humanID string, key ratify.HybridPublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pinned[humanID] = key
}

// ResolveRoot returns the principal's current root key. Every failure mode
// returns an error; callers MUST treat any error as "key unresolved" and
// fail verification.
func (r *RegistryResolver) ResolveRoot(humanID string) (ratify.HybridPublicKey, error) {
	var zero ratify.HybridPublicKey
	if !humanIDPattern.MatchString(humanID) {
		return zero, fmt.Errorf("human_id %q is not 32 lowercase hex characters", humanID)
	}

	r.mu.Lock()
	if c, ok := r.cache[humanID]; ok && r.now().Sub(c.fetchedAt) < r.ttl {
		key := c.key
		r.mu.Unlock()
		return key, nil
	}
	r.mu.Unlock()

	resp, err := r.client.Get(r.baseURL + "/v1/registry/principals/" + humanID)
	if err != nil {
		return zero, fmt.Errorf("registry fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return zero, fmt.Errorf("registry body: %w", err)
	}
	var rec registryRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return zero, fmt.Errorf("registry JSON: %w", err)
	}
	if err := r.validate(humanID, &rec); err != nil {
		return zero, err
	}

	r.mu.Lock()
	r.cache[humanID] = cachedKey{key: rec.PublicKey, fetchedAt: r.now()}
	r.mu.Unlock()
	return rec.PublicKey, nil
}

// validate applies the §13.1 resolver checks to a fetched record.
func (r *RegistryResolver) validate(humanID string, rec *registryRecord) error {
	if rec.HumanID != humanID {
		return fmt.Errorf("registry record human_id %q does not match requested %q", rec.HumanID, humanID)
	}
	if len(rec.PublicKey.Ed25519) != 32 || len(rec.PublicKey.MLDSA65) != 1952 {
		return errors.New("registry record public_key has wrong component sizes")
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

	// Pinned-key continuity: the chain must connect the verifier's pinned
	// key to the current key. The pin may be the current key itself or any
	// historical key that appears as a statement's old key.
	r.mu.Lock()
	pin, pinned := r.pinned[humanID]
	r.mu.Unlock()
	if pinned {
		connected := pubKeyEqual(pin, rec.PublicKey)
		for i := range rec.Rotations {
			if pubKeyEqual(pin, rec.Rotations[i].OldPubKey) {
				connected = true
				break
			}
		}
		if !connected {
			return errors.New("rotation chain does not connect the pinned key to the current key (continuity failure)")
		}
	}
	return nil
}

func pubKeyEqual(a, b ratify.HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}
