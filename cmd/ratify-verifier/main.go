// Command ratify-verifier is a minimal HTTP reference verifier for the
// Ratify Protocol. It exposes the two endpoints from SPEC.md §13:
//
//	POST /v1/ratify/challenge
//	    Response: {"challenge":"<base64>","expires_at":<unix>,"ttl_seconds":300}
//
//	POST /v1/ratify/verify
//	    Body:  {"proof_bundle":"<base64-json>","required_scope":"<scope>"}
//	    Response: <VerifyResult>
//
// Security hardening:
//   - Per-IP rate limiting on the challenge endpoint (default 60/min).
//   - Optional API key via -api-key flag. When set, all requests must
//     include `Authorization: Bearer <key>`.
//   - Challenge store is capped (default 10,000 entries). Excess issuance
//     returns 429.
//
// This is a reference implementation for integration testing, not a
// production verifier. Production deployments should add persistent
// revocation, TLS termination, authentication, and monitoring.
//
// Usage:
//
//	go run ./cmd/ratify-verifier                   # listens on :8080
//	go run ./cmd/ratify-verifier -addr :9090       # custom port
//	go run ./cmd/ratify-verifier -api-key secret   # require Bearer auth
//	go run ./cmd/ratify-verifier -rate-limit 30    # 30 challenges/min/IP
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

// challengeStore tracks issued challenges with a 5-minute TTL.
// Each challenge is single-use: verified-and-consumed in one round trip.
type challengeStore struct {
	mu         sync.Mutex
	challenges map[string]int64 // base64(challenge) -> expires_at
	maxSize    int
}

func newChallengeStore(maxSize int) *challengeStore {
	return &challengeStore{challenges: make(map[string]int64), maxSize: maxSize}
}

func (s *challengeStore) issue(challenge []byte, ttl time.Duration) (int64, bool) {
	expiresAt := time.Now().Add(ttl).Unix()
	key := base64.StdEncoding.EncodeToString(challenge)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if len(s.challenges) >= s.maxSize {
		return 0, false
	}
	s.challenges[key] = expiresAt
	return expiresAt, true
}

func (s *challengeStore) consume(challenge []byte) bool {
	key := base64.StdEncoding.EncodeToString(challenge)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	_, ok := s.challenges[key]
	if ok {
		delete(s.challenges, key)
	}
	return ok
}

func (s *challengeStore) expireLocked() {
	now := time.Now().Unix()
	for k, exp := range s.challenges {
		if exp < now {
			delete(s.challenges, k)
		}
	}
}

// rateLimiter tracks per-IP request counts in a rolling window.
type rateLimiter struct {
	mu      sync.Mutex
	counts  map[string][]int64 // IP -> list of request timestamps
	limit   int
	windowS int64
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{
		counts:  make(map[string][]int64),
		limit:   limit,
		windowS: 60,
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now().Unix()
	cutoff := now - rl.windowS

	// Prune old entries for this IP.
	timestamps := rl.counts[ip]
	pruned := timestamps[:0]
	for _, ts := range timestamps {
		if ts > cutoff {
			pruned = append(pruned, ts)
		}
	}

	if len(pruned) >= rl.limit {
		rl.counts[ip] = pruned
		return false
	}
	rl.counts[ip] = append(pruned, now)
	return true
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

type challengeResponse struct {
	Challenge  string `json:"challenge"`
	ExpiresAt  int64  `json:"expires_at"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type verifyRequest struct {
	ProofBundle   string `json:"proof_bundle"`   // base64-encoded bundle JSON
	RequiredScope string `json:"required_scope"` // optional
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	apiKey := flag.String("api-key", "", "optional Bearer API key (if set, all requests must include it)")
	rateLimit := flag.Int("rate-limit", 60, "max challenge requests per IP per minute (0 = unlimited)")
	maxChallenges := flag.Int("max-challenges", 10000, "max pending challenges in memory")
	registryURL := flag.String("registry", "", "optional https registry base URL (SPEC §13.1) — when set, the chain root key must be the registry's current key for the principal")
	registryTTL := flag.Duration("registry-ttl", 5*time.Minute, "registry cache lifetime; stale entries are re-fetched, never served")
	registryPins := flag.String("registry-pins", "", "optional JSON file of pinned HybridPublicKeys — pins are keyed by their own derived id and enforced per SPEC §13.1")
	registryRequirePinned := flag.Bool("registry-require-pinned", false, "pin-plus-registry mode: only accept principals descending from a configured pin (requires -registry-pins)")
	flag.Parse()

	store := newChallengeStore(*maxChallenges)
	limiter := newRateLimiter(*rateLimit)

	var resolver *RegistryResolver
	requirePinned := false
	if *registryURL != "" {
		var err error
		resolver, err = NewRegistryResolver(*registryURL, *registryTTL, nil)
		if err != nil {
			log.Fatalf("registry: %v", err)
		}
		if *registryPins != "" {
			n, err := resolver.LoadPinsFile(*registryPins)
			if err != nil {
				log.Fatalf("registry pins: %v", err)
			}
			log.Printf("loaded %d pinned key(s) from %s", n, *registryPins)
		}
		if *registryRequirePinned {
			if *registryPins == "" {
				log.Fatal("registry: -registry-require-pinned needs -registry-pins (fail closed on misconfiguration)")
			}
			requirePinned = true
		}
		mode := "registry trust (operator + TLS)"
		if requirePinned {
			mode = "pin-plus-registry (only pinned principals and their rotation successors)"
		}
		log.Printf("registry-mode key discovery enabled: %s — %s (SPEC §13.1, fail-closed)", *registryURL, mode)
	} else if *registryPins != "" || *registryRequirePinned {
		log.Fatal("registry: -registry-pins / -registry-require-pinned need -registry")
	}

	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		if *apiKey == "" {
			return next
		}
		expected := "Bearer " + *apiKey
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != expected {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			next(w, r)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ratify/challenge", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if *rateLimit > 0 && !limiter.allow(clientIP(r)) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": fmt.Sprintf("rate limit exceeded: max %d challenges per minute per IP", *rateLimit),
			})
			log.Printf("rate-limited challenge request from %s", clientIP(r))
			return
		}

		challenge, err := ratify.GenerateChallenge()
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		expiresAt, ok := store.issue(challenge, 5*time.Minute)
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "challenge store full — too many pending challenges",
			})
			log.Printf("challenge store full (%d max)", *maxChallenges)
			return
		}
		resp := challengeResponse{
			Challenge:  base64.StdEncoding.EncodeToString(challenge),
			ExpiresAt:  expiresAt,
			TTLSeconds: int(ratify.ChallengeWindowSeconds),
		}
		writeJSON(w, http.StatusOK, resp)
		log.Printf("issued challenge %s... expires at %d", resp.Challenge[:16], expiresAt)
	}))

	mux.HandleFunc("POST /v1/ratify/verify", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req verifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("parse body: %w", err))
			return
		}
		bundleJSON, err := base64.StdEncoding.DecodeString(req.ProofBundle)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("decode bundle base64: %w", err))
			return
		}
		var bundle ratify.ProofBundle
		if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("parse bundle: %w", err))
			return
		}

		// Challenge MUST have been issued by this server and not yet consumed.
		if !store.consume(bundle.Challenge) {
			writeJSON(w, http.StatusOK, ratify.VerifyResult{
				Valid:          false,
				IdentityStatus: "invalid",
				ErrorReason:    "unknown_challenge: challenge was not issued by this verifier or has already been used",
			})
			log.Printf("reject: unknown or consumed challenge")
			return
		}

		// Registry-mode key discovery (SPEC §13.1): the chain root's issuer
		// key must be the registry's CURRENT key for the principal. Any
		// resolution failure is a rejection (fail closed); a mismatch is a
		// rejection — historical roots are rejected by default.
		if resolver != nil {
			if len(bundle.Delegations) == 0 {
				writeJSON(w, http.StatusOK, ratify.VerifyResult{
					Valid:          false,
					IdentityStatus: "invalid",
					ErrorReason:    "registry_unresolved: bundle carries no delegations",
				})
				return
			}
			root := &bundle.Delegations[len(bundle.Delegations)-1]
			var key ratify.HybridPublicKey
			var err error
			if requirePinned {
				key, err = resolver.ResolveRootDescendedFromAnyPin(root.IssuerID)
			} else {
				key, err = resolver.ResolveRoot(root.IssuerID)
			}
			if err != nil {
				writeJSON(w, http.StatusOK, ratify.VerifyResult{
					Valid:          false,
					IdentityStatus: "invalid",
					ErrorReason:    "registry_unresolved: " + err.Error(),
				})
				log.Printf("reject: registry resolution failed for %s: %v", root.IssuerID, err)
				return
			}
			if !pubKeyEqual(key, root.IssuerPubKey) {
				writeJSON(w, http.StatusOK, ratify.VerifyResult{
					Valid:          false,
					IdentityStatus: "invalid",
					ErrorReason:    "registry_key_mismatch: chain root key is not the registry's current key for this principal (historical roots are rejected by default — SPEC §13.1)",
				})
				log.Printf("reject: registry key mismatch for %s", root.IssuerID)
				return
			}
		}

		result := ratify.Verify(&bundle, ratify.VerifyOptions{RequiredScope: req.RequiredScope})
		writeJSON(w, http.StatusOK, result)

		if result.Valid {
			log.Printf("verify OK  agent=%s human=%s scope=%v",
				result.AgentID, result.HumanID, result.GrantedScope)
		} else {
			log.Printf("verify FAIL  %s: %s", result.IdentityStatus, result.ErrorReason)
		}
	}))

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	log.Printf("ratify-verifier listening on %s", *addr)
	log.Printf("  POST /v1/ratify/challenge    issues a 32-byte challenge (rate-limited: %d/min/IP)", *rateLimit)
	log.Printf("  POST /v1/ratify/verify       verifies a base64-encoded ProofBundle")
	log.Printf("  GET  /health                 liveness check")
	if *apiKey != "" {
		log.Printf("  auth: Bearer API key required on all endpoints")
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
