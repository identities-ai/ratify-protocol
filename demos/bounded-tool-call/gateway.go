package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

type toolRequest struct {
	Tool   string             `json:"tool"`
	Amount float64            `json:"amount"`
	Bundle ratify.ProofBundle `json:"bundle"`
}

type challengeRequest struct {
	AgentID string  `json:"agent_id"`
	Tool    string  `json:"tool"`
	Amount  float64 `json:"amount"`
}

type challengeResponse struct {
	Challenge []byte `json:"challenge"`
	ExpiresAt int64  `json:"expires_at"`
}

type toolResponse struct {
	Decision   string `json:"decision"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	OrderID    string `json:"order_id,omitempty"`
	OrderCount int    `json:"order_count"`
}

type gateway struct {
	trust      vendorState
	challenges *ratify.MemoryChallengeStore
	mu         sync.Mutex
	orders     []string
	revoked    map[string]bool
}

func newGateway(trust vendorState) *gateway {
	return &gateway{
		trust: trust, challenges: ratify.NewMemoryChallengeStore(100),
		revoked: make(map[string]bool),
	}
}

func (g *gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge", g.challenge)
	mux.HandleFunc("POST /tools", g.callTool)
	mux.HandleFunc("POST /revoke", g.revoke)
	return mux
}

func (g *gateway) challenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sessionContext, err := operationSessionContext(req.AgentID, req.Tool, req.Amount)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	challenge, expiresAt, err := g.challenges.Issue(sessionContext, 60*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeHTTPJSON(w, http.StatusOK, challengeResponse{Challenge: challenge, ExpiresAt: expiresAt})
}

func (g *gateway) callTool(w http.ResponseWriter, r *http.Request) {
	var req toolRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result := g.verify(req)
	response := toolResponse{
		Decision: "DENY", Status: decisionCode(result),
		Reason: displayReason(result, req), OrderCount: g.orderCount(),
	}
	if result.Valid {
		response.Decision = "ALLOW"
		response.Reason = "signed authority is valid"
		response.OrderID = g.placeOrder()
		response.OrderCount = g.orderCount()
	}
	fmt.Printf("%-9s Scout → %s($%.2f)  %s  %s", "INCOMING", req.Tool, req.Amount, response.Decision, response.Status)
	if response.OrderID != "" {
		fmt.Printf("  order=%s", response.OrderID)
	}
	fmt.Println()
	writeHTTPJSON(w, http.StatusOK, response)
}

func displayReason(result ratify.VerifyResult, req toolRequest) string {
	switch decisionCode(result) {
	case "constraint_denied":
		return fmt.Sprintf("$%.2f exceeds Scout's signed $500 limit", req.Amount)
	case "scope_denied":
		return fmt.Sprintf("Scout is authorized for %s, not %s", authorizedTool, req.Tool)
	case "bad_signature":
		return "the signed authorization was changed after issuance"
	case "revoked":
		return "Alice's upstream delegation to Atlas was revoked"
	case "unknown_challenge":
		return "the vendor challenge was already used or was not issued here"
	case "session_context_mismatch":
		return "the tool request changed after Scout signed it"
	case "untrusted_root":
		return "the proof does not descend from the vendor's trusted Alice root"
	default:
		return result.ErrorReason
	}
}

func (g *gateway) verify(req toolRequest) ratify.VerifyResult {
	if len(req.Bundle.Delegations) == 0 {
		return invalidResult("untrusted_root", "proof has no delegation chain")
	}
	root := req.Bundle.Delegations[len(req.Bundle.Delegations)-1]
	if root.IssuerID != g.trust.TrustedHumanID ||
		!bytes.Equal(root.IssuerPubKey.Ed25519, g.trust.TrustedRootKey.Ed25519) ||
		!bytes.Equal(root.IssuerPubKey.MLDSA65, g.trust.TrustedRootKey.MLDSA65) {
		return invalidResult("untrusted_root", "proof does not descend from the vendor's trusted Alice root")
	}
	sessionContext, err := operationSessionContext(req.Bundle.AgentID, req.Tool, req.Amount)
	if err != nil {
		return invalidResult("invalid_operation", err.Error())
	}
	return ratify.Verify(&req.Bundle, ratify.VerifyOptions{
		RequiredScope:  toolScope(req.Tool),
		ChallengeStore: g.challenges,
		SessionContext: sessionContext,
		IsRevoked: func(certID string) bool {
			g.mu.Lock()
			defer g.mu.Unlock()
			return g.revoked[certID]
		},
		Context: ratify.VerifierContext{
			RequestedAmount: req.Amount, RequestedCurrency: "USD", HasAmount: true,
		},
	})
}

func (g *gateway) placeOrder() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := fmt.Sprintf("ACME-%04d", 1042+len(g.orders))
	g.orders = append(g.orders, id)
	return id
}

func (g *gateway) orderCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.orders)
}

func (g *gateway) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+g.trust.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	g.mu.Lock()
	g.revoked[g.trust.UpstreamCertID] = true
	g.mu.Unlock()
	writeHTTPJSON(w, http.StatusOK, map[string]string{"status": "revoked", "cert_id": g.trust.UpstreamCertID})
}

func invalidResult(code, reason string) ratify.VerifyResult {
	return ratify.VerifyResult{IdentityStatus: "invalid", ErrorReason: code + ": " + reason}
}

func decisionCode(result ratify.VerifyResult) string {
	if result.IdentityStatus != "invalid" {
		return result.IdentityStatus
	}
	code, _, ok := bytes.Cut([]byte(result.ErrorReason), []byte(":"))
	if ok {
		return string(code)
	}
	return result.IdentityStatus
}

func writeHTTPJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
