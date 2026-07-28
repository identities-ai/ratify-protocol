package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayExecutesOnlyAuthorizedToolCalls(t *testing.T) {
	vendor, agent, err := createArtifacts("")
	if err != nil {
		t.Fatal(err)
	}
	gateway := newGateway(vendor)
	server := httptest.NewServer(gateway.handler())
	defer server.Close()

	tests := []struct {
		name       string
		tool       string
		amount     float64
		wantStatus string
		wantOrders int
	}{
		{name: "authorized", tool: "place_order", amount: 200, wantStatus: "authorized_agent", wantOrders: 1},
		{name: "over limit", tool: "place_order", amount: 2000, wantStatus: "constraint_denied", wantOrders: 1},
		{name: "wrong tool", tool: "cancel_order", amount: 200, wantStatus: "scope_denied", wantOrders: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request, err := buildToolRequest(http.DefaultClient, server.URL, agent, tt.tool, tt.amount)
			if err != nil {
				t.Fatal(err)
			}
			var response toolResponse
			if err := postJSON(http.DefaultClient, server.URL+"/tools", request, &response); err != nil {
				t.Fatal(err)
			}
			if response.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q", response.Status, tt.wantStatus)
			}
			if response.OrderCount != tt.wantOrders {
				t.Fatalf("orders = %d, want %d", response.OrderCount, tt.wantOrders)
			}
		})
	}
}

func TestGatewayRejectsReplayAndUntrustedRootWithoutSideEffects(t *testing.T) {
	vendor, agent, err := createArtifacts("")
	if err != nil {
		t.Fatal(err)
	}
	gateway := newGateway(vendor)
	server := httptest.NewServer(gateway.handler())
	defer server.Close()

	request, err := buildToolRequest(http.DefaultClient, server.URL, agent, "place_order", 200)
	if err != nil {
		t.Fatal(err)
	}
	var first, replay toolResponse
	if err := postJSON(http.DefaultClient, server.URL+"/tools", request, &first); err != nil {
		t.Fatal(err)
	}
	if err := postJSON(http.DefaultClient, server.URL+"/tools", request, &replay); err != nil {
		t.Fatal(err)
	}
	if first.OrderCount != 1 || replay.Status != "unknown_challenge" || replay.OrderCount != 1 {
		t.Fatalf("unexpected replay results: first=%+v replay=%+v", first, replay)
	}

	_, stranger, err := createArtifacts("")
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := buildToolRequest(http.DefaultClient, server.URL, stranger, "place_order", 200)
	if err != nil {
		t.Fatal(err)
	}
	var rejected toolResponse
	if err := postJSON(http.DefaultClient, server.URL+"/tools", untrusted, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status != "untrusted_root" || rejected.OrderCount != 1 {
		t.Fatalf("unexpected untrusted-root result: %+v", rejected)
	}
}

func TestGatewayRejectsRequestChangedAfterAgentSigns(t *testing.T) {
	vendor, agent, err := createArtifacts("")
	if err != nil {
		t.Fatal(err)
	}
	gateway := newGateway(vendor)
	server := httptest.NewServer(gateway.handler())
	defer server.Close()

	request, err := buildToolRequest(http.DefaultClient, server.URL, agent, "place_order", 200)
	if err != nil {
		t.Fatal(err)
	}
	request.Amount = 400

	var rejected toolResponse
	if err := postJSON(http.DefaultClient, server.URL+"/tools", request, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status != "session_context_mismatch" || rejected.OrderCount != 0 {
		t.Fatalf("unexpected changed-request result: %+v", rejected)
	}
}

func TestGatewayRejectsTamperingAndRevocationWithoutSideEffects(t *testing.T) {
	vendor, agent, err := createArtifacts("")
	if err != nil {
		t.Fatal(err)
	}
	gateway := newGateway(vendor)
	server := httptest.NewServer(gateway.handler())
	defer server.Close()

	tampered, err := buildToolRequest(http.DefaultClient, server.URL, agent, "place_order", 200)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Bundle.Delegations[0].Constraints[0].MaxAmount = 5000
	var rejected toolResponse
	if err := postJSON(http.DefaultClient, server.URL+"/tools", tampered, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status != "bad_signature" || rejected.OrderCount != 0 {
		t.Fatalf("unexpected tamper result: %+v", rejected)
	}
	agent.Delegations[0].Constraints[0].MaxAmount = 500

	var revoked map[string]string
	if err := postAuthorizedJSON(http.DefaultClient, server.URL+"/revoke", vendor.AdminToken, &revoked); err != nil {
		t.Fatal(err)
	}
	request, err := buildToolRequest(http.DefaultClient, server.URL, agent, "place_order", 200)
	if err != nil {
		t.Fatal(err)
	}
	if err := postJSON(http.DefaultClient, server.URL+"/tools", request, &rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status != "revoked" || rejected.OrderCount != 0 {
		t.Fatalf("unexpected revocation result: %+v", rejected)
	}
}
