package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"time"

	ratify "github.com/identities-ai/ratify-protocol"
)

func runIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	dir := fs.String("state", defaultStateDir, "demo state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	vendor, _, err := createArtifacts(*dir)
	if err != nil {
		return err
	}
	fmt.Println("RATIFY — PORTABLE TOOL AUTHORIZATION")
	fmt.Println()
	fmt.Println("Alice → Atlas   place_order up to $5,000 for 24 hours")
	fmt.Println("Atlas → Scout   place_order up to $500 for 1 hour")
	fmt.Printf("Vendor trusts   Alice %s…\n", vendor.TrustedHumanID[:12])
	fmt.Printf("Artifacts       %s\n", *dir)
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := fs.String("state", defaultStateDir, "demo state directory")
	addr := fs.String("addr", "127.0.0.1:8080", "gateway address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var vendor vendorState
	if err := readJSON(filepath.Join(*dir, "vendor.json"), &vendor); err != nil {
		return fmt.Errorf("read vendor trust: %w (run issue first)", err)
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("start gateway on %s: %w", *addr, err)
	}
	defer listener.Close()
	fmt.Println("ACME SUPPLIES — AGENT TOOL GATEWAY")
	fmt.Println()
	fmt.Printf("Listening      http://%s\n", *addr)
	fmt.Println("Protected tool place_order")
	fmt.Printf("Trusted root   Alice %s…\n", vendor.TrustedHumanID[:12])
	fmt.Println("Verification   Local Ratify SDK")
	fmt.Println()
	fmt.Println("Waiting for agent calls…")
	return http.Serve(listener, newGateway(vendor).handler())
}

func runCall(args []string) error {
	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	dir := fs.String("state", defaultStateDir, "demo state directory")
	baseURL := fs.String("gateway", "http://127.0.0.1:8080", "gateway URL")
	tool := fs.String("tool", authorizedTool, "tool to call")
	amount := fs.Float64("amount", 200, "amount in USD")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *amount < 0 {
		return fmt.Errorf("amount must be zero or greater")
	}
	var agent agentState
	if err := readJSON(filepath.Join(*dir, "scout.json"), &agent); err != nil {
		return fmt.Errorf("read Scout state: %w (run issue first)", err)
	}
	req, err := buildToolRequest(http.DefaultClient, *baseURL, agent, *tool, *amount)
	if err != nil {
		return err
	}
	var response toolResponse
	if err := postJSON(http.DefaultClient, *baseURL+"/tools", req, &response); err != nil {
		return err
	}
	printToolResponse(req, response)
	return nil
}

func buildToolRequest(client *http.Client, baseURL string, agent agentState, tool string, amount float64) (toolRequest, error) {
	sessionContext, err := operationSessionContext(agent.Agent.ID, tool, amount)
	if err != nil {
		return toolRequest{}, err
	}
	var challenge challengeResponse
	if err := postJSON(client, baseURL+"/challenge", challengeRequest{
		AgentID: agent.Agent.ID,
		Tool:    tool,
		Amount:  amount,
	}, &challenge); err != nil {
		return toolRequest{}, err
	}
	priv, err := agent.Seeds.privateKey()
	if err != nil {
		return toolRequest{}, err
	}
	now := time.Now().Unix()
	sig, err := ratify.SignChallengeWithSessionContext(challenge.Challenge, now, sessionContext, priv)
	if err != nil {
		return toolRequest{}, err
	}
	return toolRequest{Tool: tool, Amount: amount, Bundle: ratify.ProofBundle{
		AgentID: agent.Agent.ID, AgentPubKey: agent.Agent.PublicKey,
		Delegations: agent.Delegations, Challenge: challenge.Challenge,
		ChallengeAt: now, ChallengeSig: sig, SessionContext: sessionContext,
	}}, nil
}

func runRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	dir := fs.String("state", defaultStateDir, "demo state directory")
	baseURL := fs.String("gateway", "http://127.0.0.1:8080", "gateway URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var vendor vendorState
	if err := readJSON(filepath.Join(*dir, "vendor.json"), &vendor); err != nil {
		return fmt.Errorf("read vendor state: %w", err)
	}
	var response map[string]string
	if err := postAuthorizedJSON(http.DefaultClient, *baseURL+"/revoke", vendor.AdminToken, &response); err != nil {
		return err
	}
	fmt.Println("REVOKED     Alice → Atlas")
	return nil
}

func postAuthorizedJSON(client *http.Client, url, token string, out any) error {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway returned %s", response.Status)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func printToolResponse(req toolRequest, response toolResponse) {
	fmt.Printf("Scout → %s($%.2f)\n\n", req.Tool, req.Amount)
	fmt.Printf("Decision     %s\n", response.Decision)
	fmt.Printf("Status       %s\n", response.Status)
	if response.Decision == "ALLOW" {
		fmt.Printf("Executed     order %s created\n", response.OrderID)
	} else {
		fmt.Println("Executed     no — tool handler was not called")
		fmt.Printf("Reason       %s\n", response.Reason)
	}
	fmt.Printf("Orders       %d\n", response.OrderCount)
}

func postJSON(client *http.Client, url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	response, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return json.NewDecoder(response.Body).Decode(out)
}
