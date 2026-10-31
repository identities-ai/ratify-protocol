package v2vectors

// Middleware Custody Profile vectors (SPEC-v2 §7.15). Under middleware
// custody the party that signs presentations also routes them, so a validly
// signed proof can be attached to the wrong tenant, invocation, action, or
// receiver. Each vector signs a proof whose session_context was derived from
// one swapped binding input, while the challenge issuer stored the context of
// the authenticated request. The verifier must reject it before claim with
// session_context_mismatch: nothing is consumed and no callback runs.

import ratify "github.com/identities-ai/ratify-protocol/v2"

// custodyBinding is the complete set of inputs to the session context of
// SPEC-v2 §2.4, including the operation context behind request_hash.
type custodyBinding struct {
	verifierID, workspace, agentID, session, invocation string
	scope, operation, resource, path                    string
	payload                                             []byte
}

func (b custodyBinding) context() []byte {
	request := operationContextHash(b.scope, b.operation, b.resource, b.path, b.payload)
	return sessionContext(b.verifierID, b.workspace, b.agentID, b.session, b.invocation, request)
}

func (g *gen) custodyProfileScenarios() []scenario {
	agent := g.k("agent")
	certs := g.chain(chainSpec{})
	// The authenticated request: exactly the fixture context of every other
	// ordering vector.
	authentic := custodyBinding{
		verifierID: g.k("verifier").ID, workspace: fixtureWorkspace, agentID: agent.ID, session: fixtureSession, invocation: fixtureInvocation,
		scope: "data:read", operation: "records.get", resource: "customer/123", path: "/v1/customers/123",
	}
	expected := authentic.context()
	if string(expected) != string(g.fixtureSessionContext(agent)) {
		panic("custody vectors: authentic binding differs from the fixture session context")
	}
	otherPayload := make([]byte, 32)
	for i := range otherPayload {
		otherPayload[i] = 0x33
	}
	swaps := []struct {
		name, desc string
		edit       func(*custodyBinding)
	}{
		{"tenant", "workspace (tenant) ID of another tenant", func(b *custodyBinding) { b.workspace = "00000000-0000-4000-8000-000000000002" }},
		{"invocation", "another invocation of the same session", func(b *custodyBinding) { b.invocation = "invocation-02" }},
		{"session", "another session of the same agent", func(b *custodyBinding) { b.session = "session-02" }},
		{"receiver", "another receiver's verifier ID inside the session context (the bundle's own verifier_id is unchanged)", func(b *custodyBinding) { b.verifierID = g.k("party_b_agent").ID }},
		{"agent", "another agent ID inside the session context (the bundle is still signed by the bound agent)", func(b *custodyBinding) { b.agentID = g.k("party_b_agent").ID }},
		{"scope", "an action under another required scope (files:read)", func(b *custodyBinding) { b.scope = "files:read" }},
		{"operation", "another operation on the same resource", func(b *custodyBinding) { b.operation = "records.delete" }},
		{"resource", "the same operation on another resource ID", func(b *custodyBinding) { b.resource = "customer/124" }},
		{"path", "the same operation on another requested path", func(b *custodyBinding) { b.path = "/v1/customers/124" }},
		{"payload", "the same action with a payload digest where the authentic request has none", func(b *custodyBinding) { b.payload = otherPayload }},
	}
	var out []scenario
	for _, swap := range swaps {
		signed := authentic
		swap.edit(&signed)
		_, bundle, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: signed.context()})
		out = append(out, scenario{
			name:     "custody_profile_swapped_" + swap.name,
			desc:     "Middleware Custody Profile: a correctly signed proof whose session context binds " + swap.desc + " fails before claim; nothing is consumed and no callback runs",
			bundle:   bundle,
			certs:    certs,
			scope:    "data:read",
			expected: g.defaultExpected(agent, expected),
			policy:   g.verifyPolicyJSON(expected),
			trust:    g.trustRoot("root"),
			evidence: g.currentEvidenceBatches(certs),
			out:      preflight(string(ratify.V2ErrSessionContextMismatch), 0),
		})
	}
	return out
}
