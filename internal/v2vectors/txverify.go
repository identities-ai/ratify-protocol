package v2vectors

// Composed transaction-receipt verification (SPEC-v2 §5.7). Each vector is
// one single-party receipt over the default two-link chain, evaluated with
// the verifier-ordering provider and journal inputs. Expected results are
// written from the spec rules here.

import ratify "github.com/identities-ai/ratify-protocol/v2"

type txPartyResultJSON struct {
	PartyID              string         `json:"party_id"`
	AgentID              string         `json:"agent_id"`
	RequiredScope        string         `json:"required_scope"`
	TrustAssessment      string         `json:"trust_assessment"`
	DelegationAssessment string         `json:"delegation_assessment"`
	DelegationExpiresAt  *int64         `json:"delegation_expires_at"`
	StatusAssessment     string         `json:"status_assessment"`
	ScopeAssessment      string         `json:"scope_assessment"`
	Freshness            string         `json:"freshness"`
	StatusEvidence       []EvidenceJSON `json:"status_evidence_digests"`
}

type txResultJSON struct {
	TransactionID string              `json:"transaction_id"`
	Actionable    bool                `json:"actionable"`
	Parties       []txPartyResultJSON `json:"parties"`
}

type txVerifyExpectJSON struct {
	ErrorClass string        `json:"error_class,omitempty"`
	Result     *txResultJSON `json:"result,omitempty"`
}

type txVerifyVector struct {
	Name              string                        `json:"name"`
	Description       string                        `json:"description"`
	ReceiptB64        string                        `json:"receipt_b64"`
	Now               int64                         `json:"now"`
	FutureSkewSeconds int64                         `json:"future_skew_seconds"`
	Trust             *trustJSON                    `json:"trust"`
	StatusKeys        map[string]statusKeyJSON      `json:"status_keys"`
	StatusPolicy      statusPolicyJSON              `json:"status_policy"`
	Journal           journalJSON                   `json:"journal"`
	StatusEvidence    map[string]statusProviderJSON `json:"status_evidence"`
	Expected          txVerifyExpectJSON            `json:"expected"`
}

type txVerifyFile struct {
	Version     int               `json:"version"`
	Description string            `json:"description"`
	Semantics   map[string]string `json:"semantics"`
	Vectors     []txVerifyVector  `json:"vectors"`
}

const txVerifyID = "tx-verify-0001"

// txVerifyReceipt signs a one-party receipt (party "buyer", the fixture
// agent) whose proof carries certs and whose signed required scope is scope.
func (g *gen) txVerifyReceipt(certs []ratify.DelegationCertV2, scope string) []byte {
	agent := g.k("agent")
	schema := "https://example.com/terms/purchase/v1"
	txCtx := func() []byte {
		pre := append([]byte("ratify/transaction-context/v2"), lp([]byte(txVerifyID))...)
		pre = append(pre, lp([]byte(schema))...)
		pre = append(pre, sha384([]byte(txTerms))...)
		return sha256Sum(pre)
	}()
	req := sha256Sum(append(append([]byte("ratify/transaction-party-request/v2"), lp(txCtx)...), lp([]byte(scope))...))
	session := sessionContext(g.k("verifier").ID, fixtureWorkspace, agent.ID, "session-buyer", "invocation-buyer", req)
	b, bwire, _ := g.bundle(bundleSpec{agent: agent, certs: certs, session: session})
	receipt := &ratify.TransactionReceiptV2{Version: 2, TransactionID: txVerifyID, CreatedAt: Now - 5, TermsSchemaURI: schema, TermsCanonicalJSON: []byte(txTerms),
		Parties: []ratify.TransactionReceiptPartyV2{{
			PartyID: "buyer", Role: "buyer", AgentID: agent.ID, AgentPubKey: agent.Pub, VerifierID: g.k("verifier").ID, WorkspaceID: fixtureWorkspace,
			SessionID: "session-buyer", InvocationID: "invocation-buyer", RequiredScope: scope, ProofBundleHash: bundleHash(bwire), ProofBundle: b,
		}}}
	signable := must(ratify.TransactionReceiptV2SignBytes(receipt))
	receipt.PartySignatures = []ratify.TransactionReceiptSignatureV2{{PartyID: "buyer", Signature: signDet(agent, codeParty, signable)}}
	return must(ratify.EncodeTransactionReceiptV2(receipt))
}

func (g *gen) txVerifyFile() any {
	st := g.statusFixtures()
	f := txVerifyFile{
		Version: 2,
		Description: "Composed transaction-receipt verification (SPEC-v2 §5.7). Decode receipt_b64 and call VerifyTransactionReceiptV2 with now, future_skew_seconds, the trust provider, status evidence provider, SecurityJournalV2 store, status_keys and status_policy built exactly as in verifier-ordering.json. expected.error_class: the call fails with that class. expected.result: the exact result; status_evidence_digests is in the canonical order of SPEC-v2 §5.8.",
		Semantics: map[string]string{
			"trust":           "as in verifier-ordering.json; null = no trust provider",
			"status_evidence": "as in verifier-ordering.json; an issuer without an entry returns an empty batch",
			"journal":         "as in verifier-ordering.json",
		},
	}
	def := g.chain(chainSpec{})
	current := []EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])}
	defExpiry := Now + 86400
	party := func(trust, delegation, status, scope string, expires *int64, evidence []EvidenceJSON) *txResultJSON {
		if evidence == nil {
			evidence = []EvidenceJSON{}
		}
		return &txResultJSON{TransactionID: txVerifyID, Parties: []txPartyResultJSON{{
			PartyID: "buyer", AgentID: g.k("agent").ID, RequiredScope: "data:read", TrustAssessment: trust, DelegationAssessment: delegation,
			DelegationExpiresAt: expires, StatusAssessment: status, ScopeAssessment: scope, Freshness: ratify.FreshnessUnverifiedV2, StatusEvidence: sortEvidence(evidence),
		}}}
	}
	add := func(name, desc string, certs []ratify.DelegationCertV2, scope string, expect txVerifyExpectJSON, edit func(*txVerifyVector)) {
		v := txVerifyVector{Name: name, Description: desc, ReceiptB64: b64(g.txVerifyReceipt(certs, scope)), Now: Now, FutureSkewSeconds: 5,
			Trust: g.trustRoot("root"), StatusKeys: g.statusKeyConfig(), StatusPolicy: orderingStatusPolicy,
			Journal: journalJSON{Mode: "anchored", Preload: []journalPreloadJSON{}}, StatusEvidence: g.currentEvidenceBatches(certs), Expected: expect}
		if expect.Result != nil {
			expect.Result.Parties[0].RequiredScope = scope
		}
		if edit != nil {
			edit(&v)
		}
		f.Vectors = append(f.Vectors, v)
	}
	ok := func(r *txResultJSON) txVerifyExpectJSON { return txVerifyExpectJSON{Result: r} }
	exp := func(t int64) *int64 { return &t }

	add("all_current", "trusted root, current delegations and status, covered scope", def, "data:read",
		ok(party("trusted", "current", "current", "covered", exp(defExpiry), current)), nil)
	add("trust_untrusted", "available trust configuration excludes the chain: every later dimension is not_evaluated", def, "data:read",
		ok(party("untrusted", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil)), func(v *txVerifyVector) { v.Trust = &trustJSON{Mode: "ok", Outcome: "untrusted"} })
	add("trust_ambiguous", "an ambiguous trust resolution is unavailable, never trusted", def, "data:read",
		ok(party("unavailable", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil)), func(v *txVerifyVector) { v.Trust = &trustJSON{Mode: "ok", Outcome: "ambiguous"} })
	add("trust_absent", "no trust provider: unavailable", def, "data:read",
		ok(party("unavailable", "not_evaluated", "not_evaluated", "not_evaluated", nil, nil)), func(v *txVerifyVector) { v.Trust = nil })
	add("leaf_revoked", "the leaf certificate is revoked by its issuer's signed list", def, "data:read",
		ok(party("trusted", "current", "revoked", "covered", exp(defExpiry), []EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_revoked_leaf"])})),
		func(v *txVerifyVector) {
			v.StatusEvidence[g.k("intermediate").ID] = evidenceBatch(g.object(st["intermediate_revoked_leaf"]))
		})
	add("status_issuer_unconfigured", "an issuer without a caller-authenticated status key is unavailable; the other issuer's evidence is reported", def, "data:read",
		ok(party("trusted", "current", "unavailable", "covered", exp(defExpiry), []EvidenceJSON{g.evidence(st["root_current"])})),
		func(v *txVerifyVector) { delete(v.StatusKeys, g.k("intermediate").ID) })
	expired := g.chain(chainSpec{leafExpires: Now})
	add("leaf_expired", "a leaf whose expires_at equals now is expired (exclusive deadline); delegation_expires_at is the earliest expiry", expired, "data:read",
		ok(party("trusted", "expired", "current", "covered", exp(Now), current)), nil)
	future := g.chain(chainSpec{leafIssued: Now + 6, leafExpires: Now + 600})
	add("leaf_issued_in_future", "a leaf issued more than future_skew_seconds after now is invalid", future, "data:read",
		ok(party("trusted", "invalid", "current", "covered", exp(Now+600), current)), nil)
	noDelegate := g.chain(chainSpec{rootScope: []string{"data:read", "files:read"}})
	add("parent_without_identity_delegate", "the root certificate omits identity:delegate: scope_assessment delegation_not_authorized", noDelegate, "data:read",
		ok(party("trusted", "current", "current", "delegation_not_authorized", exp(defExpiry), current)), nil)
	add("scope_not_covered", "the signed required scope is outside the effective delegated scope", def, "data:write",
		ok(party("trusted", "current", "current", "not_covered", exp(defExpiry), current)), nil)
	add("configuration_invalid_now", "an evaluation time outside the timestamp domain fails before decoding with configuration_invalid", def, "data:read",
		txVerifyExpectJSON{ErrorClass: "configuration_invalid"}, func(v *txVerifyVector) { v.Now = -1 })
	add("configuration_invalid_skew", "a future skew above 300 seconds fails with configuration_invalid", def, "data:read",
		txVerifyExpectJSON{ErrorClass: "configuration_invalid"}, func(v *txVerifyVector) { v.FutureSkewSeconds = 301 })
	return f
}
