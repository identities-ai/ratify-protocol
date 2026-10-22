package v2vectors

import (
	"encoding/hex"

	ratify "github.com/identities-ai/ratify-protocol/v2"
)

type sigVector struct {
	Field            string         `json:"field"`
	ObjectTypeCode   int            `json:"object_type_code"`
	Signer           string         `json:"signer"`
	SignerKeyIDV2    string         `json:"signer_key_id_v2"`
	SignableB64      string         `json:"signable_b64"`
	SignableSHA384   string         `json:"signable_sha384_hex"`
	MessageB64       string         `json:"message_b64"`
	MLDSAContext     string         `json:"mldsa_context"`
	MLDSATrB64       string         `json:"mldsa_tr_b64"`
	MLDSAMuB64       string         `json:"mldsa_mu_b64"`
	Signature        map[string]any `json:"signature"`
	SignatureEncoded string         `json:"-"`
}

// HeadJSON is caller-authenticated log state for witness and receipt logs.
type HeadJSON struct {
	LogID           string            `json:"log_id"`
	VerifierID      string            `json:"verifier_id,omitempty"`
	Sequence        int64             `json:"sequence"`
	HeadHashB64     string            `json:"head_hash_b64"`
	AcceptedDigests map[string]string `json:"accepted_digests_b64"`
	Frozen          bool              `json:"frozen"`
}

// RotationStateJSON is caller-authenticated rotation state (SPEC-v2 §5.4).
type RotationStateJSON struct {
	AuthorityID   string   `json:"authority_id"`
	RecoveryEpoch int64    `json:"recovery_epoch"`
	Role          string   `json:"role"`
	Sequence      int64    `json:"sequence"`
	HeadHashB64   string   `json:"head_hash_b64"`
	CurrentKey    string   `json:"current_key"`
	UsedKeyIDs    []string `json:"used_key_ids"`
}

type verifyContext struct {
	BoundIssuerID string             `json:"bound_issuer_id,omitempty"`
	StatusKey     string             `json:"status_key,omitempty"`
	RotationState *RotationStateJSON `json:"rotation_state,omitempty"`
	WitnessKey    string             `json:"witness_key,omitempty"`
	VerifierKey   string             `json:"verifier_key,omitempty"`
	Head          *HeadJSON          `json:"head,omitempty"`
	Now           int64              `json:"now,omitempty"`
	FutureSkew    int64              `json:"future_skew_seconds,omitempty"`
}

type objectVector struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Description string            `json:"description"`
	WireB64     string            `json:"wire_b64"`
	Verify      verifyContext     `json:"verify"`
	Signatures  []sigVector       `json:"signatures"`
	Digests     map[string]string `json:"digests"`
}

type objectsFile struct {
	Version     int            `json:"version"`
	Description string         `json:"description"`
	Kinds       map[string]int `json:"kind_object_type_codes"`
	Objects     []objectVector `json:"objects"`
}

func (g *gen) sigVec(field string, s signed) sigVector {
	m := message(s.code, s.signable)
	tr, mu := externalMu(s.signer.Pub.MLDSA65, s.code, m)
	return sigVector{
		Field: field, ObjectTypeCode: int(s.code), Signer: s.signer.Name, SignerKeyIDV2: s.signer.ID,
		SignableB64: b64(s.signable), SignableSHA384: hex.EncodeToString(sha384(s.signable)),
		MessageB64: b64(m), MLDSAContext: string(mldsaContext(s.code)), MLDSATrB64: b64(tr), MLDSAMuB64: b64(mu),
		Signature: sigJSON(s.sig),
	}
}

func genesisHead(logID, verifierID string) *HeadJSON {
	return &HeadJSON{LogID: logID, VerifierID: verifierID, HeadHashB64: b64(make([]byte, 48)), AcceptedDigests: map[string]string{}}
}

func (g *gen) genesisRotationState(key string) *RotationStateJSON {
	return &RotationStateJSON{AuthorityID: rotationAuthority, RecoveryEpoch: 1, Role: "issuer", HeadHashB64: b64(make([]byte, 48)), CurrentKey: key, UsedKeyIDs: []string{g.k(key).ID}}
}

// constrainedLeaf pins every v2 constraint encoding used by the corpus.
func (g *gen) constrainedLeafConstraints() []ratify.ConstraintV2 {
	return []ratify.ConstraintV2{
		{Type: ratify.ConstraintMaxRate, Count: 5, WindowS: 60},
		{Type: ratify.ConstraintReceiverAudience, Params: map[string]any{"exact_receiver_ids": []any{"receiver-1"}, "trust_domain_ids": []any{"domain-a"}, "max_membership_age_seconds": 3600}},
		{Type: ratify.ConstraintResourcePath, ResourceID: "customer/123", PathPrefix: "/v1/customers/"},
		{Type: ratify.ConstraintTimeWindow, Start: "22:00", End: "06:00", TZ: "America/New_York"},
		{Type: ratify.ConstraintMaxAmount, Currency: "USD", MaxAmountMicros: 2500000},
		{Type: ratify.ConstraintGeoCircle, Params: map[string]any{"lat_microdegrees": 37774900, "lon_microdegrees": -122419400, "radius_mm": 500000}},
	}
}

// txFixture builds the two-party transaction receipt.
type txFixture struct {
	receipt    *ratify.TransactionReceiptV2
	wire       []byte
	signable   []byte
	sigs       []signed
	txContext  []byte
	partyReq   map[string][]byte
	partyCtx   map[string][]byte
	bundleHash map[string]string
}

const txTerms = `{"amount":100,"currency":"USD","item":"widget"}`

func (g *gen) txFixture() txFixture {
	f := txFixture{partyReq: map[string][]byte{}, partyCtx: map[string][]byte{}, bundleHash: map[string]string{}}
	txID, schema := "tx-0001", "https://example.com/terms/purchase/v1"
	f.txContext = func() []byte {
		pre := append([]byte("ratify/transaction-context/v2"), lp([]byte(txID))...)
		pre = append(pre, lp([]byte(schema))...)
		pre = append(pre, sha384([]byte(txTerms))...)
		return sha256Sum(pre)
	}()
	type partySpec struct {
		id, role, scope string
		agent, root     *Key
	}
	parties := []partySpec{
		{"party-a", "buyer", "transact:purchase", g.k("agent"), g.k("root")},
		{"party-b", "seller", "transact:sell", g.k("party_b_agent"), g.k("party_b_root")},
	}
	receipt := &ratify.TransactionReceiptV2{Version: 2, TransactionID: txID, CreatedAt: Now - 5, TermsSchemaURI: schema, TermsCanonicalJSON: []byte(txTerms)}
	for _, p := range parties {
		req := sha256Sum(append(append([]byte("ratify/transaction-party-request/v2"), lp(f.txContext)...), lp([]byte(p.scope))...))
		ctx := sessionContext(g.k("verifier").ID, fixtureWorkspace, p.agent.ID, "session-"+p.id, "invocation-"+p.id, req)
		cert, _, _ := g.cert(certSpec{issuer: p.root, subject: p.agent, certID: "cert-" + p.id, scope: []string{p.scope}})
		b, bwire, _ := g.bundle(bundleSpec{agent: p.agent, certs: []ratify.DelegationCertV2{cert}, session: ctx})
		f.partyReq[p.id], f.partyCtx[p.id], f.bundleHash[p.id] = req, ctx, bundleHash(bwire)
		receipt.Parties = append(receipt.Parties, ratify.TransactionReceiptPartyV2{
			PartyID: p.id, Role: p.role, AgentID: p.agent.ID, AgentPubKey: p.agent.Pub,
			VerifierID: g.k("verifier").ID, WorkspaceID: fixtureWorkspace, SessionID: "session-" + p.id,
			InvocationID: "invocation-" + p.id, RequiredScope: p.scope, ProofBundleHash: bundleHash(bwire), ProofBundle: b,
		})
	}
	f.signable = must(ratify.TransactionReceiptV2SignBytes(receipt))
	for _, p := range parties {
		sig := signDet(p.agent, codeParty, f.signable)
		receipt.PartySignatures = append(receipt.PartySignatures, ratify.TransactionReceiptSignatureV2{PartyID: p.id, Signature: sig})
		f.sigs = append(f.sigs, signed{codeParty, p.agent, f.signable, sig})
	}
	f.receipt = receipt
	f.wire = must(ratify.EncodeTransactionReceiptV2(receipt))
	return f
}

func sha256Sum(b []byte) []byte {
	h := sha256Array(b)
	return h[:]
}

// receiptFixtureBody is the allow receipt body for the default bundle.
func (g *gen) receiptFixtureBody() *ratify.VerificationReceiptV2 {
	_, bwire, _ := g.bundle(bundleSpec{agent: g.k("agent"), certs: g.chain(chainSpec{}), session: g.fixtureSessionContext(g.k("agent"))})
	st := g.statusFixtures()
	digest := policyDigest(verifyPolicy, true, verifyPolicyFields)
	return &ratify.VerificationReceiptV2{
		Version: 2, VerifierID: g.k("verifier").ID, AgentID: g.k("agent").ID, BundleHash: bundleHash(bwire),
		IssuerIDs: sortedStrings(g.k("root").ID, g.k("intermediate").ID), Decision: "allow", DecisionReason: "authorized",
		IdentityStatus: "authorized_agent", TrustAssessment: "trusted", StatusAssessment: "current", ChallengeAssessment: "current",
		ContextAssessment: "bound", ContextPolicyDigest: &digest, VerifiedAt: Now, RequiredScope: "data:read",
		GrantedScope:   []string{"data:read", "files:read"},
		StatusEvidence: toLibEvidence(sortEvidence([]EvidenceJSON{g.evidence(st["root_current"]), g.evidence(st["intermediate_current"])})),
	}
}

func (g *gen) objectsFile() any {
	f := objectsFile{
		Version:     2,
		Description: "Positive vectors for every SPEC-v2 §4 object type. For each signature: signable_b64 is the exact canonical signable projection, message_b64 is the 77-byte M, mldsa_context is the FIPS 204 context, mldsa_tr/mu are the external-mu inputs, and signature holds both deterministic components. wire_b64 is the complete canonical object. An implementation MUST decode wire_b64, re-encode it to identical bytes, derive the same signable bytes, verify every signature with the named verify context, and reproduce every digest.",
		Kinds: map[string]int{
			"delegation_certificate": 1, "proof_bundle": 2, "revocation_list": 3, "key_rotation_statement": 4,
			"revocation_push": 5, "witness_entry": 6, "transaction_receipt": 7, "verification_receipt": 8,
		},
	}
	root, inter, agent := g.k("root"), g.k("intermediate"), g.k("agent")

	_, rootWire, rootSig := g.cert(certSpec{issuer: root, subject: inter, certID: "cert-root", scope: []string{"data:read", "files:read", "identity:delegate"}})
	f.Objects = append(f.Objects, objectVector{Name: "delegation_root_to_intermediate", Kind: "delegation_certificate",
		Description: "Root delegates to an intermediate, including identity:delegate. Signed by the declared issuer key under code 0x0001.",
		WireB64:     b64(rootWire), Signatures: []sigVector{g.sigVec("signature", rootSig)}, Digests: map[string]string{"issuer_key_id_v2": root.ID, "subject_key_id_v2": inter.ID}})

	_, leafWire, leafSig := g.cert(certSpec{issuer: inter, subject: agent, certID: "cert-leaf-constrained", scope: []string{"data:read"}, constraints: g.constrainedLeafConstraints()})
	f.Objects = append(f.Objects, objectVector{Name: "delegation_with_every_v2_constraint_shape", Kind: "delegation_certificate",
		Description: "Pins canonical encodings of every v2 registry schema: max_rate, ratify.receiver_audience (exact and trust-domain members), resource_path, time_window (wrapping midnight), and max_amount (integer max_amount_micros). Also pins an unregistered type (geo_circle, not in the v2 registry) carrying only type and integer params: it decodes, and evaluation fails closed as constraint_unknown.",
		WireB64:     b64(leafWire), Signatures: []sigVector{g.sigVec("signature", leafSig)}, Digests: map[string]string{}})

	chain := g.chain(chainSpec{})
	session := g.fixtureSessionContext(agent)
	_, bwire, bsig := g.bundle(bundleSpec{agent: agent, certs: chain, session: session})
	claimDigest := sha384Prefixed("ratify-protocol-challenge-claim-v2", defaultChallenge())
	claimID := sha256Sum(append(append(append([]byte("ratify-protocol-claim-id-v2\x00"), lp([]byte(fixtureNamespace))...), uint64be(fixtureReplayEpoch)...), claimDigest...))
	f.Objects = append(f.Objects, objectVector{Name: "proof_bundle_two_link_bound_context", Kind: "proof_bundle",
		Description: "Leaf-to-root chain with a bound session_context and null stream fields. The presentation signable excludes delegations and challenge_sig; delegation_digest binds the exact signed chain.",
		WireB64:     b64(bwire), Signatures: []sigVector{g.sigVec("challenge_sig", bsig), g.sigVec("delegations[0].signature", signedCert(g, chain[0], inter)), g.sigVec("delegations[1].signature", signedCert(g, chain[1], root))},
		Digests: map[string]string{
			"delegation_digest_hex": hex.EncodeToString(delegationDigest(chain)), "bundle_hash_v2": bundleHash(bwire),
			"session_context_hex": hex.EncodeToString(session), "challenge_claim_digest_hex": hex.EncodeToString(claimDigest),
			"claim_id": hex.EncodeToString(claimID), "claim_verifier_namespace": fixtureNamespace, "claim_replay_epoch": "3",
		}})

	streamID := make([]byte, 32)
	for i := range streamID {
		streamID[i] = 0x5a
	}
	_, ewire, esig := g.bundle(bundleSpec{agent: agent, streamID: streamID, streamSeq: 1})
	f.Objects = append(f.Objects, objectVector{Name: "proof_bundle_empty_chain_stream_bound", Kind: "proof_bundle",
		Description: "Empty delegations array (verified with the bundle agent key), null session_context, and a bound stream at sequence 1.",
		WireB64:     b64(ewire), Signatures: []sigVector{g.sigVec("challenge_sig", esig)},
		Digests: map[string]string{"delegation_digest_hex": hex.EncodeToString(delegationDigest(nil)), "bundle_hash_v2": bundleHash(ewire)}})

	_, lwire, lsig := g.list(g.k("status_root"), root.ID, 7, Now-60, Now+3600, "cert-a", "cert-b")
	f.Objects = append(f.Objects, objectVector{Name: "revocation_list", Kind: "revocation_list",
		Description: "Full snapshot signed under code 0x0003 by the status key bound to the issuer by caller configuration.",
		WireB64:     b64(lwire), Verify: verifyContext{BoundIssuerID: root.ID, StatusKey: "status_root"}, Signatures: []sigVector{g.sigVec("signature", lsig)},
		Digests: map[string]string{"status_evidence_digest": statusEvidenceDigest(codeList, lwire)}})

	_, pwire, psig := g.push(g.k("status_root"), root.ID, 8, Now-30, "cert-c")
	f.Objects = append(f.Objects, objectVector{Name: "revocation_push", Kind: "revocation_push",
		Description: "Push signed under code 0x0005 by the bound status key.",
		WireB64:     b64(pwire), Verify: verifyContext{BoundIssuerID: root.ID, StatusKey: "status_root"}, Signatures: []sigVector{g.sigVec("signature", psig)},
		Digests: map[string]string{"status_evidence_digest": statusEvidenceDigest(codePush, pwire)}})

	_, rwire, rsignable, roldSig, rnewSig := g.rotation(rotationSpec{sequence: 1, oldKey: g.k("rotation_genesis"), newKey: g.k("rotation_second")})
	f.Objects = append(f.Objects, objectVector{Name: "key_rotation_genesis", Kind: "key_rotation_statement",
		Description: "Genesis rotation. The current old key signs code 0x0004 and the new key signs the identical body under code 0x0009 (proof of possession).",
		WireB64:     b64(rwire), Verify: verifyContext{RotationState: g.genesisRotationState("rotation_genesis"), Now: Now, FutureSkew: 5},
		Signatures: []sigVector{g.sigVec("old_signature", roldSig), g.sigVec("new_signature", rnewSig)},
		Digests:    map[string]string{"statement_body_digest_hex": hex.EncodeToString(statementBodyDigest(codeRotationOld, rsignable))}})

	_, wwire, wsig := g.witness(g.k("witness"), witnessLogA, 1, make([]byte, 48), "entry-1", Now-20, "", 0)
	f.Objects = append(f.Objects, objectVector{Name: "witness_entry_genesis", Kind: "witness_entry",
		Description: "Genesis witness entry; prev_hash is 48 zero bytes and witness_id is the v2 key ID of the caller-authenticated witness key.",
		WireB64:     b64(wwire), Verify: verifyContext{WitnessKey: "witness", Head: genesisHead(witnessLogA, "")}, Signatures: []sigVector{g.sigVec("signature", wsig)},
		Digests: map[string]string{"statement_body_digest_hex": hex.EncodeToString(statementBodyDigest(codeWitness, wsig.signable))}})

	tx := g.txFixture()
	txSigs := []sigVector{}
	for i, s := range tx.sigs {
		txSigs = append(txSigs, g.sigVec("party_signatures["+tx.receipt.Parties[i].PartyID+"]", s))
	}
	txDigests := map[string]string{"transaction_context_hex": hex.EncodeToString(tx.txContext)}
	for id := range tx.partyReq {
		txDigests[id+".transaction_party_request_hash_hex"] = hex.EncodeToString(tx.partyReq[id])
		txDigests[id+".session_context_hex"] = hex.EncodeToString(tx.partyCtx[id])
		txDigests[id+".proof_bundle_hash"] = tx.bundleHash[id]
	}
	f.Objects = append(f.Objects, objectVector{Name: "transaction_receipt_two_parties", Kind: "transaction_receipt",
		Description: "Two parties sign the identical signable object (parties without proof_bundle, no party_signatures) under code 0x0007. Each bundle's session_context binds the transaction context and that party's required_scope.",
		WireB64:     b64(tx.wire), Signatures: txSigs, Digests: txDigests})

	body := g.receiptFixtureBody()
	_, rcWire, rcSig := g.receipt(g.k("verifier"), body, receiptLogA, 1, make([]byte, 48), 0)
	outbox := must(ratify.VerificationReceiptV2Body(body))
	f.Objects = append(f.Objects, objectVector{Name: "verification_receipt_allow_genesis", Kind: "verification_receipt",
		Description: "Genesis allow receipt signed under code 0x0008 by the caller-authenticated verifier key. receipt_outbox_body_b64 is the sealed pre-append body (no log_id, sequence, previous_receipt_hash, or signature).",
		WireB64:     b64(rcWire), Verify: verifyContext{VerifierKey: "verifier", Head: genesisHead(receiptLogA, g.k("verifier").ID)},
		Signatures: []sigVector{g.sigVec("signature", rcSig)},
		Digests:    map[string]string{"statement_body_digest_hex": hex.EncodeToString(statementBodyDigest(codeReceipt, rcSig.signable)), "receipt_outbox_body_b64": b64(outbox)}})
	return f
}

func signedCert(g *gen, c ratify.DelegationCertV2, issuer *Key) signed {
	wire := must(ratify.EncodeDelegationCertV2(&c))
	return signed{codeDelegation, issuer, without(wire, "signature"), c.Signature}
}

func uint64be(v uint64) []byte {
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}
