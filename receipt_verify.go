package ratify

import (
	"fmt"
	"time"
)

// VerifyReceiptOptions controls the per-party verification work inside
// VerifyTransactionReceipt. Defaults produce a generic envelope check: each
// party's ProofBundle must fully verify, every declared party must have
// exactly one signature, and every party signature must verify against that
// party's agent_pub_key over the canonical signable. Applications add scope
// routing by setting PartyVerifyOptions.
type VerifyReceiptOptions struct {
	// Now overrides the current time. Zero value uses time.Now().
	Now time.Time

	// PartyVerifyOptions returns the VerifyOptions a party's ProofBundle is
	// checked against, keyed by party role. Callers typically configure
	// required scopes per role (e.g. "buyer" requires payments:send, "seller"
	// requires transact:sell). If nil or returns an empty VerifyOptions, the
	// party's bundle is verified with defaults (no scope requirement) at
	// VerifyReceiptOptions.Now. The option's Now field is ignored — the outer
	// Now propagates for consistency.
	PartyVerifyOptions func(role string) VerifyOptions
}

// TransactionReceiptResult is the generic envelope-verifier outcome. Valid
// iff every envelope check in SPEC §5.14 passes AND every party's ProofBundle
// produced Valid=true from Verify. ErrorReason carries the first envelope- or
// party-level failure encountered; PartyResults captures the per-party
// VerifyResult in Parties-order for callers that want audit detail.
type TransactionReceiptResult struct {
	Valid        bool
	ErrorReason  string
	PartyResults []VerifyResult
}

// VerifyTransactionReceipt runs the canonical envelope verification of
// SPEC §5.14 / TRANSACTION_RECEIPTS.md §5. The envelope is atomic: any
// single-party failure fails the whole receipt, there is no partial-valid
// state.
func VerifyTransactionReceipt(receipt *TransactionReceipt, opts VerifyReceiptOptions) TransactionReceiptResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if receipt == nil {
		return TransactionReceiptResult{ErrorReason: "receipt_nil: receipt must not be nil"}
	}
	if receipt.Version != ProtocolVersion {
		return TransactionReceiptResult{ErrorReason: fmt.Sprintf("version_mismatch: unsupported version %d", receipt.Version)}
	}
	if receipt.TransactionID == "" {
		return TransactionReceiptResult{ErrorReason: "missing_transaction_id: transaction_id must not be empty"}
	}
	if receipt.TermsSchemaURI == "" {
		return TransactionReceiptResult{ErrorReason: "missing_terms_schema_uri: terms_schema_uri must not be empty"}
	}
	if len(receipt.TermsCanonicalJSON) == 0 {
		return TransactionReceiptResult{ErrorReason: "missing_terms_canonical_json: terms_canonical_json must not be empty"}
	}
	if len(receipt.Parties) == 0 {
		return TransactionReceiptResult{ErrorReason: "no_parties: receipt must list at least one party"}
	}

	// Party IDs must be unique; collect an id→index map.
	partyIdx := make(map[string]int, len(receipt.Parties))
	for i, p := range receipt.Parties {
		if p.PartyID == "" {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("empty_party_id: party %d has no party_id", i)}
		}
		if _, dup := partyIdx[p.PartyID]; dup {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("duplicate_party_id: %q listed more than once", p.PartyID)}
		}
		partyIdx[p.PartyID] = i
	}

	// Each listed party must have exactly one signature; every signature's
	// party_id must refer to a listed party.
	sigByParty := make(map[string]int, len(receipt.PartySignatures))
	for i, s := range receipt.PartySignatures {
		if _, ok := partyIdx[s.PartyID]; !ok {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("unknown_party_signature: signature %d references unknown party_id %q", i, s.PartyID)}
		}
		if _, dup := sigByParty[s.PartyID]; dup {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("duplicate_party_signature: party %q has multiple signatures", s.PartyID)}
		}
		sigByParty[s.PartyID] = i
	}
	for _, p := range receipt.Parties {
		if _, ok := sigByParty[p.PartyID]; !ok {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("missing_party_signature: party %q has no signature", p.PartyID)}
		}
	}

	// Canonical signable — every party's signature must verify over these bytes.
	signable, err := transactionReceiptSignBytes(receipt)
	if err != nil {
		return TransactionReceiptResult{ErrorReason: fmt.Sprintf("signable_serialize: %v", err)}
	}

	partyResults := make([]VerifyResult, len(receipt.Parties))
	for i := range receipt.Parties {
		p := &receipt.Parties[i]
		// Proof bundle's agent_id / agent_pub_key MUST match the party's.
		if p.ProofBundle.AgentID != p.AgentID {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("party_agent_id_mismatch: party %q proof_bundle.agent_id=%q != party.agent_id=%q", p.PartyID, p.ProofBundle.AgentID, p.AgentID)}
		}
		if !hybridPubKeyEqual(p.ProofBundle.AgentPubKey, p.AgentPubKey) {
			return TransactionReceiptResult{ErrorReason: fmt.Sprintf("party_agent_key_mismatch: party %q proof_bundle.agent_pub_key != party.agent_pub_key", p.PartyID)}
		}
		// Bundle verification — each party's authority to commit to the terms.
		var bundleOpts VerifyOptions
		if opts.PartyVerifyOptions != nil {
			bundleOpts = opts.PartyVerifyOptions(p.Role)
		}
		bundleOpts.Now = now
		r := Verify(&p.ProofBundle, bundleOpts)
		partyResults[i] = r
		if !r.Valid {
			return TransactionReceiptResult{
				ErrorReason:  fmt.Sprintf("party_bundle_invalid: party %q status=%s reason=%s", p.PartyID, r.IdentityStatus, r.ErrorReason),
				PartyResults: partyResults,
			}
		}
		// Party signature check over the atomic signable.
		sig := receipt.PartySignatures[sigByParty[p.PartyID]].Signature
		if err := verifyBoth(signable, sig, p.AgentPubKey); err != nil {
			return TransactionReceiptResult{
				ErrorReason:  fmt.Sprintf("party_signature_invalid: party %q: %v", p.PartyID, err),
				PartyResults: partyResults,
			}
		}
	}

	return TransactionReceiptResult{Valid: true, PartyResults: partyResults}
}
