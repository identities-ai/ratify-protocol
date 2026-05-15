// Cross-SDK byte-equivalence vectors (SPEC §17.5–§17.6, alpha.9).
//
// The vectors emitted here are independent of the 59 wire-format conformance
// fixtures. They lock the canonical byte representation of the alpha.7
// derived primitives (BundleHash, VerifierContextHash) and the signable
// bytes of the new HMAC- / hybrid-signed primitives (PolicyVerdict,
// VerificationReceipt) across every reference SDK. Each SDK's conformance
// test loads this file and asserts byte equality against its own output.
//
// Single source of truth — Go-generated, committed to the repo, and gated by
// make release-check (which re-runs the generator and fails on any drift).

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ratify "github.com/identities-ai/ratify-protocol"
)

// crossSDKDoc is the wire shape of the cross_sdk_vectors.json file.
type crossSDKDoc struct {
	Description string             `json:"description"`
	Vectors     []crossSDKVector   `json:"vectors"`
}

// crossSDKVector is one byte-equivalence assertion. `Kind` discriminates the
// primitive; `Input` is the kind-specific deterministic input; the expected
// output is one of `ExpectedHashHex` (32-byte SHA-256) or
// `ExpectedBytesB64` (raw canonical signable bytes).
type crossSDKVector struct {
	Kind             string                 `json:"kind"`
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Input            map[string]interface{} `json:"input"`
	ExpectedHashHex  string                 `json:"expected_hash_hex,omitempty"`
	ExpectedBytesB64 string                 `json:"expected_bytes_b64,omitempty"`
}

// generateCrossSDKVectors emits cross_sdk_vectors.json under outDir.
// This is the alpha.9 byte-equivalence corpus; every SDK loads it.
func generateCrossSDKVectors(outDir string) error {
	doc := crossSDKDoc{
		Description: "Cross-SDK byte-equivalence vectors for alpha.9 primitives. " +
			"Every reference SDK (Go, TypeScript, Python, Rust, C/C++) MUST produce " +
			"identical bytes for each vector. Generated deterministically by " +
			"cmd/ratify-testvectors; regenerate via `go run ./cmd/ratify-testvectors`.",
		Vectors: []crossSDKVector{},
	}

	// --- VerifierContextHash vectors (SPEC §17.6) ---
	doc.Vectors = append(doc.Vectors, verifierContextHashVectors()...)

	// --- BundleHash vectors (SPEC §17.5) ---
	bhVectors, err := bundleHashVectors()
	if err != nil {
		return err
	}
	doc.Vectors = append(doc.Vectors, bhVectors...)

	// --- PolicyVerdict signable-bytes vectors (SPEC §17.6) ---
	doc.Vectors = append(doc.Vectors, policyVerdictSignableVectors()...)

	// --- VerificationReceipt signable-bytes vectors (SPEC §17.5) ---
	rvVectors, err := verificationReceiptSignableVectors()
	if err != nil {
		return err
	}
	doc.Vectors = append(doc.Vectors, rvVectors...)

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(outDir, "cross_sdk_vectors.json")
	return os.WriteFile(path, data, 0o644)
}

func verifierContextHashVectors() []crossSDKVector {
	type ctxIn struct {
		HasLocation       bool    `json:"has_location"`
		HasSpeed          bool    `json:"has_speed"`
		HasAmount         bool    `json:"has_amount"`
		CurrentLat        float64 `json:"current_lat"`
		CurrentLon        float64 `json:"current_lon"`
		CurrentAltM       float64 `json:"current_alt_m"`
		CurrentSpeedMps   float64 `json:"current_speed_mps"`
		RequestedAmount   float64 `json:"requested_amount"`
		RequestedCurrency string  `json:"requested_currency"`
	}
	cases := []struct {
		name string
		desc string
		ctx  ratify.VerifierContext
	}{
		{
			name: "verifier_context_hash_empty",
			desc: "Empty VerifierContext — every Has* flag false, every numeric zero. Baseline.",
			ctx:  ratify.VerifierContext{},
		},
		{
			name: "verifier_context_hash_location_only",
			desc: "Location only (San Francisco). HasLocation=true, lat/lon set.",
			ctx: ratify.VerifierContext{
				CurrentLat: 37.0, CurrentLon: -122.0, HasLocation: true,
			},
		},
		{
			name: "verifier_context_hash_amount_only",
			desc: "Transaction context only. HasAmount=true, USD 100.50.",
			ctx: ratify.VerifierContext{
				RequestedAmount: 100.5, RequestedCurrency: "USD", HasAmount: true,
			},
		},
		{
			name: "verifier_context_hash_full",
			desc: "All three Has* flags true: London-ish location, 25 mps speed, GBP 999.99.",
			ctx: ratify.VerifierContext{
				CurrentLat: 51.5, CurrentLon: -0.1, CurrentAltM: 35, HasLocation: true,
				CurrentSpeedMps: 25, HasSpeed: true,
				RequestedAmount: 999.99, RequestedCurrency: "GBP", HasAmount: true,
			},
		},
	}
	out := make([]crossSDKVector, 0, len(cases))
	for _, c := range cases {
		h, err := ratify.VerifierContextHash(c.ctx)
		if err != nil {
			panic(fmt.Errorf("verifier_context_hash %s: %w", c.name, err))
		}
		// Serialize input as a flat dict; SDKs reconstruct their native context
		// from these fields. has_* flags drive whether the corresponding
		// numeric is meaningful (alpha.7 normalization rule, SPEC §17.6).
		in := ctxIn{
			HasLocation:       c.ctx.HasLocation,
			HasSpeed:          c.ctx.HasSpeed,
			HasAmount:         c.ctx.HasAmount,
			CurrentLat:        c.ctx.CurrentLat,
			CurrentLon:        c.ctx.CurrentLon,
			CurrentAltM:       c.ctx.CurrentAltM,
			CurrentSpeedMps:   c.ctx.CurrentSpeedMps,
			RequestedAmount:   c.ctx.RequestedAmount,
			RequestedCurrency: c.ctx.RequestedCurrency,
		}
		inMap := map[string]interface{}{}
		b, _ := json.Marshal(in)
		_ = json.Unmarshal(b, &inMap)
		out = append(out, crossSDKVector{
			Kind:            "verifier_context_hash",
			Name:            c.name,
			Description:     c.desc,
			Input:           inMap,
			ExpectedHashHex: hex.EncodeToString(h),
		})
	}
	return out
}

func bundleHashVectors() ([]crossSDKVector, error) {
	// Use a deterministic existing-fixture-style bundle so cross-SDK hashes
	// stay stable across regenerations. Reuse the same builders the rest of
	// the generator uses.
	human := newEntity("human_root", 0x01)
	agent := newEntity("agent", 0x02)
	cert := buildCert(
		"cross-sdk-bundle-hash-cert",
		human, agent,
		[]string{ratify.ScopeMeetingAttend},
		fixtureIssuedAt, fixtureExpiresAt,
	)
	challenge := deterministicChallenge("cross_sdk_bundle_hash")
	bundle := buildBundle(agent, []ratify.DelegationCert{cert}, challenge, fixtureNow)
	h, err := ratify.BundleHash(&bundle)
	if err != nil {
		return nil, fmt.Errorf("bundle_hash: %w", err)
	}
	// Serialize the bundle as canonical JSON so each SDK can deserialize it
	// and recompute the hash from the same wire bytes.
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	var bundleMap map[string]interface{}
	if err := json.Unmarshal(bundleJSON, &bundleMap); err != nil {
		return nil, err
	}
	return []crossSDKVector{
		{
			Kind:            "bundle_hash",
			Name:            "bundle_hash_minimal_depth1",
			Description:     "SHA-256 of canonical JSON of a depth-1 ProofBundle. SDKs must produce identical hash.",
			Input:           map[string]interface{}{"bundle": bundleMap},
			ExpectedHashHex: hex.EncodeToString(h),
		},
	}, nil
}

func policyVerdictSignableVectors() []crossSDKVector {
	contextHash := sha256.Sum256([]byte("cross-sdk-context"))
	cases := []struct {
		name        string
		description string
		verdictID   string
		agentID     string
		scope       string
		allow       bool
		issuedAt    int64
		validUntil  int64
	}{
		{
			name:        "policy_verdict_sign_bytes_allow",
			description: "Allow-verdict for agent A on scope meeting:attend.",
			verdictID:   "cross-sdk-verdict-allow",
			agentID:     "agent-cross-sdk-A",
			scope:       ratify.ScopeMeetingAttend,
			allow:       true,
			issuedAt:    fixtureNow,
			validUntil:  fixtureNow + 3600,
		},
		{
			name:        "policy_verdict_sign_bytes_deny",
			description: "Cached-deny verdict for agent B on scope payments:send.",
			verdictID:   "cross-sdk-verdict-deny",
			agentID:     "agent-cross-sdk-B",
			scope:       ratify.ScopePaymentsSend,
			allow:       false,
			issuedAt:    fixtureNow,
			validUntil:  fixtureNow + 60,
		},
	}
	out := make([]crossSDKVector, 0, len(cases))
	for _, c := range cases {
		// Use a fixed policy_secret so the output of issue is deterministic;
		// but the signable bytes don't depend on the secret. Build the verdict
		// by hand to avoid the secret entirely.
		v := ratify.PolicyVerdict{
			Version:     ratify.ProtocolVersion,
			VerdictID:   c.verdictID,
			AgentID:     c.agentID,
			Scope:       c.scope,
			Allow:       c.allow,
			ContextHash: contextHash[:],
			IssuedAt:    c.issuedAt,
			ValidUntil:  c.validUntil,
		}
		bytes, err := ratify.PolicyVerdictSignBytes(&v)
		if err != nil {
			panic(fmt.Errorf("policy_verdict_sign_bytes %s: %w", c.name, err))
		}
		out = append(out, crossSDKVector{
			Kind:        "policy_verdict_sign_bytes",
			Name:        c.name,
			Description: c.description,
			Input: map[string]interface{}{
				"version":           v.Version,
				"verdict_id":        v.VerdictID,
				"agent_id":          v.AgentID,
				"scope":             v.Scope,
				"allow":             v.Allow,
				"context_hash_hex":  hex.EncodeToString(v.ContextHash),
				"issued_at":         v.IssuedAt,
				"valid_until":       v.ValidUntil,
			},
			ExpectedBytesB64: base64Standard(bytes),
		})
	}
	return out
}

func verificationReceiptSignableVectors() ([]crossSDKVector, error) {
	// Build a deterministic verifier_pub: same hybrid seeds as the fixture
	// human_root, so the bytes are reproducible across runs.
	verifier := newEntity("verifier", 0x05)
	bundleHash := sha256.Sum256([]byte("cross-sdk-bundle-payload"))
	prevHash := make([]byte, 32) // genesis

	cases := []struct {
		name        string
		description string
		decision    string
		humanID     string
		agentID     string
		grantedScope []string
		errorReason string
		verifiedAt  int64
	}{
		{
			name:        "verification_receipt_sign_bytes_minimal",
			description: "Minimal receipt: decision-only, no granted scope, no human/agent IDs.",
			decision:    "authorized_agent",
			verifiedAt:  fixtureNow,
		},
		{
			name:        "verification_receipt_sign_bytes_full",
			description: "Full receipt: human_id, agent_id, granted_scope (sorted), and decision.",
			decision:    "authorized_agent",
			humanID:     "human-cross-sdk-R",
			agentID:     "agent-cross-sdk-R",
			// Out of alpha order on input — SDKs MUST sort lex.
			grantedScope: []string{ratify.ScopeMeetingSpeak, ratify.ScopeMeetingAttend},
			verifiedAt:   fixtureNow,
		},
		{
			name:        "verification_receipt_sign_bytes_failed",
			description: "Failure receipt: decision=revoked, error_reason populated.",
			decision:    "revoked",
			humanID:     "human-cross-sdk-R",
			agentID:     "agent-cross-sdk-R",
			errorReason: "delegation certificate has been revoked",
			verifiedAt:  fixtureNow + 1,
		},
	}
	out := make([]crossSDKVector, 0, len(cases))
	for _, c := range cases {
		r := ratify.VerificationReceipt{
			Version:      ratify.ProtocolVersion,
			VerifierID:   verifier.ID,
			VerifierPub:  verifier.PublicKey,
			BundleHash:   bundleHash[:],
			Decision:     c.decision,
			HumanID:      c.humanID,
			AgentID:      c.agentID,
			GrantedScope: c.grantedScope,
			ErrorReason:  c.errorReason,
			VerifiedAt:   c.verifiedAt,
			PrevHash:     prevHash,
		}
		bytes, err := ratify.VerificationReceiptSignBytes(&r)
		if err != nil {
			return nil, fmt.Errorf("verification_receipt_sign_bytes %s: %w", c.name, err)
		}
		in := map[string]interface{}{
			"version":         r.Version,
			"verifier_id":     r.VerifierID,
			"verifier_pub": map[string]string{
				"ed25519":   base64Standard(verifier.PublicKey.Ed25519),
				"ml_dsa_65": base64Standard(verifier.PublicKey.MLDSA65),
			},
			"bundle_hash_hex": hex.EncodeToString(r.BundleHash),
			"decision":        r.Decision,
			"verified_at":     r.VerifiedAt,
			"prev_hash_hex":   hex.EncodeToString(r.PrevHash),
		}
		if c.humanID != "" {
			in["human_id"] = c.humanID
		}
		if c.agentID != "" {
			in["agent_id"] = c.agentID
		}
		if len(c.grantedScope) > 0 {
			in["granted_scope"] = c.grantedScope
		}
		if c.errorReason != "" {
			in["error_reason"] = c.errorReason
		}
		out = append(out, crossSDKVector{
			Kind:             "verification_receipt_sign_bytes",
			Name:             c.name,
			Description:      c.description,
			Input:            in,
			ExpectedBytesB64: base64Standard(bytes),
		})
	}
	return out, nil
}

func base64Standard(b []byte) string {
	// Standard alphabet, with padding — matches canonical_json's []byte
	// convention used uniformly across all five reference SDKs.
	return base64.StdEncoding.EncodeToString(b)
}
