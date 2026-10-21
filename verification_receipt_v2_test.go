package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validVerificationReceiptV2Test(t *testing.T) (*VerificationReceiptV2, HybridPrivateKey, HybridPublicKey) {
	t.Helper()
	pub, priv := rotationTestKey(t, 151)
	verifierID, err := keyIDV2(pub)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, _ := rotationTestKey(t, 152)
	issuerID, err := keyIDV2(issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	statusPub, _ := rotationTestKey(t, 154)
	statusKeyID, err := keyIDV2(statusPub)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest := "sha384:" + strings.Repeat("c", 96)
	return &VerificationReceiptV2{
		Version: 2, LogID: "0123456789abcdef0123456789abcdef", Sequence: 1,
		VerifierID: verifierID, AgentID: strings.Repeat("a", 64),
		BundleHash: "sha384:" + strings.Repeat("b", 96), IssuerIDs: []string{issuerID},
		Decision: "allow", DecisionReason: "authorized", IdentityStatus: "authorized_agent",
		TrustAssessment: "trusted", StatusAssessment: "current", ChallengeAssessment: "current",
		ContextAssessment: "bound", ContextPolicyDigest: &contextDigest, VerifiedAt: 1800000000,
		RequiredScope: "execute:tool", GrantedScope: []string{"execute:tool"},
		StatusEvidence: []StatusEvidenceEntryV2{{IssuerID: issuerID, StatusKeyID: statusKeyID, Sequence: 1,
			ObjectType: 3, Digest: "sha384:" + strings.Repeat("d", 96)}},
		PreviousReceiptHash: make([]byte, 48),
	}, priv, pub
}

func TestVerificationReceiptV2AcceptsPostStatusLocalDenials(t *testing.T) {
	for _, reason := range []string{"scope_denied", "constraint_unknown"} {
		t.Run(reason, func(t *testing.T) {
			receipt, _, _ := validVerificationReceiptV2Test(t)
			receipt.Decision = "deny"
			receipt.DecisionReason = reason
			receipt.IdentityStatus = reason
			receipt.GrantedScope = []string{}
			if err := validateVerificationReceiptV2(receipt, false); err != nil {
				t.Fatalf("valid post-status local denial cannot be signed: %v", err)
			}
			receipt.StatusAssessment = "not_evaluated"
			receipt.StatusEvidence = []StatusEvidenceEntryV2{}
			if err := validateVerificationReceiptV2(receipt, false); err == nil {
				t.Fatal("post-status local denial omitted mandatory full status assessment")
			}
		})
	}
}

func TestVerificationReceiptV2StatusPrecedenceRetainsPendingContext(t *testing.T) {
	tests := []struct {
		name, decision, reason, identity, status, context string
	}{
		{"revoked over mismatch", "deny", "delegation_revoked", "revoked", "revoked", "mismatch"},
		{"unavailable over mismatch", "indeterminate", "status_unavailable", "authorization_unverified", "unavailable", "mismatch"},
		{"stale over unverified", "indeterminate", "status_stale", "authorization_unverified", "stale", "unverified"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt, _, _ := validVerificationReceiptV2Test(t)
			receipt.Decision, receipt.DecisionReason, receipt.IdentityStatus = test.decision, test.reason, test.identity
			receipt.StatusAssessment, receipt.ContextAssessment = test.status, test.context
			receipt.GrantedScope = []string{}
			if err := validateVerificationReceiptV2(receipt, false); err != nil {
				t.Fatalf("status precedence discarded an already-completed context result: %v", err)
			}
		})
	}
}

func TestVerificationReceiptV2SignWireAndAuthenticatedLog(t *testing.T) {
	first, priv, pub := validVerificationReceiptV2Test(t)
	signedFirst, err := SignVerificationReceiptV2(first, priv)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeVerificationReceiptV2(signedFirst)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeVerificationReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeVerificationReceiptV2(decoded)
	if err != nil || !bytes.Equal(wire, reencoded) {
		t.Fatal("receipt wire encoding is not canonical and stable")
	}
	head := ReceiptV2Head{LogID: first.LogID, VerifierID: first.VerifierID, HeadHash: make([]byte, 48)}
	if result, err := VerifyVerificationReceiptV2(decoded, pub, head); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("valid genesis receipt rejected: result=%v err=%v", result, err)
	}
	tampered := *decoded
	tampered.VerifiedAt++
	if _, err := VerifyVerificationReceiptV2(&tampered, pub, head); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("modified receipt body did not fail signature verification: %v", err)
	}
	badMLDSA := *decoded
	badMLDSA.Signature.MLDSA65 = bytes.Clone(decoded.Signature.MLDSA65)
	badMLDSA.Signature.MLDSA65[0] ^= 1
	if _, err := VerifyVerificationReceiptV2(&badMLDSA, pub, head); err == nil || !strings.Contains(err.Error(), "ML-DSA-65 v2 signature invalid") {
		t.Fatalf("receipt with valid Ed25519 and invalid ML-DSA signature was accepted: %v", err)
	}
	digestOne, err := VerificationReceiptV2Digest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	second := *decoded
	second.Sequence = 2
	second.VerifiedAt++
	second.PreviousReceiptHash = digestOne
	signedSecond, err := SignVerificationReceiptV2(&second, priv)
	if err != nil {
		t.Fatal(err)
	}
	digestTwo, err := VerificationReceiptV2Digest(signedSecond)
	if err != nil {
		t.Fatal(err)
	}
	firstHead := ReceiptV2Head{LogID: first.LogID, VerifierID: first.VerifierID, Sequence: 1, HeadHash: digestOne,
		AcceptedDigests: map[int64][]byte{1: digestOne}}
	if result, err := VerifyVerificationReceiptV2(signedSecond, pub, firstHead); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("valid linked second receipt rejected: result=%v err=%v", result, err)
	}
	rotatedPub, rotatedPriv := rotationTestKey(t, 155)
	rotatedID, err := keyIDV2(rotatedPub)
	if err != nil {
		t.Fatal(err)
	}
	rotated := second
	rotated.VerifierID = rotatedID
	signedRotated, err := SignVerificationReceiptV2(&rotated, rotatedPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerificationReceiptV2(signedRotated, rotatedPub, firstHead); err == nil || !strings.Contains(err.Error(), "verifier identity") {
		t.Fatalf("receipt log accepted an unannounced verifier-key change: %v", err)
	}
	resignedSecond, err := SignVerificationReceiptV2(&second, priv)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(resignedSecond.Signature.MLDSA65, signedSecond.Signature.MLDSA65) {
		t.Fatal("test signer did not produce an independently signed ML-DSA body")
	}
	resignedHead := ReceiptV2Head{LogID: first.LogID, VerifierID: first.VerifierID, Sequence: 2, HeadHash: digestTwo,
		AcceptedDigests: map[int64][]byte{1: digestOne, 2: digestTwo}}
	if result, err := VerifyVerificationReceiptV2(resignedSecond, pub, resignedHead); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("same-body receipt with a fresh randomized signature was not a replay: result=%v err=%v", result, err)
	}
	secondHead := ReceiptV2Head{LogID: first.LogID, VerifierID: first.VerifierID, Sequence: 2, HeadHash: digestTwo,
		AcceptedDigests: map[int64][]byte{1: digestOne, 2: digestTwo}}
	if result, err := VerifyVerificationReceiptV2(signedSecond, pub, secondHead); err != nil || result != WitnessEntryV2Replay {
		t.Fatalf("exact receipt replay was not idempotent: result=%v err=%v", result, err)
	}
	fork := *signedSecond
	fork.VerifiedAt++
	signedFork, err := SignVerificationReceiptV2(&fork, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerificationReceiptV2(signedFork, pub, secondHead); !errors.Is(err, ErrWitnessLogFork) {
		t.Fatalf("different valid receipt at accepted sequence was not a fork: %v", err)
	}
	orphan := *signedSecond
	orphan.PreviousReceiptHash = bytes.Repeat([]byte{1}, 48)
	signedOrphan, err := SignVerificationReceiptV2(&orphan, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerificationReceiptV2(signedOrphan, pub, firstHead); !errors.Is(err, ErrWitnessLogOrphan) {
		t.Fatalf("receipt with a wrong previous hash was not an orphan: %v", err)
	}
	gap := *signedSecond
	gap.Sequence = 3
	gap.VerifiedAt++
	gap.PreviousReceiptHash = digestTwo
	signedGap, err := SignVerificationReceiptV2(&gap, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerificationReceiptV2(signedGap, pub, firstHead); !errors.Is(err, ErrWitnessLogGap) {
		t.Fatalf("receipt sequence gap was not rejected: %v", err)
	}
	frozenHead := firstHead
	frozenHead.Frozen = true
	if _, err := VerifyVerificationReceiptV2(signedSecond, pub, frozenHead); !errors.Is(err, ErrWitnessLogFrozen) {
		t.Fatalf("frozen receipt log accepted an append: %v", err)
	}
	badHead := firstHead
	badHead.AcceptedDigests = map[int64][]byte{}
	if _, err := VerifyVerificationReceiptV2(signedSecond, pub, badHead); err == nil || !strings.Contains(err.Error(), "missing accepted sequence digests") {
		t.Fatalf("receipt verifier did not reject incomplete authenticated head history: %v", err)
	}
	wrongPub, _ := rotationTestKey(t, 153)
	if _, err := VerifyVerificationReceiptV2(decoded, wrongPub, head); err == nil || !strings.Contains(err.Error(), "does not match caller-authenticated key") {
		t.Fatalf("receipt with a different caller key did not fail at key pinning: %v", err)
	}
}

func TestVerificationReceiptV2RejectsMalformedWireAndDecisionTuples(t *testing.T) {
	receipt, priv, _ := validVerificationReceiptV2Test(t)
	signed, err := SignVerificationReceiptV2(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeVerificationReceiptV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatal(err)
	}
	validWire, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeVerificationReceiptV2(validWire); err != nil {
		t.Fatalf("valid control receipt failed to decode: %v", err)
	}
	for name, test := range map[string]struct {
		mutate func(map[string]json.RawMessage)
		cause  string
	}{
		"unknown field":                             {func(m map[string]json.RawMessage) { m["extra"] = json.RawMessage(`true`) }, "unknown field"},
		"wildcard required scope":                   {func(m map[string]json.RawMessage) { m["required_scope"] = json.RawMessage(`"meeting:*"`) }, "required scope must be one non-empty canonical scope"},
		"bundle hash must be hex digest not base64": {func(m map[string]json.RawMessage) { m["bundle_hash"] = json.RawMessage(`"YWJj"`) }, "bundle hash"},
		"missing required field":                    {func(m map[string]json.RawMessage) { delete(m, "decision_reason") }, "required field"},
		"empty optional human ID":                   {func(m map[string]json.RawMessage) { m["human_id"] = json.RawMessage(`""`) }, "not canonical ratify json"},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				candidate[key] = bytes.Clone(value)
			}
			test.mutate(candidate)
			bad, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeVerificationReceiptV2(bad); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.cause) {
				t.Fatalf("malformed receipt did not fail for %q: %v", test.cause, err)
			}
		})
	}

	invalid := []struct {
		name   string
		cause  string
		change func(*VerificationReceiptV2)
	}{
		{"allow without current status", "allow receipt violates", func(r *VerificationReceiptV2) { r.StatusAssessment = "stale" }},
		{"allow with empty grant", "allow receipt violates", func(r *VerificationReceiptV2) { r.GrantedScope = []string{} }},
		{"allow without evidence", "evaluated status requires authenticated evidence", func(r *VerificationReceiptV2) { r.StatusEvidence = []StatusEvidenceEntryV2{} }},
		{"allow with unknown identity status", "allow receipt violates", func(r *VerificationReceiptV2) { r.IdentityStatus = "authorized" }},
		{"wrong genesis hash", "previous_receipt_hash is inconsistent", func(r *VerificationReceiptV2) { r.PreviousReceiptHash[0] = 1 }},
		{"delegated decision has empty issuer list", "a receipt for a delegated decision must identify its certificate issuers", func(r *VerificationReceiptV2) { r.IssuerIDs = []string{} }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			candidate := *receipt
			candidate.IssuerIDs = append([]string(nil), receipt.IssuerIDs...)
			candidate.GrantedScope = append([]string(nil), receipt.GrantedScope...)
			candidate.StatusEvidence = append([]StatusEvidenceEntryV2(nil), receipt.StatusEvidence...)
			candidate.PreviousReceiptHash = bytes.Clone(receipt.PreviousReceiptHash)
			test.change(&candidate)
			if _, err := SignVerificationReceiptV2(&candidate, priv); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.cause) {
				t.Fatalf("invalid decision tuple did not fail for %q: %v", test.cause, err)
			}
		})
	}

	validTuples := []struct {
		name   string
		change func(*VerificationReceiptV2)
	}{
		{"not delegated before trust", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "not_delegated", "delegation_not_authorized"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.IssuerIDs, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
			r.GrantedScope = []string{}
		}},
		{"interrupted empty chain before trust", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.IssuerIDs, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
			r.GrantedScope = []string{}
		}},
		{"unauthorized root", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "unauthorized", "unauthorized"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "untrusted", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.StatusEvidence = nil, []StatusEvidenceEntryV2{}
			r.GrantedScope = []string{}
		}},
		{"revoked after context check", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "delegation_revoked", "revoked"
			r.StatusAssessment = "revoked"
			r.GrantedScope = []string{}
		}},
		{"nonempty chain without delegation authority", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "delegation_not_authorized", "delegation_not_authorized"
			r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.StatusEvidence, r.GrantedScope = nil, []StatusEvidenceEntryV2{}, []string{}
		}},
		{"context mismatch after current status", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "constraint_denied", "constraint_denied"
			r.ContextAssessment = "mismatch"
			r.GrantedScope = []string{}
		}},
		{"rate denial after current status", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "constraint_denied", "constraint_denied"
			r.GrantedScope = []string{}
		}},
		{"scope denial precedes completed context mismatch", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "scope_denied", "scope_denied"
			r.ContextAssessment = "mismatch"
			r.GrantedScope = []string{}
		}},
		{"scope denial precedes unverifiable context", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "scope_denied", "scope_denied"
			r.ContextAssessment = "unverified"
			r.GrantedScope = []string{}
		}},
		{"status stale with accepted snapshot", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "status_stale", "authorization_unverified"
			r.StatusAssessment, r.GrantedScope = "stale", []string{}
		}},
		{"current status with contiguous accepted push", func(r *VerificationReceiptV2) {
			push := r.StatusEvidence[0]
			push.Sequence, push.ObjectType = 2, 5
			r.StatusEvidence = append(r.StatusEvidence, push)
		}},
		{"untrusted source unavailable", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "trust_unavailable", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "unavailable", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"status stale after context", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "status_stale", "authorization_unverified"
			r.StatusAssessment, r.GrantedScope = "stale", []string{}
		}},
		{"action context has no configured policy", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "action_context_unverified", "authorization_unverified"
			r.ContextAssessment, r.ContextPolicyDigest = "unverified", nil
			r.GrantedScope = []string{}
		}},
		{"interrupted before trust", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"interrupted during trust lookup", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "unavailable", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"custom effective scope", func(r *VerificationReceiptV2) {
			r.GrantedScope = []string{"custom:acme:inventory:read", "execute:tool"}
		}},
		{"interrupted after context before status", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "trusted", "not_evaluated", "bound"
			r.GrantedScope, r.StatusEvidence = []string{}, []StatusEvidenceEntryV2{}
		}},
		{"interrupted during status lookup", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "trusted", "unavailable", "bound"
			r.GrantedScope, r.StatusEvidence = []string{}, []StatusEvidenceEntryV2{}
		}},
	}
	for _, test := range validTuples {
		t.Run("valid "+test.name, func(t *testing.T) {
			candidate := cloneVerificationReceiptV2(receipt)
			test.change(candidate)
			if err := validateVerificationReceiptV2(candidate, false); err != nil {
				t.Fatalf("valid table tuple rejected: %v", err)
			}
		})
	}
	invalidTuples := []struct {
		name   string
		cause  string
		change func(*VerificationReceiptV2)
	}{
		{"unbound context carries digest", "context_policy_digest", func(r *VerificationReceiptV2) { r.ContextAssessment = "unbound" }},
		{"not delegated cannot name issuers", "not_delegated receipt cannot contain certificate issuers", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "not_delegated", "delegation_not_authorized"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.StatusEvidence, r.GrantedScope = nil, []StatusEvidenceEntryV2{}, []string{}
		}},
		{"human ID invalid UTF-8", "human_id must be a valid utf-8 string", func(r *VerificationReceiptV2) { r.HumanID = string([]byte{0xff}) }},
		{"constraint denial after stale status", "post-status local policy denial requires current status", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus, r.StatusAssessment = "deny", "constraint_denied", "constraint_denied", "stale"
			r.GrantedScope = []string{}
		}},
		{"action context failure before status", "action_context_unverified assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "action_context_unverified", "authorization_unverified"
			r.ContextAssessment, r.StatusAssessment = "unverified", "not_evaluated"
			r.GrantedScope, r.StatusEvidence = []string{}, []StatusEvidenceEntryV2{}
		}},
		{"not evaluated status carries evidence", "status evidence cannot be present", func(r *VerificationReceiptV2) { r.StatusAssessment = "not_evaluated" }},
		{"interrupted status before context", "evaluation_interrupted assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus, r.StatusAssessment, r.ContextAssessment = "indeterminate", "evaluation_interrupted", "authorization_unverified", "unavailable", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope = nil, []string{}
		}},
		{"interrupted after context mismatch", "evaluation_interrupted assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus, r.ContextAssessment = "indeterminate", "evaluation_interrupted", "authorization_unverified", "mismatch"
			r.GrantedScope = []string{}
		}},
		{"allow missing full list for issuer", "current or stale status requires", func(r *VerificationReceiptV2) { r.StatusEvidence[0].ObjectType = 5 }},
		{"allow missing full list for one issuer", "current or stale status requires", func(r *VerificationReceiptV2) {
			secondIssuer := strings.Repeat("0", 64)
			r.IssuerIDs = append([]string{secondIssuer}, r.IssuerIDs...)
		}},
		{"allow has status push gap", "current or stale status requires", func(r *VerificationReceiptV2) {
			push := r.StatusEvidence[0]
			push.Sequence, push.ObjectType = 3, 5
			r.StatusEvidence = append(r.StatusEvidence, push)
		}},
		{"allow has second snapshot base", "current or stale status requires", func(r *VerificationReceiptV2) {
			base := r.StatusEvidence[0]
			base.Sequence = 2
			r.StatusEvidence = append(r.StatusEvidence, base)
		}},
		{"allow has conflicting snapshot base at same sequence", "current or stale status requires", func(r *VerificationReceiptV2) {
			base := r.StatusEvidence[0]
			base.Digest = "sha384:" + strings.Repeat("f", 96)
			r.StatusEvidence = append(r.StatusEvidence, base)
		}},
		{"allow has a second status key for issuer", "current or stale status requires", func(r *VerificationReceiptV2) {
			push := r.StatusEvidence[0]
			push.StatusKeyID, push.Sequence, push.ObjectType = strings.Repeat("f", 64), 2, 5
			r.StatusEvidence = append(r.StatusEvidence, push)
		}},
		{"allow has duplicate push sequence", "current or stale status requires", func(r *VerificationReceiptV2) {
			push := r.StatusEvidence[0]
			push.Sequence, push.ObjectType = 2, 5
			secondPush := push
			secondPush.Digest = "sha384:" + strings.Repeat("f", 96)
			r.StatusEvidence = append(r.StatusEvidence, push, secondPush)
		}},
		{"allow has push at base sequence", "current or stale status requires", func(r *VerificationReceiptV2) {
			push := r.StatusEvidence[0]
			push.ObjectType = 5
			r.StatusEvidence = append(r.StatusEvidence, push)
		}},
		{"allow has push below base sequence", "current or stale status requires", func(r *VerificationReceiptV2) {
			base := r.StatusEvidence[0]
			base.Sequence = 2
			push := base
			push.Sequence, push.ObjectType = 1, 5
			r.StatusEvidence = []StatusEvidenceEntryV2{push, base}
		}},
		{"status key equals issuer key", "status evidence is invalid", func(r *VerificationReceiptV2) { r.StatusEvidence[0].StatusKeyID = r.StatusEvidence[0].IssuerID }},
		{"status key equals verifier key", "status evidence is invalid", func(r *VerificationReceiptV2) { r.StatusEvidence[0].StatusKeyID = r.VerifierID }},
		{"status key equals agent key", "status evidence is invalid", func(r *VerificationReceiptV2) { r.StatusEvidence[0].StatusKeyID = r.AgentID }},
		{"status key equals another issuer key", "status evidence is invalid", func(r *VerificationReceiptV2) {
			otherIssuer := strings.Repeat("0", 64)
			r.IssuerIDs = append([]string{otherIssuer}, r.IssuerIDs...)
			r.StatusEvidence[0].StatusKeyID = otherIssuer
		}},
		{"one status key is bound to multiple issuers", "status evidence is invalid", func(r *VerificationReceiptV2) {
			otherIssuer := strings.Repeat("0", 64)
			secondEvidence := r.StatusEvidence[0]
			secondEvidence.IssuerID = otherIssuer
			r.IssuerIDs = append([]string{otherIssuer}, r.IssuerIDs...)
			r.StatusEvidence = append([]StatusEvidenceEntryV2{secondEvidence}, r.StatusEvidence...)
		}},
		{"interrupted trust lookup reports later completed dimension", "evaluation_interrupted assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "unavailable", "unavailable", "bound"
			r.GrantedScope = []string{}
		}},
		{"empty interrupted chain with unavailable trust", "interrupted empty-chain receipt cannot claim", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "unavailable", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.IssuerIDs, r.GrantedScope, r.StatusEvidence = nil, []string{}, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"empty interrupted chain with completed context", "interrupted empty-chain receipt cannot claim", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "trusted", "not_evaluated", "bound"
			r.IssuerIDs, r.GrantedScope, r.StatusEvidence = []string{}, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"empty interrupted chain with status lookup underway", "interrupted empty-chain receipt cannot claim", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "trusted", "unavailable", "bound"
			r.IssuerIDs, r.GrantedScope, r.StatusEvidence = []string{}, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"deny reason cannot use empty identity status", "deny receipt has an invalid reason/status pair", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "deny", "authorized", ""
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "trusted", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"interrupted after trust rejection", "evaluation_interrupted assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "untrusted", "not_evaluated", "not_evaluated"
			r.ContextPolicyDigest, r.GrantedScope, r.StatusEvidence = nil, []string{}, []StatusEvidenceEntryV2{}
		}},
		{"interrupted before trust completed context", "evaluation_interrupted assessment tuple", func(r *VerificationReceiptV2) {
			r.Decision, r.DecisionReason, r.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
			r.TrustAssessment, r.StatusAssessment, r.ContextAssessment = "not_evaluated", "not_evaluated", "bound"
			r.GrantedScope, r.StatusEvidence = []string{}, []StatusEvidenceEntryV2{}
		}},
	}
	for _, test := range invalidTuples {
		t.Run("invalid "+test.name, func(t *testing.T) {
			candidate := cloneVerificationReceiptV2(receipt)
			test.change(candidate)
			if err := validateVerificationReceiptV2(candidate, false); err == nil || !strings.Contains(strings.ToLower(err.Error()), test.cause) {
				t.Fatalf("invalid tuple did not fail for %q: %v", test.cause, err)
			}
		})
	}
}

func TestVerificationReceiptV2InterruptedEmptyChainRoundTripAndBinding(t *testing.T) {
	receipt, verifierPrivate, verifierPublic := validVerificationReceiptV2Test(t)
	agentPub, agentPrivate := rotationTestKey(t, 156)
	agentID, err := keyIDV2(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &ProofBundleV2{Version: 2, VerifierID: receipt.VerifierID, AgentID: agentID,
		AgentPubKey: agentPub, Delegations: []DelegationCertV2{}, Challenge: bytes.Repeat([]byte{0x31}, 32), ChallengeAt: 1800000000}
	bundle.DelegationDigest, err = delegationDigestV2(bundle.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err := presentationSignableBytesV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		t.Fatalf("valid empty-chain challenge signature was rejected: %v", err)
	}

	receipt.AgentID = agentID
	receipt.BundleHash, err = BundleHashV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	receipt.IssuerIDs, receipt.GrantedScope, receipt.StatusEvidence = []string{}, []string{}, []StatusEvidenceEntryV2{}
	receipt.Decision, receipt.DecisionReason, receipt.IdentityStatus = "indeterminate", "evaluation_interrupted", "authorization_unverified"
	receipt.TrustAssessment, receipt.StatusAssessment, receipt.ContextAssessment = "not_evaluated", "not_evaluated", "not_evaluated"
	receipt.ContextPolicyDigest = nil
	receipt.HumanID = "customer:external/α"
	signed, err := SignVerificationReceiptV2(receipt, verifierPrivate)
	if err != nil {
		t.Fatalf("empty-chain interrupted receipt could not be signed: %v", err)
	}
	wire, err := EncodeVerificationReceiptV2(signed)
	if err != nil {
		t.Fatalf("empty-chain interrupted receipt could not be encoded: %v", err)
	}
	decoded, err := DecodeVerificationReceiptV2(wire)
	if err != nil || decoded.HumanID != receipt.HumanID {
		t.Fatalf("receipt did not round trip opaque human ID: human_id=%q err=%v", decoded.HumanID, err)
	}
	if err := CheckVerificationReceiptV2BundleBinding(decoded, bundle); err != nil {
		t.Fatalf("empty-chain interrupted receipt did not bind to empty-chain bundle: %v", err)
	}
	head := ReceiptV2Head{LogID: receipt.LogID, VerifierID: receipt.VerifierID, HeadHash: make([]byte, 48)}
	if result, err := VerifyVerificationReceiptV2(decoded, verifierPublic, head); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("valid empty-chain receipt failed authenticated log verification: result=%v err=%v", result, err)
	}

	issuerPub, issuerPrivate := rotationTestKey(t, 157)
	issuerID, err := keyIDV2(issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	cert := DelegationCertV2{Version: 2, CertID: "empty-chain-binding-test", IssuerID: issuerID,
		IssuerPubKey: issuerPub, SubjectID: agentID, SubjectPubKey: agentPub,
		Scope: []string{"execute:tool"}, Constraints: []Constraint{}, IssuedAt: 10, ExpiresAt: 20}
	certBody, err := certSignableBytesV2(&cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.Signature, err = signV2Statement(v2DelegationCertificate, certBody, issuerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	nonEmpty := *bundle
	nonEmpty.Delegations = []DelegationCertV2{cert}
	nonEmpty.DelegationDigest, err = delegationDigestV2(nonEmpty.Delegations)
	if err != nil {
		t.Fatal(err)
	}
	presentation, err = presentationSignableBytesV2(&nonEmpty)
	if err != nil {
		t.Fatal(err)
	}
	nonEmpty.ChallengeSig, err = signV2Statement(v2ChallengePresentation, presentation, agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	nonEmptyReceipt := *decoded
	nonEmptyReceipt.BundleHash, err = BundleHashV2(&nonEmpty)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckVerificationReceiptV2BundleBinding(&nonEmptyReceipt, &nonEmpty); err == nil || !strings.Contains(err.Error(), "issuer_ids") {
		t.Fatalf("empty issuer list was bound to a non-empty delegation chain: %v", err)
	}
}

func cloneVerificationReceiptV2(receipt *VerificationReceiptV2) *VerificationReceiptV2 {
	candidate := *receipt
	candidate.IssuerIDs = append([]string(nil), receipt.IssuerIDs...)
	candidate.GrantedScope = append([]string(nil), receipt.GrantedScope...)
	candidate.StatusEvidence = append([]StatusEvidenceEntryV2(nil), receipt.StatusEvidence...)
	candidate.PreviousReceiptHash = bytes.Clone(receipt.PreviousReceiptHash)
	if receipt.ContextPolicyDigest != nil {
		digest := *receipt.ContextPolicyDigest
		candidate.ContextPolicyDigest = &digest
	}
	return &candidate
}

func TestVerificationReceiptV2PreparedBodyMatchesSignedReceipt(t *testing.T) {
	receipt, private, _ := validVerificationReceiptV2Test(t)
	body, err := VerificationReceiptV2Body(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeVerificationReceiptBodyV2(body)
	if err != nil || decoded.Decision != "allow" || decoded.Sequence != 0 || decoded.LogID != "" {
		t.Fatalf("valid pre-signing body was not decoded without log fields: %v", err)
	}
	signed, err := SignVerificationReceiptV2(receipt, private)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeVerificationReceiptV2(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeVerificationReceiptV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	signedBody, err := VerificationReceiptV2Body(verified)
	if err != nil || !bytes.Equal(body, signedBody) {
		t.Fatalf("signed receipt changed its committed body: %v", err)
	}
}

func TestBindVerificationReceiptBodyV2PreservesCommittedContentAndLogOrder(t *testing.T) {
	receipt, private, public := validVerificationReceiptV2Test(t)
	body, err := VerificationReceiptV2Body(receipt)
	if err != nil {
		t.Fatal(err)
	}
	head := ReceiptV2Head{LogID: receipt.LogID, VerifierID: receipt.VerifierID, HeadHash: make([]byte, 48)}
	first, err := BindVerificationReceiptBodyV2(body, head)
	if err != nil || first.Sequence != 1 || !bytes.Equal(first.PreviousReceiptHash, head.HeadHash) {
		t.Fatalf("prepared body did not bind to genesis: %+v %v", first, err)
	}
	signed, err := SignPreparedVerificationReceiptV2(body, head, private)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Sequence != first.Sequence || !bytes.Equal(signed.PreviousReceiptHash, first.PreviousReceiptHash) {
		t.Fatal("prepared signer changed the assigned log position")
	}
	if result, err := VerifyVerificationReceiptV2(signed, public, head); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("bound receipt did not verify as next append: %v %v", result, err)
	}
	if rebound, err := VerificationReceiptV2Body(signed); err != nil || !bytes.Equal(rebound, body) {
		t.Fatalf("signing changed the prepared body: %v", err)
	}
	digest, err := VerificationReceiptV2Digest(signed)
	if err != nil {
		t.Fatal(err)
	}
	head.Sequence, head.HeadHash = 1, digest
	head.AcceptedDigests = map[int64][]byte{1: bytes.Clone(digest)}
	second, err := BindVerificationReceiptBodyV2(body, head)
	if err != nil || second.Sequence != 2 || !bytes.Equal(second.PreviousReceiptHash, digest) {
		t.Fatalf("prepared body did not link to prior receipt: %+v %v", second, err)
	}
	if rebound, err := VerificationReceiptV2Body(second); err != nil || !bytes.Equal(rebound, body) {
		t.Fatalf("log binding changed the prepared body: %v", err)
	}
	signedSecond, err := SignPreparedVerificationReceiptV2(body, head, private)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := VerifyVerificationReceiptV2(signedSecond, public, head); err != nil || result != WitnessEntryV2Appended {
		t.Fatalf("second bound receipt did not verify as next append: %v %v", result, err)
	}
	badHead := head
	badHead.VerifierID = strings.Repeat("0", 64)
	if _, err := BindVerificationReceiptBodyV2(body, badHead); err == nil {
		t.Fatal("prepared body bound to a different verifier log")
	}
	badHead = head
	badHead.AcceptedDigests = nil
	if _, err := BindVerificationReceiptBodyV2(body, badHead); err == nil {
		t.Fatal("prepared body bound to a log with missing history")
	}
	badHead = head
	badHead.HeadHash = make([]byte, 48)
	if _, err := BindVerificationReceiptBodyV2(body, badHead); err == nil {
		t.Fatal("prepared body bound to a log head different from its history")
	}
	badHead = head
	badHead.Frozen = true
	if _, err := BindVerificationReceiptBodyV2(body, badHead); err == nil {
		t.Fatal("prepared body bound to a frozen log")
	}
	if _, err := SignPreparedVerificationReceiptV2(append(bytes.Clone(body), ' '), head, private); err == nil {
		t.Fatal("noncanonical prepared body was signed")
	}
}

func TestDecodeVerificationReceiptBodyV2RejectsInvalidPreparedContent(t *testing.T) {
	receipt, _, _ := validVerificationReceiptV2Test(t)
	body, err := VerificationReceiptV2Body(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, altered := range map[string][]byte{
		"unknown field":      bytes.Replace(body, []byte(`{"agent_id":`), []byte(`{"unexpected":1,"agent_id":`), 1),
		"log position":       bytes.Replace(body, []byte(`{"agent_id":`), []byte(`{"log_id":"0123456789abcdef0123456789abcdef","agent_id":`), 1),
		"duplicate decision": bytes.Replace(body, []byte(`"decision":"allow"`), []byte(`"decision":"deny","decision":"allow"`), 1),
		"wrong decision":     bytes.Replace(body, []byte(`"decision":"allow"`), []byte(`"decision":"deny"`), 1),
		"missing assessment": bytes.Replace(body, []byte(`"trust_assessment":"trusted",`), nil, 1),
		"noncanonical":       append([]byte(" "), body...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeVerificationReceiptBodyV2(altered); err == nil {
				t.Fatal("invalid pre-signing receipt body was accepted")
			}
		})
	}
}

func TestVerificationReceiptV2PreparedBodyReservesSignedEnvelope(t *testing.T) {
	receipt, private, _ := validVerificationReceiptV2Test(t)
	receipt.HumanID = strings.Repeat("x", MaxProofBundleBytes)
	if _, err := VerificationReceiptV2Body(receipt); err == nil {
		t.Fatal("outbox body would commit a receipt too large to sign and append")
	}
	lo, hi := 0, MaxProofBundleBytes
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		receipt.HumanID = strings.Repeat("x", mid)
		if _, err := VerificationReceiptV2Body(receipt); err == nil {
			lo = mid
		} else {
			hi = mid
		}
	}
	receipt.HumanID = strings.Repeat("x", lo)
	if _, err := VerificationReceiptV2Body(receipt); err != nil {
		t.Fatalf("largest admitted body was rejected: %v", err)
	}
	receipt.Sequence = maxSafeInteger
	receipt.PreviousReceiptHash[0] = 1
	signed, err := SignVerificationReceiptV2(receipt, private)
	if err != nil {
		t.Fatalf("largest admitted body could not be signed: %v", err)
	}
	if _, err := EncodeVerificationReceiptV2(signed); err != nil {
		t.Fatalf("largest admitted body could not be encoded: %v", err)
	}
	receipt.HumanID += "x"
	if _, err := VerificationReceiptV2Body(receipt); err == nil {
		t.Fatal("body one byte beyond the signed envelope limit was accepted")
	}
}

func TestStatementBodyDigestV2RequiresTypedReceiptBody(t *testing.T) {
	if _, err := StatementBodyDigestV2(0x0008, []byte(`{"statement_body":"test"}`)); err == nil {
		t.Fatal("verification receipt body digest accepted an object outside the receipt schema")
	}
	receipt, _, _ := validVerificationReceiptV2Test(t)
	body, err := CanonicalJSON(receiptV2Signable(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StatementBodyDigestV2(0x0008, body); err != nil {
		t.Fatalf("valid receipt body rejected: %v", err)
	}
}

func TestBundleHashV2AndReceiptBundleBinding(t *testing.T) {
	bundle := signedV2TestBundle(t)
	encoded, err := EncodeProofBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	h := sha512.New384()
	h.Write([]byte("ratify-protocol-bundle-v2\x00"))
	h.Write(encoded)
	expected := "sha384:" + hex.EncodeToString(h.Sum(nil))
	got, err := BundleHashV2(bundle)
	if err != nil || got != expected {
		t.Fatalf("BundleHashV2 mismatch: got %q err=%v", got, err)
	}

	receipt, _, _ := validVerificationReceiptV2Test(t)
	receipt.VerifierID = bundle.VerifierID
	receipt.AgentID = bundle.AgentID
	receipt.BundleHash = got
	receipt.IssuerIDs = []string{bundle.Delegations[0].IssuerID}
	receipt.StatusEvidence[0].IssuerID = bundle.Delegations[0].IssuerID
	receipt.StatusEvidence[0].StatusKeyID = strings.Repeat("e", 64)
	if err := CheckVerificationReceiptV2BundleBinding(receipt, bundle); err != nil {
		t.Fatalf("matching receipt and bundle were rejected: %v", err)
	}

	wrongHash := *receipt
	wrongHash.BundleHash = "sha384:" + strings.Repeat("e", 96)
	if err := CheckVerificationReceiptV2BundleBinding(&wrongHash, bundle); err == nil || !strings.Contains(err.Error(), "bundle_hash") {
		t.Fatalf("receipt bound to a different proof bundle hash did not fail at binding: %v", err)
	}
	wrongVerifier := *receipt
	wrongVerifier.VerifierID = strings.Repeat("f", 64)
	if err := CheckVerificationReceiptV2BundleBinding(&wrongVerifier, bundle); err == nil || !strings.Contains(err.Error(), "verifier or agent ID") {
		t.Fatalf("receipt with a verifier ID different from the bundle did not fail at binding: %v", err)
	}
	wrongAgent := *receipt
	wrongAgent.AgentID = strings.Repeat("f", 64)
	if err := CheckVerificationReceiptV2BundleBinding(&wrongAgent, bundle); err == nil || !strings.Contains(err.Error(), "verifier or agent ID") {
		t.Fatalf("receipt with an agent ID different from the bundle did not fail at binding: %v", err)
	}
	overlap := *receipt
	overlap.AgentID = ""
	overlap.StatusEvidence = append([]StatusEvidenceEntryV2(nil), receipt.StatusEvidence...)
	overlap.StatusEvidence[0].StatusKeyID = bundle.AgentID
	if err := CheckVerificationReceiptV2BundleBinding(&overlap, bundle); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("bundle binding failed to check status-key role separation: %v", err)
	}
	wrongIssuers := *receipt
	wrongIssuers.IssuerIDs = []string{strings.Repeat("f", 64)}
	wrongIssuers.StatusEvidence = append([]StatusEvidenceEntryV2(nil), receipt.StatusEvidence...)
	wrongIssuers.StatusEvidence[0].IssuerID = strings.Repeat("f", 64)
	wrongIssuers.StatusEvidence[0].StatusKeyID = strings.Repeat("e", 64)
	if err := CheckVerificationReceiptV2BundleBinding(&wrongIssuers, bundle); err == nil || !strings.Contains(err.Error(), "issuer_ids") {
		t.Fatalf("receipt with issuer IDs different from the proof chain did not fail at binding: %v", err)
	}
}
