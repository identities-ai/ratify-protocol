package ratify

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"unicode/utf8"
)

const verifySessionContextProfileV2 = "ratify.verify.session-context/v1"

var verifySessionContextFieldsV2 = []string{"verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"}

// V2ContextPolicy is validated verifier-owned context policy. Its receipt
// digest is derived from the canonical policy fields, never supplied by callers.
type V2ContextPolicy struct {
	profile                string
	requireBound           bool
	requiredFields         []string
	expectedSessionContext []byte
	digest                 string
	valid                  bool
}

// V2ContextPolicyAssessment is an intermediate ordered-stage result. A
// caller stops on any status other than "passed" before constraints or status.
type V2ContextPolicyAssessment struct {
	Assessment   string
	PolicyDigest *string
	Status       string
	Reason       string
	Detail       string
}

// NewV2ContextPolicy validates and fingerprints a policy. expectedSessionContext
// is per-invocation authenticated state and is excluded from the policy digest.
func NewV2ContextPolicy(profile string, requireBound bool, requiredFields []string, expectedSessionContext []byte) (_ *V2ContextPolicy, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrConfigurationInvalid, resultErr) }()
	if profile == "" || !utf8.ValidString(profile) {
		return nil, fmt.Errorf("v2 context policy profile must be non-empty valid UTF-8")
	}
	seen := make(map[string]struct{}, len(requiredFields))
	fields := make([]string, len(requiredFields))
	for i, field := range requiredFields {
		if field == "" || !utf8.ValidString(field) {
			return nil, fmt.Errorf("v2 context policy field %d is empty or invalid UTF-8", i)
		}
		if _, ok := seen[field]; ok {
			return nil, fmt.Errorf("v2 context policy has duplicate field %q", field)
		}
		seen[field] = struct{}{}
		fields[i] = field
	}
	if requireBound && (len(fields) == 0 || len(expectedSessionContext) != 32) {
		return nil, fmt.Errorf("bound v2 context policy requires fields and a 32-byte authenticated context")
	}
	if !requireBound && len(expectedSessionContext) != 0 {
		return nil, fmt.Errorf("unbound v2 context policy cannot carry an expected context")
	}
	if profile == verifySessionContextProfileV2 && (!requireBound || !equalStringSlicesV2(fields, verifySessionContextFieldsV2)) {
		return nil, fmt.Errorf("Ratify Verify session-context policy must require the canonical field set")
	}
	policy := v2ContextPolicyWire{Profile: profile, RequireBound: requireBound, RequiredFields: fields, Version: 1}
	encoded, err := CanonicalJSON(policy)
	if err != nil {
		return nil, fmt.Errorf("encode v2 context policy: %w", err)
	}
	sum := sha512.Sum384(encoded)
	digest := "sha384:" + hex.EncodeToString(sum[:])
	return &V2ContextPolicy{profile: profile, requireBound: requireBound, requiredFields: fields, expectedSessionContext: bytes.Clone(expectedSessionContext), digest: digest, valid: true}, nil
}

// Fields returns copies of the validated policy content: the profile, whether
// a bound context is required, the required fields in configured order, and
// the expected session context (nil when unbound). A durable issuance store
// uses them to persist the policy and to project it into the single-device
// offline complete-state digest (SPEC-v2 §7.13).
func (p *V2ContextPolicy) Fields() (profile string, requireBound bool, requiredFields []string, expectedSessionContext []byte) {
	if p == nil {
		return "", false, nil, nil
	}
	return p.profile, p.requireBound, append([]string{}, p.requiredFields...), bytes.Clone(p.expectedSessionContext)
}

type v2ContextPolicyWire struct {
	Profile        string   `json:"profile"`
	RequireBound   bool     `json:"require_bound"`
	RequiredFields []string `json:"required_fields"`
	Version        int      `json:"version"`
}

// EvaluateProofBundleV2ContextPolicy applies a validated verifier context
// policy after preflight and claim. Verify's expected-context mismatch is
// rejected earlier by ValidateProofBundleV2Preflight.
func EvaluateProofBundleV2ContextPolicy(bundle *ProofBundleV2, policy *V2ContextPolicy) V2ContextPolicyAssessment {
	if bundle == nil {
		return contextPolicyFailure("unverified", "authorization_unverified", "action_context_unverified", "proof bundle is unavailable")
	}
	if policy == nil {
		assessment := "unbound"
		if bundle.SessionContext != nil && *bundle.SessionContext != nil {
			assessment = "unverified"
		}
		return contextPolicyFailure(assessment, "authorization_unverified", "action_context_unverified", "no caller-authenticated context policy is configured")
	}
	if !policy.valid || policy.digest == "" || !validPrefixedDigestV2(policy.digest) {
		assessment := "unbound"
		if bundle.SessionContext != nil && *bundle.SessionContext != nil {
			assessment = "unverified"
		}
		return contextPolicyFailure(assessment, "authorization_unverified", "action_context_unverified", "no valid caller-authenticated context policy is configured")
	}
	digest := policy.digest
	if !policy.requireBound {
		return V2ContextPolicyAssessment{Assessment: "not_required", PolicyDigest: &digest, Status: "passed"}
	}
	if bundle.SessionContext == nil || *bundle.SessionContext == nil {
		return V2ContextPolicyAssessment{Assessment: "unverified", PolicyDigest: &digest, Status: "authorization_unverified", Reason: "action_context_unverified", Detail: "required session context is absent"}
	}
	if !bytes.Equal(*bundle.SessionContext, policy.expectedSessionContext) {
		return V2ContextPolicyAssessment{Assessment: "mismatch", PolicyDigest: &digest, Status: "constraint_denied", Reason: "constraint_denied", Detail: "proof session context does not match the verifier's authenticated context"}
	}
	return V2ContextPolicyAssessment{Assessment: "bound", PolicyDigest: &digest, Status: "passed"}
}

func contextPolicyFailure(assessment, status, reason, detail string) V2ContextPolicyAssessment {
	return V2ContextPolicyAssessment{Assessment: assessment, Status: status, Reason: reason, Detail: detail}
}

func sameV2ContextPolicy(a, b *V2ContextPolicy) bool {
	return a != nil && b != nil && a.valid && b.valid && a.profile == b.profile &&
		a.requireBound == b.requireBound && a.digest == b.digest &&
		equalStringSlicesV2(a.requiredFields, b.requiredFields) &&
		bytes.Equal(a.expectedSessionContext, b.expectedSessionContext)
}

func cloneV2ContextPolicy(policy *V2ContextPolicy) *V2ContextPolicy {
	if policy == nil {
		return nil
	}
	copy := *policy
	copy.requiredFields = append([]string(nil), policy.requiredFields...)
	copy.expectedSessionContext = bytes.Clone(policy.expectedSessionContext)
	return &copy
}
