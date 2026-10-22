package ratify

import (
	"bytes"
	"fmt"
	"slices"
)

// ExpectedChallengeV2 contains verifier-authenticated issuance state. Values
// must come from the local issuer or an independently authenticated issuer.
type ExpectedChallengeV2 struct {
	Value                  []byte
	IssuedAt               int64
	ExpiresAt              int64
	VerifierNamespace      string
	ReplayEpoch            int64
	VerifierID             string
	ExpectedAgentID        string
	ExpectedAgentPublicKey *HybridPublicKey
	ExpectedReceiverID     string
	ExpectedSessionContext []byte
	ContextPolicy          *V2ContextPolicy
}

// V2PreflightResult seals the authenticated issuance, policy, and proof identity
// for one request. Its state is never exposed or mutated after construction.
type V2PreflightResult struct{ state *expectedChallengeStateV2 }

type expectedChallengeStateV2 struct {
	Value                  []byte
	IssuedAt               int64
	ExpiresAt              int64
	VerifierNamespace      string
	ReplayEpoch            int64
	VerifierID             string
	ExpectedAgentID        string
	ExpectedAgentPublicKey *HybridPublicKey
	ExpectedReceiverID     string
	ExpectedSessionContext []byte
	RequiredScope          string
	BundleHash             string
	IssuerIDs              []string
	FutureSkew             int64
	MaxAge                 int64
	ContextPolicyDigest    string
	ContextPolicy          *V2ContextPolicy
	// NoContextPolicy records an explicit generic-Protocol evaluation with no
	// configured context policy. Only the internal end-to-end verifier sets it;
	// the terminal result is then indeterminate/action_context_unverified.
	NoContextPolicy bool
}

func snapshotExpectedChallengeV2(expected *ExpectedChallengeV2, policy *V2ContextPolicy, requiredScope, bundleHash string, issuerIDs []string, maxAge, futureSkew int64) *expectedChallengeStateV2 {
	state := &expectedChallengeStateV2{
		Value: bytes.Clone(expected.Value), IssuedAt: expected.IssuedAt, ExpiresAt: expected.ExpiresAt,
		VerifierNamespace: expected.VerifierNamespace, ReplayEpoch: expected.ReplayEpoch, VerifierID: expected.VerifierID,
		ExpectedAgentID: expected.ExpectedAgentID, ExpectedReceiverID: expected.ExpectedReceiverID,
		ExpectedSessionContext: bytes.Clone(expected.ExpectedSessionContext), RequiredScope: requiredScope,
		BundleHash: bundleHash, IssuerIDs: append([]string(nil), issuerIDs...), MaxAge: maxAge, FutureSkew: futureSkew,
	}
	state.ContextPolicy = cloneV2ContextPolicy(policy)
	if policy != nil {
		state.ContextPolicyDigest = policy.digest
	} else {
		state.NoContextPolicy = true
	}
	if expected.ExpectedAgentPublicKey != nil {
		key := *expected.ExpectedAgentPublicKey
		key.Ed25519 = bytes.Clone(key.Ed25519)
		key.MLDSA65 = bytes.Clone(key.MLDSA65)
		state.ExpectedAgentPublicKey = &key
	}
	return state
}

func cloneExpectedChallengeStateV2(state *expectedChallengeStateV2) *expectedChallengeStateV2 {
	if state == nil {
		return nil
	}
	clone := *state
	clone.Value = bytes.Clone(state.Value)
	clone.ExpectedSessionContext = bytes.Clone(state.ExpectedSessionContext)
	clone.IssuerIDs = append([]string(nil), state.IssuerIDs...)
	clone.ContextPolicy = cloneV2ContextPolicy(state.ContextPolicy)
	if state.ExpectedAgentPublicKey != nil {
		key := *state.ExpectedAgentPublicKey
		key.Ed25519 = bytes.Clone(key.Ed25519)
		key.MLDSA65 = bytes.Clone(key.MLDSA65)
		clone.ExpectedAgentPublicKey = &key
	}
	return &clone
}

func matchesExpectedChallengeV2(expected *ExpectedChallengeV2, state *expectedChallengeStateV2) bool {
	if expected == nil || state == nil || !bytes.Equal(expected.Value, state.Value) ||
		expected.IssuedAt != state.IssuedAt || expected.ExpiresAt != state.ExpiresAt ||
		expected.VerifierNamespace != state.VerifierNamespace || expected.ReplayEpoch != state.ReplayEpoch ||
		expected.VerifierID != state.VerifierID || expected.ExpectedAgentID != state.ExpectedAgentID ||
		expected.ExpectedReceiverID != state.ExpectedReceiverID ||
		!bytes.Equal(expected.ExpectedSessionContext, state.ExpectedSessionContext) ||
		(expected.ContextPolicy != nil && !sameV2ContextPolicy(expected.ContextPolicy, state.ContextPolicy)) {
		return false
	}
	if (expected.ExpectedAgentPublicKey == nil) != (state.ExpectedAgentPublicKey == nil) {
		return false
	}
	return expected.ExpectedAgentPublicKey == nil || equalHybridPublicKeys(*expected.ExpectedAgentPublicKey, *state.ExpectedAgentPublicKey)
}

// PreflightProofBundleV2 binds the challenge's
// expected context to the same immutable policy used by terminal evaluation.
// Verify callers use this entry point so a missing or divergent policy value
// cannot consume the challenge before context validation.
func PreflightProofBundleV2(bundle *ProofBundleV2, expected *ExpectedChallengeV2, policy *V2ContextPolicy, requiredScope, configuredNamespace string, configuredReplayEpoch int64, nowUnix, maxAgeSeconds, futureSkewSeconds int64) (*V2PreflightResult, error) {
	return preflightProofBundleV2(bundle, expected, policy, false, nil, requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds)
}

// preflightProofBundleV2 is the ordered pre-claim pipeline. allowNoPolicy is
// used only by VerifyProofBundleV2 for a generic verifier that explicitly has
// no context policy. hook is the application's pure receiver-binding check; it
// runs only after every built-in pre-claim check has passed.
func preflightProofBundleV2(bundle *ProofBundleV2, expected *ExpectedChallengeV2, policy *V2ContextPolicy, allowNoPolicy bool, hook func(*ProofBundleV2, ExpectedChallengeV2) error, requiredScope, configuredNamespace string, configuredReplayEpoch int64, nowUnix, maxAgeSeconds, futureSkewSeconds int64) (*V2PreflightResult, error) {
	if expected == nil {
		return nil, v2Errorf(V2ErrExpectedChallengeMissing, "v2 expected challenge is unavailable")
	}
	if policy == nil && !allowNoPolicy || policy != nil && (!policy.valid || policy.digest == "" || !validPrefixedDigestV2(policy.digest)) {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 context policy is missing or invalid")
	}
	if policy == nil && expected.ContextPolicy != nil {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge context policy does not match the issued policy")
	}
	if policy != nil {
		if expected.ContextPolicy != nil && !sameV2ContextPolicy(expected.ContextPolicy, policy) {
			return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge context policy does not match the issued policy")
		}
		if policy.requireBound {
			// SPEC-v2 §6.7: an ExpectedChallenge without an expected session
			// context is accepted; the policy's own expected context is then
			// compared after claim and a mismatch is a post-claim deny.
			if expected.ExpectedSessionContext != nil && !bytes.Equal(expected.ExpectedSessionContext, policy.expectedSessionContext) {
				return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 challenge context does not match the configured context policy")
			}
		} else if expected.ExpectedSessionContext != nil {
			return nil, v2Errorf(V2ErrConfigurationInvalid, "unbound v2 context policy cannot have an expected session context")
		}
	}
	checked := *expected
	checked.ContextPolicy = policy
	if err := ValidateProofBundleV2Preflight(bundle, checked, requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds); err != nil {
		return nil, err
	}
	if hook != nil {
		if err := hook(bundle, checked); err != nil {
			return nil, v2Errorf(V2ErrReceiverBindingRejected, "v2 receiver-binding hook rejected the presentation: %w", err)
		}
	}
	bundleHash, err := BundleHashV2(bundle)
	if err != nil {
		return nil, v2Classify(V2ErrMalformed, fmt.Errorf("v2 validated bundle hash: %w", err))
	}
	issuerIDs := make([]string, 0, len(bundle.Delegations))
	seenIssuerIDs := make(map[string]struct{}, len(bundle.Delegations))
	for i := range bundle.Delegations {
		issuerID := bundle.Delegations[i].IssuerID
		if _, ok := seenIssuerIDs[issuerID]; !ok {
			seenIssuerIDs[issuerID] = struct{}{}
			issuerIDs = append(issuerIDs, issuerID)
		}
	}
	slices.Sort(issuerIDs)
	return &V2PreflightResult{state: snapshotExpectedChallengeV2(expected, policy, requiredScope, bundleHash, issuerIDs, maxAgeSeconds, futureSkewSeconds)}, nil
}

// ValidateProofBundleV2Preflight performs the pure pre-claim checks required
// before a caller may atomically consume challenge/stream state. It validates
// the requested canonical scope, then proof/challenge bindings. It performs
// no trust, status, policy, billing, or other external calls and issues no
// authorization decision.
func ValidateProofBundleV2Preflight(bundle *ProofBundleV2, expected ExpectedChallengeV2, requiredScope, configuredNamespace string, configuredReplayEpoch int64, nowUnix, maxAgeSeconds, futureSkewSeconds int64) error {
	if expected.ContextPolicy != nil {
		if !expected.ContextPolicy.valid || expected.ContextPolicy.digest == "" || !validPrefixedDigestV2(expected.ContextPolicy.digest) {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 expected context policy is invalid")
		}
		if expected.ContextPolicy.requireBound && expected.ExpectedSessionContext != nil && !bytes.Equal(expected.ExpectedSessionContext, expected.ContextPolicy.expectedSessionContext) {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 expected context does not match its policy")
		}
		if !expected.ContextPolicy.requireBound && expected.ExpectedSessionContext != nil {
			return v2Errorf(V2ErrConfigurationInvalid, "unbound v2 context policy cannot have an expected session context")
		}
	}
	if err := ValidateRequiredScopeV2(requiredScope); err != nil {
		return v2Errorf(V2ErrInvalidRequiredScope, "v2 request scope: %w", err)
	}
	if err := VerifyProofBundleV2Signatures(bundle); err != nil {
		return fmt.Errorf("v2 cryptographic preflight: %w", err)
	}
	if configuredNamespace == "" || expected.VerifierNamespace != configuredNamespace {
		return v2Errorf(V2ErrNamespaceMismatch, "v2 challenge verifier namespace mismatch")
	}
	if configuredReplayEpoch < 0 || configuredReplayEpoch > maxSafeInteger || expected.ReplayEpoch < 0 || expected.ReplayEpoch > maxSafeInteger || expected.ReplayEpoch != configuredReplayEpoch {
		return v2Errorf(V2ErrStaleReplayEpoch, "v2 challenge replay epoch is stale")
	}
	if expected.VerifierID == "" || expected.VerifierID != bundle.VerifierID || !validV2ID(expected.VerifierID) {
		return v2Errorf(V2ErrVerifierIDMismatch, "v2 challenge verifier ID mismatch")
	}
	if len(expected.Value) != 32 || !bytes.Equal(bundle.Challenge, expected.Value) || bundle.ChallengeAt != expected.IssuedAt {
		return v2Errorf(V2ErrChallengeMismatch, "v2 proof does not match authenticated challenge issuance")
	}
	if !validV2Timestamp(expected.IssuedAt) || !validV2Timestamp(expected.ExpiresAt) || expected.ExpiresAt <= expected.IssuedAt {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 authenticated challenge time bounds are invalid")
	}
	if err := validateV2FreshnessConfiguration(nowUnix, maxAgeSeconds, futureSkewSeconds); err != nil {
		return err
	}
	if !v2ChallengeTimeCurrent(nowUnix, expected.IssuedAt, expected.ExpiresAt, maxAgeSeconds, futureSkewSeconds) {
		return v2Errorf(V2ErrChallengeNotFresh, "v2 challenge is not fresh (future-dated, expired, or beyond maximum age)")
	}
	if (expected.ExpectedAgentID == "") != (expected.ExpectedAgentPublicKey == nil) {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 expected agent ID and public key must be configured together")
	}
	if expected.ExpectedAgentPublicKey != nil {
		id, err := keyIDV2(*expected.ExpectedAgentPublicKey)
		if err != nil {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 expected agent key: %w", err)
		}
		if id != expected.ExpectedAgentID || bundle.AgentID != id || !equalHybridPublicKeys(bundle.AgentPubKey, *expected.ExpectedAgentPublicKey) {
			return v2Errorf(V2ErrExpectedAgentMismatch, "v2 presentation does not match authenticated expected agent")
		}
	}
	if expected.ExpectedSessionContext != nil {
		if len(expected.ExpectedSessionContext) != 32 || bundle.SessionContext == nil || *bundle.SessionContext == nil || !bytes.Equal(*bundle.SessionContext, expected.ExpectedSessionContext) {
			return v2Errorf(V2ErrSessionContextMismatch, "v2 presentation does not match expected session context")
		}
	}
	return checkExactReceiverAudienceV2(bundle, expected.ExpectedReceiverID)
}

func equalHybridPublicKeys(a, b HybridPublicKey) bool {
	return bytes.Equal(a.Ed25519, b.Ed25519) && bytes.Equal(a.MLDSA65, b.MLDSA65)
}

func checkExactReceiverAudienceV2(bundle *ProofBundleV2, receiverID string) error {
	for i, cert := range bundle.Delegations {
		for _, constraint := range cert.Constraints {
			if constraint.Type != ConstraintReceiverAudience {
				continue
			}
			if receiverID == "" {
				return v2Errorf(V2ErrReceiverAudienceRequired, "v2 receiver audience requires an authenticated expected receiver ID")
			}
			exact, _ := constraint.Params["exact_receiver_ids"].([]any)
			domains, _ := constraint.Params["trust_domain_ids"].([]any)
			matches := false
			for _, value := range exact {
				if id, ok := value.(string); ok && id == receiverID {
					matches = true
					break
				}
			}
			// A domain audience is evaluated only after claim from authenticated
			// trust configuration. An exact mismatch cannot pre-reject that case.
			if len(domains) == 0 && !matches {
				return v2Errorf(V2ErrReceiverAudienceMismatch, "v2 receiver does not match exact-only audience at delegation %d", i)
			}
		}
	}
	return nil
}
