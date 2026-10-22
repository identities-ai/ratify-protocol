package ratify

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Protocol v2 extension constraint evaluator profiles (SPEC-v2 §5.2).
//
// A certificate may carry a constraint whose type is outside the closed v2
// registry. Without configuration it fails closed as constraint_unknown. A
// verifier may register, in caller-authenticated configuration, an evaluator
// profile for an exact extension type. The profile is identified by a digest
// over a canonical descriptor that names the type and a versioned profile
// identifier whose semantics are published separately; the certificate and
// the proof never select a profile or code. The registry entries used by a
// chain are sealed with the challenge claim and recorded, sorted by type, in
// the signed receipt member constraint_evaluators.

const (
	// ConstraintMaxCountV2 is the type of the standard count profile.
	ConstraintMaxCountV2 ConstraintType = "com.ratifyprotocol.max_count"
	// ConstraintAllowedValuesV2 is the type of the standard exact-value profile.
	ConstraintAllowedValuesV2 ConstraintType = "com.ratifyprotocol.allowed_values"

	// ProfileMaxCountV2 and ProfileAllowedValuesV2 are the versioned profile
	// identifiers whose semantics SPEC-v2 §5.2 defines.
	ProfileMaxCountV2      = "com.ratifyprotocol.max_count/v1"
	ProfileAllowedValuesV2 = "com.ratifyprotocol.allowed_values/v1"

	// MaxConstraintEvaluatorsV2 bounds the profiles one registry may hold, and
	// therefore the entries of a receipt's constraint_evaluators member.
	MaxConstraintEvaluatorsV2 = 32
	// MaxExtensionTypeBytesV2 bounds a registrable extension type.
	MaxExtensionTypeBytesV2 = 128
	// MaxProfileIDBytesV2 bounds a versioned profile identifier.
	MaxProfileIDBytesV2 = 128
	// MaxExtensionContextEntriesV2 bounds each extension request-context map.
	MaxExtensionContextEntriesV2 = 64
	// MaxExtensionContextNameBytesV2 bounds a counter or field name.
	MaxExtensionContextNameBytesV2 = 128
	// MaxExtensionContextValueBytesV2 bounds an extension context value and
	// each allowed value of the standard exact-value profile.
	MaxExtensionContextValueBytesV2 = 512
	// MaxAllowedValuesV2 bounds the allowed array of the exact-value profile.
	MaxAllowedValuesV2 = 64
	// MaxConstraintEvaluatorTimeoutV2 bounds the configured evaluation timeout.
	MaxConstraintEvaluatorTimeoutV2 = 10 * time.Second

	constraintProfileDigestLabelV2 = "ratify-protocol-constraint-profile-v2"
)

// ConstraintProfileDescriptorV2 is the canonical object whose digest
// identifies an evaluator profile: {"profile":<id>,"type":<type>}.
type ConstraintProfileDescriptorV2 struct {
	Profile string         `json:"profile"`
	Type    ConstraintType `json:"type"`
}

// ConstraintEvaluatorRefV2 is one entry of a receipt's constraint_evaluators
// member and of a claim's sealed evaluator snapshot.
type ConstraintEvaluatorRefV2 struct {
	ProfileDigest string         `json:"profile_digest"`
	Type          ConstraintType `json:"type"`
}

// ConstraintEvaluationInputV2 is everything an evaluator may read. It is a
// copy; changing it changes nothing in the verifier. EvaluationTime is the
// authoritative claim time T_claim.
type ConstraintEvaluationInputV2 struct {
	Type            ConstraintType
	ParamsJSON      []byte // canonical params object, or nil when absent
	DelegationIndex int
	ConstraintIndex int
	IssuerID        string
	CertID          string
	Context         ConstraintContextV2
	EvaluationTime  int64
}

// ConstraintOutcomeV2 is an evaluator verdict.
type ConstraintOutcomeV2 string

const (
	ConstraintOutcomePassV2         ConstraintOutcomeV2 = "pass"
	ConstraintOutcomeDeniedV2       ConstraintOutcomeV2 = "denied"
	ConstraintOutcomeUnverifiableV2 ConstraintOutcomeV2 = "unverifiable"
)

// ConstraintEvaluationResultV2 is an evaluator's answer. ValidUntil is an
// optional exclusive horizon for a pass (0 = none); it must be later than
// EvaluationTime and contributes to the allow horizon (SPEC-v2 §6.8).
type ConstraintEvaluationResultV2 struct {
	Outcome    ConstraintOutcomeV2
	ValidUntil int64
	Detail     string
}

// ConstraintEvaluatorFuncV2 evaluates one signed extension constraint. It
// must be a pure function of its input: no I/O, no clock, no randomness.
// An error, a panic, a timeout, or an invalid result is unverifiable. The
// verifier stops waiting at the registry timeout; an implementation must
// also return once ctx is done, or its goroutine outlives the call.
type ConstraintEvaluatorFuncV2 func(ctx context.Context, in ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error)

// ConstraintEvaluatorRegistrationV2 binds one profile descriptor to its
// implementation.
type ConstraintEvaluatorRegistrationV2 struct {
	Descriptor ConstraintProfileDescriptorV2
	Evaluate   ConstraintEvaluatorFuncV2
}

type registeredConstraintEvaluatorV2 struct {
	ref      ConstraintEvaluatorRefV2
	evaluate ConstraintEvaluatorFuncV2
}

// ConstraintEvaluatorRegistryV2 is caller-authenticated verifier
// configuration. It is immutable once built; only
// NewConstraintEvaluatorRegistryV2 builds a valid one.
type ConstraintEvaluatorRegistryV2 struct {
	valid   bool
	timeout time.Duration
	entries map[ConstraintType]registeredConstraintEvaluatorV2
}

// NewConstraintEvaluatorRegistryV2 validates and freezes a registry. Every
// type must be a registrable extension type (validExtensionTypeV2) and appear
// once; every descriptor must name its registration's type and a valid
// versioned profile identifier; timeout must be positive and at most
// MaxConstraintEvaluatorTimeoutV2. A violation is configuration_invalid.
func NewConstraintEvaluatorRegistryV2(timeout time.Duration, registrations ...ConstraintEvaluatorRegistrationV2) (*ConstraintEvaluatorRegistryV2, error) {
	if timeout <= 0 || timeout > MaxConstraintEvaluatorTimeoutV2 {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 constraint evaluator timeout must be in (0, %s]", MaxConstraintEvaluatorTimeoutV2)
	}
	if len(registrations) > MaxConstraintEvaluatorsV2 {
		return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 constraint evaluator registry holds at most %d profiles", MaxConstraintEvaluatorsV2)
	}
	registry := &ConstraintEvaluatorRegistryV2{valid: true, timeout: timeout, entries: map[ConstraintType]registeredConstraintEvaluatorV2{}}
	for i, registration := range registrations {
		if registration.Evaluate == nil {
			return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 constraint evaluator %d has no implementation", i)
		}
		digest, err := ConstraintProfileDigestV2(registration.Descriptor)
		if err != nil {
			return nil, v2Classify(V2ErrConfigurationInvalid, err)
		}
		if _, exists := registry.entries[registration.Descriptor.Type]; exists {
			return nil, v2Errorf(V2ErrConfigurationInvalid, "v2 constraint type %q is registered more than once", registration.Descriptor.Type)
		}
		registry.entries[registration.Descriptor.Type] = registeredConstraintEvaluatorV2{
			ref:      ConstraintEvaluatorRefV2{Type: registration.Descriptor.Type, ProfileDigest: digest},
			evaluate: registration.Evaluate,
		}
	}
	return registry, nil
}

// Refs returns the registered {type, profile_digest} pairs sorted by type.
func (r *ConstraintEvaluatorRegistryV2) Refs() []ConstraintEvaluatorRefV2 {
	if r == nil {
		return nil
	}
	out := make([]ConstraintEvaluatorRefV2, 0, len(r.entries))
	for _, entry := range r.entries {
		out = append(out, entry.ref)
	}
	slices.SortFunc(out, func(a, b ConstraintEvaluatorRefV2) int { return strings.Compare(string(a.Type), string(b.Type)) })
	return out
}

// ConstraintProfileDigestV2 returns "sha384:" and the lowercase hexadecimal
// SHA-384(ASCII("ratify-protocol-constraint-profile-v2") || 0x00 ||
// RatifyCanonicalJSON({"profile":profile,"type":type})).
func ConstraintProfileDigestV2(d ConstraintProfileDescriptorV2) (string, error) {
	if !validExtensionTypeV2(string(d.Type)) {
		return "", fmt.Errorf("v2 constraint profile type %q is not a registrable extension type", d.Type)
	}
	if !validProfileIDV2(d.Profile) {
		return "", fmt.Errorf("v2 constraint profile identifier %q is invalid", d.Profile)
	}
	body, err := CanonicalJSON(d)
	if err != nil {
		return "", err
	}
	h := sha512.New384()
	h.Write([]byte(constraintProfileDigestLabelV2))
	h.Write([]byte{0})
	h.Write(body)
	return "sha384:" + hex.EncodeToString(h.Sum(nil)), nil
}

// validExtensionTypeV2: 3 to 128 bytes of at least three '.'-separated
// labels of [a-z0-9_-], not in the reserved ratify. namespace. Every
// registered v2 type and every reserved name fails this rule.
func validExtensionTypeV2(t string) bool {
	if len(t) == 0 || len(t) > MaxExtensionTypeBytesV2 || strings.HasPrefix(t, "ratify.") {
		return false
	}
	labels := strings.Split(t, ".")
	if len(labels) < 3 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validProfileIDV2: <name>/v<n>, at most 128 bytes, where name is
// '.'-separated labels of [a-z0-9_-] and n is a positive decimal integer
// without leading zeros.
func validProfileIDV2(id string) bool {
	if len(id) > MaxProfileIDBytesV2 {
		return false
	}
	name, version, ok := strings.Cut(id, "/v")
	if !ok || name == "" || version == "" || version[0] == '0' || strings.Contains(version, "/") {
		return false
	}
	for i := 0; i < len(version); i++ {
		if version[i] < '0' || version[i] > '9' {
			return false
		}
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// validExtensionContextNameV2: 1 to 128 bytes of [a-z0-9_.:-].
func validExtensionContextNameV2(name string) bool {
	if name == "" || len(name) > MaxExtensionContextNameBytesV2 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ':' || c == '-') {
			return false
		}
	}
	return true
}

// validateV2ExtensionContext checks the extension request context before
// claim (configuration_invalid on failure).
func validateV2ExtensionContext(c ConstraintContextV2) error {
	if len(c.ExtensionCounts) > MaxExtensionContextEntriesV2 || len(c.ExtensionValues) > MaxExtensionContextEntriesV2 {
		return v2Errorf(V2ErrConfigurationInvalid, "v2 extension request context holds at most %d counts and %d values", MaxExtensionContextEntriesV2, MaxExtensionContextEntriesV2)
	}
	for name, count := range c.ExtensionCounts {
		if !validExtensionContextNameV2(name) || count < 0 || count > maxSafeInteger {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 extension count %q must be named by 1 to %d bytes of [a-z0-9_.:-] and be 0..%d", name, MaxExtensionContextNameBytesV2, maxSafeInteger)
		}
	}
	for name, value := range c.ExtensionValues {
		if !validExtensionContextNameV2(name) || !utf8.ValidString(value) || len(value) > MaxExtensionContextValueBytesV2 {
			return v2Errorf(V2ErrConfigurationInvalid, "v2 extension value %q must be named by 1 to %d bytes of [a-z0-9_.:-] and be valid UTF-8 of at most %d bytes", name, MaxExtensionContextNameBytesV2, MaxExtensionContextValueBytesV2)
		}
	}
	return nil
}

func cloneConstraintContextV2(c ConstraintContextV2) ConstraintContextV2 {
	c.ExtensionCounts = maps.Clone(c.ExtensionCounts)
	c.ExtensionValues = maps.Clone(c.ExtensionValues)
	return c
}

// snapshotConstraintEvaluatorsV2 returns the registry entries for the
// extension types present in the chain, keyed by type, and their sorted refs.
func snapshotConstraintEvaluatorsV2(registry *ConstraintEvaluatorRegistryV2, bundle *ProofBundleV2) (map[ConstraintType]registeredConstraintEvaluatorV2, []ConstraintEvaluatorRefV2, time.Duration) {
	if registry == nil || !registry.valid || bundle == nil {
		return nil, nil, 0
	}
	used := map[ConstraintType]registeredConstraintEvaluatorV2{}
	for _, cert := range bundle.Delegations {
		for _, constraint := range cert.Constraints {
			if entry, ok := registry.entries[constraint.Type]; ok {
				used[constraint.Type] = entry
			}
		}
	}
	if len(used) == 0 {
		return nil, nil, 0
	}
	refs := make([]ConstraintEvaluatorRefV2, 0, len(used))
	for _, entry := range used {
		refs = append(refs, entry.ref)
	}
	slices.SortFunc(refs, func(a, b ConstraintEvaluatorRefV2) int { return strings.Compare(string(a.Type), string(b.Type)) })
	return used, refs, registry.timeout
}

// validConstraintEvaluatorRefsV2 checks a receipt or claim snapshot: every
// entry has a registrable type and a sha384: digest, strictly sorted by type.
func validConstraintEvaluatorRefsV2(refs []ConstraintEvaluatorRefV2) bool {
	if len(refs) > MaxConstraintEvaluatorsV2 {
		return false
	}
	for i, ref := range refs {
		if !validExtensionTypeV2(string(ref.Type)) || !validPrefixedDigestV2(ref.ProfileDigest) || i > 0 && refs[i-1].Type >= ref.Type {
			return false
		}
	}
	return true
}

func cloneConstraintEvaluatorRefsV2(refs []ConstraintEvaluatorRefV2) []ConstraintEvaluatorRefV2 {
	if len(refs) == 0 {
		return nil
	}
	return slices.Clone(refs)
}

// runConstraintEvaluatorV2 invokes one sealed evaluator under its timeout
// with panic containment and maps the answer to the constraint error model:
// nil (pass) with an optional horizon, a denial error, or an unverifiable
// error. Missing context is the evaluator's own unverifiable verdict.
func runConstraintEvaluatorV2(entry registeredConstraintEvaluatorV2, timeout time.Duration, in ConstraintEvaluationInputV2) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type answer struct {
		result ConstraintEvaluationResultV2
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		var out answer
		defer func() {
			if recovered := recover(); recovered != nil {
				out = answer{err: fmt.Errorf("evaluator panicked: %v", recovered)}
			}
			done <- out
		}()
		out.result, out.err = entry.evaluate(ctx, in)
	}()
	var got answer
	select {
	case got = <-done:
	case <-ctx.Done():
		return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator did not answer within %s", in.Type, timeout))
	}
	if got.err != nil {
		return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator failed: %v", in.Type, got.err))
	}
	switch got.result.Outcome {
	case ConstraintOutcomePassV2:
		if got.result.ValidUntil == 0 {
			return 0, nil
		}
		if got.result.ValidUntil <= in.EvaluationTime {
			return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator returned a pass horizon not after the evaluation time", in.Type))
		}
		return min(got.result.ValidUntil, V2MaxTimestampSeconds), nil
	case ConstraintOutcomeDeniedV2:
		if got.result.ValidUntil != 0 {
			return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator returned a horizon with a denial", in.Type))
		}
		return 0, fmt.Errorf("%s denied: %s", in.Type, got.result.Detail)
	case ConstraintOutcomeUnverifiableV2:
		if got.result.ValidUntil != 0 {
			return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator returned a horizon with an unverifiable result", in.Type))
		}
		return 0, errConstraintUnverifiable(fmt.Sprintf("%s unverifiable: %s", in.Type, got.result.Detail))
	default:
		return 0, errConstraintUnverifiable(fmt.Sprintf("%s evaluator returned an invalid outcome", in.Type))
	}
}

// ---------------------------------------------------------------------------
// Standard profiles (SPEC-v2 §5.2).

// StandardMaxCountEvaluatorV2 is the standard count profile
// com.ratifyprotocol.max_count/v1 for type com.ratifyprotocol.max_count.
// params is exactly {"counter":<name>,"max":<integer 0..2^53-1>}. The request
// supplies the authenticated quantity it asks for in ExtensionCounts[counter].
// Absent quantity: unverifiable. Quantity above max: denied. Params outside
// this shape can never pass: denied. Otherwise pass, with no horizon.
func StandardMaxCountEvaluatorV2() ConstraintEvaluatorRegistrationV2 {
	return ConstraintEvaluatorRegistrationV2{
		Descriptor: ConstraintProfileDescriptorV2{Profile: ProfileMaxCountV2, Type: ConstraintMaxCountV2},
		Evaluate:   evaluateMaxCountV2,
	}
}

// StandardAllowedValuesEvaluatorV2 is the standard exact-value profile
// com.ratifyprotocol.allowed_values/v1 for type
// com.ratifyprotocol.allowed_values. params is exactly
// {"allowed":[<1 to 64 unique strings of 1 to 512 bytes>],"field":<name>}.
// The request supplies the authenticated value in ExtensionValues[field].
// Absent value: unverifiable. A value byte-equal to no allowed entry: denied.
// Params outside this shape: denied. Otherwise pass, with no horizon.
func StandardAllowedValuesEvaluatorV2() ConstraintEvaluatorRegistrationV2 {
	return ConstraintEvaluatorRegistrationV2{
		Descriptor: ConstraintProfileDescriptorV2{Profile: ProfileAllowedValuesV2, Type: ConstraintAllowedValuesV2},
		Evaluate:   evaluateAllowedValuesV2,
	}
}

func evaluateMaxCountV2(_ context.Context, in ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) {
	counter, max, err := decodeMaxCountParamsV2(in.ParamsJSON)
	if err != nil {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2, Detail: err.Error()}, nil
	}
	count, ok := in.Context.ExtensionCounts[counter]
	if !ok {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeUnverifiableV2, Detail: fmt.Sprintf("no authenticated count %q in the request context", counter)}, nil
	}
	if count > max {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2, Detail: fmt.Sprintf("count %q is %d, above the signed maximum %d", counter, count, max)}, nil
	}
	return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, nil
}

func evaluateAllowedValuesV2(_ context.Context, in ConstraintEvaluationInputV2) (ConstraintEvaluationResultV2, error) {
	field, allowed, err := decodeAllowedValuesParamsV2(in.ParamsJSON)
	if err != nil {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2, Detail: err.Error()}, nil
	}
	value, ok := in.Context.ExtensionValues[field]
	if !ok {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeUnverifiableV2, Detail: fmt.Sprintf("no authenticated value %q in the request context", field)}, nil
	}
	if !slices.Contains(allowed, value) {
		return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomeDeniedV2, Detail: fmt.Sprintf("value of %q is not an allowed value", field)}, nil
	}
	return ConstraintEvaluationResultV2{Outcome: ConstraintOutcomePassV2}, nil
}

// decodeStandardParamsV2 strictly decodes a params object with exactly the
// named members, rejecting duplicates and trailing data, with numbers kept
// as their exact JSON tokens.
func decodeStandardParamsV2(data []byte, members ...string) (map[string]json.RawMessage, error) {
	if data == nil {
		return nil, fmt.Errorf("params are required")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("params are not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	root, err := decoder.Token()
	if err != nil || root != json.Delim('{') || validateUniqueJSONObjectV2(decoder) != nil {
		return nil, fmt.Errorf("params must be one JSON object without duplicate members")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("params have trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || len(fields) != len(members) {
		return nil, fmt.Errorf("params must have exactly the members %v", members)
	}
	for _, name := range members {
		if _, ok := fields[name]; !ok {
			return nil, fmt.Errorf("params must have exactly the members %v", members)
		}
	}
	return fields, nil
}

func decodeMaxCountParamsV2(data []byte) (string, int64, error) {
	fields, err := decodeStandardParamsV2(data, "counter", "max")
	if err != nil {
		return "", 0, err
	}
	counter, err := v2StringField(fields["counter"])
	if err != nil || !validExtensionContextNameV2(counter) {
		return "", 0, fmt.Errorf("counter must be 1 to %d bytes of [a-z0-9_.:-]", MaxExtensionContextNameBytesV2)
	}
	max, err := v2IntegerField(fields["max"])
	if err != nil || max < 0 {
		return "", 0, fmt.Errorf("max must be an integer in 0..%d", maxSafeInteger)
	}
	return counter, max, nil
}

func decodeAllowedValuesParamsV2(data []byte) (string, []string, error) {
	fields, err := decodeStandardParamsV2(data, "allowed", "field")
	if err != nil {
		return "", nil, err
	}
	field, err := v2StringField(fields["field"])
	if err != nil || !validExtensionContextNameV2(field) {
		return "", nil, fmt.Errorf("field must be 1 to %d bytes of [a-z0-9_.:-]", MaxExtensionContextNameBytesV2)
	}
	raw := bytes.TrimSpace(fields["allowed"])
	if len(raw) == 0 || raw[0] != '[' {
		return "", nil, fmt.Errorf("allowed must be an array of strings")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 || len(items) > MaxAllowedValuesV2 {
		return "", nil, fmt.Errorf("allowed must hold 1 to %d strings", MaxAllowedValuesV2)
	}
	allowed := make([]string, 0, len(items))
	for _, item := range items {
		value, err := v2StringField(item)
		if err != nil || value == "" || len(value) > MaxExtensionContextValueBytesV2 || slices.Contains(allowed, value) {
			return "", nil, fmt.Errorf("allowed values must be unique strings of 1 to %d bytes", MaxExtensionContextValueBytesV2)
		}
		allowed = append(allowed, value)
	}
	return field, allowed, nil
}

// extensionParamsJSONV2 returns the canonical params object of an extension
// constraint, or nil when it carries none.
func extensionParamsJSONV2(c ConstraintV2) ([]byte, error) {
	if c.Params == nil {
		return nil, nil
	}
	return CanonicalJSON(c.Params)
}
