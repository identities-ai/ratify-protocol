package v2vectors

// Standard extension evaluator profile semantics (SPEC-v2 §5.2). Every case
// gives the canonical params a certificate carries (or none), the
// authenticated extension request context, and the one outcome every SDK's
// standard profile implementation must return. Cases stay inside the
// restricted value model of §2.1, because params outside it are malformed
// before claim and never reach an evaluator. Context cases outside the
// request-context bounds are rejected before claim as configuration_invalid.

import (
	"encoding/json"
	"strings"
)

type profileContextJSON struct {
	ExtensionCounts map[string]int64  `json:"extension_counts,omitempty"`
	ExtensionValues map[string]string `json:"extension_values,omitempty"`
}

type profileCaseJSON struct {
	Name    string             `json:"name"`
	Params  json.RawMessage    `json:"params,omitempty"`
	Absent  bool               `json:"params_absent,omitempty"`
	Context profileContextJSON `json:"context"`
	Outcome string             `json:"outcome"`
}

type profileSuiteJSON struct {
	Profile       string            `json:"profile"`
	Type          string            `json:"type"`
	ProfileDigest string            `json:"profile_digest"`
	Cases         []profileCaseJSON `json:"cases"`
}

type contextBoundCaseJSON struct {
	Name       string             `json:"name"`
	Context    profileContextJSON `json:"context"`
	ErrorClass string             `json:"error_class,omitempty"`
}

type evaluatorProfilesFile struct {
	Version       int                    `json:"version"`
	Description   string                 `json:"description"`
	Semantics     map[string]string      `json:"semantics"`
	Profiles      []profileSuiteJSON     `json:"profiles"`
	ContextBounds []contextBoundCaseJSON `json:"context_bounds"`
}

const maxSafe = int64(1)<<53 - 1

func (g *gen) evaluatorProfilesFile() any {
	counts := func(kv ...any) profileContextJSON {
		m := map[string]int64{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = int64(kv[i+1].(int64))
		}
		return profileContextJSON{ExtensionCounts: m}
	}
	values := func(kv ...string) profileContextJSON {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return profileContextJSON{ExtensionValues: m}
	}
	mc := func(counter any, max any) map[string]any { return map[string]any{"counter": counter, "max": max} }
	c := func(name string, params any, ctx profileContextJSON, outcome string) profileCaseJSON {
		// params is always present here (JSON null included); params_absent
		// cases are written separately.
		return profileCaseJSON{Name: name, Params: canon(params), Context: ctx, Outcome: outcome}
	}
	name128 := strings.Repeat("n", 128)
	name129 := strings.Repeat("n", 129)
	nodes := counts("nodes", int64(5))

	maxCount := profileSuiteJSON{Profile: maxCountProfile, Type: maxCountType, ProfileDigest: profileDigest(maxCountProfile, maxCountType), Cases: []profileCaseJSON{
		c("below_max_passes", mc("nodes", 10), nodes, "pass"),
		c("equal_to_max_passes", mc("nodes", 5), nodes, "pass"),
		c("one_above_max_denied", mc("nodes", 4), nodes, "denied"),
		c("zero_max_zero_count_passes", mc("nodes", 0), counts("nodes", int64(0)), "pass"),
		c("zero_max_one_count_denied", mc("nodes", 0), counts("nodes", int64(1)), "denied"),
		c("largest_max_largest_count_passes", mc("nodes", maxSafe), counts("nodes", maxSafe), "pass"),
		c("largest_count_above_max_denied", mc("nodes", maxSafe-1), counts("nodes", maxSafe), "denied"),
		c("counter_absent_from_context_unverifiable", mc("nodes", 10), counts("other", int64(1)), "unverifiable"),
		c("empty_context_unverifiable", mc("nodes", 10), profileContextJSON{}, "unverifiable"),
		c("counter_only_in_values_unverifiable", mc("nodes", 10), values("nodes", "5"), "unverifiable"),
		c("counter_name_128_bytes_passes", mc(name128, 10), counts(name128, int64(10)), "pass"),
		c("counter_name_with_all_name_characters_passes", mc("a-z_0.9:x", 1), counts("a-z_0.9:x", int64(1)), "pass"),
		{Name: "params_absent_denied", Absent: true, Context: nodes, Outcome: "denied"},
		c("params_empty_object_denied", map[string]any{}, nodes, "denied"),
		c("params_array_denied", []any{"nodes", 10}, nodes, "denied"),
		c("params_string_denied", "nodes", nodes, "denied"),
		c("params_integer_denied", 10, nodes, "denied"),
		c("params_null_denied", nil, nodes, "denied"),
		c("missing_max_denied", map[string]any{"counter": "nodes"}, nodes, "denied"),
		c("missing_counter_denied", map[string]any{"max": 10}, nodes, "denied"),
		c("extra_member_denied", map[string]any{"counter": "nodes", "max": 10, "window_s": 60}, nodes, "denied"),
		c("negative_max_denied", mc("nodes", -1), nodes, "denied"),
		c("most_negative_max_denied", mc("nodes", -maxSafe), nodes, "denied"),
		c("string_max_denied", mc("nodes", "10"), nodes, "denied"),
		c("boolean_max_denied", mc("nodes", true), nodes, "denied"),
		c("null_max_denied", mc("nodes", nil), nodes, "denied"),
		c("array_max_denied", mc("nodes", []any{10}), nodes, "denied"),
		c("integer_counter_denied", mc(7, 10), counts("7", int64(1)), "denied"),
		c("null_counter_denied", mc(nil, 10), nodes, "denied"),
		c("empty_counter_denied", mc("", 10), nodes, "denied"),
		c("uppercase_counter_denied", mc("Nodes", 10), counts("nodes", int64(1)), "denied"),
		c("counter_with_space_denied", mc("node count", 10), nodes, "denied"),
		c("counter_name_129_bytes_denied", mc(name129, 10), nodes, "denied"),
		c("invalid_params_denied_before_missing_context", mc("nodes", -1), profileContextJSON{}, "denied"),
	}}

	av := func(allowed any, field any) map[string]any { return map[string]any{"allowed": allowed, "field": field} }
	region := values("region", "eu-west-1")
	regions := []any{"us-east-1", "eu-west-1"}
	sixtyFour := make([]any, 64)
	for i := range sixtyFour {
		sixtyFour[i] = "v" + strings.Repeat("x", i)
	}
	sixtyFive := append(append([]any{}, sixtyFour...), "overflow")
	value512 := strings.Repeat("a", 512)
	value513 := strings.Repeat("a", 513)
	composed, decomposed := "café", "café"
	allowed := profileSuiteJSON{Profile: allowedProfile, Type: allowedType, ProfileDigest: profileDigest(allowedProfile, allowedType), Cases: []profileCaseJSON{
		c("listed_value_passes", av(regions, "region"), region, "pass"),
		c("single_allowed_value_passes", av([]any{"eu-west-1"}, "region"), region, "pass"),
		c("unlisted_value_denied", av(regions, "region"), values("region", "ap-south-1"), "denied"),
		c("case_differs_denied", av(regions, "region"), values("region", "EU-WEST-1"), "denied"),
		c("prefix_of_allowed_denied", av(regions, "region"), values("region", "eu-west"), "denied"),
		c("allowed_value_plus_suffix_denied", av(regions, "region"), values("region", "eu-west-1a"), "denied"),
		c("empty_value_denied", av(regions, "region"), values("region", ""), "denied"),
		c("unicode_normalization_not_applied_denied", av([]any{composed}, "word"), values("word", decomposed), "denied"),
		c("unicode_exact_bytes_pass", av([]any{composed}, "word"), values("word", composed), "pass"),
		c("sixty_four_allowed_last_passes", av(sixtyFour, "v"), values("v", sixtyFour[63].(string)), "pass"),
		c("value_512_bytes_passes", av([]any{value512}, "blob"), values("blob", value512), "pass"),
		c("field_absent_from_context_unverifiable", av(regions, "region"), values("zone", "eu-west-1"), "unverifiable"),
		c("empty_context_unverifiable", av(regions, "region"), profileContextJSON{}, "unverifiable"),
		c("field_only_in_counts_unverifiable", av(regions, "region"), counts("region", int64(1)), "unverifiable"),
		{Name: "params_absent_denied", Absent: true, Context: region, Outcome: "denied"},
		c("params_empty_object_denied", map[string]any{}, region, "denied"),
		c("params_array_denied", regions, region, "denied"),
		c("params_null_denied", nil, region, "denied"),
		c("missing_allowed_denied", map[string]any{"field": "region"}, region, "denied"),
		c("missing_field_denied", map[string]any{"allowed": regions}, region, "denied"),
		c("extra_member_denied", map[string]any{"allowed": regions, "field": "region", "mode": "exact"}, region, "denied"),
		c("empty_allowed_denied", av([]any{}, "region"), region, "denied"),
		c("sixty_five_allowed_denied", av(sixtyFive, "v"), values("v", "v"), "denied"),
		c("duplicate_allowed_denied", av([]any{"eu-west-1", "eu-west-1"}, "region"), region, "denied"),
		c("empty_allowed_entry_denied", av([]any{"eu-west-1", ""}, "region"), region, "denied"),
		c("allowed_entry_513_bytes_denied", av([]any{value513}, "blob"), values("blob", value512), "denied"),
		c("integer_allowed_entry_denied", av([]any{"eu-west-1", 7}, "region"), region, "denied"),
		c("null_allowed_entry_denied", av([]any{"eu-west-1", nil}, "region"), region, "denied"),
		c("nested_array_allowed_entry_denied", av([]any{[]any{"eu-west-1"}}, "region"), region, "denied"),
		c("allowed_string_denied", av("eu-west-1", "region"), region, "denied"),
		c("allowed_object_denied", av(map[string]any{"eu-west-1": true}, "region"), region, "denied"),
		c("integer_field_denied", av(regions, 1), region, "denied"),
		c("empty_field_denied", av(regions, ""), region, "denied"),
		c("uppercase_field_denied", av(regions, "Region"), region, "denied"),
		c("field_name_129_bytes_denied", av(regions, name129), region, "denied"),
		c("invalid_params_denied_before_missing_context", av([]any{}, "region"), profileContextJSON{}, "denied"),
	}}

	manyCounts := map[string]int64{}
	manyValues := map[string]string{}
	for i := 0; i < 65; i++ {
		name := "k" + strings.Repeat("x", i)
		manyCounts[name], manyValues[name] = 1, "v"
	}
	sixtyFourCounts := map[string]int64{}
	for i := 0; i < 64; i++ {
		sixtyFourCounts["k"+strings.Repeat("x", i)] = 1
	}
	bound := func(name string, ctx profileContextJSON, errorClass string) contextBoundCaseJSON {
		return contextBoundCaseJSON{Name: name, Context: ctx, ErrorClass: errorClass}
	}
	return evaluatorProfilesFile{
		Version:     1,
		Description: "Exhaustive semantics of the two standard extension evaluator profiles (SPEC-v2 §5.2): com.ratifyprotocol.max_count/v1 and com.ratifyprotocol.allowed_values/v1. An SDK that claims either profile MUST return the listed outcome for every case. profile_digest is a profile identifier digest computed from the specification formula; matching it says which identifier was bound, not that two implementations behave alike. These cases are that evidence.",
		Semantics: map[string]string{
			"case":           "invoke the profile's standard implementation with params (the canonical RatifyCanonicalJSON of params, or no params when params_absent is true) and the authenticated request context; the outcome is pass (with no horizon), denied, or unverifiable. Every params value here is inside the restricted value model, so a verifier would pass it to the evaluator after claim",
			"order":          "params are checked first: params outside the profile's exact shape are denied whatever the context holds; then a missing context entry is unverifiable; then the comparison decides",
			"context":        "extension_counts maps names to integers 0..2^53-1; extension_values maps names to valid UTF-8 of at most 512 bytes. A count is never read as a value or a value as a count",
			"context_bounds": "validate the extension request context before claim: error_class configuration_invalid, or none when it is within bounds (at most 64 counts and 64 values; names 1 to 128 bytes of a-z, 0-9, _, ., :, and -; counts 0..2^53-1; values valid UTF-8 of at most 512 bytes)",
		},
		Profiles: []profileSuiteJSON{maxCount, allowed},
		ContextBounds: []contextBoundCaseJSON{
			bound("sixty_four_counts_accepted", profileContextJSON{ExtensionCounts: sixtyFourCounts}, ""),
			bound("sixty_five_counts_rejected", profileContextJSON{ExtensionCounts: manyCounts}, "configuration_invalid"),
			bound("sixty_five_values_rejected", profileContextJSON{ExtensionValues: manyValues}, "configuration_invalid"),
			bound("largest_count_accepted", counts("n", maxSafe), ""),
			bound("count_above_safe_integer_rejected", counts("n", maxSafe+1), "configuration_invalid"),
			bound("negative_count_rejected", counts("n", int64(-1)), "configuration_invalid"),
			bound("value_512_bytes_accepted", values("v", value512), ""),
			bound("value_513_bytes_rejected", values("v", value513), "configuration_invalid"),
			bound("empty_value_accepted", values("v", ""), ""),
			bound("name_128_bytes_accepted", counts(name128, int64(1)), ""),
			bound("name_129_bytes_rejected", counts(name129, int64(1)), "configuration_invalid"),
			bound("uppercase_name_rejected", values("Region", "x"), "configuration_invalid"),
			bound("empty_name_rejected", counts("", int64(1)), "configuration_invalid"),
		},
	}
}
