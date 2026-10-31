package v2vectors

// Annex A vectors (SPEC-v2-ANNEX-A.md). They lock the v1 clauses that v2
// incorporates: the restricted value model, RatifyCanonicalJSON, and the
// scope vocabulary with wildcard expansion, chain intersection, and custom
// scopes. Every expected value is written here from the annex text, not read
// back from the implementation under test.

// annexClause pins one copied clause by its exact byte length and SHA-256.
type annexClause struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type annexCanonical struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// InputB64 is the exact input bytes; Canonical is the expected
	// RatifyCanonicalJSON text of the decoded value (UTF-8).
	InputB64 string `json:"input_b64"`
	// InputIsCanonical states whether the input bytes are already the
	// canonical encoding of their value.
	InputIsCanonical bool   `json:"input_is_canonical"`
	Canonical        string `json:"canonical"`
}

type annexRejection struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputB64    string `json:"input_b64"`
	ErrorClass  string `json:"error_class"`
}

type annexScopeValidation struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
	Valid  bool     `json:"valid"`
}

type annexExpansion struct {
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	Expanded []string `json:"expanded"`
}

type annexIntersection struct {
	Name      string     `json:"name"`
	Lists     [][]string `json:"lists"`
	Effective []string   `json:"effective"`
}

type annexVocabulary struct {
	Canonical []string            `json:"canonical"`
	Sensitive []string            `json:"sensitive"`
	Wildcards map[string][]string `json:"wildcards"`
}

type annexFile struct {
	Version           int                    `json:"version"`
	Description       string                 `json:"description"`
	Semantics         map[string]string      `json:"semantics"`
	Clauses           []annexClause          `json:"clauses"`
	CanonicalJSON     []annexCanonical       `json:"canonical_json"`
	Rejections        []annexRejection       `json:"strict_decode_rejections"`
	Vocabulary        annexVocabulary        `json:"vocabulary"`
	ScopeValidation   []annexScopeValidation `json:"scope_validation"`
	ScopeExpansion    []annexExpansion       `json:"scope_expansion"`
	ScopeIntersection []annexIntersection    `json:"scope_intersection"`
}

func (g *gen) annexFile() any {
	f := annexFile{
		Version:     2,
		Description: "Annex A vectors (SPEC-v2-ANNEX-A.md): the v1 clauses that Protocol v2 incorporates, pinned by digest and locked by behavior. The annex, not SPEC.md, is normative for v2.",
		Semantics: map[string]string{
			"clauses":                  "recompute SHA-256 over the exact UTF-8 bytes between the annex-a:begin and annex-a:end marker lines of SPEC-v2-ANNEX-A.md (no final newline); bytes and sha256 must match",
			"canonical_json":           "strictly decode input_b64 under SPEC-v2 §2.1 and the A.2 value model, re-encode with RatifyCanonicalJSON (A.3), and compare with canonical byte for byte; input_is_canonical states whether the input bytes already equal that encoding",
			"strict_decode_rejections": "input_b64 must be rejected before any value is produced, with error_class",
			"vocabulary":               "canonical is the complete A.4 §9.1 vocabulary in byte order; sensitive is its sensitive subset; wildcards maps each A.4 §9.2 wildcard to its sorted expansion",
			"scope_validation":         "validate a v2 certificate scope list (A.4 plus SPEC-v2 §5.1: non-empty, no duplicate, no custom:*)",
			"scope_expansion":          "expand a scope list (A.4 §9.2 and §9.4) and sort it in byte order without duplicates",
			"scope_intersection":       "effective scope of a chain: the intersection of every list's expansion, sorted (A.4 §9.3)",
		},
		Clauses: []annexClause{
			{"A.2", "SPEC.md §5.7.1, the Restricted value model item", 499, "adc4e5aba2f47577f4eb336a226c46d9d45d108e111b0ca8cb084a1c4277a727"},
			{"A.3", "SPEC.md §§6.1 to 6.3", 1616, "e89aeebd1238aff661ae087cec6134cd8c70d63eb7584003ce2539f9c182f9ab"},
			{"A.4", "SPEC.md §9 introduction and §§9.1 to 9.5", 11777, "bf265807bd61dd241bbcca4f70a2e860ec436c5f09bceeb82f0ae607ceaf15c6"},
		},
	}
	canonical := func(name, desc, input string, isCanonical bool, out string) {
		f.CanonicalJSON = append(f.CanonicalJSON, annexCanonical{name, desc, b64([]byte(input)), isCanonical, out})
	}
	canonical("key_order_utf8_bytes", "object keys sort by UTF-8 bytes, not UTF-16 code units: U+FF61 (EF BD A1) sorts before U+1F600 (F0 9F 98 80)",
		`{"b":1,"a":2,"\uff61":3,"\ud83d\ude00":4,"\u00e9":5,"Z":6}`, false,
		"{\"Z\":6,\"a\":2,\"b\":1,\"\u00e9\":5,\"\uff61\":3,\"\U0001F600\":4}")
	canonical("whitespace_and_nesting", "insignificant whitespace is removed and nested object keys sort recursively",
		" { \"z\" : [ 1 , { \"y\" : null , \"x\" : true } ] , \"a\" : \"s\" } ", false,
		`{"a":"s","z":[1,{"x":true,"y":null}]}`)
	canonical("minimal_escaping", "minimal RFC 8259 escaping, no HTML escaping, U+2028 and U+2029 escaped, DEL and solidus literal, escaped non-ASCII emitted literally",
		`{"s":"<>&\u2028\u2029\u0001\u001f\n\t\r\b\f\"\\\/\u007f\u00e9"}`, false,
		"{\"s\":\"<>&\\u2028\\u2029\\u0001\\u001f\\n\\t\\r\\b\\f\\\"\\\\/\u007f\u00e9\"}")
	canonical("literal_line_separator", "a literal U+2028 in the input is the same value as its escape and is emitted escaped",
		"{\"s\":\"a\u2028b\"}", false, "{\"s\":\"a\\u2028b\"}")
	canonical("safe_integer_bounds", "integers at the safe-integer bounds keep their shortest decimal form",
		`{"max":9007199254740991,"min":-9007199254740991,"neg":-1,"zero":0}`, true,
		`{"max":9007199254740991,"min":-9007199254740991,"neg":-1,"zero":0}`)
	canonical("no_unicode_normalization", "NFC U+00E9 and NFD e + U+0301 are distinct keys and distinct values; nothing is normalized, and the NFD key (65 CC 81) sorts first",
		"{\"\u00e9\":\"\u00e9\",\"e\u0301\":\"e\u0301\"}", false,
		"{\"e\u0301\":\"e\u0301\",\"\u00e9\":\"\u00e9\"}")
	canonical("empty_containers", "empty arrays and objects", `{"b":{},"a":[]}`, false, `{"a":[],"b":{}}`)
	canonical("already_canonical", "canonical input is unchanged", `{"a":[true,false,null,"x",-5],"b":{"c":"d"}}`, true, `{"a":[true,false,null,"x",-5],"b":{"c":"d"}}`)

	reject := func(name, desc string, input []byte) {
		f.Rejections = append(f.Rejections, annexRejection{name, desc, b64(input), "malformed"})
	}
	reject("fraction", "a number with a fraction is outside the value model", []byte(`{"a":1.5}`))
	reject("integral_fraction", "1.0 is a fraction token even though its value is integral", []byte(`{"a":1.0}`))
	reject("exponent", "a number with an exponent is outside the value model", []byte(`{"a":1e2}`))
	reject("exponent_upper", "an uppercase exponent is outside the value model", []byte(`{"a":1E2}`))
	reject("negative_zero", "the integer spelling -0 is rejected (SPEC-v2 §2.1)", []byte(`{"a":-0}`))
	reject("above_safe_integer", "2^53 is outside the safe-integer range", []byte(`{"a":9007199254740992}`))
	reject("below_safe_integer", "-2^53 is outside the safe-integer range", []byte(`{"a":-9007199254740992}`))
	reject("duplicate_key", "a repeated object key", []byte(`{"a":1,"a":1}`))
	reject("duplicate_key_after_escape", "a key and its escaped spelling are the same key", []byte(`{"a":1,"a":2}`))
	reject("nested_duplicate_key", "duplicate keys are rejected at any depth", []byte(`{"o":{"k":1,"k":2}}`))
	reject("lone_high_surrogate", "an unpaired high surrogate escape", []byte(`{"a":"\ud800"}`))
	reject("lone_low_surrogate", "an unpaired low surrogate escape", []byte(`{"a":"\udc00"}`))
	reject("reversed_surrogates", "a low surrogate followed by a high surrogate is not a pair", []byte(`{"a":"\udc00\ud800"}`))
	reject("invalid_utf8", "raw bytes that are not UTF-8", []byte("{\"a\":\"\xff\"}"))
	reject("nan_token", "NaN is not JSON", []byte(`{"a":NaN}`))
	reject("trailing_document", "content after the first JSON value", []byte(`{"a":1}{}`))

	f.Vocabulary = annexVocabulary{
		Canonical: []string{
			"actuate:motor", "actuate:switch", "actuate:valve",
			"comms:calendar:read", "comms:calendar:write", "comms:email:delete", "comms:email:read", "comms:email:send",
			"comms:message:delete", "comms:message:read", "comms:message:send",
			"contract:read", "contract:sign",
			"data:delete", "data:export", "data:read", "data:share", "data:write",
			"drone:capture", "drone:deliver", "drone:fly",
			"execute:code", "execute:tool",
			"files:read", "files:write",
			"generate:content", "generate:deepfake",
			"identity:delegate", "identity:prove",
			"infrastructure:access", "infrastructure:control", "infrastructure:monitor",
			"meeting:attend", "meeting:chat", "meeting:record", "meeting:share_screen", "meeting:speak", "meeting:video",
			"payments:authorize", "payments:receive", "payments:send",
			"physical:actuate", "physical:enter", "physical:exit", "physical:manipulate",
			"presence:represent",
			"robot:interact", "robot:move", "robot:operate",
			"transact:purchase", "transact:sell",
			"vehicle:charge", "vehicle:operate", "vehicle:transport",
		},
		Sensitive: []string{
			"actuate:motor", "actuate:switch", "actuate:valve",
			"comms:email:delete", "comms:message:delete",
			"contract:sign",
			"data:delete", "data:export", "data:write",
			"drone:fly",
			"execute:code",
			"files:write",
			"generate:deepfake",
			"identity:delegate",
			"infrastructure:access", "infrastructure:control",
			"meeting:record",
			"payments:authorize",
			"physical:actuate", "physical:manipulate",
			"presence:represent",
			"vehicle:operate",
		},
		Wildcards: map[string][]string{
			"meeting:*":        {"meeting:attend", "meeting:chat", "meeting:share_screen", "meeting:speak", "meeting:video"},
			"comms:message:*":  {"comms:message:read", "comms:message:send"},
			"comms:email:*":    {"comms:email:read", "comms:email:send"},
			"comms:*":          {"comms:calendar:read", "comms:calendar:write", "comms:email:read", "comms:email:send", "comms:message:read", "comms:message:send"},
			"transact:*":       {"transact:purchase", "transact:sell"},
			"payments:*":       {"payments:receive", "payments:send"},
			"data:*":           {"data:read", "data:share"},
			"execute:*":        {"execute:tool"},
			"generate:*":       {"generate:content"},
			"physical:*":       {"physical:enter", "physical:exit"},
			"robot:*":          {"robot:interact", "robot:move", "robot:operate"},
			"drone:*":          {"drone:capture", "drone:deliver"},
			"vehicle:*":        {"vehicle:charge", "vehicle:transport"},
			"infrastructure:*": {"infrastructure:monitor"},
		},
	}

	valid := func(name string, ok bool, scopes ...string) {
		if scopes == nil {
			scopes = []string{}
		}
		f.ScopeValidation = append(f.ScopeValidation, annexScopeValidation{name, scopes, ok})
	}
	valid("canonical", true, "data:read")
	valid("wildcard", true, "data:*")
	valid("custom", true, "custom:acme:inventory:read")
	valid("custom_single_character", true, "custom:x")
	valid("custom_looks_like_wildcard", true, "custom:data:*")
	valid("custom_non_ascii_exact", true, "custom:caf\u00e9")
	valid("empty_list", false)
	valid("custom_prefix_only", false, "custom:")
	valid("custom_star", false, "custom:*")
	valid("reserved_x_prefix", false, "x-acme:read")
	valid("reserved_urn_prefix", false, "urn:ratify:read")
	valid("duplicate", false, "data:read", "data:read")
	valid("no_actuate_wildcard", false, "actuate:*")
	valid("no_presence_wildcard", false, "presence:*")
	valid("no_files_wildcard", false, "files:*")
	valid("case_sensitive", false, "Data:read")
	valid("trailing_space", false, "data:read ")

	expand := func(name string, scopes, expanded []string) {
		f.ScopeExpansion = append(f.ScopeExpansion, annexExpansion{name, scopes, expanded})
	}
	expand("wildcard_excludes_sensitive", []string{"data:*"}, []string{"data:read", "data:share"})
	expand("explicit_sensitive_kept", []string{"meeting:*", "meeting:record"}, []string{"meeting:attend", "meeting:chat", "meeting:record", "meeting:share_screen", "meeting:speak", "meeting:video"})
	expand("custom_passes_through", []string{"custom:acme:x", "data:*"}, []string{"custom:acme:x", "data:read", "data:share"})
	expand("custom_wildcard_shape_is_literal", []string{"custom:data:*"}, []string{"custom:data:*"})
	expand("physical_wildcard", []string{"physical:*"}, []string{"physical:enter", "physical:exit"})
	expand("deduplicated_and_sorted", []string{"data:share", "data:*", "comms:email:*", "comms:email:read"}, []string{"comms:email:read", "comms:email:send", "data:read", "data:share"})

	intersect := func(name string, effective []string, lists ...[]string) {
		if effective == nil {
			effective = []string{}
		}
		f.ScopeIntersection = append(f.ScopeIntersection, annexIntersection{name, lists, effective})
	}
	intersect("wildcard_narrowed_by_child", []string{"data:read"}, []string{"data:*"}, []string{"data:read", "data:write"})
	intersect("sensitive_needs_every_link", nil, []string{"data:*"}, []string{"data:write"})
	intersect("sensitive_explicit_in_every_link", []string{"identity:delegate"}, []string{"identity:delegate", "data:read"}, []string{"identity:delegate"})
	intersect("custom_in_every_link", []string{"custom:acme:x"}, []string{"custom:acme:x", "data:read"}, []string{"custom:acme:x"})
	intersect("custom_byte_exact", nil, []string{"custom:acme:x"}, []string{"custom:acme:X"})
	intersect("custom_not_granted_by_canonical", nil, []string{"data:*"}, []string{"custom:data:read"})
	intersect("nested_wildcards", []string{"comms:email:read", "comms:email:send"}, []string{"comms:*"}, []string{"comms:email:*", "comms:email:delete"})
	intersect("three_links", []string{"data:read"}, []string{"data:*", "files:read"}, []string{"data:read", "data:share"}, []string{"data:read", "files:read"})
	return f
}
