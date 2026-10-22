package ratify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/identities-ai/ratify-protocol/v2/internal/tzdbv2"
	"strconv"
	"strings"
	"time"
)

// Protocol v2 closed constraint registry (SPEC-v2 §5.2).
//
// v2 defines its own constraint schemas. It does not import v1 shapes by
// reference, and no v2 constraint field carries a floating-point number.
// The registered types and their exact wire members are:
//
//	time_window              {"end","start","tz","type"}
//	                         start, end: "HH:MM" local wall-clock minutes,
//	                         00:00..23:59, inclusive; start > end wraps midnight.
//	                         tz: IANA time-zone identifier, 1-64 bytes of
//	                         /-separated [A-Za-z0-9_+-] segments. A zone the verifier's
//	                         time-zone database cannot load (unknown ID, missing
//	                         or different tz data) is constraint_unverifiable.
//	max_amount               {"currency","max_amount_micros","type"}
//	                         currency: ISO-4217 alphabetic code, [A-Z]{3}.
//	                         max_amount_micros: integer 0..2^53-1 in 10^-6 major
//	                         units of currency. The authenticated request amount
//	                         MUST use the same unit (ConstraintContextV2).
//	max_rate                 {"count","type","window_s"}
//	                         count: integer 1..2^53-1; window_s: 1..86400.
//	resource_path            {"path_prefix"?,"resource_id","type"}
//	                         resource_id: non-empty, at most
//	                         MAX_IDENTIFIER_LENGTH_BYTES; path_prefix, when
//	                         present, is a non-empty string.
//	ratify.receiver_audience {"params","type"} (see validateV2ReceiverAudience).
//
// Every other type, including the v1 types geo_circle, geo_polygon, geo_bbox
// and max_speed_mps (deferred to a later revision), is unregistered in v2.
// An unregistered constraint may carry only "type" and an optional "params"
// object; it decodes, and fails closed as constraint_unknown at evaluation.
// v1 member names on an unregistered type (for example "lat") are malformed.
const (
	// MaxAudienceIDsV2 bounds each receiver-audience ID array.
	MaxAudienceIDsV2 = 64
)

// ConstraintV2 is one entry of a v2 delegation certificate's constraints
// array. Only the members of the registered schema for Type are encoded.
type ConstraintV2 struct {
	Type ConstraintType

	// time_window
	Start string
	End   string
	TZ    string

	// max_amount
	Currency        string
	MaxAmountMicros int64

	// max_rate
	Count   int64
	WindowS int64

	// resource_path
	ResourceID string
	PathPrefix string

	// ratify.receiver_audience and unregistered types.
	Params map[string]any
}

// ConstraintContextV2 carries the verifier-authenticated action inputs that
// registered v2 constraints evaluate against. It contains no floating point:
// RequestedAmountMicros uses the same 10^-6 major-unit scale as
// max_amount_micros. max_rate and ratify.receiver_audience are evaluated by
// their dedicated post-status stages, not from this context.
type ConstraintContextV2 struct {
	RequestedAmountMicros int64
	RequestedCurrency     string
	HasAmount             bool

	// RequestedResourceID / RequestedPath follow the resource_path rules:
	// callers apply every decoding and normalization step first; the
	// verifier compares bytes exactly.
	RequestedResourceID string
	RequestedPath       string
	HasResource         bool

	// ExtensionCounts and ExtensionValues are authenticated request inputs
	// for registered extension evaluator profiles (SPEC-v2 §5.2): a named
	// quantity (0..2^53-1) and a named exact value (valid UTF-8, at most 512
	// bytes). Names are 1 to 128 bytes of [a-z0-9_.:-]; each map holds at
	// most 64 entries. An absent name is missing context, never a pass.
	ExtensionCounts map[string]int64
	ExtensionValues map[string]string
}

// MarshalJSON emits exactly the registered members for c.Type, with keys in
// RatifyCanonicalJSON order and without HTML escaping.
func (c ConstraintV2) MarshalJSON() (_ []byte, resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	m := map[string]any{"type": string(c.Type)}
	switch c.Type {
	case ConstraintTimeWindow:
		m["start"], m["end"], m["tz"] = c.Start, c.End, c.TZ
	case ConstraintMaxAmount:
		m["currency"], m["max_amount_micros"] = c.Currency, c.MaxAmountMicros
	case ConstraintMaxRate:
		m["count"], m["window_s"] = c.Count, c.WindowS
	case ConstraintResourcePath:
		m["resource_id"] = c.ResourceID
		if c.PathPrefix != "" {
			m["path_prefix"] = c.PathPrefix
		}
	default:
		if c.Params != nil {
			m["params"] = c.Params
		}
	}
	if c.Params != nil && isRegisteredStructuredConstraintV2(c.Type) {
		return nil, fmt.Errorf("v2 constraint type %q must not carry params", c.Type)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	out := bytes.TrimRight(buf.Bytes(), "\n")
	if err := validateV2ConstraintFields(out); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalJSON strictly decodes one v2 constraint against the closed registry.
func (c *ConstraintV2) UnmarshalJSON(data []byte) (resultErr error) {
	defer func() { resultErr = v2Classify(V2ErrMalformed, resultErr) }()
	if err := validateV2ConstraintFields(data); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var out ConstraintV2
	if err := json.Unmarshal(fields["type"], &out.Type); err != nil {
		return err
	}
	str := func(name string, dst *string) {
		if raw, ok := fields[name]; ok {
			_ = json.Unmarshal(raw, dst)
		}
	}
	num := func(name string, dst *int64) {
		if raw, ok := fields[name]; ok {
			*dst, _ = strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
		}
	}
	switch out.Type {
	case ConstraintTimeWindow:
		str("start", &out.Start)
		str("end", &out.End)
		str("tz", &out.TZ)
	case ConstraintMaxAmount:
		str("currency", &out.Currency)
		num("max_amount_micros", &out.MaxAmountMicros)
	case ConstraintMaxRate:
		num("count", &out.Count)
		num("window_s", &out.WindowS)
	case ConstraintResourcePath:
		str("resource_id", &out.ResourceID)
		str("path_prefix", &out.PathPrefix)
	default:
		if raw, ok := fields["params"]; ok {
			if err := json.Unmarshal(raw, &out.Params); err != nil {
				return err
			}
		}
	}
	*c = out
	return nil
}

func isRegisteredStructuredConstraintV2(t ConstraintType) bool {
	switch t {
	case ConstraintTimeWindow, ConstraintMaxAmount, ConstraintMaxRate, ConstraintResourcePath:
		return true
	}
	return false
}

// IsRegisteredConstraintTypeV2 reports whether t is in the closed v2 registry.
func IsRegisteredConstraintTypeV2(t ConstraintType) bool {
	return isRegisteredStructuredConstraintV2(t) || t == ConstraintReceiverAudience
}

// validateV2ConstraintFields enforces the closed v2 constraint registry on
// one encoded constraint object.
func validateV2ConstraintFields(data []byte) error {
	if err := checkV2Nulls(data); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return fmt.Errorf("constraint must be an object")
	}
	var kind string
	if raw, ok := fields["type"]; !ok || json.Unmarshal(raw, &kind) != nil || kind == "" {
		return fmt.Errorf("constraint type must be a non-empty string")
	}
	t := ConstraintType(kind)
	exact := func(required []string, optional ...string) error {
		for key := range fields {
			if key != "type" && !containsV2Field(required, key) && !containsV2Field(optional, key) {
				return fmt.Errorf("field %q is not allowed for constraint type %q", key, t)
			}
		}
		for _, name := range required {
			if _, ok := fields[name]; !ok {
				return fmt.Errorf("constraint type %q requires field %q", t, name)
			}
		}
		return nil
	}
	switch t {
	case ConstraintTimeWindow:
		if err := exact([]string{"start", "end", "tz"}); err != nil {
			return err
		}
		for _, name := range []string{"start", "end"} {
			value, err := v2StringField(fields[name])
			if err != nil {
				return fmt.Errorf("time_window %s must be a string", name)
			}
			if _, err := parseHHMMV2(value); err != nil {
				return fmt.Errorf("time_window %s: %w", name, err)
			}
		}
		tz, err := v2StringField(fields["tz"])
		if err != nil || !validTimeZoneIDV2(tz) {
			return fmt.Errorf("time_window tz must be 1 to 64 bytes of /-separated [A-Za-z0-9_+-] segments")
		}
	case ConstraintMaxAmount:
		if err := exact([]string{"currency", "max_amount_micros"}); err != nil {
			return err
		}
		currency, err := v2StringField(fields["currency"])
		if err != nil || !validISO4217AlphaV2(currency) {
			return fmt.Errorf("max_amount currency must be an ISO-4217 alphabetic code")
		}
		amount, err := v2IntegerField(fields["max_amount_micros"])
		if err != nil || amount < 0 {
			return fmt.Errorf("max_amount_micros must be a nonnegative safe integer")
		}
	case ConstraintMaxRate:
		if err := exact([]string{"count", "window_s"}); err != nil {
			return err
		}
		count, err := v2IntegerField(fields["count"])
		if err != nil || count <= 0 {
			return fmt.Errorf("max_rate count must be a positive safe integer")
		}
		window, err := v2IntegerField(fields["window_s"])
		if err != nil || window <= 0 || window > V2MaxRateWindowSeconds {
			return fmt.Errorf("max_rate window_s must be an integer in 1..%d", V2MaxRateWindowSeconds)
		}
	case ConstraintResourcePath:
		if err := exact([]string{"resource_id"}, "path_prefix"); err != nil {
			return err
		}
		id, err := v2StringField(fields["resource_id"])
		if err != nil || id == "" || len(id) > MaxIdentifierLengthBytes {
			return fmt.Errorf("resource_path resource_id must be a non-empty string within MAX_IDENTIFIER_LENGTH_BYTES")
		}
		if raw, ok := fields["path_prefix"]; ok {
			prefix, err := v2StringField(raw)
			if err != nil || prefix == "" {
				return fmt.Errorf("resource_path path_prefix must be a non-empty string when present")
			}
		}
	case ConstraintReceiverAudience:
		if err := exact([]string{"params"}); err != nil {
			return err
		}
		return validateV2ReceiverAudience(fields["params"])
	default:
		// Unregistered type, including geo_circle, geo_polygon, geo_bbox and
		// max_speed_mps: evaluated as constraint_unknown.
		if len(kind) > MaxIdentifierLengthBytes {
			return fmt.Errorf("unregistered constraint type exceeds MAX_IDENTIFIER_LENGTH_BYTES")
		}
		if err := exact(nil, "params"); err != nil {
			return err
		}
		if raw, ok := fields["params"]; ok {
			var params map[string]any
			if err := json.Unmarshal(raw, &params); err != nil || params == nil {
				return fmt.Errorf("unregistered constraint params must be an object")
			}
			if err := ValidateParamsValue(params, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateV2ReceiverAudience(raw json.RawMessage) error {
	var params map[string]json.RawMessage
	if err := json.Unmarshal(raw, &params); err != nil || params == nil {
		return fmt.Errorf("receiver audience requires params object")
	}
	for key := range params {
		if !containsV2Field([]string{"exact_receiver_ids", "trust_domain_ids", "max_membership_age_seconds"}, key) {
			return fmt.Errorf("unknown receiver audience parameter %q", key)
		}
	}
	var exact, domains []string
	if json.Unmarshal(params["exact_receiver_ids"], &exact) != nil || exact == nil || json.Unmarshal(params["trust_domain_ids"], &domains) != nil || domains == nil {
		return fmt.Errorf("receiver audience requires exact_receiver_ids and trust_domain_ids arrays")
	}
	if len(exact)+len(domains) == 0 {
		return fmt.Errorf("receiver audience must name an exact receiver or trust domain")
	}
	for _, values := range [][]string{exact, domains} {
		if len(values) > MaxAudienceIDsV2 {
			return fmt.Errorf("receiver audience arrays hold at most %d IDs", MaxAudienceIDsV2)
		}
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || len(value) > MaxIdentifierLengthBytes || seen[value] {
				return fmt.Errorf("receiver audience IDs must be unique and 1 to %d bytes", MaxIdentifierLengthBytes)
			}
			seen[value] = true
		}
	}
	age, hasAge := params["max_membership_age_seconds"]
	if len(domains) > 0 && (!hasAge || bytes.Equal(bytes.TrimSpace(age), []byte("null"))) {
		return fmt.Errorf("receiver audience trust domains require max_membership_age_seconds")
	}
	if hasAge {
		seconds, err := v2IntegerField(age)
		if err != nil || seconds <= 0 || seconds > V2MaxAudienceMembershipAgeSeconds {
			return fmt.Errorf("max_membership_age_seconds must be an integer in 1..%d", V2MaxAudienceMembershipAgeSeconds)
		}
	}
	if len(domains) == 0 && hasAge {
		return fmt.Errorf("receiver audience without trust domains must omit max_membership_age_seconds")
	}
	return nil
}

// v2IntegerField parses a JSON integer token in the safe-integer range. A
// fraction or exponent spelling is rejected even when its value is integral.
func v2IntegerField(raw json.RawMessage) (int64, error) {
	token := string(bytes.TrimSpace(raw))
	if token == "" {
		return 0, fmt.Errorf("integer is required")
	}
	digits := token
	if digits[0] == '-' {
		digits = digits[1:]
	}
	if digits == "" || (len(digits) > 1 && digits[0] == '0') {
		return 0, fmt.Errorf("integer %q is not canonical", token)
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, fmt.Errorf("integer %q is not a JSON integer", token)
		}
	}
	if token == "-0" {
		return 0, fmt.Errorf("negative zero is not a canonical integer")
	}
	n, err := strconv.ParseInt(token, 10, 64)
	if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
		return 0, fmt.Errorf("integer %q is outside the safe-integer range", token)
	}
	return n, nil
}

func v2StringField(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", fmt.Errorf("string is required")
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", err
	}
	return value, nil
}

func validISO4217AlphaV2(code string) bool {
	if len(code) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if code[i] < 'A' || code[i] > 'Z' {
			return false
		}
	}
	return true
}

// validTimeZoneIDV2 checks the SPEC-v2 §5.2 tz shape: 1 to 64 ASCII bytes of
// '/'-separated segments of [A-Za-z0-9_+-], with no empty, "." or ".."
// segment. Whether the zone exists is decided at evaluation time.
func validTimeZoneIDV2(tz string) bool {
	if len(tz) == 0 || len(tz) > 64 {
		return false
	}
	for _, segment := range strings.Split(tz, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '+' || c == '-') {
				return false
			}
		}
	}
	return true
}

// parseHHMMV2 accepts exactly two-digit hours 00..23 and minutes 00..59.
func parseHHMMV2(s string) (int, error) {
	if len(s) != 5 || s[2] != ':' {
		return 0, fmt.Errorf("expected HH:MM, got %q", s)
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("expected HH:MM, got %q", s)
		}
	}
	h := int(s[0]-'0')*10 + int(s[1]-'0')
	m := int(s[3]-'0')*10 + int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, fmt.Errorf("out-of-range HH:MM %q", s)
	}
	return h*60 + m, nil
}

// TZDBVersionV2 is the IANA tzdata release embedded in this module and used
// for every time_window evaluation (SPEC-v2 §5.2). A verifier configures the
// release it requires; any other configured value, or none, makes every
// time_window constraint_unverifiable.
const TZDBVersionV2 = tzdbv2.Version

// loadV2TimeZone loads an IANA zone from the embedded, pinned time-zone
// database after checking the configured database version. The host zone
// database is never consulted, and "Local" is never loaded.
func loadV2TimeZone(configuredVersion, tz string) (*time.Location, error) {
	if configuredVersion == "" {
		return nil, fmt.Errorf("no tzdb_version is configured")
	}
	if configuredVersion != TZDBVersionV2 {
		return nil, fmt.Errorf("configured tzdb_version %q differs from the loaded IANA tzdata %s", configuredVersion, TZDBVersionV2)
	}
	return tzdbv2.Load(tz)
}

// evaluateConstraintV2 evaluates one registered locally decidable constraint.
// It returns nil when the constraint passes, an ErrConstraintUnverifiable
// wrapper when required authenticated input is unavailable, an
// unknownConstraintError for an unregistered type, and any other error for a
// denial. max_rate and ratify.receiver_audience are deferred stages and must
// not reach this function.
func evaluateConstraintV2(c ConstraintV2, ctx ConstraintContextV2, tzdbVersion string, now time.Time) error {
	switch c.Type {
	case ConstraintResourcePath:
		// SPEC-v2 §5.2 order: the signed path_prefix is checked before any
		// request input, because its validity does not depend on the request.
		if c.PathPrefix != "" {
			if _, err := NormalizeResourcePath(c.PathPrefix); err != nil {
				return fmt.Errorf("malformed path_prefix: %v", err)
			}
		}
		if !ctx.HasResource || ctx.RequestedResourceID == "" {
			return errConstraintUnverifiable("no requested resource in context")
		}
		if ctx.RequestedResourceID != c.ResourceID {
			return fmt.Errorf("requested resource does not match the authorized resource")
		}
		if c.PathPrefix == "" {
			return nil
		}
		if ctx.RequestedPath == "" {
			return errConstraintUnverifiable("no requested path in context")
		}
		if _, err := NormalizeResourcePath(ctx.RequestedPath); err != nil {
			return fmt.Errorf("invalid requested path: %v", err)
		}
		if !ResourcePathMatches(c.PathPrefix, ctx.RequestedPath) {
			return fmt.Errorf("requested path %s is outside the authorized prefix %s", fmtQuoted(ctx.RequestedPath), fmtQuoted(c.PathPrefix))
		}
		return nil
	case ConstraintTimeWindow:
		loc, err := loadV2TimeZone(tzdbVersion, c.TZ)
		if err != nil {
			return errConstraintUnverifiable(fmt.Sprintf("time zone %q cannot be evaluated: %v", c.TZ, err))
		}
		start, err := parseHHMMV2(c.Start)
		if err != nil {
			return err
		}
		end, err := parseHHMMV2(c.End)
		if err != nil {
			return err
		}
		local := now.In(loc)
		cur := local.Hour()*60 + local.Minute()
		if start <= end && (cur < start || cur > end) || start > end && cur < start && cur > end {
			return fmt.Errorf("current %02d:%02d is outside [%s, %s] %s", local.Hour(), local.Minute(), c.Start, c.End, c.TZ)
		}
		return nil
	case ConstraintMaxAmount:
		if !ctx.HasAmount {
			return errConstraintUnverifiable("no requested amount in context")
		}
		if ctx.RequestedAmountMicros < 0 || ctx.RequestedAmountMicros > maxSafeInteger || !validISO4217AlphaV2(ctx.RequestedCurrency) {
			return errConstraintUnverifiable("requested amount is not a nonnegative safe integer in ISO-4217 micro-units")
		}
		if ctx.RequestedCurrency != c.Currency {
			return fmt.Errorf("currency mismatch: requested %q, constraint %q", ctx.RequestedCurrency, c.Currency)
		}
		if ctx.RequestedAmountMicros > c.MaxAmountMicros {
			return fmt.Errorf("amount %d exceeds max %d micro-units of %s", ctx.RequestedAmountMicros, c.MaxAmountMicros, c.Currency)
		}
		return nil
	case ConstraintMaxRate, ConstraintReceiverAudience:
		return errConstraintUnverifiable(fmt.Sprintf("%s requires its dedicated post-status stage", c.Type))
	default:
		return unknownConstraintError{kind: string(c.Type)}
	}
}
