package ratify

// Resource-bound authority — the resource_path constraint's path model,
// segment-boundary matching, and the extension-constraint params value model
// (SPEC §5.7.1, §5.7.3).
//
// Paths are absolute logical POSIX-style paths: they name a location inside
// the resource's own namespace, not filesystem paths on any machine. The
// verifier compares bytes exactly — no Unicode normalization, no percent
// decoding, no case folding. Issuers and adapters pre-normalize (NFC) and
// pre-decode BEFORE constructing constraints and verifier context; nothing
// transforms a path after verification.
//
// CROSS-SDK: TypeScript / Python / Rust / C MUST implement identical
// semantics; adapters use these exported helpers rather than reimplementing
// matching.

import (
	"fmt"
	"math"
	"strings"
)

// NormalizeResourcePath validates p against the logical path model
// (SPEC §5.7.3) and returns its comparison form: at most one trailing "/"
// trimmed, except for the root path "/" itself. It returns an error when p
// is not a valid logical path:
//
//   - must begin with "/" ("/" is the only separator)
//   - no NUL byte, no backslash (rejected, never translated)
//   - no "." or ".." segment (rejected outright, never resolved)
//   - no empty interior segment ("/a//b" is invalid; "/" is valid)
//
// "%" is an ordinary literal byte: the path model has no percent-encoding.
func NormalizeResourcePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("path is empty")
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path must begin with '/'")
	}
	if strings.IndexByte(p, 0x00) >= 0 {
		return "", fmt.Errorf("path contains a NUL byte")
	}
	if strings.IndexByte(p, '\\') >= 0 {
		return "", fmt.Errorf("path contains a backslash; '/' is the only separator")
	}
	if p == "/" {
		return "/", nil
	}
	// Trim at most one trailing slash before segment validation, per the
	// path model: "/docs/" ≡ "/docs", while "/docs//" leaves an empty
	// interior segment after the trim and is invalid.
	trimmed := strings.TrimSuffix(p, "/")
	segments := strings.Split(trimmed[1:], "/")
	for _, seg := range segments {
		switch seg {
		case "":
			return "", fmt.Errorf("path contains an empty segment")
		case ".", "..":
			return "", fmt.Errorf("path contains a dot-segment; dot-segments are rejected, never resolved")
		}
	}
	return trimmed, nil
}

// ResourcePathMatches reports whether requestedPath is at or below
// pathPrefix under segment-boundary prefix matching (SPEC §5.7.3). Both
// inputs MUST already be valid; callers use NormalizeResourcePath first.
// This is NOT glob matching and NOT plain string-prefix matching: "/src"
// matches "/src" and "/src/a.ts", never "/src-old/a.ts" or "/srcx".
func ResourcePathMatches(pathPrefix, requestedPath string) bool {
	prefix, err := NormalizeResourcePath(pathPrefix)
	if err != nil {
		return false
	}
	path, err := NormalizeResourcePath(requestedPath)
	if err != nil {
		return false
	}
	if prefix == "/" {
		// The root prefix matches every valid path.
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// resourcePathsNested reports whether two valid prefixes are comparable
// under the prefix relation (one at or below the other). An absent prefix
// orders as "/" (SPEC §5.7.3 issuance rule).
func resourcePathsNested(a, b string) bool {
	if a == "" {
		a = "/"
	}
	if b == "" {
		b = "/"
	}
	return ResourcePathMatches(a, b) || ResourcePathMatches(b, a)
}

// ValidateResourceConstraints enforces the issuance rule of SPEC §5.7.3:
// a certificate's resource_path constraints must be jointly satisfiable.
// It rejects constraint sets naming different resource_ids, and
// same-resource sets whose prefixes do not form a nested chain under the
// prefix relation. Individual constraints are also validated (non-empty
// resource_id within MaxIdentifierLengthBytes; well-formed path_prefix).
//
// Decoders do NOT call this — wire compatibility is not conditioned on
// issuance hygiene; verification denies unsatisfiable sets fail-closed.
func ValidateResourceConstraints(constraints []Constraint) error {
	var resourceID string
	var prefixes []string
	for i, c := range constraints {
		if c.Type != ConstraintResourcePath {
			continue
		}
		if c.ResourceID == "" {
			return fmt.Errorf("constraint[%d]: resource_path requires a non-empty resource_id", i)
		}
		if len(c.ResourceID) > MaxIdentifierLengthBytes {
			return fmt.Errorf("constraint[%d]: resource_id is %d bytes, exceeding MAX_IDENTIFIER_LENGTH_BYTES (%d)", i, len(c.ResourceID), MaxIdentifierLengthBytes)
		}
		if c.PathPrefix != "" {
			if _, err := NormalizeResourcePath(c.PathPrefix); err != nil {
				return fmt.Errorf("constraint[%d]: invalid path_prefix: %w", i, err)
			}
		}
		if resourceID == "" {
			resourceID = c.ResourceID
		} else if c.ResourceID != resourceID {
			return fmt.Errorf("constraint[%d]: certificate carries resource_path constraints naming different resource_ids — jointly unsatisfiable (SPEC §5.7.3); issue separate certificates", i)
		}
		for _, prev := range prefixes {
			if !resourcePathsNested(prev, c.PathPrefix) {
				return fmt.Errorf("constraint[%d]: same-resource path_prefix values %q and %q do not nest — jointly unsatisfiable (SPEC §5.7.3); narrow to one prefix or issue separate certificates", i, prev, c.PathPrefix)
			}
		}
		prefixes = append(prefixes, c.PathPrefix)
	}
	return nil
}

// ValidateParamsValue enforces the extension-constraint params value model
// (SPEC §5.7.1): null, booleans, strings, safe integers (|n| ≤ 2^53−1),
// and arrays/objects of these. Floats and non-integer numbers are
// prohibited; integers beyond the safe range travel as decimal strings.
// depth is the container nesting already consumed; nesting beyond
// MaxJSONNestingDepth is rejected.
func ValidateParamsValue(v any, depth int) error {
	if depth > MaxJSONNestingDepth {
		return fmt.Errorf("params nesting exceeds MAX_JSON_NESTING_DEPTH (%d)", MaxJSONNestingDepth)
	}
	switch val := v.(type) {
	case nil, bool, string:
		return nil
	case int:
		return validateSafeInt(int64(val))
	case int32:
		return validateSafeInt(int64(val))
	case int64:
		return validateSafeInt(val)
	case uint:
		return validateSafeUint(uint64(val))
	case uint32:
		return validateSafeUint(uint64(val))
	case uint64:
		return validateSafeUint(val)
	case float64:
		// JSON decoding yields float64 for every number. Integral values
		// within the safe range are integers on the wire; anything else is
		// outside the value model.
		if val != math.Trunc(val) || math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("params values must be safe integers, not floats (carry non-integers as strings)")
		}
		if math.Abs(val) > maxSafeInteger {
			return fmt.Errorf("params integer exceeds the safe-integer range; carry it as a decimal string")
		}
		return nil
	case float32:
		return ValidateParamsValue(float64(val), depth)
	case []any:
		for _, item := range val {
			if err := ValidateParamsValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range val {
			if err := ValidateParamsValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("params value of type %T is outside the restricted value model", v)
	}
}

func validateSafeInt(n int64) error {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return fmt.Errorf("params integer exceeds the safe-integer range; carry it as a decimal string")
	}
	return nil
}

func validateSafeUint(n uint64) error {
	if n > maxSafeInteger {
		return fmt.Errorf("params integer exceeds the safe-integer range; carry it as a decimal string")
	}
	return nil
}
