package ratify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxSafeInteger is the interoperable bound for JSON integer wire fields
// (SPEC §6.2): IEEE-754's largest exact integer, 2^53-1. Binary signable
// representations use 64-bit fields, but a JSON integer outside this range
// does not survive a double-precision JSON parser, so strict wire
// acceptance rejects it.
const maxSafeInteger = 1<<53 - 1

// wireByteFields are the protocol byte-field member names: their values
// are base64-standard with padding on the wire, and strict acceptance
// requires the canonical encoding (no missing padding, no nonzero unused
// padding bits, no embedded whitespace).
var wireByteFields = map[string]bool{
	"bundle_hash":          true,
	"chain_hash":           true,
	"challenge":            true,
	"context_hash":         true,
	"ed25519":              true,
	"entry_data":           true,
	"mac":                  true,
	"ml_dsa_65":            true,
	"prev_hash":            true,
	"session_context":      true,
	"stream_id":            true,
	"terms_canonical_json": true,
}

// CheckWireJSON validates untrusted wire JSON before it is unmarshaled
// into protocol structs. It fails closed on defects that encoding/json
// would otherwise accept silently:
//
//   - invalid UTF-8 (encoding/json substitutes U+FFFD inside strings);
//   - a duplicated object key at any nesting depth, compared after string
//     escapes are decoded, so a Unicode-escaped spelling of a key collides
//     with its literal form (encoding/json keeps the last occurrence);
//   - an integer token outside the safe-integer range
//     [-(2^53-1), 2^53-1] (SPEC §6.2);
//   - trailing content after the first JSON document;
//   - non-canonical base64 in a protocol byte field (encoding/base64
//     otherwise tolerates nonzero unused padding bits and embedded
//     newlines).
//
// It does not unmarshal into structs and does not change the semantics of
// Verify for already-parsed inputs. Callers on an untrusted path pair it
// with a json.Decoder configured with DisallowUnknownFields, as the
// bundled CLI and reference verifier do.
func CheckWireJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("wire: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	// One frame per open container; keys is non-nil for objects. Inside an
	// object, tokens alternate key, value — expectKey tracks which side the
	// next token is on, and pendingKey remembers the member being read so
	// byte-field values can be validated.
	type frame struct {
		keys       map[string]bool
		expectKey  bool
		pendingKey string
	}
	var stack []*frame
	done := false // a complete top-level value has been consumed
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	valueSeen := func() {
		if f := top(); f != nil && f.keys != nil {
			f.expectKey = true
		} else if len(stack) == 0 {
			done = true
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("wire: invalid JSON: %w", err)
		}
		if done {
			return fmt.Errorf("wire: trailing data after JSON document")
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
				valueSeen()
			}
		case string:
			// Token returns keys with escapes already decoded, so the
			// duplicate comparison is on decoded key names.
			if f := top(); f != nil && f.keys != nil && f.expectKey {
				if f.keys[t] {
					return fmt.Errorf("wire: duplicate key %q in JSON object", t)
				}
				f.keys[t] = true
				f.pendingKey = t
				f.expectKey = false
			} else {
				if f := top(); f != nil && f.keys != nil && wireByteFields[f.pendingKey] {
					if err := checkCanonicalBase64(f.pendingKey, t); err != nil {
						return err
					}
				}
				valueSeen()
			}
		case json.Number:
			s := t.String()
			// Integer-formed tokens only; canonical floats (constraint
			// bounds) are out of scope for the integer domain.
			if !strings.ContainsAny(s, ".eE") {
				n, perr := strconv.ParseInt(s, 10, 64)
				if perr != nil || n > maxSafeInteger || n < -maxSafeInteger {
					return fmt.Errorf(
						"wire: integer %s outside the safe-integer range [-(2^53-1), 2^53-1]", s)
				}
			}
			valueSeen()
		default:
			valueSeen()
		}
	}
}

// checkWireIntegerDomain scans marshaled canonical bytes for integer
// tokens outside the safe-integer range (SPEC §6.2): the encoder side of
// the rule the decoders enforce. Float tokens (constraint bounds) are out
// of scope.
func checkWireIntegerDomain(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("canonical JSON: %w", err)
		}
		if n, ok := tok.(json.Number); ok {
			s := n.String()
			if !strings.ContainsAny(s, ".eE") {
				v, perr := strconv.ParseInt(s, 10, 64)
				if perr != nil || v > maxSafeInteger || v < -maxSafeInteger {
					return fmt.Errorf(
						"canonical JSON: integer %s outside the safe-integer range [-(2^53-1), 2^53-1]", s)
				}
			}
		}
	}
}

// checkCanonicalBase64 requires the canonical base64-standard encoding:
// Strict() rejects nonzero unused padding bits and missing padding; the
// re-encode comparison rejects embedded "\r"/"\n" (which encoding/base64
// otherwise skips silently), so decode(encode(x)) is byte-exact.
func checkCanonicalBase64(key, s string) error {
	decoded, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return fmt.Errorf("wire: field %q: malformed or non-canonical base64", key)
	}
	if base64.StdEncoding.EncodeToString(decoded) != s {
		return fmt.Errorf("wire: field %q: non-canonical base64", key)
	}
	return nil
}
