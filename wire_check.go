package ratify

import (
	"bytes"
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

// CheckWireJSON validates untrusted wire JSON before it is unmarshaled
// into protocol structs. It fails closed on defects that encoding/json
// would otherwise accept silently:
//
//   - invalid UTF-8 (encoding/json substitutes U+FFFD inside strings);
//   - a duplicated object key at any nesting depth, compared after string
//     escapes are decoded, so a Unicode-escaped spelling of a key collides
//     with its literal form (encoding/json keeps the last occurrence);
//   - an integer token outside the safe-integer range
//     [-(2^53-1), 2^53-1] (SPEC §6.2).
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
	// next token is on.
	type frame struct {
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	top := func() *frame {
		if len(stack) == 0 {
			return nil
		}
		return stack[len(stack)-1]
	}
	valueSeen := func() {
		if f := top(); f != nil && f.keys != nil {
			f.expectKey = true
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
				f.expectKey = false
			} else {
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
