package mcp

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalidArguments means the tool arguments are not a JSON object under
// the restricted value model. Nothing is signed for such a call.
var ErrInvalidArguments = errors.New("mcp: invalid tool arguments")

// MaxArgumentDepth is the deepest nesting a value may have: the arguments
// object is depth 0 and each enclosing object or array adds one.
const MaxArgumentDepth = 4

const maxSafeInteger = 1<<53 - 1

// CanonicalArguments parses the JSON text of params.arguments under the
// restricted value model and returns its canonical bytes. The model allows
// objects with unique keys, strings, integers in the safe range (no
// fraction, exponent, or negative zero), booleans, and arrays, nested at
// most MaxArgumentDepth deep. Strings and keys must be valid UTF-8 without
// control characters (U+0000 to U+001F, U+007F to U+009F), U+2028, U+2029,
// or unpaired surrogate escapes. Empty input, whitespace, and the literal
// null mean the empty object.
//
// Canonical form: object keys sorted by their UTF-8 bytes, no insignificant
// whitespace, strings with only '"' and '\' escaped, integers in decimal.
func CanonicalArguments(raw []byte) ([]byte, error) {
	trimmed := bytes.Trim(raw, " \t\r\n")
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return []byte("{}"), nil
	}
	p := &argParser{in: raw}
	p.space()
	if p.pos >= len(p.in) || p.in[p.pos] != '{' {
		return nil, ErrInvalidArguments
	}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.in) {
		return nil, ErrInvalidArguments
	}
	var out bytes.Buffer
	writeArg(&out, v)
	return out.Bytes(), nil
}

type argObject struct {
	keys   []string
	values map[string]any
}

type argParser struct {
	in  []byte
	pos int
}

func (p *argParser) space() {
	for p.pos < len(p.in) {
		switch p.in[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *argParser) literal(word string) bool {
	if bytes.HasPrefix(p.in[p.pos:], []byte(word)) {
		p.pos += len(word)
		return true
	}
	return false
}

func (p *argParser) value(depth int) (any, error) {
	if depth > MaxArgumentDepth {
		return nil, ErrInvalidArguments
	}
	p.space()
	if p.pos >= len(p.in) {
		return nil, ErrInvalidArguments
	}
	switch c := p.in[p.pos]; {
	case c == '{':
		p.pos++
		obj := &argObject{values: map[string]any{}}
		p.space()
		if p.pos < len(p.in) && p.in[p.pos] == '}' {
			p.pos++
			return obj, nil
		}
		for {
			p.space()
			key, err := p.str()
			if err != nil {
				return nil, err
			}
			if _, dup := obj.values[key]; dup {
				return nil, ErrInvalidArguments
			}
			p.space()
			if p.pos >= len(p.in) || p.in[p.pos] != ':' {
				return nil, ErrInvalidArguments
			}
			p.pos++
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj.keys = append(obj.keys, key)
			obj.values[key] = child
			p.space()
			if p.pos >= len(p.in) {
				return nil, ErrInvalidArguments
			}
			if p.in[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.in[p.pos] == '}' {
				p.pos++
				return obj, nil
			}
			return nil, ErrInvalidArguments
		}
	case c == '[':
		p.pos++
		list := []any{}
		p.space()
		if p.pos < len(p.in) && p.in[p.pos] == ']' {
			p.pos++
			return list, nil
		}
		for {
			child, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, child)
			p.space()
			if p.pos >= len(p.in) {
				return nil, ErrInvalidArguments
			}
			if p.in[p.pos] == ',' {
				p.pos++
				continue
			}
			if p.in[p.pos] == ']' {
				p.pos++
				return list, nil
			}
			return nil, ErrInvalidArguments
		}
	case c == '"':
		return p.str()
	case c == 't':
		if p.literal("true") {
			return true, nil
		}
	case c == 'f':
		if p.literal("false") {
			return false, nil
		}
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return nil, ErrInvalidArguments
}

// number accepts only the JSON integer grammar: -?(0|[1-9][0-9]*).
func (p *argParser) number() (any, error) {
	start := p.pos
	if p.in[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.in) {
		return nil, ErrInvalidArguments
	}
	if p.in[p.pos] == '0' {
		p.pos++
	} else if p.in[p.pos] >= '1' && p.in[p.pos] <= '9' {
		for p.pos < len(p.in) && p.in[p.pos] >= '0' && p.in[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return nil, ErrInvalidArguments
	}
	if p.pos < len(p.in) {
		switch p.in[p.pos] {
		case '.', 'e', 'E':
			return nil, ErrInvalidArguments
		}
	}
	text := string(p.in[start:p.pos])
	if text == "-0" || len(text) > 17 {
		return nil, ErrInvalidArguments
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
		return nil, ErrInvalidArguments
	}
	return n, nil
}

func (p *argParser) hex4() (rune, bool) {
	if p.pos+4 > len(p.in) {
		return 0, false
	}
	var r rune
	for _, c := range p.in[p.pos : p.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	p.pos += 4
	return r, true
}

func (p *argParser) str() (string, error) {
	if p.pos >= len(p.in) || p.in[p.pos] != '"' {
		return "", ErrInvalidArguments
	}
	p.pos++
	var out []byte
	for {
		if p.pos >= len(p.in) {
			return "", ErrInvalidArguments
		}
		c := p.in[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.in) {
				return "", ErrInvalidArguments
			}
			e := p.in[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return "", ErrInvalidArguments
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xdc00 || !p.literal(`\u`) {
						return "", ErrInvalidArguments
					}
					low, ok := p.hex4()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return "", ErrInvalidArguments
					}
					r = utf16.DecodeRune(r, low)
				}
				if !allowedRune(r) {
					return "", ErrInvalidArguments
				}
				out = utf8.AppendRune(out, r)
			default:
				// \b \f \n \r \t decode to control characters, which the
				// model refuses; any other escape is not JSON.
				return "", ErrInvalidArguments
			}
		default:
			r, size := utf8.DecodeRune(p.in[p.pos:])
			if r == utf8.RuneError && size <= 1 {
				return "", ErrInvalidArguments
			}
			if !allowedRune(r) {
				return "", ErrInvalidArguments
			}
			out = append(out, p.in[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

func allowedRune(r rune) bool {
	return !(r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || utf16.IsSurrogate(r))
}

func writeArg(out *bytes.Buffer, v any) {
	switch t := v.(type) {
	case *argObject:
		keys := append([]string(nil), t.keys...)
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeArgString(out, k)
			out.WriteByte(':')
			writeArg(out, t.values[k])
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				out.WriteByte(',')
			}
			writeArg(out, item)
		}
		out.WriteByte(']')
	case string:
		writeArgString(out, t)
	case int64:
		out.WriteString(strconv.FormatInt(t, 10))
	case bool:
		out.WriteString(strconv.FormatBool(t))
	}
}

func writeArgString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			out.WriteByte('\\')
		}
		out.WriteByte(s[i])
	}
	out.WriteByte('"')
}
