package v2vectors

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

// shapeNegatives derives strict-shape negatives (SPEC-v2 §2.1) from one
// positive object of every kind. Each mutation spells a value that a lenient
// JSON decoder maps onto a Go, JavaScript, or Python value that encodes
// differently: an empty object for a required structure, null inside an array
// or for a non-nullable member, a byte string spelled as an array of
// numbers, and a member name that differs from the schema only by case or by
// Unicode case folding. Every one is malformed at decode. Arrays are walked
// through their first element only. An embedded transaction proof bundle is
// not walked, because mutating it first breaks its signed bundle hash, and
// constraint params are not walked, because extension params follow the
// general value model.
func (g *gen) shapeNegatives(n *negBuilder) {
	positives := g.objectsFile().(objectsFile)
	use := map[string]bool{
		"delegation_with_every_v2_constraint_shape": true,
		"proof_bundle_two_link_bound_context":       true,
		"revocation_list":                           true,
		"revocation_push":                           true,
		"key_rotation_genesis":                      true,
		"witness_entry_genesis":                     true,
		"transaction_receipt_two_parties":           true,
		"verification_receipt_allow_genesis":        true,
	}
	for _, o := range positives.Objects {
		if !use[o.Name] {
			continue
		}
		wire, err := base64.StdEncoding.DecodeString(o.WireB64)
		if err != nil {
			panic(err)
		}
		for _, s := range shapeMutations(parse(wire)) {
			n.add("strict_shape/"+s.name, o.Kind, s.mutation, canon(s.value), o.Verify, "malformed")
		}
	}
}

type shapeMutation struct {
	name, mutation string
	value          any
}

// shapeByteMembers are byte-string members short enough to spell as an
// array of numbers in a vector.
var shapeByteMembers = map[string]bool{
	"ed25519": true, "challenge": true, "delegation_digest": true, "session_context": true,
	"stream_id": true, "previous_receipt_hash": true, "prev_hash": true, "entry_data": true,
	"previous_statement_hash": true,
}

func shapeMutations(root any) []shapeMutation {
	var out []shapeMutation
	add := func(name, mutation string, apply func(any)) {
		clone := parse(canon(root))
		apply(clone)
		out = append(out, shapeMutation{name: name, mutation: mutation, value: clone})
	}
	type ref struct {
		path string
		get  func(any) map[string]any
	}
	objects := []ref{{"", func(v any) map[string]any { return v.(map[string]any) }}}
	for i := 0; i < len(objects); i++ {
		current := objects[i]
		object := current.get(root)
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == "proof_bundle" || key == "params" {
				continue
			}
			key, get := key, current.get
			path := strings.TrimPrefix(current.path+"."+key, ".")
			label := strings.NewReplacer(".", "_", "[0]", "_0").Replace(path)
			switch value := object[key].(type) {
			case map[string]any:
				add(label+"_empty_object", path+" = {}", func(v any) { get(v)[key] = map[string]any{} })
				objects = append(objects, ref{path, func(v any) map[string]any { return get(v)[key].(map[string]any) }})
			case []any:
				if len(value) == 0 {
					add(label+"_null_element", path+" = [null]", func(v any) { get(v)[key] = []any{nil} })
					continue
				}
				add(label+"_null_element", path+"[0] = null", func(v any) { get(v)[key].([]any)[0] = nil })
				if _, isObject := value[0].(map[string]any); isObject {
					add(label+"_0_empty_object", path+"[0] = {}", func(v any) { get(v)[key].([]any)[0] = map[string]any{} })
					objects = append(objects, ref{path + "[0]", func(v any) map[string]any { return get(v)[key].([]any)[0].(map[string]any) }})
				}
			case string:
				if !shapeByteMembers[key] {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil || len(decoded) > 64 {
					continue
				}
				add(label+"_number_array", path+" spelled as an array of byte values", func(v any) {
					items := make([]any, len(decoded))
					for i, b := range decoded {
						items[i] = num(int64(b))
					}
					get(v)[key] = items
				})
				if key == "ed25519" {
					add(label+"_null", path+" = null", func(v any) { get(v)[key] = nil })
				}
			}
		}
		if current.path == "" {
			// Member-name case at the top level: a renamed member, a
			// case-variant duplicate beside the real member, and a Unicode
			// case-folding variant (U+017F for "s", U+212A for "k").
			first := keys[0]
			upper := strings.ToUpper(first[:1]) + first[1:]
			add("member_name_case_renamed", fmt.Sprintf("member %q renamed %q", first, upper), func(v any) {
				m := v.(map[string]any)
				m[upper] = m[first]
				delete(m, first)
			})
			add("member_name_case_duplicate", fmt.Sprintf("member %q repeated as %q", first, upper), func(v any) {
				m := v.(map[string]any)
				m[upper] = m[first]
			})
			for _, key := range keys {
				folded := strings.NewReplacer("s", "ſ", "k", "K").Replace(key)
				if folded == key {
					continue
				}
				add("member_name_unicode_fold", fmt.Sprintf("member %q spelled %q (Unicode case folding)", key, folded), func(v any) {
					m := v.(map[string]any)
					m[folded] = m[key]
					delete(m, key)
				})
				break
			}
		} else if len(keys) > 0 && (current.path == firstNestedObjectPath(root) || strings.HasSuffix(current.path, "[0]")) {
			first := keys[0]
			upper := strings.ToUpper(first)
			get := current.get
			add(strings.NewReplacer(".", "_", "[0]", "_0").Replace(current.path)+"_member_name_case", fmt.Sprintf("nested member %s.%s renamed %q", current.path, first, upper), func(v any) {
				m := get(v)
				m[upper] = m[first]
				delete(m, first)
			})
		}
	}
	return out
}

// firstNestedObjectPath names the first nested object member of root in
// byte order, the one place a nested member-name case variant is tested.
func firstNestedObjectPath(root any) string {
	object := root.(map[string]any)
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := object[key].(map[string]any); ok {
			return key
		}
	}
	return ""
}
