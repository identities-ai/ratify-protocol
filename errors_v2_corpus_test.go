package ratify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// v2ClassAssertionMembers are the vector members whose string value is an
// expected SPEC-v2 §2.7 error class. outcomes entries end in "/<class>".
var v2ClassAssertionMembers = map[string]bool{
	"error_class": true, "expected_error_class": true, "expect_error_class": true, "expect": true, "device_error": true,
}

// TestV2CorpusAssertsEveryErrorClass fails if any class of the closed
// SPEC-v2 §2.7 list has no shared vector in testvectors/v2 that expects it,
// so a class can never be left to SDK-local tests alone.
func TestV2CorpusAssertsEveryErrorClass(t *testing.T) {
	listed := v2ListedErrorClasses(t)
	paths, err := filepath.Glob(filepath.Join("testvectors", "v2", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no vector files: %v", err)
	}
	seen := map[V2ErrorClass][]string{}
	var walk func(v any, file string)
	walk = func(v any, file string) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if s, ok := child.(string); ok && v2ClassAssertionMembers[k] && listed[V2ErrorClass(s)] {
					seen[V2ErrorClass(s)] = append(seen[V2ErrorClass(s)], file)
				}
				if k == "outcomes" {
					for _, o := range child.([]any) {
						s := o.(string)
						if i := strings.LastIndexByte(s, '/'); i >= 0 && listed[V2ErrorClass(s[i+1:])] {
							seen[V2ErrorClass(s[i+1:])] = append(seen[V2ErrorClass(s[i+1:])], file)
						}
					}
				}
				walk(child, file)
			}
		case []any:
			for _, child := range x {
				walk(child, file)
			}
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		walk(v, filepath.Base(path))
	}
	var missing []string
	for class := range listed {
		if len(seen[class]) == 0 {
			missing = append(missing, string(class))
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("no shared vector asserts these SPEC-v2 §2.7 classes: %v", missing)
	}
}
