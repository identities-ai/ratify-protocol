package ratify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type annexAVectors struct {
	Clauses []struct {
		ID     string `json:"id"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	} `json:"clauses"`
	CanonicalJSON []struct {
		Name             string `json:"name"`
		InputB64         string `json:"input_b64"`
		InputIsCanonical bool   `json:"input_is_canonical"`
		Canonical        string `json:"canonical"`
	} `json:"canonical_json"`
	Rejections []struct {
		Name     string `json:"name"`
		InputB64 string `json:"input_b64"`
	} `json:"strict_decode_rejections"`
	Vocabulary struct {
		Canonical []string            `json:"canonical"`
		Sensitive []string            `json:"sensitive"`
		Wildcards map[string][]string `json:"wildcards"`
	} `json:"vocabulary"`
	ScopeValidation []struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		Valid  bool     `json:"valid"`
	} `json:"scope_validation"`
	ScopeExpansion []struct {
		Name     string   `json:"name"`
		Scopes   []string `json:"scopes"`
		Expanded []string `json:"expanded"`
	} `json:"scope_expansion"`
	ScopeIntersection []struct {
		Name      string     `json:"name"`
		Lists     [][]string `json:"lists"`
		Effective []string   `json:"effective"`
	} `json:"scope_intersection"`
}

func loadAnnexAVectors(t *testing.T) annexAVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testvectors", "v2", "annex-a.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f annexAVectors
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// annexStrictDecode is the v2 strict decode of SPEC-v2 §2.1 over the Annex A
// value model: strict wire JSON, then the restricted value model.
func annexStrictDecode(data []byte) (any, error) {
	if err := checkWireJSON(data, nil, nil, true); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := validateRatifyJSONValueV2(value); err != nil {
		return nil, err
	}
	return value, nil
}

// The copied v1 clauses in SPEC-v2-ANNEX-A.md are pinned: editing a clause
// without regenerating annex-a.json (and revising SPEC-v2) fails here, and
// later edits to SPEC.md cannot change v2 because the annex is the source.
func TestV2AnnexAClausesArePinned(t *testing.T) {
	f := loadAnnexAVectors(t)
	annex, err := os.ReadFile("SPEC-v2-ANNEX-A.md")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(annex), "\n")
	if len(f.Clauses) != 3 {
		t.Fatalf("want 3 pinned clauses, got %d", len(f.Clauses))
	}
	for _, c := range f.Clauses {
		begin := slices.Index(lines, "<!-- annex-a:begin "+c.ID+" -->")
		end := slices.Index(lines, "<!-- annex-a:end "+c.ID+" -->")
		if begin < 0 || end <= begin+1 {
			t.Fatalf("%s: markers missing", c.ID)
		}
		block := []byte(strings.Join(lines[begin+1:end], "\n"))
		sum := sha256.Sum256(block)
		if len(block) != c.Bytes || hex.EncodeToString(sum[:]) != c.SHA256 {
			t.Errorf("%s: %d bytes sha256 %x, want %d bytes %s", c.ID, len(block), sum, c.Bytes, c.SHA256)
		}
		// The annex table states the same digest.
		if !strings.Contains(string(annex), "`"+c.SHA256+"`") {
			t.Errorf("%s: digest not stated in the annex table", c.ID)
		}
	}
}

func TestV2AnnexACanonicalJSON(t *testing.T) {
	f := loadAnnexAVectors(t)
	if len(f.CanonicalJSON) == 0 || len(f.Rejections) == 0 {
		t.Fatal("no canonical JSON vectors")
	}
	for _, v := range f.CanonicalJSON {
		t.Run(v.Name, func(t *testing.T) {
			input, err := base64.StdEncoding.Strict().DecodeString(v.InputB64)
			if err != nil {
				t.Fatal(err)
			}
			value, err := annexStrictDecode(input)
			if err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			got, err := CanonicalJSON(value)
			if err != nil || string(got) != v.Canonical {
				t.Fatalf("canonical %q (%v), want %q", got, err, v.Canonical)
			}
			if err := validateCanonicalTransactionTermsV2([]byte(v.Canonical)); err != nil {
				t.Fatalf("expected canonical bytes rejected as non-canonical: %v", err)
			}
			isCanonical := validateCanonicalTransactionTermsV2(input) == nil
			if isCanonical != v.InputIsCanonical || isCanonical != bytes.Equal(input, got) {
				t.Fatalf("input canonical=%v, want %v", isCanonical, v.InputIsCanonical)
			}
		})
	}
	for _, v := range f.Rejections {
		t.Run("reject_"+v.Name, func(t *testing.T) {
			input, err := base64.StdEncoding.Strict().DecodeString(v.InputB64)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := annexStrictDecode(input); err == nil {
				t.Fatalf("%q accepted", input)
			}
		})
	}
}

func TestV2AnnexAScopeVocabulary(t *testing.T) {
	f := loadAnnexAVectors(t)
	if got := Vocabulary(); !slices.Equal(got, f.Vocabulary.Canonical) {
		t.Fatalf("vocabulary differs from Annex A:\n got %v\nwant %v", got, f.Vocabulary.Canonical)
	}
	sensitive := []string{}
	for _, s := range f.Vocabulary.Canonical {
		if IsSensitive(s) {
			sensitive = append(sensitive, s)
		}
		if err := ValidateScopesV2([]string{s}); err != nil {
			t.Errorf("canonical %s rejected: %v", s, err)
		}
	}
	if !slices.Equal(sensitive, f.Vocabulary.Sensitive) {
		t.Fatalf("sensitive set %v, want %v", sensitive, f.Vocabulary.Sensitive)
	}
	if len(f.Vocabulary.Wildcards) != len(scopeWildcards) {
		t.Fatalf("%d wildcards, want %d", len(scopeWildcards), len(f.Vocabulary.Wildcards))
	}
	for w, want := range f.Vocabulary.Wildcards {
		if got := ExpandScopes([]string{w}); !slices.Equal(got, want) {
			t.Errorf("%s expands to %v, want %v", w, got, want)
		}
		for _, s := range want {
			if IsSensitive(s) {
				t.Errorf("%s expands to sensitive %s", w, s)
			}
		}
	}
	for _, v := range f.ScopeValidation {
		if err := ValidateScopesV2(v.Scopes); (err == nil) != v.Valid {
			t.Errorf("validation %s: %v, want valid=%v", v.Name, err, v.Valid)
		}
	}
	for _, v := range f.ScopeExpansion {
		if got := ExpandScopes(v.Scopes); !slices.Equal(got, v.Expanded) {
			t.Errorf("expansion %s: %v, want %v", v.Name, got, v.Expanded)
		}
	}
	for _, v := range f.ScopeIntersection {
		if got := IntersectScopes(v.Lists...); !slices.Equal(got, v.Effective) {
			t.Errorf("intersection %s: %v, want %v", v.Name, got, v.Effective)
		}
	}
}
