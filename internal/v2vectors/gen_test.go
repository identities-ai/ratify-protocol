package v2vectors

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedV2VectorsMatchCommittedFiles fails if any committed vector file
// differs from deterministic generator output. Regenerate with
// `go run ./cmd/ratify-v2-vectors` only after reviewing the semantic change.
func TestGeneratedV2VectorsMatchCommittedFiles(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(Files) {
		t.Fatalf("generated %d files, want %d", len(files), len(Files))
	}
	for _, name := range Files {
		committed, err := os.ReadFile(filepath.Join("..", "..", "testvectors", "v2", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(committed, files[name]) {
			t.Errorf("%s differs from generator output", name)
		}
	}
}

// TestGenerateIsDeterministic guards against map-order or randomness leaks.
func TestGenerateIsDeterministic(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for name := range a {
		if !bytes.Equal(a[name], b[name]) {
			t.Errorf("%s is not deterministic", name)
		}
	}
}
