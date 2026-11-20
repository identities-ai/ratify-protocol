package mcpvectors

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Every SDK reproduces these files byte for byte, so a committed file that
// drifts from the generator would make the SDKs agree on a stale contract.
// Regenerate with `go run ./cmd/ratify-mcp-vectors` only after reviewing the
// change.
func TestGeneratedMCPVectorsMatchCommittedFiles(t *testing.T) {
	files, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "testvectors", "v2", "mcp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var present []string
	for _, e := range entries {
		present = append(present, e.Name())
	}
	want := append([]string{"README.md"}, Files...)
	sort.Strings(want)
	if len(present) != len(want) {
		t.Fatalf("testvectors/v2/mcp holds %v, want %v", present, want)
	}
	for i := range want {
		if present[i] != want[i] {
			t.Fatalf("testvectors/v2/mcp holds %v, want %v", present, want)
		}
	}
	for _, name := range Files {
		committed, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(committed, files[name]) {
			t.Errorf("%s differs from generator output", name)
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Files {
		if !bytes.Equal(a[name], b[name]) {
			t.Errorf("%s is not deterministic", name)
		}
	}
}
