// Command ratify-v2-vectors regenerates the shared Protocol v2 conformance
// corpus under testvectors/v2. Run it from the repository root:
//
//	go run ./cmd/ratify-v2-vectors
//
// Output is deterministic; TestGeneratedV2VectorsMatchCommittedFiles fails if
// a committed file differs from the generator output.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/identities-ai/ratify-protocol/v2/internal/v2vectors"
)

func main() {
	files, err := v2vectors.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join("testvectors", "v2"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, name := range v2vectors.Files {
		path := filepath.Join("testvectors", "v2", name)
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(path)
	}
}
