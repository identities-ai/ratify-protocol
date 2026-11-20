// Command ratify-mcp-vectors regenerates the Verify MCP signer vectors under
// testvectors/v2/mcp. Run it from the repository root:
//
//	go run ./cmd/ratify-mcp-vectors
//
// Output is deterministic; TestGeneratedMCPVectorsMatchCommittedFiles fails
// if a committed file differs from the generator output.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/identities-ai/ratify-protocol/v2/internal/mcpvectors"
)

func main() {
	dir := filepath.Join("testvectors", "v2", "mcp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	files, err := mcpvectors.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, name := range mcpvectors.Files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, files[name], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(path)
	}
}
