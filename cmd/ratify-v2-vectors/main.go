// Command ratify-v2-vectors regenerates the shared Protocol v2 conformance
// corpus under testvectors/v2. Run it from the repository root:
//
//	go run ./cmd/ratify-v2-vectors
//
// Output is deterministic; TestGeneratedV2VectorsMatchCommittedFiles fails if
// a committed file differs from the generator output.
//
// With -hedged it writes only testvectors/v2/hedged-signatures.json, whose
// ML-DSA-65 signatures use fresh randomness and therefore differ on every
// run. Commit that file deliberately; it is never compared to generator
// output.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/identities-ai/ratify-protocol/v2/internal/v2vectors"
)

func main() {
	hedged := flag.Bool("hedged", false, "write only the non-reproducible hedged-signatures.json")
	flag.Parse()
	if err := os.MkdirAll(filepath.Join("testvectors", "v2"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *hedged {
		data, err := v2vectors.GenerateHedged()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path := filepath.Join("testvectors", "v2", v2vectors.HedgedFile)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(path)
		return
	}
	files, err := v2vectors.Generate()
	if err != nil {
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
