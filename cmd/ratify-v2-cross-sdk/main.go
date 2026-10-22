// Command ratify-v2-cross-sdk writes the Go cross-SDK fixture of SPEC-v2
// §8.1. Run it from the repository root:
//
//	go run ./cmd/ratify-v2-cross-sdk -out testvectors/v2/cross-sdk/go.json
//
// Every run generates fresh random keys and hedged ML-DSA-65 signatures, so
// the output differs on each run by design. The fixture is verified with the
// Go reference before it is written; commit it deliberately.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/identities-ai/ratify-protocol/v2/internal/v2vectors"
)

func main() {
	out := flag.String("out", filepath.Join("testvectors", "v2", v2vectors.CrossSDKDir, "go.json"), "output path")
	version := flag.String("sdk-version", "2.0.0-alpha.1+dev", "SDK version recorded in the fixture")
	flag.Parse()
	data, err := v2vectors.GenerateCrossSDK(*version, "go run ./cmd/ratify-v2-cross-sdk (Go reference, module github.com/identities-ai/ratify-protocol/v2)")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(*out)
}
