// Command ratify-v2-rotation-vectors regenerates only
// testvectors/v2/key-rotation-signature.json. The generation logic now lives
// in internal/v2vectors so the complete corpus and this file share one
// deterministic source; cmd/ratify-v2-vectors regenerates every file.
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
		panic(err)
	}
	if err := os.MkdirAll("testvectors/v2", 0o755); err != nil {
		panic(err)
	}
	path := filepath.Join("testvectors/v2", "key-rotation-signature.json")
	if err := os.WriteFile(path, files["key-rotation-signature.json"], 0o644); err != nil {
		panic(err)
	}
	fmt.Println(path)
}
