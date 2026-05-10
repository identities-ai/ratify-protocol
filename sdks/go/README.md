# Go SDK

The Go SDK is the **reference implementation** and lives at the project root — not in this directory.

```go
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.5
```

```go
import ratify "github.com/identities-ai/ratify-protocol"

result := ratify.Verify(&bundle, ratify.VerifyOptions{
    RequiredScope: "meeting:attend",
})
```

**Source:** [`types.go`](../../types.go), [`crypto.go`](../../crypto.go), [`verify.go`](../../verify.go), [`scope.go`](../../scope.go), [`constraints.go`](../../constraints.go)

**Tests:** [`ratify_test.go`](../../ratify_test.go), [`fuzz_test.go`](../../fuzz_test.go)

**Why it's at the root:** Go modules are imported by their module path. Placing the Go code at the root means the import path is simply `github.com/identities-ai/ratify-protocol` — clean and standard. The other SDKs live in `sdks/` because they are independent language implementations with their own package managers (npm, PyPI, crates.io).
