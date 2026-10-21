## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root — not in this directory.

### Protocol v2 (module path `/v2`)

Protocol v2 is published from the Go major-version module path
`github.com/identities-ai/ratify-protocol/v2`, on a separate `v2.0.0-alpha.N`
prerelease line:

```go
go get github.com/identities-ai/ratify-protocol/v2@v{{VERSION}}
```

```go
import ratify "github.com/identities-ai/ratify-protocol/v2"
```

`v{{VERSION}}` is the v2 version prepared in this tree; it is not a published tag until the release gates in SPEC-v2 §8 pass. See
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

### Protocol v1 (unchanged module path)

v1 stays at the original module path and its existing tags. Released v1 tags
are not moved or replaced, and `go get` on that path never resolves to v2.
The latest published v1 tag is `v1.0.0-alpha.20`:

```go
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.20
```

```go
import ratify "github.com/identities-ai/ratify-protocol"

result := ratify.Verify(&bundle, ratify.VerifyOptions{
    RequiredScope: "meeting:attend",
})
```

Because the two lines have different module paths, one Go build can require
both and import them side by side (for example as `ratifyv1` and `ratify`)
during the migration window.

**Source:** [`types.go`](https://github.com/identities-ai/ratify-protocol/blob/main/types.go), [`crypto.go`](https://github.com/identities-ai/ratify-protocol/blob/main/crypto.go), [`verify.go`](https://github.com/identities-ai/ratify-protocol/blob/main/verify.go), [`scope.go`](https://github.com/identities-ai/ratify-protocol/blob/main/scope.go), [`constraints.go`](https://github.com/identities-ai/ratify-protocol/blob/main/constraints.go)

**Why it's at the root:** Go modules are imported by their module path. Placing the Go code at the root means the import path is simply `github.com/identities-ai/ratify-protocol` (or `.../ratify-protocol/v2` for the v2 line) — clean and standard. The other SDKs live in `sdks/` because they are independent language implementations with their own package managers (npm, PyPI, crates.io).

## API added in v1 alpha.16

The following surface first shipped in the v1 alpha.16 release and is available in every later v1 release.

- **Resource-bound verification.** The `resource_path` constraint (`ConstraintResourcePath`, the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via `Constraint.ResourceID` and an optional `Constraint.PathPrefix`. At verify time the application supplies `VerifierContext.RequestedResourceID`, `VerifierContext.RequestedPath`, and `VerifierContext.HasResource` (SPEC §5.16); `Verify(bundle, VerifyOptions{Context: ...})` evaluates them. Helpers: `NormalizeResourcePath`, `ResourcePathMatches`, `ValidateResourceConstraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `OperationContextBytes`, `OperationContextHash`, `SessionContextBytes`, and `BuildSessionContext`; `VerifierContextHash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `EncodeVerificationReceipt` and `DecodeVerificationReceipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `VerifyStreamedTurnWithOptions` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** `Constraint.Params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `ValidateParamsValue`.
- **Deeper delegation chains.** `MaxDelegationChainDepth` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MaxProofBundleBytes`, `MaxScopesPerCert`, `MaxConstraintsPerCert`, `MaxScopeLengthBytes`, `MaxIdentifierLengthBytes`, `MaxAgentNameLengthBytes`, `MaxJSONNestingDepth`.
