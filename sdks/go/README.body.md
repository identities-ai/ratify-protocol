## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root — not in this directory.

```go
go get github.com/identities-ai/ratify-protocol@{{VERSION_TAG}}
```

```go
import ratify "github.com/identities-ai/ratify-protocol"

result := ratify.Verify(&bundle, ratify.VerifyOptions{
    RequiredScope: "meeting:attend",
})
```

**Source:** [`types.go`](https://github.com/identities-ai/ratify-protocol/blob/main/types.go), [`crypto.go`](https://github.com/identities-ai/ratify-protocol/blob/main/crypto.go), [`verify.go`](https://github.com/identities-ai/ratify-protocol/blob/main/verify.go), [`scope.go`](https://github.com/identities-ai/ratify-protocol/blob/main/scope.go), [`constraints.go`](https://github.com/identities-ai/ratify-protocol/blob/main/constraints.go)

**Why it's at the root:** Go modules are imported by their module path. Placing the Go code at the root means the import path is simply `github.com/identities-ai/ratify-protocol` — clean and standard. The other SDKs live in `sdks/` because they are independent language implementations with their own package managers (npm, PyPI, crates.io).

## API added on main (ships in alpha.16, release unpublished)

The following surface is merged to `main` and ships in alpha.16. The tag is not yet published; pin to `main` to use it ahead of the release.

- **Resource-bound verification.** The `resource_path` constraint (`ConstraintResourcePath`, the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via `Constraint.ResourceID` and an optional `Constraint.PathPrefix`. At verify time the application supplies `VerifierContext.RequestedResourceID`, `VerifierContext.RequestedPath`, and `VerifierContext.HasResource` (SPEC §5.16); `Verify(bundle, VerifyOptions{Context: ...})` evaluates them. Helpers: `NormalizeResourcePath`, `ResourcePathMatches`, `ValidateResourceConstraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `OperationContextBytes`, `OperationContextHash`, `SessionContextBytes`, and `BuildSessionContext`; `VerifierContextHash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `EncodeVerificationReceipt` and `DecodeVerificationReceipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `VerifyStreamedTurnWithOptions` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** `Constraint.Params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `ValidateParamsValue`.
- **Deeper delegation chains.** `MaxDelegationChainDepth` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MaxProofBundleBytes`, `MaxScopesPerCert`, `MaxConstraintsPerCert`, `MaxScopeLengthBytes`, `MaxIdentifierLengthBytes`, `MaxAgentNameLengthBytes`, `MaxJSONNestingDepth`.
