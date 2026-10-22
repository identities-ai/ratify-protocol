## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root, not in this directory.

### Protocol v2 (module path `/v2`)

Protocol v2 is published from the Go major-version module path
`github.com/identities-ai/ratify-protocol/v2`, on a separate prerelease line:

```go
go get github.com/identities-ai/ratify-protocol/v2@v{{VERSION}}
```

```go
import ratify "github.com/identities-ai/ratify-protocol/v2"
```

`v{{VERSION}}` is the v2 version prepared in this tree. It is a prerelease:
review so far is internal adversarial review, and external independent review
is a gate for `2.0.0`. v2 is not backward compatible with v1; see the upgrade
guide,
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

The v2 API in outline:

- **Keys and signing.** `GenerateHybridKeypair`, `KeyIDV2`, and one typed
  signer per object (`SignDelegationCertV2`, `SignProofBundleV2`, ...), each
  with a `...WithSigner` form that takes an external `SignerV2` (direct or
  external-mu mode). Every returned signature is verified before use.
- **Challenges.** `V2ChallengeIssuer.IssueChallengeV2` persists each challenge
  before it returns it; `LoadExpectedChallengeV2` loads the record for a
  presented challenge.
- **Verify, then release.** `VerifyProofBundleV2` returns a committed outcome
  that exposes no decision. `ReleaseV2Decision` verifies the signed receipt
  and the checkpoint acknowledgement and returns the only actionable value,
  `V2ReleasedDecision`; gate side effects on `Allowed(ctx, clock)`.
- **Status.** `NewV2StatusPublisher` / `NewV2StatusPublisherWithKey` sign
  status under a separate status key; the verifier applies signed evidence
  through `SecurityJournalV2` (`RecordSecurityKeyRoleV2`,
  `ConfigureStatusKeyEpochV2`, `ApplyRevocationListToJournalV2`, ...).
- **Constraints.** The closed v2 registry plus extension evaluator profiles
  registered with `NewConstraintEvaluatorRegistryV2`
  (`StandardMaxCountEvaluatorV2`, `StandardAllowedValuesEvaluatorV2`).
- **Part B interfaces** for the claim store, clock, receipt publisher,
  checkpoint, journal store and issuance store. Package
  `github.com/identities-ai/ratify-protocol/v2/v2reference` holds in-memory
  implementations for tests and examples only.

Runnable programs (quickstart, signed status, custom scope with the
`max_count/v1` profile, external signer) are in
[`examples/v2/go`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/go);
run one with `go run ./examples/v2/go/quickstart` from the repository root.

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
while you migrate. Choose the version at each boundary; a v2 verifier never
falls back to v1.

**Source:** [`types.go`](https://github.com/identities-ai/ratify-protocol/blob/main/types.go), [`crypto.go`](https://github.com/identities-ai/ratify-protocol/blob/main/crypto.go), [`verify.go`](https://github.com/identities-ai/ratify-protocol/blob/main/verify.go), [`scope.go`](https://github.com/identities-ai/ratify-protocol/blob/main/scope.go), [`constraints.go`](https://github.com/identities-ai/ratify-protocol/blob/main/constraints.go)

**Why it's at the root:** Go modules are imported by their module path. Placing the Go code at the root means the import path is simply `github.com/identities-ai/ratify-protocol` (or `.../ratify-protocol/v2` for the v2 line), which is clean and standard. The other SDKs live in `sdks/` because they are independent language implementations with their own package managers (npm, PyPI, crates.io).

## v1 API added in alpha.16

The following surface first shipped in the v1 alpha.16 release and is available in every later v1 release.

- **Resource-bound verification.** The `resource_path` constraint (`ConstraintResourcePath`, the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via `Constraint.ResourceID` and an optional `Constraint.PathPrefix`. At verify time the application supplies `VerifierContext.RequestedResourceID`, `VerifierContext.RequestedPath`, and `VerifierContext.HasResource` (SPEC §5.16); `Verify(bundle, VerifyOptions{Context: ...})` evaluates them. Helpers: `NormalizeResourcePath`, `ResourcePathMatches`, `ValidateResourceConstraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `OperationContextBytes`, `OperationContextHash`, `SessionContextBytes`, and `BuildSessionContext`; `VerifierContextHash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `EncodeVerificationReceipt` and `DecodeVerificationReceipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `VerifyStreamedTurnWithOptions` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** `Constraint.Params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `ValidateParamsValue`.
- **Deeper delegation chains.** `MaxDelegationChainDepth` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MaxProofBundleBytes`, `MaxScopesPerCert`, `MaxConstraintsPerCert`, `MaxScopeLengthBytes`, `MaxIdentifierLengthBytes`, `MaxAgentNameLengthBytes`, `MaxJSONNestingDepth`.
