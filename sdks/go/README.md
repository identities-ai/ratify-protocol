<!-- GENERATED FILE — do not edit directly.
     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.
     Regenerate: python3 scripts/gen-sdk-readmes.py -->
# Ratify Protocol Go SDK

**Go reference implementation of the Ratify Protocol: delegated-authority proofs for human-agent and agent-agent interactions.**

Hybrid signatures: every signature is Ed25519 plus ML-DSA-65 (NIST FIPS 204), and both must verify, so a forger has to break both algorithms.

Byte-identical interoperability with the TypeScript, Python, Rust, and C/C++ reference implementations. Validated against the **79 canonical test vectors** (Protocol v1) on every CI run. This package also implements Protocol v2 (version `2.0.0-beta.1`, a prerelease) and runs every file in the shared `testvectors/v2` corpus and the cross-SDK fixtures of every other SDK.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof without calling back to whoever issued it. In Protocol v2 the verifier then **releases** the decision: it is actionable only after the verifier's signed receipt has been acknowledged by an independent checkpoint.

For Protocol v1, beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec. Protocol v2 has its own session and stream binding, signed status, receipts, witness entries and key rotation; the SessionToken fast path, A2A mutual presentation, the HTTP and registry bindings, and the geo and speed constraints remain v1-only until Protocol 2.1.

- Protocol v1 spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Protocol v2 spec: [SPEC-v2.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC-v2.md), upgrade guide: [docs/PROTOCOL_V2_MIGRATION.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md)
- Runnable v2 examples in every SDK language: [examples/v2](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.ratifyprotocol.com](https://docs.ratifyprotocol.com)

## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root, not in this directory.

### Protocol v2 (module path `/v2`)

Protocol v2 is published from the Go major-version module path
`github.com/identities-ai/ratify-protocol/v2`, on a separate prerelease line:

```go
go get github.com/identities-ai/ratify-protocol/v2@v2.0.0-beta.1
```

```go
import ratify "github.com/identities-ai/ratify-protocol/v2"
```

`v2.0.0-beta.1` is the v2 version prepared in this tree. It is a prerelease:
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
The latest published v1 tag is `v1.0.0-alpha.21`:

```go
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.21
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
