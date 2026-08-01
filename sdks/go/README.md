<!-- GENERATED FILE — do not edit directly.
     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.
     Regenerate: python3 scripts/gen-sdk-readmes.py -->
# Ratify Protocol — Go SDK

**Go reference implementation of the Ratify Protocol v1 — delegated-authority proofs for human-agent and agent-agent interactions.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the TypeScript, Python, Rust, and C/C++ reference implementations. Validated against the **79 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1 — practical for live voice and video) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root — not in this directory.

```go
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.15
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
