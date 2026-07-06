# Ratify Protocol — Go SDK

**Go reference implementation of the Ratify Protocol v1 — a cryptographic trust protocol for human-agent and agent-agent interactions as agents start to transact.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the TypeScript, Python, Rust, and C reference implementations. Validated against the **63 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), the SessionToken fast path (~95% less per-turn crypto — practical for live voice and video), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec, all covered by the 63 canonical fixtures.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Note on package layout

The Go SDK is the **reference implementation** and lives at the project root — not in this directory.

```go
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.10
```

```go
import ratify "github.com/identities-ai/ratify-protocol"

result := ratify.Verify(&bundle, ratify.VerifyOptions{
    RequiredScope: "meeting:attend",
})
```

**Source:** [`types.go`](https://github.com/identities-ai/ratify-protocol/blob/main/types.go), [`crypto.go`](https://github.com/identities-ai/ratify-protocol/blob/main/crypto.go), [`verify.go`](https://github.com/identities-ai/ratify-protocol/blob/main/verify.go), [`scope.go`](https://github.com/identities-ai/ratify-protocol/blob/main/scope.go), [`constraints.go`](https://github.com/identities-ai/ratify-protocol/blob/main/constraints.go)

**Why it's at the root:** Go modules are imported by their module path. Placing the Go code at the root means the import path is simply `github.com/identities-ai/ratify-protocol` — clean and standard. The other SDKs live in `sdks/` because they are independent language implementations with their own package managers (npm, PyPI, crates.io).
