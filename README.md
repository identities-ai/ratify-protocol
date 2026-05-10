# Ratify Protocol™

**A cryptographic trust protocol for human-agent and agent-agent interactions as agents start to transact.**

When a human authorizes an agent, when one agent transacts with another agent, or when a chain of delegation passes through intermediaries, Ratify produces a signed, verifiable proof that says exactly *who* authorized *what*, *within which bounds*, and *for how long*. Any party in the conversation can check that proof in under a millisecond, without trusting the agent or its vendor.

**Quantum-safe by design.** Every signature is hybrid: Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify. This defends against classical cryptanalytic advances on either algorithm and against quantum attacks via ML-DSA-65's lattice-based security. Bundles signed today remain unforgeable even when cryptographically-relevant quantum computers exist.

JSON wire format. No blockchain. No tokens. Open spec under CC-BY-4.0.

**Status:** main branch after v1.0.0-alpha.5 — reference implementation complete, 59 canonical test vectors, cross-language interop proven (Go + TypeScript + Python + Rust). Patent Pending.

Maintained by Identities AI, Inc. Identities AI, Inc. owns the Ratify Protocol™ trademark and the patent-pending invention.

---

## The three verbs

```
  DELEGATE                PRESENT                  VERIFY
  ────────                ───────                  ──────
  Principal signs a       Presenter (agent)        Any third party
  DelegationCert          carries the cert         runs the verifier.
  naming the subject      and signs a fresh        Both Ed25519 and
  and the scopes.         challenge on every       ML-DSA-65 must
  Human-to-agent or       interaction.             verify. Yes/no in
  agent-to-agent.                                   <1ms. No trust
                                                    required.
```

Symmetric in both directions. A human delegating to an AI agent and one AI agent sub-delegating to another use the exact same primitive, the same verifier algorithm, and the same cryptographic guarantees.

## Quickstart — run the full flow in 60 seconds

### Go

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol
go test ./...                            # unit tests + 59 conformance fixtures
go run ./cmd/ratify-testvectors          # regenerate test vectors deterministically
```

### TypeScript

```bash
cd sdks/typescript
npm install
npm run test:conformance                 # 59/59 fixtures pass
```

### End-to-end human → agent → verifier demo

```bash
# 1. DELEGATOR: create a root identity
mkdir -p /tmp/demo
go build -o /tmp/demo/ratify ./cmd/ratify
HOME=/tmp/demo /tmp/demo/ratify init

# 2. AGENT: generate a hybrid keypair (on its machine)
# In this demo, we run it in the same folder for simplicity.
# This produces agent-pubkey.json (public) and agent.priv (private).
cd /tmp/demo && HOME=/tmp/demo ./ratify agent-init

# 3. DELEGATOR: sign a delegation cert for the agent
cd /tmp/demo && HOME=/tmp/demo ./ratify delegate \
  --agent-pubkey-file agent-pubkey.json \
  --scope "meeting:attend,meeting:speak" \
  --days 7 --out delegation.json
```

For a **complete bash-only end-to-end demo** (Alice → cert → agent → bundle → verifier), see [`docs/TESTING.md`](docs/TESTING.md) §3. For **narrative demos in each language** (Python, Go, TypeScript, Rust) that print the full lifecycle with attack rejections, see [`demos/`](demos/). For **real HTTP wire-protocol testing** with a minimal reference verifier server, see [`docs/TESTING.md`](docs/TESTING.md) §4.

## Repository layout

```
ratify-protocol/
├── SPEC.md                      Normative protocol specification
├── README.md                    This file
├── LICENSE                      Apache-2.0 (for code)
├── docs/LICENSES.md             CC-BY-4.0 (for SPEC.md text)
├── SECURITY.md                  Disclosure policy
├── CONTRIBUTING.md              How to contribute
├── CODE_OF_CONDUCT.md
│
├── types.go                     Data structures
├── crypto.go                    Hybrid Ed25519 + ML-DSA-65 primitives + canonical JSON
├── scope.go                     Canonical scope vocabulary + intersect/expand
├── verify.go                    The verifier
├── ratify_test.go               Unit tests + conformance-suite loader
├── go.mod
│
├── cmd/
│   ├── ratify/                  Human-side CLI (init, delegate, verify, ...)
│   └── ratify-testvectors/      Deterministic test-vector generator
│
├── testvectors/
│   └── v1/                      59 canonical fixtures (JSON)
│
├── sdks/
│   ├── typescript/              @identitiesai/ratify-protocol (npm)
│   ├── python/                  ratify-protocol (PyPI)
│   └── rust/                    ratify-protocol (crates.io)
│
├── cmd/
│   ├── ratify/                  ratify-cli (init, delegate, agent-init,
│   │                            agent-bundle, challenge, verify, scopes)
│   ├── ratify-testvectors/      Deterministic fixture generator
│   └── ratify-verifier/         Minimal HTTP reference verifier
│
├── demos/                       End-to-end narrative demos in all four
│   ├── python/    go/    typescript/    rust/    languages + README
│
└── docs/
    ├── AGENT_TO_AGENT.md        Canonical A2A patterns (mutual, sub-delegation, receipt)
    ├── EXPLAINED.md             Architecture + threat model + real-time patterns
    ├── RELEASES.md              Release process + versioning + cross-SDK sync
    ├── ROADMAP.md               v1.1 / v2 gaps (continuous streams, tamper-evidence)
    ├── SDKS.md                  SDK roadmap + conformance contract for new languages
    ├── TESTING.md               Internal testing guide — four levels from lib to HTTP
    ├── TEST_PLAN.md             Testing methodology + conformance suite
    └── TRANSACTION_RECEIPTS.md   v1.1 receipt envelope design
```

## Why this exists

Today an AI agent can call your company, join your meeting, or send your email, and the receiving party has no cryptographic way to verify that claim of authorization. Trust reduces to *"the AI says so."* As synthesis gets cheaper and agents proliferate, that is a foundation that cannot hold.

Ratify is one primitive — a signed delegation cert plus a fresh challenge signature — that replaces *"the AI says so"* with a yes/no cryptographic check any verifier can run.

Read [`docs/EXPLAINED.md`](docs/EXPLAINED.md) for the full architecture, threat model, and real-time workflow patterns. Read [`SPEC.md`](SPEC.md) for the normative protocol.

## Interoperability

The 59 fixtures in `testvectors/v1/` are the canonical conformance set. Any implementation in any language that passes all 59 is byte-for-byte interoperable with the reference. C / C++ support is part of the roadmap via a stable C ABI for embedded verifiers, appliance vendors, and other systems that need a native library boundary. Currently proven:

| Implementation | Language | Status |
|---|---|---|
| `github.com/identities-ai/ratify-protocol` | Go | ✅ 59/59 |
| `@identitiesai/ratify-protocol` (`sdks/typescript`) | TypeScript | ✅ 59/59 |
| `ratify-protocol` (`sdks/python`) | Python | ✅ 59/59 |
| `ratify-protocol` (`sdks/rust`) | Rust | ✅ 59/59 |
| *C / C++ via C ABI* | — | planned (embedded systems / appliances) |
| *Swift* | — | planned (mobile wallet) |
| *Java / Kotlin* | — | planned (Android / JVM) |

If you're implementing a new language port, start from the fixtures. See [`docs/SDKS.md`](docs/SDKS.md) for the conformance contract and [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) for testing methodology.

## Security

- **Quantum-safe in v1.** Every signature is hybrid Ed25519 (RFC 8032) + ML-DSA-65 (NIST FIPS 204). Both must verify. Harvest-now-decrypt-later attacks against bundles signed today remain infeasible under known quantum algorithms.
- External audit planned before v1.0.0 stable (Trail of Bits / NCC / Cure53).
- Responsible-disclosure policy: [`SECURITY.md`](SECURITY.md).
- Threat model: [`docs/EXPLAINED.md`](docs/EXPLAINED.md) §5.

## License

Code under Apache-2.0. Specification text under CC-BY-4.0. See `LICENSE` and `docs/LICENSES.md`.

Ratify Protocol™ and Identities AI™ are trademarks or service marks of Identities AI, Inc. Patent Pending.

## Maintainers

Identities AI. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for participation and the governance plan.
