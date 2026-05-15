<p align="center">
  <img src="assets/ratify-protocol-logo.png" alt="Ratify Protocol" width="160" height="160" />
</p>

<h1 align="center">Ratify Protocol™</h1>

<p align="center">
  <em>A cryptographic trust protocol for human-to-agent and agent-to-agent interactions.</em>
</p>

[![CI](https://github.com/identities-ai/ratify-protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/identities-ai/ratify-protocol/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/identities-ai/ratify-protocol?include_prereleases&sort=semver&color=blue)](https://github.com/identities-ai/ratify-protocol/releases)
[![License: Apache 2.0](https://img.shields.io/badge/code-Apache--2.0-green.svg)](LICENSE)
[![Spec: CC BY 4.0](https://img.shields.io/badge/spec-CC--BY--4.0-lightgrey.svg)](docs/LICENSES.md)
[![Patent Pending](https://img.shields.io/badge/patent-pending-orange.svg)](#license--trademarks--patent)

[![Go Reference](https://pkg.go.dev/badge/github.com/identities-ai/ratify-protocol.svg)](https://pkg.go.dev/github.com/identities-ai/ratify-protocol)
[![PyPI](https://img.shields.io/pypi/v/ratify-protocol?label=pypi&color=informational)](https://pypi.org/project/ratify-protocol/)
[![Crates.io](https://img.shields.io/crates/v/ratify-protocol?label=crates.io)](https://crates.io/crates/ratify-protocol)
[![npm](https://img.shields.io/npm/v/@identities-ai/ratify-protocol?label=npm&color=informational)](https://www.npmjs.com/package/@identities-ai/ratify-protocol)

When a human authorizes an AI agent — or when one agent transacts with another agent — Ratify produces a signed, verifiable proof that says exactly *who* authorized *what*, *within which bounds*, and *for how long*. Any party in the conversation can check that proof in under a millisecond, across voice, video, API, and Physical AI.

**Quantum-safe by design.** Every signature is hybrid: Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify. Bundles signed today remain unforgeable even when cryptographically-relevant quantum computers exist.

JSON wire format. No blockchain. No tokens. No central issuer. Open spec under CC-BY-4.0.

**Status:** `v1.0.0-alpha.8` · reference implementation complete · 59 canonical test vectors · cross-language interop proven (Go + TypeScript + Python + Rust + C/C++) · Patent Pending.

Maintained by Identities AI, Inc. Ratify Protocol™ and identities.ai™ are trademarks of Identities AI, Inc.

---

## Table of contents

- [The mental model](#the-mental-model)
- [The three verbs](#the-three-verbs)
- [How the bytes flow](#how-the-bytes-flow)
- [60-second install + verify](#60-second-install--verify)
- [End-to-end demo — see the full protocol run](#end-to-end-demo--see-the-full-protocol-run)
- [What's actually happening (read this once)](#whats-actually-happening-read-this-once)
- [Cross-language interop](#cross-language-interop)
- [Where to go next](#where-to-go-next)
- [Repository layout](#repository-layout)
- [Security](#security)
- [License + trademarks + patent](#license--trademarks--patent)

---

## The mental model

The protocol replaces *"the AI says so"* with *"prove it."*

Today, when an AI agent shows up — joining a meeting, calling your support line, sending an email, executing a trade on your behalf — the receiving party has no cryptographic way to verify three things:

1. **Who** authorized this agent to act?
2. **What** is this agent allowed to do?
3. **For how long** is that authority valid?

Ratify answers those three questions with a single primitive — a signed delegation certificate paired with a fresh challenge signature — that any verifier can check **offline, in under a millisecond, with no live call to a central authority.**

Same primitive works for humans authorizing agents *and* agents sub-authorizing other agents. Same verifier algorithm in every direction. That symmetry is what makes Ratify a *protocol* rather than a product.

---

## The three verbs

```
   DELEGATE                  PRESENT                   VERIFY
   ────────                  ───────                   ──────
   Principal signs a         Presenter (agent)         Any third party
   DelegationCert            carries the cert          runs the verifier.
   naming the subject,       and signs a fresh         Both Ed25519 AND
   the scopes, and the       challenge on every        ML-DSA-65 must
   expiration.               interaction.              verify. Yes/no
                                                       in <1ms. No trust
   Human → Agent OR          Proves "this key is       relationship with
   Agent → Agent.            live right now."          presenter required.
```

Symmetric in both directions. A human delegating to an AI agent and one AI agent sub-delegating to another use the **exact same primitive**, the **same verifier algorithm**, and the **same cryptographic guarantees**.

---

## How the bytes flow

Concrete picture of one full interaction:

```
                  ┌───────────────────────────────────┐
                  │   Alice (Principal)               │
                  │                                   │
                  │   Holds: Hybrid private key       │
                  │   ▸ Ed25519 + ML-DSA-65           │
                  │   Key never leaves Alice's        │
                  │   device.                         │
                  └───────────────┬───────────────────┘
                                  │
                                  │ 1. signs DelegationCert {
                                  │      issuer:    Alice
                                  │      subject:   Agent-A
                                  │      scope:     ["meeting:attend"]
                                  │      expires:   +7 days
                                  │      hybrid signature
                                  │    }
                                  ▼
                  ┌───────────────────────────────────┐
                  │   Agent-A (Subject)               │
                  │                                   │
                  │   Holds: Cert + own hybrid key    │
                  └───────────────┬───────────────────┘
                                  │
                                  │ 3. presents ProofBundle {
                                  │      delegations: [cert]
                                  │      challenge:   nonce-from-verifier
                                  │      challenge_sig: hybrid signature
                                  │                     over (nonce, time)
                                  │    }
                                  ▼
                  ┌───────────────────────────────────┐
   2. issues      │   Verifier (Zoom / your API /     │
   challenge ───▶ │   any third party)                │
                  │                                   │
                  │   ✓ both signatures verify        │
                  │   ✓ cert not expired              │
                  │   ✓ challenge fresh (<5 min)      │
                  │   ✓ scope covers requested action │
                  │   ✓ cert not revoked              │
                  │                                   │
                  │   → YES / NO in <1ms              │
                  └───────────────────────────────────┘
```

**What's not in the picture (and why that matters):** no central authority is consulted at verify time. The verifier needs only Alice's **public** key to check everything above. No OAuth introspection endpoint, no token registry call, no network hop. That is what makes Ratify deployable in offline environments (drones, vehicles, edge inference) and at internet scale (every Zoom call, every API call, every voice interaction).

For sub-delegation (Agent-A authorizing Agent-B), the bundle just carries **two certs**, and the verifier checks each link in the chain plus the scope intersection. Same verifier algorithm.

---

## 60-second install + verify

Pick your language. Each one runs the full 59-fixture conformance suite — the same fixtures every other SDK passes byte-for-byte. If you see "all passing," you've proven cross-language interop **on your own machine.**

### Go

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol
go test ./...
# → ok  github.com/identities-ai/ratify-protocol  0.5s
```

Or install as a module in your own project:

```bash
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.8
```

### TypeScript

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/typescript
npm install
npm run test:conformance
# → 59/59 fixtures pass
```



### Python

```bash
pip install ratify-protocol==1.0.0a8
```

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/python
pip install -e '.[dev]'
pytest
# → 59 passed
```

### Rust

```bash
cargo add ratify-protocol@1.0.0-alpha.8
```

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/rust
cargo test
# → test result: ok. 1 passed (loads all 59 fixtures)
```

---

## End-to-end demo — see the full protocol run

The conformance suite proves *the bytes are correct*. The demos prove *the protocol does what it claims.* Each runs the same nine-scenario narrative — five positive (authorized → verified), four negative (tampered / out-of-scope / expired / revoked) — and prints what happened and why.

| Language | Run from repo root |
|---|---|
| Go | `go run ./demos/go` |
| Python | `cd sdks/python && pip install -e . && cd ../.. && python demos/python/demo.py` |
| TypeScript | `cd sdks/typescript && npm install && npm run build && cd ../../demos/typescript && npm install && npm run demo` |
| Rust | `cargo run --manifest-path demos/rust/Cargo.toml` |

What you'll see (abbreviated):

```
═══ Scenario 1: Authorized agent joins a meeting ═══
Alice creates her hybrid root identity ✓
Agent-A generates its hybrid keypair  ✓
Alice signs delegation:
  scope: [meeting:attend, meeting:speak]
  expires: 2026-05-17 18:00:00 UTC
Agent-A builds proof bundle with fresh challenge ✓
Verifier runs verify_bundle() → ✅ VALID
  effective scope: [meeting:attend, meeting:speak]

═══ Scenario 2: Attacker tampers cert scope after signing ═══
Attacker modifies cert.scope: [meeting:attend] → [meeting:record]
Verifier runs verify_bundle() → ❌ REJECTED
  identity_status: bad_signature
  reason: Ed25519 signature does not cover modified bytes

═══ Scenario 3: Agent presents wrong scope ═══
Agent-A holds cert for meeting:attend, requests meeting:record
Verifier runs verify_bundle(required_scope: meeting:record) → ❌ REJECTED
  identity_status: scope_denied
  reason: requested scope not in effective chain scope

═══ Scenario 4: Cert expired ═══
... (and so on)
```

This is what an alpha tester runs to convince themselves the protocol works the way the spec says. **Read the spec second; run the demo first.**

Full demo source for every language is in [`demos/`](demos/). The accompanying [`demos/README.md`](demos/README.md) explains each scenario in prose.

---

## What's actually happening (read this once)

If you got this far and want a real understanding of *why* the bytes are the bytes:

### The signing function

Every Ratify signature is **two signatures concatenated** — one Ed25519, one ML-DSA-65 — over the **same canonical bytes** of the object being signed.

```
HybridSignature = Ed25519.Sign(canonicalBytes, priv.ed) ∥ MLDSA65.Sign(canonicalBytes, priv.ml)

Verify(σ) := Ed25519.Verify(canonicalBytes, σ.ed, pub.ed)
           ∧ MLDSA65.Verify(canonicalBytes, σ.ml, pub.ml)
```

Both must hold. This means:

- If a quantum computer breaks Ed25519 tomorrow, ML-DSA-65 still holds the line.
- If a flaw is found in the (newer) ML-DSA-65 algorithm, Ed25519 still holds the line.
- Harvest-now-decrypt-later adversaries cannot forge today's bundles in a post-quantum future.

This is the **hybrid-PQC posture** recommended by CNSA 2.0 and BSI for the transition period.

### Canonical JSON

Both signers must produce identical bytes from the same logical input. JSON is unordered by default, which would break this. Ratify defines a small canonical serialization:

- Object keys sorted lexicographically
- No insignificant whitespace
- UTF-8 with `\u` escapes only where mandatory
- Numbers as integers when integer-valued, no trailing zeros otherwise

The canonicalizer is hand-written in every SDK and produces byte-identical output across Go, TypeScript, Python, Rust, and C/C++. The 59 fixtures verify this on every CI run.

Spec: [`SPEC.md`](SPEC.md) §6 (canonical JSON) and §7 (`delegationSignBytes` / `challengeSignBytes`).

### The challenge-response

Without freshness, an attacker who steals a valid bundle once could replay it forever. The challenge-response defeats this:

1. **Verifier** generates 32 random bytes (`challenge`) and notes the current timestamp.
2. **Verifier** sends those to the presenter.
3. **Presenter** signs `(challenge, timestamp)` with the agent's hybrid private key.
4. **Verifier** rejects if the challenge timestamp is older than ~5 minutes.

So even if Eve recorded last Tuesday's interaction, she can't replay it today: today's challenge bytes are different.

### Effective scope of a chain

If Alice delegates `[meeting:*]` to Agent-A, and Agent-A sub-delegates `[meeting:attend, meeting:record]` to Agent-B, the **effective scope** of Agent-B's chain is the *intersection*:

```
effective(chain) = ⋂  cert.scope.expand()   for each cert in chain
                  i

  Alice → Agent-A:   meeting:*  expands to  {attend, speak, video, record, chat, share_screen}
  Agent-A → Agent-B: {attend, record}
                  ∩ = {attend, record}
```

An agent *cannot* grant more rights than it itself was given. Spec: [`SPEC.md`](SPEC.md) §9.

---

## Cross-language interop

The 59 fixtures in `testvectors/v1/` are the canonical conformance set. **Any implementation in any language that passes all 59 is byte-for-byte interoperable with the reference.** This is the contract.

| Implementation | Language | Status | Install |
|---|---|---|---|
| `github.com/identities-ai/ratify-protocol` | Go | ✅ 59/59 | `go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.8` |
| `@identities-ai/ratify-protocol` | TypeScript | ✅ 59/59 | `npm install @identities-ai/ratify-protocol` |
| `ratify-protocol` | Python | ✅ 59/59 | `pip install ratify-protocol==1.0.0a8` |
| `ratify-protocol` | Rust | ✅ 59/59 | `cargo add ratify-protocol@1.0.0-alpha.8` |
| `sdks/c/` (`libratify_c`) | C / C++ | ✅ 59/59 | build from source: `sdks/c/` (Apache-2.0) |
| *Swift* | — | planned | mobile wallet |
| *Java / Kotlin* | — | planned | Android / JVM |

If you're implementing a new language port, **start from the fixtures, not the spec.** Match the bytes; the rest follows. See [`docs/SDKS.md`](docs/SDKS.md) for the conformance contract.

---

## Where to go next

| You want to… | Go to |
|---|---|
| **Run the demo and see the protocol work** | [`demos/README.md`](demos/README.md) |
| **Understand the threat model** | [`docs/EXPLAINED.md`](docs/EXPLAINED.md) |
| **Read the normative spec** | [`SPEC.md`](SPEC.md) |
| **Use the Verify managed service** (revocation, audit, policy enforcement at scale) | [docs.identities.ai](https://docs.identities.ai) |
| **Integrate with a specific surface** (Meetings, Conversational AI, Agentic API, Physical AI) | [docs.identities.ai/guides](https://docs.identities.ai) |
| **Add a new language SDK** | [`docs/SDKS.md`](docs/SDKS.md) + the new-SDK issue template |
| **Report a security issue** | [`SECURITY.md`](SECURITY.md) — do not open a public issue |
| **Cite Ratify in academic work** | [`CITATION.cff`](CITATION.cff) — GitHub auto-renders BibTeX/APA/Chicago |

This README is the entry point. **[docs.identities.ai](https://docs.identities.ai) covers per-language quickstarts in depth, integration guides for each surface, the managed Ratify Verify product, and the commercial API reference.**

---

## Repository layout

```
ratify-protocol/
├── SPEC.md                Normative protocol specification (CC-BY-4.0)
├── README.md              You are here
├── LICENSE                Apache-2.0 (source code)
├── docs/LICENSES.md       Per-asset license breakdown
├── SECURITY.md            Vulnerability disclosure policy
├── CONTRIBUTING.md        How to contribute (DCO, conformance contract)
├── CODE_OF_CONDUCT.md
├── CITATION.cff           Citation metadata
│
├── types.go               Data structures (DelegationCert, ProofBundle, …)
├── crypto.go              Hybrid Ed25519 + ML-DSA-65 primitives + canonical JSON
├── scope.go               Canonical 52-scope vocabulary + intersect/expand
├── constraints.go         Geo, time, version constraints
├── verify.go              The verifier algorithm
├── ratify_test.go         Unit tests + conformance-suite loader
├── fuzz_test.go           Fuzz harness
├── go.mod
│
├── cmd/
│   ├── ratify/                  ratify-cli (init, delegate, agent-init,
│   │                            agent-bundle, challenge, verify, scopes)
│   ├── ratify-testvectors/      Deterministic fixture generator
│   └── ratify-verifier/         Minimal HTTP reference verifier
│
├── testvectors/v1/        59 canonical fixtures (JSON)
│
├── sdks/
│   ├── typescript/        @identities-ai/ratify-protocol (npm)
│   ├── python/            ratify-protocol (PyPI)
│   ├── rust/              ratify-protocol (crates.io)
│   └── c/                 libratify_c — static + shared library, ratify.h (Apache-2.0)
│
├── demos/                 End-to-end narrative demos: go/ python/ typescript/ rust/
│
└── docs/
    ├── EXPLAINED.md           Architecture + threat model + real-time patterns
    ├── AGENT_TO_AGENT.md      A2A patterns (mutual auth, sub-delegation, receipts)
    ├── RELEASES.md            Release process + cross-SDK sync
    ├── REGISTRY_SETUP.md      How the SDK orgs are set up on PyPI/crates.io/npm
    ├── ROADMAP.md             v1.1 / v2 planned work
    ├── SDKS.md                SDK roadmap + conformance contract for new languages
    ├── TESTING.md             Internal testing guide — four levels
    ├── TEST_PLAN.md           Testing methodology
    └── TRANSACTION_RECEIPTS.md  v1.1 receipt envelope design
```

---

## Security

- **Quantum-safe in v1.** Every signature is hybrid Ed25519 (RFC 8032) + ML-DSA-65 (NIST FIPS 204). Both must verify.
- **No central authority** at verify time — verifiers need only the principal's public key. No live token-introspection call.
- **Fail-closed verifier.** Unknown fields, invalid signatures, expired certs, out-of-scope requests all return a deterministic NO.
- **External audit planned** before v1.0.0 stable.
- **Responsible-disclosure policy:** see [`SECURITY.md`](SECURITY.md). Do not open public issues for security reports.
- **Threat model:** [`docs/EXPLAINED.md`](docs/EXPLAINED.md) §5.

---

## License + trademarks + patent

- **Source code:** Apache-2.0 — see [`LICENSE`](LICENSE).
- **Specification text:** CC-BY-4.0 — see [`docs/LICENSES.md`](docs/LICENSES.md).
- **Trademarks:** Ratify Protocol™ and identities.ai™ are trademarks of Identities AI, Inc. The trademark and patent rights are not licensed under the open-source licenses governing the code or specification.
- **Patent:** U.S. patent application pending.

Maintained by **Identities AI, Inc.** See [`CONTRIBUTING.md`](CONTRIBUTING.md) for participation, the governance plan, and the DCO sign-off requirement.

---

*Built by ex-Nokia engineers from the Symbian OS team. The same principle that made mobile identity work at carrier scale — proof by math, not by the network trusting the endpoint — is what makes Ratify work for AI agents.*
