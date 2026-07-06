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

[![PyPI Downloads](https://img.shields.io/pepy/dt/ratify-protocol?label=pypi%20downloads&color=informational)](https://pepy.tech/projects/ratify-protocol)
[![Crates.io Downloads](https://img.shields.io/crates/d/ratify-protocol?label=crates.io%20downloads&color=informational)](https://crates.io/crates/ratify-protocol)
[![npm Downloads](https://img.shields.io/npm/dt/@identities-ai/ratify-protocol?label=npm%20downloads&color=informational)](https://www.npmjs.com/package/@identities-ai/ratify-protocol)
[![C/C++ Downloads](https://img.shields.io/github/downloads/identities-ai/ratify-protocol/total?label=c%2Fc%2B%2B%20downloads&color=informational)](https://github.com/identities-ai/ratify-protocol/releases)

When a human authorizes an AI agent — or when one agent transacts with another agent — Ratify produces a signed, verifiable proof that says exactly *who* authorized *what*, *within which bounds*, and *for how long*. Any party in the conversation can check that proof in [under a millisecond](docs/BENCHMARKS.md), across voice, video, API, and Physical AI.

Ratify is not agent login, registration, or credential issuance. Ratify starts where those end: when an agent is about to act, Ratify proves delegated authority, scope, constraints, expiry, and freshness — offline, in under a millisecond, with no vendor in the path.

**Quantum-safe by design.** Every signature is hybrid: Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify. Bundles signed today remain unforgeable even when cryptographically-relevant quantum computers exist.

JSON wire format. No blockchain. No tokens. No central issuer. Open spec under CC-BY-4.0.

**Status:** alpha — fixture bytes may change between pre-releases · reference implementation complete · 63 canonical test vectors · cross-language interop proven (Go + TypeScript + Python + Rust + C/C++) · Patent Pending.

Counts and feature descriptions in this README describe `main` (the development branch). Install commands reference the latest published release — see [Releases](https://github.com/identities-ai/ratify-protocol/releases) for its notes and exact fixture set.

Maintained by Identities AI, Inc. Ratify Protocol™ and identities.ai™ are trademarks of Identities AI, Inc.

---

## Table of contents

- [The mental model](#the-mental-model)
- [The three verbs](#the-three-verbs)
- [How the bytes flow](#how-the-bytes-flow)
- [60-second install + verify](#60-second-install--verify)
- [End-to-end demo — see the full protocol run](#end-to-end-demo--see-the-full-protocol-run)
- [What's actually happening (read this once)](#whats-actually-happening-read-this-once)
- [Beyond one-shot verify — continuous and multi-party interactions](#beyond-one-shot-verify--continuous-and-multi-party-interactions)
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

Pick your language. Each one runs the full 63-fixture conformance suite — the same fixtures every other SDK passes byte-for-byte. If you see "all passing," you've proven cross-language interop **on your own machine.**

### Go

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol
go test ./...
# → ok  github.com/identities-ai/ratify-protocol  0.5s
```

Or install as a module in your own project:

```bash
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.11
```

### TypeScript

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/typescript
npm install
npm test
# → 63/63 fixtures pass
```



### Python

```bash
pip install ratify-protocol==1.0.0a11
```

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/python
pip install -e '.[dev]'
pytest
# → 63 passed
```

### Rust

```bash
cargo add ratify-protocol@1.0.0-alpha.11
```

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/rust
cargo test
# → test result: ok. 1 passed (loads all 63 fixtures)
```

---

## End-to-end demo — see the full protocol run

The conformance suite proves *the bytes are correct*. The demos prove *the protocol does what it claims.* Each runs the same narrative — one positive end-to-end flow (delegate → present → verify, in five steps) followed by four rejection scenarios (tampered / out-of-scope / expired / revoked) — and prints what happened and why.

| Language | Run from repo root |
|---|---|
| Go | `go run ./demos/go` |
| Python | `cd sdks/python && pip install -e . && cd ../.. && python demos/python/demo.py` |
| TypeScript | `cd sdks/typescript && npm install && npm run build && cd ../../demos/typescript && npm install && npm run demo` |
| Rust | `cargo run --manifest-path demos/rust/Cargo.toml` |

What you'll see (abbreviated, representative output from `go run ./demos/go` — signatures and timestamps vary per run):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3  Alice authorizes the agent for meeting:attend, 7 days
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Cert ID:             cert-demo-001
  Scope:               meeting:attend
  Ed25519 sig:         cf0a687f5e946b732175e6f0e103a8ce…
  ML-DSA-65 sig:       <3309 bytes>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5  Verifier runs Verify() — expects meeting:attend
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅  VALID
  Status:              authorized_agent
  Granted scope:       meeting:attend

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK 1  Attacker appends files:write to the scope after signing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ❌  REJECTED as expected: bad_signature: cert 0: Ed25519 signature invalid
  Why:                 Canonical bytes differ; Ed25519 AND ML-DSA-65 both fail verify.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ATTACK 2  Agent tries to use meeting:attend cert for meeting:record
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ❌  REJECTED as expected: scope_denied: required scope "meeting:record"
      not in effective delegation scope

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REVOCATION  Alice revokes the cert
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ❌  REJECTED as expected: revoked: delegation certificate has been revoked
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

The canonicalizer is hand-written in every SDK and produces byte-identical output across Go, TypeScript, Python, Rust, and C/C++. The 63 fixtures verify this on every CI run.

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

## Beyond one-shot verify — continuous and multi-party interactions

Everything above describes a single delegate → present → verify round trip. Real deployments — a voice agent on a 20-minute call, two agents settling a transaction, an auditor reconstructing what happened — need more. All of the following is **shipped, normative, and covered by the canonical fixture set in every SDK**:

| Feature | What it solves | Spec |
|---|---|---|
| **Session-bound challenges** | A 32-byte `session_context` binds a proof bundle to one verifier, so a bundle presented to Zoom can't be replayed at your bank. Also defeats challenge-forwarding by a malicious verifier. | [§5.8](SPEC.md#58-proofbundle), [§15.1](SPEC.md#151-challenge-forwarding-by-malicious-verifier) |
| **Stream sequence numbers** | `stream_id` + `stream_seq` in the challenge signable detect replay, reordering, and omission across the turns of a multi-turn conversation. | [§5.8](SPEC.md#58-proofbundle), [§6.4.2](SPEC.md#642-challengesignable-not-json) |
| **SessionToken fast path** | After one full chain verification, the verifier issues an HMAC-based session token; subsequent turns verify the token plus a fresh challenge signature — roughly 95% less per-turn crypto work. This is what makes per-turn verification practical on live voice calls. | [§5.13](SPEC.md#513-sessiontoken), [§6.4.8](SPEC.md#648-sessiontokensignable) |
| **Push-based revocation** | Signed `RevocationPush` deltas let issuers push revocations to subscribed verifiers in real time, instead of waiting for the next poll. | [§5.11](SPEC.md#511-revocationpush), [§6.4.5](SPEC.md#645-revocationpushsignable) |
| **Transaction receipts** | A canonical `TransactionReceipt` where every party signs the same bytes (terms + sorted party set + transaction ID). Adding, removing, or altering any party invalidates every signature — no partial-valid state. | [§5.14](SPEC.md#514-transactionreceipt), [§6.4.7](SPEC.md#647-transactionreceiptsignable) |
| **Witness append-only log** | Signed `WitnessEntry` hash chain for tamper-evident audit logs. Any party can operate a witness. | [§5.12](SPEC.md#512-witnessentry), [§6.4.6](SPEC.md#646-witnessentrysignable) |
| **Key rotation statements** | `KeyRotationStatement` signed by both the old and new root keys, so auditors and registries can verify identity continuity across rotations. | [§5.15](SPEC.md#515-keyrotationstatement), [§6.4.4](SPEC.md#644-keyrotationsignable) |

The [`docs/AGENT_TO_AGENT.md`](docs/AGENT_TO_AGENT.md) guide shows how these compose for agent-to-agent patterns (mutual authorization, sub-delegation, receipts), and [`docs/TRANSACTION_RECEIPTS.md`](docs/TRANSACTION_RECEIPTS.md) has the receipt envelope design rationale.

---

## Cross-language interop

The 63 fixtures in `testvectors/v1/` are the canonical conformance set. **Any implementation in any language that passes all 63 is byte-for-byte interoperable with the reference.** This is the contract. (The directory also contains `cross_sdk_vectors.json` — a separate byte-equivalence corpus used by the NxN cross-SDK matrix; it is not one of the 63 canonical fixtures.)

| Implementation | Language | Conformance (`main`) | Install (latest release) |
|---|---|---|---|
| `github.com/identities-ai/ratify-protocol` | Go | ✅ 63/63 | `go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.11` |
| `@identities-ai/ratify-protocol` | TypeScript | ✅ 63/63 | `npm install @identities-ai/ratify-protocol` |
| `ratify-protocol` | Python | ✅ 63/63 | `pip install ratify-protocol==1.0.0a11` |
| `ratify-protocol` | Rust | ✅ 63/63 | `cargo add ratify-protocol@1.0.0-alpha.11` |
| `sdks/c/` (`libratify_c`) | C / C++ | ✅ full C ABI conformance | pre-built archives or build from source: `sdks/c/` (Apache-2.0) |
| *Swift* | — | planned | mobile wallet |
| *Java / Kotlin* | — | planned | Android / JVM |

The Conformance column describes `main`; a published release's exact fixture set is in its [release notes](https://github.com/identities-ai/ratify-protocol/releases). Between a feature merging and the next tag, `main` may be ahead of what the install commands deliver.

If you're implementing a new language port, **start from the fixtures, not the spec.** Match the bytes; the rest follows. See [`docs/SDKS.md`](docs/SDKS.md) for the conformance contract.

---

## Where to go next

| You want to… | Go to |
|---|---|
| **Run the demo and see the protocol work** | [`demos/README.md`](demos/README.md) |
| **See the measured performance numbers** | [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) |
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
├── CHANGELOG.md           Release history
│
├── types.go               Data structures (DelegationCert, ProofBundle, …)
├── crypto.go              Hybrid Ed25519 + ML-DSA-65 primitives + canonical JSON
├── scope.go               Canonical 54-scope vocabulary + intersect/expand
├── constraints.go         Geo, time, version constraints
├── verify.go              The verifier algorithm
├── streamed_verify.go     SessionToken fast path — multi-turn verification (§5.13)
├── receipt_verify.go      TransactionReceipt verification (§5.14)
├── ratify_test.go         Unit tests + conformance-suite loader
├── fuzz_test.go           Fuzz harness
├── bench_verify_test.go   Benchmarks backing docs/BENCHMARKS.md
├── cross_sdk_test.go      NxN cross-SDK byte-equivalence tests
├── levers_test.go         Verifier option / policy lever tests
├── providers_test.go      Provider interface (§17) tests
├── go.mod
│
├── Makefile               test-all / release-check / release targets
├── scripts/               test-all.sh, check-release-sync.sh, release.sh
│
├── cmd/
│   ├── ratify/                  ratify-cli (init, delegate, agent-init,
│   │                            agent-bundle, challenge, verify, scopes)
│   ├── ratify-testvectors/      Deterministic fixture generator
│   └── ratify-verifier/         Minimal HTTP reference verifier
│
├── testvectors/v1/        63 canonical fixtures + cross_sdk_vectors.json
│
├── sdks/
│   ├── go/                Pointer README — the Go SDK lives at the repo root
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
    ├── BENCHMARKS.md          Measured numbers behind the <1ms claim
    ├── ATTRIBUTION.md         Badge program + attribution guidelines
    ├── RELEASES.md            Release process + cross-SDK sync
    ├── REGISTRY_SETUP.md      How the SDK orgs are set up on PyPI/crates.io/npm
    ├── ROADMAP.md             Shipped / planned / v2 work
    ├── SDKS.md                SDK roadmap + conformance contract for new languages
    ├── TESTING.md             Internal testing guide — four levels
    ├── TEST_PLAN.md           Testing methodology
    └── TRANSACTION_RECEIPTS.md  Receipt envelope — design rationale (normative text: SPEC §5.14)
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

## Attribution & badge program

When you build a product on Ratify Protocol, we ask — but don't require — that you say so. The reason is the same reason apps display "Messages secured with Signal Protocol": your users' trust is grounded in an inspectable open standard, and making that visible increases confidence rather than eroding it.

**In developer docs / security pages:**
```
Agent authorization powered by Ratify Protocol (https://identities.ai/protocol)
```

**In product UIs** (verification results, meeting policy screens, agent consents):

| Variant | Asset |
|---|---|
| Dark background | [`assets/badge-verified-dark.svg`](assets/badge-verified-dark.svg) |
| Light background | [`assets/badge-verified-light.svg`](assets/badge-verified-light.svg) |
| "Powered by" (dark) | [`assets/badge-powered-dark.svg`](assets/badge-powered-dark.svg) |
| "Powered by" (light) | [`assets/badge-powered-light.svg`](assets/badge-powered-light.svg) |

Link any badge to `https://identities.ai/protocol`. Full guidelines: [`docs/ATTRIBUTION.md`](docs/ATTRIBUTION.md).

## License + trademarks + patent

- **Source code:** Apache-2.0 — see [`LICENSE`](LICENSE).
- **Specification text:** CC-BY-4.0 — see [`docs/LICENSES.md`](docs/LICENSES.md).
- **Attribution:** Apache 2.0 requires preserving the [`NOTICE`](NOTICE) file. The badge program above is a request, not a license condition — see [`docs/ATTRIBUTION.md`](docs/ATTRIBUTION.md).
- **Trademarks:** Ratify Protocol™ and identities.ai™ are trademarks of Identities AI, Inc. The trademark and patent rights are not licensed under the open-source licenses governing the code or specification.
- **Patent:** U.S. patent application pending.

Maintained by **Identities AI, Inc.** See [`CONTRIBUTING.md`](CONTRIBUTING.md) for participation, the governance plan, and the DCO sign-off requirement.

---

*Built by ex-Nokia engineers from the Symbian OS team. The same principle that made mobile identity work at carrier scale — proof by math, not by the network trusting the endpoint — is what makes Ratify work for AI agents.*
