<p align="center">
  <img src="assets/ratify-protocol-logo.png" alt="Ratify Protocol" width="160" height="160" />
</p>

<h1 align="center">Ratify Protocol™</h1>

<p align="center">
  <em>Delegated-authority proofs for human-agent and agent-agent interactions: who authorized the agent, what it may do, and for how long.</em>
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

When a human authorizes an AI agent, or when one agent transacts with another, Ratify produces a signed, verifiable proof that says exactly *who* authorized *what*, *within which bounds*, and *for how long*. The receiving side checks that proof itself, without calling back to whoever issued it, across voice, video, API, and Physical AI. Per-SDK latency and wire sizes are in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

Ratify is not agent login, registration, or credential issuance. Ratify starts where those end: when an agent is about to act, Ratify proves delegated authority, scope, constraints, expiry, and freshness, with no vendor in the path.

Keep your IAM, OAuth, MCP, A2A, and policy engines. Ratify adds the missing proof and replaces none of them. IAM authenticates the human. MCP and A2A move the request. Policy engines interpret local rules. **Ratify proves delegated authority before the action.**

**Hybrid signatures.** Every signature is a pair: Ed25519 and ML-DSA-65 (NIST FIPS 204), and both must verify. A forger has to break both algorithms, so a break of Ed25519 alone, for example by a future quantum computer, does not let anyone forge a proof while ML-DSA-65 holds.

JSON wire format. No blockchain. No bearer tokens. No central issuer. Open spec under CC-BY-4.0.

**Status.** Two protocol lines live in this repository:

- **Protocol v2** ([`SPEC-v2.md`](SPEC-v2.md)) is in prerelease toward its first beta. It is not backward compatible with v1. Every SDK runs the full shared `testvectors/v2` corpus (22 vector files plus cross-SDK fixtures from all five SDKs). Review so far is internal adversarial review; external independent review and outside interoperability are gates for `2.0.0`, so v2 carries no production security claim yet.
- **Protocol v1** ([`SPEC.md`](SPEC.md)) is alpha, validated by 79 canonical test vectors in every SDK. It remains available and pinned; v1 support terms will be announced with v2 `2.0.0`.

Counts and feature descriptions in this README describe `main` (the development branch). Install commands pin the versions prepared in this tree: `2.0.0-alpha.1` on the v2 line (Go, TypeScript, Rust, C/C++, and the separate `ratify-protocol-v2` Python distribution) and `1.0.0a21` for the v1 Python SDK. A pin installs only once its release appears on [Releases](https://github.com/identities-ai/ratify-protocol/releases), which also lists each release's notes and exact fixture set. The latest published v1 release is `v1.0.0-alpha.20`.

Ratify Protocol™ and the Ratify logo are trademarks of Identities.AI, Inc. U.S. patent application pending.

---

## Use Ratify with agent platforms

The protocol SDKs provide the portable authority primitive. Executable
[reference integrations](references/README.md) show where that primitive fits
inside real agent platforms and where the receiving system enforces it.
The [reference index](references/README.md) lists every integration currently
available, with setup instructions and its endorsement and production status.
For the in-development breaking v2 profile and upgrade path, read
[`SPEC-v2.md`](SPEC-v2.md) and
[`docs/PROTOCOL_V2_MIGRATION.md`](docs/PROTOCOL_V2_MIGRATION.md). The
reference-by-reference migration and evidence checklist is
[`docs/V2_REFERENCE_COMPATIBILITY.md`](docs/V2_REFERENCE_COMPATIBILITY.md).
Released v1 packages remain separate and unchanged.

---

## Protocol v2

Protocol v2 is a separately versioned wire profile for the same idea:
portable authority proofs with hybrid Ed25519 and ML-DSA-65 signatures. It
changes how a verifier reaches a decision:

- **Verify, then release.** Verification commits a terminal result and a
  receipt body, which is not actionable. Release returns the actionable
  decision only after the signed receipt is in an ordered log, an independent
  checkpoint has acknowledged it, and the deadlines are still current.
- **Signed status** under a status key that is separate from the issuer key,
  applied through an anchored journal. An allow always needs current status.
- **Stored challenges** from an issuance helper, claimed atomically, so a
  replay is never evaluated.
- **Exact `custom:` scopes and evaluator profiles** for extension
  constraints, with the profile digests signed into the receipt.
- **Integer-only numbers** (amounts in micro-units), wire limits checked
  before parsing, 49 error classes, typed and external signers, and
  deployment profiles for a single offline device, dual-root approval and
  middleware custody.

v1 and v2 install side by side, and a deployment picks the version at each
boundary; there is no automatic fallback. Four v1 capabilities stay v1-only
until Protocol 2.1: the SessionToken fast path, A2A mutual presentation, the
HTTP and registry bindings, and the geo and speed constraints.

| SDK | v2 install (prerelease) | v1 install |
|---|---|---|
| Go | `go get github.com/identities-ai/ratify-protocol/v2@v2.0.0-alpha.1` | `go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.20` |
| TypeScript | `npm install @identities-ai/ratify-protocol@2.0.0-alpha.1` (dist-tag `next`; import `@identities-ai/ratify-protocol/v2`) | `npm install @identities-ai/ratify-protocol@1.0.0-alpha.20` |
| Python | `pip install ratify-protocol-v2==2.0.0a1` (import `ratify_protocol_v2`) | `pip install ratify-protocol==1.0.0a21` |
| Rust | `cargo add ratify-protocol@2.0.0-alpha.1` (module `ratify_protocol::v2`) | `ratify-protocol = "=1.0.0-alpha.20"` |
| C/C++ | `ratify-c` 2.x: build `sdks/c` (`ratify_v2_*` ABI in `ratify.h`) | the `1.0.0-alpha.20` release archive |

Start here:

- [`examples/v2/`](examples/v2/): runnable programs in all five languages
  (quickstart, signed status, custom scope with an evaluator profile, external
  signer). Every language prints the same output, and CI checks it. They use
  in-memory reference stores and are development-only.
- [`docs/PROTOCOL_V2_MIGRATION.md`](docs/PROTOCOL_V2_MIGRATION.md): the v1 to
  v2 upgrade guide.
- [`SPEC-v2.md`](SPEC-v2.md) and [`SPEC-v2-ANNEX-A.md`](SPEC-v2-ANNEX-A.md):
  the normative v2 text.

The sections below that describe the three verbs, the byte flow, the demos and
the continuous-interaction features describe Protocol v1 unless they say
otherwise.

---

## Table of contents

- [Protocol v2](#protocol-v2)
- [The mental model](#the-mental-model)
- [Use Ratify with agent platforms](#use-ratify-with-agent-platforms)
- [The three verbs](#the-three-verbs)
- [How the bytes flow](#how-the-bytes-flow)
- [60-second install + verify](#60-second-install--verify)
- [End-to-end demo (Protocol v1)](#end-to-end-demo-protocol-v1)
- [What's actually happening (read this once)](#whats-actually-happening-read-this-once)
- [Beyond one-shot verify: continuous and multi-party interactions (Protocol v1)](#beyond-one-shot-verify-continuous-and-multi-party-interactions-protocol-v1)
- [Cross-language interop](#cross-language-interop)
- [Where to go next](#where-to-go-next)
- [Repository layout](#repository-layout)
- [Security](#security)
- [License + trademarks + patent](#license--trademarks--patent)

---

## The mental model

The protocol replaces *"the AI says so"* with *"prove it."*

Today, when an AI agent shows up (joining a meeting, calling your support line, sending an email, executing a trade on your behalf), the receiving party has no cryptographic way to verify three things:

1. **Who** authorized this agent to act?
2. **What** is this agent allowed to do?
3. **For how long** is that authority valid?

Bearer tokens never had to answer these. They were built for an era when a human was present at the keyboard, a known client called a known API, and the session stayed inside one app boundary. Agents break all three assumptions: they act later, call many tools, cross vendor boundaries, and hand work to other agents.

Ratify answers those three questions with a single primitive: a signed delegation certificate paired with a fresh challenge signature. Any verifier can check the proof itself, with **no live call to a central authority** ([sub-millisecond signature checks in the Go, Rust, and C SDKs](docs/BENCHMARKS.md)).

In Protocol v2, checking the proof is not yet acting on it. An actionable allow also needs the verifier's own claim store, a signed receipt, and an independent checkpoint acknowledgement (or the single-device offline profile of SPEC-v2 §7.13). None of these is a call to the issuer.

Same primitive works for humans authorizing agents *and* agents sub-authorizing other agents. Same verifier algorithm in every direction. That symmetry is what makes Ratify a *protocol* rather than a product.

---

## The three verbs

This diagram describes Protocol v1. Protocol v2 adds a fourth step, RELEASE:
the verifier publishes a signed receipt, an independent checkpoint
acknowledges it, and only the released decision is actionable.

```
   DELEGATE                  PRESENT                   VERIFY
   ────────                  ───────                   ──────
   Principal signs a         Presenter (agent)         Any third party
   DelegationCert            carries the cert          runs the verifier.
   naming the subject,       and signs a fresh         Both Ed25519 AND
   the scopes, and the       challenge on every        ML-DSA-65 must
   expiration.               interaction.              verify. Yes/no
                                                       in ms. No trust
   Human → Agent OR          Proves "this key is       relationship with
   Agent → Agent.            live right now."          presenter required.
```

Symmetric in both directions. A human delegating to an AI agent and one AI agent sub-delegating to another use the **exact same primitive**, the **same verifier algorithm**, and the **same cryptographic guarantees**.

---

## How the bytes flow

Concrete picture of one full Protocol v1 interaction (in v2 the verifier also
stores each challenge at issuance, requires signed status from a separate
status key, and releases the decision only after its receipt is acknowledged):

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
                  │   → YES / NO in milliseconds      │
                  └───────────────────────────────────┘
```

**What's not in the picture (and why that matters):** no central authority is consulted at verify time. The verifier needs only Alice's **public** key to check everything above. No OAuth introspection endpoint, no token registry call, no network hop. That is what makes Ratify deployable in offline environments (drones, vehicles, edge inference) and at internet scale (every Zoom call, every API call, every voice interaction).

For sub-delegation (Agent-A authorizing Agent-B), the bundle just carries **two certs**, and the verifier checks each link in the chain plus the scope intersection. Same verifier algorithm.

---

## 60-second install + verify

Pick your language. Each one runs the full 79-fixture conformance suite for Protocol v1, the same fixtures every other SDK passes byte-for-byte, and the v2 SDKs also run every file in `testvectors/v2`. If you see "all passing," you've proven cross-language interop **on your own machine.** For v2 code you can read and run, see [`examples/v2/`](examples/v2/).

### Go

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol
go test ./...
# → ok  github.com/identities-ai/ratify-protocol/v2  0.5s
```

Or install as a module in your own project:

```bash
go get github.com/identities-ai/ratify-protocol/v2@v2.0.0-alpha.1
```

The v2 line uses the `/v2` module path. The v1 module path is unchanged, and
its latest published tag stays installable:

```bash
go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.20
```

### TypeScript

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/typescript
npm install
npm test
# → all tests pass (79/79 v1 fixtures and the testvectors/v2 corpus)
```

To use the v2 prerelease in your project, pin it exactly (it is published
under the `next` dist-tag, so an unpinned install resolves to v1):

```bash
npm install @identities-ai/ratify-protocol@2.0.0-alpha.1
```


### Python

```bash
pip install ratify-protocol==1.0.0a21
```

The v2 Python SDK is a separate distribution that imports as
`ratify_protocol_v2`, so it installs next to the v1 package:

```bash
pip install ratify-protocol-v2==2.0.0a1
```

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/python
pip install -e '.[dev]'
pytest
# → all tests pass
```

### Rust

```bash
cargo add ratify-protocol@2.0.0-alpha.1
```

To stay on v1, pin the published crate exactly: `ratify-protocol = "=1.0.0-alpha.20"`.

Or to run the conformance suite yourself:

```bash
git clone https://github.com/identities-ai/ratify-protocol
cd ratify-protocol/sdks/rust
cargo test
# → test result: ok (all 79 v1 fixtures and the testvectors/v2 corpus)
```

---

## End-to-end demo (Protocol v1)

The conformance suite proves *the bytes are correct*. The demos prove *the protocol does what it claims.* Each runs the same narrative: one positive end-to-end flow (delegate → present → verify, in five steps) followed by four rejection scenarios (tampered, out-of-scope, expired, revoked), and prints what happened and why. These demos use the v1 API. For Protocol v2, run the programs in [`examples/v2/`](examples/v2/); for example `go run ./examples/v2/go/quickstart` prints:

```
Ratify Protocol v2 quickstart
development only: in-memory reference stores
keys: root, agent, status and verifier generated (key IDs are 64 hex characters)
delegation: scope=payments:send max_amount=50000000 USD micros lifetime=86400s
status: genesis list signed by the status key (sequence 1, 0 revoked)
challenge: issued and persisted, expires in 120s
proof: agent signed the presentation (1 delegation)
verify: stage=committed (not actionable until released)
receipt: published at log sequence 1
checkpoint: acknowledged sequence 1
release: status=released decision=allow reason=authorized
granted scope: payments:send
allowed now: true
replay: stage=replay disposition=terminal_replay
allowed at challenge expiry: false
```

| Language | Run from repo root |
|---|---|
| Go | `go run ./demos/go` |
| Python | `cd sdks/python && pip install -e . && cd ../.. && python demos/python/demo.py` |
| TypeScript | `cd sdks/typescript && npm install && npm run build && cd ../../demos/typescript && npm install && npm run demo` |
| Rust | `cargo run --manifest-path demos/rust/Cargo.toml` |

What the v1 demo prints (abbreviated, representative output from `go run ./demos/go`; signatures and timestamps vary per run):

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

Deeper platform compositions, including the executed NVIDIA OpenShell + NOOA
profile, are indexed under [`references/`](references/). Platform references add
adversarial acceptance cases, evidence, and a claim ledger while preserving
simple language demos as the protocol's fastest introduction.

---

## What's actually happening (read this once)

If you got this far and want a real understanding of *why* the bytes are the bytes:

### The signing function

Every Ratify signature is **two signatures**, one Ed25519 and one ML-DSA-65, over the **same message**.

Protocol v1 signs the object's canonical bytes directly:

```
HybridSignature = Ed25519.Sign(canonicalBytes, priv.ed) ∥ MLDSA65.Sign(canonicalBytes, priv.ml)

Verify(σ) := Ed25519.Verify(canonicalBytes, σ.ed, pub.ed)
           ∧ MLDSA65.Verify(canonicalBytes, σ.ml, pub.ml)
```

Protocol v2 signs a domain-separated message that names the object type, and
gives ML-DSA-65 a fixed context string per object type (SPEC-v2 §3):

```
M = "ratify-protocol-signature" ∥ 0x00 ∥ 0x02 ∥ uint16_be(type_code) ∥ SHA-384(signable)
HybridSignature = Ed25519.Sign(M, priv.ed) ∥ MLDSA65.Sign(M, ctx = "ratify-protocol/2/<type_code>", priv.ml)
```

Both must hold. This means:

- If a quantum computer breaks Ed25519, ML-DSA-65 still has to be forged.
- If a flaw is found in the newer ML-DSA-65 algorithm, Ed25519 still has to be forged.
- Harvest-now-decrypt-later is a threat to encrypted data; Ratify signs and does not encrypt. The risk for signatures is a future forgery, and forging a hybrid signature needs a break of both algorithms.

This hybrid construction follows the transition approach that agencies such as BSI and ANSSI recommend.

### Canonical JSON

Both signers must produce identical bytes from the same logical input. JSON is unordered by default, which would break this. Ratify defines a small canonical serialization:

- Object keys sorted lexicographically
- No insignificant whitespace
- UTF-8 with `\u` escapes only where mandatory
- Numbers as integers when integer-valued, no trailing zeros otherwise (v1); integers only in v2, where floating-point values and negative zero are rejected

The canonicalizer is hand-written in every SDK and produces byte-identical output across Go, TypeScript, Python, Rust, and C/C++. The 79 v1 fixtures and the `testvectors/v2` corpus verify this on every CI run.

Spec: [`SPEC.md`](SPEC.md) §6 (canonical JSON) and §7 (`delegationSignBytes` / `challengeSignBytes`) for v1; [`SPEC-v2-ANNEX-A.md`](SPEC-v2-ANNEX-A.md) for v2.

### The challenge-response

Without freshness, an attacker who steals a valid bundle once could replay it forever. The challenge-response defeats this:

1. **Verifier** generates 32 random bytes (`challenge`) and notes the current timestamp.
2. **Verifier** sends those to the presenter.
3. **Presenter** signs `(challenge, timestamp)` with the agent's hybrid private key.
4. **Verifier** rejects if the challenge timestamp is older than ~5 minutes.

So even if Eve recorded last Tuesday's interaction, she can't replay it today: today's challenge bytes are different.

One caveat that matters in production: stateless cryptographic verification is not, by itself, replay-safe task acceptance. In v1, freshness bounds a replay to the ~5-minute window, and within that window a captured bundle would still verify. A v1 verifier that issues challenges closes this by making each challenge single-use: the SDKs ship a `ChallengeStore` for exactly that, and SPEC §10 makes single-use acceptance normative for challenge-issuing verifiers. Verifiers that accept self-issued challenges keep only the freshness bound and should pair it with request-level deduplication.

Protocol v2 makes this mandatory for a live decision. The verifier's issuance helper persists each challenge with its namespace, replay epoch and expected bindings before it returns it, the maximum age is configurable from 1 to 300 seconds with exclusive deadlines, and the verifier claims the stored challenge atomically, so a replay is never evaluated. Self-issued challenges are accepted only for archival verification, which is never actionable.

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

In v2 a required scope may also be one exact `custom:<name>` scope. It must be byte-equal to an entry of the effective scope, every certificate in the chain must list it, and `custom:*` is invalid (SPEC-v2 §2.4).

---

## Beyond one-shot verify: continuous and multi-party interactions (Protocol v1)

> **Protocol line:** this section describes Protocol v1 ([SPEC.md](SPEC.md)). Protocol v2 ([SPEC-v2.md](SPEC-v2.md)) has its own session and stream binding, signed status, receipts, transaction receipts, witness entries, and key rotation. Four v1 capabilities have no v2 equivalent yet and remain v1-only until Protocol 2.1: the SessionToken fast path, A2A mutual presentation, the HTTP and registry bindings, and the geographic and speed constraints. See [docs/PROTOCOL_V2_MIGRATION.md](docs/PROTOCOL_V2_MIGRATION.md).

Everything above describes a single delegate → present → verify round trip. Real deployments, such as a voice agent on a 20-minute call, two agents settling a transaction, or an auditor reconstructing what happened, need more. All of the following is **shipped, normative, and covered by the canonical v1 fixture set in every SDK**:

| Feature | What it solves | Spec |
|---|---|---|
| **Session-bound challenges** | A 32-byte `session_context` binds a proof bundle to one verifier, so a bundle presented to Zoom can't be replayed at your bank. Also defeats challenge-forwarding by a malicious verifier. | [§5.8](SPEC.md#58-proofbundle), [§15.1](SPEC.md#151-challenge-forwarding-by-malicious-verifier) |
| **Stream sequence numbers** | `stream_id` + `stream_seq` in the challenge signable detect replay, reordering, and omission across the turns of a multi-turn conversation. | [§5.8](SPEC.md#58-proofbundle), [§6.4.2](SPEC.md#642-challengesignable-not-json) |
| **SessionToken, the default for repeated v1 interactions** | Verify the full chain once at session start, issue an HMAC-based session token, then verify each turn against the token plus a fresh challenge signature: one hybrid signature verification per turn instead of N+1 (50–75% less signature work depending on chain depth; [measured numbers](docs/BENCHMARKS.md)) and a per-turn payload roughly 2–5× smaller than a full bundle. This is the intended integration pattern for anything multi-turn (voice calls, streams, agent sessions), not an optimization to bolt on later; the streamed-turn verifier enforces scope, single-use challenges, and session/stream bindings on this path. Reserve per-turn full-chain verification for high-stakes actions that need fresh revocation semantics. | [§5.13](SPEC.md#513-sessiontoken), [§6.4.8](SPEC.md#648-sessiontokensignable) |
| **Push-based revocation** | Signed `RevocationPush` deltas let issuers push revocations to subscribed verifiers in real time, instead of waiting for the next poll. | [§5.11](SPEC.md#511-revocationpush), [§6.4.5](SPEC.md#645-revocationpushsignable) |
| **Transaction receipts** | A canonical `TransactionReceipt` where every party signs the same bytes (terms + sorted party set + transaction ID). Adding, removing, or altering any party invalidates every signature, so there is no partial-valid state. | [§5.14](SPEC.md#514-transactionreceipt), [§6.4.7](SPEC.md#647-transactionreceiptsignable) |
| **Witness append-only log** | Signed `WitnessEntry` hash chain for tamper-evident audit logs. Any party can operate a witness. | [§5.12](SPEC.md#512-witnessentry), [§6.4.6](SPEC.md#646-witnessentrysignable) |
| **Key rotation statements** | `KeyRotationStatement` signed by both the old and new root keys, so auditors and registries can verify identity continuity across rotations. | [§5.15](SPEC.md#515-keyrotationstatement), [§6.4.4](SPEC.md#644-keyrotationsignable) |
| **Resource-bound authority** | The `resource_path` constraint scopes a delegation to one resource (an opaque `resource_id` compared byte-for-byte) and, optionally, to a `path_prefix` within it under segment-boundary matching, so a broad grant like `files:write` can be pinned to `/docs` of a single repository. Down a sub-delegation chain, effective authority can stay the same or narrow but never widen: a child may carry a broader prefix on the same resource and still verify, yet gains no authority because every upstream constraint still applies, so downstream escape is impossible by construction. This is the eighth canonical constraint type, alongside `geo_circle`, `geo_polygon`, `geo_bbox`, `time_window`, `max_speed_mps`, `max_amount`, and `max_rate`. | [§5.7.3](SPEC.md#573-the-resource_path-constraint), [§5.16](SPEC.md#516-verifiercontext) |

The [`docs/AGENT_TO_AGENT.md`](docs/AGENT_TO_AGENT.md) guide shows how these compose for agent-to-agent patterns (mutual authorization, sub-delegation, receipts), and [`docs/TRANSACTION_RECEIPTS.md`](docs/TRANSACTION_RECEIPTS.md) has the receipt envelope design rationale.

---

## Cross-language interop

The 79 fixtures in `testvectors/v1/` are the canonical Protocol v1 conformance set. **Any implementation in any language that passes all 79 is byte-for-byte interoperable with the v1 reference.** This is the contract. (The directory also contains `cross_sdk_vectors.json`, a separate byte-equivalence corpus used by the NxN cross-SDK matrix; it is not one of the 79 canonical fixtures.) For Protocol v2 the contract is every file in [`testvectors/v2/`](testvectors/v2/README.md), and each SDK also verifies the cross-SDK fixtures every other SDK produces; the per-SDK record is [`docs/V2_REFERENCE_COMPATIBILITY.md`](docs/V2_REFERENCE_COMPATIBILITY.md).

| Implementation | Language | Conformance (`main`) | Install (pinned version) |
|---|---|---|---|
| `github.com/identities-ai/ratify-protocol/v2` | Go | ✅ 79/79 v1; full `testvectors/v2` | `go get github.com/identities-ai/ratify-protocol/v2@v2.0.0-alpha.1` |
| `@identities-ai/ratify-protocol` | TypeScript | ✅ 79/79 v1; full `testvectors/v2` | `npm install @identities-ai/ratify-protocol@2.0.0-alpha.1` (an unpinned install resolves to v1) |
| `ratify-protocol` | Python (v1) | ✅ 79/79 | `pip install ratify-protocol==1.0.0a21` |
| `ratify-protocol-v2` | Python (v2) | full `testvectors/v2` | `pip install ratify-protocol-v2==2.0.0a1` |
| `ratify-protocol` | Rust | ✅ 79/79 v1; full `testvectors/v2` | `cargo add ratify-protocol@2.0.0-alpha.1` |
| `sdks/c/` (`libratify_c`) | C / C++ | ✅ full v1 C ABI conformance; full `testvectors/v2` through the `ratify_v2_*` ABI, including the stateful verifier (also run on armv7 Linux) | pre-built archives or build from source: `sdks/c/` (Apache-2.0) |
| *Swift* | n/a | planned | mobile wallet |
| *Java / Kotlin* | n/a | planned | Android / JVM |

The Conformance column describes `main`; a published release's exact fixture set is in its [release notes](https://github.com/identities-ai/ratify-protocol/releases). Between a feature merging and the next tag, `main` may be ahead of what the install commands deliver.

If you're implementing a new language port, **start from the fixtures, not the spec.** Match the bytes; the rest follows. See [`docs/SDKS.md`](docs/SDKS.md) for the conformance contract.

---

## Where to go next

[`references/`](references/README.md) is the open-source home for executable
integrations with agent frameworks, transports, and runtimes. These profiles
prove interoperability and document the receiver-side trust boundary. They do
not replace **Ratify Verify**, the managed commercial surface for production
trust configuration, revocation, policy, audit, observability, availability,
and supported deployment adapters. Both use the same portable protocol and
verification semantics; there is no managed-only wire format.

| You want to… | Go to |
|---|---|
| **Run the demo and see the protocol work** | [`demos/README.md`](demos/README.md) (v1), [`examples/v2/`](examples/v2/) (v2) |
| **Upgrade from v1 to v2** | [`docs/PROTOCOL_V2_MIGRATION.md`](docs/PROTOCOL_V2_MIGRATION.md) |
| **See integrations with specific agent platforms** | [`references/README.md`](references/README.md) |
| **See the measured performance numbers** | [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) |
| **Understand the threat model** | [`docs/EXPLAINED.md`](docs/EXPLAINED.md) |
| **Read the normative spec** | [`SPEC.md`](SPEC.md) (v1), [`SPEC-v2.md`](SPEC-v2.md) (v2) |
| **Use the Verify managed service** (revocation, audit, policy enforcement at scale) | [docs.ratifyprotocol.com](https://docs.ratifyprotocol.com) |
| **Integrate with a specific surface** (Meetings, Conversational AI, Agentic API, Physical AI) | [docs.ratifyprotocol.com/guides](https://docs.ratifyprotocol.com/guides/) |
| **Guard a protected handler on the receiver side** | [`ratify-receiver`](https://github.com/identities-ai/ratify-receiver), a TypeScript helper for receivers that use Ratify Verify |
| **Add a new language SDK** | [`docs/SDKS.md`](docs/SDKS.md) + the new-SDK issue template |
| **Report a security issue** | [`SECURITY.md`](SECURITY.md) (do not open a public issue) |
| **Cite Ratify in academic work** | [`CITATION.cff`](CITATION.cff) (GitHub renders BibTeX, APA and Chicago) |

This README is the entry point. **[docs.ratifyprotocol.com](https://docs.ratifyprotocol.com) covers per-language quickstarts in depth, integration guides for each surface, the managed Ratify Verify product, and the commercial API reference.**

---

## Repository layout

```
ratify-protocol/
├── SPEC.md                Normative Protocol v1 specification (CC-BY-4.0)
├── SPEC-v2.md             Normative Protocol v2 specification (prerelease)
├── SPEC-v2-ANNEX-A.md     v1 clauses incorporated into v2, pinned
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
├── constraints.go         v1 constraints: geo, time, speed, amount, rate, resource path
├── verify.go              The v1 verifier algorithm
├── streamed_verify.go     v1 SessionToken fast path, multi-turn verification (§5.13)
├── *_v2.go                Protocol v2: wire, signing, verify, release, status, receipts
├── v2reference/           In-memory Part B reference stores (tests and examples only)
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
├── testvectors/v1/        79 canonical fixtures + cross_sdk_vectors.json
├── testvectors/v2/        Protocol v2 corpus and cross-SDK fixtures
│
├── sdks/
│   ├── go/                Pointer README; the Go SDK lives at the repo root
│   ├── typescript/        @identities-ai/ratify-protocol (npm)
│   ├── python/            ratify-protocol (PyPI)
│   ├── rust/              ratify-protocol (crates.io)
│   └── c/                 libratify_c: static + shared library, ratify.h (Apache-2.0)
│
├── demos/                 End-to-end narrative demos (v1): go/ python/ typescript/ rust/
├── examples/v2/           Runnable v2 programs in go/ typescript/ python/ rust/ c/
│
├── references/            Platform-specific profiles, threat models, and executable gates
│
└── docs/
    ├── EXPLAINED.md           Architecture + threat model + real-time patterns
    ├── AGENT_TO_AGENT.md      A2A patterns (mutual auth, sub-delegation, receipts)
    ├── BENCHMARKS.md          Per-SDK latency matrix + wire sizes behind the performance claims
    ├── ATTRIBUTION.md         Badge program + attribution guidelines
    ├── RELEASES.md            Release process + cross-SDK sync
    ├── REGISTRY_SETUP.md      How the SDK orgs are set up on PyPI/crates.io/npm
    ├── PROTOCOL_V2_MIGRATION.md  v1 to v2 upgrade guide
    ├── V2_REFERENCE_COMPATIBILITY.md  Per-SDK and per-reference v2 status
    ├── ROADMAP.md             Shipped and planned work for v1, v2 and 2.1
    ├── SDKS.md                SDK roadmap + conformance contract for new languages
    ├── TESTING.md             Testing guide, four levels
    ├── TEST_PLAN.md           Testing methodology
    └── TRANSACTION_RECEIPTS.md  Receipt envelope design rationale (normative text: SPEC §5.14)
```

---

## Security

- **Hybrid signatures in both lines.** Every signature is Ed25519 (RFC 8032) plus ML-DSA-65 (NIST FIPS 204). Both must verify.
- **No central authority** at verify time. Verifiers need only the principal's public key, and there is no live token-introspection call.
- **Fail-closed verifier.** Unknown fields, invalid signatures, expired certs, out-of-scope requests all return a deterministic NO.
- **Review status.** Protocol v2 has had internal adversarial review of the specification, vectors and every SDK. External independent review is a gate for v2 `2.0.0`, and no release carries a production security claim until it passes.
- **Responsible-disclosure policy:** see [`SECURITY.md`](SECURITY.md). Do not open public issues for security reports.
- **Threat model:** [`docs/EXPLAINED.md`](docs/EXPLAINED.md) §5.

---

## Attribution & badge program

When you build a product on Ratify Protocol, we ask, but don't require, that you say so. The reason is the same reason apps display "Messages secured with Signal Protocol": your users' trust is grounded in an inspectable open standard, and making that visible increases confidence rather than eroding it.

**In developer docs / security pages:**
```
Agent authorization powered by Ratify Protocol (https://ratifyprotocol.com)
```

**In product UIs** (verification results, meeting policy screens, agent consents):

| Variant | Asset |
|---|---|
| Dark background | [`assets/badge-verified-dark.svg`](assets/badge-verified-dark.svg) |
| Light background | [`assets/badge-verified-light.svg`](assets/badge-verified-light.svg) |
| "Powered by" (dark) | [`assets/badge-powered-dark.svg`](assets/badge-powered-dark.svg) |
| "Powered by" (light) | [`assets/badge-powered-light.svg`](assets/badge-powered-light.svg) |

Link any badge to `https://ratifyprotocol.com`. Full guidelines: [`docs/ATTRIBUTION.md`](docs/ATTRIBUTION.md).

## License + trademarks + patent

- **Source code:** Apache-2.0; see [`LICENSE`](LICENSE).
- **Specification text:** CC-BY-4.0; see [`docs/LICENSES.md`](docs/LICENSES.md).
- **Attribution:** Apache 2.0 requires preserving the [`NOTICE`](NOTICE) file. The badge program above is a request, not a license condition; see [`docs/ATTRIBUTION.md`](docs/ATTRIBUTION.md).
- **Trademarks:** Ratify Protocol™ and the Ratify logo are trademarks of Identities.AI, Inc. The trademark and patent rights are not licensed under the open-source licenses governing the code or specification.
- **Patent:** U.S. patent application pending.

Maintained by **Identities.AI, Inc.** See [`CONTRIBUTING.md`](CONTRIBUTING.md) for participation, the governance plan, and the DCO sign-off requirement. Questions and bug reports are welcome as GitHub issues.

---

*Built by ex-Nokia engineers from the Symbian OS team. The same principle that made mobile identity work at carrier scale, proof by math rather than the network trusting the endpoint, is what makes Ratify work for AI agents.*
