# SDK Roadmap and Interop Contract

**Where Ratify Protocol reference implementations live, which languages are coming next, and exactly what any new implementation must pass to be considered conformant.**

This document is for language SDK authors, external contributors, and anyone planning to ship a Ratify implementation. For the protocol itself see [`SPEC.md`](../SPEC.md). For testing methodology see [`TEST_PLAN.md`](TEST_PLAN.md).

---

## 1. Why multiple SDKs matter

Ratify's value is a two-sided network: agents carry proofs and verifiers check them. Both sides need ergonomic library support in whatever language they happen to be written in. The goal is that embedding Ratify should be a single `import` statement and fewer than 20 lines of code for any mainstream stack.

A protocol with one SDK is a product. A protocol with SDKs everywhere is a protocol.

## 2. Current status

All five reference SDKs are shipped and passing conformance. The C/C++ SDK is the newest addition, targeting embedded Linux, RTOS, and any language that FFIs against a C ABI.

| Language | Package | Location | Test status |
|---|---|---|---|
| **Go** | `github.com/identities-ai/ratify-protocol` | module root | ✅ 62/62 fixtures + unit tests |
| **TypeScript / JavaScript** | `@identities-ai/ratify-protocol` | `sdks/typescript/` | ✅ 62/62 fixtures |
| **Python** | `ratify-protocol` (PyPI) | `sdks/python/` | ✅ 62/62 fixtures |
| **Rust** | `ratify-protocol` (crates.io) | `sdks/rust/` | ✅ 62/62 fixtures |
| **C / C++ via C ABI** | `libratify_c` (GitHub Releases) | `sdks/c/` | ✅ 62/62 fixtures + 58 unit tests |
| Swift | — | planned (mobile wallet) | — |
| Java / Kotlin | — | planned (Android / JVM) | — |

### C / C++ SDK — shipped in v1.0.0-alpha.8

The C SDK wraps the Rust SDK via a stable C ABI (`cbindgen`-generated header). It ships as:

- `libratify_c.a` — static library for firmware and embedded Linux
- `libratify_c.so` / `libratify_c.dylib` — shared library for Linux / macOS
- `include/ratify.h` — committed header; usable without the Rust toolchain

**Supported targets:**

| Architecture | Target triple | Example hardware |
|---|---|---|
| x86-64 | `x86_64-unknown-linux-gnu` | Intel/AMD server, Linux PC |
| ARM64 | `aarch64-unknown-linux-gnu` | Raspberry Pi 4, embedded Linux, Apple Silicon |
| ARM32 | `armv7-unknown-linux-gnueabihf` | Raspberry Pi 2/3, older embedded Linux |
| ARM Cortex-M4/M7 | `thumbv7em-none-eabihf` | STM32, NXP — FreeRTOS, Zephyr |
| RISC-V 64 | `riscv64gc-unknown-linux-gnu` | SiFive, emerging IoT |
| macOS ARM64 | `aarch64-apple-darwin` | Apple Silicon Mac |
| Windows x86-64 | `x86_64-pc-windows-msvc` | Native Windows |

**Conformance:** All 62 canonical fixtures pass through the C ABI across every fixture kind (verify, scope, revocation, revocation_push, key_rotation, session_token, transaction_receipt, witness_entry), plus 58 unit tests. Full parity with Go, TypeScript, Python, and Rust.

**FFI languages:** any language that can link a C shared library (`libratify_c.so`) can use the C SDK as its Ratify integration — Swift (via bridging header), Zig, Lua, Julia, Ruby, Elixir, and others.

## 3. Priority order for future language ports

Five SDKs are now shipped. The next ports expand platform coverage.

### Next up: Swift

**Why:** iOS Secure Enclave is the best available civilian hardware for private-key custody. A mobile wallet and native iOS integrations need a Swift SDK that integrates with iOS Keychain for secure key storage.

**Target:** SwiftPM. Crypto via Apple's CryptoKit (Ed25519) + an external ML-DSA-65 implementation (probably a Swift wrapper around liboqs or a Swift port). Must pass all 62 fixtures. Note: Swift can already link the C SDK via bridging header as an interim path.

### After Swift: Java / Kotlin

**Why:** Android, JVM agent services, and enterprise middleware. A Kotlin-first SDK covers Android wallet work and Java backends without forcing those deployments through FFI.

**Target:** Maven Central. Crypto via mainstream Ed25519 and ML-DSA-65 libraries or a tightly-audited native binding. Must pass all 62 fixtures.

### Completed: Python

**Why:** the AI/agent ecosystem is Python-heavy. LangChain, AutoGen, CrewAI, every major agent framework has Python bindings. Voice-agent platforms run Python on their backends. MCP server reference impls exist in both Python and TypeScript. A Python SDK unlocks the largest single ecosystem of agent authors.

**Status:** Implemented in `sdks/python/` and passing all 62 fixtures. Note: the `pqcrypto` ML-DSA-65 library does not support deterministic keygen from seeds, so Python is a verification-only SDK for fixture conformance — it cannot regenerate the canonical test fixtures. See `sdks/python/README.md` for details.

### Completed: Rust

**Why:** edge verifiers. Cloudflare Workers, Fastly, Vercel Edge all run WebAssembly workloads. A Rust implementation compiles to WASM and lets enterprises drop Ratify verification into their edge gateway config. Rust also covers embedded, IoT, and systems programming use cases where Go/Python aren't appropriate.

**Status:** Implemented in `sdks/rust/` and passing all 62 fixtures.

### Enterprise-pulled: Java / Kotlin

**Why:** Android wallet depends on Kotlin. Large enterprise shops run on JVM. Salesforce, Oracle, SAP, many large banks — if they embed Ratify server-side, they want a JVM SDK.

**Target:** Maven Central + Kotlin Multiplatform for mobile. Crypto via Bouncy Castle (has Ed25519 and is getting ML-DSA support) or a direct Java port.

### C / C++ via C ABI — shipped in v1.0.0-alpha.8, full conformance in v1.0.0-alpha.10

**Why:** any language that does not have a native SDK can link against a C shared library via FFI. Elixir, Ruby, Lua, Swift, Zig, embedded environments, and vendor firmware all benefit.

**Implementation:** wraps the Rust SDK via `cbindgen`-generated C ABI. Ships as `libratify_c.a` (static) and `libratify_c.so`/`.dylib`/`.dll` (shared) with a committed `ratify.h` header. Pre-built archives for common targets are published as GitHub Release assets — no Rust toolchain required to consume the SDK. See `sdks/c/` for full details.

## 4. The conformance contract

**Every Ratify SDK, in every language, MUST pass all fixtures at `testvectors/v1/` byte-for-byte.** That is the contract. Without it, an SDK may appear to work locally but silently diverge from the reference — producing signatures that fail to verify across ecosystems or verifying forgeries that the reference would reject.

### What conformance means, concretely

For every fixture in `testvectors/v1/*.json`:

**Kind = `verify`:**
- The SDK's canonical signing bytes (its `delegationSignBytes` equivalent) MUST produce hex output matching `expected.delegation_sign_bytes_hex[i]` for every cert in the chain.
- The SDK's challenge signing bytes helper MUST match `expected.challenge_sign_bytes_hex`.
- The SDK's `verifyBundle` equivalent, when called with the bundle and the `verify_options`, MUST produce a `VerifyResult` semantically equivalent to `expected.verify_result` (with `granted_scope` compared as a set, not as an ordered list — though in practice implementations SHOULD emit it lex-sorted).
- Error-path messages SHOULD match the Go reference format for cross-language tooling compatibility (e.g. `"bad_signature: cert 0: Ed25519 signature invalid"`).

**Kind = `scope`:**
- `expandScopes(fx.scope_input)` output MUST equal `expected.expanded_scopes` (order-independent but values-identical).

**Kind = `revocation`:**
- `revocationSignBytes(fx.revocation_list)` hex MUST match `expected.revocation_sign_bytes_hex`.
- The SDK's `verifyRevocationList` MUST succeed against the issuer's hybrid public key.

**Kind = `key_rotation`:**
- `keyRotationSignBytes(fx.key_rotation)` hex MUST match `expected.key_rotation_sign_bytes_hex`.
- The SDK's `verifyKeyRotationStatement` MUST succeed or fail exactly as `expected.key_rotation_verify_ok` declares.

**Kind = `session_token`:**
- `sessionTokenSignBytes(fx.session_token.token)` hex MUST match `expected.session_token_sign_bytes_hex`.
- The SDK's token MAC and streamed-turn verifier MUST succeed or fail exactly as fixture expectations declare.

**Kind = `transaction_receipt`:**
- `transactionReceiptSignBytes(fx.transaction_receipt)` hex MUST match `expected.receipt_sign_bytes_hex`.
- The SDK's `verifyTransactionReceipt` MUST succeed or fail exactly as `expected.receipt_valid` declares.

**Kind = `revocation_push`:**
- `revocationPushSignBytes(fx.revocation_push)` hex MUST match `expected.revocation_push_sign_bytes_hex`.
- The SDK's `verifyRevocationPush` MUST succeed against the issuer's hybrid public key.

**Kind = `witness_entry`:**
- `witnessEntrySignBytes(fx.witness_entry)` hex MUST match `expected.witness_entry_sign_bytes_hex`.
- The SDK's `verifyWitnessEntry` MUST succeed against the witness operator's hybrid public key.

### Minimum SDK surface

Every implementation MUST export these primitives with equivalent semantics:

| Go name | What it does |
|---|---|
| `CanonicalJSON(v) -> []byte` | RFC 8785-ish canonical JSON (§6 of SPEC). |
| `DeriveID(HybridPublicKey) -> string` | 16-byte hex ID from SHA-256(ed25519 \|\| ml_dsa_65). |
| `HybridKeypairFromSeeds(edSeed, mlSeed) -> (pub, priv)` | Deterministic keygen from two 32-byte seeds. |
| `GenerateHybridKeypair() -> (pub, priv)` | Random hybrid keypair from OS RNG. |
| `DelegationSignBytes(cert) -> []byte` | Canonical signable bytes for a cert. |
| `ChallengeSignBytes(challenge, ts) -> []byte` | Raw binary `challenge \|\| BE u64(ts)`. |
| `ChallengeSignBytesWithSessionContext(challenge, ts, sessionContext) -> []byte` | v1.1 session-bound `challenge \|\| BE u64(ts) \|\| session_context`; SDKs may expose this as an optional argument where idiomatic. |
| `ChallengeSignBytesWithStream(challenge, ts, sessionContext, streamID, streamSeq) -> []byte` | v1.1 stream-bound challenge bytes with optional session context plus `stream_id` and `stream_seq`. |
| `RevocationSignBytes(list) -> []byte` | Canonical signable bytes for a revocation list. |
| `KeyRotationSignBytes(statement) -> []byte` | Canonical signable bytes for root-key rotation statements. |
| `RevocationPushSignBytes(push) -> []byte` | Canonical signable bytes for revocation push notifications. |
| `WitnessEntrySignBytes(entry) -> []byte` | Canonical signable bytes for witness log entries. |
| `SessionTokenSignBytes(token) -> []byte` | Canonical bytes HMACed by verifier-issued session tokens. |
| `TransactionReceiptSignBytes(receipt) -> []byte` | Canonical bytes signed by every receipt party. |
| `IssueDelegation(cert, priv)` | Populates `cert.signature` (hybrid). |
| `VerifyDelegationSignature(cert) -> bool` | Returns true iff both component sigs verify. |
| `SignChallenge(challenge, ts, priv[, sessionContext]) -> HybridSignature` | Hybrid challenge signature; optional 32-byte session context binds the challenge to a verifier/session/request. |
| `SignChallengeWithStream(challenge, ts, sessionContext, streamID, streamSeq, priv) -> HybridSignature` | Hybrid challenge signature for ordered streams. |
| `VerifyChallengeSignature(challenge, ts, sig, pub[, sessionContext]) -> bool` | Both components; optional 32-byte session context must match what was signed. |
| `VerifyChallengeSignatureWithStream(challenge, ts, sessionContext, streamID, streamSeq, sig, pub) -> bool` | Both components over stream-bound challenge bytes. |
| `IssueRevocationList(list, priv)` | Populates `list.signature`. |
| `VerifyRevocationList(list, pub) -> bool` | Both components. |
| `IssueKeyRotationStatement(statement, oldPriv, newPriv)` | Populates both rotation signatures. |
| `VerifyKeyRotationStatement(statement) -> bool/error` | Verifies old-key endorsement, new-key possession, and ID/pubkey consistency. |
| `IssueRevocationPush(push, priv)` | Populates `push.signature`. |
| `VerifyRevocationPush(push, pub) -> bool/error` | Verifies signed revocation deltas. |
| `IssueWitnessEntry(entry, priv)` | Populates `entry.signature`. |
| `VerifyWitnessEntry(entry, pub) -> bool/error` | Verifies signed witness log entries. |
| `IssueSessionToken(bundle, result, secret, sessionID, issuedAt, validUntil) -> token` | Creates verifier-local session-cache token after full verification. |
| `VerifySessionToken(token, secret, now) -> bool/error` | Verifies verifier-local token MAC and validity window. |
| `SignTransactionReceiptParty(receipt, partyID, priv) -> ReceiptPartySignature` | Produces one party signature over the canonical receipt signable. |
| `VerifyTransactionReceipt(receipt, options) -> TransactionReceiptResult` | Verifies receipt envelope atomicity, party proofs, and party signatures. |
| `ExpandScopes([]string) -> []string` | Sort the deduplicated expansion. |
| `IntersectScopes(lists...) -> []string` | Chain intersection, sorted. |
| `HasScope(granted, required) -> bool` | Membership after expansion. |
| `ValidateScopes([]string) -> error?` | Reject unknown. |
| `Verify(bundle, options) -> VerifyResult` | The full verifier algorithm (§10 of SPEC). |

Naming conventions and capitalization follow the idioms of each language (`camelCase` for JS/Swift, `snake_case` for Python, `PascalCase` for Go). Semantics MUST be identical.

### Cryptography library recommendations

| Language | Ed25519 | ML-DSA-65 |
|---|---|---|
| Go | stdlib `crypto/ed25519` | `github.com/cloudflare/circl/sign/mldsa/mldsa65` |
| TypeScript | `@noble/ed25519` | `@noble/post-quantum` (ml-dsa-65) |
| Python | `cryptography` or `pynacl` | `dilithium-py`, `pqcrypto`, or liboqs-python |
| Rust | `ed25519-dalek` | `pqcrypto-mldsa` or `oqs-rs` |
| Swift | Apple `CryptoKit` | liboqs-swift wrapper (or port) |
| Java / Kotlin | Bouncy Castle | Bouncy Castle (ML-DSA support is current as of BC 1.78+) |
| C | libsodium | liboqs |

SDK authors MUST use audited, mainstream implementations. Rolling your own Ed25519 or ML-DSA-65 is not acceptable for a Ratify SDK.

## 5. Interop matrix

As more implementations ship, we maintain a cross-implementation interop matrix in CI. Every (signer, verifier) pair runs the full fixture suite:

```
                 verifier →
signer ↓    Go      TS     Python   Rust     ...
   Go       ✅      ✅     [soon]   [soon]
   TS       ✅      ✅     [soon]   [soon]
   Python   [soon]  [soon] ✅       [soon]
   Rust     [soon]  [soon] [soon]   ✅
   ...
```

Any red cell means two implementations have drifted. Drift is always a bug in at least one of them, not a spec ambiguity — the test vectors are the spec.

When a new SDK PR is opened, CI runs all existing implementations as verifiers against bundles produced by the new one, and the new one as a verifier against all existing implementations' bundles. 62 × (signer_count) × (verifier_count) total assertions per CI run at full matrix.

## 6. Contributing a new SDK

The recommended path:

1. **Open a tracking issue** naming the language and maintainer(s). Coordinate with existing maintainers on naming (package-registry conventions, repository placement).
2. **Copy the test vectors.** The canonical fixtures at `testvectors/v1/*.json` are the specification in runnable form.
3. **Implement canonical JSON first.** This is the single hardest and most error-prone part. Get to byte-identical output against every fixture's `expected.delegation_sign_bytes_hex` before writing anything else.
4. **Implement the two crypto primitives** (Ed25519 + ML-DSA-65) using audited libraries from the table above.
5. **Implement the rest** (scope vocabulary, verifier algorithm) against the spec.
6. **Run conformance.** Every fixture, byte-for-byte.
7. **Submit the PR.** Include a CI job that runs conformance on every push.

The `sdks/typescript/` directory is the reference template for what a mature SDK looks like: tests, README, package manifest, language-idiomatic type definitions, exactly one set of canonical-serialization rules, audited crypto dependencies.

## 7. Governance and naming

SDKs MAY live in this monorepo under `sdks/<language>/` (the recommended path for actively-maintained implementations), OR in their own repositories (if the maintainer prefers independent release cadence). Either is conformant as long as the fixture contract is met on every release.

Package names SHOULD follow the pattern `@identities-ai/ratify-protocol` (JS scope), `identitiesai-ratify-protocol` (Python/PyPI), `ratify-protocol` (Rust crate), etc. Namespace squatting or confusingly-similar names on public registries are not acceptable.

When transfer to a foundation (Linux Foundation, OpenSSF, etc.) happens in the future, SDK trademarks follow the protocol's naming convention and ownership moves accordingly.

## 8. Versioning

Each SDK version SHOULD track the protocol version it targets:

- `1.0.0-alpha.N` during the pre-v1 stabilization period.
- `1.0.0` after external security audit and the first stable fixture freeze.
- `1.x.y` for backward-compatible SDK improvements within Protocol v1.
- `2.0.0+` when Protocol v2 ships (and SDKs MAY support both v1 and v2 concurrently during the migration window).

SDK releases include a mandatory CI gate: run the conformance suite for the targeted protocol version. Red = no release.
