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
| **Go** | `github.com/identities-ai/ratify-protocol` | module root | ✅ 79/79 fixtures + unit tests |
| **TypeScript / JavaScript** | `@identities-ai/ratify-protocol` | `sdks/typescript/` | ✅ 79/79 fixtures |
| **Python** | `ratify-protocol` (PyPI) | `sdks/python/` | ✅ 79/79 fixtures |
| **Rust** | `ratify-protocol` (crates.io) | `sdks/rust/` | ✅ 79/79 fixtures |
| **C / C++ via C ABI** | `libratify_c` (GitHub Releases) | `sdks/c/` | ✅ 79/79 fixtures + API test suite |
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
| ARM Cortex-M4/M7 (with RTOS) | `thumbv7em-none-eabihf` + std shim | STM32, NXP running FreeRTOS or Zephyr |
| RISC-V 64 | `riscv64gc-unknown-linux-gnu` | SiFive, emerging IoT |
| macOS ARM64 | `aarch64-apple-darwin` | Apple Silicon Mac |
| Windows x86-64 | `x86_64-pc-windows-msvc` | Native Windows |

**std requirement:** the C SDK wraps the Rust SDK, whose JSON wire codec (`serde_json`) requires Rust `std` and a heap. It therefore targets hosted platforms (embedded Linux on any architecture, macOS, Windows) and RTOS environments that supply a std shim (FreeRTOS via an `embedded-std` shim, Zephyr's std support). Bare-metal Cortex-M with no OS and no heap is out of scope for the C SDK: use the Rust SDK directly (`#[no_std]` + `alloc`) for that.

**Conformance:** All 79 canonical fixtures pass through the C ABI across every fixture kind (verify, scope, revocation, revocation_push, key_rotation, session_token, transaction_receipt, witness_entry), plus the API test suite (44 tests), 33 advanced-surface tests, and 7 input-bound boundary tests. The C SDK proves conformance through this shared 79-fixture set; the cross-SDK byte-equivalence corpus (`testvectors/v1/cross_sdk_vectors.json`, checked hub-and-spoke against the Go reference) is consumed by Go, TypeScript, Python, and Rust, not by C.

**FFI languages:** any language that can link a C shared library (`libratify_c.so`) can use the C SDK as its Ratify integration — Swift (via bridging header), Zig, Lua, Julia, Ruby, Elixir, and others.

## 3. Priority order for future language ports

Five SDKs are now shipped. The next ports expand platform coverage.

### Next up: Swift

**Why:** iOS Secure Enclave is the best available civilian hardware for private-key custody. A mobile wallet and native iOS integrations need a Swift SDK that integrates with iOS Keychain for secure key storage.

**Target:** SwiftPM. Crypto via Apple's CryptoKit (Ed25519) + an external ML-DSA-65 implementation (probably a Swift wrapper around liboqs or a Swift port). Must pass all 79 fixtures. Note: Swift can already link the C SDK via bridging header as an interim path.

### After Swift: Java / Kotlin

**Why:** Android, JVM agent services, and enterprise middleware. A Kotlin-first SDK covers Android wallet work and Java backends without forcing those deployments through FFI.

**Target:** Maven Central + Kotlin Multiplatform for mobile. Crypto via Bouncy Castle (Ed25519, plus ML-DSA support as of BC 1.78+) or a direct Java port. Must pass all 79 fixtures. Rationale is enterprise pull: Android wallet depends on Kotlin, and large JVM shops (Salesforce, Oracle, SAP, many banks) want a JVM SDK if they embed Ratify server-side.

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

Every implementation MUST export these primitives with equivalent semantics, with one intentional exception recorded under Documented exceptions below (Python does not implement deterministic seed-based key generation):

| Go name | What it does |
|---|---|
| `CanonicalJSON(v) -> []byte` | RFC 8785-ish canonical JSON (§6 of SPEC). |
| `DeriveID(HybridPublicKey) -> string` | 16-byte hex ID from SHA-256(ed25519 \|\| ml_dsa_65). |
| `HybridKeypairFromSeeds(edSeed, mlSeed) -> (pub, priv)` | Deterministic keygen from two 32-byte seeds. |
| `GenerateHybridKeypair() -> (pub, priv)` | Random hybrid keypair from OS RNG. |
| `GenerateChallenge() -> []byte` | Cryptographically random 32-byte challenge. |
| `DelegationSignBytes(cert) -> []byte` | Canonical signable bytes for a cert. |
| `ChallengeSignBytes(challenge, ts) -> []byte` | Raw binary `challenge \|\| BE u64(ts)`. |
| `ChallengeSignBytesWithSessionContext(challenge, ts, sessionContext) -> []byte` | v1.1 session-bound `challenge \|\| BE u64(ts) \|\| session_context`; SDKs may expose this as an optional argument where idiomatic. |
| `ChallengeSignBytesWithStream(challenge, ts, sessionContext, streamID, streamSeq) -> []byte` | v1.1 stream-bound challenge bytes with optional session context plus `stream_id` and `stream_seq`. |
| `OperationContextBytes(ctx) -> []byte` | alpha.16 operation-context preimage (§6.4.9): required scope, operation, resource ID, requested path, payload digest. |
| `OperationContextHash(ctx) -> []byte` | 32-byte `request_hash` over the operation-context bytes. |
| `SessionContextBytes(inputs) -> []byte` | alpha.16 session-context preimage (§6.4.9): verifier/workspace/agent/session/invocation IDs plus the 32-byte `request_hash`. |
| `BuildSessionContext(inputs) -> []byte` | 32-byte `session_context` over the session-context bytes, ready for `VerifyOptions.SessionContext` and challenge signing. |
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
| `VerifyStreamedTurnWithOptions(token, secret, turn, options) -> VerifyResult` | Options-object streamed-turn verification against a verifier-local session token (§5.13). |
| `ExpandScopes([]string) -> []string` | Sort the deduplicated expansion. |
| `IntersectScopes(lists...) -> []string` | Chain intersection, sorted. |
| `HasScope(granted, required) -> bool` | Membership after expansion. |
| `IsSensitive(scope) -> bool` | True if a scope requires explicit grant (never introduced by wildcard expansion). |
| `ValidateScopes([]string) -> error?` | Reject unknown. |
| `Verify(bundle, options) -> VerifyResult` | The full verifier algorithm (§10 of SPEC). |

Naming conventions and capitalization follow the idioms of each language (`camelCase` for JS/Swift, `snake_case` for Python, `PascalCase` for Go). Semantics MUST be identical.

### Documented exceptions

The table above is the contract. Where an implementation cannot meet an entry,
the exception is recorded here rather than left implicit, and it is the only
place an SDK may fall short without being a defect.

**Python: `hybrid_keypair_from_seeds` raises `NotImplementedError`.** The
`pqcrypto` ML-DSA-65 binding calls PQClean's `crypto_sign_keypair`, which reads
the OS RNG and ignores a caller-supplied seed, so Python cannot honour the
deterministic half of the entry. It refuses rather than returning a keypair,
because returning one would silently break the single property the function
exists for: the same seeds would yield a different identity on every call, with
no error at the call site. Derive or restore identities from seeds with the Go,
Rust, TypeScript, or C SDK.

Python is therefore intentionally non-equivalent for this one entry. It is not
a defect and it is not expected to be fixed in the pure-Python distribution:
closing it requires a native extension, which would make the package
platform-specific. Every other entry in the table is implemented in Python,
and the deterministic keygen vector asserted by the Go, Rust, TypeScript, and
C suites has no Python counterpart for the same reason.

**C: some entries have a different shape, none are absent.** The C ABI has no
value types, so a few entries are expressed through handles or through the
lower-level primitive the contract is built on:

- `GenerateHybridKeypair` returns the public key as JSON plus the two 32-byte
  seeds that reproduce it. The protocol specifies no private-key serialisation
  format, so seeds are the C SDK's unit of private key material; feed them back
  through `ratify_human_root_from_seeds` or `ratify_agent_from_seeds`.
- `SignChallenge` is `ratify_agent_sign_challenge`, taking an agent handle
  rather than a bare private key, because that is where the C SDK holds key
  material.
- The three `ChallengeSignBytes*` entries and the two `SignChallenge*` entries
  are each one function with optional session and stream arguments, which this
  section permits where idiomatic.
- `OperationContextBytes` and `SessionContextBytes` take the same explicit
  parameters as their hash counterparts, since the context types are not
  deserialisable from JSON across the ABI.

### Cryptography library recommendations

| Language | Ed25519 | ML-DSA-65 |
|---|---|---|
| Go | stdlib `crypto/ed25519` | `github.com/cloudflare/circl/sign/mldsa/mldsa65` |
| TypeScript | `@noble/ed25519` | `@noble/post-quantum` (ml-dsa-65) |
| Python | `cryptography` (shipped SDK) | `pqcrypto` (shipped SDK) |
| Rust | `ed25519-dalek` (shipped SDK) | `fips204` (shipped SDK) |
| Swift | Apple `CryptoKit` | liboqs-swift wrapper (or port) |
| Java / Kotlin | Bouncy Castle | Bouncy Castle (ML-DSA support is current as of BC 1.78+) |
| C | `ed25519-dalek` via the Rust SDK | `fips204` via the Rust SDK |

SDK authors MUST use audited, mainstream implementations. Rolling your own Ed25519 or ML-DSA-65 is not acceptable for a Ratify SDK.

## 5. Interop

Interop is proven through a hub-and-spoke corpus, not an N×N grid.

The Go reference implementation generates a byte-equivalence corpus (`testvectors/v1/cross_sdk_vectors.json`) covering the canonical hashing and signable-bytes constructions (`verifier_context_hash`, `bundle_hash`, `policy_verdict_sign_bytes`, `verification_receipt_sign_bytes`). The TypeScript, Python, and Rust SDKs each load that corpus and assert byte-identical output against the Go reference. Because all three match the same reference bytes, they are transitively byte-identical to Go and to one another, without maintaining a quadratic set of pairwise assertions.

On top of the corpus, all five SDKs (Go, TypeScript, Python, Rust, and C) load the 79 canonical fixtures at `testvectors/v1/` and execute each fixture through the API appropriate to its kind, checking the expected result, which gives 79 × 5 fixture executions across the five SDKs. Of the 79, 62 exercise bundle verification; the rest exercise the scope, session-token, transaction-receipt, key-rotation, revocation, and witness APIs. The C SDK proves conformance through those 79 fixtures; it does not consume the cross-SDK byte-equivalence corpus.

Any divergence from the Go reference bytes is canonical-serialization drift: a bug in the diverging implementation, not a spec ambiguity. The reference bytes are the spec in runnable form.

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

Package names SHOULD follow the pattern `@identities-ai/ratify-protocol` (JS scope), `ratify-protocol` (Python/PyPI), `ratify-protocol` (Rust crate), etc. Namespace squatting or confusingly-similar names on public registries are not acceptable.

When transfer to a foundation (Linux Foundation, OpenSSF, etc.) happens in the future, SDK trademarks follow the protocol's naming convention and ownership moves accordingly.

## 8. Versioning

Each SDK version SHOULD track the protocol version it targets:

- `1.0.0-alpha.N` during the pre-v1 stabilization period.
- `1.0.0` after external security audit and the first stable fixture freeze.
- `1.x.y` for backward-compatible SDK improvements within Protocol v1.
- `2.0.0+` when Protocol v2 ships (and SDKs MAY support both v1 and v2 concurrently during the migration window).

SDK releases include a mandatory CI gate: run the conformance suite for the targeted protocol version. Red = no release.
