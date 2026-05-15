# Changelog

All notable changes to the Ratify Protocol are documented here. This project follows [Semantic Versioning](https://semver.org/).

For the release process and SDK coordination, see [`docs/RELEASES.md`](docs/RELEASES.md).

---

## v1.0.0-alpha.9 (2026-05-15)

### Changed — SDK READMEs and registry publishing

- All five SDK READMEs (Go, TypeScript, Python, Rust, C/C++) now include a "What is Ratify Protocol?" introduction, the quantum-safe line, and consistent cross-language interop framing
- All relative links in SDK READMEs replaced with absolute GitHub URLs (broken on npm, PyPI, and crates.io package pages)
- npm package homepage updated to `docs.identities.ai`
- npm publishing switched from long-lived `NPM_TOKEN` to OIDC Trusted Publisher — no stored secret required
- `publish.sh` auto-detects prerelease tag from version string

---

## v1.0.0-alpha.8 (2026-05-13)

### Added — Fifth Reference SDK: C / C++ (`sdks/c/`)

A new C reference implementation (`sdks/c/`) ships as the fifth SDK. Licensed Apache-2.0.

**Artifacts:**
- Static library: `libratify_c.a`
- Shared library: `libratify_c.so`
- Auto-generated header: `ratify.h` (produced by cbindgen)

**Operations supported:** Delegate, Present, Verify (all three verbs), session tokens, verification receipts, revocation, key rotation, scope utilities, policy verdicts, and transaction receipts — full parity with the other four SDKs.

**Embedded target support:** `no_std` + alloc. The C SDK compiles for embedded RTOS targets (Cortex-M4/M7) with no heap allocator requirement beyond a caller-supplied alloc. Custom entropy via `ratify_set_entropy_source()` for hardware RNG on RTOS targets.

**Conformance:** 100 new tests in the C SDK. All five SDKs pass all 59 canonical test vectors byte-identical.

### Changed — Rust SDK

- **`fips204` (pure Rust) replaces `pqcrypto-mldsa` (C FFI).** The Rust SDK's ML-DSA-65 implementation is now `fips204`, a pure-Rust, `no_std`-compatible FIPS 204 implementation. Eliminates the C FFI dependency entirely.
- **`#![no_std]` + alloc support.** The Rust SDK now compiles for embedded Cortex-M4/M7 RTOS targets. Requires only `alloc`; no `std` dependency.
- **Eliminated `serde_json` from the canonical signing path.** The canonical serializer no longer touches `serde_json` in the hot path, removing a source of potential non-determinism and improving embedded portability.

### Wire format

Unchanged. All five SDKs produce and accept the same wire format as alpha.7. All 59 canonical test vectors regenerate byte-identical.

---

## v1.0.0-alpha.7 (2026-05-11)

### Added — SDK Provider Interfaces (SPEC §17)

A new SDK-architecture surface that brackets the deterministic verifier core with pluggable hooks. The protocol wire format, signable bytes, and verifier algorithm are unchanged — all 59 canonical test vectors regenerate byte-identical to alpha.6. The provider surface is purely additive: existing v1 callers continue to work with no changes.

**Provider hooks (§17.1–§17.4):**

- **`RevocationProvider` (§17.1)** — pluggable revocation lookup. Returns `(bool, error)` instead of a bare bool; errors are fail-closed (`revocation_error`). Takes precedence over the legacy `IsRevoked` closure when both are configured.
- **`PolicyProvider` (§17.2)** — verifier-local, stateful policy evaluation that runs AFTER all cryptographic / temporal / revocation / constraint / scope checks pass. Deny → `scope_denied`. Provider error → `policy_error`.
- **`AuditProvider` (§17.3)** — verification-receipt persistence hook. Invoked on every `Verify` (success AND failure). Provider errors are swallowed — auditing cannot alter the verdict.

**Crypto primitives & extension surfaces (§17.5–§17.8):**

- **`VerificationReceipt` (§17.5)** — verifier-signed attestation that a specific `ProofBundle` was verified at a specific time with a specific outcome. Hybrid-signed; chains by `prev_hash` so missing or backdated entries are detectable. Optional: the protocol does not auto-issue. SDK API: `BundleHash`, `IssueVerificationReceipt`, `VerifyVerificationReceipt`, `ReceiptHash`.
- **`PolicyVerdict` (§17.6)** — HMAC-bound cached policy decision. Same shape as `SessionToken`: issued once by a policy backend, accepted locally for the rest of `valid_until`. Context-bound: `context_hash` is SHA-256 of the canonical `VerifierContext`, so a verdict cached for one context cannot leak into another. Wired into `verify_bundle` as a fast-path that skips the live `Policy` provider; stale verdicts fall back without failing.
- **`ConstraintEvaluator` registry (§17.7)** — per-Verify map of extension constraint-type evaluators. Built-in types (§5.7.2) are handled by the SDK directly; unknown types fall through to the registry; types with no registered evaluator still fail closed with `constraint_unknown`. Naming convention: `verify.<type>` for Verify-managed types, `<vendor>.<type>` for deployment / third-party types.
- **`AnchorResolver` (§17.8)** — resolves verified `human_id` → `Anchor` (the external-identity binding registered when the HumanRoot was minted) on every successful verification. Populates `VerifyResult.Anchor` so downstream `AuditProvider`s observe identity-bound receipts. Resolver errors are non-fatal.

**Deprecation (§17.11):**

- `VerifyOptions.IsRevoked` (the legacy `func(string) bool` closure) is **deprecated** and slated for removal in `v1.0.0-beta.1`. New code MUST use `Revocation` (§17.1). The closure remains functional through all `v1.0.0-*` releases; when both fields are set, `Revocation` wins. Each SDK marks the field with its language's idiomatic deprecation mechanism.

### Why this matters

These hook points are the integration boundary between the open-source protocol and operational services that wrap it (revocation push, no-code policy UI, immutable audit ledgers, identity-directory lookups). The verifier's deterministic core stays universal and offline-capable; everything that requires global state, mutable rules, server-side state, or compliance-grade retention is delegated to a provider the deployment configures.

Bundles verified with any provider stack are byte-identical to bundles verified with no providers at all. The 59 fixtures continue to exercise only the deterministic core; providers are tested per-SDK.

### Conformance

All four reference SDKs ship matching interfaces with consistent cross-language naming (§17.4 + §17.9).

Per-SDK provider + lever test suites:
- **Go:** 12 provider + 22 lever + 4 receipt-composition tests; FuzzVerifyWithProvidersNeverPanics fuzz harness exercises provider error paths across millions of inputs.
- **TypeScript:** 12 provider + 20 lever tests.
- **Python:** 13 provider + 20 lever tests.
- **Rust:** 11 provider + 20 lever tests.

Total alpha.7 test additions: **134 tests**, all green; **59/59 canonical fixtures** regenerate byte-identical to alpha.6.

### Spec changes

- **§5.7.2 VerifyOptions** — table extended with `Revocation`, `Policy`, `Audit`, `ConstraintEvaluators`, `PolicyVerdict`, `PolicySecret`, and `AnchorResolver` fields, with precedence rules between the legacy `IsRevoked` closure and the new `Revocation` provider.
- **§17 (new section)** — Provider Interfaces, including:
  - §17.0 conformance and wire-format invariance
  - §17.1–§17.3 the three core providers
  - §17.4 cross-language naming table
  - §17.5 `VerificationReceipt`
  - §17.6 `PolicyVerdict`
  - §17.7 `ConstraintEvaluator` extension registry
  - §17.8 `AnchorResolver`
  - §17.9 cross-language naming for §17.5–§17.8
  - §17.10 surface adapters (intentionally out of scope)
  - §17.11 deprecation of legacy `IsRevoked`

### Wire format

Unchanged. v1.0.0-alpha.7 verifiers accept v1.0.0-alpha.6 bundles and vice versa.

## v1.0.0-alpha.5 (2026-05-10)

### Changed
- Renamed from Fabric Protocol to Ratify Protocol.
- No wire-format or behavioral changes.
- Updated all SDKs, documentation, and metadata to reflect the new brand.
- Patent pending and trademark notices updated.

## v1.0.0-alpha.4 (2026-04-22)

### Added — v1.1 features (all backward-compatible with v1.0)

**Continuous real-time interactions:**
- **Session binding** — optional 32-byte `session_context` in the challenge signable binds a bundle to one verifier/session. Prevents stolen bundles from being replayed at a different endpoint.
- **Stream sequence numbers** — `stream_id` + `stream_seq` in the challenge signable detect replay, reorder, and omission within multi-turn conversations.
- **Session cert cache** — HMAC-based `SessionToken` lets verifiers skip chain re-verification on subsequent turns (~95% reduction in per-turn crypto work).
- **Push-based revocation** — signed `RevocationPush` delta payload for real-time revocation propagation. `ForceRevocationCheck` verify option for high-stakes endpoints.
- **Challenge forwarding defense** — session binding defeats cross-verifier challenge relay attacks.

**Tamper-evident transaction streams:**
- **Transaction receipt envelope** — canonical `TransactionReceipt` where every party signs the same signable (terms + sorted party set + transaction ID). No partial-valid receipt state.
- **Witness append-only log** — signed `WitnessEntry` hash-chain shape for append-only audit logs.
- **Key rotation statement** — `KeyRotationStatement` signed by both old and new root keys for identity continuity.

**Security hardening:**
- Formal threat model table in SPEC §15.0 (11 adversary scenarios + 4 out-of-scope).
- Hybrid single-component-corruption fixtures proving the both-must-verify guarantee.
- Go native fuzz tests (verifier, canonical JSON, scope expansion — millions of inputs, zero panics).
- Reference verifier hardened with per-IP rate limiting, optional API key auth, and challenge store cap.
- Tiered key-custody model (self-custody, custodial, delegated) with self-custody upgrade path via `KeyRotationStatement`.

**SDK support:** all features implemented in Go, TypeScript, Python, and Rust with 59 canonical test vectors.

### Changed
- Documentation scrubbed for open-source readiness (no commercial product references).
- SPEC expanded: §5.16 VerifierContext, §5.17 VerifyOptions, §10 verifier algorithm expanded from 7 to 11 steps, §6.5 reference API fully categorized, §15.2 key-custody model, §15.3 root key compromise.

## v1.0.0-alpha.3 (2026-04-18)

### Added
- First-class constraints: `geo_circle`, `geo_polygon`, `geo_bbox`, `time_window`, `max_speed_mps`, `max_amount`, `max_rate` with 12 constraint fixtures.
- Sub-delegation gate: `identity:delegate` scope required for intermediates to sub-delegate.
- Session binding: optional `session_context` field on ProofBundle (v1.1 preview).
- Key rotation: `KeyRotationStatement` type and fixtures.
- Release tooling: `make release` with coordinated SDK tags and `make release-check` for metadata sync.

**SDK support:** Go, TypeScript, Python, Rust — 38 canonical test vectors.

## v1.0.0-alpha.2 (2026-04-14)

### Added
- Python and Rust SDK implementations.
- Cross-SDK conformance suite.
- Deterministic test-vector generator (`cmd/ratify-testvectors`).

## v1.0.0-alpha.1 (2026-04-10)

### Added
- Initial protocol specification (SPEC.md).
- Go reference implementation with hybrid Ed25519 + ML-DSA-65.
- TypeScript SDK.
- 20 canonical test vectors.
- CLI tool (`cmd/ratify`): init, delegate, verify, agent-init, agent-bundle, challenge, scopes.
- HTTP reference verifier (`cmd/ratify-verifier`).
