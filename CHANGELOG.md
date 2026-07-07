# Changelog

All notable changes to the Ratify Protocol are documented here. This project follows [Semantic Versioning](https://semver.org/).

For the release process and SDK coordination, see [`docs/RELEASES.md`](docs/RELEASES.md).

---

## v1.0.0-alpha.13 (unreleased)

### Added — SPEC §13.1: registry read binding (optional)

- Defines the open lookup contract for registry-mode key discovery (§15.4): `GET /v1/registry/principals/{human_id}` returning the current root key, the full `KeyRotationStatement` chain (oldest → newest), the optional `Anchor`, and `updated_at`. TLS mandatory; no enumeration endpoint; constant-shape 404s; short cache lifetimes.
- Resolver requirements are fail-closed on every branch (network, schema, chain order, dual-signature validity, link contiguity, final-key match, pinned-key continuity, staleness). Historical-root bundles are rejected by default after rotation. The contract states plainly that rotation proves continuity **after** first trust — first key acquisition is the trust decision — and that the v1 trust model is registry operator + TLS, with signed responses / witness-logged registries as the designated future hardening.
- A reference resolver in `cmd/ratify-verifier` ships alongside (no SDK API surface, no fixtures, no wire change).

### Fixed — C SDK version pipeline

- `sdks/c` was invisible to the release pipeline: `bump_versions` never touched its manifests (crate stuck at alpha.10 in-tree — meaning `ratify_version()` in the alpha.11/alpha.12 release binaries reported alpha.10), the CI crates job never published it (crates.io `ratify-c` frozen at alpha.8 since publishing moved off the manual flow), and `check-release-sync.sh` never checked it. All three fixed: the bump now covers `sdks/c/Cargo.toml` (crate version + `ratify-protocol` dependency pin), `Cargo.lock`, and the cbindgen header banner; the sync gate asserts all three match; the CI crates job publishes `ratify-c` after `ratify-protocol` indexes; the tag-coherence gate checks the C version. C crate bumped to alpha.12 in-tree.
- Remaining count-stale CI step/job names made count-free ("Python SDK (102 tests)", "TS full test suite (101 tests)", "C/C++ SDK (63 fixtures + API tests)", "Python full test suite (102 tests)"). Note for consumers of required status checks: the required context "Python SDK (102 tests)" is renamed to "Python SDK".

### Changed — ROADMAP

- No-expiry sentinel section rewritten from "proposed / until this ships" to shipped-in-alpha.12 behavior (and its stale SPEC §4.3 reference corrected to §5.1/§5.7).

---

## v1.0.0-alpha.12 (2026-07-06)

### Added — no-expiry sentinel (normative)

- `NO_EXPIRY_SENTINEL = 4070908799` (2099-12-31 23:59:59 UTC): a cert whose `expires_at` equals the sentinel means **"no expiry (until revoked)"**. Implementations MUST treat it that way in display and policy evaluation — never as a literal 2099 expiry. Verification is unchanged (the sentinel is a future timestamp); revocation is the sole termination mechanism. SPEC §5.1 + §5.7; Go reference adds `NoExpirySentinel` and `DelegationCert.IsNoExpiry()`; mirrored in TS (`NO_EXPIRY_SENTINEL`/`isNoExpiry`), Python (`NO_EXPIRY_SENTINEL`/`is_no_expiry`), Rust (`NO_EXPIRY_SENTINEL`/`is_no_expiry`), and the C ABI (`ratify_no_expiry_sentinel()`, `ratify_expires_at_is_no_expiry()`). Fixture: `no_expiry_cert`.
- Closes a live gap: the Ratify Verify platform already signs sentinel certs; offline SDK verifiers previously had no way to distinguish "no expiry" from a cert legitimately expiring in 2099.

### Added — `presence:represent` scope (sensitive)

- New canonical scope (54 total): the agent is authorized to attend and interact as a **direct representative of the principal** — other parties may be interacting with the agent as if it were the principal. Covers non-likeness representatives and full likeness agents.
- Design as locked 2026-07-06: does NOT imply `identity:prove` (grant both explicitly; no implication table); one scope, no fidelity sub-qualifiers; disclosure of the representation relationship is platform policy with a non-normative SPEC note — not a protocol constraint. SPEC §9.1.
- There is deliberately no `presence:*` wildcard — sensitive scopes never ride wildcards. Fixtures: `presence_represent_allowed`, `reject_presence_sensitive_wildcard`.

### Added — verifier scope-vocabulary validation (`invalid_scope`)

- The verifier now enforces SPEC §9 at verification time, not just at issuance: any cert granting a scope that is not canonical, not a wildcard, and not a `custom:` extension is rejected with the new identity status `invalid_scope`, before any effective-scope arithmetic. Previously invalid vocabulary was silently carried into the intersection and only failed by non-membership — meaning an unknown string could in principle become an effective grant. New verifier step §10 7.a2; `identity_status` enum extended (§5.9 — a closed set, extended via this spec bump). Mirrored in all SDKs; pinned by the `reject_presence_sensitive_wildcard` fixture.

### Changed — conformance suite: 59 → 63 canonical fixtures

- Four new fixtures (above). All 59 pre-existing fixtures are byte-identical to alpha.11.
- `scripts/check-release-sync.sh` now also gates SPEC.md and the TypeScript/Go/C READMEs on the fixture count, and adds a **scope-count check** derived from `scope.go` — documented counts can no longer silently drift from the vocabulary.

### Changed — release process: no more direct pushes to main

- The single-step `make release` (which committed the version bump directly to main via a ruleset bypass) is removed. Releases are now two-phase: `make release-prepare VERSION=…` creates a `release/<version>` branch, bumps versions, runs the full cross-SDK gate, and opens a PR; after it merges through the normal path (CI + DCO), `make release-tag VERSION=…` verifies main carries the bump and pushes the coordinated tags. See `docs/RELEASES.md` §4.
- `release.sh` pushes the protocol tag on its own before the `sdk-*` tags: GitHub creates no push event when more than three tags arrive in one push, which had silently prevented the tag-triggered Release workflow from ever firing (§5.3.1).
- `release-prepare` now stamps the `(unreleased)` changelog entry with the release date.

---

## v1.0.0-alpha.11 (2026-07-06)

### Changed — docs & spec truth pass (no wire change, no protocol or SDK code change)

**Wire format unchanged. All 59 canonical test vectors are byte-identical to alpha.10. No protocol or SDK code was modified — the only executable change is to the local test-gate script (see Fixed below).**

**README credibility pass.** The README described the alpha.4-era one-shot protocol; the shipped protocol is larger.

- New "Beyond one-shot verify" section surfaces the shipped v1.1 feature set: session-bound challenges, stream sequence numbers, SessionToken fast path, push-based revocation, transaction receipts, witness append-only logs, key rotation statements — each linked to its SPEC section.
- Demo section now shows representative `go run ./demos/go` output (signatures and timestamps vary per run) and describes the narrative accurately (one positive end-to-end flow + four rejection scenarios; previously mislabeled "nine-scenario — five positive").
- Repository layout tree updated: adds `streamed_verify.go`, `receipt_verify.go`, the benchmark/cross-SDK/lever/provider test files, `Makefile`, `scripts/`, `sdks/go/`, `docs/BENCHMARKS.md`, `docs/ATTRIBUTION.md`; relabels `docs/TRANSACTION_RECEIPTS.md` as normative-companion rather than "v1.1 design."
- Fixture-count note: 59 canonical fixtures; `cross_sdk_vectors.json` is a separate byte-equivalence corpus.
- The "under a millisecond" claim now links to [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).
- All five SDK READMEs gained the same "beyond one-shot verify" summary so registry pages (npm, PyPI, crates.io) tell the full story.

### Added — SPEC security-considerations hardening (guidance only, no normative wire change)

- **§15.4 Trust anchors and public-key discovery** — the five supported key-bootstrap modes (pinned keys, enterprise IdP root, registry lookup, self-published + rotation continuity, witness-backed evidence); verifiers MUST NOT treat in-band keys as trust roots.
- **Threat T12 — key-substitution attacker** added to the §15.0 threat model: signature verification proves key possession, not key ownership; trust bootstrap is a required deployment decision.
- **§15.5 Revocation freshness** — fail-closed requirement restated, staleness bounds by risk tier, `ForceRevocationCheck` guidance, push-gap recovery (full `RevocationList` refetch after a missed-delta gap).
- **§15.6 Verifier clock discipline** — NTS/NTP guidance, ±30s budget, drift-compensated challenge windows for offline/edge verifiers; temporal bounds stay strict in v1 (slack belongs at issuance, not verification).
- **§15.7 Constraint attestation limits** — constraints defend the principal against agent overreach at an honest verifier; verifier-supplied context is asserted, not proven; bind evaluated context into `VerificationReceipt`/`TransactionReceipt.terms` for auditable claims.
- **§5.13 SessionToken operational guidance** — token lifetimes by risk tier (≤5 min high-stakes, ≤15 min conversational), eviction triggers, and multi-instance `session_secret` handling for load-balanced verifiers.
- **§12 crypto agility** — why v1 fixes the algorithm pair instead of negotiating, and the migration path if a component weakens.
- **§5.16** — one-line pointer to §15.7 on what constraint evaluation does and does not prove.

### Fixed — local test gate now covers all five SDKs

- `scripts/test-all.sh` now runs the C/C++ SDK conformance and API tests. Previously the local `make test-all` / `make release` gate covered only four of the five SDKs — CI tested C/C++ on every push, but the local release preflight did not, contradicting `docs/RELEASES.md` §4.2 step 5.

### Changed — ROADMAP restructured into three buckets

Shipped (alpha.10) / planned backward-compatible (alpha.11 docs pass, alpha.12 protocol additions) / v2 wire-breaking. `presence:represent` design locked (2026-07-06): no scope implication, single scope without sub-qualifiers, disclosure as platform policy with a non-normative SPEC note. No-expiry sentinel (`4070908799`) scheduled for alpha.12.

---

## v1.0.0-alpha.10 (2026-05-17)

### Added — C/C++ SDK: full 59/59 conformance + pre-built release binaries

**C ABI surface expanded.** 13 new exported functions added to `advanced.rs`:

- `ratify_revocation_list_sign_bytes_hex`, `ratify_revocation_push_sign_bytes_hex`, `ratify_key_rotation_sign_bytes_hex`, `ratify_session_token_sign_bytes_hex`, `ratify_transaction_receipt_sign_bytes_hex`, `ratify_witness_entry_sign_bytes_hex` — canonical sign-bytes as lowercase hex for all signed types
- `ratify_revocation_push_sig_ed25519_hex`, `ratify_revocation_push_sig_ml_dsa_65_hex`, `ratify_witness_entry_sig_ed25519_hex`, `ratify_witness_entry_sig_ml_dsa_65_hex` — signature component hex accessors
- `ratify_verify_streamed_turn` — session-token fast-path multi-turn verification via C ABI
- `ratify_transaction_receipt_verify_full` — receipt verify with explicit `valid` + `error_reason` outputs
- `ratify_session_token_mac_hex` — token MAC as hex for conformance testing

**Conformance test rewritten.** `tests/conformance.rs` now exercises all 59 canonical fixtures across all 8 fixture kinds (verify, scope, revocation, revocation_push, key_rotation, session_token, transaction_receipt, witness_entry). Previously only verify fixtures (42) ran through the C ABI; all 17 non-verify kinds were skipped. Now 59/59 pass.

**Pre-built library release assets.** CI now builds and publishes `.tar.gz` archives for Linux (x86-64, ARM64, ARM32) and macOS (Intel, Apple Silicon), and `.zip` for Windows x86-64 as part of every release. C/C++ consumers no longer need the Rust toolchain.

**Wire format unchanged.** All 59 canonical test vectors regenerate byte-identical to alpha.9.

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
