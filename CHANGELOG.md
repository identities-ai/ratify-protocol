# Changelog

All notable changes to the Ratify Protocol are documented here. This project follows [Semantic Versioning](https://semver.org/).

For the release process and SDK coordination, see [`docs/RELEASES.md`](docs/RELEASES.md).

---

## v1.0.0-alpha.20 (2026-09-01)

Completes the C SDK's context-binding surface. No canonical bytes, fixture
contents, wire format or verifier behavior change, and the protocol version
remains 1. The Go, Rust, Python and TypeScript SDKs are unchanged in this
release; their versions move only to keep the release line synchronized.

### Added

- **C: `ratify_proof_bundle_create_with_context`.** Every other reference
  implementation could already build a ProofBundle bound to a 32-byte session
  context: Go through `SignChallengeWithSessionContext`, Rust through
  `sign_challenge_with_session_context`, and Python and TypeScript through the
  optional `session_context` argument on their challenge signing functions. The
  C SDK could not, so a C caller could verify a context-bound proof but never
  produce one, and any C integration needing that binding had to reach outside
  the published surface.

  The new function mirrors `ratify_proof_bundle_create` with two extra
  parameters, and follows the Go and Rust shape of a separate entry point
  rather than an optional argument, which C cannot express. Both the challenge
  and the session context must be exactly 32 bytes; any other length returns
  `RatifyErrBadArgument` and produces no bundle. Existing symbols are
  unchanged, so the addition is ABI-compatible for callers already linked
  against alpha.19.

## v1.0.0-alpha.19 (2026-08-30)

A security release for the TypeScript SDK. No canonical bytes, fixture
contents, wire format or verifier behavior change, and the protocol version
remains 1.

### Fixed

- **TypeScript: quadratic backtracking when stripping base64 padding.** The
  fallback decoder in `sdks/typescript/src/canonical.ts` stripped trailing `=`
  with the regular expression `/=+$/`. Against a run of `n` padding characters
  followed by any non-terminal character, that expression backtracks
  polynomially: measured at 52 ms for 10 000 characters, 847 ms for 40 000 and
  3.4 s for 80 000, which extrapolates to several seconds of blocked event loop
  at the 128 KiB `MAX_PROOF_BUNDLE_BYTES` ceiling. The decoder is exported and
  its input is not always size-checked before the call, so one crafted bundle
  could stall a verifier.

  The strip now scans backwards, which is linear and measured below a
  millisecond at every size above.

  This affects only the path taken where `Buffer` is undefined: browsers, Deno
  without node compatibility, and edge runtimes. Node.js uses `Buffer` and was
  never exposed. Decoded output is unchanged and the canonical fixtures still
  pass byte-identically.

### Changed

- **CI workflow token scoped to read-only.** `.github/workflows/ci.yml` declared
  no `permissions` block, so its token inherited the repository default, which
  may grant write. Every job in that workflow only checks out and runs tests.
  Publishing lives in `release.yml`, which grants its own scopes.

---

## v1.0.0-alpha.18 (2026-08-30)

An SDK surface release. No canonical bytes, fixture contents, wire format or
verifier behavior change, and the protocol version remains 1.

### Added

- **Deterministic key generation in Rust and C.** `docs/SDKS.md` requires every
  SDK to export `HybridKeypairFromSeeds`, and neither the Rust SDK nor the C ABI
  had it. Without it an application cannot reconstruct an identity it created,
  so a C or Rust issuer could mint a key and publish its public half but never
  load it back, and any verifier pinning that identity broke on the next
  restart. Seeds are the portable unit of private key material: the protocol
  specifies no private-key serialization format, so storing two 32-byte seeds
  and rebuilding is the supported way to persist an issuer identity.
- **Remaining minimum-surface entries in the C ABI:** `ratify_derive_id`,
  `ratify_canonical_json`, `ratify_delegation_sign_bytes_hex`,
  `ratify_challenge_sign_bytes_hex`, `ratify_verify_delegation_signature`,
  `ratify_agent_sign_challenge`, `ratify_verify_challenge_signature`,
  `ratify_generate_hybrid_keypair`, `ratify_human_root_from_seeds`,
  `ratify_agent_from_seeds`, `ratify_agent_pub_key_json`, and the operation- and
  session-context byte helpers. Four entries take a different shape because the
  ABI has no value types; each is documented in `docs/SDKS.md`.
- **A deterministic keygen known-answer vector** asserted by the Go, Rust, C and
  TypeScript suites. The canonical fixtures carry no seeds, so nothing held the
  seeded implementations to each other: one could have been deterministic and
  deterministically different from the rest with every existing test passing.

### Fixed

- **The native extra's pyo3 dependency carried three security advisories.**
  `ratify-protocol-native` was introduced pinned to pyo3 0.22, which is subject
  to GHSA advisories for an out-of-bounds read in `PyList`/`PyTuple` iterator
  `nth`/`nth_back` (high), a missing `Sync` bound on
  `PyCFunction::new_closure` (moderate), and a buffer overflow risk in
  `PyString::from_object` (low). The extension calls none of those APIs, so
  none was reachable through it, but a package in this project's supply chain
  should not ship against known advisories. Now pinned to pyo3 0.29, which
  patches all three. `PyBytes::new_bound`, the transitional name from pyo3's
  Bound migration, is now `PyBytes::new`. Key generation output is unchanged
  and still matches the cross-SDK vector byte for byte.

- **Python: `time_window` constraints were denied on any host without a system
  IANA time zone database.** `zoneinfo` reads the operating system's copy where
  one exists and falls back to the `tzdata` package where it does not. Windows
  ships no system database and minimal Linux containers often omit theirs, so on
  those hosts every `time_window` constraint resolved no zone and failed closed
  with `constraint_denied: unknown timezone`. The same proof bundle therefore
  verified on one machine and was rejected on another. `tzdata` is now a
  dependency. Affects every published Python release to date; no other SDK is
  affected, and nothing about the wire format or the fixtures changes.

- **The C conformance suite did not assert two requirements it claimed to meet.**
  `docs/SDKS.md` requires that for every `Kind = verify` fixture an SDK's
  delegation signing bytes match `expected.delegation_sign_bytes_hex` and its
  challenge signing bytes match `expected.challenge_sign_bytes_hex`. The Go and
  Rust suites assert both. The C suite asserted neither, because the ABI did not
  expose the helpers, so it was structurally narrower than the contract. Both
  assertions now run across all canonical verify fixtures.
- **The generated C header could go stale.** `sdks/c/build.rs` declared
  `rerun-if-changed` for `src/lib.rs` only, while most of the ABI lives in
  `src/advanced.rs`. A change confined to that file regenerated nothing, so the
  committed `include/ratify.h` kept its previous contents: a newly added symbol
  was compiled into the library but never declared for callers, and a removed
  one stayed declared and would fail at link time.

### Added

- **Optional native extra for Python deterministic key generation.**
  `pip install 'ratify-protocol[native]'` installs `ratify-protocol-native`, a
  separate distribution that supplies seed-based key generation through the
  Ratify Rust core. With it, the same two seeds produce the same identity in
  Python as in every other SDK, and Python asserts the same cross-SDK keygen
  vector as the Go, Rust, C and TypeScript suites.

  It is a separate distribution on purpose: `ratify-protocol` itself remains a
  pure-Python `py3-none-any` wheel that installs on any platform and any
  supported CPython, and a release check asserts that it stays that way. The
  extra ships abi3 wheels, so one wheel per platform covers every CPython from
  3.10 up. Installing it is only necessary for seed portability across
  languages: verifying proofs, issuing delegations, signing challenges, and
  persisting an identity by storing its key bytes all work without it. Signing
  and verification always use `pqcrypto` and are unaffected.

### Changed

- **Python `hybrid_keypair_from_seeds` now raises `NotImplementedError` when the
  native extra is absent.**
  It previously accepted an ML-DSA seed, validated that it was exactly 32 bytes,
  and then discarded it: the `pqcrypto` binding calls PQClean's
  `crypto_sign_keypair`, which reads the OS RNG. Callers passing identical seeds
  received different keypairs with no error and no warning at the call site, so
  anyone persisting seeds to restore an identity silently received a new one and
  discovered it only when verification failed elsewhere. This is a behavioral
  change for any caller of that one function; every other Python entry point is
  unaffected. Install the `native` extra above, or derive identities from seeds
  with the Go, Rust, TypeScript or C SDK.

---

## v1.0.0-alpha.17 (2026-08-24)

A packaging and documentation release. No SDK behavior, canonical bytes or fixture
contents change, and the protocol version remains 1.

### Fixed

- **Python SDK dependency bound.** `pqcrypto` 1.0.0, published 2026-08-15, changed ML-DSA-65
  behavior, and hybrid signatures do not verify against it. The Python package declared
  `pqcrypto>=0.3.4` with no upper bound, so any installation made after that date produced a
  verifier that rejected valid signatures, including the canonical fixtures. The dependency is
  now bounded to `>=0.3.4,<1.0`. No other SDK depends on `pqcrypto`, and Go, TypeScript, Rust
  and C were unaffected. Signed objects, canonical bytes, fixture contents and the verifier
  algorithm are unchanged; this is a packaging repair rather than a protocol change. Anyone who
  installed `1.0.0a16` between 2026-08-15 and this release should upgrade, or pin
  `pqcrypto<1.0` alongside it.

### Changed

- **Extension type namespaces:** newly defined extension constraint types now
  use a reverse-domain prefix controlled by the defining organization. Ratify
  profiles use `com.ratifyprotocol.<profile>.<type>`. Existing signed names,
  verifier behavior, SDK APIs, and canonical fixture bytes are unchanged.

---

## v1.0.0-alpha.16 (2026-08-05)

The "resource-bound authority" release: delegations can now name *where* a scope applies, not just *what* it permits.

### Added — specification (implementation follows in the same release)

- **`resource_path` constraint** (SPEC §5.7.2, §5.7.3): binds a delegation to an opaque `resource_id` (exact byte equality, never dereferenced or normalized) and an optional `path_prefix` under segment-boundary matching — deliberately a prefix, not a glob. Absolute logical POSIX-style path model with dot-segments, backslashes, and empty interior segments rejected outright; percent-encoding does not exist in the path model, and post-verification path transformation is forbidden. NFC pre-normalization is the issuer's obligation; the verifier compares bytes exactly (a mixed-form pair fails closed; byte identity, not visual identity, is the boundary). Chain evaluation is conjunctive: effective authority can stay the same or narrow but never widen (a child may carry a broader prefix on the same resource and still verify, gaining nothing because every upstream constraint still applies), and jointly unsatisfiable constraint sets — different resources, or same-resource prefixes that don't nest — must be rejected at issuance (decoders still accept them; verification fails closed).
- **Resource-identifier profiles** (SPEC §5.7.4, `docs/RESOURCE_PROFILES.md`): the shared recipes that make an opaque `resource_id` interoperable. Git profile v1 (repository identity — never a branch, commit, or checkout; renames and transfers fail closed) with known-answer and negative vectors. Profiles for platform-owned resources are authored by the platforms themselves and linked when published.
- **Extension-constraint `params`** (SPEC §5.7.1, §17.7): parameterized extension constraints are now representable in signed certificates under a restricted, cross-language-deterministic value model. Type-only extension constraints serialize exactly as before; existing signed certs remain byte-stable. Closes the wire-format limitation documented in alpha.15.
- **Input bounds** (SPEC §5.1): `MAX_PROOF_BUNDLE_BYTES` (128 KiB, applied to the received wire representation and enforced before parsing), `MAX_JSON_NESTING_DEPTH`, and per-cert scope/constraint count and length limits. Violations route to the existing `invalid` status. §5.1 also notes that the byte ceiling and `MAX_DELEGATION_CHAIN_DEPTH` are independent and can bind near the same point: a chain within the depth limit can still be rejected by the wire decoder for exceeding `MAX_PROOF_BUNDLE_BYTES` before depth is evaluated, so operational depth choices should budget for the deployment's maximum expected per-certificate content.
- **Conformance suite** grows from 63 to 79 canonical vectors: 16 new verify-kind fixtures (14 `resource_path` accept/deny/unverifiable/narrowing/escape/traversal/percent-literal/root/trailing-slash/whole-resource/unsatisfiable-pair, 1 extension-`params`, 1 depth-8), with `reject_chain_too_deep` regenerated at depth 9. Byte-identical across all five SDKs.
- **`VerifierContext` resource fields** (SPEC §5.16): `RequestedResourceID`, `RequestedPath`, `HasResource`, with the standard fail-closed absence semantics.
- **Confinement guidance** (SPEC §15.7): a verified `resource_path` is lexical authorization, not filesystem confinement. Stated as normative properties rather than a prescribed mechanism: the deployment states its concurrent-mutation attacker model; a confinement or policy refusal leaves no operation-created effect inside or outside the boundary (with identity-safe cleanup that never touches objects a concurrent principal substituted); execution causes no effect outside the boundary; write atomicity is a separate contract; and refusal tests must attribute effects to the operation rather than assert blanket snapshot equality. Descriptor-relative traversal is the illustrative mechanism, not a mandate.

### Changed

- **`MAX_DELEGATION_CHAIN_DEPTH` raised from 3 to 8** (SPEC §5.1) for multi-hop agent topologies. The ceiling is a wire-determinism and denial-of-service bound, not cryptography; the new byte/count/length limits bound the work that depth alone does not.

### Fixed

- **Cross-SDK constrained-bundle hashing**: `bundle_hash` serialized a delegation's constraints in their raw in-memory form instead of the canonical per-kind wire form, so any bundle whose cert carried a constraint (for example a `resource_path` constraint) produced a digest that diverged from the Go reference. Python diverged on every constrained bundle; TypeScript carried the same issue latently, surfacing only for a programmatically constructed constraint. Both SDKs now map constraints through the canonical per-kind form (`to_canonical_dict` / `canonicalConstraintDict`), and a constrained cross-SDK byte-equivalence vector plus a TypeScript raw-object regression test prevent recurrence. Identity verification and signature validity were unaffected; Go, Rust, and C were already correct.

---

## v1.0.0-alpha.15 (2026-07-25)

The "integration readiness" release: everything an integrator needs to adopt the SDKs over a real transport without hand-written glue, driven by the Agent Relay integration spike. No fixture changes — all 63 canonical vectors are byte-identical to alpha.13.

### Added — public wire codecs and vocabulary parity (#39, #40)

- TypeScript and Python gain public, strict wire codecs: `encode`/`decode` for `DelegationCert`, `ProofBundle`, and `SessionToken`. Round-trip identity is fixture-tested and cross-SDK transport parity is asserted byte-for-byte in both directions.
- Strict wire acceptance across all five SDKs: duplicated keys, out-of-domain integers, invalid UTF-8, and unknown fields are rejected before verification, and the normative JSON integer domain is stated in the SPEC.
- `Vocabulary()` and `ScopeWildcards()` accessors in TypeScript, Python, Rust, and C, matching Go, with a cross-SDK parity vector.

### Added — single-use challenge acceptance (#41)

- `ChallengeStore` interface (`Issue`/`Validate`/`Consume`) with an in-memory implementation in every SDK (C: `ratify_challenge_store_*`). Consume atomically removes the issuance record, so store capacity counts pending challenges only; concurrent consumption admits exactly one winner.
- SPEC §10 makes single-use acceptance normative for challenge-issuing verifiers (steps 2b and 9b): the store is consulted without consuming before signature work and atomically consumed after the challenge signature verifies, before authorization — so a forged presentation never burns a challenge and a denied caller cannot probe authorization with one liveness proof. Every store failure normalizes to one canonical `unknown_challenge` response (response-level indistinguishability; the timing channel of the early lookup is explicitly out of scope).
- Threat-model row T1 corrected: freshness alone bounds replay to the window; single-use eliminates it at issuing verifiers; self-issued challenges need request-level deduplication.

### Added — streamed-turn verification with options (#42)

- Options-object streamed-turn verifier in every SDK (Go `VerifyStreamedTurnWithOptions`, C `ratify_verify_streamed_turn_opts`) taking a dedicated `StreamedVerifyOptions`: required scope (checked against `token.granted_scope`), challenge store (single-use on the fast path), session context, stream state, and clock override — and nothing else. Full-verifier options cannot be passed and silently ignored: distinct types at compile time in Go/Rust/C, runtime fail-closed rejection in TypeScript and Python.
- Stream state is documented as a caller-owned snapshot with an atomic-advance requirement; the token-HMAC-first order is stated normatively in §5.13. The positional streamed verifiers are deprecated (still callable).

### Added — operation-context and session-context constructions (#43)

- SPEC §6.4.9: canonical, domain-separated, length-prefixed constructions. `OperationContextBytes` binds the action (scope, operation, resource, path, payload digest) into a 32-byte `request_hash`; `SessionContextBytes` binds verifier/workspace/agent/session/invocation identifiers plus that hash into the 32-byte `session_context`. Implemented in all five SDKs with shared known-answer vectors proving byte-identical hashes; ill-formed Unicode is rejected everywhere.
- SPEC §15.2.1: the named **Middleware Custody Profile** for deployments where platform middleware holds agent keys — every presentation session-bound with these constructions, `request_hash` derived from the specific action, receipts binding the hash and never the preimage.

### Changed — documentation accuracy (#44)

- Per-SDK verify-latency matrix and wire-size table in `docs/BENCHMARKS.md`; every sub-millisecond claim is qualified to the Go/Rust/C SDKs; session tokens are repositioned as the default pattern for repeated interactions with accurate one-vs-N+1 signature-count framing (an earlier ~95% claim is corrected everywhere, including per-SDK READMEs and a changelog erratum below); §17.7 gains the type-only extension-constraint limitation note; allocation attribution is profile-backed.

---

## v1.0.0-alpha.13 (2026-07-06)

### Added — SPEC §13.1: registry read binding (optional)

- Defines the open lookup contract for registry-mode key discovery (§15.4): `GET /v1/registry/principals/{human_id}` returning the current root key, the full `KeyRotationStatement` chain (oldest → newest), the optional `Anchor`, and `updated_at`. TLS mandatory; no enumeration endpoint; constant-shape 404s; short cache lifetimes.
- Resolver requirements are fail-closed on every branch (network, schema, chain order, dual-signature validity, link contiguity, final-key match, pinned-key continuity, staleness). Historical-root bundles are rejected by default after rotation. The contract states plainly that rotation proves continuity **after** first trust — first key acquisition is the trust decision — and that the v1 trust model is registry operator + TLS, with signed responses / witness-logged registries as the designated future hardening.
- A reference resolver in `cmd/ratify-verifier` implements the resolver requirements — fail-closed on every branch, TLS-only, pins keyed by the pinned key's own derived id, pin checks re-evaluated on cache hits — with TLS-server test coverage. Both deployment modes are demonstrated end to end: `--registry` (registry trust: operator + TLS) and `--registry-pins` + `--registry-require-pinned` (pin-plus-registry: only first-trusted principals and their rotation successors, via `ResolveRootDescendedFromAnyPin`). No SDK API surface, no fixtures, no wire change.

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
- `release.sh` pushes the protocol tag on its own before the `sdk-*` tags: GitHub creates no push event when more than three tags arrive in one push, which had silently prevented the tag-triggered Release workflow from ever firing (see `docs/RELEASES.md` §5.3.1).
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

- **§5.17 VerifyOptions** — table extended with `Revocation`, `Policy`, `Audit`, `ConstraintEvaluators`, `PolicyVerdict`, `PolicySecret`, and `AnchorResolver` fields, with precedence rules between the legacy `IsRevoked` closure and the new `Revocation` provider.
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
- **Session cert cache** — HMAC-based `SessionToken` lets verifiers skip chain re-verification on subsequent turns (one hybrid signature verification per turn instead of N+1; an earlier revision of this entry overstated the reduction as ~95%).
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
