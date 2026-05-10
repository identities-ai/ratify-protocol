# Changelog

All notable changes to the Ratify Protocol are documented here. This project follows [Semantic Versioning](https://semver.org/).

For the release process and SDK coordination, see [`docs/RELEASES.md`](docs/RELEASES.md).

---

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
