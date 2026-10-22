# Protocol v2 reference compatibility ledger

Status: inventory and test plan. A reference is not v2-compatible until its
implementation has been updated where needed, run against the v2 vectors, and
its README and evidence record state the exact tested versions. Existing v1
evidence remains historical evidence for its pinned release and is not
rewritten as a v2 result.

## Compatibility rules

- Public Protocol `main` is the canonical development contract. The v1 alpha.20
  tag remains available for consumers who need the released v1 behavior.
- V2 uses a distinct protocol version, key identity namespace, schemas, and
  strict dispatch. A v1 key or proof is never silently upgraded or accepted as
  v2. References must pin an SDK version or commit and name the protocol
  profile they exercise.
- A v1 reference may remain v1-only during the v2 alpha transition, but its
  documentation must say so. It cannot be advertised as v2-compatible until
  its complete runnable path passes v2 conformance and its platform checks.
- Any provider, framework, or hardware claim needs a reproducible executable
  gate. Diagrams, proposals, and design briefs are not executable compatibility
  evidence.

## Coverage inventory

| Surface | Current artifact | V2 work and required evidence | Status |
|---|---|---|---|
| Go SDK | `sdks/go` (repository root, module `/v2`) | Reference implementation; run shared vectors, strict parser negatives, crypto vectors, Go tests, race tests, decoder fuzzing | Full v2 reference verifier. Strict decode and canonical encode of every v2 object, hybrid signatures, `VerifyProofBundleV2` live verifier, revocation status reducer, witness and receipt logs, key rotation journal, and transaction receipts. `v2_conformance_test.go` runs every file in `testvectors/v2`, and `internal/v2vectors` fails if a committed vector differs from the generator. `go vet ./...` and `go test ./...` pass; decoder fuzz targets run as seed tests. Not independently reviewed. |
| TypeScript SDK | `sdks/typescript` (`2.0.0-alpha.1`) | Same; package/version strategy must allow explicit v1 and v2 use; run vectors and TS tests | Full v2 verifier including `verifyProofBundleV2`. `npm test` (779 tests, 0 skipped) runs every file in `testvectors/v2`; see the coverage table below. v2 prereleases use the `v2-alpha` npm dist-tag. No fuzzed decode or concurrent-state tests yet. Not published. |
| Python SDK | `sdks/python` (v1), `sdks/python-v2` (v2) | Version the v2 API separately from published alpha.20; run shared vectors, malformed-input tests, full suite, and native-required CI. | The v1 package (`ratify-protocol`, `1.0.0a21` in this tree) carries no v2 API. The v2 API lives in the separate `ratify-protocol-v2` distribution, `2.0.0a1`, import package `ratify_protocol_v2`, and includes `verify_proof_bundle_v2`. Its suite (438 tests in pure-Python mode) runs every file in `testvectors/v2`, and CI repeats it with the native extra required. Locally built v1 and v2 packages install and import side by side. No fuzzed decode or concurrent-state tests yet. Not published. |
| Python native SDK | `sdks/python-native` (v1), `sdks/python-native-v2` (v2) | Build and test the exact matching wheel; check package-version lockstep and ensure stale wheels fail clearly. | Native support is deterministic key generation only, on both lines; there is no native v2 signing or verification bridge. The v1 extension (`ratify-protocol-native`, `1.0.0-alpha.21`) builds against the published v1 crate pinned exactly at `1.0.0-alpha.20`, not the v2 source tree. The v2 extension (`ratify-protocol-native-v2`, `2.0.0-alpha.1`) is version-locked to `ratify-protocol-v2`, which refuses to import a mismatched extension. Both wheels build and pass their native-required Python suites locally. Not published. |
| Rust SDK | `sdks/rust` (`2.0.0-alpha.1`) | Same; run vectors, parser negatives, cargo tests | Full v2 verifier including `verify_proof_bundle_v2`. `cargo test` passes; `tests/v2_conformance.rs` runs every file in `testvectors/v2` and asserts per-file minimum counts. No fuzzed decode or concurrent-state tests yet. Not published. |
| C SDK | `sdks/c` (`2.0.0-alpha.1`) | Same; validate constrained/edge build, memory and parser bounds, vectors, hardware-independent tests | Object-level v2 only. The `ratify_v2_*` ABI derives and checks v2 key IDs and strictly decodes and verifies the signatures of every v2 object; `cargo test --test v2_abi` runs `keys.json`, `objects.json`, `object-negatives.json`, and `key-rotation-signature.json`, and `scripts/test-v2-c-abi.sh` runs keys, objects, and negatives from a compiled C program (18 key IDs, 10 positive and 224 negative objects, 0 failures). Operation/session context, challenge-claim, and delegation-signature helpers match their vectors. There is no C stateful live verifier, status reducer, or log and rotation state machine, so the verifier ordering, status, log, and rotation sequence vectors do not run. Embedded target builds for v2 are not yet tested. Not published. |
| Google ADK | `references/google-adk` | Upgrade integration and pinned dependencies; preserve ADK-specific multi-agent, ceiling, delegation, and scale cases; run reference gate on v2 | Alpha.20 v1 evidence; v2 pending |
| LangChain | `references/langchain` | Upgrade its exact SDK pin; preserve MCP boundary and independent receiver verification; run documented gate | Alpha.19 v1 evidence; v2 pending |
| GitHub Copilot | `references/github-copilot` | Upgrade TypeScript SDK, action profile, plugin/runtime and tests; check registry entry and published Lab page | Alpha.19 v1 evidence; v2 pending |
| NVIDIA OpenShell + NOOA | `references/nvidia-nooa-openshell`, `demos/nvidia-nooa-delegated-authority` | Upgrade lock and sandbox profile; rerun all live OpenShell gates where credentials/runtime permit; preserve the alpha.20 historical campaign separately | Alpha.20 v1 evidence; v2 pending |
| Physical AI edge sentinel | `references/physical-ai-edge-sentinel` and its Pi/Arduino lab | Port constrained verifier/controller path, embedded key handling, offline/freshness/revocation behavior, replay and fail-safe actuation tests; repeat the Raspberry Pi 2 Model B ARMv7 plus Arduino Uno path with trusted RTC, no clock override, replay denial, and exact actuator invocation count. The Arduino remains an untrusted actuator; the Linux verifier is the enforcement boundary. Preserve the prior v1 physical run as dated v1 evidence. | Alpha.17/18 benchmark history and alpha.20 v1 acceptance; v2 pending |
| Classifier.dev | `references/classifier-dev` and the `ratify-classifier-reference` repository | Upgrade classifier-to-scope mapping and receiver path; run model-output adversarial cases, policy refusal cases, shared v2 vectors and deploy-independent tests | Alpha.20 v1 profile evidence; v2 pending |
| Maritime | Separate maritime reference repository | Upgrade Python pin and constrained maritime authorization examples; run offline and simulator/evidence gates; do not claim live hardware compatibility without fresh run | Alpha.16/17 v1 evidence; v2 pending |
| Agent Relay | Public Phase 2 harness `ratify-agent-relay-harness` and its published evidence | Keep the 2026-08-19 run as historical evidence for its pinned v1 version. The later network-denied rerun validates only offline harness reproduction. A v2 compatibility result requires a new versioned adapter/run and, for partner-specific claims, partner review and sign-off. | Historical v1 result retained; v2 not run |
| XMTP | XMTP proposal/reference design artifacts; no published executable Protocol reference identified in the inventory | Proposal/design only in this workspace. Keep the artifact in the inventory, but do not describe it as an executable compatible integration. If executable code is found, add its repo, adapter, pin, and gate, then test message/action binding against v2. | Design only; no compatibility claim |
| Ratify Verify service | Managed service, OpenAPI and receipt contract (not in this repository) | Implement strict v2 key/profile dispatch, cross-issuer trust, challenge/replay, revocation, receipts, migration fencing, and policy/audit fields; integration and adversarial tests | Not started |
| Receiver SDK | `ratify-receiver` | Keep v1 API pinned; add explicit v2 profile, fail-closed decision enforcement, v2 challenge/session/action binding and vectors; package tests | Not started |
| Ratify Verify web app | Managed service user interface (not in this repository) | Explain profile/version and trust domain, key migration and revocation policy; UI/API contract tests | Not started |
| Ratify developer docs | docs.ratifyprotocol.com | Explain alpha v2 break, pin-v1 choice, migration sequence, all v2 integrations, boundaries and no-guarantee language | Not started |
| Ratify Labs catalog | Public reference catalog | Per-reference v1/v2 status and links; never advertise untested v2 paths | Not started |
| Protocol demos | `demos/*`, including bounded-tool-call and NVIDIA | V2 examples plus preserved explicitly pinned v1 examples; run every demo gate and verify command documentation | Not started |
| Registry and discovery | `references/registry/*`, `references/README.md`, root README | Versioned profiles, executable gate, exact tested package versions, review state and working links | Not started |

## Protocol v2 vector coverage at 2.0.0-alpha.1

Each cell names the test that consumes the file and how many vectors it runs.
"Yes" without a count means the whole file is checked by one test. Python
native has no verifier of its own; it reruns the Python v2 suite with the
native extra required.

| `testvectors/v2` file | Go reference | TypeScript | Python v2 | Rust | C ABI |
|---|---|---|---|---|---|
| `keys.json` (18 keys, 6 invalid IDs) | Yes | Yes | 18 + 6 | Yes | 18 + 6 (Rust-driven); 18 (compiled C) |
| `objects.json` (10 objects, 14 signatures) | Yes | 10 | 10 | 10 | Verify only: 10 (Rust-driven and compiled C) |
| `object-negatives.json` (224) | Yes | 224 | 224 | 224 | 224 (Rust-driven and compiled C) |
| `verifier-ordering.json` (81: 32 pre-claim, 2 replay, 47 terminal) | Yes | 81 | 81 | 81 | Not run |
| `status-sequences.json` (20 scenarios, 39 queries) | Yes | 20 | 20 | 20 | Not run |
| `log-sequences.json` (witness and receipt logs) | Yes | 2 | 2 | 2 | Not run |
| `rotation-sequences.json` | Yes | 1 | 1 | 1 | Not run |
| `key-rotation-signature.json` (genesis and continuation) | Yes | Yes | 2 | Yes | Verify only: 2 |
| `delegation-signature.json` | Yes | Yes | Yes | Yes | Key ID and signature primitive |
| `operation-session-context.json` | Yes | Yes | Yes | Yes | Yes |
| `challenge-claim.json` | Yes | Yes | Yes | Yes | Yes |

Go, TypeScript, Python v2, and Rust run the full stateful verifier
(`VerifyProofBundleV2` and its equivalents) against the ordering vectors,
including stage, error class, terminal tuple, exact receipt body, allow
horizon, rate batch, and callback counts. The C ABI verifies key IDs, strict
object decoding, and object signatures only. Each TypeScript, Python, and Rust
runner also fails if `testvectors/v2` contains a file it does not consume.

What this alpha does not yet prove, against the `2.0.0-beta.1` gates in
SPEC-v2 §8.1: fuzzed decode tests outside Go; concurrency and issuer-collision
tests against the reference stores in every SDK; the vector files marked
required for beta in `testvectors/v2/README.md` (limits, numeric bounds,
constraints, security journal, status provenance, provider failures, trust
resolution, stream sequence, claim lifecycle, release, transaction
verification, archival, and external signer); fixtures generated by every SDK
and verified by every other; a C stateful verifier with its suite run on armv7
Linux hardware; Python signing through the native backend only; and a recorded
closure of the internal adversarial review. Embedded v2 target builds remain
untested. External independent review is a `2.0.0` gate (SPEC-v2 §8.2), not a
beta gate. v2.0.0-alpha.1 is therefore not a v2 conformance claim.

## Cross-SDK fixture matrix (SPEC-v2 §8.1)

Each SDK writes `testvectors/v2/cross-sdk/<sdk>.json` from fresh keys and
hedged ML-DSA-65 signatures, and every SDK verifies every fixture present
with its `objects.json` positive procedure. The format and procedure are in
[`testvectors/v2/README.md`](../testvectors/v2/README.md#cross-sdk). Rows
are the producing SDK and columns the verifying SDK. A cell is filled only
when that verifier's suite runs that fixture and passes.

| Producer (row), verifier (column) | Go | TypeScript | Python v2 | Rust | C ABI |
|---|---|---|---|---|---|
| Go (`go.json`, `go run ./cmd/ratify-v2-cross-sdk`) | Pass (`TestV2CrossSDKFixtures`) | Not run | Not run | Not run | Not run |
| TypeScript | No fixture | No fixture | No fixture | No fixture | No fixture |
| Python v2 | No fixture | No fixture | No fixture | No fixture | No fixture |
| Rust | No fixture | No fixture | No fixture | No fixture | No fixture |
| C ABI | No fixture | No fixture | No fixture | No fixture | No fixture |

Only Go to Go is covered. The §8.1 gate requires every cell. The TypeScript
runner's unconsumed-entry check lists directory entries, so it also reports
`cross-sdk` until that port consumes the directory.

## Corpus changes pending SDK ports (beta reconciliation)

The Go reference and SPEC-v2 were reconciled for `2.0.0-beta.1` after alpha.1.
Only the Go reference runs the resulting corpus; the other SDK suites fail
against it until they are ported, and no SDK other than Go may be described as
passing it. Changes to `testvectors/v2`:

| File | Change since alpha.1 |
|---|---|
| `object-negatives.json` | 224 → 281 negatives: the closed v2 constraint registry, every wire timestamp outside 0..253402300799, `custom:*` and bare-prefix required scopes in receipts, and the optional receipt member `constraint_evaluators` |
| `verifier-ordering.json` | 81 → 194 cases (57 pre-claim, 2 replay, 133 committed, 2 evaluating), including 10 Middleware Custody Profile cases; new input fields (`tzdb_version`, amount and currency request context, `extension_counts` and `extension_values`, `constraint_evaluators`, `status_keys`, `status_policy`, `journal`, signed status evidence batches) and the `progress` and `evaluator` callback counts; exact `custom:` required scopes; committed outcomes are not decisions |
| `operation-session-context.json` | `invalid_required_scopes` replaces `custom:invoice:read`, now a valid exact required scope, with the bare prefix `custom:` |
| `status-sequences.json` | 20 → 22 scenarios; exclusive `next_update` and status-age deadlines |
| `objects.json` | The constrained-certificate object now pins every v2 registry schema (`time_window`, `max_amount` in micro-units); its bytes, digests, and signatures changed |
| `log-sequences.json`, `rotation-sequences.json` | Section references in descriptions only |
| `limits.json` | New: 32 byte, count, and timestamp boundary cases, including the status evidence batch |
| `hedged-signatures.json` | New: 10 objects with 2 hedged ML-DSA-65 variants each (not reproducible) |
| `security-journal.json` | New: `SecurityJournalV2` snapshot known answers, transitions, migration, import negatives |
| `lifecycle-scenarios.json` | New: 28 Part B scripts (140 steps) against each SDK's in-memory reference store, plus 29 `profile_scenarios` for the single-device offline and dual-root profiles, over 23 requests |
| `transaction-verification.json` | New: 12 composed transaction verification cases |
| `annex-a.json` | New: Annex A clause digests, canonical JSON and strict-decode cases, and the scope vocabulary, expansion, intersection, and `custom:` cases |
| `issuer-duties.json` | New: 11 delegation issuer-duty cases for the typed signer |
| `challenge-issuance.json` | New: 9 challenge issuance helper scenarios (33 steps) |
| `status-publisher.json` | New: 13 signed-status publisher scenarios (39 steps) with journal ingestion and role-configuration refusals |
| `evaluator-profiles.json` | New: 70 standard evaluator profile cases (34 `max_count/v1`, 36 `allowed_values/v1`) and 13 request-context bound cases |

SDK test files that read these vector files, and therefore fail until ported:

| SDK | Test file | Changed files it reads |
|---|---|---|
| TypeScript | `sdks/typescript/test/conformance_v2.test.ts` | `objects.json`, `object-negatives.json`, `verifier-ordering.json`, `status-sequences.json`, `log-sequences.json`, `rotation-sequences.json`; also fails on the eight new files it does not consume |
| Python v2 | `sdks/python-v2/tests/test_v2_conformance.py` | Same files as TypeScript, and the same unconsumed-file check |
| Python v2 | `sdks/python-v2/tests/test_mldsa65_pure.py` | `objects.json`, `object-negatives.json` |
| Rust | `sdks/rust/tests/v2_conformance.rs` | Same files as TypeScript, with per-file minimum counts, and the same unconsumed-file check |
| Rust | `sdks/rust/tests/v2_roundtrip.rs` | `objects.json` |
| C ABI | `sdks/c/tests/v2_abi.rs`, `sdks/c/scripts/test-v2-c-abi.sh` | `objects.json`, `object-negatives.json` (the new timestamp and registry negatives) |
| C ABI | `sdks/c/src/v2.rs` | `objects.json` (test module) |

Go reference state on this branch: `go test ./...` runs every file in
`testvectors/v2`; the decoder fuzz targets (`scripts/fuzz-v2.sh`) cover every
v2 decoder including the status evidence batch, checkpoint acknowledgement,
journal snapshot import, and archival proof verification. The external signer
interface is tested with direct signing and with an external-μ provider that
the tests emulate in software; no hardware security module or key-management
service has been exercised, and no provider-specific claim is made (SPEC-v2
§3.2).

## Fresh v1 baseline runs

These runs were repeated on 2026-10-11 to verify the current pinned v1 references before making v2 changes. They do not establish v2 compatibility.

| Reference | Result | Scope and limitation |
| --- | --- | --- |
| Google ADK | 49/49 passed, zero skipped; published alpha.20 | `./scripts/google-adk-reference-check.sh`; warnings were framework deprecations/experimental-feature notices.
| LangChain | 28/28 passed, zero skipped; published alpha.20 | `./scripts/langchain-reference-check.sh`; pins: LangChain 1.3.14, MCP adapter 0.3.0, MCP 1.29.0.
| GitHub Copilot | 9/9 passed, zero skipped; plugin build and demo passed | `./references/github-copilot/run-reference-check.sh`; npm reported 4 dependency advisories (2 moderate, 1 high, 1 critical), which need separate dependency-scope triage.
| NVIDIA NOOA | 181/181 passed, zero skipped; Python 3.12.10, NOOA 0.0.8, MCP 2.0.0 | `PYTHON=/path/to/python3.12 ./scripts/nvidia-reference-check.sh`; this gate does not run the live OpenShell container profile.
| NVIDIA OpenShell profile | 64 passed, 0 failed, 0 skipped; all 52 required live profile cases passed; OpenShell CLI 0.0.102 | Isolated Colima profile, published Ratify SDK, pinned sandbox image; cleanup verified with zero residual containers. Alpha.20 v1 evidence only.
| classifier.dev | Existing `npm run check` passed, including TypeScript checks, 6 tests, and build | Source repository gate; its scope and exact pinned versions remain v1 evidence.
| Published receiver SDK | `@identities-ai/ratify-receiver@0.1.4`, commit `5caf88b`; `npm run check` passed 115/115 | Published main artifact and unchanged v1 behavior; no v2 compatibility claim.
| Physical AI edge | Fresh alpha.20 production-binary Pi 2/Arduino run passed; core suite 29/29, 0 skipped | Trusted DS3231 clock, normal 300-second quarantine, no override; monitor did not actuate; direct request and first captured-proof replay produced 2 LED calls; exact second replay was denied with no extra call. v1 evidence, not v2 compatibility.

## Completion record

For every row, replace “Not started” with one of `v2 tested`, `v1 only`,
`design only`, or `not applicable`, and link the command, immutable version,
run date, and result. Record platform limitations and skipped checks beside the
result. A skipped hardware or hosted-platform gate cannot be counted as passed.
