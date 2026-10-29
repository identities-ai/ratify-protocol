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
| Go SDK | `sdks/go` (repository root, module `/v2`) | Reference implementation; run shared vectors, strict parser negatives, crypto vectors, Go tests, race tests, decoder fuzzing | Full v2 reference verifier. Strict decode and canonical encode of every v2 object, hybrid signatures, `VerifyProofBundleV2` live verifier, revocation status reducer, witness and receipt logs, key rotation journal, and transaction receipts. `v2_conformance_test.go` runs every file in `testvectors/v2`, and `internal/v2vectors` fails if a committed vector differs from the generator. `go vet ./...` and `go test ./...` pass (3537 tests and subtests, 0 skipped, measured 2026-10-27), `go test -race -timeout 40m ./...` passes, and `scripts/fuzz-v2.sh` runs every v2 decoder fuzz target (20 targets, 30 seconds each). Not independently reviewed. |
| TypeScript SDK | `sdks/typescript` (`2.0.0-beta.1`) | Same; package/version strategy must allow explicit v1 and v2 use; run vectors and TS tests | Full v2 verifier including `verifyProofBundleV2`. `npm test` (2304 tests, 0 skipped, measured 2026-10-27) runs every file in `testvectors/v2` and fails on any corpus entry no runner consumes (`test/v2/corpus_files.test.ts`). It includes randomized decoder tests (`test/v2/decoders_fuzz.test.ts`) and concurrency and issuer-collision tests against the reference store. v2 prereleases use the `next` npm dist-tag; `latest` stays on v1 until `2.0.0`. Not published. |
| Python SDK | `sdks/python` (`2.0.0b1`; v1 at `ratify_protocol`, v2 at `ratify_protocol.v2`) | Carry the v2 API next to the unchanged v1 API without changing v1's base requirements; run shared vectors, malformed-input tests, full suite, and native-required CI. | The `ratify-protocol` distribution (`2.0.0b1` in this tree) keeps the v1 API at `ratify_protocol` and carries the v2 API at `ratify_protocol.v2`, including `verify_proof_bundle_v2`. v2's requirements come only with the `protocol-v2` extra; CI runs the v1 suite on the base install and checks that `import ratify_protocol` does not load `ratify_protocol.v2`. With the native extension required (`RATIFY_REQUIRE_NATIVE=1`) the v2 suite passes 2227 tests, 0 skipped (measured 2026-10-27, when v2 was still packaged as a separate distribution), over every file in `testvectors/v2` (`tests_v2/test_corpus_files.py` fails on an unconsumed entry), including Hypothesis decoder and evaluation tests and concurrency tests against the reference store. With the pure-Python verifier (`RATIFY_V2_PURE_VERIFY=1`) 2222 pass and 5 are skipped, the skips being the native-versus-pure comparisons. Not published. |
| Python native SDK | `sdks/python-native` (v1), `sdks/python-native-v2` (v2) | Build and test the exact matching wheel; check package-version lockstep and ensure stale wheels fail clearly. | The v2 extension (`ratify-protocol-native-v2`, `2.0.0-beta.1`) is pinned exactly by the `protocol-v2` extra of `ratify-protocol` and performs every v2 private-key operation: key generation and Ed25519 + ML-DSA-65 signing. There is no pure-Python signing path. Hybrid signature verification also runs in the extension by default, through the Rust core's strict v2 verifier; a pure-Python verifier remains as a fallback for verify-only installs (`RATIFY_V2_PURE_VERIFY=1` selects it), and the suite requires identical verdicts and error classes from both. Measured throughput is in [`sdks/python/README.md`](../sdks/python/README.md#protocol-v2-performance). It is version-locked to `ratify-protocol`, whose `ratify_protocol.v2` refuses to import a mismatched extension. The v1 extension (`ratify-protocol-native`, `1.0.0-alpha.21`) provides deterministic key generation only and builds against the published v1 crate pinned exactly at `1.0.0-alpha.20`, not the v2 source tree. Not published. |
| Rust SDK | `sdks/rust` (`2.0.0-beta.1`) | Same; run vectors, parser negatives, cargo tests | Full v2 verifier including `verify_proof_bundle_v2`. `cargo test` (232 tests, 0 failed, 0 ignored, measured 2026-10-27) runs every file in `testvectors/v2`: `tests/v2_conformance.rs` asserts per-file minimum counts and `tests/v2_corpus_inventory.rs` fails on an unconsumed entry. It includes proptest decoder properties and concurrency tests against the reference store, and `fuzz/` holds `cargo fuzz` decoder targets. `cargo clippy --all-targets -- -D warnings` is clean. Not published. |
| C SDK | `sdks/c` (`2.0.0-beta.1`) | Same; validate constrained/edge build, memory and parser bounds, vectors, hardware-independent tests | Full v2 C ABI at parity with the Rust SDK it wraps. `cargo test` (208 tests, 0 failed, 0 ignored, measured 2026-10-27) drives every file in `testvectors/v2` through `ratify_v2_*` exports only (`tests/v2c_inventory.rs` fails on an unconsumed entry), and every fallible export must return a SPEC-v2 §2.7 class (`tests/v2c_public_error_classes.rs`). `scripts/test-v2-c-abi.sh` compiles a plain C program against `include/ratify.h` and runs keys, objects, negatives, hedged signatures, limits, every verifier-ordering vector with C-implemented providers, a release lifecycle with a C-implemented store, and every cross-SDK fixture, and feeds every ordering vector trust outcomes and claim dispositions outside their enums (7152 checks, 0 failures), also clean with `SANITIZE=1`. The same program cross-compiled for armv7 passed on a Raspberry Pi 2 Model B running Linux: 7152 checks, 0 failures, in 1560 s (commit c3f08db, `2.0.0-beta.1`, 2026-10-27). Earlier runs passed 7149, 7145, 7132 checks at f758842, 1345 at bb55039, 1331 at f87afbe, 1330 at c1e3afd, 945 at 505dabe and 929 at b6aed4d. Other embedded targets are untested. Not published. |
| Google ADK | `references/google-adk` | Upgrade integration and pinned dependencies; preserve ADK-specific multi-agent, ceiling, delegation, and scale cases; run reference gate on v2 | v2 tested, in-tree SDK: 58/58 (2026-10-27, in-tree `2.0.0b1`); see [reference matrix](#reference-v2-gate-matrix). v1 history in `references/google-adk/v1/` |
| LangChain | `references/langchain` | Upgrade its exact SDK pin; preserve MCP boundary and independent receiver verification; run documented gate | v2 tested, in-tree SDK: 34/34 (2026-10-27, in-tree `2.0.0b1`); see [reference matrix](#reference-v2-gate-matrix). v1 history in `references/langchain/v1/` |
| A2A delegated authority | `references/a2a` | Give the draft its own v2 receiver instead of the Google ADK package; keep task and context binding, pending-task handling, the HTTPS path and the independent Node.js wire client; run the documented gate | v2 tested, in-tree SDK, one-directional: 8/8 (2026-10-29, in-tree `ratify-protocol` `2.0.0b1` with the `protocol-v2` extra); see [reference matrix](#reference-v2-gate-matrix). Mutual presentation, the receiver-to-caller proof and `verification_result` stay v1-only until Protocol 2.1. v1 history in `references/a2a/EVIDENCE.md` |
| GitHub Copilot | `references/github-copilot` | Upgrade TypeScript SDK, action profile, plugin/runtime and tests; check registry entry and published Lab page | v2 tested, in-tree SDK: 13/13 (2026-10-27, in-tree `2.0.0-beta.1`); see [reference matrix](#reference-v2-gate-matrix). Native Copilot CLI run not repeated on v2 |
| NVIDIA OpenShell + NOOA | `references/nvidia-nooa-openshell`, `demos/nvidia-nooa-delegated-authority` | Upgrade lock and sandbox profile; rerun all live OpenShell gates where credentials/runtime permit; preserve the alpha.20 historical campaign separately | v2 tested, in-tree SDK: deterministic 192/192 and live OpenShell profile 64/64 gates (2026-10-29, in-tree `ratify-protocol` `2.0.0b1` with the `protocol-v2` extra); see [reference matrix](#reference-v2-gate-matrix) |
| Physical AI edge sentinel | `references/physical-ai-edge-sentinel` and its Pi/Arduino lab | Port constrained verifier/controller path, embedded key handling, offline/freshness/revocation behavior, replay and fail-safe actuation tests; repeat the Raspberry Pi 2 Model B ARMv7 plus Arduino Uno path with trusted RTC, no clock override, replay denial, and exact actuator invocation count. The Arduino remains an untrusted actuator; the Linux verifier is the enforcement boundary. Preserve the prior v1 physical run as dated v1 evidence. | v2 tested, in-tree C SDK: 32/32 on macOS and on the Pi 2 (ARMv7) with test builds against `2.0.0-beta.1` (2026-10-27); production run with the DS3231 RTC and the Arduino passed (2026-10-22, one authorized pulse, exactly one actuator call); Google ADK adapter (`adk/edge_agent.py`) v1 only; see [reference matrix](#reference-v2-gate-matrix) |
| Classifier.dev | `references/classifier-dev` and the public [`ratify-classifier-reference`](https://github.com/identities-ai/ratify-classifier-reference) repository | Upgrade classifier-to-scope mapping and receiver path; run model-output adversarial cases, policy refusal cases, shared v2 vectors and deploy-independent tests | v1 published reference (alpha.20). A v2 port passed its local gate (6/6, 2026-10-22) on a pre-release branch against an unpublished local SDK build; not yet published |
| Maritime | Public [`ratify-maritime-reference`](https://github.com/identities-ai/ratify-maritime-reference) repository | Upgrade Python pin and constrained maritime authorization examples; run offline and simulator/evidence gates; do not claim live hardware compatibility without fresh run | Alpha.16/17 v1 evidence; v2 pending |
| Agent Relay | Public [`ratify-agent-relay-harness`](https://github.com/identities-ai/ratify-agent-relay-harness) repository and its published evidence | Keep the 2026-08-19 run as historical evidence for its pinned v1 version. The later network-denied rerun validates only offline harness reproduction. A v2 compatibility result requires a new versioned adapter and run. | Historical v1 result retained; v2 not run |
| Receiver SDK | Public [`ratify-receiver`](https://github.com/identities-ai/ratify-receiver) repository | Keep v1 API pinned; add explicit v2 profile, fail-closed decision enforcement, v2 challenge/session/action binding and vectors; package tests | Not started |
| Ratify developer docs | docs.ratifyprotocol.com | Explain the v2 break, pin-v1 choice, migration sequence, all v2 integrations, boundaries and no-guarantee language. v2 code samples render the tested programs in `examples/v2` (single source) | v2 site pages not yet published; the upgrade guide is `docs/PROTOCOL_V2_MIGRATION.md` |
| Ratify Labs catalog | Public reference catalog | Per-reference v1/v2 status and links; never advertise untested v2 paths | Not started |
| Protocol demos and examples | `demos/*` (v1), `examples/v2/*` (v2) | V2 examples plus preserved v1 demos; run every demo gate and verify command documentation | v2 tested: `examples/v2/<lang>/test.sh` runs the same four programs in Go, TypeScript, Python, Rust and C and diffs the output against `examples/v2/expected` (4/4 in each language, 2026-10-22; C also under ASan and UBSan); wired into CI. `demos/*` remain v1 only |
| Registry and discovery | `references/registry/*`, `references/README.md`, root README | Versioned profiles, executable gate, exact tested package versions, review state and working links | Every registry entry states a Protocol line; `scripts/check-reference-versions.py` enforces the allowed v2 versions and that each named gate exists; `references/README.md` lists the v2 gate per reference |

## Protocol v2 vector coverage on this branch

"Yes" means that SDK's suite runs the whole entry and passes on this branch.
`derive-external-mu.py` is a helper that recomputes the external signer bytes
pinned in `objects.json`, not a vector file. Each port has an inventory test
that fails if `testvectors/v2` holds an entry no runner consumes: TypeScript
`test/v2/corpus_files.test.ts`, Python `tests/test_corpus_files.py`, Rust
`tests/v2_corpus_inventory.rs`, and C `tests/v2c_inventory.rs`; the Go
reference generates the corpus, and `internal/v2vectors` fails if a committed
vector differs from its generator. Python native
has no verifier of its own; the Python v2 suite runs with it required. The C
ABI column counts only runners that call `ratify_v2_*` exports.

| `testvectors/v2` entry | Go reference | TypeScript | Python v2 | Rust | C ABI |
|---|---|---|---|---|---|
| `annex-a.json` (Annex A clauses, canonical JSON, strict decode, scopes) | Yes | Yes | Yes | Yes | Yes |
| `archival.json` (19 cases, every object kind) | Yes | Yes | Yes | Yes | Yes |
| `challenge-claim.json` (claim ID inputs) | Yes | Yes | Yes | Yes | Yes |
| `challenge-issuance.json` (11 scenarios) | Yes | Yes | Yes | Yes | Yes |
| `cross-sdk/` (5 fixtures, one per SDK, 4 verifier and release scenarios each) | Yes | Yes | Yes | Yes | Yes |
| `digest-functions.json` (25 cases) | Yes | Yes | Yes | Yes | Yes |
| `delegation-signature.json` (signature primitive and negatives) | Yes | Yes | Yes | Yes | Yes |
| `device-state.json` (6 complete-state projections) | Yes | Yes | Yes | Yes | Yes |
| `evaluator-profiles.json` (70 profile cases, 13 context bounds) | Yes | Yes | Yes | Yes | Yes |
| `external-signer.json` (17 cases) | Yes | Yes | Yes | Yes | Yes |
| `hedged-signatures.json` (10 objects) | Yes | Yes | Yes | Yes | Yes |
| `issuer-duties.json` (11 vectors) | Yes | Yes | Yes | Yes | Yes |
| `key-rotation-signature.json` (genesis and continuation) | Yes | Yes | Yes | Yes | Yes |
| `keys.json` (18 keys, 6 invalid IDs) | Yes | Yes | Yes | Yes | Yes |
| `lifecycle-scenarios.json` (108 Part B scripts, 29 profile scripts) | Yes | Yes | Yes | Yes | Yes |
| `limits.json` (80 vectors) | Yes | Yes | Yes | Yes | Yes |
| `log-sequences.json` (2 scenarios) | Yes | Yes | Yes | Yes | Yes |
| `object-negatives.json` (476 negatives) | Yes | Yes | Yes | Yes | Yes |
| `objects.json` (13 objects) | Yes | Yes | Yes | Yes | Yes |
| `operation-session-context.json` (context known answers) | Yes | Yes | Yes | Yes | Yes |
| `rotation-sequences.json` (4 scenarios) | Yes | Yes | Yes | Yes | Yes |
| `security-journal.json` (2 scenarios, 8 migrations, 20 import negatives, 6 transition negatives) | Yes | Yes | Yes | Yes | Yes |
| `status-publisher.json` (13 scenarios) | Yes | Yes | Yes | Yes | Yes |
| `status-sequences.json` (22 scenarios, 63 body digest checks) | Yes | Yes | Yes | Yes | Yes |
| `transaction-verification.json` (13 vectors) | Yes | Yes | Yes | Yes | Yes |
| `verifier-ordering.json` (515 cases) | Yes | Yes | Yes | Yes | Yes |

Go, TypeScript, Python v2, Rust, and the C ABI all run the full stateful
verifier against the ordering vectors, including stage, error class, terminal
tuple, exact receipt body, allow horizon, rate batch, and callback counts. Each
SDK's public error class table mirrors Go `TestV2PublicAPIErrorsAreClassified`
(`errors_v2_public_test.go`), and every row an SDK calls with Go's input
returns Go's SPEC-v2 §2.7 class.

Every vector gate in
[`testvectors/v2/README.md`](../testvectors/v2/README.md#required-for-200-beta1)
is closed on this branch, and the internal adversarial review closure is
recorded in [`releases/v2.0.0-beta.1-review.md`](releases/v2.0.0-beta.1-review.md).
The release notes record the tag commit and the per-SDK results. Embedded v2
targets other than armv7 Linux remain untested. External independent review and a
soak are `2.0.0` gates (SPEC-v2 §8.2), not beta gates. This is therefore not a
v2 conformance claim.

## Cross-SDK fixture matrix (SPEC-v2 §8.1)

Each SDK writes `testvectors/v2/cross-sdk/<sdk>.json` from fresh keys and
hedged ML-DSA-65 signatures, and every SDK verifies every fixture present
with its `objects.json` positive procedure. The format and procedure are in
[`testvectors/v2/README.md`](../testvectors/v2/README.md#cross-sdk). Rows
are the producing SDK and columns the verifying SDK. A cell is filled only
when that verifier's suite runs that fixture and passes.

| Producer (row), verifier (column) | Go | TypeScript | Python v2 | Rust | C ABI |
|---|---|---|---|---|---|
| Go (`go.json`, `go run ./cmd/ratify-v2-cross-sdk`) | Pass | Pass | Pass | Pass | Pass |
| TypeScript (`typescript.json`, `npm run generate:cross-sdk`) | Pass | Pass | Pass | Pass | Pass |
| Python v2 (`python.json`, `python tests/gen_cross_sdk_fixture.py`) | Pass | Pass | Pass | Pass | Pass |
| Rust (`rust.json`, `cargo run --example v2_cross_sdk_fixture`) | Pass | Pass | Pass | Pass | Pass |
| C ABI (`c.json`, `RATIFY_WRITE_CROSS_SDK=1 cargo test --test v2c_cross_sdk`) | Pass | Pass | Pass | Pass | Pass |

The verifying tests are Go `TestV2CrossSDKFixtures` (`cross_sdk_v2_test.go`),
TypeScript `test/v2/cross_sdk_v2.test.ts`, Python `tests/test_cross_sdk_v2.py`,
Rust `tests/v2_cross_sdk.rs`, and C `tests/v2c_cross_sdk.rs` together with the
compiled C program of `scripts/test-v2-c-abi.sh`. All 25 cells pass.

## Corpus changes since alpha.1 (beta reconciliation)

The Go reference and SPEC-v2 were reconciled for `2.0.0-beta.1` after alpha.1.
All five SDKs have since been ported and pass the resulting corpus. Changes to
`testvectors/v2`:

| File | Change since alpha.1 |
|---|---|
| `object-negatives.json` | 224 → 476 negatives: the closed v2 constraint registry, every wire timestamp outside 0..253402300799, `custom:*` and bare-prefix required scopes in receipts, the optional receipt member `constraint_evaluators`, 118 `strict_shape/` decode negatives (empty objects, `null` in arrays and non-nullable members, byte strings as number arrays, member-name case and Unicode case-folding variants), fully re-signed wire-layer negatives (small-order and mixed-order Ed25519 keys, ML-DSA under another context, UTF-16 key-order traps, escape spellings, byte fields at wrong lengths), 10 non-canonical transaction receipts (outer bytes, a nested bundle, a party array out of order, or a repeated party) with a second fault that must still be `malformed`, and 2 repeated signature records beside a nested bundle fault, which is reported first |
| `verifier-ordering.json` | 81 → 515 cases (149 pre-claim, 2 replay, 362 committed, 2 evaluating), including 10 Middleware Custody Profile cases and 6 `time_window` offset-change boundary cases; new input fields (`configured_verifier_id`, `tzdb_version`, amount and currency request context, `extension_counts` and `extension_values`, `constraint_evaluators`, `status_keys`, `status_policy`, `journal`, signed status evidence batches) and the `progress` and `evaluator` callback counts, and the exact `status_requests` each vector sends the status provider; exact `custom:` required scopes; committed outcomes are not decisions |
| `operation-session-context.json` | `invalid_required_scopes` replaces `custom:invoice:read`, now a valid exact required scope, with the bare prefix `custom:` |
| `status-sequences.json` | 20 → 22 scenarios; exclusive `next_update` and status-age deadlines; a rejected status-key epoch transition (reuse of a retired key) is `status_object_rejected`, no longer `configuration_invalid` (SPEC-v2 §2.7) |
| `objects.json` | The constrained-certificate object now pins every v2 registry schema (`time_window`, `max_amount` in micro-units); its bytes, digests, and signatures changed |
| `log-sequences.json`, `rotation-sequences.json` | Section references in descriptions only |
| `limits.json` | New: 80 byte, count, and timestamp boundary cases, including the status evidence batch |
| `hedged-signatures.json` | New: 10 objects with 2 hedged ML-DSA-65 variants each (not reproducible) |
| `security-journal.json` | New: `SecurityJournalV2` snapshot known answers, transitions, migration, 20 import negatives (including unsafe integers, a member-name case variant, and a `null` array element) |
| `lifecycle-scenarios.json` | New: 108 Part B scripts (579 steps) against each SDK's in-memory reference store, plus 29 `profile_scenarios` for the single-device offline and dual-root profiles, over 29 requests |
| `transaction-verification.json` | New: 13 composed transaction verification cases |
| `annex-a.json` | New: Annex A clause digests, canonical JSON and strict-decode cases, and the scope vocabulary, expansion, intersection, and `custom:` cases |
| `issuer-duties.json` | New: 11 delegation issuer-duty cases for the typed signer |
| `challenge-issuance.json` | New: 11 challenge issuance helper scenarios (42 steps) |
| `status-publisher.json` | New: 13 signed-status publisher scenarios (39 steps) with journal ingestion and role-configuration refusals |
| `evaluator-profiles.json` | New: 70 standard evaluator profile cases (34 `max_count/v1`, 36 `allowed_values/v1`) and 13 request-context bound cases |
| `device-state.json` | New: 6 single-device offline complete-state projection known answers (SPEC-v2 §7.13). The record encoding inside each projection member is now normative instead of implementation-defined, so an SDK that implements the profile must replace its own record encoding with the §7.13 encoding and reproduce these bytes |

Go reference state on this branch: `go test ./...` runs every file in
`testvectors/v2`; the decoder fuzz targets (`scripts/fuzz-v2.sh`) cover every
v2 decoder including the status evidence batch, checkpoint acknowledgement,
journal snapshot import, and archival proof verification. The external signer
interface is tested with direct signing and with an external-μ provider that
the tests emulate in software; no hardware security module or key-management
service has been exercised, and no provider-specific claim is made (SPEC-v2
§3.2).

## v2 example programs

`examples/v2/` holds four programs per SDK (quickstart, signed status, custom
scope with the `max_count/v1` profile, external signer). Every language must
print exactly `examples/v2/expected/<program>.txt`, so the examples double as
a behavioral cross-SDK check of the public API. They use the test-only
reference stores.

| SDK | Command | Result (2026-10-22) | Notes |
|---|---|---|---|
| Go | `examples/v2/go/test.sh` | 4/4 | |
| TypeScript | `examples/v2/typescript/test.sh` | 4/4 | Node.js 22.18 or later |
| Python v2 | `examples/v2/python/test.sh` | 4/4 | The external-signer provider uses the native-v2 key type as a stand-in, because no public Python dependency offers ML-DSA-65 signing with a context |
| Rust | `examples/v2/rust/test.sh` | 4/4 | |
| C ABI | `examples/v2/c/test.sh` | 4/4, also with `SANITIZE=1` | Needs the `test-reference` feature and OpenSSL 3.5 or later for the external signer; CI runs it on macOS |

## Reference v2 gate matrix

A2A delegated authority, run on 2026-10-29 on macOS (Apple Silicon) at commit
`5ad1bfc`: `./references/a2a/run-reference-check.sh` passed 8/8, 0 failed,
0 skipped, in a fresh environment with `ratify-protocol` `2.0.0b1` (with the
`protocol-v2` extra) and `ratify-protocol-native-v2` `2.0.0b1` built from this
repository, Python 3.12, `a2a-sdk==1.2.2`, and Node.js 26 for the wire client.
The reference is one-directional: mutual presentation, the receiver-to-caller
proof and `verification_result` are not covered until Protocol 2.1. Its
evidence is in [`references/a2a/EVIDENCE.md`](../references/a2a/EVIDENCE.md).

Re-run on 2026-10-29 after the Python v2 SDK moved into the `ratify-protocol`
distribution as `ratify_protocol.v2` (installed with the `protocol-v2` extra),
still built from this repository: Google ADK 58/58, LangChain 34/34 and NVIDIA
NOOA (deterministic) 192/192, each in a fresh environment, with the Google ADK
10, 100 and 1,000-call tiers re-measured, and one live OpenShell profile run
at 64/64 gates and 52/52 required cases. GitHub Copilot 13/13 and the edge
sentinel 32/32, which do not use the Python SDK, passed in the same
`scripts/test-all.sh` run. Every gate ran with 0 skipped. Each reference's
evidence records its run.

Re-run on 2026-10-27 on macOS (Apple Silicon) after the in-tree v2 SDKs moved
to `2.0.0-beta.1` (Python `2.0.0b1`), still built from this repository and not
from published packages: Google ADK 58/58, LangChain 34/34, GitHub Copilot
13/13, NVIDIA NOOA (deterministic) 192/192, and the physical AI edge sentinel
32/32 rows (plain and with AddressSanitizer and UndefinedBehaviorSanitizer),
every gate with 0 skipped. On the same build the live OpenShell profile passed
64/64 gates and 52/52 required cases (one run), and the Google ADK 10, 100 and
1,000-call tiers were re-measured. The edge sentinel matrix was also repeated on the
Raspberry Pi 2 with the ARMv7 test builds (32/32, 0 skipped, 5 mock
invocations); the classifier.dev port was not repeated. Each reference's evidence
records the run. The table below is the earlier record and stays as written.

Run on 2026-10-22 on the merged tree (after the reference ports were merged
into `feat/verify-federation-v2`) on macOS (Apple Silicon), against the v2 SDKs
built from this repository at `2.0.0-alpha.1` (Python `2.0.0a1`). None of these
runs used a published v2 package. **Every row must be re-run against the
published `2.0.0-beta.1` packages** (the `RATIFY_V2_PIN` markers in each gate)
before a reference is described as tested on a released v2. Every gate fails on
any skip and on an unexpected count. The receivers use the SDKs' in-memory
reference stores (development only).

| Reference | Protocol line | Gate | Result (2026-10-22, in-tree `2.0.0-alpha.1`) | Not covered |
|---|---|---|---|---|
| Google ADK | v2 | `./references/google-adk/run-reference-check.sh` | 58/58 passed, 0 skipped; dual-root HTTP MCP demo ran. Python 3.12, `google-adk==2.6.3`, `mcp==1.29.0` | One-million-call endurance run is v1 history only |
| LangChain | v2 | `./references/langchain/run-reference-check.sh` | 34/34 passed, 0 skipped (2026-10-26). Python 3.12, `langchain==1.3.14`, `langchain-mcp-adapters==0.3.0`, `mcp==1.29.0` | |
| GitHub Copilot | v2 | `./references/github-copilot/run-reference-check.sh` | 13/13 passed, 0 skipped; plugin runtime rebuilt from the v2 TypeScript SDK; demo ran | Native Copilot CLI run not repeated on v2 |
| NVIDIA NOOA (deterministic) | v2 | `PYTHON=python3.12 ./demos/nvidia-nooa-delegated-authority/reference-check-v2.sh` | 192/192 passed, 0 skipped (64 receiver, 40 MCP transport, 84 adjudicator, 4 NOOA); narrated scenario verified its receipt log. `nooa==0.0.8`, `mcp==2.0.0` | |
| NVIDIA OpenShell (live) | v2 | `./demos/nvidia-nooa-delegated-authority/run-openshell-profile.sh` | Recorded by the port on 2026-10-22: 64/64 gates, 52/52 required cases (one run), in [`evidence-v2-2026-10-22.md`](../references/nvidia-nooa-openshell/evidence-v2-2026-10-22.md) | Not repeated on the merged tree (needs a container runtime and the OpenShell CLI) |
| Physical AI edge sentinel | v2 (C ABI) | `RATIFY_SDK=/path/to/ratify-c ./references/physical-ai-edge-sentinel/run-reference-check.sh` | 32/32 rows on macOS and on a Raspberry Pi 2 Model B (ARMv7) with the test builds (2026-10-26), 5 mock actuator invocations, 0 hardware writes | Production binaries with the DS3231 RTC and the Arduino passed on 2026-10-22 (one authorized pulse observed, all other requests refused, one actuator call; see the reference evidence). The Google ADK adapter (`adk/edge_agent.py`) is v1 only and does not work with the v2 receiver |
| classifier.dev | v1 | `npm run check` in the source repository | Not run here; v1 (`1.0.0-alpha.20`) is the published reference | A v2 port passed its local gate (6/6, 2026-10-22) on a pre-release branch of the source repository against an unpublished local SDK build; not yet published, and must be re-run against the published `2.0.0-beta.1` |

The repository-level checks also passed on the same tree:
`scripts/check-reference-versions.py`, `scripts/check-reference-readmes.py`,
`scripts/check-release-sync.sh`, and `scripts/gen-sdk-readmes.py --check`.
The SDK suites and the `examples/v2` programs in all five languages were
re-run with the results recorded above. No A2A reference lives in this
repository.

## Fresh v1 baseline runs

These runs were repeated on 2026-10-11 to verify the current pinned v1 references before making v2 changes. They do not establish v2 compatibility. The `scripts/*-reference-check.sh` commands below ran the v1 gates at the time; they now hand off to each reference's v2 gate.

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
