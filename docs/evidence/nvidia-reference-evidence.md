# NVIDIA NOOA delegated-authority reference — final evidence

Machine-readable form: [`nvidia-reference-evidence.json`](./nvidia-reference-evidence.json).

**Executed 2026-08-05.** Branch `feat/nvidia-nooa-reference` at `37b378b`, rebased
onto `origin/main` at `f5a1522` (the commit marking `v1.0.0-alpha.16` published).
This is the first evidence produced after alpha.16's publication; every run in
this document installs `ratify-protocol==1.0.0a16` from PyPI rather than this
repository's own checkout, and every artifact's own `evidence_status` field says
so.

## Provenance

`ratify-protocol==1.0.0a16` was installed and imported in a clean virtual
environment outside any repository checkout before the sandbox pin was
uncommitted, confirming it resolves to an installed package rather than a source
tree. Inside the built sandbox image, `ratify_protocol` resolves to
`/opt/ratify-nooa/site/ratify_protocol` — the staged, hash-verified dependency
tree, not a mounted checkout. `RATIFY_SDK=published` mode does not mount the
repository's SDK source at all; the authoritative gate asserts this and would
fail the run if the module resolved inside the repository.

## Platform

Executed on arm64 macOS with Docker 29.2.1. **linux/amd64 and Podman are
compatibility targets, not results** — nothing in this document establishes
their behavior.

## Component versions and digests

| Component | Version / digest |
|---|---|
| OpenShell CLI | 0.0.96 |
| Gateway image | `sha256:329adb1784989705a33c51f81df22eca33e2dc527675642364f013c5b8b79a67` |
| Sandbox base image | `sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e` |
| Supervisor image | `sha256:523e0565f8957362d8f3c70c6ef7a221d92b10f32b96fbc76821febfb01bae8e` |
| Sandbox interpreter | CPython 3.12.3 (from the pinned base) |
| nooa | 0.0.8 |
| mcp | 2.0.0 |
| uvicorn | 0.52.1 |
| ratify-protocol | **1.0.0a16, published, PyPI** |

Dockerfile SHA-256: `9b128c9d2744ac6c671c1f51422df0c26d9e054952dd550d33886799e0e61f6e`.

## Dependency lock and reproducibility

`sandbox-requirements.lock`, SHA-256 `74172610bfd265b992a944059f33325b3fdc778ab112b81d0a09eefa3634d76b`:
**75 pinned distributions, 1,927 recorded hashes**, installed with
`--require-hashes`. Two independent clean builds against this lock produced a
**byte-identical staged dependency tree**
(`ead8506e3017c1cf4f658bbecdd5f5cdacfe79f34fe30873db2975c344cd1475`) and the same
image tag; only the image ID differed, which is build-timestamp metadata rather
than content. Built locally from a digest-pinned base using the committed
Dockerfile and locked dependency set; the executed image ID is recorded per run
and is never described as registry-pinned.

## Authoritative Python gate

`RATIFY_SDK=published ./scripts/nvidia-reference-check.sh` — **181 tests, zero
skips**: 54 receiver-security, 39 MCP transport, 84 adjudicator, 4 mandatory NOOA
integration.

## Live OpenShell profile

52 required cases, judged by **64 gates**. `SANDBOX_MEMORY=512Mi`.

| Run | Result | Gates | Notes |
|---|---|---|---|
| Sequential 1 | PASS | 64/64 | |
| Sequential 2 | PASS | 64/64 | |
| Concurrent A | PASS | 64/64 | |
| Concurrent B | PASS | 64/64 | one `sandbox download` retried once, self-healed, disclosed below |
| Intentional policy failure | **FAIL, exit 1 (expected)** | 36/64 | |

Every passing run: `not_executed: []`, `driver_errors: []`, `timeouts: []`, **zero
container residue**, refund total **375.00**, **16 receipts**, `nooa` module
loaded exactly once in the suite process (measured by an import audit hook, not
declared), exactly one process in the profile capable of importing it, and 22/22
events attributed to their subcase.

### Memory selection

Selected by a bounded search against cgroup v2's `memory.peak` — a true
high-water mark, not a sampled maximum, which mattered: the sampled figure missed
the peak by more than the margin between passing and failing rungs. The observed
true peak was **208 MiB**. 256 MiB and above passed; 192 MiB failed with a kernel
memcg OOM kill at an observed RSS of 208 MiB, exceeding the unconstrained
container's own measured peak. **512 MiB was selected** — 2.46× the true peak, two
binary steps above the highest failing rung — and confirmed with repeat passing
runs. This is an executed-profile setting for this host and dependency tree, not
a universal NOOA requirement.

### Concurrency

`gateway_bootstrap_serialized: true`. OpenShell v0.0.96 names its
supervisor-extraction container with a fixed name, so two gateways bootstrapping
concurrently against one container runtime collide on a Docker 409; only
bootstrap is serialized. Measured on the concurrent pair: **bootstrap window 4.0
seconds** (gateways came up 1.78 seconds apart), **fully concurrent matrix
execution 63.0 seconds**. Every other resource is per-run isolated: ports, data
home, compose project, network, sandbox, work directory, artifact.

### A transient operational note, disclosed rather than hidden

Under concurrent load, `sandbox download` exited 1 twice across this engagement
(out of well over 150 download operations) and succeeded on an immediate retry
both times. Neither occurrence lost any case's evidence — the driver's stdout
fallback recovered the result before the retry existed, and `not_executed`
stayed empty in both instances. A bounded, disclosed retry (at most two extra
attempts) was added to `download` operations only, never to `exec` or `upload`,
because a download only re-reads a file the sandbox already finished writing and
cannot touch the presentation or authorization boundary. Every attempt is
recorded; a self-healed retry appears in the artifact's `retried_operations`
rather than disappearing, and an exhausted retry still reaches `driver_errors`
exactly as an unretried failure would.

### Intentional failure, verified

Injection: removed the `refund.execute` allow rule from the OpenShell policy.
Policy template restored byte-identical afterward
(`3f039a5b28547f2647612b56656d11e65dc7f0f6e8dc4a40a3e42f6d31f84e78`).

- Exit code: **1**
- Refund total: **0**. Receipts: **0**.
- `not_executed: []` — the profile still accounted for every required case.
- **Parser safety: PASS, 15/15** — the "admitted as X, never dispatched as Y"
  invariant held even under a deny-all policy, because a blanket refusal never
  laundered one tool into another.
- **Parser coverage: FAIL, 0/10 admitted** — the separate gate that exists
  precisely because safety alone is satisfiable by a policy that refuses
  everything. It failed exactly as required.

## Proof carriage

16 proofs measured across the passing runs. Only SHA-256 and byte length are
recorded here or in the JSON companion; no proof body, delegation body, or
certificate is retained in this summary.

## Policy and configuration hashes

Each run renders and hashes its own OpenShell policy and gateway config. Example
from a passing run: policy `5ddacb2cc9bd2d9006ba70f5a89ad1c786ac25d0373944ffee2c81d7fbc4d950`,
gateway config `169583c9441c091514083d3cea3b71b303e1cf628288f019032f524fcdf8e93e`.
The injected-failure run's modified policy hashed to
`0d5d337a971701f1c150eadf9454009f852ba272e604804afd33d664580f7466`.

## Canary log audit

Every component-owned log source — gateway compose, gateway container,
supervisor, OpenShell audit, MCP receiver — was searched for this run's canary
values: **zero hits** across all of them, on every run. Only harness-owned
sources (the sandbox's own stdout, the runner's operation log) show hits, which
is expected: the harness's own report of a request it just sent necessarily
contains the values it sent.

## Non-Docker verification sweep

Go tests (4 packages, pass) · Python SDK (464 pass) · TypeScript (416 pass, 0
fail, 0 skipped) · test-vector determinism (byte-identical) · release-sync
(**v1.0.0-alpha.16**, 79 fixtures, 54 scopes) · shell syntax (clean) · Python
compile (clean) · YAML (8 files) · TOML (5 files) · CI YAML parse (9 jobs,
`nooa-reference` present) · `git diff --check` (clean) · secret scan (clean) ·
Markdown relative links (1 checked, 0 broken).

## Known limitations

- linux/amd64 execution not performed; only arm64 macOS/Docker is a result.
- Podman as the container runtime not performed.
- Verifier-side missing resource context (`has_resource=False`) is unreachable
  through the MCP path by construction; covered hermetically instead.
- Genuinely duplicated HTTP header fields: `urllib` folds repeated header names,
  so duplicate-header probes send one folded value.
- Concurrent OpenShell gateway bootstrap is serialized by a fixed
  supervisor-extraction container name in v0.0.96; only bootstrap is serialized,
  not the measured matrix.
- TLS, OIDC, or mTLS in front of the gateway not exercised; the profile runs a
  local single-player gateway on loopback with plaintext, unauthenticated
  access.

## Raw artifacts

Retained outside this repository, not distributed with it. SHA-256 of each:

| Run | SHA-256 |
|---|---|
| Sequential 1 | `258ef940dca9e5a45471c8aa49a7d6e74b589c7909701016bc352190d3aafa6a` |
| Sequential 2 | `f790caab5d0bd38f06d51bf47f60bf1ea6d61139e0dc18112a8f9db27d9419b6` |
| Concurrent A | `1ed0778d10b3242f9eabd38296396d2bf7794514da74507412f20d017d0fad9d` |
| Concurrent B | `9358067e6b68fae2a4b6b0d9c6b0a4ab7c0a7a88fe53e32c7a10c8d2b87f2b13` |
| Intentional failure | `f48a3b324566a22c0fb18b4717d20ee0a7527a02a7d49d4cc18e22d1a6df9481` |
