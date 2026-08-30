# PR inventory: NVIDIA NOOA delegated-authority reference

Everything this contribution adds or changes, in one place, so a reviewer can see the blast radius before reading a line of code. **No NVIDIA repository is modified.** All of it lands inside `ratify-protocol`, under Apache-2.0.

## New: the reference

`demos/nvidia-nooa-delegated-authority/`

| File | Role |
|---|---|
| `principal.py` | Creates authority. The only place delegations are signed. |
| `refund_service.py` | The receiver. Verifies, decides, acts, and signs receipts for authenticated decisions. Sole authorization decision point. |
| `mcp_server.py` | The MCP Streamable HTTP boundary. Decodes transport, bounds size, adapts MCP to the receiver. No authorization logic. |
| `agent_client.py` | Carries the proof and answers the challenge. Decides nothing. |
| `nooa_adapter.py` | NOOA presentation adapter via the public `intercept("agent_call", ...)` middleware API. |
| `scenarios.py` | The narrated run. |

## New: the live OpenShell profile

| File | Role |
|---|---|
| `run-openshell-profile.sh` | Environment setup and teardown. Pins, dynamic ports, per-run data home, rendered policy, receiver, sandbox, scoped cleanup. |
| `openshell_driver.py` | Orchestration. Bounded external calls, per-case snapshots, log capture, the artifact. |
| `openshell_probe.py` | The receiver process, the append-only event log, and the loopback control plane. Holds every private key in memory and serializes none. |
| `openshell_client.py` | Runs inside the sandbox. Sends one case, reports what happened, interprets nothing. |
| `openshell_cases.py` | Case expectations and the adjudicator. Pure functions over recorded evidence. |
| `openshell-policy.yaml.in` | Sandbox policy template. Default deny; names two tools and three methods. |
| `openshell-gateway.toml.in` | Gateway configuration template. |

## New: tests

| File | Count | What it covers |
|---|---|---|
| `test_verification.py` | 54 | Receiver security. No NOOA, no LLM, no container runtime. |
| `test_mcp_transport.py` | 39 | MCP transport, proof carriage, size boundaries, the presenter's clock safety margin. |
| `test_adjudicator.py` | 84 | That the adjudicator cannot be fooled. Each test feeds evidence of one violation and asserts FAIL. |
| `test_nooa_presentation.py` | 4 | Against released `nooa==0.0.8`. Required to run, not permitted to skip. |

**181 total, zero skips.** The authoritative gate is `scripts/nvidia-reference-check.sh`, which requires Python 3.12 or 3.13, installs exact pins, and **fails on any skip**. An ordinary pytest invocation on Python 3.11 reported "91 passed, 1 skipped" and exited 0 while the entire 34-test MCP module had not run; that loophole is closed by `RATIFY_REQUIRE_MCP=1`.

The live OpenShell profile drives 52 required cases across 7 isolated groups, judged by 64 gates, and has passed twice sequentially and twice concurrently against the published SDK. Full evidence: [`docs/evidence/nvidia-reference-evidence.md`](evidence/nvidia-reference-evidence.md).

**Release provenance.** `v1.0.0-alpha.16` is tagged and published on PyPI. Every gate and every live profile run cited in this document was executed as `RATIFY_SDK=published`, which does not mount this repository's SDK source at all: the package comes from `sandbox-requirements.lock`, hash-verified, and the authoritative gate asserts `ratify_protocol` resolves outside the repository before it will report success. Every retained artifact carries its own `evidence_status` field recording this.

## New: documentation

| File | Audience |
|---|---|
| `docs/nvidia-open-secure-ai-contribution-brief.md` | The executive brief. Under 1,000 words. |
| `docs/nvidia-open-secure-ai-reference-proposal.md` | Engineering appendix. Architecture, threat model, OpenShell results and findings, open questions. |
| `docs/nvidia-introduction-email.md` | Three cover-email variants and the rules for sending them. |
| `docs/nvidia-pr-inventory.md` | This file. |
| `demos/nvidia-nooa-delegated-authority/README.md` | Engineer's five-minute path from clone to observed denials. |

## Changed: existing repository files

Three files, additive only, no deletions.

| File | Change | Why |
|---|---|---|
| `.github/workflows/ci.yml` | Adds one job, `nooa-reference` | Runs the three hermetic suites, then `nooa-integration-check.sh`. A skip in the integration step fails the job. |
| `scripts/test-all.sh` | Adds one block | Runs the demo suites in the local gate. The NOOA test may skip here; the hermetic suites always run. |
| `.gitignore` | Adds two blocks | Python caches, and per-run OpenShell profile artifacts, which are evidence rather than source. |

New helpers: `scripts/nvidia-reference-check.sh` (the authoritative, skip-proof gate) and `scripts/nooa-integration-check.sh`. This is the one place the integration claim is actually exercised, with `RATIFY_REQUIRE_NOOA=1` turning the module's `importorskip` into a hard failure and the skip count asserted to be zero.

## What this contribution does not do

- Modify any NVIDIA repository, fork NOOA, or use a private hook.
- Add a dependency to the Ratify Protocol SDKs. The receiver uses only the Python standard library; `mcp` and `uvicorn` are test-environment pins for the transport suite and the profile.
- Change protocol semantics, wire format, or any SDK. The reference consumes alpha.16 as published.
- Require a container runtime for its core claim. The profile needs Docker; the 177 hermetic tests do not.

One reference-application constant changed during this work: the receiver's `MAX_PROOF_BYTES` moved from 196,608 to 131,072. The reasoning is in appendix section 15.2. It is an application-level ceiling, not a protocol bound.

## Review order

1. `README.md` for the shape and the five-minute path.
2. `refund_service.py` to confirm the receiver, not the agent, decides.
3. `test_verification.py` for the denials.
4. `openshell_cases.py` and `test_adjudicator.py` to confirm no gate can pass on the mere existence of a record.
5. Appendix section 15 for the v0.0.102 compatibility result, and section 15.3 for historical observations from the v0.0.96 campaign.
