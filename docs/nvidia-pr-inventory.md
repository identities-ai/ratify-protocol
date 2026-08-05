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
| `test_mcp_transport.py` | 34 | MCP transport, proof carriage, size boundaries. |
| `test_adjudicator.py` | 42 | That the adjudicator cannot be fooled. Each test feeds evidence of one violation and asserts FAIL. |
| `test_nooa_presentation.py` | 4 | Against released `nooa==0.0.8`. Required to run, not permitted to skip. |

**134 total.** The authoritative gate is `scripts/nvidia-reference-check.sh`, which requires Python 3.12 or 3.13, installs exact pins, and **fails on any skip**. An ordinary pytest invocation on Python 3.11 reported "91 passed, 1 skipped" and exited 0 while the entire 34-test MCP module had not run; that loophole is closed by `RATIFY_REQUIRE_MCP=1`.

> **Not yet send-ready, for one remaining reason: release provenance.** The
> reference is functionally complete and stable. The unified NOOA path is a stable
> gate: it imports `nooa` exactly once in a single process, which is measured
> rather than declared, and it has passed sequentially and concurrently. What is
> not yet true is the provenance of the evidence. Every artifact so far was
> produced with the Ratify SDK built from this checkout, and each one says so in
> its own `evidence_status` field. The reference needs alpha.16's `resource_path`
> constraint, and alpha.16 is merged but not yet tagged or published, so the
> published package cannot be installed yet.
>
> **Release transition, once `v1.0.0-alpha.16` is tagged and on PyPI.** The switch
> is implemented and defaults to the checkout, so nothing changes until it is
> taken deliberately:
>
> 1. Uncomment the `ratify-protocol==1.0.0a16` pin in
>    `demos/nvidia-nooa-delegated-authority/sandbox-requirements.in` and
>    regenerate the lock with `./stage-lock.sh`.
> 2. Run the authoritative gate as `RATIFY_SDK=published
>    ./scripts/nvidia-reference-check.sh`. It asserts that `ratify_protocol`
>    resolves outside the repository, so a published run cannot silently prove the
>    checkout.
> 3. Run the profile as `RATIFY_SDK=published ./run-openshell-profile.sh`. The
>    checkout is not mounted at all in that mode, the package comes from the
>    hash-verified lock, and the run fails if the version in the built image is not
>    the expected one.
> 4. Rebuild the sandbox image and regenerate every artifact. The evidence must be
>    regenerated rather than reused: upstream commit `4925538` canonicalises
>    constraints in `bundle_hash`, every delegation here carries constraints, so
>    receipt and proof hashes change even though no authorization outcome does.
> 5. Re-run release-sync, which currently still reports alpha.15.
>
> Counts and send-readiness claims in this document and the README are updated only
> from post-publication results.

## New: documentation

| File | Audience |
|---|---|
| `docs/nvidia-open-secure-ai-contribution-brief.md` | The executive brief. Under 1,000 words. |
| `docs/nvidia-open-secure-ai-reference-proposal.md` | Engineering appendix. Architecture, threat model, OpenShell results and findings, open questions. |
| `docs/nvidia-introduction-email.md` | Three cover-email variants and the rules for sending them. |
| `docs/nvidia-pr-inventory.md` | This file. |
| `demos/nvidia-nooa-delegated-authority/README.md` | Engineer's five-minute path from clone to observed denials. |

## Changed: existing repository files

Three files, additive only, 33 inserted lines and no deletions.

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
- Require a container runtime for its core claim. The profile needs Docker; the 125 hermetic tests do not.

One reference-application constant changed during this work: the receiver's `MAX_PROOF_BYTES` moved from 196,608 to 131,072. The reasoning is in appendix section 15.2. It is an application-level ceiling, not a protocol bound.

## Review order

1. `README.md` for the shape and the five-minute path.
2. `refund_service.py` to confirm the receiver, not the agent, decides.
3. `test_verification.py` for the denials.
4. `openshell_cases.py` and `test_adjudicator.py` to confirm no gate can pass on the mere existence of a record.
5. Appendix section 15 for what the live profile established, and section 15.3 for what it observed about OpenShell v0.0.96.
