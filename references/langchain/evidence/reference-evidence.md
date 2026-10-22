# LangChain reference evidence (Protocol v2)

**Evidence date:** 2026-10-22 (run started 2026-10-22T15:56:47Z)

**Branch:** `ref-v2-adk-langchain`, based on `feat/verify-federation-v2` at `a1e5b5e`

**Code commit:** `bb48e57` (`bb48e576af918d02e277840ae649b767007df317`)

**Protocol line:** v2 (2.0.0-beta.1), exercised with the in-tree SDK build 2.0.0a1

The Protocol v1 evidence (Ratify `1.0.0a19`, 28/28, 2026-09-20) is kept
unchanged in [`../v1/evidence/reference-evidence.md`](../v1/evidence/reference-evidence.md).

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 (Apple M2 Pro, 10 logical CPUs) |
| Python | `3.12.10` |
| Rust / maturin (native extension build) | `rustc 1.95.0`, `maturin 1.15.0` |
| ratify-protocol-v2 | `2.0.0a1`, installed from `sdks/python-v2` at the code commit |
| ratify-protocol-native-v2 | `2.0.0a1`, built from `sdks/python-native-v2` at the code commit |
| LangChain | `1.3.14` |
| langchain-mcp-adapters | `0.3.0` |
| MCP Python SDK | `1.29.0` |
| pytest | `9.0.3` |
| pytest-asyncio | `1.4.0` |
| Requirements SHA-256 | `e908837662775ee2e833597ae304b3f94b00d8a4fbfc78537494b1b4031b5d5a` |

## Reproduction

```bash
./references/langchain/run-reference-check.sh
```

The recorded run set `RATIFY_REFERENCE_VENV` to a fresh directory outside the
repository. The gate builds the native extension, installs both v2 packages
from this repository into that environment, asserts that the SDK does not
import from the source tree and that the v1 `ratify_protocol` package is
absent, checks every pin, runs the suite, and requires exactly 33 passing
tests with none skipped.

## Recorded result

The transcript below is copied by script from the captured gate log, from the
first line after the build steps; only the absolute virtual-environment path
is shortened.

```text
installed Ratify v2 SDK: .../site-packages/ratify_protocol_v2/__init__.py
langchain==1.3.14 langchain-mcp-adapters==0.3.0 mcp==1.29.0 pytest==9.0.3 pytest-asyncio==1.4.0 ratify-protocol-v2==2.0.0a1 ratify-protocol-native-v2==2.0.0a1
.................................                                        [100%]
33 passed in 70.32s (0:01:10)
gate: 33/33 passed; zero skipped, xfailed, failed, or errored
```

Zero tests were skipped or marked xfail. The run took longer than an
uncontended run because a separate benchmark process was running on the same
host.

## Evidence covered

- a valid two-hop delegation is verified, its signed receipt is appended and
  acknowledged, the decision is released, and the protected handler runs once;
- the exact custom scope `custom:infra:provision` is required, and the node
  ceiling is the standard `com.ratifyprotocol.max_count/v1` profile;
- region and node-ceiling denials are released Protocol decisions with their
  own signed receipts and never reach the handler;
- expiry, signed revocation, replay, operation alteration, wrong agent, and
  hostile root fail closed;
- revocation and expiry that occur after the agent's local preflight are
  rechecked by the receiver and fail closed, with paired control actions
  allowed before the change;
- status signed by a key the receiver did not configure is
  `status_unavailable`, status past `next_update` without a heartbeat is
  `status_stale`, and a status key equal to the root key is refused at
  configuration;
- a receipt the checkpoint does not acknowledge is not released, and the
  handler does not run;
- the claim store refuses a replay even when the receiver's pending
  application envelope is restored;
- a signed revocation written to the local status feed denies the next call
  over HTTP MCP;
- malformed proof does not consume an honest pending operation, invalid
  business values never reach verification, and pending state is bounded;
- unauthenticated HTTP cannot reach the MCP receiver, and duplicate or
  oversized security headers fail before MCP dispatch;
- the model-visible schema excludes proof material, the public MCP interceptor
  injects the proof after tool selection, and the real `create_agent`
  LangGraph loop executes the gated HTTP MCP tool; and
- the optional Jev adapter returns a typed tool proposal, and a Jev-selected
  tool still fails closed when receiver authority is out of scope.

## What this run does not establish

- The SDK packages are the in-tree 2.0.0a1 build, not the published
  2.0.0-beta.1 packages. The result must be re-run when those are released.
- The claim store, receipt log, checkpoint, issuance store and security
  journal are the SDK's in-memory reference stores. Nothing here is evidence
  of a durable or production-shaped deployment.
- Only the platform and versions above were executed.
- This evidence supports only the independent draft and limitations documented
  in the reference README. It is not evidence of LangChain review or
  endorsement.
