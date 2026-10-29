# LangChain reference evidence (Protocol v2)

**Evidence date:** 2026-10-29 (run started 2026-10-29T02:09:05Z)

**Branch:** `feat/python-unified`

**Code commit:** `32c1c09` (the commit that records this run follows it and
changes only this record). Since `d62bed2` the reference code changed only in
its SDK import path: Protocol v2 moved from the separate `ratify_protocol_v2`
package into the `ratify-protocol` distribution as `ratify_protocol.v2`.

**Protocol line:** v2 (2.0.0-beta.1), exercised with the in-tree SDK build 2.0.0b1

The Protocol v1 evidence (Ratify `1.0.0a19`, 28/28, 2026-09-20) is kept
unchanged in [`../v1/evidence/reference-evidence.md`](../v1/evidence/reference-evidence.md).

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 (Apple M2 Pro, 10 logical CPUs) |
| Python | `3.12.10` |
| Rust / maturin (native extension build) | `rustc 1.95.0`, `maturin 1.15.0` |
| ratify-protocol | `2.0.0b1` with the `protocol-v2` extra, installed from `sdks/python` at the code commit |
| ratify-protocol-native-v2 | `2.0.0b1`, built from `sdks/python-native-v2` at the code commit |
| LangChain | `1.3.14` |
| langchain-mcp-adapters | `0.3.0` |
| MCP Python SDK | `1.29.0` |
| pytest | `9.0.3` |
| pytest-asyncio | `1.4.0` |
| Requirements SHA-256 | `e6a508203652babddc5e35f446a93257b2bedf0f3af2a077949c423cbef8f9b2` |

## Reproduction

```bash
./references/langchain/run-reference-check.sh
```

The recorded run set `RATIFY_REFERENCE_VENV` to a fresh directory outside the
repository. The gate builds the native extension, installs `ratify-protocol`
with its `protocol-v2` extra from this repository into that environment,
asserts that the SDK does not import from the source tree, checks every pin,
runs the suite, and requires exactly 34 passing tests with none skipped.

## Recorded result

The transcript below is copied by script from the captured gate log, from the
first line after the build steps; only the absolute virtual-environment path
is shortened.

```text
installed Ratify v2 SDK: .../site-packages/ratify_protocol/v2/__init__.py
langchain==1.3.14 langchain-mcp-adapters==0.3.0 mcp==1.29.0 pytest==9.0.3 pytest-asyncio==1.4.0 ratify-protocol==2.0.0b1 ratify-protocol-native-v2==2.0.0b1
..................................                                       [100%]
34 passed in 9.91s
gate: 34/34 passed; zero skipped, xfailed, failed, or errored
```

Zero tests were skipped or marked xfail.

The previous run (2026-10-27, code commit `9ea1ec2` with the beta bump,
against the separate `ratify-protocol-v2` 2.0.0b1 build) passed 34/34; its
record is in git history at `32c1c09`. The run before it (2026-10-26, code
commit `d62bed2`, against the in-tree alpha.1 build) passed 34/34; its record
is in git history at `c800022`. The
run before it (2026-10-22, code commit `bb48e57`) passed 33/33. The
34th test was added with the fix for an intermittent `400` from the receiver:
a signed presentation header of about 38 KB exceeded the HTTP parser's
default 16 KiB buffer for incomplete headers when the headers arrived in
several reads.

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
- a maximum-size presentation header sent in small pieces is parsed and
  reaches the boundary;
- the model-visible schema excludes proof material, the public MCP interceptor
  injects the proof after tool selection, and the real `create_agent`
  LangGraph loop executes the gated HTTP MCP tool; and
- the optional Jev adapter returns a typed tool proposal, and a Jev-selected
  tool still fails closed when receiver authority is out of scope.

## What this run does not establish

- The SDK packages are the in-tree 2.0.0b1 build, not the published
  2.0.0-beta.1 packages. The result must be re-run when those are released.
- The claim store, receipt log, checkpoint, issuance store and security
  journal are the SDK's in-memory reference stores. Nothing here is evidence
  of a durable or production-shaped deployment.
- Only the platform and versions above were executed.
- This evidence supports only the independent draft and limitations documented
  in the reference README. It is not evidence of LangChain review or
  endorsement.
