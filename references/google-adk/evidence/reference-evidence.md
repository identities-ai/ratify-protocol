# Google ADK reference evidence (Protocol v2)

**Status:** executed reference evidence, recorded 2026-10-29 (gate run started
2026-10-29T02:07:59Z). This record is generated from the independent Ratify reference; it
is not Google attestation.

**Branch:** `feat/python-unified` at `32c1c09` (the commit that records this
run follows it and changes only the evidence). Since code commit `1315454` the
reference code changed only in its SDK import path: Protocol v2 moved from the
separate `ratify_protocol_v2` package into the `ratify-protocol` distribution
as `ratify_protocol.v2`.

**Protocol line:** v2 (2.0.0-beta.1), exercised with the in-tree SDK build
2.0.0b1.

The previous v2 run (2026-10-27, `9ea1ec2` with the beta bump, 58/58, against
the separate `ratify-protocol-v2` 2.0.0b1 build) is kept in git history at
`32c1c09`; the one before it (2026-10-22, code commit `1315454`, 58/58, against
the in-tree alpha.1 build) at `2244540`.

The Protocol v1 evidence (Ratify `1.0.0a20`, 49/49, and the
one-million-call run, September 2026) is kept unchanged in
[`../v1/evidence/`](../v1/evidence/reference-evidence.md).

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 (Apple M2 Pro, 10 logical CPUs) |
| Python | `3.12.10` |
| Rust / maturin (native extension build) | `rustc 1.95.0`, `maturin 1.15.0` |
| ratify-protocol | `2.0.0b1` with the `protocol-v2` extra, installed from `sdks/python` at the recorded tree |
| ratify-protocol-native-v2 | `2.0.0b1`, built from `sdks/python-native-v2` at the recorded tree |
| Google ADK | `2.6.3` |
| MCP Python SDK | `1.29.0` |
| pytest | `9.0.3` |
| Requirements SHA-256 | `27a8242661be3c5a4fa9a193a91a1c21c40d9b9181013a94beff38489153f492` |

## Reproduction

```bash
./references/google-adk/run-reference-check.sh
```

The recorded run set `RATIFY_REFERENCE_VENV` to a fresh directory outside the
repository. The gate builds the native extension, installs `ratify-protocol`
with its `protocol-v2` extra from this repository into that environment,
asserts that the SDK does not import from the source tree, checks every pin, runs the test matrix (exactly 58 passing tests, none
skipped), and runs the deterministic dual-root HTTP MCP demo.

## Recorded result

The transcript below is selected by script from the captured gate log; build
output and the pytest warnings summary are omitted, and the absolute
virtual-environment path is shortened.

```text
installed Ratify v2 SDK: .../site-packages/ratify_protocol/v2/__init__.py
google-adk==2.6.3 mcp==1.29.0 pytest==9.0.3 ratify-protocol==2.0.0b1 ratify-protocol-native-v2==2.0.0b1
..........................................................               [100%]
(pytest warnings summary omitted: ADK and dependency deprecation and experimental-feature notices)
58 passed, 38 warnings in 37.03s
gate: 58/58 passed; zero skipped, xfailed, failed, or errored
ALLOW across ADK HTTP MCP: {'decision': 'allow', 'status': 'authorized_agent', 'reason': 'authorized', 'resource': 'gcp:projects/customer-project/regions/us-central1', 'nodes_provisioned': 1, 'receipt_sequences': [1, 2], 'tool_invocations': 1, 'protected_action_invoked': True, 'approval_set_id': 'cf115d2df9b170213df4e21c26d33759', 'constraint_evaluators': [{'type': 'com.ratifyprotocol.max_count', 'profile_digest': 'sha384:27e6c6b37856ce4eed4c0923641d45a59d06e138b38893d850f8f0f1356200286fdb2e2e8d36cc69e4b550f9b2443e2b'}]}
DENY excessive count: {'decision': 'deny', 'status': 'constraint_denied', 'reason': 'released Protocol decision: constraint_denied', 'tool_invocations': 1, 'protected_action_invoked': False, 'protocol_reason': 'constraint_denied', 'identity_status': 'constraint_denied', 'receipt_sequence': 3, 'approval_slot': 'authority'}
DENY wrong region: {'decision': 'deny', 'status': 'constraint_denied', 'reason': 'released Protocol decision: constraint_denied', 'tool_invocations': 1, 'protected_action_invoked': False, 'protocol_reason': 'constraint_denied', 'identity_status': 'constraint_denied', 'receipt_sequence': 4, 'approval_slot': 'authority'}
GOOGLE ADK HTTP MCP DUAL-ROOT REFERENCE PASSED
```

No tests were skipped, xfailed, or retried.

## Measured call tiers

Command, run from `references/google-adk` on the same host on 2026-10-29
(started 2026-10-29T02:09:54Z), on branch `feat/python-unified` at `32c1c09`,
with the virtual environment the gate
above created for the in-tree `2.0.0b1` build (writing to a scratch path, then
copied to `evidence/federation-scale-local.json`):

```bash
RATIFY_REQUIRE_NATIVE=1 python -m authority_reference.scale_benchmark \
  --calls 10,100,1000 --workers 8 --output <scratch>/federation-scale-local.json
```

Hybrid verification ran in the native extension (`2.0.0-beta.1`). The result
records `ratify_protocol` and `ratify_protocol_native_v2` `2.0.0b1`. The
gate test `test_checked_in_evidence_matches_current_dual_root_proof_size`
re-derives the presentation size from the committed code.

The full result is [`federation-scale-local.json`](federation-scale-local.json).

| Calls | Workers | Allowed | Denied | Released receipts | Protected actions | Calls/s | p50 ms | p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 5 | 9 | 1 | 19 | 9 | 16.531 | 281.576 | 343.632 |
| 100 | 8 | 90 | 10 | 190 | 90 | 16.108 | 477.911 | 602.781 |
| 1,000 | 8 | 900 | 100 | 1,900 | 900 | 15.945 | 502.777 | 636.69 |

Every denial is `constraint_denied` (the deterministic one-in-ten node count
excess). The encoded dual-root presentation is 76,148 bytes. No other
benchmark or test ran during the measurement; ordinary desktop applications
and a few idle local containers were running. The tiers of 2026-10-27 against the separate `ratify-protocol-v2` build
(15.15, 16.206 and 15.694 calls/s) are kept in git history at `32c1c09`. The
earlier tiers (2026-10-22,
in-tree alpha.1 build, before native verification: 1.79, 1.406 and 0.89
calls/s) are kept in git history at `1315454`. The one-million-call tier was
not run on v2; see
[`../FEDERATION_SCALE.md`](../FEDERATION_SCALE.md#measured-call-tiers).

## What this run establishes

- A real `google.adk.agents.LlmAgent` exposes one ordinary
  `google.adk.tools.FunctionTool`, and the public callback lane carries the
  proof in MCP request metadata, absent from serialized ADK events.
- A valid request is verified, its signed receipt is appended and
  acknowledged, the decision is released, and the protected handler runs
  once; a receipt the checkpoint does not acknowledge is never released.
- `custom:infra:provision` is one exact custom scope, `custom:*` is refused at
  issuance, and the node ceiling is the standard
  `com.ratifyprotocol.max_count/v1` profile whose digest is sealed into the
  receipt.
- Each issuer's revocation status is signed by a separate status key; a
  revocation reaches the receiver through the local status feed and denies
  the next call over HTTP MCP; unauthenticated status is `status_unavailable`,
  stale status is `status_stale`, and a status key equal to the root key is
  refused at configuration.
- A real nested ADK coordinator, broker, and worker handoff reaches a
  receiver-owned federated route, and runtime broker narrowing is enforced.
- The SPEC-v2 §7.14 dual-root composition profile executes only with two
  released approvals on two distinct challenges; a missing approval, a
  revoked second root's certificate, an approval on the wrong challenge, and a
  set naming one root twice are refused.
- Excess count, wrong region, expiry, revocation, replay (also with the
  application envelope restored), altered operation, wrong agent, untrusted
  root, unapproved route, and invalid input never invoke the protected
  handler.
- The SDK resolved from the gate's virtual environment, not from the source
  tree, and the v1 package was absent.

## What this run does not establish

- The SDK packages are the in-tree 2.0.0b1 build, not the published
  2.0.0-beta.1 packages. The result must be re-run when those are released.
- The claim store, receipt log, checkpoint, issuance store, security journal
  and approval ledger are the SDK's in-memory reference stores. Nothing here
  is evidence of a durable or production-shaped deployment.
- No Gemini API call was made, and no Vertex AI Agent Engine, Agent Identity,
  A2A, TLS workload authentication, or Google Cloud resource was used.
- The scale numbers are single-host Python measurements; they are not Google
  production capacity claims, and no v2 tier above 1,000 calls was measured.
- Only the platform and versions above were executed.
