# Google ADK reference evidence

**Status:** executed published-reference evidence, re-run September 16, 2026. This record is generated
from the independent Ratify reference; it is not Google attestation.

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 |
| Python | 3.12.10 |
| Google ADK | `2.6.3` |
| MCP Python SDK | `1.29.0` |
| Ratify Protocol | published PyPI package `1.0.0a20` |
| pytest | `9.0.3` |
| Protocol release | `v1.0.0-alpha.20` |

## Reproduction

```bash
./scripts/google-adk-reference-check.sh
```

The gate creates `references/google-adk/.venv`, installs the exact public
requirements, asserts the Ratify import does not resolve from `sdks/python`,
runs the test matrix, and runs the deterministic native ADK MCP demo.

## Recorded result

```text
pins: google-adk==2.6.3 mcp==1.29.0 ratify-protocol==1.0.0a20
.................................................                        [100%]
49 passed, 37 warnings in 19.01s
gate: 49/49 passed; zero skipped, xfailed, failed, or errored
ALLOW across ADK HTTP MCP: {'decision': 'allow', 'status': 'authorized_agent', 'resource': 'gcp:projects/customer-project/regions/us-central1', 'nodes_provisioned': 1, 'tool_invocations': 1, 'protected_action_invoked': True}
DENY excessive count: {'decision': 'deny', 'status': 'constraint_denied', 'reason': 'constraint_denied: cert 0: constraint[1] (com.ratifyprotocol.adk.max_nodes): requested 3 nodes exceeds max 1', 'tool_invocations': 1, 'protected_action_invoked': False, 'verification_code': 'constraint_denied'}
DENY wrong region: {'decision': 'deny', 'status': 'constraint_denied', 'reason': 'constraint_denied: cert 0: constraint[0] (resource_path): requested resource does not match the authorized resource', 'tool_invocations': 1, 'protected_action_invoked': False, 'verification_code': 'constraint_denied'}
GOOGLE ADK HTTP MCP FEDERATION REFERENCE PASSED
```

The warnings came from Google ADK and transitive dependency deprecations or
experimental feature notices. No tests were skipped, xfailed, or retried.

## What this run establishes

- A real `google.adk.agents.LlmAgent` exposes one ordinary
  `google.adk.tools.FunctionTool`.
- The public ADK callback lane carries the authority proof in MCP request
  metadata, not model-visible arguments, and the exact proof is absent from
  serialized ADK events.
- A real nested ADK coordinator, broker, and worker handoff reaches a
  receiver-owned federated route.
- A dual-root authority and workload-admission presentation succeeds only when
  both roots approve the same worker key.
- Runtime broker narrowing is enforced by receiver verification: narrower
  certificates allow, while widened region or node ceilings deny before action.
- A deterministic model double drives the real ADK runner through model turn,
  function call, gated tool execution, function response, and final response.
- Native ADK `McpToolset` discovers the public tool from an independently
  started Streamable HTTP MCP receiver.
- The model-visible MCP declaration contains only business arguments. The
  adapter acquires the challenge and injects the proof after tool selection.
- Altered operations and replayed presentations are denied across the MCP
  process boundary without an additional protected-handler invocation.
- ADK confirmation and tool-name prefixing remain intact; ordinary malformed
  model output returns a structured denial instead of crashing the agent loop.
- A dedicated transport-token header blocks unauthenticated challenge calls,
  duplicate transport-token headers fail as ambiguous before MCP dispatch,
  hostile roots fail over HTTP, junk presentations cannot cancel honest pending operations,
  and pending capacity fails structurally at its enforced bound.
- Concurrent duplicate request IDs produce exactly one pending operation, and
  an unavailable receiver fails within the configured timeout rather than
  hanging the agent loop.
- The function tool uses a receiver-issued, operation-bound, single-use
  challenge; the federation path uses three signed delegation certificates.
- The independent receiver invokes its protected handler exactly once for the
  valid request.
- Excess count, wrong region, expiry, revocation, replay, altered operation,
  wrong agent, untrusted root, and invalid input cases do not invoke the
  protected handler.
- Ratify resolved from the demo virtual environment's public package install,
  not from this repository's Python SDK source.
- The exact-call scale harness completed 10, 100, 1,000, and 1,000,000 calls
  with one unique challenge and dual-root hybrid verification per call. The
  one-million result is recorded in
  [`federation-scale-local.json`](federation-scale-local.json): 369.693 calls
  per second, p50 20.229 ms, p95 28.129 ms, p99 31.801 ms, 56,244 encoded proof
  bytes, 900,000 allows, 100,000 constraint denials, and 900,000 protected-action
  invocations. The scale workload deliberately uses constraint denials only;
  replay, revocation, malformed-admission, and untrusted-root denials are
  covered by the deterministic gate rather than mixed into the million-call
  throughput sample.

## What this run does not establish

- No Gemini API call was made. The optional app is configured with the example
  `gemini-3.6-flash` model identifier, but model judgment is not part of the
  authorization guarantee.
- No Vertex AI Agent Engine deployment or preview Agent Identity API was used.
- Streamable HTTP MCP was executed over loopback. A2A, TLS workload
  authentication, Agent Engine, and Agent Identity deployment were not.
- No real Google Cloud resource was provisioned.
- The scale numbers are single-host Python measurements on a 10-core Apple
  Silicon host with eight workers. They exclude ADK model latency, MCP HTTP,
  external revocation distribution, multi-host storage, and Google Cloud
  service latency; they are not Google production capacity claims.
- Only the platform and versions above were executed. Other operating systems,
  architectures, Python versions, and ADK versions remain compatibility
  targets, not results.
