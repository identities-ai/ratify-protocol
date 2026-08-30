# Google ADK reference evidence

**Status:** executed draft evidence, August 10, 2026. This record is generated
from the independent Ratify reference; it is not Google attestation.

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 |
| Python | 3.11.1 |
| Google ADK | `2.6.3` |
| MCP Python SDK | `1.29.0` |
| Ratify Protocol | published PyPI package `1.0.0a16` |
| pytest | `8.4.1` |
| Protocol base commit | `f5a1522f20b79c881f77db96ae44948dd19dbd42` |
| Requirements SHA-256 | `b934bca56ea62573af6b5ffe9b8b9224138ee405a5efd3f99f157c21fef5a3b9` |

## Reproduction

```bash
./scripts/google-adk-reference-check.sh
```

The gate creates `references/google-adk/.venv`, installs the exact public
requirements, asserts the Ratify import does not resolve from `sdks/python`,
runs the test matrix, and runs the deterministic native ADK MCP demo.

## Recorded result

```text
pins: google-adk==2.6.3 mcp==1.29.0 ratify-protocol==1.0.0a16
.................................                                        [100%]
33 passed, 37 warnings
gate: 33/33 passed; zero skipped, xfailed, failed, or errored
ALLOW across ADK HTTP MCP -> tool invoked once
DENY excessive count -> no additional invocation
DENY wrong region -> no additional invocation
GOOGLE ADK HTTP MCP AUTHORITY REFERENCE PASSED
```

The warnings came from Google ADK and transitive dependency deprecations or
experimental feature notices. No tests were skipped, xfailed, or retried.

## What this run establishes

- A real `google.adk.agents.LlmAgent` exposes one ordinary
  `google.adk.tools.FunctionTool`.
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
- The function tool uses a two-hop Ratify delegation and a receiver-issued,
  operation-bound, single-use challenge.
- The independent receiver invokes its protected handler exactly once for the
  valid request.
- Excess count, wrong region, expiry, revocation, replay, altered operation,
  wrong agent, untrusted root, and invalid input cases do not invoke the
  protected handler.
- Ratify resolved from the demo virtual environment's public package install,
  not from this repository's Python SDK source.

## What this run does not establish

- No Gemini API call was made. The optional app is configured for the current
  stable `gemini-3.6-flash` path, but model judgment is not part of the
  authorization guarantee.
- No Vertex AI Agent Engine deployment or preview Agent Identity API was used.
- Streamable HTTP MCP was executed over loopback. A2A, TLS workload
  authentication, Agent Engine, and Agent Identity deployment were not.
- No real Google Cloud resource was provisioned.
- Only the platform and versions above were executed. Other operating systems,
  architectures, Python versions, and ADK versions remain compatibility
  targets, not results.
