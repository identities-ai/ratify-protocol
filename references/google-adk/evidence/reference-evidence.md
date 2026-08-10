# Google ADK reference evidence

**Status:** executed draft evidence, August 10, 2026. This record is generated
from the independent Ratify reference; it is not Google attestation.

## Environment

| Field | Value |
|---|---|
| Host | macOS 26.6, arm64 |
| Python | 3.11.1 |
| Google ADK | `2.6.3` |
| Ratify Protocol | published PyPI package `1.0.0a16` |
| pytest | `8.4.1` |
| Protocol base commit | `f5a1522f20b79c881f77db96ae44948dd19dbd42` |
| Requirements SHA-256 | `ab0942b5164e36d43f6bc99b78ebc751011c2726e7a31117bc155d566da409f7` |

## Reproduction

```bash
./scripts/google-adk-reference-check.sh
```

The gate creates `references/google-adk/.venv`, installs the exact public
requirements, asserts the Ratify import does not resolve from `sdks/python`,
runs the test matrix, and runs the deterministic ADK `FunctionTool` demo.

## Recorded result

```text
pins: google-adk==2.6.3 ratify-protocol==1.0.0a16
................                                                         [100%]
16 passed, 5 warnings in 5.86s
ALLOW -> tool invoked once
DENY excessive count -> no additional invocation
DENY wrong region -> no additional invocation
GOOGLE ADK AUTHORITY REFERENCE PASSED
```

The five warnings came from Google ADK transitive dependencies during import:
one OpenTelemetry entry-point deprecation and four ADK
`BaseAgentConfig` deprecations. No tests were skipped, xfailed, or retried.

## What this run establishes

- A real `google.adk.agents.LlmAgent` exposes one ordinary
  `google.adk.tools.FunctionTool`.
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

- No Gemini API call was made. The model path remains optional because model
  judgment is not part of the authorization guarantee.
- No Vertex AI Agent Engine deployment or preview Agent Identity API was used.
- No MCP or A2A transport hop was executed; the recorded run covers the ADK
  `FunctionTool` to independently instantiated receiver boundary.
- No real Google Cloud resource was provisioned.
- Only the platform and versions above were executed. Other operating systems,
  architectures, Python versions, and ADK versions remain compatibility
  targets, not results.
