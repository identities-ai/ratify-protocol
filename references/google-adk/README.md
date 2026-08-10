# Proof-carrying authority for Google ADK agents

**Status:** independent draft reference implementation. Not a Google
partnership, Google-approved integration, or Google reference architecture.

This reference answers one narrow question:

> When a Google ADK agent crosses an MCP, A2A, tool, or organizational
> boundary, can the system carrying the consequence independently verify who
> authorized the agent for that exact action and which bounds still apply?

The visible result is intentionally simple:

```text
ALLOW -> tool invoked once
DENY  -> tool invocation count does not change
```

The model may request more authority. It cannot grant that authority to
itself.

## Run the published-package gate

From the Ratify repository root:

```bash
./scripts/google-adk-reference-check.sh
```

The script creates a disposable demo virtual environment, installs the exact
published packages in `requirements.txt`, refuses to run if Ratify resolves to
this repository's local Python SDK, runs the deterministic adversarial suite,
and then runs the three-case demonstration.

Tested pins:

- `google-adk==2.6.3`
- `ratify-protocol==1.0.0a16`
- `pytest==8.4.1`

The deterministic path needs no API key, Google Cloud project, or paid
service. It drives the real ADK runner with a scripted model double, so ADK
still performs model-turn handling, tool selection, tool execution, and
function-response delivery. The authorization result cannot depend on model
judgment.
The recorded run is in
[`evidence/reference-evidence.md`](evidence/reference-evidence.md).

## What the reference implements

```text
Principal
  signs root -> ADK commander
        scope: custom:infra:provision + identity:delegate
                  |
                  v
ADK commander
  signs commander -> infrastructure specialist
        scope: custom:infra:provision
        resource: gcp:projects/customer-project/regions/us-central1
        extension constraint: max_nodes = 1
                  |
                  v
Google ADK FunctionTool
  asks the independent receiver for an operation-bound challenge
  signs that challenge with the specialist key
                  |
                  v
Independent receiver
  pins the accepted principal root out of band
  reconstructs the operation and payload digest
  binds the challenge to verifier, workspace, agent, session, invocation,
    and operation hash
  atomically consumes the single-use challenge
  checks revocation, chain signatures, scope, resource, node count, and expiry
  invokes the protected tool only after ALLOW
```

The `ai.identities.ratify.adk.max_nodes` extension is a draft Ratify integration
profile. It is deliberately not placed in a Google namespace and does not
claim that Google defines or endorses it.

## Layer separation

| Layer | Question answered | This reference does not claim |
|---|---|---|
| Google Agent Identity / IAM | Which deployed agent workload is calling, and which Google Cloud permissions does it have? | That the workload carries a principal-signed grant for this exact cross-boundary action |
| Google ADK | How does the agent reason and invoke a tool? | That an in-process callback is an independent authorization boundary |
| MCP / A2A / tool transport | How does the request cross the boundary? | That transport authentication proves the principal's bounded intent |
| Ratify | Who delegated authority, for which scope/resource/bounds, and is the presentation fresh and unrevoked? | That the receiver must execute |
| Receiver policy and tool | Is the verified request acceptable now, and should the action execute? | That verifier-supplied context becomes trustworthy without receiver validation |

## Security boundary

The receiver is the security boundary. It performs five actions the presenting
agent is not trusted to perform:

1. Pins the accepted principal root. A valid self-issued chain is denied.
2. Parses and validates the requested operation.
3. Constructs the operation and session bindings itself.
4. Issues and atomically consumes a single-use challenge.
5. Verifies the proof and local policy before the protected handler runs.

The ADK tool is presentation code. It injects the proof so the model never sees
private keys or proof bytes. Moving `verify_bundle` into an ADK callback inside
the agent process would be a useful fail-fast check, but not a security control:
a compromised agent could skip its own callback.

## Deterministic acceptance matrix

The suite encodes why the boundary matters:

| Case | Expected result | Protected tool |
|---|---|---|
| Correct agent, one node, `us-central1` | `allow` | Invoked once |
| Three nodes under a one-node grant | `constraint_denied` | Not invoked |
| `us-east1` under a `us-central1` grant | `constraint_denied` | Not invoked |
| Expired delegation | `expired` | Not invoked |
| Revoked leaf delegation | `revoked` | Not invoked |
| Replayed presentation | `invalid` / consumed challenge | Not invoked again |
| Operation changed after challenge issuance | `operation_binding_failed` | Not invoked |
| Different agent answers the challenge | `agent_binding_failed` | Not invoked |
| Valid chain under an untrusted root | `untrusted_root` | Not invoked |
| Non-integral, zero, negative, boolean, or excessive node count | Input rejected | Not invoked |

## Optional live Gemini path

The deterministic suite is authoritative. To let Gemini select and invoke the
same ADK tool interactively:

```bash
cd references/google-adk
source .venv/bin/activate
export GOOGLE_API_KEY=your_key
adk run adk_app
```

Example prompt:

```text
Provision one n2-standard-4 node in us-central1. Use request id demo-1.
```

Then request three nodes or change the region and observe the receiver denial.
The app defaults to `gemini-3.6-flash`, Google's current stable Flash model as
of this evidence date. The optional live path demonstrates orchestration; it
adds no authorization guarantee beyond the deterministic receiver tests.

## Evidence tiers

| Tier | Executed here | Meaning |
|---|---|---|
| Receiver verification | Yes | Cryptographic and local-policy allow/deny matrix |
| ADK `FunctionTool` | Yes | Ordinary tool schema; proof injection stays outside model context |
| ADK runner loop | Yes | Model turn → function call → gated tool → function response |
| Gemini 3.6 Flash | Configuration-ready | Requires an operator API key; not part of recorded evidence |
| MCP / A2A / Agent Engine | Not yet | Proposed follow-on, not claimed as executed |

## Limitations

- The receiver and challenge store are in-memory and single-process.
- The protected provisioner is a counter, not Google Compute Engine. No cloud
  resources are created.
- Trust-root distribution, durable revocation, shared challenge storage, key
  custody, authorization receipts, rate limits, and production audit retention
  are deployment responsibilities not solved by this draft.
- The logical `gcp:` resource name is an integration profile. Verification
  proves authorization against the receiver-supplied logical resource; the
  execution layer must still ensure the real cloud operation matches it.
- This reference composes with Agent Identity conceptually but does not deploy
  to Vertex AI Agent Engine or exercise preview IAM Agent Identity APIs.
- The executed draft uses the real ADK runner and `FunctionTool` in one process.
  It does not yet execute an MCP or A2A transport hop; those are follow-on
  carriage profiles for the same receiver contract.

## Sources

- Google Agent Identity: <https://docs.cloud.google.com/iam/docs/auth-agent-own-identity>
- Google ADK: <https://github.com/google/adk-python>
- Gemini API release notes: <https://ai.google.dev/gemini-api/docs/changelog>
- Ratify Protocol: <https://github.com/identities-ai/ratify-protocol>
- Agent Relay integration note: <https://ratifyprotocol.com/writing/agent-relay-phase1-technical-note>
