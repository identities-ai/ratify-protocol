# LangChain delegated-authority reference design

**Status:** pre-implementation design for an independent reference. This is
not a LangChain partnership, LangChain-approved integration, or LangChain
reference architecture.

## Question

When a LangChain agent selects a consequential MCP tool across a process or
organizational boundary, can the receiver independently verify who authorized
that agent for the exact action and which bounds still apply?

The intended observable result is:

```text
ALLOW -> protected handler invoked once
DENY  -> protected handler invocation count does not change
```

## Current LangChain stack

The names describe different layers and should not be collapsed:

| Layer | Native responsibility | Authority gap this reference tests |
|---|---|---|
| LangChain `create_agent` | Model/tool agent loop and middleware | The model-selected call does not itself carry principal-signed authority |
| LangGraph | Durable orchestration, state, persistence, interrupts, and human-in-the-loop | Stored state or an approval event is not portable evidence a remote receiver can verify |
| LangChain MCP adapters | Convert MCP tools to LangChain tools; connect over Streamable HTTP; intercept calls and add per-call arguments or headers | Transport credentials identify or authenticate a caller but do not prove the principal's bounded intent for one operation |
| LangSmith Agent Server | Deploy assistants, threads, runs, persistence, and task queues | Agent Server access control governs LangSmith resources, not an external receiver's protected business operation |
| LangSmith custom auth | Authenticate requests and authorize access to threads, assistants, runs, and related resources; pass user-scoped credentials into agent context | Bearer credentials forwarded on a user's behalf remain ambient credentials and receiver-local policy inputs |
| Ratify | Present a signed delegation chain and fresh, operation-bound proof | Ratify does not authenticate the transport, orchestrate the agent, define local policy, or require execution |
| Receiver policy/tool | Reconstruct the requested operation, pin trust, verify, apply local policy, and execute | The receiver remains the final decision maker |

## Native integration seam

Use `langchain==1.3.14` and `langchain-mcp-adapters==0.3.0`, pinned to the
public packages inspected for this design.

`MultiServerMCPClient` accepts `tool_interceptors`. An interceptor receives an
`MCPToolCallRequest` after the model has selected a tool and arguments. Its
public `override` method supports replacing `args` and HTTP `headers`. This is
the narrowest native seam because it lets application code:

1. read the exact business arguments selected by the model;
2. request a challenge from the independently operated receiver;
3. sign the challenge with the presenting agent's key outside model context;
4. attach the encoded proof and binding data as per-call HTTP headers; and
5. invoke the ordinary MCP tool through the adapter's normal handler.

The MCP tool schema therefore contains only business arguments. Private keys,
challenge bytes, session-context bytes, and proof bundles are never tool
arguments and never enter the model-visible schema or conversation state.

This is preferable to LangChain `wrap_tool_call` for this profile. That hook is
appropriate for general LangChain tools, but the MCP interceptor is closer to
the actual remote boundary and has a documented, public mechanism for dynamic
HTTP headers.

## Proposed flow

```text
Principal
  signs root -> LangChain commander
        scope: custom:infra:provision + identity:delegate
                  |
                  v
LangChain commander
  signs commander -> infrastructure specialist
        scope: custom:infra:provision
        resource: gcp:projects/customer-project/regions/us-central1
        extension constraint: max_nodes = 1
                  |
                  v
LangChain create_agent (real agent loop, scripted model in the gate)
  model selects an ordinary MCP tool and business arguments
                  |
                  v
Public MCP tool interceptor
  obtains an operation-bound challenge after tool selection
  signs outside model context
  adds proof and binding data as per-call HTTP headers
                  |
                  v
Independent Streamable HTTP MCP receiver
  authenticates the transport separately
  pins the accepted root and expected agent out of band
  reconstructs the operation from MCP tool arguments
  binds verifier, workspace, agent, session, invocation, and operation hash
  atomically consumes the challenge
  checks chain, scope, resource, node ceiling, expiry, revocation, and freshness
  invokes the protected handler only after ALLOW
```

## Security decisions

- The receiver, not the LangChain process, is the security boundary. A local
  middleware denial can improve safety but a compromised agent can skip its
  own middleware.
- The receiver chooses its trusted root and expected presenting agent from
  deployment configuration. Neither is accepted from model arguments or proof
  headers.
- The receiver reconstructs canonical payload bytes from validated business
  arguments. The presenter cannot supply its own operation digest.
- Challenge issuance and protected execution are distinct HTTP operations.
  The challenge is single-use and bound to the exact operation.
- Transport authentication is independent from delegated-authority proof.
  Possession of the transport credential is insufficient to execute.
- Proof headers are application metadata, not an MCP authorization proposal.
  A production profile should map their names and transport treatment with the
  LangChain and MCP maintainers.
- Protected execution is at-most-once. A production tool needs an idempotency
  and result ledger before retries can provide exactly-once business effects.

## Deterministic evidence gate

The authoritative path should use LangChain's real `create_agent` graph with
`GenericFakeChatModel`, which LangChain documents for deterministic tool-call
tests. It requires no model API key and still exercises model-turn handling,
tool selection, the MCP adapter, the interceptor, HTTP transport, receiver
verification, and function-response delivery.

At minimum, denial cases must assert that the protected invocation counter is
unchanged:

- excessive node count;
- wrong region/resource;
- expired delegation;
- revoked leaf delegation;
- replayed presentation;
- operation altered after challenge issuance;
- wrong presenting agent;
- valid chain under an untrusted root;
- missing, malformed, oversized, or duplicated proof headers;
- invalid business arguments;
- unauthenticated transport;
- pending-capacity saturation;
- concurrent duplicate request identifiers; and
- receiver unavailability.

The gate should create a disposable virtual environment, install exact public
package pins, reject a Ratify import from the repository SDK, run with zero
skips and zero xfails, and record package versions plus the requirements hash.

## Non-claims

The first reference should not claim to exercise LangSmith cloud deployment,
Agent Server custom authentication, durable LangGraph checkpoints, production
OAuth, TLS workload identity, a real cloud provisioner, or a LangChain-managed
authorization feature. Those are adjacent composition points, not prerequisites
for proving the receiver-side boundary.

## Primary sources

- LangChain agents: <https://docs.langchain.com/oss/python/langchain/agents>
- LangChain middleware: <https://docs.langchain.com/oss/python/langchain/middleware/overview>
- LangChain MCP adapters and interceptors: <https://docs.langchain.com/oss/python/langchain/mcp>
- LangGraph overview: <https://docs.langchain.com/oss/python/langgraph/overview>
- LangSmith authentication and access control: <https://docs.langchain.com/langsmith/auth>
- LangSmith Agent Server: <https://docs.langchain.com/langsmith/agent-server>
- LangChain unit testing: <https://docs.langchain.com/oss/python/langchain/test/unit-testing>
- Ratify Protocol: <https://github.com/identities-ai/ratify-protocol>
