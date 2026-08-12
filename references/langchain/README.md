# Proof-carrying authority for LangChain agents

**Status:** independent draft reference implementation. Not a LangChain
partnership, LangChain-approved integration, or LangChain reference architecture.

This reference answers one narrow question:

> When a LangChain agent crosses an MCP or organizational boundary, can the
> receiver independently verify who authorized that agent for the exact action
> and which bounds still apply?

```text
ALLOW -> protected tool invoked once
DENY  -> protected tool invocation count does not change
```

Run the published-package gate from the repository root:

```bash
./scripts/langchain-reference-check.sh
```

The gate uses the real `create_agent` LangGraph loop with a deterministic model
double, the public `MultiServerMCPClient` tool-interceptor API, and an
independently started Streamable HTTP MCP receiver. It needs no model API key or
paid service.

## Boundary

The model sees only `request_id`, `region`, `instance_type`, and `count`. After
tool selection, a LangChain MCP interceptor obtains an operation-bound challenge,
signs it outside model context, and adds the proof as a per-call HTTP header.
The receiver pins the accepted root and expected agent out of band, reconstructs
the operation, consumes the challenge, verifies the delegation, and invokes the
protected handler only after ALLOW.

LangChain and LangGraph orchestrate the agent. LangSmith authentication and
authorization protect Agent Server resources and can supply user-scoped
credentials. MCP transports the tool call. Ratify adds portable evidence of the
principal's bounded authority for the exact action. Receiver policy still makes
the final execution decision.

## Tested pins

- `langchain==1.3.14`
- `langchain-mcp-adapters==0.3.0`
- `mcp==1.29.0`
- `ratify-protocol==1.0.0a16`

## Limitations

- In-memory receiver state fails closed on restart.
- The protected provisioner is a counter; no cloud resources are created.
- Loopback HTTP is used without TLS or production workload identity.
- Trust distribution, durable revocation, shared challenge storage, receipts,
  rate limits, key custody, and audit retention remain deployment concerns.
- Proof headers are an independent integration profile, not an MCP or LangChain
  standard. Header naming should be reviewed with maintainers.
- Execution is at-most-once, not exactly-once; production retries require an
  idempotency and result ledger.
- LangSmith deployment, Agent Server custom auth, durable checkpoints, and live
  hosted models are composition-ready but not exercised or claimed here.

See [DESIGN.md](DESIGN.md) for the architecture and threat-boundary rationale.
