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

Identity answers **which workload connected**. LangChain answers **which tool
the agent selected**. Ratify answers a different question: **which principal
authorized this agent to perform this exact operation, on this resource, within
these signed limits?** The receiving organization can verify that evidence
without sharing the sender's API key or calling the sender during the decision.

```mermaid
sequenceDiagram
    participant P as Principal
    participant A as LangChain agent
    participant R as Independent receiver
    participant T as Protected tool
    P->>A: Signed, bounded delegation
    A->>R: Exact operation
    R-->>A: Single-use operation-bound challenge
    A->>R: Challenge response + delegation proof
    R->>R: Verify root, agent, scope, resource,<br/>limit, expiry, revocation, freshness
    alt proof and receiver policy allow
        R->>T: Execute once
        T-->>A: ALLOW
    else anything fails
        R-->>A: DENY; tool remains untouched
    end
```

Run the published-package gate from the repository root:

```bash
./scripts/langchain-reference-check.sh
```

The gate creates a clean environment and uses the real `create_agent` LangGraph loop with a deterministic model
double, the public `MultiServerMCPClient` tool-interceptor API, and an
independently started Streamable HTTP MCP receiver. It needs no model API key or
paid service. It requires exactly 24 passing tests and fails on a skipped,
xfail, missing, or additional test. See
[`evidence/reference-evidence.md`](evidence/reference-evidence.md).

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

## What is actually tested

| Boundary case | Expected effect |
|---|---|
| Valid two-hop delegation, one node, allowed region | Receiver invokes the protected handler once |
| Excess count or wrong region | Signed constraint denies before execution |
| Expired or revoked delegation | Denied before execution |
| Replayed proof or changed operation | Denied; prior execution count is unchanged |
| Wrong presenting agent or untrusted root | Denied despite a cryptographically valid hostile proof |
| Malformed proof or invalid business input | Denied without consuming honest work or reaching the tool |
| Duplicate transport/proof headers or oversized proof header | HTTP boundary rejects the request before MCP |
| Missing transport credential | HTTP `401`; MCP receiver is not reached |
| Concurrent duplicate request IDs or exhausted pending capacity | Receiver state remains bounded and unambiguous |
| Real `create_agent` → interceptor → HTTP MCP path | Proof stays out of the model schema and ALLOW reaches the tool |

The deterministic model is deliberate: authorization must not depend on a
model deciding to follow a security instruction. A live model would demonstrate
tool selection, but add no authority guarantee.

The `com.ratifyprotocol.langchain.max_nodes` constraint is a draft Ratify
integration profile in a Ratify-owned namespace. It is not a LangChain-defined
constraint.

## Tested pins

- `langchain==1.3.14`
- `langchain-mcp-adapters==0.3.0`
- `mcp==1.29.0`
- `ratify-protocol==1.0.0a19`

## Limitations

- In-memory receiver state fails closed on restart.
- The protected provisioner is a counter; no cloud resources are created.
- Loopback HTTP is used without TLS or production workload identity.
- Trust distribution, durable revocation, shared challenge storage, receipts,
  rate limits, key custody, and audit retention remain deployment concerns.
- Proof headers are an independent integration profile, not an MCP or LangChain
  standard. The two-certificate alpha16 presentation is about 28 KB. This
  reference rejects presentations over 64 KiB, but many production proxies
  default to a much smaller per-header limit. Do not deploy this carrier without
  aligning every hop's limits and log redaction. A standardized MCP metadata or
  body carrier is the preferred maintainer-reviewed production path, especially
  for deeper post-quantum chains.
- Execution is at-most-once, not exactly-once; production retries require an
  idempotency and result ledger.
- LangSmith deployment, Agent Server custom auth, durable checkpoints, and live
  hosted models are composition-ready but not exercised or claimed here.

See [DESIGN.md](DESIGN.md) for the architecture and threat-boundary rationale.
