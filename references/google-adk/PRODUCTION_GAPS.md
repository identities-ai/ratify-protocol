# Production transport profile backlog

The current Google ADK profile proves delegated authority at an independent
receiver over native Streamable HTTP MCP. It does not claim a production Google
Cloud deployment or a Google-approved transport profile.

## Definition of done

Call this a production profile only when the presentation path uses a supported
ADK/MCP extension point, deployed workload identity is bound to the expected
Ratify agent, receiver state and retries survive multi-instance failure, and
the profile has repeatable Agent Engine or equivalent deployment evidence.

## Ordered work

### P0 — supported hidden presentation hook

The reference subclasses pinned-version `McpTool` behavior because ADK does not
currently expose a stable operation-specific hidden metadata hook.

- Review the seam with ADK maintainers.
- Prefer an official callback/interceptor that runs after tool selection and
  before MCP dispatch.
- Keep keys, challenges, session context, and proof bytes outside model-visible
  arguments, events, traces, and confirmation prompts.
- Define a versioned MCP metadata/body carrier rather than relying on a large
  custom HTTP proof header.

**Exit criterion:** public supported API, carrier contract, and forward-
compatibility tests; no private member or pinned internal subclass is required.

### P0 — Agent Identity and transport binding

- Deploy the presenting workload with Google Agent Identity or the supported
  successor and authenticate the MCP transport with workload identity/mTLS.
- Bind the authenticated workload identity to the receiver-pinned Ratify
  `agent_id`; document legitimate rotation and mismatch handling.
- Keep IAM permissions, transport authentication, and Ratify delegated
  authority as separate checks.

**Exit criterion:** wrong workload, valid proof; right workload, wrong proof;
and credential/proof theft cases all fail closed.

### P0 — durable replay and exactly-once recovery

- Move challenges and pending operations to an atomic shared store.
- Enforce per-workload quotas, TTL, restart safety, and multi-instance single
  consumption.
- Add an idempotency/result ledger so a response lost after execution returns
  the recorded result without executing again.

**Exit criterion:** failover, concurrency, and lost-response tests produce one
business effect.

### P1 — Agent Engine and A2A execution

- Deploy the ADK agent to Vertex AI Agent Engine or the current supported
  production runtime.
- Exercise the same receiver boundary through real TLS ingress.
- Add A2A only where the operation crosses an agent boundary; do not imply that
  A2A transport itself proves delegated authority.
- Verify ADK confirmation/HITL composition without treating local confirmation
  as the receiver's security boundary.

**Exit criterion:** reproducible deployed evidence for workload → ADK → MCP
receiver, plus separately labelled A2A evidence if implemented.

### P1 — trust, revocation, operation maps, and failures

- Define root provisioning, rotation, revocation freshness, outage policy, and
  receiver-owned configuration versioning.
- Publish deterministic tool-to-scope/operation/resource/payload/constraint
  mappings.
- Standardize machine-readable failures, including failure after execution.

**Exit criterion:** independent receiver implementation reaches the same
authorization inputs and failure classes.

### P1 — secure operations and observability

- Set TLS, proxy/body limits, timeouts, rate limits, secret rotation, and audit
  retention.
- Prove Cloud Logging, Agent Engine telemetry, ADK events, traces, and proxy
  logs redact proof bytes, challenges, credentials, and keys.
- Record hashes and decision metadata rather than secret-bearing payloads.

**Exit criterion:** deployment and log-capture review finds no sensitive proof
material and exercises dependency outages.

### P2 — conformance and compatibility

- Test supported ADK, MCP SDK, Agent Engine, and Agent Identity versions.
- Cover multiple receiver instances, proxy limits, version negotiation,
  unsupported extensions, credential rotation, and restart behavior.
- Publish a zero-skip reusable transport conformance gate.

**Exit criterion:** compatibility matrix and independent reproduction.

## Maintainer questions

1. Which supported ADK hook should inject hidden, operation-specific MCP
   authorization metadata after tool selection?
2. Which MCP carrier will ADK preserve without exposing it to the model?
3. What is the supported binding between Agent Identity and an outbound MCP
   client workload?
4. Which Agent Engine deployment should be the canonical production test?
