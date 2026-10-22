# Production transport profile backlog

This document records what remains after the independent LangChain reference.
The current evidence proves the receiver-side authority boundary; it does not
claim a production deployment profile.

## Definition of done

Call this a production transport profile only when independently implemented
clients and receivers can carry the same operation-bound proof through real
infrastructure, survive retries and concurrency, and make the same fail-closed
decision without relying on undocumented LangChain behavior.

## Ordered work

### P0 — agree on the proof carrier

**Open question for LangChain and MCP maintainers:** what stable,
non-model-visible MCP carrier should contain an operation-bound authorization
presentation?

The reference uses `X-Ratify-Presentation`. A two-certificate hybrid proof is
about 28 KB, above common 8 KiB proxy defaults. Before production:

- select MCP metadata, a structured request envelope, or another documented
  carrier;
- namespace and version it;
- define encoding, maximum size, duplicate handling, forwarding, redaction,
  unsupported-version behavior, and capability negotiation;
- verify that LangChain interceptors can populate it through public APIs; and
- publish cross-client/server conformance fixtures.

**Exit criterion:** maintainer-reviewed carrier contract plus tests through at
least one real reverse proxy. No private LangChain API is required.

### P0 — transport identity and binding

- Replace the static token with MCP OAuth 2.1, mTLS/workload identity, or an
  equivalent production credential.
- Keep transport authentication distinct from Ratify authority.
- Define receiver policy for binding the authenticated workload to the Ratify
  `agent_id` and for rejecting mismatches.
- Exercise credential rotation, expiry, and authentication-service outage.

**Exit criterion:** an arbitrary network holder of a valid proof or transport
credential alone cannot execute the operation.

### P0 — durable replay and idempotency state

- Replace in-memory pending/challenge state with an atomic shared store.
- Enforce TTL, per-workload capacity, multi-instance single consumption, and
  restart-safe replay denial.
- Add an idempotency/result ledger with `pending → executing → completed`.
- Return the recorded result after a lost response instead of executing twice.

**Exit criterion:** concurrent presentations and post-execution retries across
multiple receiver instances produce one business effect.

### P1 — trust, revocation, and key operations

- Specify trusted-root provisioning, expected-agent policy, key rotation,
  revocation distribution, configuration versioning, and cache freshness.
- Define fail-closed behavior for stale or unavailable trust/revocation data.
- Keep all trust inputs receiver-owned.

**Exit criterion:** rotation, revocation, stale-cache, and dependency-outage
tests pass without presenter-controlled trust decisions.

### P1 — stable operation mappings and failures

- Publish a mapping for every protected tool: scope, canonical operation,
  resource identifier, payload digest, and extension constraints.
- Define machine-readable statuses for missing/unsupported proof, invalid
  delegation, replay, binding mismatch, transport failure, dependency outage,
  and failure after execution.
- Ensure model-facing messages cannot obscure the receiver decision.

**Exit criterion:** two independent receivers derive identical authorization
inputs and status classes from the same MCP call.

### P1 — deployment and safe observability

- Require TLS, request limits, timeouts, rate limits, secret rotation, and
  resource-exhaustion controls.
- Verify that proxies, LangSmith traces, application logs, and error reporting
  never record proof bytes or credentials.
- Record decision code, proof hash, certificate IDs, root/agent IDs, operation
  hash, idempotency ID, receipt ID, and execution outcome under retention policy.

**Exit criterion:** deployment review and log-capture tests show no proof,
challenge, key, or credential disclosure.

### P2 — LangSmith and compatibility evidence

- Deploy through LangSmith Agent Server custom authentication.
- Exercise durable LangGraph checkpoints and resume behavior.
- Test multiple LangChain/MCP versions, reverse proxies, multiple receiver
  instances, version negotiation, and unsupported extensions.
- Keep a deterministic gate authoritative; a live hosted model is optional
  orchestration evidence, not an authorization control.

**Exit criterion:** a published compatibility matrix and reusable conformance
suite pass with zero skips.

## Not blockers for the current independent draft

The current PR is ready for technical review without completing this backlog.
Its purpose is to pressure-test the receiver boundary and choose the production
carrier with maintainers before prematurely standardizing one.
