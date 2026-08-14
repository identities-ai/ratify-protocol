# Production transport profile backlog

The NVIDIA OpenShell + NOOA reference has executed a real sandbox, gateway,
MCP receiver, Ratify decision, consequential action, and signed-receipt path.
That is stronger deployment evidence than a loopback-only profile, but it is
still an independent interoperability draft rather than an NVIDIA-approved
production profile.

## Definition of done

Call this a production profile only when workload identity, durable receiver
state, exactly-once recovery, operational trust/revocation, stable proof
carriage, and repeatable multi-instance OpenShell evidence are specified and
validated under failure.

## Ordered work

### P0 — stable MCP proof carrier

The reference carries proof in Ratify-owned MCP metadata. Before production:

- review the metadata namespace and lifecycle with NVIDIA/OpenShell and MCP
  maintainers;
- define encoding, size, duplicates, forwarding, redaction, versioning, and
  unsupported-profile behavior;
- verify OpenShell preserves the bytes exactly while never exposing them as
  model business arguments; and
- publish envelope limits for the deepest supported hybrid delegation chain.

**Exit criterion:** maintainer-reviewed carrier contract and cross-version
fidelity tests through the real gateway.

### P0 — workload and sandbox identity binding

- Replace development credentials with supported workload identity or mTLS.
- Bind authenticated sandbox/workload identity to the receiver-pinned Ratify
  `agent_id` where policy requires it.
- Test stolen proof, stolen transport credential, wrong sandbox identity,
  credential rotation, and identity-provider outage separately.
- Preserve the distinction between OpenShell reachability policy and Ratify
  semantic authority.

**Exit criterion:** neither network admission nor a valid proof alone is enough
to execute from the wrong workload.

### P0 — durable receiver and exactly-once effects

- Replace process-local challenge, pending-operation, receipt-chain, and
  idempotency state with atomic durable storage.
- Prove multi-instance single consumption, restart-safe replay prevention,
  bounded per-workload capacity, and receipt-chain continuity.
- Return a recorded result after response loss rather than issuing a second
  refund.

**Exit criterion:** gateway, receiver, and storage failover tests yield exactly
one refund and one durable decision/result record.

### P1 — production trust and revocation

- Specify root onboarding, agent allowlisting, rotation continuity, revocation
  distribution, cache freshness, configuration versions, and outage policy.
- Exercise stale and unavailable revocation/trust sources.
- Keep trust configuration receiver-controlled.

**Exit criterion:** rotation/revocation/freshness tests pass across receiver
instances without presenter-selected roots.

### P1 — OpenShell deployment operations

- Move from a local disposable profile to the intended NVIDIA deployment
  topology with TLS, secrets, image provenance, resource limits, rate limits,
  timeouts, upgrades, and rollback.
- Repeat stability and concurrency campaigns on supported OpenShell releases.
- Define which OpenShell policy, gateway, and audit APIs are stable contracts.

**Exit criterion:** documented support matrix, repeatable clean deployment, and
failure-injection evidence for gateway restart, policy reload, and saturation.

### P1 — mappings, failures, receipts, and observability

- Publish canonical mappings for every protected capability.
- Standardize machine-readable transport, verification, policy, dependency,
  and post-execution failure classes.
- Define receipt signing-key custody, rotation, retention, and consumer
  verification.
- Audit OpenShell, NOOA, MCP, receiver, and service logs to retain hashes and
  decisions without proof bytes, credentials, or sensitive refund data.

**Exit criterion:** independent implementations agree on inputs/statuses and
receipts remain verifiable across rotation and retention windows.

### P2 — independent conformance

- Publish reusable client/server fixtures for fidelity, replay, duplicate
  metadata, size bounds, concurrency, failover, version negotiation, and
  unsupported extensions.
- Reproduce the live profile outside the development machine and, ideally,
  with an NVIDIA/OpenShell maintainer or design partner.

**Exit criterion:** zero-skip conformance suite plus independent reproduction.

## Maintainer questions

1. Is the current MCP metadata carrier stable across supported OpenShell
   releases and gateway implementations?
2. Which OpenShell identity should the receiver bind to the Ratify agent?
3. Which policy/audit APIs are supported production contracts?
4. What deployment topology and release matrix should define compatibility?
