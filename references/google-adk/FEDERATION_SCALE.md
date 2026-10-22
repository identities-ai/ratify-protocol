# Cross-domain multi-agent authorization and scale

**Status:** executable independent reference on Ratify Protocol v2
(2.0.0-beta.1 line, tested against the in-tree 2.0.0a1 SDK); not a Google
architecture, endorsement, or production benchmark. The v1 version of this
note, with its one-million-call result, is kept in
[`v1/FEDERATION_SCALE.md`](v1/FEDERATION_SCALE.md).

This artifact addresses three questions together:

1. Can authority cross separately anchored trust domains without making the
   sender, model, or Ratify service the receiver's trust boundary?
2. Can several Google ADK agents narrow and exercise that authority while the
   receiver retains the final decision?
3. What is measured, and what must change operationally, as traffic grows?

The answer implemented here is a local-verification data plane. A receiving
service pins trust roots and approved federation routes, reconstructs the exact
operation, issues single-use challenges, verifies each proof, and releases the
decision immediately before its protected action. Ratify Verify is not required
on the synchronous call path.

Protocol v2 makes the receiver's local state explicit. Verification makes no
call to Ratify infrastructure, but a v2 `allow` needs current signed status for
every certificate in the chain, a claim store that consumes each challenge
once, a receipt log, and a checkpoint that acknowledges each receipt before the
decision is released. "No call to Ratify infrastructure" therefore means the
receiver runs a local status feed, claim store, receipt log and checkpoint. In
this reference those are the SDK's in-memory reference stores, labelled
development only.

## Executed topology

```text
Trust domain A                 Trust domain B

Root A (principal)             Root B (receiving organization)
  signs coordinator mandate      approves the same worker key for the
        |                        same exact scope and region
ADK coordinator A                        |
  narrows to approved broker B           |
        |  cross-domain handoff          |
ADK broker B                             |
  narrows to worker B                    |
        |                                |
ADK worker B  <--------------------------+
  selects ordinary business tool
        |
public ADK before_tool_callback
  obtains the approval set's two challenges and signs both
        |
MCP tools/call
  ordinary arguments
  _meta.com.ratifyprotocol/authority = proof under root A (challenge A)
  _meta.com.ratifyprotocol/admission = proof under root B (challenge B)
        |
receiver in domain B
  verifies A with trust pinned only to root A
  verifies B with trust pinned only to root B
  releases both; the approval ledger executes the set once
        |
ALLOW: durable protected write
DENY: protected write is absent
```

The ADK hierarchy routes work; it does not confer authority. The receiver
accepts the worker only when the authority chain follows its configured route
under root A and the second root independently approves the same worker key
for the same action. Replacing the broker, leaf, root, operation, resource,
constraint, challenge, or session binding fails closed.

## The dual-root composition profile (SPEC-v2 §7.14)

A single v2 verification has exactly one trusted root, and a second bundle on
the same challenge is a claim replay. The v1 reference presented two bundles
on one challenge; v2 composes two independent verifications instead:

1. **Approval set.** At challenge time the receiver opens an approval set in
   its ledger: a fresh `approval_set_id`, its verifier ID, workspace and
   session, the complete agent key, the required scope, the action's request
   hash, and the two complete root keys. A set naming one root twice is
   refused.
2. **Expected context.** The session context is derived from the set's own
   fields with `invocation_id = approval_set_id`, never taken from a proof.
3. **Two challenges.** One per root, both bound to the same agent key,
   verifier and derived context, each persisted before it is returned.
4. **Two verifications.** Each pins one root only and must reach a released
   `allow` with its own signed receipt.
5. **Ledger.** Each released decision is recorded in its root's slot only if
   it matches the set; the set executes once, at the receiver's clock, while
   both decisions are still current.

Because both approvals must name the set's single required scope, root B now
approves `custom:infra:provision` directly. The v1 `custom:workload:admit`
admission scope is retired in v2. The composite result is application state,
not a Protocol receipt.

The ledger here is the SDK's `ApprovalLedgerTestOnly`, which is development
only; a production deployment needs a durable ledger with the same checks.

## Architectural decisions

| Decision | Reference choice | Reason |
| --- | --- | --- |
| Enforcement point | Receiver immediately before the consequential handler | A compromised model or sender cannot bypass a check it does not operate |
| ADK integration | Public `FunctionTool` plus `before_tool_callback` | Supported ADK surface; authorization occurs after tool selection and before dispatch |
| MCP carrier | Request `_meta` keys `com.ratifyprotocol/authority` and `com.ratifyprotocol/admission` | Proof is not a model-selected business argument and MCP preserves extension metadata |
| A2A carrier | A registered or mutually agreed A2A extension with identical semantics | A2A already has an extension mechanism; this reference does not invent a parallel envelope |
| Two-organization approval | SPEC-v2 §7.14 dual-root composition profile | One verification has one root; two independent released approvals compose in an application ledger |
| Workload identity | Google Agent Identity or IAM authenticates the workload; deployment binds that identity to the Ratify leaf key | Workload identity and delegated authority answer different questions |
| Ephemeral workers | Pre-provisioned Google workload identity, short-lived Ratify leaf authority | Avoids creating a Google Agent Identity resource for every transient task |
| Replay defense | SDK issuance helper persists each challenge; the claim store consumes it once | Two replicas must not both accept one presentation |
| Revocation | Each issuer signs status with a separate status key; the receiver authenticates it into its security journal; missing, unauthenticated or stale status denies | Status semantics must be explicit and authenticated under partition |
| Release | Signed receipt appended and acknowledged before the handler runs | A committed decision is not actionable on its own |
| Node ceiling | Standard `com.ratifyprotocol.max_count/v1` profile, registered by the receiver | A shared, published evaluator instead of a reference-specific one |
| Scale unit | Completed protected calls, each with fresh challenges and full decisions | Avoids relabeling proof rechecks or cached allows as authorized calls |
| Hosted dependency | None on the verification critical path | Requires the local state above, not a hosted call |

The native `McpToolset` adapter remains an explicitly experimental lane because
ADK 2.6.3 does not expose a public operation-specific custom-MCP-metadata hook
on `McpTool`. The Google-facing recommendation is to validate whether ADK should
offer that hook. The executable supported lane does not depend on private
`McpTool` fields or methods.

## Exact call path

For every measured call:

1. The receiver validates canonical business arguments.
2. It reconstructs the operation, payload digest, request hash, receiver
   verifier ID, workspace, expected worker key, and resource.
3. It opens an approval set and issues two challenges through the SDK
   issuance helper, which persists each before returning it.
4. The worker signs each challenge with the derived session context and
   presents the authority chain on challenge A and root B's approval on
   challenge B.
5. The receiver checks the agent, challenge, and federation route of both
   presentations before claiming either challenge.
6. It ingests any new signed status lists into its security journal.
7. Ratify verifies each presentation: hybrid signatures, linkage, expiry,
   signed status, effective scope, resource, the max_count profile, the
   challenge signature, and the session binding. Each verification claims its
   challenge exactly once.
8. Each decision's signed receipt is appended to the log, the checkpoint
   acknowledges it, and the decision is released.
9. The ledger records both released allows and executes the set once.
10. Only then does the receiver-owned protected provisioner run.

Malformed or forged presentations do not consume an honest pending challenge.
A claimed attempt is terminal, so the same business request identifier can be
retried with new challenges. This distinction is tested because conflating the
two states creates either denial-of-service or replay defects.

## Scale architecture

The local reference intentionally uses one process. A production data plane is
the same decision split into horizontally scalable components:

```text
Global or organizational control plane
  trust-bundle publication
  key lifecycle and external identity binding
  status publishers (one per issuer, separate status keys) and their feed
  policy and evaluator-profile distribution
  audit export and retention

Regional receiver data plane
  workload transport authentication
  local trust configuration and security journal
  stateless verifier workers
  shared atomic claim store and challenge issuance store
  receipt log with an independent checkpoint
  durable approval ledger
  receiver-owned policy and resource reconstruction
  protected service with idempotency key
```

The claim store is the synchronization point for a single-use challenge across
replicas. The receipt log is strictly sequential per log ID, so a deployment
that needs more release throughput than one log provides runs several logs,
each under its own verifier key. Trust configuration and signed status are
read-mostly and distributed out of band.

## Measured call tiers

Run the exact-call benchmark from this directory after the gate has created
its virtual environment:

```bash
source .venv/bin/activate
python -m authority_reference.scale_benchmark \
  --calls 10,100,1000 \
  --workers 8 \
  --output evidence/federation-scale-local-rerun.json
```

Each call runs the complete dual-root path above. Every allowed call must equal
one protected-action invocation; denied calls (one in ten, deterministic node
count excess) are included to measure discrimination and fail-closed behavior.

The checked-in result is
[`evidence/federation-scale-local.json`](evidence/federation-scale-local.json),
measured on 2026-10-22 on a 10-core Apple M2 Pro (macOS 26.6, Python 3.12.10)
with eight requested workers:

| Calls | Workers | Allowed | Denied (`constraint_denied`) | Released receipts | Protected actions | Wall seconds | Calls per second | p50 ms | p95 ms | p99 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 5 | 9 | 1 | 19 | 9 | 5.588 | 1.790 | 2,556 | 3,071 | 3,071 |
| 100 | 8 | 90 | 10 | 190 | 90 | 71.112 | 1.406 | 5,414 | 7,195 | 8,017 |
| 1,000 | 8 | 900 | 100 | 1,900 | 900 | 1,123.928 | 0.890 | 7,185 | 19,359 | 25,503 |

The encoded dual-root presentation (both proofs, base64 as carried in MCP
`_meta`) is 76,148 bytes. Every allow released two receipts and every denial
one, and protected actions equal allows in every tier. The run is far slower
than v1: throughput is about one call per second, latency is seconds, and it
falls as the tier grows. Two causes are visible in profiles of the same path:
the Python v2 SDK verifies ML-DSA-65 and canonicalizes the security journal in
pure Python, and the in-memory reference stores grow with every claim and
receipt. The 10-call tier ran five workers because the harness splits calls
into equal batches. Another test process shared the host during part of the
1,000-call tier.

These are single-host measurements of the Python v2 SDK with in-memory
reference stores. They exclude Gemini latency, ADK reasoning, MCP HTTP,
status distribution, durable stores, multi-host storage, and Google Cloud
service latency, and they are not Google capacity claims.

**Why there is no one-million-call v2 tier.** The v1 note records 1,000,000
calls at 369.693 calls per second with Ratify `1.0.0a20`. The Python v2 SDK
verifies in pure Python, and each dual-root call runs two full verifications
with signed status and two receipt publications, so at the measured rate the
same tier would take roughly two weeks on this host. The in-memory reference
stores also retain every claim and receipt, so memory grows with the call
count. A meaningful v2 endurance number
needs a faster v2 verifier and durable stores; it is listed in
[`PRODUCTION_GAPS.md`](PRODUCTION_GAPS.md). The v1 result remains valid only as
v1 history and is not a v2 claim.

## Evidence and acceptance matrix

| Gate | Evidence in this reference | Status |
| --- | --- | --- |
| Public ADK hook | Real runner uses `before_tool_callback` and `FunctionTool` | Executed |
| Proof hidden from model | Ordinary schema; captured proof is in MCP `_meta` and absent from serialized ADK events | Executed |
| Real ADK multi-agent route | Coordinator to broker to worker nested-agent run | Executed |
| Dual-root composition profile | Two challenges, two released allows, ledger executes once; missing, revoked, wrong-challenge and same-root cases refused | Executed |
| Runtime narrowing | Broker-issued shorter-lived worker certificate; widened region or node ceiling denied | Executed |
| Independent MCP receiver | Separate process owns trust, status feed, and protected action | Executed |
| Durable consequence | SQLite row exists only for allow | Executed locally |
| Mid-task revocation | Signed revocation after challenge issuance prevents action | Executed |
| Status partition | Stale or unauthenticated status denies | Executed |
| Release gate | An unacknowledged receipt is not released and the action does not run | Executed |
| Replay and races | Replay (also with the application envelope restored), altered payload, duplicate request ID, and concurrent challenge tests | Executed |
| 10, 100, 1,000 calls | Exact full-path local benchmark | Measured |
| 1,000,000 calls | Not run on v2 (see above) | Not measured |
| Durable Part B stores and independent checkpoint | Contracts in SPEC-v2 §7 | Not implemented here |
| Vertex AI Agent Engine | Composition described | Not deployed here |
| Google Agent Identity | Upstream binding described | Not exercised here |
| A2A extension preservation | Required interoperability question identified | Not exercised here |

## Agent Relay provenance

The cross-company precedent is the published Agent Relay design partnership:

- Ratify harness: <https://github.com/identities-ai/ratify-agent-relay-harness>
- Agent Relay evidence: <https://github.com/AgentWorkforce/ratify-agent-relay-evidence>
- Ratify technical note: <https://ratifyprotocol.com/writing/agent-relay-phase2-technical-note>
- Agent Relay account: <https://agentrelay.com/blog/someone-elses-agent-in-your-repo>

That work ran on Protocol v1. It demonstrated narrowing and revocation across
two independently operated company deployments and exposed why the
consequential write must be gated. It is evidence for the cross-domain
semantics, not evidence for Google ADK compatibility, for Protocol v2, or for
Google-scale throughput.

## Failure policy

| Condition | Receiver behavior |
| --- | --- |
| Unknown root or unapproved route | Deny before any challenge is claimed |
| Wrong agent or workload-to-key binding | Deny |
| Changed operation or resource | Deny |
| Expired, revoked, excessive, or out-of-scope authority | Deny with a signed receipt |
| Missing, unauthenticated, or stale signed status | Deny (`status_unavailable` or `status_stale`) |
| Replay or claim-store uncertainty | Deny |
| Receipt not acknowledged by the checkpoint | Not released; deny |
| Either root's approval missing or not released | The approval set does not execute |
| Unregistered extension profile | Deny (`constraint_unknown`) |
| Protected action fails after authorization | Return execution failure; do not report allow |

Ratify does not detect prompt injection or decide whether a model's goal is
benign. A prompt-injected agent holding valid in-scope authority can spend that
authority. The reference includes an explicit test for this honesty boundary.
Prompt defenses, human confirmation, workload sandboxing, IAM, and tool policy
remain complementary controls.

## Questions for an ADK and Agent Engine review

1. Should `McpTool` expose a supported callback or provider for per-invocation
   MCP request metadata after model tool selection?
2. Which ADK and Agent Engine telemetry surfaces can observe MCP `_meta`, and
   what redaction contract can be guaranteed?
3. Will Agent Engine proxies and gateways preserve namespaced MCP `_meta` and
   A2A extensions end to end?
4. What is Google's recommended binding between Agent Identity and an
   application cryptographic key used by an ephemeral agent worker?
5. Which receiver deployments need shared claim state across regions, and
   what replay window and partition policy are acceptable?
6. Which proof-size, latency, and throughput envelopes should gate a joint
   evaluation on Google infrastructure?

These are integration questions, not requests for Google to adopt Ratify's
trust policy. The receiving service remains responsible for deciding which
roots, routes, profiles, resources, and freshness budgets it accepts.
