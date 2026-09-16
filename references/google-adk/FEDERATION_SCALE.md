# Cross-domain multi-agent authorization and scale

**Status:** executable independent reference; not a Google architecture,
endorsement, or production benchmark.

This artifact addresses three questions together:

1. Can authority cross separately anchored trust domains without making the
   sender, model, or Ratify service the receiver's trust boundary?
2. Can several Google ADK agents narrow and exercise that authority while the
   receiver retains the final decision?
3. What is measured, and what must change operationally, as traffic grows from
   10 to 1,000,000 protected calls?

The answer implemented here is a local-verification data plane. A receiving
service pins trust roots and approved federation routes, reconstructs the exact
operation, issues a single-use challenge, and verifies the proof immediately
before its protected action. Ratify Verify is not required on the synchronous
call path.

## Executed topology

```text
Trust domain A                 Trust domain B

Principal root
  signs coordinator mandate
        |
ADK coordinator A
  narrows to approved broker B
        |  cross-domain handoff
ADK broker B
  narrows to worker B
        |
ADK worker B
  selects ordinary business tool
        |
public ADK before_tool_callback
  obtains receiver challenge and signs it
        |
MCP tools/call
  ordinary arguments
  _meta.com.ratifyprotocol/authority = authority proof
  _meta.com.ratifyprotocol/admission = workload admission proof (dual-root profile)
        |
receiver in domain B
  pins the Domain A authority root and, in the dual-root profile,
  the Domain B admission root
  reconstructs operation and verifies locally
        |
ALLOW: durable protected write
DENY: protected write is absent
```

The ADK hierarchy routes work; it does not confer authority. In the dual-root
profile, the receiver accepts the final worker only when the hybrid-signed
authority chain follows its configured route and a separate admission chain
recognizes the same worker key under the receiving organization's root.
Replacing the broker, leaf, root, operation, resource, constraint, challenge,
or session binding fails closed.

## Architectural decisions

| Decision | Reference choice | Reason |
| --- | --- | --- |
| Enforcement point | Receiver immediately before the consequential handler | A compromised model or sender cannot bypass a check it does not operate |
| ADK integration | Public `FunctionTool` plus `before_tool_callback` | Supported ADK surface; authorization occurs after tool selection and before dispatch |
| MCP carrier | Request `_meta` key `com.ratifyprotocol/authority` | Proof is not a model-selected business argument and MCP preserves extension metadata |
| A2A carrier | A registered or mutually agreed A2A extension with identical semantics | A2A already has an extension mechanism; this reference does not invent a parallel envelope |
| Trust-domain admission | Separate authority and workload-admission roots, both receiver-pinned | Authority without local workload admission is not executable, and admission without an operation mandate is insufficient |
| Workload identity | Google Agent Identity or IAM authenticates the workload; deployment binds that identity to the Ratify leaf key | Workload identity and delegated authority answer different questions |
| Ephemeral workers | Pre-provisioned Google workload identity, short-lived Ratify leaf authority | Avoids creating a Google Agent Identity resource for every transient task |
| Replay defense | Receiver-issued operation-bound challenge with atomic consume | Two replicas must not both accept one presentation |
| Revocation | Signed/distributed snapshots with a receiver freshness budget; stale or unavailable state denies | Revocation semantics must be explicit under partition |
| Caching | Cache immutable certificate validation only within expiry and revocation epoch; never cache the per-call challenge, payload binding, or final allow | Maintains per-operation freshness and constraints |
| Scale unit | Completed protected calls, each with a unique challenge and full decision | Avoids relabeling proof rechecks or cached allows as authorized calls |
| Hosted dependency | None on the verification critical path | One million agent calls do not imply one million calls to Ratify infrastructure |

The native `McpToolset` adapter remains an explicitly experimental lane because
ADK 2.6.3 does not expose a public operation-specific custom-MCP-metadata hook
on `McpTool`. The Google-facing recommendation is to validate whether ADK should
offer that hook. The executable supported lane does not depend on private
`McpTool` fields or methods.

## Exact call path

For every measured call:

1. The receiver validates canonical business arguments.
2. It reconstructs the operation, payload digest, receiver identity, workspace,
   expected leaf agent, invocation, and resource.
3. It issues a fresh challenge and stores it as pending.
4. The leaf signs the challenge and session context and presents the full
   authority chain plus the independent workload-admission chain.
5. The receiver checks its federation route before accepting the chain.
6. Ratify verifies hybrid signatures, linkage, expiry, revocation, effective
   scope, resource, node-count constraint, challenge signature, and binding.
7. The challenge is atomically consumed even when a cryptographically valid
   presentation is later denied by authorization policy.
8. Only an allow reaches the receiver-owned protected provisioner.

Malformed or forged presentations do not consume an honest pending challenge.
A cryptographically valid denial terminates its attempt so the same business
request identifier can be retried with a new challenge. This distinction is
tested because conflating the two states creates either denial-of-service or
replay defects.

## Scale architecture

The local reference intentionally uses one process. A production data plane is
the same decision split into horizontally scalable components:

```text
Global or organizational control plane
  trust-bundle publication
  key lifecycle and external identity binding
  signed revocation publication
  policy/profile version distribution
  audit export and retention

Regional receiver data plane
  workload transport authentication
  local trust and revocation snapshot
  stateless verifier workers
  shared atomic challenge store
  receiver-owned policy and resource reconstruction
  protected service with idempotency key
```

The shared challenge store is the only mandatory synchronization point for a
single-use challenge across replicas. Its consume operation must be an atomic
compare-and-delete. Trust bundles and revocation snapshots are read-mostly and
distributed out of band. Verification workers can scale horizontally without a
central Ratify decision service.

At very high rates, the receiver may cache verified certificate-chain facts
keyed by the chain digest, policy version, trust-bundle version, and revocation
epoch. It must still verify the fresh leaf challenge signature, reconstruct the
operation, evaluate dynamic constraints, and atomically consume the challenge
for each call. The current executable benchmark does not implement or claim
this optimization.

## Reproducible measurements

Run the exact-call benchmark from this directory after installing the pinned
requirements:

```bash
python -m authority_reference.scale_benchmark \
  --calls 10,100,1000,1000000 \
  --workers 8 \
  --output evidence/federation-scale-local-rerun.json
```

The benchmark stores one eight-byte latency sample per call and uses additional
working memory while calculating percentiles. It does not reuse a proof or
final verdict. Use a separate output filename for reruns so the canonical
checked-in result is not overwritten accidentally.
Every allowed call must equal one protected-action invocation; denied calls are
included to measure discrimination and fail-closed behavior.

The checked-in local evidence records the 10, 100, 1,000, and 1,000,000 call
tiers. On the recorded 10-core Apple Silicon host with eight workers, the
1,000,000-call tier completed with 900,000 allows, 100,000 deterministic
constraint denials, and 900,000 protected actions at 369.693 calls per second.
The dual-root encoded proof was 56,244 bytes. These are single-host Python
measurements, not Google capacity claims; extrapolation to a Google deployment
remains labeled as extrapolation. The aggregate 369.693 calls per second is
approximately 154 receiver decisions per second per logical core on this host;
the aggregate ceiling is a property of this single-process Python reference.

The benchmark includes challenge issuance, leaf signing, full hybrid-chain
verification, constraints, revocation lookup, challenge consumption, and the
in-memory protected action. It excludes Gemini latency, ADK reasoning, MCP HTTP,
external revocation delivery, multi-host storage, and Google Cloud service
latency. Those require separate transport and deployed load tests.

## Evidence and acceptance matrix

| Gate | Evidence in this reference | Status |
| --- | --- | --- |
| Public ADK hook | Real runner uses `before_tool_callback` and `FunctionTool` | Executed |
| Proof hidden from model | Ordinary schema; captured proof is in MCP `_meta` and absent from serialized ADK events | Executed |
| Real ADK multi-agent route | Coordinator to broker to worker nested-agent run | Executed |
| Cross-domain chain | Dual-root authority plus workload-admission chains and receiver-owned exact route | Executed |
| Runtime narrowing | Broker-issued shorter-lived worker certificate; widened region or node ceiling denied | Executed |
| Independent MCP receiver | Separate process owns trust and protected action | Executed |
| Durable consequence | SQLite row exists only for allow | Executed locally |
| Mid-task revocation | Revocation after challenge issuance prevents action | Executed |
| Revocation partition | Stale snapshot returns a fail-closed denial code | Executed |
| Replay and races | Replay, altered payload, duplicate request ID, and concurrent challenge tests | Executed |
| 10, 100, 1,000 calls | Exact full-path local benchmark | Measured |
| 1,000,000 calls | Same exact harness and command | Measured locally |
| Multi-host shared store | Required interface and atomicity defined | Not deployed here |
| Vertex AI Agent Engine | Composition described | Not deployed here |
| Google Agent Identity | Upstream binding described | Not exercised here |
| A2A extension preservation | Required interoperability question identified | Not exercised here |

## Agent Relay provenance and the new evidence

The cross-company precedent is the published Agent Relay design partnership:

- Ratify harness: <https://github.com/identities-ai/ratify-agent-relay-harness>
- Agent Relay evidence: <https://github.com/AgentWorkforce/ratify-agent-relay-evidence>
- Ratify technical note: <https://ratifyprotocol.com/writing/agent-relay-phase2-technical-note>
- Agent Relay account: <https://agentrelay.com/blog/someone-elses-agent-in-your-repo>

That work demonstrated narrowing and revocation across two independently
operated company deployments and exposed why the consequential write must be
gated. It is evidence for the cross-domain semantics, not evidence for Google
ADK compatibility or Google-scale throughput. This reference adds the public
ADK callback path, MCP metadata carrier, executable ADK multi-agent topology,
receiver route policy, local durable action, and reproducible exact-call scale
harness.

## Failure policy

| Condition | Receiver behavior |
| --- | --- |
| Unknown root or unapproved route | Deny before protected action |
| Wrong agent or workload-to-key binding | Deny |
| Changed operation or resource | Deny |
| Expired, revoked, excessive, or out-of-scope authority | Deny |
| Replay or challenge-store uncertainty | Deny |
| Stale or unavailable revocation snapshot | Deny |
| Policy/profile version unknown | Deny |
| Protected action fails after authorization | Return execution failure; do not report allow |
| Audit export fails | Decision policy is deployment-specific; local verification result must remain observable |

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
5. Which receiver deployments need shared challenge state across regions, and
   what replay window and partition policy are acceptable?
6. Which proof-size, latency, and throughput envelopes should gate a joint
   evaluation on Google infrastructure?

These are integration questions, not requests for Google to adopt Ratify's
trust policy. The receiving service remains responsible for deciding which
roots, routes, profiles, resources, and freshness budgets it accepts.
