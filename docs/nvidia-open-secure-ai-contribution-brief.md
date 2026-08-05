# Proof-Carrying Delegated Authority for NVIDIA's Open Agent-Security Stack

**A proposed open reference from Ratify Protocol, an NVIDIA Inception member**

---

## The proposal

An open reference showing how an agent built on NVIDIA's open agent stack carries a principal-signed, bounded delegation to an independent action boundary, where the receiver verifies who authorized it, what was delegated, and whether the action stays in scope before executing. Built, adversarially tested, running today.

## What we are asking

> 1. **The right technical point person** for identity, permissions, and delegated authority in the Open Secure AI Alliance.
> 2. **One working session** with the NOOA and OpenShell engineers, to validate the integration seam and trust boundaries.
> 3. **Guidance on the upstream path,** if it proves useful.

## The authorization question

NVIDIA's stack provides orchestration, tracing, guardrails, and runtime isolation; workload identity establishes which service is calling. One question remains when an agent crosses an organizational boundary: **who authorized it to perform this action, and what limits did that principal set?**

**The receiver executes the action and bears the consequence, yet has the least evidence of anyone in the chain.** A principal intends *"refunds up to $100, for 24 hours."* By the time that reaches a payments service elsewhere it is an API key in a header, and the service learns only that some caller wants $150.

## How it composes

| Layer | Question it answers |
|---|---|
| **NOOA** | Agent harness; the seam where the proof is presented |
| **NeMo / guardrails** | Does this comply with enterprise policy? |
| **OpenShell** | What may this runtime reach, via which MCP method and tool? |
| **SPIFFE/SPIRE** | Which workload is calling? |
| **Ratify Protocol** | Who authorized this action, within what limits? |

OpenShell and Ratify are independent, and both must permit execution. OpenShell governs destination, MCP method, and tool name. Ratify governs principal, tenant and resource, amount, expiry, revocation, and the delegation chain. v0.0.96 cannot match tool arguments, so it never sees the amount or order id and is not asked to. Ratify does not replace isolation; OpenShell does not evaluate Ratify's constraints.

**NOOA presents the proof. The receiver verifies and decides. The agent never authorizes itself.** An agent-side check would be worthless as a control, since a compromised agent would not run it, so no verification lives in the agent process and that property is tested rather than asserted. The adapter uses only NOOA's public middleware API, no forks and no private hooks, mirroring `nemo_flow_middleware.py`.

## What is working today

A principal authorizes refunds up to $100 for a limited period; a NOOA agent calls a refund service at another party. A $75 refund is authorized. Denied, reason attested: $150 against the $100 ceiling; an expired or revoked delegation, or an unreachable revocation source, failing closed; a stolen certificate presented by another key; a replayed proof; a subdelegation claiming more than the parent held; another tenant's order of the same number. An amount restated at execution time is ignored: the receiver's own parse stands.

Every **authenticated authorization decision** produces a verifier-signed receipt bound by hash to the proof presented. Traffic refused before proof of possession produces a bounded unsigned log entry, so an unauthenticated caller cannot write to the audit trail.

**129 deterministic tests: 125 hermetic plus 4 mandatory NOOA integration tests** against the real released `nooa==0.0.8` middleware API, zero skips in the required environment. No LLM, no API key, no paid service. Verified against Ratify Protocol v1.0.0-alpha.16, whose resource-bound authority scopes a refund to one tenant-qualified order.

## The composition, executed

Two seams are independently verified, and the composition of both has executed:

> NOOA agent → proof-carrying MCP Streamable HTTP → OpenShell destination, method, and tool enforcement → an independent MCP receiver → Ratify principal-issued semantic authorization → consequential action → signed receipt

**Status, stated precisely.** The MCP-through-OpenShell seam and the fourteen Ratify semantic denials are stable and repeatable. A single execution containing *every* layer above, with `nooa==0.0.8` running inside the OpenShell-governed sandbox on its own generated key, has passed and is asserted by a dedicated gate; that group is not yet reliably repeatable, because consecutive NOOA imports exhaust the sandbox. The constraint is characterised and the remedy known. Treat the unified path as demonstrated, not yet as a stable gate.

One command brings up the gateway on dynamic ports from immutable digests, renders the policy, drives **48 cases in seven isolated groups** inside an OpenShell sandbox, and writes a machine-readable artifact. **54 gates, all passing, twice sequentially and twice concurrently.** Each case declares its expected outcome and is judged against before-and-after snapshots of the receiver's counters, pulled from a control endpoint the sandbox cannot reach. A case that did not run fails rather than vanishing.

The proof travels in MCP `_meta` under `ai.identities.ratify/proof`, and the receiver measures its inbound SHA-256 and length, so byte-identical carriage across the boundary is measured, not asserted. A maximum-depth alpha.16 chain, eight certificates and 88,990 bytes, crosses inline and authorizes. Three size limits are demonstrated separately: the MCP body limit, OpenShell's 256 KiB envelope limit, and the receiver's decoded-proof limit.

Fifteen parser-differential probes test one invariant: **a request admitted by OpenShell as one method and tool must never be dispatched by the MCP server as another.** Duplicate JSON members in both orders, and header-versus-body disagreement both ways, produced no violation on the pinned versions. Per-run canaries were searched across five component log sources with no hits, harness output classified separately so it cannot flatter the result.

## Why this is worth NVIDIA's time

A service that cannot verify the caller's authority can only refuse or accept unbounded liability. Most refuse, capping agent workloads at what someone will underwrite, and the cap tightens when the agent belongs to another organization.

It fills a slot the Alliance already named, separating three routinely conflated things: which workload is calling, what local policy permits, and what a principal authorized. SPIFFE answers the first; this answers the third. Apache-2.0 on both sides, no NVIDIA repository modified, no dependency created. An engineer can run the hermetic suite in five minutes and say "wrong seam".

## Next step

One technical working session on the architecture, the NOOA seam, and trust boundaries. Feedback can be incorporated within days: the implementation exists, so the work ahead is validation and placement, not construction. SPIFFE binding and Jetson or IGX boundaries are in the appendix.

## Disclosure

<https://github.com/identities-ai/ratify-protocol> · <https://docs.identities.ai> · Appendix: `docs/nvidia-open-secure-ai-reference-proposal.md`

Published by Identities.AI, Inc., a member of NVIDIA Inception. An independent proposal: not an NVIDIA partnership, approved integration, reference architecture, or Alliance membership artifact. Every result above comes from executions recorded in the profile's artifact, on the one architecture recorded there.
