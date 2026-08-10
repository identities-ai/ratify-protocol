# Receiver-Verifiable Delegated Authority: An Executable Interoperability Profile for ODIS

A proposed open reference from Ratify Protocol, an NVIDIA Inception member.

## Proposal

Ratify Protocol proposes an open reference for evaluation against NVIDIA's ODIS
direction, showing how an agent carries a
principal-signed, resource-bound delegation to an independent action boundary. The
receiver verifies who authorized the agent, what it may do, and whether the
request stays within those limits before it acts.

The reference does not claim ODIS conformance. It makes one trust-boundary choice
executable so NVIDIA engineers can determine whether it is compatible with the
ODIS delegation contract.

## Request

We are asking NVIDIA to:

1. Connect us with the appropriate technical owner for Secure Agent Workspace and
   the ODIS delegation contract.
2. Convene one 45-minute architecture-mapping session with that owner and the
   relevant NOOA and OpenShell engineers.
3. Give the work a disposition: useful as an interoperability, conformance, or
   threat-model artifact; relevant elsewhere; or redundant with planned ODIS work.

The implementation and its validation are complete. What remains is placement.

## The authorization question

NVIDIA's Secure Agent Workspace design describes ODIS as covering identity,
delegation, scoped authority, revocation, and audit context. Ratify does not claim
that delegation is missing. It offers a running profile that makes one
trust-boundary choice testable when an agent crosses a tool, service, or
organizational boundary:

**Should ODIS-style authority also be independently verifiable by the receiver
when an agent crosses an organizational boundary?**

Runtime enforcement can present ordinary service credentials downstream. This
profile tests the complementary case: the receiver bears the consequence, does
not trust the originating runtime, and verifies the principal's bounded authority
itself. A principal authorizes refunds up to $100, for 24 hours, for one tenant
and one order; a receiving service elsewhere verifies those bounds before acting.

## How the layers compose

| Layer | Question |
|---|---|
| NOOA | Where is the agent invocation presented? |
| OpenShell | Which destination, MCP method, and tool may the runtime reach? |
| ODIS | How are identity and delegation contracts made interoperable? |
| Ratify profile | How can receiver-verifiable authority be made executable and tested? |
| Receiver | Does the verified authority and local policy permit this action? |

OpenShell and Ratify are independent and conjunctive. OpenShell does not evaluate
refund amount, tenant, order, expiry, revocation, or delegation semantics. Ratify
does not replace runtime isolation or destination and tool policy.

The agent never authorizes itself. It presents the proof; the independent receiver
verifies and decides. The agent's own process contains no authorization logic, and
a test asserts its absence.

## Working reference

The reference implements principal-signed delegated authority; alpha.16
`resource_path` constraints over tenant-qualified resources; MCP Streamable HTTP
proof carriage in `_meta`; a NOOA `agent_call` middleware seam using released
public APIs; OpenShell MCP destination and tool enforcement; and receiver-side
verification with signed decision receipts. Expiry, revocation, replay,
wrong-key, wrong-resource, excessive-amount and subdelegation-denial cases are all
exercised, alongside post-quantum proof-size and parser-differential tests.

Two results are worth stating precisely. The receiver measures each inbound
proof's SHA-256 and length, so byte-identical carriage across the boundary is
measured rather than asserted. And a maximum-depth alpha.16 chain, eight
certificates and 88,990 bytes, crosses inline in `_meta` and authorizes.

Validation is **181 Python tests**: 54 receiver-security, 39 MCP transport, 84
adjudicator, 4 mandatory NOOA integration tests. Zero skips, and no LLM, API key,
or paid service anywhere in the suite. Verified against the **published**
`ratify-protocol==1.0.0a16` package, not a local checkout: the gate asserts the
module resolves from the installed package before it will report success.

The live OpenShell profile executes **52 cases judged by 64 gates**, passing twice
sequentially and twice concurrently, with zero skips, zero driver errors, and no
unexplained events. The full NOOA to MCP to OpenShell to receiver to Ratify path
runs inside the OpenShell-governed sandbox in a single execution.

## Why it matters

A service that cannot verify an agent's authority has two choices: refuse the
action, or accept unbounded liability. Most refuse, which limits agent deployment
at exactly the boundaries where autonomous systems start being useful.

Ratify contributes an open, portable implementation and adversarial test profile
for delegated authority crossing an independent action boundary. It separates
which workload is calling, what the runtime permits, and what a principal actually
authorized. That gives NVIDIA engineers a concrete artifact to map against ODIS
and either adopt, revise, place elsewhere, or identify as redundant.

## Next step

We would value one 45-minute architecture-mapping session covering the NOOA
presentation seam, OpenShell MCP policy composition, receiver-side authority
verification, and ODIS compatibility. The desired outcome is a disposition:
interoperability, conformance, or threat-model artifact; relevant elsewhere; or
redundant with planned ODIS work.

## Disclosure

Published by Identities.AI, Inc., a member of NVIDIA Inception. An independent
proposal: not an NVIDIA partnership, an approved integration, an NVIDIA reference
architecture, or an Open Secure AI Alliance membership artifact. No NVIDIA
repository is modified.

Every result above comes from executions recorded in the profile's own artifact,
on the single platform recorded there: arm64 macOS with Docker. linux/amd64 and
Podman are compatibility targets, not results. Full evidence:
[`docs/evidence/nvidia-reference-evidence.md`](evidence/nvidia-reference-evidence.md).

- https://github.com/identities-ai/ratify-protocol
- https://ratifyprotocol.com
