# Comparing task authorization work

This is a discussion note for A2A and AGNTCY maintainers, not a proposed standard or claim of integration. The [runnable draft](README.md) uses an A2A 1.0 Agent Card and two structured messages: the receiver issues a challenge for an exact operation, then checks a signed proof before its protected provisioner runs.

AGNTCY's [A2A and task-based access-control analysis](https://blogs.agntcy.org/technical/identity/2026/08/25/agent-identity-tbac-a2a-task-authorization.html) describes more than agent identification. Its existing TBAC rules decide which named tools an Agentic Service may call, with allow, deny, and approval outcomes re-evaluated at invocation. The article also describes a task authorization profile under development: an authorization object bound to the agent, A2A task ID, action, resource, delegation limits, proof of possession, and lifetime. **That proposed profile substantially overlaps Ratify's delegated-authority model.** The formats and enforcement boundaries need comparison before proposing another A2A extension.

| Work | Current status | Relationship to this draft |
| --- | --- | --- |
| AGNTCY Identity | Released identifiers, ResolverMetadata, and Agent Badges establish agent provenance. | The draft pins an expected agent ID; it does not verify an AGNTCY identity or badge. |
| AGNTCY TBAC | Existing per-tool policy can allow, deny, or require approval and re-evaluates at invocation. | The draft uses its receiver's local policy and signed one-node limit; it does not call TBAC. |
| AGNTCY task authorization profile | In development, including task binding, delegated constraints, and proof of possession. | This is the closest overlap. Ratify's draft verifies an exact action and signed limit, but does not bind an A2A `taskId` or implement approval propagation. |
| A2A | Defines task states and the extension carrier; authorization scope remains implementation-specific. | The draft advertises a provisional URI, carries the operation in a `DataPart` and proof in metadata, and returns an immediate response. |

The immediate experiment to discuss is whether an AGNTCY-identified agent can present a Ratify mandate at the receiving action, with both the existing TBAC rule and the signed operation limits enforced. That may be an integration of complementary controls, or it may expose redundant authority objects. The present draft does not establish which design is preferable.

Questions for maintainers:

1. Where is the current task authorization profile draft, and which of its authorization object fields and validation rules are already agreed?
2. Could Ratify's signed delegation and receiver-side operation check serve as one implementation or proof format within that profile, or would it conflict with its trust model?
3. How should the A2A `taskId`, approver identity, invocation, and actual receiver operation be bound so a declared operation cannot widen authority?
4. Should the proof ride an existing in-task authorization flow or extension, and which receiver checks remain independent of A2A and TBAC?

The current draft has no transport authentication, AGNTCY integration, durable task state, or multi-replica replay store. See [limitations and evidence](README.md#evidence-security-status-and-limitations).

Sources: [AGNTCY A2A and TBAC analysis](https://blogs.agntcy.org/technical/identity/2026/08/25/agent-identity-tbac-a2a-task-authorization.html), [AGNTCY identity introduction](https://spec.identity.agntcy.org/docs/intro/), [A2A extension model](https://a2a-protocol.org/latest/topics/extensions/).
