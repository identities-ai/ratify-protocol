# Where agent identity meets delegated authority

This is a discussion note for A2A and AGNTCY maintainers, not a proposed standard or claim of integration. The [runnable draft](README.md) uses an A2A 1.0 Agent Card and two structured messages: the receiver issues a challenge for an exact operation, then checks a signed proof before its protected provisioner runs.

| Layer | Question it answers | Current draft |
| --- | --- | --- |
| AGNTCY identity or another identity system | Which agent is this, and which key or credential identifies it? | The receiver pins an expected agent ID. It does not resolve an AGNTCY ID, Badge, or credential. |
| A2A | How do agents discover capabilities and exchange the operation and proof? | A provisional required extension URI is advertised in the Agent Card; the operation travels in a `DataPart` and the proof in message metadata. |
| Ratify | Did a recognized principal delegate this exact action to that agent under these bounds? | The receiver checks a trusted-root chain, challenge signature, operation binding, node ceiling, and replay state before acting. |

The integration seam to test is a receiver policy that resolves an AGNTCY identity and binds its authenticated key to the presenter in the Ratify delegation. The two checks should be independently visible: a valid agent identity must not authorize an excessive action, and a valid mandate must not bypass caller admission. This draft tests the latter authority boundary with a locally pinned presenter; it does not implement the identity binding.

Questions for maintainers:

1. Which AGNTCY identifier and proof should the receiver bind to the delegated agent key, and at what point in an A2A request?
2. Should the challenge and proof stay in separate A2A messages, use an existing in-task authorization flow, or use another carrier?
3. Which A2A task or context identifiers should enter the signed operation context, and who defines their canonical form?
4. Does this belong in an existing extension profile or merit a separate experimental extension after the overlap is understood?

The current draft has no transport authentication, AGNTCY integration, durable task state, or multi-replica replay store. See [limitations and evidence](README.md#evidence-security-status-and-limitations).

Sources: [AGNTCY identity introduction](https://spec.identity.agntcy.org/docs/intro/), [A2A extension model](https://a2a-protocol.org/latest/topics/extensions/).
