# {{TITLE}}

**{{SDK_DESC}} of the Ratify Protocol: delegated-authority proofs for human-agent and agent-agent interactions.**

Hybrid signatures: every signature is Ed25519 plus ML-DSA-65 (NIST FIPS 204), and both must verify, so a forger has to break both algorithms.

Byte-identical interoperability with the {{SIBLINGS}} reference implementations. Validated against the **79 canonical test vectors** (Protocol v1) on every CI run. {{PROTOCOL_LINES}}

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof without calling back to whoever issued it. In Protocol v2 the verifier then **releases** the decision: it is actionable only after the verifier's signed receipt has been acknowledged by an independent checkpoint.

For Protocol v1, beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec. Protocol v2 has its own session and stream binding, signed status, receipts, witness entries and key rotation; the SessionToken fast path, A2A mutual presentation, the HTTP and registry bindings, and the geo and speed constraints remain v1-only until Protocol 2.1.

- Protocol v1 spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Protocol v2 spec: [SPEC-v2.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC-v2.md), upgrade guide: [docs/PROTOCOL_V2_MIGRATION.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md)
- Runnable v2 examples in every SDK language: [examples/v2](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.ratifyprotocol.com](https://docs.ratifyprotocol.com)
