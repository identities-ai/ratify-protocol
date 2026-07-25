# {{TITLE}}

**{{SDK_DESC}} of the Ratify Protocol v1 — delegated-authority proofs for human-agent and agent-agent interactions.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the {{SIBLINGS}} reference implementations. Validated against the **63 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1 — practical for live voice and video) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)
