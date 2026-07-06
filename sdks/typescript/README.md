# @identities-ai/ratify-protocol

**TypeScript reference SDK for the Ratify Protocol v1 — a cryptographic trust protocol for human-agent and agent-agent interactions as agents start to transact.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the Go, Python, Rust, and C/C++ reference implementations. Validated against the **63 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), the SessionToken fast path (~95% less per-turn crypto — practical for live voice and video), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec, all covered by the 63 canonical fixtures.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Install

```bash
npm install @identities-ai/ratify-protocol@1.0.0-alpha.10
```

## Three verbs, three examples

### 1. DELEGATE — a human authorizes an agent

```ts
import {
  generateHumanRoot,
  generateAgent,
  issueDelegation,
  PROTOCOL_VERSION,
  SCOPE_MEETING_ATTEND,
  SCOPE_MEETING_SPEAK,
  type DelegationCert,
} from "@identities-ai/ratify-protocol";

// Alice creates her root (once, ever)
const { root, privateKey: alicePriv } = await generateHumanRoot();

// Her agent has its own keypair
const { agent, privateKey: agentPrivateKey } = await generateAgent("Alice's Scheduler", "custom");

// Alice signs a delegation
const cert: DelegationCert = {
  cert_id: crypto.randomUUID(),
  version: PROTOCOL_VERSION,
  issuer_id: root.id,
  issuer_pub_key: root.public_key,
  subject_id: agent.id,
  subject_pub_key: agent.public_key,
  scope: [SCOPE_MEETING_ATTEND, SCOPE_MEETING_SPEAK],
  issued_at: Math.floor(Date.now() / 1000),
  expires_at: Math.floor(Date.now() / 1000) + 7 * 24 * 3600, // 7 days
  constraints: [],
  signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) }, // filled in by issueDelegation
};
await issueDelegation(cert, alicePriv);
```

### 2. PRESENT — an agent builds a proof bundle

```ts
import {
  signChallenge,
  generateChallenge,
  type ProofBundle,
} from "@identities-ai/ratify-protocol";

// Challenge comes from the verifier, over the wire
const challenge = /* received from verifier */ new Uint8Array(32);
const challengeAt = Math.floor(Date.now() / 1000);

const bundle: ProofBundle = {
  agent_id: agent.id,
  agent_pub_key: agent.public_key,
  delegations: [cert],
  challenge,
  challenge_at: challengeAt,
  challenge_sig: await signChallenge(challenge, challengeAt, agentPrivateKey),
};

// Send bundle (as canonical JSON) over HTTP / your transport
```

### 3. VERIFY — any third party checks the proof

```ts
import { verifyBundle, SCOPE_MEETING_ATTEND } from "@identities-ai/ratify-protocol";

const result = await verifyBundle(bundle, {
  required_scope: SCOPE_MEETING_ATTEND,
});

if (!result.valid) {
  console.log("rejected:", result.identity_status, result.error_reason);
} else {
  console.log("authorized agent:", result.agent_id, "for", result.human_id);
  console.log("effective scope:", result.granted_scope);
}
```

## Key custody

The protocol supports three key-custody modes with different trust tradeoffs. See [SPEC.md §15.2](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full model.

### Self-custody (strongest)

The user generates and holds their own keypair. No third party can sign on their behalf.

```ts
import { generateHumanRoot, issueDelegation } from "@identities-ai/ratify-protocol";

// User generates keypair on their own device — private key never leaves
const { root, privateKey } = await generateHumanRoot();

// User signs delegations locally
const cert = { /* ... */ };
await issueDelegation(cert, privateKey);

// Only the public root.id and root.public_key are shared with registries
```

### Custodial

A registry operator generates and stores the keypair server-side (envelope-encrypted with KMS). The user never touches keys directly. The operator calls the same SDK functions on the user's behalf.

### Self-custody upgrade

A user who started in custodial mode can migrate to self-custody at any time using `KeyRotationStatement`:

```ts
import {
  generateHumanRoot,
  issueKeyRotationStatement,
} from "@identities-ai/ratify-protocol";

// User generates a NEW keypair on their device
const { root: newRoot, privateKey: newPrivateKey } = await generateHumanRoot();

// Rotation statement signed by BOTH old (custodial) and new (device) keys
const stmt = {
  version: 1,
  old_id: oldRoot.id,
  old_pub_key: oldRoot.public_key,
  new_id: newRoot.id,
  new_pub_key: newRoot.public_key,
  rotated_at: Math.floor(Date.now() / 1000),
  reason: "routine" as const,
  signature_old: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  signature_new: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
};
await issueKeyRotationStatement(stmt, oldCustodialPrivateKey, newPrivateKey);

// From now on, only the user's device key can sign delegations.
// Auditors verify continuity via the rotation statement.
```

## Canonical serialization

Signed payloads follow Ratify's canonical JSON rules (see [SPEC.md §6.3.1](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)). The SDK exposes:

```ts
import { canonicalJSON, delegationSignBytes, challengeSignBytes } from "@identities-ai/ratify-protocol";
```

These produce byte-identical output to the Go reference implementation. The `test/conformance.test.ts` suite runs the 63 published test vectors through the TS code and asserts byte-for-byte equivalence.

## Scope vocabulary

```ts
import {
  SCOPE_MEETING_ATTEND,     // "meeting:attend"
  SCOPE_FILES_WRITE,         // sensitive — never rides a wildcard
  expandScopes,
  intersectScopes,
  isSensitive,
  validateScopes,
} from "@identities-ai/ratify-protocol";

expandScopes(["meeting:*"]);
// ["meeting:attend", "meeting:chat", "meeting:share_screen", "meeting:speak", "meeting:video"]

intersectScopes(["meeting:*"], ["meeting:attend", "meeting:speak"]);
// ["meeting:attend", "meeting:speak"]
```

Ratify v1 ships 54 canonical scopes across fourteen domains, plus a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

For app-specific needs not covered by the canonical vocabulary, use the `custom:` prefix:

```ts
import { CUSTOM_SCOPE_PREFIX, validateScopes } from "@identities-ai/ratify-protocol";

validateScopes(["custom:acme:inventory:read"]); // → null (valid)
```

Custom scopes pass through `expandScopes` unchanged and are non-sensitive by default.

## Running the conformance tests

From this SDK directory:

```bash
npm install
npm test
```

The conformance suite loads every fixture from the [canonical test vectors](https://github.com/identities-ai/ratify-protocol/tree/main/testvectors/v1) and runs it through the TypeScript implementation. It checks:

- Canonical signing bytes match the committed hex for every cert
- Challenge signing bytes match
- `verifyBundle` produces the same `VerifyResult` as the Go reference
- Scope expansion is deterministic and matches
- Revocation list signatures verify

A single failure means TypeScript and the Go reference have drifted.

## Security posture

- **Ed25519** via [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) — audited, zero native deps, universal.
- **ML-DSA-65** via [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) — NIST FIPS 204, post-quantum lattice signature.
- **SHA-256** via [@noble/hashes](https://github.com/paulmillr/noble-hashes) — same author, same posture.
- **WebCrypto** for secure random (32-byte challenges).

No network code in this package. HTTP concerns (challenge issuance, revocation list fetching, API auth) live one layer up.

## License

Apache-2.0
