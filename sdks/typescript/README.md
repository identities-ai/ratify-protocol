# @identitiesai/ratify-protocol

**TypeScript reference SDK for the Ratify Protocol v1 — cryptographic delegation for AI agents.**

This package lets you:

- Generate human and agent hybrid keypairs
- Issue signed delegation certs (human side)
- Build signed proof bundles (agent side)
- Verify proof bundles (verifier side)

See [`docs/EXPLAINED.md`](../../docs/EXPLAINED.md) and [`docs/AGENT_TO_AGENT.md`](../../docs/AGENT_TO_AGENT.md) in the repository for full protocol semantics.

Byte-for-byte interoperable with the Go reference implementation. Tested against the canonical test vectors at `../../testvectors/v1/`.

## Install

```bash
npm install @identitiesai/ratify-protocol
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
} from "@identitiesai/ratify-protocol";

// Alice creates her root (once, ever)
const { root, privateKey: alicePriv } = await generateHumanRoot();

// Her agent has its own keypair
const { agent } = await generateAgent("Alice's Scheduler", "custom");

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
  signature: new Uint8Array(), // filled in by issueDelegation
};
await issueDelegation(cert, alicePriv);
```

### 2. PRESENT — an agent builds a proof bundle

```ts
import {
  signChallenge,
  generateChallenge,
  type ProofBundle,
} from "@identitiesai/ratify-protocol";

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
import { verifyBundle, SCOPE_MEETING_ATTEND } from "@identitiesai/ratify-protocol";

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

The protocol supports three key-custody modes with different trust tradeoffs. See `SPEC.md` §15.2 for the full model.

### Self-custody (strongest)

The user generates and holds their own keypair. No third party can sign on their behalf.

```ts
import { generateHumanRoot, issueDelegation } from "@identitiesai/ratify-protocol";

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
} from "@identitiesai/ratify-protocol";

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
  signature_old: { ed25519: new Uint8Array(), ml_dsa_65: new Uint8Array() },
  signature_new: { ed25519: new Uint8Array(), ml_dsa_65: new Uint8Array() },
};
await issueKeyRotationStatement(stmt, oldCustodialPrivateKey, newPrivateKey);

// From now on, only the user's device key can sign delegations.
// Auditors verify continuity via the rotation statement.
```

## Canonical serialization

Signed payloads follow Ratify's canonical JSON rules (see `RATIFY_PROTOCOL.md` §6.3.1). The SDK exposes:

```ts
import { canonicalJSON, delegationSignBytes, challengeSignBytes } from "@identitiesai/ratify-protocol";
```

These produce byte-identical output to the Go reference implementation. The `test/conformance.test.ts` suite runs the 59 published test vectors through the TS code and asserts byte-for-byte equivalence.

## Scope vocabulary

```ts
import {
  SCOPE_MEETING_ATTEND,     // "meeting:attend"
  SCOPE_FILES_WRITE,         // sensitive — never rides a wildcard
  expandScopes,
  intersectScopes,
  isSensitive,
  validateScopes,
} from "@identitiesai/ratify-protocol";

expandScopes(["meeting:*"]);
// ["meeting:attend", "meeting:chat", "meeting:share_screen", "meeting:speak", "meeting:video"]

intersectScopes(["meeting:*"], ["meeting:attend", "meeting:speak"]);
// ["meeting:attend", "meeting:speak"]
```

### Full scope vocabulary at a glance

Ratify v1 ships 52 canonical scopes across fourteen domains, plus a `custom:` extension pattern for application-specific scopes. See [`SPEC.md`](../../SPEC.md) §9 for the full table including sensitivity flags and wildcard expansions.

For app-specific needs not covered by the canonical vocabulary, use the `custom:` prefix:

```ts
import { CUSTOM_SCOPE_PREFIX, validateScopes } from "@identitiesai/ratify-protocol";

validateScopes(["custom:acme:inventory:read"]); // → null (valid)
```

Custom scopes pass through `expandScopes` unchanged and are non-sensitive by default.

## Running the conformance tests

From this SDK directory:

```bash
npm install
npm run test:conformance
```

The conformance suite loads every fixture at `../../../../testvectors/v1/*.json` and runs it through the TS implementation. It checks:

- Canonical signing bytes match the committed hex for every cert
- Challenge signing bytes match
- `verifyBundle` produces the same `VerifyResult` as the Go reference
- Scope expansion is deterministic and matches
- Revocation list signatures verify

A single failure means TS and Go have drifted.

## Security posture

- **Ed25519** via [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) — audited, zero native deps, universal.
- **SHA-256** via [@noble/hashes](https://github.com/paulmillr/noble-hashes) — same author, same posture.
- **WebCrypto** for secure random (32-byte challenges).

No network code in this package. HTTP concerns (challenge issuance, revocation list fetching, API auth) live one layer up.

## License

Apache-2.0
