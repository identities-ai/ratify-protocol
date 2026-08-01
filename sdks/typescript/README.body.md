## Install

```bash
npm install @identities-ai/ratify-protocol@{{VERSION}}
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

Signed payloads follow Ratify's canonical JSON rules (see [SPEC.md §6](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)). The SDK exposes:

```ts
import { canonicalJSON, delegationSignBytes, challengeSignBytes } from "@identities-ai/ratify-protocol";
```

These produce byte-identical output to the Go reference implementation. The `test/conformance.test.ts` suite runs the 79 published test vectors through the TS code and asserts byte-for-byte equivalence.

## Wire transport

Signed Ratify structures travel as canonical JSON. The wire codec turns typed structures into those bytes and back, so integrators never hand-roll the base64 and byte-length handling.

### Sending a proof bundle

```ts
import { encodeProofBundle } from "@identities-ai/ratify-protocol";

const body = encodeProofBundle(bundle); // canonical JSON string
await fetch("https://verifier.example.com/verify", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body,
});
```

### Receiving a proof bundle

```ts
import { decodeProofBundle, verifyBundle, SCOPE_MEETING_ATTEND } from "@identities-ai/ratify-protocol";

const bundle = decodeProofBundle(requestBody); // string or Uint8Array
const result = await verifyBundle(bundle, { required_scope: SCOPE_MEETING_ATTEND });
```

### Session tokens

`SessionToken`s cross the wire the same way (`DelegationCert`s too, via `encodeDelegationCert` / `decodeDelegationCert`):

```ts
import { encodeSessionToken, decodeSessionToken } from "@identities-ai/ratify-protocol";

// Verifier issues the token after the first full verify and sends it out:
const tokenJSON = encodeSessionToken(token);

// The agent presents it on later turns; the verifier decodes and checks it:
const presented = decodeSessionToken(tokenJSON);
```

### Strict decoding

Decoders fail closed. A document is rejected — with an error naming the offending field — if it carries malformed UTF-8 or a byte-order mark; malformed or non-canonical base64; a wrong byte length for a key, signature, challenge, or 32-byte binding field; a missing or mistyped required field; an integer outside the IEEE-754 safe-integer range [-(2^53-1), 2^53-1] (SPEC §6.2); an empty delegation chain; unpaired stream fields; duplicated JSON object keys (at any nesting depth, with string escapes decoded before comparison); or an unknown field in a signed structure. Anything a conformant implementation would not have produced is treated as malformed at the transport boundary instead of surfacing later as a confusing verification failure.

The strictness applies to the signed structures themselves — `ProofBundle`, `DelegationCert`, `SessionToken` reject unknown fields because every byte of them is protocol surface. Your application's transport envelope is a different thing: it may carry whatever integration metadata you need, as long as that metadata stays outside the signed structure. For example, `{"proof_bundle": {...}, "app_metadata": {...}}` is fine — decode `proof_bundle` strictly with `decodeProofBundle` and treat the rest of the envelope as your own; a `request_id` inside the bundle itself would (correctly) be rejected.

### Vocabulary discovery

Consoles and policy editors that present scope choices should derive them from the protocol rather than hardcoding strings, so UI vocabularies cannot drift:

```ts
import { vocabulary, scopeWildcards } from "@identities-ai/ratify-protocol";

vocabulary();     // all 54 canonical scopes, lex-sorted
scopeWildcards(); // wildcard shorthand -> non-sensitive member scopes
```

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

Ratify v1 ships 54 canonical scopes plus 14 wildcards and a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

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

## API added on main (ships in alpha.16, release unpublished)

The following surface is merged to `main` and ships in alpha.16. The tag is not yet published; install from `main` to use it ahead of the release.

- **Resource-bound verification.** The `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via a constraint's `resource_id` and optional `path_prefix`. At verify time the application supplies `requested_resource_id`, `requested_path`, and `has_resource` on `VerifierContext` (SPEC §5.16); `verifyBundle(bundle, { context })` evaluates them. Helpers: `normalizeResourcePath`, `resourcePathMatches`, `validateResourceConstraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `operationContextBytes`, `operationContextHash`, `sessionContextBytes`, and `buildSessionContext`; `verifierContextHash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `encodeVerificationReceipt` and `decodeVerificationReceipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `verifyStreamedTurnWithOptions` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** A constraint's `params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `validateParamsValue`; `isCanonicalConstraintType` guards which types may carry them.
- **Deeper delegation chains.** `MAX_DELEGATION_CHAIN_DEPTH` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MAX_PROOF_BUNDLE_BYTES`, `MAX_SCOPES_PER_CERT`, `MAX_CONSTRAINTS_PER_CERT`, `MAX_SCOPE_LENGTH_BYTES`, `MAX_IDENTIFIER_LENGTH_BYTES`, `MAX_AGENT_NAME_LENGTH_BYTES`, `MAX_JSON_NESTING_DEPTH`.

## License

Apache-2.0
