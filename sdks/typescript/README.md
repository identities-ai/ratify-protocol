<!-- GENERATED FILE — do not edit directly.
     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.
     Regenerate: python3 scripts/gen-sdk-readmes.py -->
# @identities-ai/ratify-protocol

**TypeScript reference SDK of the Ratify Protocol: delegated-authority proofs for human-agent and agent-agent interactions.**

Hybrid signatures: every signature is Ed25519 plus ML-DSA-65 (NIST FIPS 204), and both must verify, so a forger has to break both algorithms.

Byte-identical interoperability with the Go, Python, Rust, and C/C++ reference implementations. Validated against the **79 canonical test vectors** (Protocol v1) on every CI run. This package also implements Protocol v2 (version `2.0.0-beta.1`, a prerelease) and runs every file in the shared `testvectors/v2` corpus and the cross-SDK fixtures of every other SDK.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof without calling back to whoever issued it. In Protocol v2 the verifier then **releases** the decision: it is actionable only after the verifier's signed receipt has been acknowledged by an independent checkpoint.

For Protocol v1, beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec. Protocol v2 has its own session and stream binding, signed status, receipts, witness entries and key rotation; the SessionToken fast path, A2A mutual presentation, the HTTP and registry bindings, and the geo and speed constraints remain v1-only until Protocol 2.1.

- Protocol v1 spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Protocol v2 spec: [SPEC-v2.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC-v2.md), upgrade guide: [docs/PROTOCOL_V2_MIGRATION.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md)
- Runnable v2 examples in every SDK language: [examples/v2](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.ratifyprotocol.com](https://docs.ratifyprotocol.com)

## Install

```bash
npm install @identities-ai/ratify-protocol@2.0.0-beta.1
```

Version `2.0.0-beta.1` is a Protocol v2 prerelease. It is published under the
npm dist-tag `next`, so pin it exactly (or install `@next`); an unpinned
install resolves to the latest v1 release until `2.0.0`. The v2 API is at
`@identities-ai/ratify-protocol/v2`, and the v1 API stays at the package
root. To keep the exact v1 release next to it, use an alias:
`npm install ratify-v1@npm:@identities-ai/ratify-protocol@1.0.0-alpha.20`.

### Bundle size

The package declares `"sideEffects": false`, so a bundler drops every module
an application does not import: a v1-only import from the package root does
not pull in the v2 tree. Measured with esbuild 0.28.2 (browser platform,
minified, `gzip -9`) on 2026-10-22:

| Import | Minified | Gzip |
|---|---|---|
| The v1 flow above (`generateHumanRoot`, `generateAgent`, `issueDelegation`, `signChallenge`, `verifyBundle`) from the package root | 58.7 kB | 21.5 kB |
| `decodeProofBundleV2` from `/v2` | 33.1 kB | 11.2 kB |
| `verifyProofBundleV2` and `decodeProofBundleV2` from `/v2` | 750.5 kB | 223.0 kB |

Most of the v2 verifier's size is the embedded IANA tzdata archive that
`time_window` evaluation needs. Without the `sideEffects` declaration the
same v1-only import bundled to 198.0 kB gzipped, because the v2 modules
came along with it.

## Protocol v2 quickstart

Runnable TypeScript programs live in
[`examples/v2/typescript`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/typescript):
a quickstart (keys, delegation, challenge from the issuance helper, proof,
verify, receipt, checkpoint, release, `allowed`), signed status with a
revocation, an exact `custom:` scope with the `max_count/v1` evaluator
profile, and an external signer. Each prints the same output as the other
SDKs' programs, and CI checks it. They use the in-memory reference stores and
are development-only. Upgrading from v1 is covered in
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

## Three verbs, three examples (Protocol v1 API)

### 1. DELEGATE: a human authorizes an agent

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

### 2. PRESENT: an agent builds a proof bundle

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

### 3. VERIFY: any third party checks the proof

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

// User generates keypair on their own device; private key never leaves
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

### Session tokens (Protocol v1 only)

Session tokens are a v1 construction; Protocol v2 has no session token until
2.1. `SessionToken`s cross the wire the same way (`DelegationCert`s too, via `encodeDelegationCert` / `decodeDelegationCert`):

```ts
import { encodeSessionToken, decodeSessionToken } from "@identities-ai/ratify-protocol";

// Verifier issues the token after the first full verify and sends it out:
const tokenJSON = encodeSessionToken(token);

// The agent presents it on later turns; the verifier decodes and checks it:
const presented = decodeSessionToken(tokenJSON);
```

### Strict decoding

Decoders fail closed. A document is rejected, with an error naming the offending field, if it carries malformed UTF-8 or a byte-order mark; malformed or non-canonical base64; a wrong byte length for a key, signature, challenge, or 32-byte binding field; a missing or mistyped required field; an integer outside the IEEE-754 safe-integer range [-(2^53-1), 2^53-1] (SPEC §6.2); an empty delegation chain; unpaired stream fields; duplicated JSON object keys (at any nesting depth, with string escapes decoded before comparison); or an unknown field in a signed structure. Anything a conformant implementation would not have produced is treated as malformed at the transport boundary instead of surfacing later as a confusing verification failure.

The strictness applies to the signed structures themselves: `ProofBundle`, `DelegationCert`, `SessionToken` reject unknown fields because every byte of them is protocol surface. Your application's transport envelope is a different thing: it may carry whatever integration metadata you need, as long as that metadata stays outside the signed structure. For example, `{"proof_bundle": {...}, "app_metadata": {...}}` is fine. Decode `proof_bundle` strictly with `decodeProofBundle` and treat the rest of the envelope as your own; a `request_id` inside the bundle itself would (correctly) be rejected.

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
  SCOPE_FILES_WRITE,         // sensitive: never rides a wildcard
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

- **Ed25519** via [@noble/ed25519](https://github.com/paulmillr/noble-ed25519): audited, zero native deps, universal.
- **ML-DSA-65** via [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum): NIST FIPS 204, post-quantum lattice signature.
- **SHA-256** via [@noble/hashes](https://github.com/paulmillr/noble-hashes): same author, same posture.
- **WebCrypto** for secure random (32-byte challenges).

No network code in this package. HTTP concerns (challenge issuance, revocation list fetching, API auth) live one layer up.

**Signing mode.** `@noble/post-quantum` signs ML-DSA-65 with hedged randomization by default, so two signings of the same message produce different bytes. This does NOT affect interop: the signatures verify in Go, Python, Rust, and C/C++, and vice versa. What must match across languages is the canonical signable bytes (SPEC §8.3), and those match byte-for-byte. Only the Go reference generator signs deterministically, so that fixtures regenerate reproducibly; passing `{ extraEntropy: false }` would make this SDK deterministic too, but hedged signing is side-channel hardening and is kept as the default.

## v1 API added in alpha.16

The following surface first shipped in the v1 alpha.16 release and is available in every later v1 release.

- **Resource-bound verification.** The `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via a constraint's `resource_id` and optional `path_prefix`. At verify time the application supplies `requested_resource_id`, `requested_path`, and `has_resource` on `VerifierContext` (SPEC §5.16); `verifyBundle(bundle, { context })` evaluates them. Helpers: `normalizeResourcePath`, `resourcePathMatches`, `validateResourceConstraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `operationContextBytes`, `operationContextHash`, `sessionContextBytes`, and `buildSessionContext`; `verifierContextHash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `encodeVerificationReceipt` and `decodeVerificationReceipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `verifyStreamedTurnWithOptions` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** A constraint's `params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `validateParamsValue`; `isCanonicalConstraintType` guards which types may carry them.
- **Deeper delegation chains.** `MAX_DELEGATION_CHAIN_DEPTH` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MAX_PROOF_BUNDLE_BYTES`, `MAX_SCOPES_PER_CERT`, `MAX_CONSTRAINTS_PER_CERT`, `MAX_SCOPE_LENGTH_BYTES`, `MAX_IDENTIFIER_LENGTH_BYTES`, `MAX_AGENT_NAME_LENGTH_BYTES`, `MAX_JSON_NESTING_DEPTH`.

## Protocol v2 API

Version `2.0.0-beta.1` is a prerelease on the separate v2 line. It exports the
v2 API from `@identities-ai/ratify-protocol/v2` (and from the package root,
next to the unchanged v1 API). v2 prereleases use the `next` npm dist-tag, so
an unpinned install and exact `1.0.0-alpha.20` pins continue to resolve to
v1. Review so far is internal adversarial review; external independent review
is a gate for `2.0.0`, and v2 carries no production security claim yet.

Choose the helpers that match the proof version: v1 proofs use the v1 API,
and v2 proofs use the v2 API. The v2 API follows the Go reference and
SPEC-v2:

- **Wire layer.** Strict decoding (byte limits checked before parsing,
  integer-only JSON, `-0` and unpaired surrogate escapes rejected, the
  timestamp domain) and canonical encoding of every signed object, the
  closed constraint registry, `keyIDV2`, and every digest of SPEC-v2 §4.
  Failures carry one of the 49 language-neutral classes in `V2_ERROR_CLASSES`.
- **Signing.** Only typed signers, one per object (`signDelegationCertV2`,
  `signProofBundleV2`, ...). Each has a `...WithSigner` form that takes a
  `SignerV2`, an external signer in direct or external-mu mode; every
  returned signature is verified before use. No export signs caller-selected
  bytes, and no local `SignerV2` is exported: an in-process key signs only
  through the typed key-pair functions. The delegation signer refuses certificates that break the issuer
  duties of SPEC-v2 §5.1 before any signer method runs.
- **Live verification.** `verifyProofBundleV2` runs the SPEC-v2 §6 order and
  returns a committed outcome, which exposes no decision. Only
  `releaseV2Decision` produces a `V2ReleasedDecision`; its constructor
  throws for any other caller, and an object it did not return is never
  actionable. Gate a side effect on `await decision.allowed(clock)`, which
  compares the receiver's clock with the sealed exclusive deadlines. This
  guards against API misuse, not against hostile code in the same process.
- **Status.** Status comes only from signed evidence batches applied to a
  `SecurityJournalV2` (canonical snapshot, labelled digest, alpha migration).
  `newV2StatusPublisher` (external signer) and `newV2StatusPublisherWithKey`
  (in-process key pair) build a minimal signed-status publisher from the
  role journal.
- **Key material.** A typed key-pair signer copies the private key into an
  internal signer and overwrites that copy with zeros when the call settles,
  on success, refusal, or error. A publisher from
  `newV2StatusPublisherWithKey` keeps its copy of the status key until
  `dispose()` (or a `using` declaration) zeroes it; after that, every
  signing call throws `configuration_invalid`. Your own key pair is never
  modified, so clear it yourself when you are done. JavaScript cannot
  guarantee erasure: copies made by the engine or the garbage collector, and
  the internal state of the underlying cryptography libraries, are outside
  the SDK's control. Only buffers the SDK owns are wiped. For stronger
  custody, sign through an external `SignerV2` backed by an HSM or KMS.
- **Constraints.** `time_window` is evaluated against the embedded IANA
  tzdata `2025c` (SHA-256 checked at load; host zone data is never used).
  Extension evaluator profiles, including the two standard profiles, are
  registered with `newConstraintEvaluatorRegistryV2` and sealed at claim.
- **Part B.** Interfaces for the claim store, authoritative clock, rate
  reservation, receipt publisher, independent checkpoint, journal store and
  challenge issuance, plus recovery of interrupted claims, archival
  verification, and `verifyTransactionReceiptV2`. In-memory reference
  implementations, for tests only, are exported from
  `@identities-ai/ratify-protocol/v2/reference` with `TestOnly` names. They
  are not durable and must not back a production verifier.

`npm test` runs every file in `testvectors/v2`, including the lifecycle and
profile scenarios, and verifies every cross-SDK fixture in
`testvectors/v2/cross-sdk`. `npm run generate:cross-sdk` writes this SDK's
fixture. The per-SDK record against the gates in SPEC-v2 §8 is in
[`docs/V2_REFERENCE_COMPATIBILITY.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/V2_REFERENCE_COMPATIBILITY.md).
A deployment still supplies durable Part B stores and an independent
checkpoint.

## License

Apache-2.0
