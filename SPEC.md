# Ratify Protocol™ Specification — v1

**Delegated-authority proofs for human-agent and agent-agent interactions.**

**Status:** Reference — authoritative alongside the Go implementation at module root. Maintained by Identities AI, Inc. Identities AI, Inc. owns the Ratify Protocol™ trademark and the patent-pending invention.
**Version:** 1 (wire format `version` = 1)
**Cryptography:** Hybrid Ed25519 + ML-DSA-65 (FIPS 204). **Quantum-safe.**
**License:** CC-BY-4.0 for this text; Apache-2.0 for the reference code.

---

## 1. Purpose

Ratify is a cryptographic primitive and JSON wire format for proving that a party — human or AI agent — is authorized to act or transact on behalf of another party, within a specified scope and time window. Verification is stateless, offline-capable, and terminates in a deterministic yes/no.

This specification defines:

- The data structures on the wire
- The canonical byte representation that gets signed
- The hybrid (Ed25519 + ML-DSA-65) signing and verification algorithm
- The verifier's state-machine algorithm for proof bundles
- The canonical scope vocabulary
- The three patterns of use: human-agent, agent-agent, and multi-hop transactions
- An optional HTTP transport binding

An implementation is **conformant** if it reproduces the expected output of every fixture in `testvectors/v1/` byte-for-byte.

## 1.5 The Transaction Horizon — Why Now

In 2024–2025, AI agents were assistants: they drafted, summarized, and recommended. Humans stayed in the loop and executed. In 2026–2028, agents cross the line from assistant to actor: they *transact*. They make calls on humans' behalf, send money, book resources, enter into agreements, coordinate with other agents to execute multi-step workflows. This is the transaction horizon.

Two structural consequences follow:

1. **The receiving party can no longer trust a claim of authorization.** *"I am Alice's agent"* was sufficient when the AI was merely drafting an email for Alice to review. It is insufficient when the AI is booking a $50k advertising spend without further human review, or when one AI agent is paying another agent for compute, data, or service.
2. **Agent-to-agent interactions become the dominant traffic shape.** When your agent negotiates with another company's agent about a meeting, a contract, a price, or a data exchange, there is no human in the loop at the moment of the transaction. The trust layer must work without one.

Ratify exists for this moment. Every signed object the protocol produces is portable across verifiers, applications, and ecosystems; every proof is a cryptographic receipt of *who authorized what, within which bounds, for how long.* Humans delegate to agents; agents delegate to sub-agents or transact with peer agents; any third party can verify any of it in milliseconds — under a millisecond in the compiled reference implementations (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) for the per-SDK matrix). And because the transaction horizon extends beyond the lifetime of today's cryptographic assumptions, every signature is hybrid: classical and post-quantum, so that even a future quantum adversary cannot retroactively forge proofs archived today.

---

## 2. Terminology

- **Principal** — any party (human, tenant admin, or already-delegated agent) that signs a `DelegationCert` authorizing another party.
- **Agent** — an AI process that holds a keypair, carries delegations, and presents signed proofs on each interaction.
- **Verifier** — any party that needs to decide whether a presenter is authorized for a specific action.
- **HumanRoot** — the top-of-chain identity keypair for a human or tenant admin. May be anchored to an external IdP.
- **AgentIdentity** — an agent's keypair; may appear as a subject (leaf) or as an intermediate delegator.
- **DelegationCert** — a signed authorization statement binding principal to subject.
- **ProofBundle** — what a presenter hands to a verifier: delegation chain + fresh challenge signature.
- **RevocationList** — a signed list of cert IDs the principal has revoked.

The words MUST, SHOULD, MAY are used per RFC 2119.

---

## 3. Design principles

1. **Hybrid cryptography is mandatory in v1.** Every signed object carries both an Ed25519 signature (RFC 8032) and an ML-DSA-65 signature (FIPS 204). Both must verify. This defends against classical cryptanalytic advances on either algorithm and against quantum attacks on Ed25519 via ML-DSA-65's lattice-based security.
2. **Harvest-now-decrypt-later attacks cannot retroactively forge proofs.** Bundles signed today remain unforgeable even when cryptographically-relevant quantum computers exist, because ML-DSA-65 does not succumb to Shor's algorithm.
3. **JSON wire format.** CBOR deferred to v2. Debuggability and implementer ergonomics matter more than byte compactness in v1.
4. **No blockchain.** Signed revocation list + short cert lifetimes. Optional on-chain anchoring is an enterprise concern outside this spec.
5. **Stateless verification.** A verifier with the relevant public keys and a recent revocation list can verify entirely offline — no round-trip to any central service is required on the hot path.
6. **Symmetric for human-agent and agent-agent.** The same cert/bundle shapes, the same verifier algorithm. An agent-to-agent delegation is structurally identical to a human-to-agent delegation.

---

## 4. Trust equation

A verifier accepts a `ProofBundle` if and only if every one of the following checks passes:

1. **Delegation signatures** — each cert in the chain is signed by the cert's declared issuer public key. **Both** component signatures (Ed25519 AND ML-DSA-65) must verify.
2. **Temporal validity** — no cert is expired (`now <= expires_at`) and no cert is not-yet-valid (`now >= issued_at`).
3. **Liveness** — the presenter signed a fresh challenge (≤ `CHALLENGE_WINDOW_SECONDS` old) with the presenter's private key. Both component signatures must verify.
4. **Effective scope** — the required scope is present in the intersection of every cert's expanded scope set.
5. **Revocation** — none of the certs appear in the signed revocation list.
6. **Constraint evaluation** — every `Constraint` on every cert in the chain evaluates true against the caller-supplied `VerifierContext`. A constraint whose required context field is absent from the context fails with `constraint_unverifiable`. An unknown constraint `type` fails with `constraint_unknown`.

Any failure causes immediate rejection. The failure type (`expired`, `revoked`, `scope_denied`, `constraint_denied`, `constraint_unverifiable`, `constraint_unknown`, `invalid_scope`, `delegation_not_authorized`, `invalid`) is returned deterministically. A single component-signature failure (e.g. Ed25519 passes but ML-DSA-65 fails, or vice versa) fails the whole signature — fail-closed is the v1 semantics.

---

## 5. Data structures

All structures are JSON objects serialized in canonical form (see §6).

### 5.1 Constants

| Name | Value |
|---|---|
| `PROTOCOL_VERSION` | `1` |
| `MAX_DELEGATION_CHAIN_DEPTH` | `8` |
| `CHALLENGE_WINDOW_SECONDS` | `300` |
| `NO_EXPIRY_SENTINEL` | `4070908799` (2099-12-31 23:59:59 UTC) — see §5.7 |
| `ED25519_PUBLIC_KEY_SIZE` | `32` bytes |
| `ED25519_SIGNATURE_SIZE` | `64` bytes |
| `MLDSA65_PUBLIC_KEY_SIZE` | `1952` bytes (FIPS 204) |
| `MLDSA65_SIGNATURE_SIZE` | `3309` bytes (FIPS 204) |
| `MAX_PROOF_BUNDLE_BYTES` | `131072` (128 KiB) |
| `MAX_SCOPES_PER_CERT` | `128` |
| `MAX_CONSTRAINTS_PER_CERT` | `32` |
| `MAX_SCOPE_LENGTH_BYTES` | `256` |
| `MAX_IDENTIFIER_LENGTH_BYTES` | `512` |
| `MAX_AGENT_NAME_LENGTH_BYTES` | `256` |
| `MAX_JSON_NESTING_DEPTH` | `16` |

**Input-bound enforcement.** The size and count limits above bound parsing and verification work; the depth ceiling alone does not, which is why they exist alongside it. `MAX_PROOF_BUNDLE_BYTES` is enforced by the wire codecs **before** JSON parsing — an oversized payload is rejected without ever being parsed. `MAX_JSON_NESTING_DEPTH` is enforced by the codec **during** parse. Count and length limits are enforced during decode. `MAX_IDENTIFIER_LENGTH_BYTES` bounds `resource_path.resource_id` in this release; future constraint types that name opaque identifiers adopt the same bound. `MAX_AGENT_NAME_LENGTH_BYTES` bounds `AgentIdentity.name` at construction and decode. Violations route to the existing `invalid` status (§5.9) with a descriptive `error_reason` (e.g. `invalid: proof bundle exceeds MAX_PROOF_BUNDLE_BYTES`); no new status is introduced.

**Depth ceiling semantics.** `MAX_DELEGATION_CHAIN_DEPTH` is the protocol ceiling — a wire-determinism and denial-of-service bound, not a cryptographic limit. Principals who want shorter chains bound them per-delegation; a future canonical `max_delegation_depth` constraint is planned for that purpose. (The ceiling was 3 through v1.0.0-alpha.15; multi-hop agent topologies motivated raising it to 8.)

**Interaction of size and depth limits (guidance).** `MAX_PROOF_BUNDLE_BYTES` and `MAX_DELEGATION_CHAIN_DEPTH` are independent ceilings. The byte limit applies to the received wire representation and is enforced before parsing or verification. Bundle size grows with both chain depth and per-certificate content, including scopes and constraints, so a chain within the depth ceiling can still exceed the byte ceiling. In that case, the wire decoder rejects the bundle for exceeding `MAX_PROOF_BUNDLE_BYTES` before chain depth is evaluated. A wire-facing verification surface that represents decode failures as a verification result uses the existing `invalid` status, not `chain_too_deep`. Deployments choosing an operational chain-depth limit SHOULD budget for their maximum expected per-certificate content, not depth alone.

### 5.2 HybridPublicKey

Every public key in the protocol is a pair: one Ed25519 component and one ML-DSA-65 component. Canonical JSON form (keys in lex order):

```
{"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}
```

### 5.3 HybridSignature

Every signature in the protocol is a pair over the same canonical bytes. Both components MUST verify for the signature to be accepted.

```
{"ed25519":"<base64-64-bytes>","ml_dsa_65":"<base64-3309-bytes>"}
```

### 5.4 HumanRoot

```
{
  "id":         "<16-byte-hex>",         // = hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])
  "public_key": <HybridPublicKey>,
  "created_at": <unix-seconds>,
  "anchors":    [<Anchor>, ...]          // optional
}
```

Only the public component travels on the wire. Private keys SHOULD be stored on the owner's device where possible (self-custody mode). Custodial deployments where a registry operator holds envelope-encrypted keys are a valid deployment mode with different trust assumptions — see §15.2 for the full key-custody model.

### 5.5 Anchor

```
{
  "type":        "email" | "enterprise_sso" | "government_id",
  "provider":    "<string>",             // e.g. "google", "okta", "azure_ad"
  "reference":   "<opaque string>",      // privacy-preserving handle, not PII
  "verified_at": <unix-seconds>
}
```

### 5.6 AgentIdentity

```
{
  "id":         "<16-byte-hex>",
  "public_key": <HybridPublicKey>,
  "name":       "<string>",
  "agent_type": "<string>",              // "zoom_bot", "voice_agent", "mcp_server", "custom"
  "created_at": <unix-seconds>
}
```

### 5.7 DelegationCert

```
{
  "cert_id":         "<string>",         // UUID recommended
  "version":         1,
  "issuer_id":       "<hex>",
  "issuer_pub_key":  <HybridPublicKey>,
  "subject_id":      "<hex>",
  "subject_pub_key": <HybridPublicKey>,
  "scope":           ["<scope>", ...],
  "constraints":     [<Constraint>, ...], // empty array if none; never absent
  "issued_at":       <unix-seconds>,
  "expires_at":      <unix-seconds>,
  "signature":       <HybridSignature>
}
```

`scope` answers *what* the agent may do. `constraints` answer *where / when / how much* — first-class bounds evaluated at verify time against a caller-supplied context (§5.7.1). `constraints` is always present in the JSON even when empty (serialized as `[]`) so canonical bytes are deterministic across issuers.

**No-expiry sentinel.** `expires_at` is a required integer with no null representation. A delegation intended to last "until revoked" carries the sentinel value `NO_EXPIRY_SENTINEL = 4070908799` (2099-12-31 23:59:59 UTC) as its `expires_at`. Conformant implementations MUST treat a cert whose `expires_at` equals the sentinel as **"no expiry (until revoked)"** in display and policy evaluation — never as a literal 2099 expiry (e.g. an organizational lifetime cap MUST NOT interpret the sentinel as a ~75-year grant; it is an open-ended grant terminated only by revocation). Verification behavior is unchanged: the sentinel is a future timestamp, so the temporal check in §10 passes; revocation (§5.10, §5.11) is the sole termination mechanism for such certs. Issuers SHOULD NOT sign `expires_at` values greater than the sentinel — values above it are reserved, carry no defined meaning, and MAY be rejected by issuer helpers in a future revision (v1 issuer helpers do not enforce this). The fixture `no_expiry_cert` pins the sentinel's verify behavior.

### 5.7.1 Constraint

A `Constraint` is a tagged JSON object. `type` identifies the kind; the remaining fields are kind-specific. Unknown `type` values MUST be rejected by conformant verifiers (fail-closed).

```
{
  "type":      "<ConstraintType>",
  ...         // kind-specific fields (see §5.7.2)
}
```

**Extension-constraint parameters (`params`).** A constraint whose `type` is not one of the canonical types in §5.7.2 MAY carry a single generic parameter object:

```
{
  "type":   "<ConstraintType>",   // non-canonical (extension) kind
  "params": { ... }               // optional; extension parameters
}
```

- `params` is permitted **only** on non-canonical constraint types. A canonical type (§5.7.2) carrying `params` MUST be rejected as malformed (`invalid`).
- When present, `params` is part of the canonical signed bytes (§6): the `params` key sorts alphabetically among the constraint's keys, and object keys inside `params` sort per RFC 8785. An extension constraint without `params` serializes exactly as before — `{"type":"<name>"}` — so certificates signed under earlier releases remain byte-stable.
- **Restricted value model**, so canonical bytes are deterministic across languages. Permitted values: `null`, booleans, strings, safe integers (|n| ≤ 2^53 − 1), and arrays and objects of these. Prohibited: floats and any non-integer numbers, `NaN`/`Infinity`, raw bytes, and duplicate object keys. Integers beyond 2^53 − 1 MUST be carried as decimal strings. Nesting depth is bounded by `MAX_JSON_NESTING_DEPTH` (§5.1); total size participates in the ordinary `MAX_PROOF_BUNDLE_BYTES` limit.
- Encoders MUST reject a `params` value outside this model at construction time; decoders MUST reject it as malformed (`invalid`).
- Evaluation of extension constraints is unchanged: a verifier without a registered evaluator for the type fails closed with `constraint_unknown` (§17.7), whether or not `params` is present. Verifiers MUST be upgraded before issuers begin emitting new constraint types.

### 5.7.2 Canonical constraint types (v1)

| `type` | Required fields | Verifier context input | Semantics |
|---|---|---|---|
| `geo_circle` | `lat`, `lon`, `radius_m` | agent location (lat/lon) | Agent must be within `radius_m` of (`lat`, `lon`). Haversine on WGS-84 mean radius 6 371 000 m. |
| `geo_polygon` | `points` (≥3 `[lat,lon]` pairs) | agent location | Agent must be inside the polygon. Ray-casting in equirectangular projection. v1 rejects polygons whose longitude span exceeds 180° (anti-meridian-crossing) — fail-closed; geodesic inclusion is a v2 feature. |
| `geo_bbox` | `min_lat`, `min_lon`, `max_lat`, `max_lon` (opt: `min_alt_m`, `max_alt_m`) | agent location (and altitude if alt bounds are set) | Inclusive bounding box. When `min_lon > max_lon`, the bbox is interpreted as wrapping the 180° meridian (e.g. `min_lon=170, max_lon=-170` = "from 170°E through 180° to -170°W"), and the point is inside iff `lon >= min_lon OR lon <= max_lon`. Altitude bounds are ignored if both are zero. |
| `time_window` | `start`, `end` (HH:MM), `tz` (IANA zone) | current time | Current time in `tz` must fall in `[start, end]` inclusive. `end < start` means the window wraps midnight. |
| `max_speed_mps` | `max_mps` | agent current speed (m/s) | Agent speed must not exceed `max_mps`. Verifier requires speed input; SI units chosen to avoid unit ambiguity. |
| `max_amount` | `max_amount`, `currency` (ISO 4217) | requested amount + currency | Requested amount must not exceed `max_amount`; currencies must match. |
| `max_rate` | `count`, `window_s` | per-cert invocation counter | Across a rolling `window_s` seconds, at most `count` exercises of this cert are allowed. **Verifier-local policy, not byte-identical canonical protocol behavior.** The counter is supplied by the caller via `VerifierContext.invocations_in_window(certID, window_s)` and backed by whatever the operator chooses (an in-memory ring, a cache, a shared service). Two verifiers observing the same agent can disagree depending on clock skew, replication lag, and counter backend semantics. Operators requiring globally-consistent rate accounting must route through a single verifier or share a central counter. |
| `resource_path` | `resource_id` (opt: `path_prefix`) | requested resource ID + requested path | The operation must target the named resource and, when `path_prefix` is present, a path at or below `path_prefix` under segment-boundary prefix matching (§5.7.3). `resource_id` is an opaque string compared byte-for-byte; the verifier never dereferences, fetches, or normalizes it. Absent `path_prefix` authorizes the entire named resource. |

### 5.7.3 The `resource_path` constraint

`resource_path` binds a delegation to a specific resource — a repository, a workspace, a channel, a device — and optionally to a path prefix within that resource's own namespace. It answers *where* an agent's scope applies: `files:write` says the agent may write files; `files:write` plus `resource_path{repo R, /docs}` says it may write files only in `/docs` of repository R.

**Wire shape.**

```
{
  "type":        "resource_path",
  "resource_id": "<string>",          // required, non-empty
  "path_prefix": "<string>"           // optional; absent = entire resource
}
```

**`resource_id` semantics.**

- `resource_id` is an **opaque UTF-8 string**. Verifiers compare it to the caller-supplied `RequestedResourceID` (§5.16) by **exact byte equality** — no case folding, no percent-decoding, no scheme interpretation, no network dereference, no normalization of any kind.
- `resource_id` MUST be non-empty and MUST NOT exceed `MAX_IDENTIFIER_LENGTH_BYTES` (§5.1).
- The spec recommends URI/URN-shaped identifiers for readability but requires no particular scheme. Interoperability — issuer and verifier constructing the same bytes for the same real-world resource — is delegated to **resource-identifier profiles** (§5.7.4), which are normative for parties that adopt them but are not part of the core constraint semantics. A verifier that has never heard of a profile still verifies correctly, because it only ever compares bytes.

**Path model** (applies to `path_prefix` and to the caller-supplied `RequestedPath`). Paths are **absolute logical POSIX-style paths**: they name a location inside the resource's own namespace (e.g. a path within a repository), not filesystem paths on any particular machine. A path is valid iff all of the following hold:

- It begins with `/`, and `/` is the **only** separator.
- It contains no NUL (U+0000) byte and no backslash (`\`) — backslash is rejected, not translated.
- No segment is `.` or `..`. Dot-segments are rejected outright, never resolved.
- No interior segment is empty (`/a//b` is invalid). The root path `/` is valid.
- A trailing `/` is trimmed before comparison, except for the root path `/` itself (`/docs/` ≡ `/docs`).

Issuer helpers MUST reject an invalid `path_prefix` at construction time. A verifier that encounters an externally created cert whose `path_prefix` is invalid MUST fail the constraint closed with `constraint_denied`. A supplied `RequestedPath` that is invalid likewise fails with `constraint_denied`: the context was supplied and is unacceptable. `constraint_unverifiable` is reserved for context that is *absent*.

**Unicode.** The verifier compares path and resource bytes exactly; it performs no Unicode normalization and no normalization-form validation. Issuers and adapters MUST pre-normalize paths and resource identifiers to Unicode NFC before constructing constraints and verifier context. The consequences of violating that obligation are asymmetric and must be understood precisely: a **mixed** pair (one side NFC, the other not) fails closed — the grant never matches, costing availability, never an unintended grant — while parties that consistently supply the **same** non-NFC bytes on both sides will verify, because the protocol treats those bytes as a distinct, valid identity. Byte identity, not visual identity, is the security boundary.

**Percent-encoding does not exist inside the path model.** `%` is an ordinary literal byte once `RequestedPath` or `path_prefix` has been constructed: `/docs/%2e%2e/secrets` names a path whose second segment is the literal characters `%2e%2e`, not a dot-segment. An adapter receiving an encoded external representation MUST perform any required percent-decoding before constructing `RequestedPath`. No component may percent-decode `RequestedPath` or the verified path during or after matching.

**No post-verification transformation.** Byte-level matching is a security boundary only while the bytes remain unchanged. After verification, no component may percent-decode, case-fold, Unicode-normalize, convert separators, or otherwise transform the verified path before acting on it — a transformation applied downstream can turn an authorized logical path into a traversal the verifier never saw. Every such step (URL decoding, platform Unicode normalization, case folding, separator conversion, path cleanup) MUST occur **before** constructing `RequestedPath`, so the bytes the verifier compares are exactly the bytes the execution layer uses.

**Matching semantics — segment-boundary prefix, not glob.** `path_prefix` matches `RequestedPath` iff, after trailing-slash trimming, either:

1. the two are byte-equal, or
2. `RequestedPath` begins with `path_prefix` followed immediately by `/` (special case: `path_prefix` `/` matches every valid path).

So `/src` matches `/src` and `/src/a.ts`, and **never** matches `/src-old/a.ts` or `/srcx`. Plain string-prefix matching is non-conformant. **This is not glob matching**: there are no wildcards, character classes, or `**` operators. A prefix of `/docs` covers everything a `/docs/**` glob would cover, so the whole-subtree case needs no glob syntax. Finer patterns (e.g. `/src/**/*.test.ts`) are **not expressible** in `resource_path` v1 and remain application-side enforcement *inside* the authorized prefix: the certificate proves the operation is confined to `/src`; the application decides which files within `/src` it will actually touch.

**Evaluation** (within §10 step 7.f, fail-closed):

- The context carries no requested resource (`HasResource` false / fields absent) → `constraint_unverifiable`.
- `RequestedResourceID` is not byte-equal to `resource_id` → `constraint_denied`.
- The constraint carries `path_prefix` and the context carries no `RequestedPath` → `constraint_unverifiable`.
- The constraint carries `path_prefix` and `RequestedPath` does not match → `constraint_denied`.
- Otherwise the constraint passes.

Evaluation is **conjunctive across the chain** with no new machinery: §10 step 7.f already evaluates every constraint on every cert in the chain against the same `VerifierContext`, and the request must satisfy every hop's `resource_path` simultaneously. A child cert **cannot widen** the effective authority: a child claiming a *broader* prefix on the *same* resource (parent `/src/security`, child `/src`) leaves the effective bound at the narrower upstream prefix — the request must still satisfy the parent's `/src/security`, so the pair is satisfiable but the child gains nothing. Downstream escape is impossible by construction, not by a new rule. Where the chain's same-resource prefixes are nested they reduce under AND to the narrowest (`/src` ∧ `/src/security` → effectively `/src/security`; an absent prefix orders as `/`). A constraint naming a **different** `resource_id`, or a same-resource prefix that is **incomparable** under the prefix relation (`/src` ∧ `/docs` — no path lies under both), makes the set jointly unsatisfiable and fails closed as `constraint_denied`. No new status, no special-case rejection rule at verify time.

**Canonical serialization.** Per the existing per-kind constraint pattern (§6): keys alphabetical, only kind-relevant fields emitted. `resource_path` emits `path_prefix` (when present), `resource_id`, `type`. **`path_prefix` is omitted when absent.** Every *valid* `path_prefix` begins with `/`, so the empty string can never be a meaningful value: an empty-string `path_prefix` MUST be rejected by issuer helpers, MUST NOT be emitted by canonical serialization, and decoders treat `"path_prefix": ""` as an invalid constraint (fails closed). Absence — not `""`, not `null` — is the sole encoding of "entire resource".

**Issuance rule — one satisfiable resource bound per certificate.** Conforming issuance APIs MUST **reject** (error, not warn) a certificate whose `resource_path` constraints are jointly unsatisfiable: multiple constraints naming **different** `resource_id`s, and multiple constraints naming the **same** `resource_id` whose prefixes do not form a nested chain under the prefix relation (an absent prefix orders as `/`). Nested same-resource prefixes are permitted — they reduce to the narrowest. An unsatisfiable cert is a footgun, not a grant. Decoders MUST still accept externally created certificates containing unsatisfiable sets — wire compatibility is not conditioned on issuance hygiene — and verification denies them as unsatisfiable.

**One resource per verification.** A verification evaluates one operation on one resource: `VerifierContext` carries a single `RequestedResourceID` and a single `RequestedPath`. Multi-resource operations ("read repo A and write repo B") are separate operations and MUST be presented as separate verifications, with separate certs where the grants differ. Future OR-expressiveness, if demand shows, arrives as a resource list *inside one constraint* — never as OR-across-constraints, which would break the conjunctive algebra of §10 step 7.f.

**What `resource_path` attests.** The verified constraint is **lexical** authorization over a logical path — it is not filesystem confinement. A receiving system that maps logical paths onto a real filesystem MUST add its own confinement layer (path resolution against a fixed root, symlink and traversal rejection, containment re-checks after create/rename, sandboxing); see §15.7. Ratify proves authorization for a canonical logical resource and path; the adapter attests context; the execution layer enforces filesystem confinement.

### 5.7.4 Resource-identifier profiles

A resource-identifier profile is a deterministic recipe both issuer and verifier follow to construct the same `resource_id` bytes for the same real-world resource. Profiles are versioned documents maintained outside this specification; they are normative for parties that adopt them and invisible to everyone else — the core constraint semantics (§5.7.3) never change, and byte-equality remains the only comparison.

| Profile | Resource kinds | Document |
|---|---|---|
| Git v1 | Git repositories (repository identity; not branches, commits, or checkouts) | `docs/RESOURCE_PROFILES.md` |
| Platform-authored profiles | Resource kinds defined by the authoring platform (e.g. workspaces, channels, conversations, compute nodes) | Authored and versioned by the platform that owns the resource semantics; referenced from `docs/RESOURCE_PROFILES.md` when published |

A profile MUST define: one canonical byte-identical representation per resource; a deterministic construction algorithm requiring no heuristic name normalization; type separation (the same underlying ID must not be interpretable as more than one resource kind); lifecycle rules (rename, archive, delete, recreate — identifiers must not silently transfer authority to a newly created resource); a no-secrets guarantee (identifiers appear in signed certificates, receipts, logs, and public test vectors); versioning from first release; and known-answer plus negative vectors.

### 5.8 ProofBundle

```
{
  "agent_id":         "<hex>",              // MUST equal delegations[0].subject_id
  "agent_pub_key":    <HybridPublicKey>,    // MUST equal delegations[0].subject_pub_key
  "delegations":      [<DelegationCert>, ...], // [leaf, ..., root], depth 1..MAX_DELEGATION_CHAIN_DEPTH
  "challenge":        "<base64-32-bytes>",
  "challenge_at":     <unix-seconds>,
  "challenge_sig":    <HybridSignature>,
  "session_context":  "<base64-32-bytes>",  // optional v1.1 verifier/session/request binding
  "stream_id":        "<base64-32-bytes>",  // optional v1.1 stream binding
  "stream_seq":       <int64>               // required when stream_id is present; MUST be ≥1
}
```

`session_context` is optional and omitted for legacy v1 proof bundles. When present it MUST be exactly 32 bytes and MUST be included in the challenge signing bytes (§6.4.2). It is a verifier-reconstructed hash over verifier/session/request context. §6.4.9 defines the canonical, length-prefixed, domain-separated construction (RECOMMENDED for all session-bound deployments; REQUIRED under the Middleware Custody Profile, §15.2.1) — raw concatenation preimages are ambiguous and SHOULD NOT be used. Whatever the preimage, both sides must agree on the resulting 32 bytes for a session-bound challenge to verify.

`stream_id` and `stream_seq` are optional and omitted for legacy v1 proof bundles. When either is present, both MUST be present, `stream_id` MUST be exactly 32 bytes, and `stream_seq` MUST be ≥1 and strictly greater than any stream_seq the verifier has previously accepted for the same stream_id. Both are included in the challenge signing bytes (§6.4.2) so a proxy cannot replay, reorder, or omit bundles within a stream without invalidating the signature. A verifier that tracks a stream provides a `StreamContext { stream_id, last_seen_seq }`; the bundle's `stream_seq` MUST equal `last_seen_seq + 1`, otherwise the bundle is rejected (`stream_seq_replay` or `stream_seq_skip`). A verifier that does not track streams MUST reject bundles carrying `stream_id` (`stream_context_unverifiable`), because it cannot reconstruct the signable bytes.

### 5.9 VerifyResult

```
{
  "valid":           true | false,
  "human_id":        "<hex>",            // always = delegations[N-1].issuer_id
  "agent_id":        "<hex>",
  "granted_scope":   ["<scope>", ...],   // effective intersection, lex-sorted
  "identity_status": "<IdentityStatus>", // enum; see table below
  "error_reason":    "<string>"          // present iff valid == false
}
```

**`identity_status` enum (closed set).** Callers route on the status directly; implementations MUST NOT invent new values without a spec bump.

| Status | Semantics |
|---|---|
| `authorized_agent` | Success — the presenter is an AI agent authorized by a human root. |
| `verified_human` | Success — the presenter is a human (trusted-domain SSO bypass). |
| `expired` | A cert in the chain is past its `expires_at`. |
| `revoked` | A cert in the chain appears in a signed revocation list. |
| `scope_denied` | Required scope not present in the effective (chain-intersected) grant. |
| `constraint_denied` | A first-class `Constraint` (geo, time, speed, amount, rate, resource) evaluated false against the caller-supplied `VerifierContext`. |
| `constraint_unverifiable` | A constraint required a context field the caller did not supply. Fail-closed. |
| `constraint_unknown` | A cert carried a `Constraint` with a `type` the verifier does not recognize. Fail-closed — prevents silently ignoring an unknown type that a future verifier version might treat as meaningful. |
| `invalid_scope` | A cert in the chain grants a scope that is not canonical, not a wildcard, and not a `custom:` extension (§9). Fail-closed — invalid vocabulary is rejected as malformed before any effective-scope arithmetic, so unknown strings can never become effective grants. |
| `delegation_not_authorized` | A non-root cert was issued by a subject whose parent cert did not explicitly grant `identity:delegate`. |
| `invalid` | Catch-all for structural or cryptographic failures (bad signature, malformed chain, bad key length, wrong version, bad challenge signature, input-bound violations per §5.1 — oversized bundle, excess scopes/constraints, over-length strings, excessive JSON nesting — etc.). |
| `unauthorized` | Reserved for future use. Not currently emitted by the reference verifier. |

For failures with their own status, `error_reason` begins with the status name followed by `: ` and a human-readable detail (e.g. `"scope_denied: required scope \"files:write\" not in effective delegation scope"`). Audit layers should prefer the status enum over parsing the text.

### 5.10 RevocationList

```
{
  "issuer_id":     "<hex>",
  "updated_at":    <unix-seconds>,
  "revoked_certs": ["<cert_id>", ...],
  "signature":     <HybridSignature>
}
```

### 5.11 RevocationPush

```
{
  "issuer_id":  "<hex>",
  "seq_no":     <int64>,                // monotonically increasing per issuer; first push is 1
  "entries":    ["<cert_id>", ...],     // cert IDs newly revoked in this push
  "pushed_at":  <unix-seconds>,
  "signature":  <HybridSignature>
}
```

`RevocationPush` is a v1.1 optional signed notification that a revocation-list issuer sends to subscribed verifiers in real time (ROADMAP, Continuous real-time interactions). The payload carries a delta — cert IDs added to the revocation list since the previous push — and is hybrid-signed by the issuer so a verifier can trust it without re-fetching the full list.

`seq_no` is monotonically increasing per issuer (first push is 1). Receivers MUST detect gaps (missed pushes) and fall back to a full revocation-list fetch when a gap is detected. `entries` is always serialized as an array (`[]` when empty), never as `null`.

The push subscription endpoint (WebSocket, SSE, gRPC stream, etc.) is an operator/infrastructure concern — this spec defines the signed payload format only. Verifiers that cannot maintain long-lived subscriptions use the existing pull model (§5.10) with the `ForceRevocationCheck` verify option (§10) for high-stakes endpoints.

### 5.12 WitnessEntry

```
{
  "prev_hash":   "<base64-32-bytes>",   // hash of previous entry, or zeros for genesis
  "entry_data":  "<base64>",            // the receipt/cert/revocation being witnessed
  "timestamp":   <unix-seconds>,
  "witness_id":  "<string>",            // who operates this witness log
  "signature":   <HybridSignature>
}
```

`WitnessEntry` is a v1.1 spec-defined element in a hash-chain append-only log (ROADMAP, Tamper-evident transaction streams). Any party may operate a Witness: Identities AI, an enterprise's own audit system, a third-party notary, or a blockchain-anchored system. Multiple witnesses MAY independently log the same events (redundancy).

v1.1 defines the shape and the signing semantics only. Operating a scalable witness is an implementation/product concern; the spec does not mandate deployment topology, storage backend, or consistency model. The fixture `witness_entry_valid` proves cross-SDK byte-identicality of the signable and signature.

### 5.13 SessionToken

```
{
  "version":       1,
  "session_id":    "<string>",             // verifier-chosen
  "agent_id":      "<hex>",
  "agent_pub_key": <HybridPublicKey>,
  "human_id":      "<hex>",
  "granted_scope": ["<scope>", ...],       // lex-sorted
  "issued_at":     <unix-seconds>,
  "valid_until":   <unix-seconds>,
  "chain_hash":    "<base64-32-bytes>",    // SHA-256 of concatenated DelegationSignBytes
  "mac":           "<base64-32-bytes>"     // HMAC-SHA256 over canonical signable bytes
}
```

`SessionToken` is a v1.1 backward-compatible signed credential that caches the result of a full chain verification. After a successful `Verify(ProofBundle)`, the verifier MAY issue a SessionToken binding the verified chain to its session. Subsequent turns in the same session present the token plus a fresh `ChallengeSig`; the verifier checks the token's HMAC and challenge signature without re-verifying the delegation chain. This is the session cert cache of ROADMAP's Continuous real-time interactions.

`chain_hash` is the 32-byte SHA-256 of the concatenated `DelegationSignBytes` of each cert in the verified chain. Any change to any cert in the chain changes `chain_hash`, invalidating tokens issued against the old chain.

`mac = HMAC-SHA256(session_secret, SessionTokenSignBytes(token))`, where `session_secret` is a cryptographically random secret (≥32 bytes recommended) private to the verifier. The secret MUST NOT leave the verifier's trust boundary; SessionTokens are single-verifier credentials.

Verifiers of a streamed turn MUST check:

- `version == 1`.
- `chain_hash` and `mac` are 32 bytes each.
- `mac` equals `HMAC-SHA256(session_secret, SessionTokenSignBytes(token))`.
- `now` ∈ [`issued_at`, `valid_until`].
- The fresh `ChallengeSig` verifies against `agent_pub_key` over the canonical challenge signable bytes (§6.4.2).
- When the verifier requires a scope for the protected action: the required scope ∈ `token.granted_scope` (else `scope_denied`). `granted_scope` stores the verified chain's effective scope lex-sorted for exactly this check — a token is a cache of a chain verification, not a bypass of the scope gate.
- When the verifier issues challenges (§10 "Challenge single-use"): the per-turn challenge resolves to an unexpired, unconsumed issuance record before the per-turn hybrid `ChallengeSig` is verified, and is atomically consumed after that signature verifies, before the scope check — with the same `unknown_challenge` normalization as §10. The streamed-turn order deliberately differs from §10 in one respect: the session token's HMAC is checked FIRST, before the store lookup. The HMAC is a cheap authenticated pre-check that stops unauthenticated callers from probing the challenge store; §10 has no equivalent authenticator ahead of its store lookup.
- When the turn presents a `session_context` or `stream_id`/`stream_seq` binding (§5.8): the verifier checks it against verifier-supplied session/stream state with the same statuses as the full verifier (`session_context_mismatch`, `stream_seq_replay`, `stream_seq_skip`, and the `*_unverifiable` rejections for bindings the verifier cannot check).

The stream state supplied to these checks is a caller-owned SNAPSHOT: the streamed-turn verifier reads it and never advances it. Two concurrent turns carrying distinct valid challenges and the same `stream_seq` will both pass against the same snapshot — the helper alone does not provide concurrency-safe sequence enforcement. A verifier claiming stream replay protection MUST atomically advance its tracked last-seen sequence (compare-and-advance to the turn's `stream_seq`) when and only when verification succeeds, and construct each snapshot from that tracked state.

Reference implementations expose these controls through an options-object form of the streamed-turn verifier taking a dedicated `StreamedVerifyOptions` — required scope, challenge store, session context, stream state, and clock override, and nothing else. It is deliberately not the full `VerifyOptions` (§5.17): revocation, policy, constraint, audit, and anchor options do not apply to a token presentation and MUST NOT be accepted — a full-verifier option can never be passed and silently ignored. Statically-typed implementations enforce this at compile time (distinct types); dynamically-typed implementations MUST enforce it at runtime, fail-closed (the reference TypeScript verifier rejects any options object carrying a full-verifier-only field, and the reference Python verifier rejects any options value that is not a `StreamedVerifyOptions`). Callers who need fresh revocation or policy semantics — including high-value operations directed to `ForceRevocationCheck` (§5.17) — MUST run full verification instead of the token fast path.

On success the verifier returns `identity_status = authorized_agent`, `granted_scope = token.granted_scope`, `agent_id = token.agent_id`, `human_id = token.human_id`. Revocation and expiry of underlying certs are NOT re-checked — callers who need fresh revocation semantics evict tokens when the issuer publishes a new revocation list or when `valid_until` expires.

**Token lifetime guidance.** Because revocation is not re-checked during a token's lifetime, `valid_until − issued_at` is the maximum revocation-staleness window for the session. Deployments SHOULD size token lifetimes to risk:

- **High-stakes actions** (payments, physical actuation, `identity:*` scopes): token lifetime ≤ 5 minutes — or skip the fast path entirely and run full verification with `ForceRevocationCheck` (§5.17) on each such action.
- **Ordinary conversational sessions** (meetings, voice/video calls): token lifetime ≤ 15 minutes. Longer lifetimes SHOULD be paired with a `RevocationPush` (§5.11) subscription so revocations evict tokens in real time rather than at expiry.
- Verifiers SHOULD evict a token immediately upon: receiving a `RevocationPush` covering any cert in the token's chain, ingesting a new `RevocationList` from the issuer, observing a `KeyRotationStatement` (§5.15) for the issuing root, a local policy change, or session end.

**Multi-instance verifiers.** The `session_secret` is private to one verifier *trust boundary*, which may span multiple processes. A load-balanced verifier deployment MUST do one of the following, or streamed turns will be spuriously rejected mid-session on failover: (a) share `session_secret` across replicas through a secret store so any replica can validate any token; (b) route each session consistently to the replica that issued its token, and force full chain re-verification on failover; or (c) treat tokens as instance-local ephemera and accept the re-verification cost whenever a session moves. Sharing the secret does not weaken the design — the boundary that matters is the verifier organization, not the process — but the shared secret then MUST be stored and rotated with the same care as any signing key.

### 5.14 TransactionReceipt

```
{
  "version":              1,
  "transaction_id":       "<string>",
  "created_at":           <unix-seconds>,
  "terms_schema_uri":     "<string>",
  "terms_canonical_json": "<base64>",
  "parties":              [<ReceiptParty>, ...],
  "party_signatures":     [<ReceiptPartySignature>, ...]
}
```

```
ReceiptParty:
  "party_id":     "<string>",
  "role":         "<string>",
  "agent_id":     "<hex>",
  "agent_pub_key": <HybridPublicKey>,
  "proof_bundle":  <ProofBundle>
```

```
ReceiptPartySignature:
  "party_id":  "<string>",
  "signature": <HybridSignature>
```

`TransactionReceipt` is a v1.1 canonical multi-party transaction envelope (ROADMAP, Tamper-evident transaction streams). Ratify does not interpret `terms_canonical_json` — the application owns the business terms schema. `terms_schema_uri` identifies which schema a specialized verifier dispatches on. Ratify guarantees envelope atomicity and party signatures.

The signable bytes for every party's signature (§6.4.7) include `version`, `transaction_id`, `created_at`, `terms_schema_uri`, `terms_canonical_json`, and the full sorted `parties` set (sorted lex by `party_id`; each party projected to `{agent_id, agent_pub_key, party_id, role}` — `proof_bundle` is excluded since it is verified independently). Because every party's signature covers the same sorted party set, adding, removing, or altering any party invalidates every existing signature — there is no partial-valid receipt state.

Generic verifiers MUST: (1) check `version == 1`; (2) check `transaction_id`, `terms_schema_uri`, `terms_canonical_json` non-empty; (3) check party_id uniqueness; (4) check every party has exactly one signature; (5) verify each party's `proof_bundle` via `Verify(ProofBundle)`; (6) check `proof_bundle.agent_id == party.agent_id`; (7) check `proof_bundle.agent_pub_key == party.agent_pub_key`; (8) recompute `TransactionReceiptSignBytes`; (9) verify each `ReceiptPartySignature.signature` over those bytes with that party's `agent_pub_key`. Any step failure fails the entire receipt.

### 5.15 KeyRotationStatement

```
{
  "version":       1,
  "old_id":        "<hex>",
  "old_pub_key":   <HybridPublicKey>,
  "new_id":        "<hex>",
  "new_pub_key":   <HybridPublicKey>,
  "rotated_at":    <unix-seconds>,
  "reason":        "routine" | "compromise_suspected" | "device_lost" | "recovery" | "other",
  "signature_old": <HybridSignature>,
  "signature_new": <HybridSignature>
}
```

`KeyRotationStatement` is a backward-compatible v1.1 signed object. It links an old root key to a new root key so auditors and registries can verify identity continuity across rotations. Both signatures cover identical canonical bytes (§6.4.4). `signature_old` proves the previous key endorsed the rotation; `signature_new` proves possession of the new key.

Verifiers of this object MUST check:

- `version == 1`.
- `old_id == DeriveID(old_pub_key)`.
- `new_id == DeriveID(new_pub_key)`.
- `old_id != new_id`.
- `reason` is one of the listed enum values.
- `signature_old` verifies over `KeyRotationSignBytes(statement)` with `old_pub_key`.
- `signature_new` verifies over `KeyRotationSignBytes(statement)` with `new_pub_key`.

Protocol-level `Verify(ProofBundle)` does not automatically consult key-rotation statements. Registries, audit tools, and applications that validate historical continuity consume this object alongside revocation state.

### 5.16 VerifierContext

Application-supplied inputs for evaluating first-class constraints at verify time. Fields are optional individually, but a cert bearing a constraint whose required context field is absent will be rejected (fail-closed).

| Field | Type | Required by | Semantics |
|---|---|---|---|
| `CurrentLat` | `float64` | `geo_circle`, `geo_polygon`, `geo_bbox` | Agent's current latitude (WGS-84). |
| `CurrentLon` | `float64` | `geo_circle`, `geo_polygon`, `geo_bbox` | Agent's current longitude (WGS-84). |
| `CurrentAltM` | `float64` | `geo_bbox` (when altitude bounds are set) | Agent's current altitude in meters. |
| `HasLocation` | `bool` | `geo_circle`, `geo_polygon`, `geo_bbox` | Must be true for geo constraints to evaluate; false causes `constraint_unverifiable`. |
| `CurrentSpeedMps` | `float64` | `max_speed_mps` | Agent's current velocity in meters per second (SI). |
| `HasSpeed` | `bool` | `max_speed_mps` | Must be true for speed constraints to evaluate; false causes `constraint_unverifiable`. |
| `RequestedAmount` | `float64` | `max_amount` | The transaction amount being authorized. |
| `RequestedCurrency` | `string` | `max_amount` | ISO 4217 currency code of the transaction. Must match the constraint's `currency`. |
| `HasAmount` | `bool` | `max_amount` | Must be true for amount constraints to evaluate; false causes `constraint_unverifiable`. |
| `InvocationsInWindow` | `func(certID string, windowS int64) int` | `max_rate` | Callback returning how many times this cert has been exercised in the most recent `windowS` seconds. Must be non-nil for rate constraints to evaluate; nil causes `constraint_unverifiable`. |
| `RequestedResourceID` | `string` | `resource_path` | Opaque identifier of the resource the operation targets. Compared byte-exactly against the constraint's `resource_id` (§5.7.3). |
| `RequestedPath` | `string` | `resource_path` (when the constraint carries `path_prefix`) | Absolute logical path the operation targets, per the path model in §5.7.3. May be empty for whole-resource operations; a `path_prefix`-bearing constraint evaluated against an empty `RequestedPath` fails `constraint_unverifiable`. |
| `HasResource` | `bool` | `resource_path` | Must be true for resource constraints to evaluate; false causes `constraint_unverifiable`. When true, `RequestedResourceID` MUST be non-empty. |

Constraint evaluation proves that the verifier's decision was consistent with the context it supplied — it does not prove that the supplied context was true in the world. See §15.7 for what constraints do and do not attest. For `resource_path` this caveat is load-bearing: the adapter supplying `RequestedResourceID` and `RequestedPath` asserts what the operation targets, and the execution layer must confine the operation to what was asserted (§5.7.3, §15.7).

### 5.17 VerifyOptions

Controls what the verifier checks beyond the cryptographic basics. Passed as the second argument to `Verify()`.

| Field | Type | Default | Semantics |
|---|---|---|---|
| `RequiredScope` | `string` | `""` (skip scope check) | Must be present in the effective scope (chain intersection) for the proof to be valid. Empty string skips scope checking. |
| `IsRevoked` | `func(certID string) bool` | `nil` (no revocation check) | Legacy v1 revocation closure. Called for each cert ID during verification. Return true if the cert has been revoked. Superseded by `Revocation` (§17.1); if both are set the provider wins. |
| `Revocation` | `RevocationProvider` | `nil` (no revocation check) | Pluggable revocation provider (§17.1). Returns `(bool, error)`. A non-nil error fails the bundle as `revocation_error` (fail-closed). Takes precedence over `IsRevoked`. |
| `ForceRevocationCheck` | `bool` | `false` | When true, signals the verifier to query for the freshest revocation state. When true and both `IsRevoked` and `Revocation` are nil, the verifier returns `force_revocation_no_callback`. |
| `Now` | `time.Time` | `time.Now()` | Overrides the current time for testing. Zero value uses wall clock. |
| `SessionContext` | `[]byte` | `nil` | Verifier-reconstructed 32-byte v1.1 context that binds a challenge to this verifier/session/request. When set, the bundle MUST carry byte-equal `session_context`; when absent, session-bound bundles are rejected as `session_context_unverifiable`. |
| `Stream` | `*StreamContext` | `nil` | Verifier-tracked stream binding for v1.1 stream-bound bundles. `StreamContext` contains `StreamID` (32 bytes) and `LastSeenSeq` (highest accepted sequence number; 0 means no turns accepted yet). When set, the bundle MUST carry matching `stream_id` and `stream_seq == LastSeenSeq + 1`. When nil, bundles carrying `stream_id` are rejected as `stream_context_unverifiable`. |
| `Context` | `VerifierContext` | zero value | Application inputs for constraint evaluation (§5.16). Zero value is fine for certs that declare no constraints. |
| `Policy` | `PolicyProvider` | `nil` | Advanced policy evaluator hook (§17.2). Evaluated after all cryptographic, temporal, revocation, constraint, and scope checks pass. Deny → `scope_denied`; provider error → `policy_error`. |
| `Audit` | `AuditProvider` | `nil` | Verification audit logging hook (§17.3). Invoked on every `Verify` call (success AND failure). Provider errors are swallowed — audit cannot alter the verdict. |
| `ConstraintEvaluators` | `map[string]ConstraintEvaluator` | `nil` | Extension constraint registry (§17.7). Consulted ONLY for constraint types unknown to the SDK's built-in evaluators. Types without a registered evaluator still fail closed with `constraint_unknown`. |
| `PolicyVerdict` | `*PolicyVerdict` | `nil` | Fast-path cached policy decision (§17.6). When present AND valid (MAC, freshness, scope, context_hash all match), the live `Policy` hook is skipped. Stale verdicts fall back to live policy without failing the bundle. |
| `PolicySecret` | `[]byte` | `nil` | HMAC secret used to verify `PolicyVerdict.MAC`. Required when `PolicyVerdict` is non-nil; otherwise ignored. |
| `AnchorResolver` | `AnchorResolver` | `nil` | Identity-binding resolver (§17.8). When non-nil, the verifier resolves `human_id` → `Anchor` on successful verifications and populates `VerifyResult.Anchor`. Resolver errors are non-fatal. |
| `ChallengeStore` | `ChallengeStore` | `nil` (freshness-only verification) | Issuance-record store that makes verifier-issued challenges single-use (§10 steps 2b and 9b). When absent, replay protection is bounded by challenge freshness alone. When set, the store is consulted without consuming before any signature work (step 2b) and the challenge is atomically consumed after the challenge signature verifies (step 9b); constraint evaluation (step 7f) is deferred until after consumption. Every store failure is normalized to the canonical `unknown_challenge` result — store-provided error detail MUST NOT reach the public response. |

---

## 6. Canonical serialization

Interop-critical. Every implementation MUST produce byte-identical output for the same input, or signatures will not verify across languages.

### 6.1 Base

RFC 8785 (JSON Canonicalization Scheme) with the byte-array convention and the U+2028 / U+2029 deviation listed below.

### 6.2 Required properties

1. **Lex-sorted object keys** (byte order on UTF-8). Applies recursively — including the `ed25519` and `ml_dsa_65` fields inside `HybridPublicKey` / `HybridSignature`, which alphabetize correctly.
2. **No whitespace** between tokens. No trailing newline.
3. **UTF-8** throughout.
4. **Shortest decimal integer representation.** No leading zeros, no exponent. JSON integer fields MUST lie within the IEEE-754 safe-integer range [-(2^53-1), 2^53-1], even where binary signable representations use 64-bit fields; a value outside that range does not survive a double-precision JSON parser. Strict wire decoders reject integers outside this range.
5. **Byte arrays as base64-standard with padding** (`A-Za-z0-9+/=`). Project convention on top of RFC 8785.
6. **No HTML escaping.** `<`, `>`, `&` pass through unmodified.
7. **Minimum string escaping** per RFC 8259 (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and control chars below U+0020 as `\u00XX`).

### 6.3 Mandatory deviation: U+2028 and U+2029

Go's `encoding/json` unilaterally escapes U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) as `\u2028` / `\u2029` with no option to disable. Other-language implementations **MUST apply the same escape** for these two code points. v1 signable field content is constrained to hex, base64, canonical scope strings, and integers — none of which contain these code points in practice — so this is a latent constraint with no live impact on v1 data.

### 6.4 Signable objects

Four JSON signable shapes exist in v1 plus the binary challenge signable. The bytes that get signed (by both algorithm components independently over identical bytes) are the canonical JSON of the following subsets, except for `ChallengeSignable`, which is explicitly binary.

#### 6.4.1 DelegationSignable

All `DelegationCert` fields except `signature`:

```
{
  "cert_id":         <string>,
  "constraints":     [<Constraint>, ...],
  "expires_at":      <int64>,
  "issued_at":       <int64>,
  "issuer_id":       <string>,
  "issuer_pub_key":  <HybridPublicKey>,
  "scope":           [<string>, ...],
  "subject_id":      <string>,
  "subject_pub_key": <HybridPublicKey>,
  "version":         <int>
}
```

The alphabetical key order above is the canonical order; enforce it via your canonicalizer (sort keys lexicographically). `constraints` is always serialized as an array (`[]` when empty), never as `null` and never absent.

#### 6.4.2 ChallengeSignable (NOT JSON)

The bytes signed to produce `ProofBundle.challenge_sig` are the raw binary concatenation:

```
challenge_bytes || big-endian uint64(challenge_at)
```

40 bytes total for a 32-byte challenge. This is not JSON; it is an explicit binary format chosen to avoid JSON overhead on a per-interaction path. Both hybrid components sign these same 40 bytes.

For a v1.1 session-bound bundle, append the optional 32-byte `session_context`:

```
challenge_bytes || big-endian uint64(challenge_at) || session_context
```

That produces 72 bytes total for a 32-byte challenge. Verifiers that require session binding provide their reconstructed `VerifyOptions.session_context`; they MUST reject bundles with no `session_context`, a non-32-byte `session_context`, or a value that does not match the verifier's reconstructed context. Verifiers that do not provide a session context continue to accept legacy unbound bundles, but MUST reject session-bound bundles because they cannot reconstruct what was signed.

For a v1.1 stream-bound bundle, append the 32-byte `stream_id` and the 8-byte big-endian `stream_seq` after the optional `session_context`:

```
challenge_bytes || big-endian uint64(challenge_at) || [session_context] || stream_id || big-endian int64(stream_seq)
```

That produces 80 bytes for a stream-only bundle, or 112 bytes when both session- and stream-bound. The four allowed signable lengths for a 32-byte challenge — 40 (legacy), 72 (session-only), 80 (stream-only), 112 (both) — are unambiguously distinct, so the verifier reconstructs the signable from the bundle's populated fields. `stream_seq` is encoded as unsigned in two's-complement but MUST be non-negative; the protocol requires ≥1 when `stream_id` is present.

#### 6.4.3 RevocationSignable

```
{
  "issuer_id":     <string>,
  "revoked_certs": [<string>, ...],
  "updated_at":    <int64>
}
```

#### 6.4.4 KeyRotationSignable

All `KeyRotationStatement` fields except `signature_old` and `signature_new`:

```
{
  "new_id":      <string>,
  "new_pub_key": <HybridPublicKey>,
  "old_id":      <string>,
  "old_pub_key": <HybridPublicKey>,
  "reason":      <string>,
  "rotated_at":  <int64>,
  "version":     <int>
}
```

The alphabetical key order above is the canonical order. Both the old key and the new key sign exactly these bytes.

#### 6.4.5 RevocationPushSignable

```
{
  "entries":    [<string>, ...],
  "issuer_id":  <string>,
  "pushed_at":  <int64>,
  "seq_no":     <int64>
}
```

`entries` is always serialized as an array (`[]` when empty), matching the RevocationList convention.

#### 6.4.6 WitnessEntrySignable

```
{
  "entry_data":  <bytes>,       // base64 per project convention
  "prev_hash":   <bytes>,       // base64 per project convention
  "timestamp":   <int64>,
  "witness_id":  <string>
}
```

#### 6.4.7 TransactionReceiptSignable

Every party's signature in a `TransactionReceipt` covers the same canonical bytes:

```
{
  "created_at":          <int64>,
  "parties":             [<ReceiptPartySignable>, ...],
  "terms_canonical_json": <bytes>,        // base64 per project convention
  "terms_schema_uri":    <string>,
  "transaction_id":      <string>,
  "version":             <int>
}
```

```
ReceiptPartySignable:
{
  "agent_id":     <string>,
  "agent_pub_key": <HybridPublicKey>,
  "party_id":      <string>,
  "role":          <string>
}
```

The `parties` array MUST be sorted by `party_id` (lex-order) before canonicalization. `party_id` values MUST be unique. `proof_bundle` and `party_signatures` are excluded. Because the full sorted party set is inside every party's signable bytes, altering any party invalidates every existing party signature.

#### 6.4.8 SessionTokenSignable

The bytes HMACed to produce `SessionToken.mac`:

```
{
  "agent_id":      <string>,
  "agent_pub_key": <HybridPublicKey>,
  "chain_hash":    <bytes>,              // base64 per project convention
  "granted_scope": [<string>, ...],      // lex-sorted
  "human_id":      <string>,
  "issued_at":     <int64>,
  "session_id":    <string>,
  "valid_until":   <int64>,
  "version":       <int>
}
```

#### 6.4.9 OperationContextBytes and SessionContextBytes (NOT JSON)

The canonical constructions behind the 32-byte `session_context` binding (§5.8). Both are raw binary, domain-separated, and length-prefixed — NOT JSON. Length prefixes exist because raw concatenation is ambiguous (`"ab" || "c"` and `"a" || "bc"` produce identical bytes); domain tags exist so a hash computed for one construction can never collide with the other or with any future construction.

Notation: `lp(x)` = big-endian uint64 byte-length of `x`, followed by the bytes of `x`. Strings encode as UTF-8, and implementations MUST reject ill-formed text — invalid UTF-8 byte sequences, lone UTF-16 surrogates — rather than replace it (a silent U+FFFD substitution would make malformed input collide with a literal replacement character) or pass it through. Rejection of ill-formed input is distinct from Unicode normalization, which these constructions deliberately do not perform. Absent fields encode as `lp("")` (an 8-byte zero prefix) — every field position is always present, so no field arrangement is ambiguous.

**OperationContextBytes** binds the specific action a presentation authorizes:

```
operation_context_bytes =
  "ratify/operation-context/v1"       // 27 ASCII bytes, raw domain tag
  || lp(required_scope)               // scope the action requires
  || lp(operation)                    // action/operation type (e.g. "git.push", "tool.invoke")
  || lp(resource_id)                  // target resource identity
  || lp(requested_path)               // path within the resource
  || lp(payload_digest)               // empty, or exactly 32 bytes: SHA-256 of the
                                      // canonical request payload, where one exists

request_hash = SHA-256(operation_context_bytes)     // 32 bytes
```

`payload_digest` MUST be empty or exactly 32 bytes. Which fields are populated is deployment-defined; the construction is total over empty fields, so `request_hash` is always well-defined.

**SessionContextBytes** binds the session a presentation belongs to, and — through `request_hash` — the operation it authorizes:

```
session_context_bytes =
  "ratify/session-context/v1"         // 25 ASCII bytes, raw domain tag
  || lp(verifier_id)                  // the verifier's identity (e.g. its public key ID)
  || lp(workspace_id)
  || lp(agent_id)
  || lp(session_id)
  || lp(invocation_id)
  || lp(request_hash)                 // exactly 32 bytes — from OperationContextBytes

session_context = SHA-256(session_context_bytes)    // 32 bytes
```

`request_hash` MUST be exactly 32 bytes. A deployment with no operation-specific inputs derives it from an all-empty operation context — still well-defined, still domain-separated. Binding the session but not the operation would let an intermediary attach a valid proof to the wrong action inside the right session; the two-layer construction closes that.

The resulting 32-byte `session_context` is what rides in the `ProofBundle` (§5.8), is covered by the challenge signing bytes (§6.4.2), and is compared by the verifier (`session_context_mismatch` on any difference). Verification receipts and audit records bind this hash, never the preimage — the preimage may contain identifiers a receipt should not carry.

These constructions are RECOMMENDED for all session-bound deployments and REQUIRED by the Middleware Custody Profile (§15.2.1).

### 6.5 Reference API

The Go reference implementation exposes the following public functions, grouped by category.

**Canonicalization:**

- `CanonicalJSON(any) ([]byte, error)` — the canonicalizer; for interop audit.

**Keygen:**

- `GenerateHybridKeypair() (HybridPublicKey, HybridPrivateKey, error)` — generate a fresh hybrid keypair from random seeds.
- `HybridKeypairFromSeeds(edSeed, mlSeed [32]byte) (HybridPublicKey, HybridPrivateKey, error)` — deterministic keypair from explicit seeds (used by fixtures).
- `GenerateHumanRootKeypair() (*HumanRoot, HybridPrivateKey, error)` — generate a human root identity and keypair.
- `GenerateAgentKeypair(name, agentType string) (*AgentIdentity, HybridPrivateKey, error)` — generate an agent identity and keypair.
- `DeriveID(HybridPublicKey) string` — compute the 16-byte hex identity from a hybrid public key (§7).
- `GenerateChallenge() ([]byte, error)` — generate a cryptographically random 32-byte challenge.

**Signing:**

- `IssueDelegation(*DelegationCert, HybridPrivateKey) error` — hybrid-sign a delegation cert in place.
- `SignChallenge([]byte, int64, HybridPrivateKey) (HybridSignature, error)` — sign a legacy unbound challenge.
- `SignChallengeWithSessionContext([]byte, int64, []byte, HybridPrivateKey) (HybridSignature, error)` — sign a session-bound challenge.
- `SignChallengeWithStream([]byte, int64, []byte, []byte, int64, HybridPrivateKey) (HybridSignature, error)` — sign a stream-bound challenge (optional session context + stream_id + stream_seq).
- `IssueRevocationList(*RevocationList, HybridPrivateKey) error` — hybrid-sign a revocation list in place.
- `IssueRevocationPush(*RevocationPush, HybridPrivateKey) error` — hybrid-sign a revocation push in place.
- `IssueKeyRotationStatement(*KeyRotationStatement, oldPriv, newPriv HybridPrivateKey) error` — dual-sign a key rotation statement.
- `IssueWitnessEntry(*WitnessEntry, HybridPrivateKey) error` — hybrid-sign a witness entry in place.
- `IssueSessionToken(*ProofBundle, VerifyResult, string, int64, int64, []byte) (*SessionToken, error)` — issue a session token after successful verification.
- `SignTransactionReceiptParty(*TransactionReceipt, string, HybridPrivateKey) (ReceiptPartySignature, error)` — sign a transaction receipt on behalf of a party.

**Signable bytes:**

- `DelegationSignBytes(*DelegationCert) ([]byte, error)` — §6.4.1 applied to a cert.
- `ChallengeSignBytes([]byte, int64) []byte` — legacy unbound form, §6.4.2.
- `ChallengeSignBytesWithSessionContext([]byte, int64, []byte) []byte` — session-bound form, §6.4.2.
- `ChallengeSignBytesWithStream([]byte, int64, []byte, []byte, int64) []byte` — stream-bound form, §6.4.2. Accepts an optional `session_context` (nil or 32 bytes) and the required `stream_id` (32 bytes) + `stream_seq` (≥1).
- `RevocationSignBytes(*RevocationList) ([]byte, error)` — §6.4.3.
- `KeyRotationSignBytes(*KeyRotationStatement) ([]byte, error)` — §6.4.4.
- `RevocationPushSignBytes(*RevocationPush) ([]byte, error)` — §6.4.5.
- `WitnessEntrySignBytes(*WitnessEntry) ([]byte, error)` — §6.4.6.
- `TransactionReceiptSignBytes(*TransactionReceipt) ([]byte, error)` — §6.4.7.
- `SessionTokenSignBytes(*SessionToken) ([]byte, error)` — §6.4.8.
- `OperationContextBytes(OperationContext) ([]byte, error)` — §6.4.9 operation-context preimage; `OperationContext` carries `RequiredScope`, `Operation`, `ResourceID`, `RequestedPath`, `PayloadDigest`.
- `OperationContextHash(OperationContext) ([]byte, error)` — the 32-byte `request_hash` over the §6.4.9 operation-context bytes.
- `SessionContextBytes(SessionContextInputs) ([]byte, error)` — §6.4.9 session-context preimage; `SessionContextInputs` carries `VerifierID`, `WorkspaceID`, `AgentID`, `SessionID`, `InvocationID`, `RequestHash`.
- `BuildSessionContext(SessionContextInputs) ([]byte, error)` — the 32-byte `session_context` over the §6.4.9 session-context bytes, ready for `VerifyOptions.SessionContext` and challenge signing.

**Verification:**

- `Verify(*ProofBundle, VerifyOptions) VerifyResult` — full chain verification (§10).
- `VerifyDelegationSignature(*DelegationCert) error` — verify a single cert's hybrid signature.
- `VerifyChallengeSignature([]byte, int64, HybridSignature, HybridPublicKey) error` — verify a legacy unbound challenge signature.
- `VerifyChallengeSignatureWithSessionContext([]byte, int64, []byte, HybridSignature, HybridPublicKey) error` — verify a session-bound challenge signature.
- `VerifyChallengeSignatureWithStream([]byte, int64, []byte, []byte, int64, HybridSignature, HybridPublicKey) error` — verify a stream-bound challenge signature.
- `VerifyRevocationList(*RevocationList, HybridPublicKey) error` — verify a revocation list's signature.
- `VerifyRevocationPush(*RevocationPush, HybridPublicKey) error` — verify a revocation push's signature.
- `VerifyKeyRotationStatement(*KeyRotationStatement) error` — verify both signatures on a key rotation statement.
- `VerifyWitnessEntry(*WitnessEntry, HybridPublicKey) error` — verify a witness entry's signature.
- `VerifySessionToken(*SessionToken, []byte, time.Time) error` — verify a session token's HMAC and temporal validity.
- `VerifyTransactionReceipt(*TransactionReceipt, VerifyReceiptOptions) TransactionReceiptResult` — full atomic receipt verification (§5.14).
- `VerifyStreamedTurn(*SessionToken, []byte, []byte, int64, HybridSignature, []byte, []byte, int64, time.Time) VerifyResult` — DEPRECATED positional streamed-turn verification (presentation checks only; cannot enforce scope, single-use, or verifier-side bindings). Retained for compatibility; use `VerifyStreamedTurnWithOptions`.
- `VerifyStreamedTurnWithOptions(*SessionToken, []byte, StreamedTurn, StreamedVerifyOptions) VerifyResult` — options-object streamed-turn verification (§5.13). `StreamedTurn` carries the presented challenge, timestamp, signature, and optional session/stream bindings. `StreamedVerifyOptions` carries exactly the verifier-side controls that apply to a token presentation: `RequiredScope` (checked against `token.granted_scope`), `ChallengeStore` (single-use; validated before the per-turn challenge signature, consumed after it), `SessionContext`, `Stream` (caller-owned snapshot — see §5.13), and `Now`.

**Scope:**

- `ExpandScopes([]string) []string` — expand wildcards to non-sensitive canonical scopes.
- `IntersectScopes(...[]string) []string` — compute the effective scope across a chain of scope lists.
- `ValidateScopes([]string) error` — reject scopes outside the canonical vocabulary and `custom:` extensions.
- `HasScope([]string, string) bool` — check whether a required scope is present in a granted set.
- `IsSensitive(string) bool` — return true if a scope requires explicit grant (never part of wildcard expansion).

All signable helpers are verified against the committed test vectors on every test run. Performance numbers for the full Verify() path are committed to [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## 7. Identifier derivation

```
id = hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])
```

where `||` denotes byte concatenation of the raw 32-byte Ed25519 public key followed by the raw 1952-byte ML-DSA-65 public key. The SHA-256 output is truncated to the first 16 bytes and rendered as lowercase hex. 128-bit collision space is sufficient for agent/human identifiers at expected scale; birthday bound is 2^64.

---

## 8. Cryptography

### 8.1 Hybrid signing

For each signable byte sequence `msg`, the signer independently produces:

- `ed25519_sig = Ed25519.Sign(ed25519_priv, msg)` — 64 bytes, per RFC 8032.
- `ml_dsa_65_sig = ML-DSA-65.Sign(ml_dsa_65_priv, msg)` — 3309 bytes, per FIPS 204.

Both are emitted into `HybridSignature.ed25519` and `HybridSignature.ml_dsa_65` respectively.

### 8.2 Hybrid verification

To verify a `HybridSignature` against a `HybridPublicKey` over the same `msg`:

1. `Ed25519.Verify(pub.ed25519, msg, sig.ed25519)` MUST return true.
2. `ML-DSA-65.Verify(pub.ml_dsa_65, msg, sig.ml_dsa_65)` MUST return true.
3. If either fails, the hybrid verification fails. **Fail-closed.**

### 8.3 Determinism

v1 uses **deterministic** ML-DSA-65 signing (FIPS 204 §3.4 without hedged randomization). Rationale:

- Reproducible test vectors and audit trails.
- Same security properties as Ed25519's determinism under the lattice assumptions.
- A future version MAY add a hedged-randomization mode for side-channel hardening in hostile environments; v1 does not.

### 8.4 Key generation

Keypair generation takes two independent 32-byte seeds:

- `ed25519_seed` — expanded via SHA-512 per RFC 8032 §5.1.5.
- `ml_dsa_65_seed` — expanded via the key-gen procedure in FIPS 204 §5.1.

Implementations MAY source seeds from any cryptographically secure RNG. Fixtures use deterministic byte-pattern seeds (32 bytes of a repeated byte value) so fixtures reproduce byte-for-byte across invocations.

### 8.5 Why hybrid, and not post-quantum-only

Pure ML-DSA-65 would be a single point of cryptographic failure against future analytic advances on lattice problems. Pure Ed25519 is known to fall to Shor's algorithm on a sufficiently large quantum computer. Hybrid composition — both signatures must verify — means an adversary must simultaneously break two independent cryptographic families, with independent mathematical foundations, to forge a signature. This is strictly stronger than either alone, and is the posture recommended by CNSA 2.0 and BSI for the post-quantum transition period.

---

## 9. Scope vocabulary (v1)

54 canonical scope strings organized by domain, plus 14 wildcards, plus one extension pattern (`custom:…`) for application-specific scopes outside the canonical vocabulary. Implementations MUST reject scopes that are not canonical, not a wildcard, and not a `custom:` extension — at issuance via `ValidateScopes`, and at verification: the verifier rejects any cert granting invalid vocabulary with `invalid_scope` (§5.9, §10 step 7.a2) before any effective-scope arithmetic.

The vocabulary covers both software agents (meetings, comms, files, transactions, execution, generation) and embodied agents (physical actions, robots, drones, vehicles, infrastructure, generic actuation). Ratify is channel-agnostic by construction (§3 principle 6) — the same cert/bundle/verify semantics authorize a software agent in a video meeting and a drone at a delivery address.

### 9.1 Canonical scopes

**Meeting**

| Scope | Sensitive | Meaning |
|---|---|---|
| `meeting:attend` | | Join a meeting as a participant |
| `meeting:speak` | | Use microphone / audio |
| `meeting:video` | | Use camera / avatar video |
| `meeting:chat` | | Send meeting chat |
| `meeting:share_screen` | | Share screen |
| `meeting:record` | **Yes** | Initiate or manage recording |

**Communication**

| Scope | Sensitive | Meaning |
|---|---|---|
| `comms:message:read` | | Read messages |
| `comms:message:send` | | Send messages |
| `comms:message:delete` | **Yes** | Delete messages |
| `comms:email:read` | | Read email |
| `comms:email:send` | | Send email |
| `comms:email:delete` | **Yes** | Delete email |
| `comms:calendar:read` | | Read calendar |
| `comms:calendar:write` | | Write calendar |

**Files**

| Scope | Sensitive | Meaning |
|---|---|---|
| `files:read` | | Read files |
| `files:write` | **Yes** | Write / modify files |

**Identity**

| Scope | Sensitive | Meaning |
|---|---|---|
| `identity:prove` | | Present Ratify proofs (implicitly granted to all agents) |
| `identity:delegate` | **Yes** | Sub-delegate to another agent (required for A2A sub-delegation) |

**Presence**

| Scope | Sensitive | Meaning |
|---|---|---|
| `presence:represent` | **Yes** | Attend and interact as a direct representative of the principal — other parties may be interacting with this agent as if it were the principal. Covers both non-likeness representatives and full likeness agents. |

`presence:represent` does NOT imply any other scope — in particular it does not imply `identity:prove`; issuers grant both explicitly when both are needed. Scope lists are literal: there is no implication table. It is distinct from `generate:deepfake` (content generation, not real-time representation) and from `identity:delegate` (key delegation). There is deliberately no `presence:*` wildcard — sensitive scopes never ride wildcards, and representation must always be granted explicitly.

*Disclosure (non-normative):* verifiers that accept a proof bundle carrying `presence:represent` are expected to surface the representation relationship to the other participants in the interaction. This disclosure is platform policy, not a protocol constraint — the protocol cannot verify at verify time that disclosure occurred. If disclosure ever requires protocol-level attestation, the receipt/audit layer (§5.14, §17.5) is the intended mechanism.

**Transactions** *(core to the "transaction horizon" thesis — §1.5)*

| Scope | Sensitive | Meaning |
|---|---|---|
| `transact:purchase` | | Buy goods / services on behalf of the principal |
| `transact:sell` | | Sell goods / services on behalf of the principal |
| `payments:send` | | Initiate an outbound payment |
| `payments:receive` | | Collect a payment on behalf |
| `payments:authorize` | **Yes** | Authorize movement of funds from an account beyond standard purchase limits |

**Contracts**

| Scope | Sensitive | Meaning |
|---|---|---|
| `contract:read` | | Read existing agreements |
| `contract:sign` | **Yes** | Enter into a binding agreement on someone's behalf |

**Data** *(structured application data, distinct from files)*

| Scope | Sensitive | Meaning |
|---|---|---|
| `data:read` | | Read data records |
| `data:write` | **Yes** | Create or modify data records |
| `data:delete` | **Yes** | Delete data records |
| `data:export` | **Yes** | Bulk export — data-exfiltration concern |
| `data:share` | | Share data with a third party |

**Execute**

| Scope | Sensitive | Meaning |
|---|---|---|
| `execute:tool` | | Invoke an external tool / API on the principal's behalf (e.g., MCP tool calls) |
| `execute:code` | **Yes** | Execute arbitrary code on the principal's compute resources |

**Generate** *(AI content generation on someone's behalf)*

| Scope | Sensitive | Meaning |
|---|---|---|
| `generate:content` | | Generate text / image / audio / video content |
| `generate:deepfake` | **Yes** | Generate content specifically intended to imitate a real person. Sensitive by policy so any such generation creates an auditable authorization trail. |

**Physical** *(the agent enters, leaves, or manipulates physical space — first-class in v1 so embodied agents have canonical vocabulary from day one)*

| Scope | Sensitive | Meaning |
|---|---|---|
| `physical:enter` | | Enter a physical zone. Usually paired with a `geo_polygon` / `geo_circle` constraint. |
| `physical:exit` | | Leave a physical zone. |
| `physical:actuate` | **Yes** | Activate a physical actuator — valve, lock, door, latch. Anything that moves matter in the world. |
| `physical:manipulate` | **Yes** | Manipulate physical objects (pick-and-place, lift, rotate). Distinct from actuate: manipulation targets objects, actuation targets fixtures. |

**Robot**

| Scope | Sensitive | Meaning |
|---|---|---|
| `robot:operate` | | Operate a robotic platform (power on, hold, idle motion). The umbrella permission for embodied robots. |
| `robot:move` | | Autonomous locomotion — the robot may move in space. Pair with a geo constraint to bound where. |
| `robot:interact` | | Interact with humans or objects in the environment (touch, grasp, gesture). High-stakes robot actions should compose this with `physical:manipulate` for explicit consent. |

**Drone**

| Scope | Sensitive | Meaning |
|---|---|---|
| `drone:fly` | **Yes** | Operate a drone under active flight. Nearly always paired with geo + altitude + `time_window` constraints. |
| `drone:deliver` | | Conduct a delivery mission. |
| `drone:capture` | | Capture imagery / telemetry data during a flight. |

**Vehicle**

| Scope | Sensitive | Meaning |
|---|---|---|
| `vehicle:operate` | **Yes** | Operate a vehicle — cars, trucks, watercraft, aircraft other than drones. `max_speed_mps` and geo constraints strongly recommended. |
| `vehicle:transport` | | Transport a named passenger or payload. |
| `vehicle:charge` | | Access charging infrastructure / refueling. |

**Infrastructure**

| Scope | Sensitive | Meaning |
|---|---|---|
| `infrastructure:monitor` | | Read sensor values and system state from a piece of infrastructure (HVAC, power, access logs). Read-only. |
| `infrastructure:control` | **Yes** | Modify infrastructure state — HVAC setpoints, breaker state, door policy, etc. |
| `infrastructure:access` | **Yes** | Unlock / grant entry to a restricted facility. Pair with geo + `time_window` constraints. |

**Actuate** *(generic actuator operations — every member is sensitive; no wildcard expansion, every grant must be explicit)*

| Scope | Sensitive | Meaning |
|---|---|---|
| `actuate:valve` | **Yes** | Generic valve operation. |
| `actuate:motor` | **Yes** | Generic motor / actuator operation. |
| `actuate:switch` | **Yes** | Generic switch / relay operation. |

### 9.2 Wildcards

Wildcards expand ONLY to non-sensitive scopes in their group. Sensitive scopes always require explicit grant. Custom scopes (§9.4) are never part of a wildcard expansion.

| Wildcard | Expands to |
|---|---|
| `meeting:*` | `meeting:attend`, `meeting:speak`, `meeting:video`, `meeting:chat`, `meeting:share_screen` |
| `comms:message:*` | `comms:message:read`, `comms:message:send` |
| `comms:email:*` | `comms:email:read`, `comms:email:send` |
| `comms:*` | the 6 non-sensitive `comms:*` scopes |
| `transact:*` | `transact:purchase`, `transact:sell` |
| `payments:*` | `payments:send`, `payments:receive` |
| `data:*` | `data:read`, `data:share` |
| `execute:*` | `execute:tool` |
| `generate:*` | `generate:content` |
| `physical:*` | `physical:enter`, `physical:exit` (sensitive actuate/manipulate excluded) |
| `robot:*` | `robot:operate`, `robot:move`, `robot:interact` |
| `drone:*` | `drone:deliver`, `drone:capture` (sensitive `drone:fly` excluded) |
| `vehicle:*` | `vehicle:transport`, `vehicle:charge` (sensitive `vehicle:operate` excluded) |
| `infrastructure:*` | `infrastructure:monitor` (both sensitive scopes excluded) |

### 9.3 Effective scope (chain intersection)

For a chain of depth N, the **effective scope** a presenter may exercise is:

```
effective = expand(certs[0].scope) ∩ expand(certs[1].scope) ∩ … ∩ expand(certs[N-1].scope)
```

The required scope in a verifier's options MUST be present in `effective` (after wildcard expansion) for verification to succeed. This is the privilege-escalation defense: an intermediate cannot pass through a scope it did not itself receive. Implementations MUST sort the effective-scope output lexicographically.

### 9.4 Custom scope extensions

For scopes outside the canonical vocabulary, Ratify defines one extension pattern:

**Any scope string starting with `custom:` followed by at least one additional character is a valid scope.**

Rules:

- `validate_scopes` accepts `custom:…` scopes.
- `expand_scopes` passes `custom:…` scopes through unchanged — they are never part of a wildcard expansion, and there is no `custom:*` wildcard.
- `is_sensitive` returns false for `custom:…` scopes by default. Applications that want a custom scope to be treated as sensitive MUST enforce that at the application policy layer (pre-sign user confirmation, extra verification, etc.) — the protocol does not distinguish.
- `intersect_scopes` treats `custom:…` like any other scope: a chain with `custom:acme:x` in every cert's scope list produces a chain intersection that includes `custom:acme:x`.

Suggested naming convention: `custom:<vendor-or-app>:<resource>:<action>`, e.g. `custom:acme:inventory:read`. This is a convention; the protocol does not enforce structure inside `custom:`.

When to use custom scopes:
- Application-specific actions not covered by the canonical vocabulary.
- Private scopes for internal use within an organization's tenant.
- Experimental scopes under evaluation before proposing a canonical addition.

When NOT to use custom scopes:
- For actions that clearly fit the canonical vocabulary. Use the canonical scope instead.
- For anything a third-party verifier outside your ecosystem needs to understand. Verifiers are not required to know any semantics attached to `custom:…` strings; all they know is "this scope exists and is or is not in the effective set."

If a custom scope becomes widely adopted across implementations, propose it for the canonical vocabulary via a PR to this spec (see [`docs/RELEASES.md`](docs/RELEASES.md) §8.2).

### 9.5 Reserved prefixes

Future versions MAY define additional extension patterns. To avoid collision, these prefixes are reserved and MUST NOT be used by applications as custom scope roots:

- `x-<vendor>:…` — reserved for future vendor-registered namespaces.
- `urn:…` — reserved for future URN-style scope identifiers.

v1 implementations MUST reject scopes with these prefixes as "unknown scope" — treating them as out-of-vocabulary to reserve the namespace.

### 9.6 Physical-world and embodied use cases

Physical-world and embodied scopes (`physical:*`, `robot:*`, `drone:*`, `vehicle:*`, `infrastructure:*`, `actuate:*`) are **canonical in v1** — see the tables in §9.1. The same cert/bundle/verify semantics that authorize a software agent in a video meeting authorize an AI agent controlling a drone, a warehouse robot, an autonomous vehicle, a surgical robot, or any other embodied system.

For location, time-of-day, speed, amount, and rate bounds that real deployments need (e.g., *"authorized to drive at speeds up to 35 mph within this geofence until 17:00"*), use first-class `Constraint` objects on the `DelegationCert` (§5.7.1). Constraints are evaluated deterministically by the verifier against caller-supplied context, with the same fail-closed semantics as signature and scope checks.

Examples of physical-agent cert construction are given in §11 (usage patterns) and in the constraint-bearing fixture set (`testvectors/v1/constraint_geo_circle_*.json`, `constraint_geo_polygon_inside.json`, `constraint_geo_bbox_denied.json`, `constraint_time_window_*.json`, `constraint_max_speed_mps_denied.json`, `constraint_max_amount_exceeds.json`, `constraint_max_rate_denied.json`).

---

## 10. Verifier algorithm

Input: a `ProofBundle` and a `VerifyOptions` (§5.17) containing optional required scope, current time, revocation callback, force-fresh revocation flag, session context, stream context, challenge store (single-use enforcement; absent = freshness-only verification), and verifier context for constraint evaluation.

```
1. Basic structure checks:
   - delegations is non-empty                      (else: no_delegations)
   - len(delegations) <= MAX_DELEGATION_CHAIN_DEPTH (else: chain_too_deep)
   - challenge is non-empty                        (else: no_challenge)

2. Session context validation:
   - if bundle.session_context is present, len(session_context) == 32
                                                    (else: invalid_session_context)
   - if VerifyOptions.session_context is present, len(session_context) == 32
                                                    (else: invalid_session_context)
   - if VerifyOptions.session_context is present, bundle.session_context MUST be
     present and byte-equal to it                   (else: missing_session_context
                                                     or session_context_mismatch)
   - if bundle.session_context is present but VerifyOptions.session_context is
     absent: reject                                 (else: session_context_unverifiable)

2b. Challenge single-use pre-check (only if VerifyOptions.challenge_store
    is present):
   - The presented challenge MUST resolve, WITHOUT being consumed, to an
     unexpired, unconsumed issuance record whose session binding matches
     VerifyOptions.session_context             (else: unknown_challenge)
   - The record is not touched on failure: a presentation under the wrong
     session binding MUST NOT consume the legitimate record.
   - Every store failure — missing, expired, consumed, wrong binding, or
     store backend error — maps to the same public result:
     `unknown_challenge` with the canonical detail (see "Challenge
     single-use" below). Store-provided error detail MUST NOT be exposed.

3. Stream binding validation:
   - if bundle.stream_id is present, len(stream_id) == 32
                                                    (else: invalid_stream_id)
   - if bundle.stream_id is absent, stream_seq MUST be 0
                                                    (else: invalid_stream_seq)
   - if bundle.stream_id is present, stream_seq MUST be >= 1
                                                    (else: invalid_stream_seq)
   - if VerifyOptions.stream is present:
       - VerifyOptions.stream.stream_id must be 32 bytes
                                                    (else: invalid_stream_id)
       - bundle.stream_id MUST be present           (else: missing_stream_context)
       - bundle.stream_id MUST be byte-equal to VerifyOptions.stream.stream_id
                                                    (else: stream_id_mismatch)
       - bundle.stream_seq MUST be > VerifyOptions.stream.last_seen_seq
                                                    (else: stream_seq_replay)
       - bundle.stream_seq MUST == VerifyOptions.stream.last_seen_seq + 1
                                                    (else: stream_seq_skip)
   - if bundle.stream_id is present but VerifyOptions.stream is absent:
     reject                                         (else: stream_context_unverifiable)

4. Agent public key validation:
   - agent_pub_key.ed25519 length   == 32           (else: invalid_agent_key)
   - agent_pub_key.ml_dsa_65 length == 1952         (else: invalid_agent_key)

5. Agent-subject binding:
   - agent_pub_key == delegations[0].subject_pub_key (both components equal)
                                                    (else: key_mismatch)
   - agent_id == delegations[0].subject_id          (else: id_mismatch)
   - Derive human_id = delegations[N-1].issuer_id for use in success and
     failure paths (expired, revoked).

6. Force-revocation check enforcement:
   - if VerifyOptions.force_revocation_check is true, VerifyOptions.is_revoked
     MUST be non-nil                                (else: force_revocation_no_callback)

7. Per-cert checks — for each cert in delegations (index 0 to N-1):
   a. cert.version == PROTOCOL_VERSION              (else: version_mismatch)
   a2. Every scope in cert.scope is canonical, a wildcard, or a custom:
       extension (§9)                               (else: invalid_scope)
   b. now <= cert.expires_at                        (else: expired)
   c. now >= cert.issued_at                         (else: not_yet_valid)
   d. if is_revoked(cert.cert_id): reject           (status: revoked)
   e. Hybrid signature verification:
        Ed25519.Verify(cert.issuer_pub_key.ed25519,
                       DelegationSignBytes(cert),
                       cert.signature.ed25519)          == true
        AND
        ML-DSA-65.Verify(cert.issuer_pub_key.ml_dsa_65,
                         DelegationSignBytes(cert),
                         cert.signature.ml_dsa_65)      == true
                                                    (else: bad_signature)
   f. Constraint evaluation against VerifierContext (§5.16):
        CONDITIONALLY DEFERRED: when VerifyOptions.challenge_store is
        present, this step is NOT evaluated here — it runs inside step 9b,
        after the challenge is consumed, so a denial outcome cannot be
        probed without spending the challenge. When no store is present,
        it runs here as written.
        Each constraint on the cert evaluates against the caller-supplied
        VerifierContext. Three distinct failure outcomes:
          - constraint_denied: the constraint evaluated false (e.g. agent
            outside geo-fence, amount exceeds max, speed too high).
          - constraint_unverifiable: a constraint requires a context field
            the caller did not supply (e.g. HasLocation=false for a
            geo_circle). Fail-closed.
          - constraint_unknown: the constraint `type` is not in the verifier's
            supported set. Fail-closed — prevents silently ignoring an
            unknown type that a future verifier version might enforce.
   g. If i+1 < N (chain linkage):
        delegations[i].issuer_id == delegations[i+1].subject_id
                                                    (else: broken_chain)
        delegations[i].issuer_pub_key == delegations[i+1].subject_pub_key
                                                    (else: broken_chain_keys)
   h. Sub-delegation gate (if i+1 < N):
        delegations[i+1].scope MUST contain `identity:delegate`
                                                    (else: delegation_not_authorized)
        This prevents an intermediate from forking a new chain without
        explicit sub-delegation privilege from its parent. Because
        `identity:delegate` is sensitive (§9.1), wildcards never grant it
        implicitly — the grant must be explicit.

8. Challenge freshness:
   - 0 <= (now - challenge_at) <= CHALLENGE_WINDOW_SECONDS
                                                    (else: stale_challenge)

9. Challenge signature (hybrid):
   - Reconstruct the signable bytes from challenge, challenge_at, optional
     session_context, and optional stream_id/stream_seq per §6.4.2.
   - Both Ed25519 AND ML-DSA-65 verify over the reconstructed signable
     against agent_pub_key.{ed25519, ml_dsa_65}.
                                                    (else: bad_challenge_sig)

9b. Atomic challenge consumption + deferred constraint evaluation (only if
    VerifyOptions.challenge_store is present):
   - Atomically consume the issuance record: of two concurrent
     presentations of one challenge, at most one may succeed
                                                    (else: unknown_challenge)
   - Every consume failure maps to the same public `unknown_challenge`
     result with the canonical detail; store-provided error detail MUST
     NOT be exposed.
   - Then run constraint evaluation (step 7f) for every cert, deferred
     from the per-cert loop: a cryptographically valid presentation
     spends its challenge even when a constraint subsequently denies it.

10. Scope check (if required_scope is set):
    - required_scope ∈ IntersectScopes(certs[0].scope, …, certs[N-1].scope)
                                                    (else: scope_denied)

11. Success:
    Return {
      valid: true,
      human_id: delegations[N-1].issuer_id,
      agent_id: bundle.agent_id,
      granted_scope: <effective intersection, lex-sorted>,
      identity_status: "authorized_agent"
    }
```

**Consistency requirement:** on every failure path that can identify the root (`expired`, `revoked`), `human_id` MUST be `delegations[N-1].issuer_id`. The last cert's issuer is always the human root, whether verification succeeds or fails.

**Challenge single-use.** A verifier that issues challenges MUST accept each challenge at most once within the freshness window (step 8). Single-use is enforced with an issuance record (a challenge store) consulted at the two points integrated into the algorithm above, in this order:

- Step 2b — before any signature verification, the presented challenge MUST resolve to an unexpired, unconsumed issuance record whose session binding matches the presentation; otherwise the verifier rejects (`unknown_challenge`) without touching the record. A presentation under the wrong session binding MUST NOT consume the legitimate record.
- Step 9b — after the structural, chain, and challenge-signature checks (steps 1–9) pass, the verifier MUST atomically consume the record before evaluating authorization (constraints, scope, policy): of two concurrent presentations of one challenge, at most one may succeed. A malformed or forged presentation therefore never consumes a challenge, while a cryptographically valid presentation consumes it even when authorization is subsequently denied — a denied caller MUST NOT be able to probe authorization outcomes with a single liveness proof. To preserve that property, constraint evaluation (step 7f) is deferred into step 9b when single-use is enforced.

Consuming a record removes it from the store: a store's capacity bounds *pending* (issued, unconsumed, unexpired) challenges, and a consumed challenge frees its slot immediately. A record removed on consumption and a challenge that was never issued produce the same uniform rejection on later presentation.

**Response-level indistinguishability.** The rejection guarantee is scoped to the response: the verifier's public status and error detail MUST be identical whether the presented challenge is missing (never issued), expired, already consumed, or bound to a different session context — one `unknown_challenge` result with one canonical detail string ("challenge was not issued by this verifier or has already been used"). To keep the guarantee under pluggable stores, the verifier MUST normalize every store failure — including custom-store backend errors and, in SDKs where stores can throw, raised exceptions (which MUST be caught and treated as rejection, fail-closed) — to that canonical result. Store-provided error text MUST NOT appear in the public response; implementations MAY log it privately for operations.

This guarantee deliberately does NOT cover timing: step 2b rejects unknown challenges before the (comparatively expensive) hybrid signature checks, so a caller measuring response latency can in principle distinguish "record found" from "record not found." That trade is intentional — the early lookup is what keeps a forged presentation from spending a legitimate record and keeps unknown-challenge floods cheap. Deployments that must also close the timing channel need constant-time-shaped responses at the transport layer; the protocol does not require it.

Verifiers that accept self-issued challenges — the presenting client generates the challenge itself, as in stateless tool-calling integrations — have no issuance record to consume and cannot enforce single-use. For them, freshness (step 8) bounds replay to the challenge window (≤ CHALLENGE_WINDOW_SECONDS) but does not eliminate it; replay protection MUST come from request-level deduplication, session binding (§5.8), or stream sequence numbers (§5.8). Stateless cryptographic verification alone is not replay-safe task acceptance.

---

## 11. Agent-to-agent patterns

Three canonical patterns covered by this spec. All use the same data structures and verifier algorithm; they differ only in chain topology.

### 11.1 Mutual presentation

*When:* Agent A (acting for Alice) interacts with Agent B (acting for Bob), and each side needs to verify the other's authorization.

Both sides emit their own challenges, receive a bundle, and verify independently. No shared secret, no trusted intermediary. See `docs/AGENT_TO_AGENT.md` for a full worked example.

### 11.2 Sub-delegation

*When:* An enterprise tenant admin delegates to a departmental agent, which further delegates to a leaf agent. The effective scope at any depth is the intersection of every hop's grant (§9.3). A party that sub-delegates MUST hold `identity:delegate` scope from its parent.

### 11.3 Transaction receipt

*When:* Two agents conclude a bounded, high-stakes transaction (payment, contract, data exchange). Both sides exchange `HybridSignature`s over application-defined terms (a JSON object whose format is application-specific) and retain the paired signed artifact as a cryptographic receipt. The signature primitive is authoritative; the `terms` schema is outside this spec.

The `TransactionReceipt` envelope is normative as of v1.0.0-alpha.6 (§5.14). [`docs/TRANSACTION_RECEIPTS.md`](docs/TRANSACTION_RECEIPTS.md) provides expanded usage guidance. It is covered by canonical receipt fixtures in `testvectors/v1/`.

See `docs/AGENT_TO_AGENT.md` for detailed sequence diagrams of all three patterns.

---

## 12. Versioning and forward compatibility

- The `version` field on `DelegationCert` is the authoritative protocol version indicator.
- A v1 verifier MUST reject any cert with `version != 1` (`version_mismatch`).
- A future v2 MAY extend `HybridPublicKey` and `HybridSignature` with additional algorithm components (e.g. SLH-DSA for ultra-conservative fallback). The wire format will remain backward-readable; v2 verifiers will accept v1 bundles during a documented migration window.
- No v1 fields are to be omitted or renamed. Extensions requiring new fields or new algorithm components require a version bump.

**Crypto agility.** v1 deliberately fixes the algorithm pair (Ed25519 + ML-DSA-65) rather than negotiating algorithms on the wire — negotiation is itself an attack surface (downgrade attacks), and a fixed pair keeps every verifier byte-compatible. The consequence is that replacing a broken component is a protocol-version event, not a configuration change. If a practical weakness is found in ML-DSA-65 (a young algorithm, FIPS 204 finalized 2024), the migration path is: v2 adds a replacement or third component (e.g. SLH-DSA, whose hash-based security assumptions are independent of both existing components), verifiers dual-accept v1 and v2 bundles during the documented migration window, and issuers re-sign delegations under v2. Until both components of the v1 pair are broken *simultaneously*, previously issued v1 bundles remain unforgeable — that is the point of the hybrid. Deployments with archival needs beyond the v1 lifetime SHOULD anchor long-lived artifacts (receipts, witness chains) so that re-attestation under a future version is possible.

---

## 13. HTTP transport binding (optional but defined)

An implementation MAY expose the following REST endpoints. The bindings are suggested, not required — any transport that carries the JSON objects unchanged is conformant.

```
POST /v1/ratify/challenge
  Response: {"challenge": "<base64>", "expires_at": <unix>, "ttl_seconds": 300}

POST /v1/ratify/verify
  Body:  {"proof_bundle": "<base64-json>", "required_scope": "<scope>"}
  Response: <VerifyResult>

GET /v1/ratify/revocations/{rootId}
  Response: <RevocationList>

GET /v1/ratify/scopes
  Response: {"scopes": [...], "wildcards": {...}, "version": 1}
```

`Content-Type` MUST be `application/json`. Canonical serialization applies only to signable-bytes computation; wire-format JSON at the HTTP layer MAY include whitespace for readability.

### 13.1 Registry read binding (optional)

The registry bootstrap mode of §15.4 needs a lookup contract: given a `human_id`, return the principal's current public key with enough evidence for a verifier to validate key continuity. This binding defines that contract so that **any** registry — the Ratify Verify managed service or a third party — can implement it interchangeably. Like the rest of §13, it is optional but defined: a deployment that uses registry-mode key discovery SHOULD use this shape; deployments using other bootstrap modes need none of it.

```
GET /v1/registry/principals/{human_id}

Response 200:
{
  "human_id":   "<hex>",
  "public_key": <HybridPublicKey>,          // the CURRENT root key
  "rotations":  [<KeyRotationStatement>…],  // full chain, oldest → newest; [] if never rotated
  "anchor":     <Anchor> | null,            // external-identity binding (§5.5), if published
  "updated_at": <unix-seconds>              // when this record last changed
}

Response 404: see rejection shape below.
```

**Identifier semantics across rotation.** Identifiers are key-derived (§7), so a key rotation changes the principal's id. `{human_id}` is the id of the principal's **current** root key: the registry addresses each record by the current id, a rotation moves the record to the new id, and the rotated-away id ceases to resolve (404 — the standard rejection shape). This matches the wire format: a proof bundle's chain-root `issuer_id` is derived from the key that signed it, so a bundle rooted in the current key presents exactly the id the registry answers for, and a bundle rooted in a rotated-away key presents an id that no longer resolves — the default historical-root rejection falls out of the id model rather than requiring a separate check. v1 deliberately defines no rotation-stable principal identifier; the wire format does not carry one.

**Resolver ID validation.** The resolver MUST verify `DeriveID(public_key) == human_id` on every record (equivalently, when `rotations` is non-empty: the final statement's `new_id` equals `human_id` — statement ids are already bound to their keys by §5.15 verification, and the final statement's `new_pub_key` must equal `public_key`). A record that fails this is malformed regardless of how the registry chose to address it.

**Transport requirements.** Registry-mode lookup MUST use authenticated transport (in practice HTTPS/TLS with certificate verification). A registry reached over unauthenticated transport is an attacker-writable trust root; resolvers MUST refuse plain-HTTP registry URLs rather than fall back. (Test harnesses use TLS test servers; there is no loopback carveout in the contract.)

**Registry server requirements.**
- `human_id` is exactly 32 lowercase hex characters (`hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])`, §7). The registry MUST validate this before lookup.
- **One rejection shape.** Malformed `human_id`, unknown principal, and removed principal all return the identical response: `404` with the fixed body `{}` and no reason string, header, or timing behavior that distinguishes the cases. The registry is not an existence or format oracle.
- There is deliberately NO enumeration or listing endpoint in this binding. Registries MUST NOT expose one under this contract's path prefix.
- Responses SHOULD carry `Cache-Control: max-age` (short — minutes, not hours) and an `ETag`; `updated_at` is informational, not a freshness guarantee.

**Resolver (verifier-side) requirements — fail closed on every branch.** A resolver consuming this binding MUST reject (treat the principal's key as unresolved, causing verification to fail) on: network failure; non-200 status; malformed or schema-violating JSON; `DeriveID(public_key) != human_id` (see resolver ID validation above); a rotation chain that is out of order, contains a statement whose signatures do not both verify (§5.15), or whose links are not contiguous (each statement's new key is the next statement's old key); a final rotation whose new key does not equal `public_key`; or cached data older than the deployment's staleness policy. **Pinned keys.** A pin is the verifier's own first-trust decision, identified by the pinned key's **own** derived id (§7) — the only id the verifier can know at pin time; the legitimacy of any post-rotation id is precisely what the chain exists to prove, so a resolver MUST NOT require the caller to pre-associate a pin with a current id. Two obligations follow. (a) *Lineage consistency:* whenever a resolution's lineage passes through a pinned id — as a rotation statement's old id or as the current id — the key at that position MUST equal the pinned key. (b) *Descent requirement:* when the caller requires that a presented id belong to a specific pinned principal, the resolution MUST additionally verify that the pinned key appears in the record — as the current key or as a statement's old key; a record that does not descend from the pin is a continuity failure, not a soft mismatch. A record whose lineage touches no pinned id satisfies (a) vacuously — pins constrain claimed lineage; establishing that an id *belongs to* a pinned principal requires (b). Both obligations apply to every resolution, **including answers served from the resolver's own cache** (a pin recorded after a record was cached must be evaluated against that record on the next resolution, not bypassed by it).

**Historical roots.** A proof bundle whose chain root is signed by a key that the rotation chain shows was rotated *away* MUST be rejected by default. A verifier MAY accept historical-root bundles under explicit policy (e.g. a grace window after rotation), but silence means reject.

**What this binding does and does not establish.** Rotation-chain validation proves **continuity after first trust** — that today's key is the legitimate successor of a key you already trusted. It does not, and cannot, prove that the *first* key belonged to the claimed principal: first acquisition — from this registry or anywhere else — **is** the trust decision (§15.4, threat T12). The v1 contract's trust model is explicit: the verifier trusts the registry operator (threat T9) and the TLS channel. Signed response envelopes and witness-logged registry entries (§5.12) are the designated future hardening path and are intentionally not specified here; a registry MAY additionally log its records to a witness chain today, and verifiers MAY check consistency, per §15.4's composition note.

The `AnchorResolver` provider interface (§17.8) is unrelated to this binding: it runs after successful verification to attach audit identity metadata. This binding is consulted *before* verification, to obtain the trust root itself.

---

## 14. Conformance

An implementation is conformant if, for every fixture in `testvectors/v1/*.json` (79 fixtures as of the v1.0.0-alpha.16 conformance set; alpha.15 had 63):

- For `kind: "verify"` fixtures: the implementation's canonical-signing-bytes hex matches `expected.delegation_sign_bytes_hex` for every cert; the challenge-signing-bytes hex matches `expected.challenge_sign_bytes_hex`; and running `Verify()` produces a `VerifyResult` equivalent to `expected.verify_result` (with `granted_scope` compared as a set).
- For `kind: "scope"` fixtures: `ExpandScopes(scope_input)` matches `expected.expanded_scopes`.
- For `kind: "revocation"` fixtures: the canonical-signing-bytes hex matches `expected.revocation_sign_bytes_hex`, and hybrid signature verification against the declared issuer public key succeeds.
- For `kind: "key_rotation"` fixtures: `KeyRotationSignBytes(key_rotation)` matches `expected.key_rotation_sign_bytes_hex`, and `VerifyKeyRotationStatement()` succeeds or fails exactly as `expected.key_rotation_verify_ok` declares.
- For `kind: "session_token"` fixtures: `SessionTokenSignBytes(session_token.token)` matches `expected.session_token_sign_bytes_hex`, the token MAC matches `expected.session_token_mac_hex`, and streamed-turn verification succeeds or fails as declared.
- For `kind: "transaction_receipt"` fixtures: `TransactionReceiptSignBytes(transaction_receipt)` matches `expected.receipt_sign_bytes_hex`, and `VerifyTransactionReceipt()` succeeds or fails exactly as `expected.receipt_valid` declares.
- For `kind: "revocation_push"` fixtures: `RevocationPushSignBytes(revocation_push)` matches `expected.revocation_push_sign_bytes_hex`, and hybrid signature verification against the declared issuer public key succeeds.
- For `kind: "witness_entry"` fixtures: `WitnessEntrySignBytes(witness_entry)` matches `expected.witness_entry_sign_bytes_hex`, and hybrid signature verification against the declared witness public key succeeds.

The reference Go test `TestConformanceVectors` and every SDK conformance suite enforce these fixture contracts on every CI run. Cross-language interop is therefore tested continuously.

---

## 15. Security considerations

### 15.0 Threat model

The following table enumerates the adversaries, their capabilities, and how the protocol defends against each. An entry marked "out of scope" means the protocol explicitly does not defend against that adversary — the mitigation is an orthogonal control.

| # | Adversary | Capability | Attack | Protocol defense | Residual risk |
|---|-----------|-----------|--------|-----------------|---------------|
| T1 | **Network eavesdropper** | Observes all traffic between agent and verifier | Capture a `ProofBundle` and replay it later | Challenge freshness bounds replay to the ≤300s window. A verifier that issues challenges MUST accept each at most once within that window (§10), which eliminates replay at that verifier. Session binding (§5.8) prevents cross-verifier replay. Stream sequence numbers (§5.8) prevent within-stream replay. | Metadata (who talked to whom, when) is visible; use TLS for transport confidentiality. Self-issued challenges have no issuance record: replay within the freshness window is bounded, not eliminated — pair them with request-level deduplication (§10). |
| T2 | **Quantum adversary** | Runs Shor's algorithm on captured signatures | Break Ed25519 signatures on archived bundles | Hybrid signatures: ML-DSA-65 (lattice-based, believed quantum-resistant) must also verify. Attacker must break both Ed25519 AND ML-DSA-65. | If both Ed25519 and ML-DSA-65 fall simultaneously to a future algorithm, the protocol is broken. This is the industry-standard assumption for hybrid post-quantum schemes. |
| T3 | **Scope escalation by intermediate** | Holds a delegation cert with limited scope | Issue a sub-delegation with wider scope than received | Effective scope = intersection of every cert's scope in the chain (§9.3). Intermediates cannot grant what they did not receive. `identity:delegate` is sensitive and never rides wildcards. | — |
| T4 | **Signature forger (classical)** | Unbounded classical compute | Forge a hybrid signature without the private key | Ed25519: 2^128 security. ML-DSA-65: Module-LWE/Module-SIS hardness. Both must verify. Single-component forgery (e.g., forge Ed25519 only) fails the hybrid check. | — |
| T5 | **Tampered cert / bundle** | Modify any field of a signed object after issuance | Change scope, expiry, subject, or terms post-signature | Canonical signing bytes cover every non-signature field. Any byte change invalidates the hybrid signature. | — |
| T6 | **Stolen agent private key** | Holds a compromised agent's private key | Sign valid challenges and present stolen delegation certs | Revocation: issuer publishes signed `RevocationList`; verifiers check before accepting. Short cert lifetimes limit exposure window. `RevocationPush` (§5.11) for real-time propagation. `ForceRevocationCheck` for high-stakes endpoints. | Revocation propagation has a staleness window (poll interval or push delivery lag). |
| T7 | **Stolen root private key** | Holds a human's root private key | Issue rogue delegations, competing rotation statements | Revocation of all certs issued by the compromised key. `KeyRotationStatement` (§5.15) to move to a new key. Registry policy for out-of-band verification. See §15.3. | Attacker can issue a competing `KeyRotationStatement`. Resolution requires registry/operator trust — see §15.3. |
| T8 | **Malicious verifier** | Legitimate verifier that acts dishonestly | Forward V1's challenge to the agent, replay the bundle at V1 | Session context binding (§5.8, §15.1): agent signs with the verifier's context. Cross-verifier replay fails because contexts differ. | Requires the agent to include session_context. Legacy unbound bundles are vulnerable on non-TLS transports. |
| T9 | **Rogue registry operator** (custodial mode) | Holds envelope-encrypted user keys | Decrypt keys and issue unauthorized delegations | Envelope encryption (DEK + KEK via KMS) limits blast radius. Self-custody mode (§15.2) eliminates this adversary entirely. Self-custody upgrade path via `KeyRotationStatement`. | In custodial mode, the operator IS trusted. This is documented in §15.2. Self-custody is the mitigation. |
| T10 | **Side-channel attacker** | Observes timing/power during signing on shared infrastructure | Extract private key material via side-channel analysis | Use well-audited crypto libraries. v1 uses deterministic ML-DSA-65 signing; future versions MAY add hedged-randomization for hostile environments. | Deterministic signing on shared VMs is a known industry-wide risk. See §8.3. |
| T11 | **Clock-skew attacker** | Manipulate the verifier's or agent's clock | Accept expired certs or stale challenges | Temporal checks use the verifier's clock. Clock skew beyond the challenge window (300s) causes rejection. See §15.6 for clock discipline requirements. | If the verifier's clock is compromised, temporal checks are meaningless. This is a deployment concern. |
| T12 | **Key-substitution attacker** | Controls or spoofs the channel a verifier uses to obtain principal public keys | Present a chain rooted in an attacker-generated key labeled "Alice" — every signature verifies, because the signatures are genuine over the attacker's key | None at the wire layer. Signature verification proves possession of a private key, not that the key belongs to the claimed principal. Trust bootstrap is a REQUIRED deployment decision — see §15.4. | Verification is only as strong as the verifier's key-discovery channel. A verifier that accepts principal keys from an unauthenticated source is fully spoofable regardless of the cryptography. |

**Out of scope (not defended by protocol):**

| Adversary | Why out of scope | Recommended mitigation |
|-----------|-----------------|----------------------|
| Private key theft at endpoints | Key storage is a deployment concern, not a wire protocol | Hardware tokens, secure enclaves, self-custody mode (§15.2) |
| Social engineering of principals | Human factors, not cryptography | Organizational procedures, MFA on delegation approval |
| Compromise of an agent platform | The platform holds agent keys; Ratify cannot stop the platform from misusing them | Short cert lifetimes, revocation, scope constraints |
| Metadata leaks | Protocol bundles are not encrypted — they prove identity, not confidentiality | TLS on transport; v2 session-key derivation for stream encryption |

### 15.1 Challenge forwarding by malicious verifier

A malicious or compromised verifier V_mal can forward a challenge from a legitimate verifier V_leg to an agent, causing the agent to sign V_leg's challenge while believing it is authenticating to V_mal. V_mal then presents the resulting bundle back to V_leg. This is authorization misdirection, not signature forgery.

**Defense (v1.1):** the v1.1 `session_context` binding (§5.8, §6.4.2) includes the verifier's identity in the signable bytes. The agent signs `challenge || ts || session_context_V_mal`; V_leg reconstructs `session_context_V_leg` from its own identity, which differs, so the challenge signature fails verification. The fixture `reject_challenge_forwarding` proves this defense end-to-end across all SDK implementations.

Deployments SHOULD include the verifier's public key ID in the `session_context` preimage so that cross-verifier misdirection is detectable at the cryptographic layer, not only at the transport layer — the canonical §6.4.9 construction carries it as its first field (`verifier_id`).

### 15.2 Key custody modes

The protocol is agnostic to where private keys are stored. Three deployment modes are valid, each with different trust assumptions:

| Mode | Where the key lives | Trust assumption | Breach impact |
|------|-------------------|------------------|---------------|
| **Self-custody** | User's device (CLI, mobile secure enclave, hardware token) | User alone controls the key. No third party can sign on the user's behalf. | Compromise requires physical access to the device or extraction of the key material from the secure enclave. |
| **Custodial** | Server-side, envelope-encrypted (e.g., AES-256-GCM + KMS key wrapping) | The registry operator's infrastructure is not compromised. The operator cannot be coerced into signing unauthorized delegations. | A breach of the operator's KMS and database together could expose private keys. Envelope encryption (separate DEK and KEK) limits blast radius. |
| **Delegated custody** | Enterprise IdP holds the root key; Ratify certs chain from the IdP's delegation | The enterprise IdP (Okta, Azure AD, etc.) is the trust anchor. Compromise of the IdP compromises all identities it manages. | Equivalent to enterprise SSO compromise — organization-wide, not protocol-wide. |

**Self-custody is the strongest mode.** Implementations SHOULD offer self-custody as the default for users who can manage their own keys, and SHOULD offer it as an upgrade path for users who start in custodial mode.

**Self-custody upgrade path:** A user who initially relied on custodial key management can generate a new keypair on their own device (via the CLI or a mobile app), publish a `KeyRotationStatement` (§5.15) signed by both the old custodial key and the new self-custody key, and from that point forward sign all delegations locally. The rotation statement provides cryptographic continuity — verifiers and auditors can trace the identity across the custody change without an out-of-band trust decision.

**Custodial deployments MUST:**
- Use envelope encryption: private key encrypted with a per-user data encryption key (DEK), DEK encrypted with a platform key encryption key (KEK) managed by a hardware-backed KMS.
- Never persist plaintext private keys to disk, logs, or network responses.
- Zero private key material from process memory immediately after each signing operation.
- Document the custodial trust model to users — do not claim "keys never leave your device" when the operator holds the key.

**Agent key custody:** Agent private keys are typically held in-process by the agent runtime. The protocol does not mandate agent key storage, but agents SHOULD use process-memory-only keys (never written to disk) where the runtime supports it, and SHOULD rotate keys on restart.

#### 15.2.1 Middleware Custody Profile

A common deployment shape holds agent keys neither on the user's device nor at an enterprise IdP but inside a **platform middleware layer** — an agent-hosting platform, relay, or gateway that signs presentations on behalf of the agents it runs. Middleware custody changes the threat model: the party constructing and signing presentations is also the party routing them, so a compromised or buggy middleware can attach a perfectly valid signature to the wrong session or the wrong action. Signatures alone cannot detect that — the binding has to.

A deployment operating under middleware custody MUST conform to this profile:

- **Every presentation MUST be session-bound.** `session_context` is REQUIRED on every `ProofBundle` (and every streamed turn) the middleware signs; verifiers in the deployment MUST reject unbound presentations from middleware-custody principals.
- **The binding MUST use the §6.4.9 constructions**, populating at minimum: `verifier_id`, `workspace_id` (or the deployment's tenant equivalent), `agent_id`, `session_id`, `invocation_id`, and `request_hash`.
- **`request_hash` MUST be derived from the §6.4.9 operation context of the specific action being authorized** — required scope, operation type, resource, path, and payload digest where one exists. Binding the session but not the operation would let the middleware attach a valid proof to the wrong action inside the right session; the operation binding is as load-bearing as the session binding.
- **Receipts and audit records MUST bind the 32-byte context hash, never the preimage.** The hash already rides in the bundle (and therefore in `bundle_hash` on verification receipts, §17.5); preimages may carry tenant and routing identifiers that receipts must not.
- **Mismatches surface as the existing statuses** — `session_context_mismatch` (or `missing_session_context` / `session_context_unverifiable`); the profile introduces no new failure vocabulary.

The profile is named so integrations can claim it: "conforms to the Ratify Middleware Custody Profile" is a checkable statement about a platform's presentation-signing path. Deployments where the agent runtime holds its own key MAY adopt the same constructions (they are RECOMMENDED for any session-bound use) but are not bound by this profile's MUSTs — the base verifier cannot know key custody, so the profile binds the deployment, not the wire format.

### 15.3 Root key compromise and recovery

If a root private key is stolen, the attacker can issue new delegation certs and competing `KeyRotationStatement`s. The protocol alone cannot distinguish a legitimate rotation from an attacker's rotation — both produce valid signatures.

**Mitigations:**
- **Short cert lifetimes.** Delegation certs with short `expires_at` windows (hours to days, not years) limit the window an attacker can exploit a stolen key.
- **Revocation.** The legitimate owner publishes a signed `RevocationList` revoking all certs issued by the compromised key. Verifiers that check revocation reject the attacker's certs.
- **Registry policy.** A registry operator can enforce out-of-band identity verification before accepting a `KeyRotationStatement` — e.g., requiring re-authentication via SSO or requiring multi-party approval for rotation. This is deployment policy, not protocol mechanics.
- **Witness anchoring.** If delegation certs and rotation statements are logged to a `WitnessEntry` chain (§5.12), auditors can detect conflicting rotation statements after the fact.

The protocol provides the cryptographic tools (revocation, rotation, witness). The operational response to key compromise is a deployment concern that depends on the custody mode and the operator's security posture.

### 15.4 Trust anchors and public-key discovery

Every guarantee in this specification is conditional on one premise: **the verifier holds the correct public key for the principal at the root of the chain.** Signature verification proves possession of a private key; it cannot prove the key belongs to the person or organization the presenter claims (threat T12). The protocol deliberately does not mandate a PKI — requiring one would reintroduce the central issuer the protocol exists to avoid — but that makes key acquisition an explicit security decision for every deployment, not an implementation detail.

A verifier MUST obtain principal public keys through at least one of the following bootstrap modes, and MUST NOT treat a key that arrives in-band with the proof bundle itself as a trust root:

| Mode | How the verifier gets the key | Trust assumption | Fits |
|------|------------------------------|------------------|------|
| **Pinned keys** | Operator pins principal keys out-of-band during onboarding (contract exchange, config management). | The onboarding channel. | Closed B2B integrations, high-stakes endpoints, offline/edge verifiers. |
| **Enterprise IdP root** | The organization's IdP holds the root key (delegated custody, §15.2); the verifier pins one IdP key and every member identity chains from it. | The enterprise IdP. | Workforce deployments. |
| **Registry lookup** | A registry maps `human_id` / `Anchor` (§5.5) to a public key, queried through a resolver *before* verification. §13.1 defines the optional read binding any registry can implement. | The registry operator (threat T9 applies). | Internet-scale consumer deployments. |
| **Self-published + continuity** | The principal publishes the key at a stable location they control (DNS record, website, profile). First acquisition is trust-on-first-use; subsequent key changes MUST be validated as a `KeyRotationStatement` chain (§5.15) from the pinned first key. | The publication channel, once, at first use. | Individuals and small publishers. |
| **Witness-backed evidence** | Key publications and rotations are logged to one or more `WitnessEntry` chains (§5.12); the verifier checks that the key it received is consistent with the log and that no conflicting rotation exists. | At least one honest witness. | Augments any of the above; detects equivocation. |

These modes compose: a registry whose entries are witness-logged is strictly stronger than a bare registry; a pinned key with rotation-chain continuity survives key rotation without re-onboarding.

Note that the `AnchorResolver` provider interface (§17.8) is **not** a trust-anchor discovery mechanism: it runs *after* successful verification to attach external-identity metadata (`VerifyResult.Anchor`) for audit purposes, and it returns an `Anchor`, not a public key. v1 defines no wire protocol for key discovery; the resolver a deployment uses to obtain root public keys before verification is deployment code, built on one of the modes above.

Deployments SHOULD document which bootstrap mode(s) they use. A verifier that cannot state where a principal key came from has no basis for the trust decisions this protocol automates.

### 15.5 Revocation freshness

Verification is offline; revocation state is not. A verifier checks revocation against its local copy of the issuer's signed `RevocationList` (or its accumulated `RevocationPush` deltas), and that copy has an age. The gap between a revocation being published and every verifier honoring it is the protocol's principal freshness exposure (threat T6, threat T7).

Requirements and guidance:

- Verifiers MUST fail closed when revocation state is required but unavailable (`revocation_error`, §5.17) — an unreachable revocation source is never treated as "nothing revoked."
- Verifiers SHOULD bound the age of the revocation state they will act on, sized to risk: for high-stakes actions, fresh state (seconds — via `RevocationPush` subscription or a live check triggered by `ForceRevocationCheck`); for ordinary interactive sessions, minutes; polling intervals beyond one hour are appropriate only where the action is low-consequence or another control (short cert lifetimes) bounds exposure.
- `ForceRevocationCheck` (§5.17) SHOULD be set for actions that are irreversible or high-value regardless of session state — payments above a threshold, physical actuation, `identity:*` scoped operations — even when a valid `SessionToken` exists (§5.13).
- **Push-gap recovery.** A verifier that subscribes to `RevocationPush` and detects a delivery gap (missed sequence, reconnect after downtime) MUST NOT resume acting on its delta state; it MUST fetch the issuer's full current `RevocationList` before trusting its revocation view again.
- Short cert lifetimes (§15.3) are the complementary control: the shorter the cert, the less revocation freshness matters.

### 15.6 Verifier clock discipline

All temporal checks — cert validity windows, challenge freshness (§10), `SessionToken` lifetimes (§5.13) — use the verifier's clock. The protocol's freshness guarantees therefore degrade with clock error (threat T11).

- Networked verifiers SHOULD synchronize time via authenticated NTP (NTS) or an equivalent trusted source. Total clock error SHOULD be kept well under the 300-second challenge window; ±30 seconds is a reasonable budget.
- Offline and edge verifiers (vehicles, drones, air-gapped deployments) SHOULD use a hardware RTC with a known drift bound, and SHOULD subtract their worst-case accumulated drift from the challenge acceptance window — a verifier that may be 60 seconds wrong should accept challenges no older than 240 seconds.
- Temporal bounds remain strict in v1: `not_before` and `expires_at` get no skew tolerance at verification time (`reject_not_yet_valid` and `reject_expired` fixtures are exact). Issuers who need slack SHOULD build it into the cert at issuance (set `not_before` slightly in the past) rather than expecting verifiers to loosen checks — a per-verifier tolerance would make acceptance non-deterministic across verifiers, which the fixture contract forbids.

### 15.7 What constraints attest — and what they do not

First-class constraints (§5.7.1, §5.7.2) are evaluated by the verifier against context the verifier itself supplies (§5.16). The signed cert proves *what the principal authorized*; the verify-time evaluation proves *the decision was consistent with the supplied context*. Nothing in the protocol proves the supplied context was true in the world: a verifier that reports `CurrentLat`/`CurrentLon` inside a `geo_circle` has asserted the agent's location, not demonstrated it.

Consequences:

- Constraints defend the **principal** against agent overreach at an honest verifier. They do not defend anyone against a dishonest or compromised verifier, which can trivially supply satisfying context (see also threat T8 — the malicious-verifier row — and §10: the verifier is the party running the algorithm; it can also simply skip it).
- A third party auditing a transaction after the fact cannot independently confirm constraint context from the protocol artifacts alone. Deployments that need auditable constraint claims SHOULD bind the evaluated context into a signed artifact — include it in the `VerificationReceipt` (§17.5) or in `TransactionReceipt.terms` (§5.14) — so the claim is at least signed and attributable to the verifier that made it.
- Where context must be *proven* rather than asserted (regulated geofencing, financial limits), the context source itself needs attestation — signed GNSS fixes, platform attestation, or a co-signing oracle — which is outside the protocol. The `ConstraintEvaluator` extension point (§17.7) is where such attested evaluators plug in.
- A verified `resource_path` constraint (§5.7.3) is **lexical** authorization over a logical path, not filesystem confinement. Ratify proves authorization for a canonical logical resource and path; a receiving system that maps those logical paths onto a real filesystem MUST enforce confinement itself. Two properties below are normative for that layer; the mechanisms that achieve them are deployment choices, not protocol requirements.

  **Normative properties.** (1) Under the deployment's **stated attacker model**, a confinement or policy refusal reached before the write commits MUST NOT modify or remove any pre-existing filesystem object, MUST NOT write the attempted payload, and MUST NOT leave behind any filesystem object created by the refused operation, whether inside or outside the confinement boundary. An implementation MAY create temporary or internal artifacts while resolving or staging the write, provided a refusal leaves no externally persistent effect: cleanup MUST act only on artifacts this invocation created whose identities still match what it created and which remain safe to remove, and MUST NOT follow paths through, remove, or modify objects a concurrent principal may have substituted. (2) Execution MUST NOT cause any filesystem effect outside the confinement boundary. The confinement property is undefined without a stated attacker model: the integrator MUST state which principals may rename, link, or replace objects under the root while an operation is in progress, because a design that is sound against a static tree is unsound against a peer that can swap a path component mid-operation. **Ordering:** all checks capable of producing a security, policy, or confinement refusal MUST complete against the objects used for the commit before the destination write is committed; an implementation MUST NOT commit the destination and then report such a refusal. Temporary staging artifacts may still be created before that decision, subject to the identity-safe cleanup requirement above.

  **What this rules out, and what satisfies it.** Resolve-then-open-then-clean-up by path cannot establish these properties when the tree is concurrently mutable: an open can follow a swapped intermediate component and touch a location outside the root before any check runs, and cleanup performed by path can delete or modify an outside target through that same swapped path. Resolve descriptor-relative instead: root at a trusted directory descriptor, open each component relative to the preceding pinned descriptor, refuse symlinked components, and perform any cleanup relative to a held descriptor rather than by re-resolving a path. On Linux, `openat2` with appropriate `RESOLVE_*` controls is one implementation; other platforms need an equivalent mechanism, and where an untrusted principal can mutate the tree, filesystem permissions, mount-namespace isolation, or an OS sandbox is required in addition. Apply every decoding and normalization step (URL decoding, Unicode normalization, case folding, separator conversion, path cleanup) **before** constructing `RequestedPath`, and never transform the verified path afterward (§5.7.3).

  **Conformance.** A test for a refusal MUST distinguish adversary-created mutations from effects attributable to the refused operation. It MUST verify that no pre-existing object was changed by the refused operation, that the attempted payload was written nowhere by the operation, and that no artifact attributable to the operation remains, inside or outside the boundary. The test harness MUST account separately for mutations deliberately performed by the adversary. Asserting only that pre-existing objects survived and the payload is absent is insufficient, because it passes an implementation that leaves partial artifacts (for example, intermediate directories) behind on refusal.

  **Atomicity is a separate contract.** The no-effect-on-refusal property above covers *security, policy, and confinement* refusals reached before the write commits. An I/O failure *after* an authorized write has begun (a short write, a full disk, an interrupted syscall) is a different case: either promise atomic replacement (write the complete contents to a temporary file within the pinned destination directory, verify every byte was written, then install it with a descriptor-relative atomic rename) or state explicitly that partial writes are possible. Do not describe every failure as mutation-free unless atomic replacement is implemented.

  The cryptographic guarantee and the confinement guarantee are separate layers and should be reported separately: Ratify proves authorization for a canonical logical resource and path; the adapter attests context; the execution layer enforces filesystem confinement.

---

## 17. SDK Architecture: Provider Interfaces

The protocol — wire format, canonical signable bytes, hybrid signature algorithm, verifier state machine (§§4–9) — is open. The integration surfaces around it are where production deployments diverge: revocation freshness, policy evaluation, and audit retention each impose operational requirements that go well beyond what a static spec can mandate. SDKs therefore expose three **Provider** hooks that bracket the verifier's deterministic core.

**The split is intentional.** The cryptographic primitives in §§5–9 are universal — every implementation must agree byte-for-byte. The provider surface in §17 is local — each deployment configures it to match its threat model, compliance regime, and infrastructure. A bundle verified with provider A and a bundle verified with provider B are byte-identical; only the verifier's local decision pipeline differs.

This separation lets the protocol stay neutral and portable while letting commercial verifiers (Ratify Verify and any third-party equivalent) compete on operational surface — revocation push latency, policy UX, signed audit archive — without forking the wire format.

### 17.0 Conformance and wire-format invariance

- A conformant SDK MUST expose all three provider hook points (`Revocation`, `Policy`, `Audit`) on its verify-options surface, with consistent naming across languages.
- A conformant SDK MUST treat any unset hook as a no-op — verification with all hooks `nil` MUST produce the same `VerifyResult` as a verifier with no provider surface at all.
- Provider invocations MUST NOT modify the `ProofBundle`. They are read-only over signed material. A bundle that re-serializes byte-identically before and after a `Verify` call (with or without providers) is REQUIRED for fixture determinism.
- Provider implementations are NOT covered by the test-vector conformance suite. The 79 fixtures in `testvectors/v1/` exercise the deterministic core; provider behavior is an SDK-level concern verified by unit tests in each language.

### 17.1 RevocationProvider

A `RevocationProvider` decides whether a `cert_id` is currently revoked.

**Interface:**
- `IsRevoked(certID string) (bool, error)`

**Semantics:**
- Invoked once per cert per `Verify` call, in chain order.
- A return of `(true, nil)` produces `identity_status="revoked"` and short-circuits the chain walk.
- A non-nil `error` is fail-closed: the bundle is rejected with `error_reason="revocation_error: ..."` and `identity_status="invalid"`. An SDK MUST NOT treat a lookup failure as "not revoked."
- The provider is on the verifier's hot path. Implementations SHOULD be O(1) at call time — bloom filter, in-memory delta cache, or warm CDN lookup. Synchronous network round-trips per-Verify are discouraged; push or batched sync is the intended pattern.

**Precedence:** if both an `IsRevoked` closure (legacy v1 surface) and a `Revocation` provider are configured, the provider MUST win. SDKs MAY surface both for migration ergonomics; a future major version may remove the closure.

**Standard Implementations:**
- **Local (Default)** — reads from a caller-supplied `RevocationList` (§5.10) loaded at SDK init or polled at a configured interval. Adequate for low-throughput verifiers and for offline / air-gapped deployments. Staleness is bounded by the poll interval.
- **Push (Commercial, e.g. Ratify Verify)** — subscribes to a real-time revocation stream and maintains a local delta cache. Designed for low-staleness delivery. Out of scope for this spec; the interface above is the only contract.

### 17.2 PolicyProvider

A `PolicyProvider` evaluates verifier-local, stateful policy that exceeds the deterministic, cert-bound constraint logic of §5.7.2.

**Interface:**
- `EvaluatePolicy(bundle *ProofBundle, context VerifierContext) (bool, error)`

**Why this is separate from Constraints (§5.7.2):** Constraints are signed by the principal as part of the delegation cert — they travel with the bundle and are byte-identical for every verifier. Policy is the inverse: it is **verifier-local**, **mutable at runtime**, and **stateful** (quota counters, global security signals, per-tenant overrides). A policy provider can deny a bundle that every constraint accepts, and vice versa — both signals are required, neither replaces the other.

**Evaluation order:** policy is evaluated AFTER all cryptographic, temporal, revocation, constraint, and scope-intersection checks have passed. A bundle that fails any earlier check never reaches the policy provider.

**Outcome mapping:**
- `(true, nil)` — allow; `Verify` returns the success result unchanged.
- `(false, nil)` — deny; `Verify` returns `identity_status="scope_denied"` with `error_reason` indicating policy denial.
- `(_, non-nil error)` — fail-closed; `Verify` returns `identity_status="invalid"`, `error_reason="policy_error: ..."`. An SDK MUST NOT allow on policy error.

**Standard Implementations:**
- **Default (no provider)** — the verifier's static scope + constraint checks are sufficient.
- **Advanced (Commercial, e.g. Ratify Verify)** — evaluates Rego/OPA rules, per-agent usage quotas, geo-tagged kill switches, and global security signals via a low-latency control plane. Out of scope for this spec.

### 17.3 AuditProvider

An `AuditProvider` records verification receipts for forensic, compliance, and ML/observability use.

**Interface:**
- `LogVerification(result VerifyResult, bundle *ProofBundle) error`

**Semantics:**
- Invoked on every `Verify` call — success AND failure — so denied attempts are recorded.
- Errors from the provider are **intentionally swallowed**. Auditing is observation, not control. An audit-store outage MUST NOT flip a `Valid=true` result to `Valid=false`. An SDK MAY surface provider errors through a separate diagnostic channel (logger, metric counter); it MUST NOT alter the verifier's verdict.
- Invocation order: audit is the last operation in `Verify`, after policy. The result passed to the provider is the final result returned to the caller.

**Standard Implementations:**
- **Default (no provider)** — no audit trail. The caller is free to log the returned `VerifyResult` themselves.
- **Local** — writes JSON lines to stdout or a local file. Adequate for development.
- **Attestation (Commercial, e.g. Ratify Verify)** — wraps each verification in a verifier-signed `WitnessEntry` (§5.12) and streams to an append-only ledger. Each entry is cryptographically linked to its predecessor, so a missing or backdated entry is detectable. This is the interface used to back SOC2/ISO compliance claims.

### 17.4 Naming across SDKs

The provider surface is named consistently across languages so that interop documentation, conformance tests, and audit fixtures all reference the same concepts:

| Concept | Go | TypeScript | Python | Rust | C/C++ |
|---|---|---|---|---|---|
| Revocation hook | `Revocation RevocationProvider` | `revocation?: RevocationProvider` | `revocation: RevocationProvider \| None` | `revocation: Option<Box<dyn RevocationProvider>>` | `ratify_set_revocation_source()` |
| Policy hook | `Policy PolicyProvider` | `policy?: PolicyProvider` | `policy: PolicyProvider \| None` | `policy: Option<Box<dyn PolicyProvider>>` | `ratify_set_policy_source()` |
| Audit hook | `Audit AuditProvider` | `audit?: AuditProvider` | `audit: AuditProvider \| None` | `audit: Option<Box<dyn AuditProvider>>` | `ratify_set_audit_source()` |

Method names: `IsRevoked` / `is_revoked`, `EvaluatePolicy` / `evaluate_policy`, `LogVerification` / `log_verification` — matching each language's idiomatic casing. C/C++ uses the `ratify_` prefix convention throughout.

### 17.5 VerificationReceipt — tamper-evident verification records

A `VerificationReceipt` is a verifier-signed attestation that a specific `ProofBundle` was verified with a specific decision at a specific moment. It is the cryptographic complement of `AuditProvider`: an `AuditProvider` chooses *what to do* with verification events; a `VerificationReceipt` makes the event itself unforgeable. Even an auditor who does not trust the verifier operator can verify a receipt — provided they know the verifier's public key.

**Why this exists.** An `AuditProvider` is a stateful component a deployment configures. A buggy or malicious provider can drop entries, backdate timestamps, or refuse to write at all. A `VerificationReceipt` is structurally append-only: each receipt's `prev_hash` is the SHA-256 of the previous receipt's canonical signable bytes, so missing or backdated entries are detectable. A chain of receipts is provable; a chain of stdout logs is not.

**Wire format (canonical JSON, lex-ordered keys):**

```jsonc
{
  "agent_id": "...",                    // optional; omitted iff empty
  "bundle_hash": "<b64-32-bytes>",      // SHA-256 of canonical ProofBundle
  "decision": "authorized_agent",        // verbatim VerifyResult.identity_status
  "error_reason": "...",                // optional; omitted iff empty
  "granted_scope": ["..."],             // optional; sorted lex
  "human_id": "...",                    // optional; omitted iff empty
  "prev_hash": "<b64-32-bytes>",        // SHA-256 of previous receipt's signable; zeros for genesis
  "signature": {"ed25519": "...", "ml_dsa_65": "..."},  // hybrid signature
  "verified_at": <unix-seconds>,
  "verifier_id": "...",                 // derived ID of the verifier's signing key
  "verifier_pub": {"ed25519": "...", "ml_dsa_65": "..."},
  "version": 1
}
```

`signature` is excluded from the signable bytes (a signature cannot cover itself).

**SDK API:**

```
BundleHash(bundle) -> 32-byte SHA-256
IssueVerificationReceipt(bundle, result, verifierID, verifierPub, verifierPriv, prevHash, verifiedAt) -> VerificationReceipt
VerifyVerificationReceipt(receipt) -> nil | error
ReceiptHash(receipt) -> 32-byte SHA-256 (use as prev_hash for the next receipt)
```

**Properties (test-vector–enforceable):**
- Mutating `decision` after signing → `VerifyVerificationReceipt` returns error.
- Substituting `bundle_hash` for a different bundle's hash → verification fails.
- Tampering an earlier receipt changes its hash → the next receipt's `prev_hash` no longer matches → chain is detectably broken.
- `BundleHash(bundle)` is deterministic across SDKs (RFC 8785).

**Receipts are OPTIONAL.** The protocol does not auto-issue them. An `AuditProvider` may choose to wrap each `VerifyResult` in a `VerificationReceipt` before persisting; an implementation that doesn't, won't. Wire format and verifier output are unchanged either way.

### 17.6 PolicyVerdict — HMAC-bound cached policy decisions

A `PolicyVerdict` is the policy analogue of `SessionToken` (§5.13): a short-lived, verifier-cached attestation that `(agent_id, scope, context_hash)` passed advanced policy evaluation at a specific moment. Once issued, the verifier can accept the cached allow/deny for the rest of `valid_until` without re-calling the policy backend — a fast path for streaming workloads where policy round-trips would dominate latency.

**MAC semantics** are identical to `SessionToken`:

```
mac = HMAC-SHA256(policy_secret, PolicyVerdictSignBytes(verdict))
```

`policy_secret` is private to whoever issued the verdict (typically a commercial policy backend). The backend rotates the secret to invalidate stale verdicts globally — the same way `SessionToken` invalidation works.

**Context binding.** `context_hash` is the SHA-256 of the canonical-JSON serialization of the **policy-relevant subset** of a `VerifierContext` (location, speed, transaction amount, currency; the `invocations_in_window` closure is excluded). A verdict cached for one context (e.g. `current_lat=37, current_lon=-122`) does NOT apply to a different context (e.g. `current_lat=51.5, current_lon=-0.1`). The verifier recomputes the context hash on each call and compares.

**Wire format:**

```jsonc
{
  "agent_id": "...",
  "allow": true,                        // false = explicit cached deny
  "context_hash": "<b64-32-bytes>",     // SHA-256 of canonical VerifierContext subset
  "issued_at": <unix-seconds>,
  "mac": "<b64-32-bytes>",
  "scope": "meeting:attend",            // the specific scope this verdict gates
  "valid_until": <unix-seconds>,
  "verdict_id": "...",                  // caller-assigned identifier
  "version": 1
}
```

**SDK API:**

```
VerifierContextHash(ctx) -> 32-byte SHA-256
IssuePolicyVerdict(verdictID, agentID, scope, allow, contextHash, issuedAt, validUntil, policySecret) -> PolicyVerdict
VerifyPolicyVerdict(verdict, policySecret, expectedAgentID, expectedScope, expectedContextHash, now) -> nil | error
```

The verify function:
- Returns `nil` on cached **allow** (MAC valid, fresh, all fields match).
- Returns `"policy_verdict_denied: ..."` on cached **deny** (MAC valid but `allow=false`).
- Returns any other error if the verdict is unusable (bad MAC, expired, scope mismatch, etc).

**Verifier fast-path semantics (§5.17):** when `VerifyOptions.PolicyVerdict` and `VerifyOptions.PolicySecret` are both set, the verifier consults the verdict BEFORE the `Policy` provider:
- Cached allow → live policy is **not called**; return success.
- Cached deny → live policy is **not called**; return `scope_denied`.
- Verdict unusable (expired / wrong MAC / scope mismatch) → fall through to live `Policy` provider. A stale verdict MUST NOT cause a verification failure on its own.

### 17.7 ConstraintEvaluator — extension constraint types

The built-in constraint types in §5.7.2 (`geo_circle`, `geo_polygon`, `geo_bbox`, `time_window`, `max_speed_mps`, `max_amount`, `max_rate`, `resource_path`) are the universal vocabulary every conformant SDK must implement byte-identically. Real deployments routinely need additional types (`max_concurrent_sessions`, `max_daily_spend`, `region_allowlist`, etc.) that don't belong in the universal spec.

**Parameters.** An extension constraint carries its parameters in the generic `params` object (§5.7.1): `params` is part of the canonical signed bytes, so parameterized extensions like `max_concurrent_sessions` or `max_daily_spend` are delegation-bound — signed by the principal, not merely enforced as verifier-local policy. The evaluator receives the full `Constraint` and reads its parameters from `params`. The value model is restricted (§5.7.1) so canonical bytes stay deterministic across languages; a type-only extension constraint (no `params`) serializes exactly as in earlier releases. Because every unregistered type fails closed as `constraint_unknown`, verifiers MUST be upgraded to a `params`-aware release before issuers begin emitting parameterized extension constraints. (Through v1.0.0-alpha.15, extension types were type-only on the wire and parameterized extensions could not be represented in a signed certificate; `params` removed that limitation.)

The `ConstraintEvaluator` interface is the pluggable layer: callers register evaluators keyed by constraint type. The resolution order is:

1. Built-in evaluators handle the universal types (always, by the SDK directly).
2. For any type the built-in evaluators do not recognize, the registry is consulted.
3. If no entry matches, the verifier fails closed with `identity_status="constraint_unknown"` (per §5.9).

**Interface:**

```
Evaluate(constraint, certID, context, now) -> nil | error
```

- `nil` → constraint passes; verification continues.
- `"constraint_unverifiable: <reason>"` (or wrapping the SDK's sentinel) → routes to `identity_status="constraint_unverifiable"`. Use this for "I don't have the inputs to decide."
- Any other error → routes to `identity_status="constraint_denied"`.

**Naming convention.** To prevent registry collisions between deployments, extension type names SHOULD use a vendor or namespace prefix:
- `verify.<type>` — types defined by Ratify Verify.
- `<vendor>.<type>` — types defined by a deployment / third party.

The protocol does not enforce naming; it does fail closed on every unregistered type, which means a deployment that uses extension types implicitly requires every downstream verifier to recognize them. **That's the moat:** a managed verifier (Ratify Verify) can ship a registry of `verify.*` types its customers use; an OSS verifier can recognize the same types only if its operator registers each one explicitly.

### 17.8 AnchorResolver — identity-bound audit

`Anchor` (§5.4) is an optional binding between a `HumanRoot` and an external identity system (Okta SSO, government ID attestation, verified email). v1 carried `Anchor` only at HumanRoot mint time. v1.1 adds `AnchorResolver`: a verifier-local lookup from `human_id` to the `Anchor` originally registered, populated on `VerifyResult.Anchor` whenever a bundle verifies AND a resolver is configured.

**Why this exists.** A `VerificationReceipt` proves "this bundle was verified at this time." An anchor-bound receipt proves "this bundle was verified at this time, AND the human root behind it was bound to an SSO-asserted identity at Okta as of `Anchor.VerifiedAt`." For compliance audits, that's the chain auditors want to see.

**Interface:**

```
ResolveAnchor(humanID) -> *Anchor | error
```

**Resolver errors are non-fatal.** A resolver that errors (identity directory down, network partition, unknown human ID) MUST NOT fail the bundle. The verifier silently leaves `VerifyResult.Anchor` nil and continues. Rationale: an identity-directory outage should not block a properly-signed, cryptographically-valid bundle; it should only degrade the audit trail.

**Audit interaction.** When both `AnchorResolver` and `Audit` are configured, the resolver runs BEFORE the audit hook, so the `VerifyResult` the audit provider sees already has `Anchor` populated. This is the contract: audit providers observe identity-bound results without having to perform their own lookup.

### 17.9 Cross-language naming for §17.5–§17.8

| Concept | Go | TypeScript | Python | Rust | C/C++ |
|---|---|---|---|---|---|
| Bundle hash | `BundleHash(b)` | `bundleHash(b)` | `bundle_hash(b)` | `bundle_hash(&b)` | `ratify_bundle_hash(b)` |
| Issue receipt | `IssueVerificationReceipt(...)` | `issueVerificationReceipt(...)` | `issue_verification_receipt(...)` | `issue_verification_receipt(...)` | `ratify_issue_verification_receipt(...)` |
| Verify receipt | `VerifyVerificationReceipt(r)` | `verifyVerificationReceipt(r)` | `verify_verification_receipt(r)` | `verify_verification_receipt(&r)` | `ratify_verify_verification_receipt(r)` |
| Chain pointer | `ReceiptHash(r)` | `receiptHash(r)` | `receipt_hash(r)` | `receipt_hash(&r)` | `ratify_receipt_hash(r)` |
| Context hash | `VerifierContextHash(ctx)` | `verifierContextHash(ctx)` | `verifier_context_hash(ctx)` | `verifier_context_hash(&ctx)` | `ratify_verifier_context_hash(ctx)` |
| Issue verdict | `IssuePolicyVerdict(...)` | `issuePolicyVerdict(...)` | `issue_policy_verdict(...)` | `issue_policy_verdict(...)` | `ratify_issue_policy_verdict(...)` |
| Verify verdict | `VerifyPolicyVerdict(...)` | `verifyPolicyVerdict(...)` | `verify_policy_verdict_e(...)` | `verify_policy_verdict(...)` | `ratify_verify_policy_verdict(...)` |
| Constraint evaluator | `ConstraintEvaluators map[string]ConstraintEvaluator` | `constraint_evaluators?: Record<string, ConstraintEvaluator>` | `constraint_evaluators: dict \| None` | `constraint_evaluators: Option<HashMap<String, Box<dyn ConstraintEvaluator>>>` | `ratify_set_constraint_evaluator(type, fn)` |
| Anchor resolver | `AnchorResolver` | `anchor_resolver?: AnchorResolver` | `anchor_resolver: AnchorResolver \| None` | `anchor_resolver: Option<Box<dyn AnchorResolver>>` | `ratify_set_anchor_resolver(fn)` |

### 17.10 Surface adapters — out of scope (intentional)

The integration code that turns a `ProofBundle` into a "Zoom auth gate," "Twilio SIP attestation," "AWS API Gateway authorizer," etc. — the **surface adapters** — lives in separate SDKs outside this protocol repository (`ratify/zoom-sdk`, `ratify/voice-sdk`, etc). Those repositories are the home of proprietary "last-mile" integration code and are NOT covered by this specification.

The protocol's contract stops at the `ProofBundle` wire format and the verifier algorithm. Anything above that — how a specific third-party platform's signaling layer is intercepted, how middleware is wired into a specific framework, how a specific incumbent product's auth model is mapped onto Ratify scopes — is integration work, not protocol work. Ratify Verify ships those adapters as commercial product; nothing about this specification prevents a third party from writing their own.

### 17.11 Deprecation: legacy `IsRevoked` closure

`VerifyOptions.IsRevoked` (the bare `func(certID) bool` closure) is **deprecated** in v1.0.0-alpha.7 and scheduled for removal in **v1.0.0-beta.1**. New code MUST use `Revocation` (§17.1).

**Why deprecated.** The closure has no way to surface a lookup failure. It must collapse "I don't know" to `false` (allow) or `true` (deny), neither of which is correct. `Revocation` returns `(bool, error)` and the verifier fails closed on error (`revocation_error`), which is the only sound behavior for a security-critical lookup.

Until v1.0.0-beta.1, the closure remains functional: when both fields are set on `VerifyOptions`, the `Revocation` provider takes precedence (§17.1). Each SDK marks the field deprecated via its language's idiomatic mechanism (Go doc comment, TypeScript `@deprecated` JSDoc, Python `warnings.warn` on use, Rust `#[deprecated]`, C `ratify_set_revocation_source()` replaces the legacy `is_revoked` function pointer field).

---

## 18. References

- Ed25519: [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)
- ML-DSA (post-quantum digital signatures): [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- SHA-256: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- JSON: [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259)
- JSON Canonicalization Scheme: [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)
- Base64: [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) §4
- CNSA 2.0 post-quantum transition: [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

---

*v1.0.0-alpha.15 · Identities AI · CC-BY-4.0 · Patent Pending*
