# Ratify Protocol Specification v2, Annex A: Incorporated v1 Text

**Status:** Normative for Protocol v2. This annex is part of `SPEC-v2.md`.

## A.1 Status, pinning, and interpretation

Protocol v2 reuses three clauses of the v1 specification: the restricted value model, the canonical JSON rules, and the scope vocabulary. This annex holds an exact copy of each clause. **The text in this annex, not `SPEC.md`, is normative for v2.** A later edit to `SPEC.md`, including an editorial one, does not change v2 conformance. Changing any clause below requires a revision of this annex, a matching change to `SPEC-v2.md`, and regenerated vectors in `testvectors/v2/annex-a.json`.

Source of every copied clause: `SPEC.md` at commit `1d44c5eb42dd9900b720652413749de7766b72a0`, whose whole-file SHA-256 is `087e8abe49ddf171c3e7b4ca69790e16799d3217bc63c15e7087f0e025f0e4aa`. Each clause sits between an HTML comment `<!-- annex-a:begin <id> -->` and `<!-- annex-a:end <id> -->`. Its digest is the SHA-256 of the exact UTF-8 bytes between the line after the begin marker and the line before the end marker, without the final newline:

| Clause | Copied from `SPEC.md` | Bytes | SHA-256 |
| --- | --- | --- | --- |
| A.2 | §5.7.1, the "Restricted value model" item only | 499 | `adc4e5aba2f47577f4eb336a226c46d9d45d108e111b0ca8cb084a1c4277a727` |
| A.3 | §§6.1 to 6.3 | 1616 | `e89aeebd1238aff661ae087cec6134cd8c70d63eb7584003ce2539f9c182f9ab` |
| A.4 | §9 introduction and §§9.1 to 9.5 | 11777 | `bf265807bd61dd241bbcca4f70a2e860ec436c5f09bceeb82f0ae607ceaf15c6` |

The Go conformance test `TestV2AnnexAClausesArePinned` recomputes these digests from this file and compares them with `testvectors/v2/annex-a.json`.

**Reading the copied text as v2.** The copied text keeps its v1 wording. Inside v2 it is read with these rules, which are normative:

1. A section number inside a copied clause refers to `SPEC.md` and is context only, except where this list maps it. `MAX_JSON_NESTING_DEPTH` (§5.1) and `MAX_PROOF_BUNDLE_BYTES` are the v2 limits of `SPEC-v2.md` §2.6. The canonical constraint types of §5.7.2 are replaced by the closed v2 registry of `SPEC-v2.md` §5.2, and a v2 verifier fails closed on an unregistered type as `SPEC-v2.md` §5.2 states, not through the v1 `ConstraintEvaluator` of §17.7. The `invalid_scope` result of §5.9 and §10 step 7.a2 is the v2 post-claim `invalid_scope` result of `SPEC-v2.md` §6.4 and §6.7. The signable objects of v1 §6.4 are not incorporated; v2 defines its own signing transcript (`SPEC-v2.md` §3).
2. A requirement that the copied text addresses to "v1 implementations" applies to v2 implementations as well. In particular, the reserved prefixes of §9.5 are out-of-vocabulary in v2.
3. The function names `ValidateScopes`, `validate_scopes`, `expand_scopes`, `is_sensitive`, and `intersect_scopes` name operations, not required API symbols.
4. `SPEC-v2.md` adds rules on top of the copied text and those rules win where they are stricter: the v2 strict-decode rules of `SPEC-v2.md` §2.1 (no fraction or exponent in any number token, no `-0`, no unpaired UTF-16 surrogate escape, no duplicate key, canonical padded base64); the prohibition of `custom:*` and of an empty or duplicate scope list in a v2 certificate (`SPEC-v2.md` §5.1); and the rules for a request's `required_scope` in `SPEC-v2.md` §2.4, which govern what a verifier may be asked to decide. The copied text governs the vocabulary, wildcard expansion, chain intersection, and the treatment of `custom:` scopes inside certificates.
5. Non-normative passages inside a copied clause (rationale, suggested naming conventions, "when to use" lists) remain non-normative.

**Not incorporated.** v1 §9.6 (physical-world and embodied use cases) is not incorporated. Its physical scopes are already in A.4, but it points to the v1 `geo_*`, `max_speed_mps`, and related constraints, which v2 does not define; see `SPEC-v2.md` §9.9. No other v1 text is normative for v2.

**Vectors.** `testvectors/v2/annex-a.json` locks the behavior these clauses define: canonical JSON key order, escaping, and integer forms; Unicode handling without normalization; the strict-decode rejections that v2 adds; the complete canonical vocabulary, its sensitive set, and every wildcard expansion; chain intersection; and `custom:` scope behavior inside certificates.

## A.2 Restricted value model (v1 §5.7.1)

<!-- annex-a:begin A.2 -->
- **Restricted value model**, so canonical bytes are deterministic across languages. Permitted values: `null`, booleans, strings, safe integers (|n| ≤ 2^53 − 1), and arrays and objects of these. Prohibited: floats and any non-integer numbers, `NaN`/`Infinity`, raw bytes, and duplicate object keys. Integers beyond 2^53 − 1 MUST be carried as decimal strings. Nesting depth is bounded by `MAX_JSON_NESTING_DEPTH` (§5.1); total size participates in the ordinary `MAX_PROOF_BUNDLE_BYTES` limit.
<!-- annex-a:end A.2 -->

## A.3 Canonical serialization (v1 §§6.1 to 6.3)

<!-- annex-a:begin A.3 -->
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
<!-- annex-a:end A.3 -->

## A.4 Scope vocabulary (v1 §9 introduction and §§9.1 to 9.5)

<!-- annex-a:begin A.4 -->
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
<!-- annex-a:end A.4 -->
