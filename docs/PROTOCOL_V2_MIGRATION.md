# Upgrading from Ratify Protocol v1 to v2

**Applies to:** `2.0.0-beta.1` and later v2 prereleases. **Normative text:**
[`SPEC-v2.md`](../SPEC-v2.md) and [`SPEC-v2-ANNEX-A.md`](../SPEC-v2-ANNEX-A.md).
Section numbers prefixed "v1" refer to [`SPEC.md`](../SPEC.md); all others
refer to `SPEC-v2.md`.

This is the upgrade guide for teams that issue or verify Ratify Protocol v1
delegated-authority proofs today. It explains what v2 changes, what stays
compatible, and the order in which to move each part of a deployment.

## Release status

`2.0.0-beta.1` is a prerelease. It freezes the v2 wire format and SDK API.
Review so far is internal adversarial review of the specification, the
vectors and every SDK. External independent review and interoperability with
at least one implementation outside this repository are gates for `2.0.0`
(SPEC-v2 §8.2), so no v2 release carries a production security claim yet.
The in-memory reference stores that the SDKs ship for tests and examples are
development-only.

## Why v2

v1 left freshness, status and audit to local hooks. A revocation callback
could return an unsigned boolean, a policy hook could rewrite the result, and
a verifier could act on a result that nobody recorded. v2 fixes the Protocol
result first and lets application policy run only after it. In practice v2
brings:

- **Verify, then release.** `VerifyProofBundleV2` commits a terminal result
  and a receipt body. That committed outcome is not actionable.
  `ReleaseV2Decision` returns the only actionable decision, and only after the
  signed receipt is appended to an ordered log, an independent checkpoint has
  acknowledged it, and the challenge and allow deadlines are still current
  (§6.9).
- **Signed status under a separate status key.** Revocation lists and pushes
  are signed by a status key that may not reuse the issuer's key, applied
  through an anchored `SecurityJournalV2`, and required for every certificate
  in the chain before an allow (§5.4, §6.5, §6.6). A minimal status publisher
  ships in every SDK.
- **Stored challenges and atomic claims.** The challenge issuance helper
  persists each challenge before returning it; the verifier loads it, claims
  it atomically, and never evaluates a replay (§6.2, §7.3).
- **Receipts for every terminal result,** in a hash-chained log with an
  independent checkpoint (§5.8, §7.7, §7.8).
- **Exact `custom:` scopes and evaluator profiles.** A required scope may be
  one exact `custom:<name>` that every certificate in the chain lists.
  Extension constraints are evaluated only by caller-registered profiles whose
  digests are signed into the receipt; `com.ratifyprotocol.max_count/v1` and
  `com.ratifyprotocol.allowed_values/v1` are standard (§5.2).
- **A closed constraint registry with integer-only numbers:** `time_window`
  (pinned IANA tzdata), `max_amount` in integer micro-units
  (`max_amount_micros`), `max_rate`, `resource_path` and
  `ratify.receiver_audience` (§5.2).
- **Domain-separated hybrid signatures.** Each signed object is signed with
  Ed25519 and ML-DSA-65 (FIPS 204) over a message that names the object type,
  with a fixed ML-DSA context per object type. Both signatures must verify
  (§3). Key IDs are full 256-bit `key_id_v2` values, and trust is pinned to
  complete public keys (§2.3, §6.1).
- **Typed and external signers.** No SDK exports a function that signs
  caller-chosen bytes. An external signing provider can hold the private key;
  the SDK verifies every returned signature before use (§3.2).
- **Wire limits checked before parsing, a closed table of 49 error classes,
  finite delegation lifetimes, and deployment profiles** for a single offline
  device, dual-root approval and middleware custody (§2.5 to §2.7, §7.13 to
  §7.15).

## Compatibility statement

- **v2 is not backward compatible with v1.** Signed bytes, key IDs, challenge
  signing, status references and verifier ordering all differ. A v1 proof is
  not a v2 proof, a v2 verifier rejects v1 objects, and there is no automatic
  fallback in either direction (§1.1).
- **Migration is a clean re-enrollment.** Generate fresh v2 keys and issue new
  v2 delegations. No v1 key can authorize a v2 key, and importing a v1 key
  into a v2 identity is prohibited.
- **Side-by-side operation is supported.** v1 and v2 run together in one
  build or environment in every ecosystem (see [Install](#install)). A deployment chooses
  the version explicitly at each API boundary and keeps a v1 verifier for v1
  proofs until it retires them.
- **v1 remains available and pinned.** Released v1 tags and artifacts are
  never moved or replaced, and v2 never widens a v1 dependency range. There is
  no fixed, dated v1 support window today; v1 support terms will be announced
  with `2.0.0`.
- **v1-only until 2.1.** Four v1 capabilities have no v2.0 equivalent: the
  SessionToken fast path, the A2A mutual presentation profile, the HTTP and
  registry bindings, and the geo and speed constraints. They are planned for
  Protocol 2.1, together with activation constraints. Until then, any claim that depends on them is a v1
  claim (see [v1-only until 2.1](#v1-only-until-21)).

## Install

| SDK | v2 (beta line) | v1 (stays available) |
| --- | --- | --- |
| Go | `go get github.com/identities-ai/ratify-protocol/v2@v2.0.0-beta.1`, import `github.com/identities-ai/ratify-protocol/v2` | `go get github.com/identities-ai/ratify-protocol@v1.0.0-alpha.20` (original module path) |
| TypeScript | `npm install @identities-ai/ratify-protocol@2.0.0-beta.1` (dist-tag `next`), import from `@identities-ai/ratify-protocol/v2` | `npm install @identities-ai/ratify-protocol@1.0.0-alpha.20` (dist-tag `latest`) |
| Python | `pip install "ratify-protocol[protocol-v2]==2.0.0b1"`, import `ratify_protocol.v2` (the `protocol-v2` extra pulls in the `ratify-protocol-native-v2` signing backend) | `pip install ratify-protocol==1.0.0a21` (the v1 maintenance release), import `ratify_protocol` |
| Rust | `cargo add ratify-protocol@2.0.0-beta.1`, use `ratify_protocol::v2` | `ratify-protocol = "=1.0.0-alpha.20"` |
| C/C++ | `ratify-c` 2.x release archive or `cargo build --release` in `sdks/c`; `#include "ratify.h"` and call `ratify_v2_*`; check `ratify_v2_abi_version()` | the `1.0.0-alpha.20` release archive and its `ratify_*` ABI |

Side by side in one build:

- **Go:** the two lines have different module paths, so one module can
  require both and import them as, for example, `ratifyv1` and `ratify`.
- **TypeScript:** the 2.x package exports the v2 API from
  `@identities-ai/ratify-protocol/v2` and keeps the v1 API at the package
  root. To keep the exact v1 release as well, add an alias:
  `npm install ratify-v1@npm:@identities-ai/ratify-protocol@1.0.0-alpha.20`.
  An unpinned install resolves to v1 until `2.0.0`.
- **Python:** the 2.x `ratify-protocol` distribution keeps the v1 API at
  `ratify_protocol` and adds `ratify_protocol.v2`, so one environment runs
  both; `import ratify_protocol` never loads v2. v2's requirements (the
  `ratify-protocol-native-v2` signing backend and the pinned `tzdata` release)
  come with the `protocol-v2` extra, and the base install keeps v1's. Every
  published version is a prerelease, so an install or upgrade without a pin
  resolves to `2.0.0b1`; pin `ratify-protocol<2` or `==1.0.0a21` to stay on
  the v1 release line. The exact v1 release cannot be installed next to 2.x
  in one environment because they share a distribution name, so a process
  that must run the exact v1 release uses its own environment.
- **Rust:** the 2.x crate keeps the v1 API at the crate root and adds
  `ratify_protocol::v2`. To keep the exact v1 release, rename it:
  `ratify_v1 = { package = "ratify-protocol", version = "=1.0.0-alpha.20" }`.
- **C/C++:** the 2.x library exports the unchanged v1 `ratify_*` ABI next to
  the `ratify_v2_*` ABI. Check `ratify_v2_abi_version()` at startup.

## Before and after

v1 verification is one call that returns a status. A typical v1 Go verifier:

```go
import ratify "github.com/identities-ai/ratify-protocol"

result := ratify.Verify(&bundle, ratify.VerifyOptions{
	RequiredScope: "payments:send",
	IsRevoked:     func(certID string) bool { return revoked[certID] },
})
if result.Valid {
	sendPayment()
}
```

In v2 the same decision takes four steps: verify (a committed outcome),
publish the signed receipt, obtain the checkpoint acknowledgement, and
release. Only the released decision gates the side effect, at the receiver's
authoritative time:

```go
if decision.Allowed(ctx, clock) {
	sendPayment()
}
```

The complete v2 code lives in tested example programs, one set per SDK. Every
program prints the same output in every language, and CI compares it with
[`examples/v2/expected/`](../examples/v2/expected/):

| Program | What it shows | Go | TypeScript | Python | Rust | C |
| --- | --- | --- | --- | --- | --- | --- |
| quickstart | keys, delegation with `max_amount_micros`, challenge from the issuance helper, proof, verify, receipt, checkpoint, release, `Allowed`, replay | [Go](../examples/v2/go/quickstart/main.go) | [TS](../examples/v2/typescript/quickstart.ts) | [Python](../examples/v2/python/quickstart.py) | [Rust](../examples/v2/rust/src/bin/quickstart.rs) | [C](../examples/v2/c/quickstart.c) |
| signed status | status publisher under a separate key, role separation, journal ingestion, a revocation that turns a later verification into deny | [Go](../examples/v2/go/signed_status/main.go) | [TS](../examples/v2/typescript/signed_status.ts) | [Python](../examples/v2/python/signed_status.py) | [Rust](../examples/v2/rust/src/bin/signed_status.rs) | [C](../examples/v2/c/signed_status.c) |
| custom scope | exact `custom:` scope, `custom:*` refused, the `max_count/v1` evaluator profile and its digest in the receipt | [Go](../examples/v2/go/custom_scope/main.go) | [TS](../examples/v2/typescript/custom_scope.ts) | [Python](../examples/v2/python/custom_scope.py) | [Rust](../examples/v2/rust/src/bin/custom_scope.rs) | [C](../examples/v2/c/custom_scope.c) |
| external signer | a provider holds the key; the SDK verifies every returned signature and refuses a faulty provider | [Go](../examples/v2/go/external_signer/main.go) | [TS](../examples/v2/typescript/external_signer.ts) | [Python](../examples/v2/python/external_signer.py) | [Rust](../examples/v2/rust/src/bin/external_signer.rs) | [C](../examples/v2/c/external_signer.c) |

The examples use the in-memory reference stores and are development-only. A
production verifier supplies durable Part B stores and an independent
checkpoint (step 7 below).

## Upgrade steps

### 1. Keep v1 running and pin it

Pin the exact v1 release you run today and keep its verifier for existing v1
proofs. Do not widen a v1 dependency range to include 2.x. Install the v2
package next to it (see [Install](#install)) on a test branch.

### 2. Generate v2 keys and prove possession

Every principal (organization or person root, issuer, agent, verifier,
status publisher) gets a fresh v2 hybrid key. Establish who owns each root out
of band, have the holder prove possession of the new key, and configure trust
as the **complete** root public key. Never pin trust to a key ID alone: the
verifier recomputes the ID from the key you configured and fails closed on
any mismatch or ambiguity (§6.1).

### 3. Re-issue delegations with v2 constraint schemas

Issue new v2 delegation certificates with the typed signer
(`SignDelegationCertV2` or its external-signer form). The signer checks issuer
duties before it signs (§5.1):

- Every certificate has a finite `expires_at`; the lifetime is at most
  315360000 seconds. There is no no-expiry sentinel.
- Amounts move from v1 floats to integers: `max_amount` becomes
  `{"type":"max_amount","currency":"USD","max_amount_micros":50000000}` for
  50.00 USD, and the verifier receives the requested amount in the same unit.
- `custom:` scopes are exact. A required scope may be one `custom:<name>`, it
  must appear in every certificate of the chain, and `custom:*` is invalid.
- Application-specific constraints move to extension types evaluated by a
  registered profile. Use the standard `com.ratifyprotocol.max_count/v1` (for
  example, a node or seat count) and `com.ratifyprotocol.allowed_values/v1`
  (an exact value such as a work-order category), or publish your own
  versioned profile. A verifier without the profile fails closed with
  `constraint_unknown`.
- `geo_circle`, `geo_polygon`, `geo_bbox` and `max_speed_mps` have no v2.0
  equivalent. Keep those delegations on v1 until 2.1, or bind the condition
  in application policy after release.

### 4. Set up signed status with a separate status key

Generate a status key for each issuer that is distinct from every root,
issuer, agent and verifier key (the publisher and the verifier both check
every component), record key roles and the status key epoch in the
`SecurityJournalV2`, and run the status publisher: a genesis list, heartbeats
that refresh freshness, and revocations as a signed push plus the cumulative
list at the next sequence. Persist the publisher state before you publish
each object. Replace v1 revocation callbacks: the verifier's status provider
returns signed objects only, and an unavailable or stale status yields
`indeterminate`, never allow.

### 5. Issue challenges with the issuance helper

Replace self-issued or ad hoc challenges with the issuance helper. It reads
the authoritative clock, draws 32 random bytes, persists the full record
(namespace, replay epoch, verifier ID, expected agent and receiver, session
context) and only then returns the challenge. The verifier loads the record
by the presented challenge. Challenge lifetime is 1 to 300 seconds and every
deadline is exclusive (§2.5).

### 6. Move verifiers to verify, commit, release

Call `VerifyProofBundleV2` with the stored expected challenge, an explicit
context policy, the required scope, the request context, the status keys and
policy, and the evaluator registry. Then publish the committed receipt body
to your receipt log, wait for the checkpoint acknowledgement, and call
`ReleaseV2Decision`. Gate each side effect on `Allowed(clock)` just before it
runs. Move application policy (the v1 `PolicyProvider` role) to after
release; it may only narrow a released decision. Map v1 statuses to the v2
decision, reason and error classes (§2.7, §6.7).

### 7. Supply durable Part B stores

The reference stores are in-memory and test-only. Production needs durable
implementations of the claim store with an authoritative clock, the challenge
issuance store, stream sequence and rate reservation, the receipt outbox and
log, an independent checkpoint in a separate failure domain, and the anchored
journal store with compare-and-swap (§7). The single-device offline profile
(§7.13) defines how one device can host both sides safely.

### 8. Test before cutover

Run the SDK's own suite against `testvectors/v2`, the lifecycle scenarios, and
your deployment's failure cases: status unavailable, checkpoint withheld,
signer failure, clock regression, replay, and restore. Re-run each reference
integration's gate and record the exact versions.

### 9. Run side by side, then retire v1

Choose the version at every boundary: a v1 proof goes to the v1 verifier and
a v2 proof to the v2 verifier, with no fallback between them. Move issuers
first so new delegations are v2, then move verifiers, then stop issuing v1
delegations. When no live v1 delegation remains, remove the v1 verifier.
Retiring a hosted v1 endpoint does not revoke proofs that third-party offline
verifiers may still accept, so revoke outstanding v1 delegations through the
v1 status path before you retire it.

## Mapping v1 concepts to v2

| v1 concept | v2 equivalent | Notes |
| --- | --- | --- |
| `HumanRoot` (v1 §5.4) | A caller-authenticated root key in trust configuration (§6.1); `authority_id` and `role` in rotation statements (§5.5) | v2 has no enrollment object. A root is a complete hybrid public key that the deployment pins; its identity is established out of band. |
| `Anchor` (v1 §5.5) | Deployment metadata outside the Protocol; optional `human_id` in a verification receipt | `human_id` is association metadata, not proof of a person (§9.11). |
| `AgentIdentity` (v1 §5.6) | The agent's complete hybrid key and `key_id_v2` (§2.3), carried in the proof bundle as `agent_id` and `agent_pub_key` | Names and other descriptive fields are application data. |
| `AnchorResolver` (v1 §17.8) | Application code after release, if it needs external-identity metadata | It never supplies trust. Root keys come only from caller-authenticated trust configuration (§6.1, §9.5), never from a resolver the proof selects. |
| `PolicyProvider` (v1 §17.2) | Application policy after `ReleaseV2Decision` | Policy may only narrow a released result. It cannot turn a committed outcome into a released one or rewrite a receipt (§9.12). |
| `AuditProvider` (v1 §17.3) | Mandatory signed verification receipts (code `0x0008`) in a hash-chained log acknowledged by an independent checkpoint (§5.8, §7.7, §7.8) | Pre-claim failures create no receipt; record them in application audit if needed. |
| `PolicyVerdict` (v1 §17.6) | No Protocol equivalent | An application cache must bind at least the policy version, `request_hash`, agent, scope, and expiry, and must never be labeled a Protocol `allow` (§9.12). |
| `RevocationProvider` and the legacy `IsRevoked` closure (v1 §17.1, §17.11) | The status evidence provider and the anchored `SecurityJournalV2` (§5.4, §6.5, §6.6), fed by the status publisher | Only signed status under a separate status key counts; a bare boolean or unsigned result is rejected. An `allow` always requires current status, so there is no `ForceRevocationCheck` switch. |
| `ConstraintEvaluator` (v1 §17.7) | Extension evaluator profiles in a caller-authenticated registry (§5.2) | The registry maps an exact extension type to a versioned profile. The profiles a chain uses are sealed with the claim and listed with their digests in the receipt member `constraint_evaluators`. Standard profiles: `com.ratifyprotocol.max_count/v1` and `com.ratifyprotocol.allowed_values/v1`. An unregistered type fails closed as `constraint_unknown`; an evaluator error, panic or timeout is `constraint_unverifiable`. The certificate never selects code. |
| v1 constraint types (v1 §5.7.2, §5.7.3) | The closed v2 registry: `time_window`, `max_amount`, `max_rate`, `resource_path`, `ratify.receiver_audience` (§5.2) | No floats: `max_amount` uses `max_amount_micros`; `time_window` uses pinned IANA tzdata. Geo and speed types are not registered in v2.0 (2.1). |
| `custom:` required scope (v1 §9) | One exact `custom:<name>` required scope (§2.4) | Byte-equal to an entry of the effective scope; every certificate in the chain lists it; `custom:*` and the bare prefix `custom:` are invalid. |
| Verifier-generated challenge bytes and `ChallengeStore` (v1 §10) | Challenge issuance helper and the atomic claim (§6.2, §7.3) | Persist before expose; the verifier loads the stored record by the presented challenge and claims it once. |
| `VerificationReceipt` (v1 §17.5) | Verification receipt `0x0008` (§5.8) | Required for every terminal result; a decision is actionable only after release (§6.9). |
| `KeyRotationStatement`, `WitnessEntry`, `TransactionReceipt` (v1 §5.12, §5.14, §5.15) | v2 rotation (§5.5), witness entry (§5.6), transaction receipt (§5.7) | New signed bytes and v2 key IDs. Rotation is intra-v2 only; no v1 key authorizes a v2 key (§1.1). |
| `VerifyResult` statuses (v1 §5.9) | Error classes (§2.7) and terminal decision, reason, and assessments (§6.7) | A committed outcome is not a decision until released. |
| Self-issued challenges (v1 §10) | Archival verification only (§6.10) | Labeled `freshness_unverified`; never authorizes a live action. |
| Private key signing calls | Typed signers and the `SignerV2` external signer interface (§3.2) | Direct or external-mu mode. The SDK verifies every returned signature. No KMS or HSM claim is made. |
| Middleware Custody Profile (v1 §15.2.1) | Middleware Custody Profile (§7.15) | Same purpose, v2 constructions, explicit non-claim. |
| Canonical JSON, value model, scope vocabulary (v1 §5.7.1, §§6.1 to 6.3, §9) | Annex A (`SPEC-v2-ANNEX-A.md`) | The annex copy is normative for v2; later edits to `SPEC.md` do not change v2. v2 JSON is integer-only. |

## v1-only until 2.1

These v1 capabilities have no v2.0 equivalent. v1 remains available for
them, and any claim that depends on them must be labeled a v1 claim.

| v1 capability | v2.0 | Planned for 2.1 |
| --- | --- | --- |
| `SessionToken` fast path (v1 §5.13) and streamed turns | None | A verifier-held session grant with per-turn request binding. |
| A2A mutual presentation (v1 §11.1) | None | A mutual presentation profile. Two independent v2 proofs are possible today but do not establish one conversation. |
| HTTP transport and registry read bindings (v1 §13, §13.1) | None | Bindings. Registry lookup remains deployment code that feeds trust configuration (§9.5). |
| `geo_circle`, `geo_polygon`, `geo_bbox` and `max_speed_mps` constraints (v1 §5.7.2) | None | Position, speed and activation constraints with a specified integer algorithm. Physical scopes exist in v2, but a v2.0 delegation cannot express a geofence or speed limit (§9.9). |

## Not carried into v2

These v1 capabilities are removed and are not planned to return.

| v1 capability | Reason |
| --- | --- |
| No-expiry sentinel (`NO_EXPIRY_SENTINEL`, v1 §5.7) | Every v2 delegation has a real `expires_at`, with a lifetime of at most 315360000 seconds (§2.5). Open-ended grants made revocation the only bound; v2 requires a finite one. |
| Empty required scope (v1 §5.17, which skipped the scope check) | A v2 request names exactly one valid required scope before claim (§2.4); a verification that checks no scope cannot be released as authorization. |
| Floating-point constraint values | v2 is integer-only. Amounts use micro-units; values that need a specified integer algorithm (geo, speed) wait for 2.1. |
| Identity enrollment objects (`HumanRoot`, `Anchor`, `AgentIdentity`) | Enrollment is deployment policy. v2 security rests on complete keys, `authority_id`, and caller-authenticated trust configuration. |
| `PolicyProvider`, `AuditProvider`, `PolicyVerdict` hooks | Policy and audit hooks inside verification let a mutable local result change or stand in for the Protocol result. v2 fixes the Protocol result and receipt first, and application policy runs after release. |
| `AnchorResolver` as part of verification | Metadata lookup is not trust; trust is configured before verification. |
| Unsigned or boolean revocation inputs, and `ForceRevocationCheck` | Status must be signed under a separate status key and evaluated through the anchored journal, and every allow requires current status. |
| Self-issued live challenges | A live decision needs an authenticated, stored expected challenge and an atomic claim. |

## Do not infer

Installing v2 does not migrate keys, delegations, trust anchors, revocation
state, or application policy. A v2 key proves possession, not an organization's
identity. Trust enrollment, domain control, approval, and operational key
custody are managed by the application or service using the Protocol. The
schedule for retiring any hosted v1 API is a separate, dated announcement for
that service; the open Protocol does not set one.
