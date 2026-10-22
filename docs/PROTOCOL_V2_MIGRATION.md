# Protocol v2 migration and compatibility

**Status:** Draft release advisory. Publish with the first Protocol v2 SDK release.

Ratify Protocol v2 is a breaking protocol version. It changes signed bytes,
key identifiers, challenge signing, issuer-scoped status references, verifier
ordering, and some signed-object fields. A v1 proof is not a v2 proof.

## What stays compatible

- Released v1 tags and package artifacts remain immutable. Applications that
  pin a v1 package and use a v1 verifier continue to use the v1 contract.
- V2 is a distinct major-version line and uses explicit v2 APIs. No v2 API
  silently downgrades or accepts a mixed v1/v2 bundle.
- The v1-to-v2 migration re-enrolls principals with fresh v2-only keys and
  issues new delegations. There is no v1-key-signed continuity bridge.

## Upgrade sequence

1. Pin the current v1 package and retain its verifier for existing v1 data.
2. Install the v2 major package in a test branch and run both SDK conformance
   suites. Do not update a v1 dependency range to include v2.
3. Establish each human or organization identity out of band, generate fresh
   v2 hybrid keys, prove possession, and configure the v2 trust anchor.
4. Reissue each delegation using v2 and update the verifier API to select v2
   explicitly. Never send a v1 credential to a v2 verifier.
5. Test revocation ingestion, status freshness, receiver and operation binding,
   replay handling, receipts, recovery, and rollback before cutover.
6. Keep v1 verification available for the announced migration period where it
   is needed. Retiring a hosted v1 endpoint does not revoke proofs accepted by
   third-party offline verifiers that ignore current status.

## SDK package lines

The v1 package versions remain immutable and continue to identify v1 behavior.
V2 releases must not replace those artifacts or widen a v1 dependency range.
Use these package-specific major-version boundaries:

- Go: publish v2 from the Go module major path
  `github.com/identities-ai/ratify-protocol/v2`; keep the current module path
  for v1.
- TypeScript: keep `@identities-ai/ratify-protocol` and publish a separate
  `2.0.0-alpha.N` release line. Existing exact `1.0.0-alpha.20` pins remain v1.
- Python: publish v2 under a distinct distribution and import package so v1
  and v2 can be installed together. The proposed names are
  `ratify-protocol-v2` and `ratify_protocol_v2`; reserve and test both before
  publication. Do not publish v2 under `ratify-protocol`: an unbounded v1
  requirement could otherwise resolve to the incompatible v2 package.
- Rust: keep crate `ratify-protocol` and publish a separate `2.0.0-alpha.N`
  release line.
- C: publish `ratify-c` 2.x with a v2 ABI and explicit ABI/version query. Keep
  the alpha.20 crate and its v1 ABI intact. Do not silently change a shared
  library ABI under the v1 name.
- Python native: keep the released v1 extension intact and use a distinct v2
  distribution and module when v2 native support is ready. Version it in
  lockstep with the Python v2 SDK and reject mismatched extension versions at
  import time. It is the Python SDK's backend, not an independent wire
  verifier. From `2.0.0-beta.1` the Python v2 SDK signs only through this
  native backend (SPEC-v2 §1.3); pure-Python verification remains available.

Every package line must be tested from its published artifact in a clean
consumer environment. Local workspace imports do not qualify as release evidence.
The Python v2 helpers no longer live in the v1 source package. They are in the
separate `ratify-protocol-v2` distribution (import package `ratify_protocol_v2`,
source `sdks/python-v2`), with native key generation in
`ratify-protocol-native-v2` (`sdks/python-native-v2`). Both are versioned
`2.0.0a1` in this repository and neither is published. Their tests pass from
the source tree in pure-Python and native-required modes, and locally built v1
and v2 packages install and import side by side in one environment. Repeating
that check against the published artifacts in a clean consumer environment
remains a release gate.

The schedule for any hosted API retirement is a separate, dated Verify
announcement. The open Protocol release does not prescribe a universal
retirement date. Every v2 SDK release is a prerelease. `2.0.0-beta.1` freezes
the v2 wire and API only after every SDK meets the gates in `SPEC-v2.md` §8.1
and the internal adversarial review closes; it carries no production security
claim, and its release notes state that external review has not yet happened.
`2.0.0` additionally requires external interoperability, an external
independent review, and a soak (`SPEC-v2.md` §8.2).

## Mapping v1 concepts to v2

Section numbers prefixed "v1" refer to `SPEC.md`; others refer to
`SPEC-v2.md`. "2.1" marks a capability planned for Protocol 2.1. Until then
it remains available only in v1, and any claim that depends on it must be
labeled a v1 claim.

| v1 concept | v2 equivalent | Notes |
| --- | --- | --- |
| `HumanRoot` (v1 §5.4) | A caller-authenticated root key in trust configuration (§6.1); `authority_id` and `role` in rotation statements (§5.5) | v2 has no enrollment object. A root is a complete hybrid public key that the deployment pins; its identity is established out of band. |
| `Anchor` (v1 §5.5) | Deployment metadata outside the Protocol; optional `human_id` in a verification receipt | `human_id` is association metadata, not proof of a person (§9.11). |
| `AgentIdentity` (v1 §5.6) | The agent's complete hybrid key and `key_id_v2` (§2.3), carried in the proof bundle as `agent_id` and `agent_pub_key` | Names and other descriptive fields are application data. |
| `AnchorResolver` (v1 §17.8) | Application code after release, if it needs external-identity metadata | It never supplies trust. Root keys come only from caller-authenticated trust configuration (§6.1, §9.5), never from a resolver the proof selects. |
| `PolicyProvider` (v1 §17.2) | Application policy after `ReleaseV2Decision` | Policy may only narrow a released result. It cannot turn a committed outcome into a released one or rewrite a receipt (§9.12). |
| `AuditProvider` (v1 §17.3) | Mandatory signed verification receipts (code `0x0008`) in a hash-chained log acknowledged by an independent checkpoint (§5.8, §7.7, §7.8) | Pre-claim failures create no receipt; record them in application audit if needed. |
| `PolicyVerdict` (v1 §17.6) | No Protocol equivalent | An application cache must bind at least the policy version, `request_hash`, agent, scope, and expiry, and must never be labeled a Protocol `allow` (§9.12). |
| `RevocationProvider` and the legacy `IsRevoked` closure (v1 §17.1, §17.11) | The status evidence provider and the anchored `SecurityJournalV2` (§5.4, §6.5, §6.6) | Only signed status under a separate status key counts; a bare boolean or unsigned result is rejected. An `allow` always requires current status, so there is no `ForceRevocationCheck` switch. |
| `ConstraintEvaluator` (v1 §17.7) | The closed v2 constraint registry (§5.2) | An unregistered type fails closed as `constraint_unknown`. |
| `VerificationReceipt` (v1 §17.5) | Verification receipt `0x0008` (§5.8) | Required for every terminal result; a decision is actionable only after release (§6.9). |
| `KeyRotationStatement`, `WitnessEntry`, `TransactionReceipt` (v1 §5.12, §5.14, §5.15) | v2 rotation (§5.5), witness entry (§5.6), transaction receipt (§5.7) | New signed bytes and v2 key IDs. Rotation is intra-v2 only; no v1 key authorizes a v2 key (§1.1). |
| `VerifyResult` statuses (v1 §5.9) | Error classes (§2.7) and terminal decision, reason, and assessments (§6.7) | A committed outcome is not a decision until released. |
| Self-issued challenges (v1 §10) | Archival verification only (§6.10) | Labeled `freshness_unverified`; never authorizes a live action. |
| Middleware Custody Profile (v1 §15.2.1) | Middleware Custody Profile (§7.15) | Same purpose, v2 constructions, explicit non-claim. |
| Canonical JSON, value model, scope vocabulary (v1 §5.7.1, §§6.1 to 6.3, §9) | Annex A (`SPEC-v2-ANNEX-A.md`) | The annex copy is normative for v2; later edits to `SPEC.md` do not change v2. |
| `SessionToken` (v1 §5.13) | None in 2.0; 2.1 | A verifier-held session grant with per-turn request binding is planned. Session-token claims stay v1 claims. |
| Mutual presentation (v1 §11.1) | None in 2.0; 2.1 | Two independent v2 proofs are possible but do not establish one conversation. |
| HTTP transport and registry read bindings (v1 §13, §13.1) | None in 2.0; 2.1 | Registry lookup remains deployment code that feeds trust configuration (§9.5). |
| `geo_circle`, `geo_polygon`, `geo_bbox`, `max_speed_mps` (v1 §5.7.2) | None in 2.0; 2.1 | Physical scopes exist in v2, but a v2.0 delegation cannot express a geofence or speed limit (§9.9). |

## Not carried into v2

| v1 capability | Reason |
| --- | --- |
| No-expiry sentinel (`NO_EXPIRY_SENTINEL`, v1 §5.7) | Every v2 delegation has a real `expires_at`, with a lifetime of at most 315360000 seconds (§2.5). Open-ended grants made revocation the only bound; v2 requires a finite one. |
| Empty required scope (v1 §5.17, which skipped the scope check) | A v2 request names exactly one valid required scope before claim (§2.4); a verification that checks no scope cannot be released as authorization. |
| Identity enrollment objects (`HumanRoot`, `Anchor`, `AgentIdentity`) | Enrollment is deployment policy. v2 security rests on complete keys, `authority_id`, and caller-authenticated trust configuration. |
| `PolicyProvider`, `AuditProvider`, `PolicyVerdict` hooks | Policy and audit hooks inside verification let a mutable local result change or stand in for the Protocol result. v2 fixes the Protocol result and receipt first, and application policy runs after release. |
| `AnchorResolver` as part of verification | Metadata lookup is not trust; trust is configured before verification. |
| Unsigned or boolean revocation inputs | Status must be signed under a separate status key and evaluated through the anchored journal. |
| Self-issued live challenges | A live decision needs an authenticated, stored expected challenge and an atomic claim. |
| `SessionToken`, mutual presentation, HTTP and registry bindings, geo and speed constraints | Deferred to 2.1 (table above); v1 remains available for these claims in the meantime. |

## Do not infer

Installing v2 does not migrate keys, delegations, trust anchors, revocation
state, or application policy. A v2 key proves possession, not an organization's
identity. Trust enrollment, domain control, approval, and operational key
custody are managed by the application or service using the Protocol.

