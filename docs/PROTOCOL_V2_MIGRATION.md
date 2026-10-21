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

## Do not infer

Installing v2 does not migrate keys, delegations, trust anchors, revocation
state, or application policy. A v2 key proves possession, not an organization's
identity. Trust enrollment, domain control, approval, and operational key
custody are managed by the application or service using the Protocol.

