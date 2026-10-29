## Install

One distribution, `ratify-protocol`, carries both protocol lines: Protocol v1
at `ratify_protocol` and Protocol v2 at `ratify_protocol.v2`.

```bash
# Protocol v1 and Protocol v2
pip install "ratify-protocol[protocol-v2]=={{VERSION_PYPI}}"

# Protocol v1 only, on the v1 maintenance release (v1.0.0-alpha.21)
pip install "ratify-protocol==1.0.0a21"
```

The base install keeps v1's requirements: `cryptography` (Ed25519 via OpenSSL), `pqcrypto>=0.3.4` (ML-DSA-65) and `tzdata`. Both binary dependencies ship wheels for Linux / macOS / Windows on CPython 3.10+. This matters because every published version of this package is a prerelease, so pip treats `{{VERSION_PYPI}}` as the newest release for anyone who installs or upgrades without a pin: a v1 user who upgrades or rebuilds lands on this release. The v1 API in it is unchanged, and `import ratify_protocol` never imports `ratify_protocol.v2`. Protocol v2's own requirements, the native signing extension `ratify-protocol-native-v2` and the IANA `tzdata` 2025.3 release, come only with the `protocol-v2` extra. To stay on the v1 release line, pin `ratify-protocol<2` or `ratify-protocol==1.0.0a21`.

The Protocol v2 API is described in [Protocol v2](#protocol-v2) below.
Runnable v2 programs are in
[`examples/v2/python`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/python),
and the upgrade guide is
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

### Optional: deterministic key generation from seeds

One function, `hybrid_keypair_from_seeds`, needs an optional add-on:

```bash
pip install 'ratify-protocol[native]=={{VERSION_PYPI}}'
```

Everything else works without it: verifying proofs, issuing delegations,
signing challenges, and persisting an identity by storing its key bytes.

You need the extra only for **seed portability across languages**, when the
same two seeds must produce the same identity in Python as in the Go, Rust,
TypeScript, or C SDK. Without it, `hybrid_keypair_from_seeds` raises
`NotImplementedError` explaining how to enable it. It never returns a
non-deterministic answer in place of a deterministic one.

The add-on is a separate package, `ratify-protocol-native`, because it contains
compiled code and is therefore platform-specific. Keeping it separate is what
lets `ratify-protocol` itself stay pure Python and install everywhere.
`pqcrypto`'s ML-DSA-65 binding ignores caller-supplied seeds, so this one
operation runs through the Ratify Rust core instead.

### Running the conformance suite from a clean checkout

If you cloned the repo and want to run `python -m pytest` against the committed fixtures, the package is not on your path until you install it. Do this:

```bash
cd sdks/python
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'              # installs ratify-protocol + cryptography + pqcrypto + pytest
python -m pytest tests/              # runs 79/79 conformance fixtures (Protocol v1)
```

If `pqcrypto` fails to install (typical on older pip), upgrade pip first:

```bash
pip install --upgrade pip
pip install -e '.[dev]'
```

`pqcrypto` requires a C compiler toolchain for source builds; prebuilt wheels exist for most platform / Python combinations.

## Quickstart

```python
from ratify_protocol import (
    generate_human_root, generate_agent,
    DelegationCert, ProofBundle, VerifyOptions,
    PROTOCOL_VERSION, SCOPE_MEETING_ATTEND,
    issue_delegation, sign_challenge, generate_challenge,
    verify_bundle, HybridSignature,
)
import time

# 1. DELEGATE: Alice creates her root and authorizes an agent.
root, root_priv = generate_human_root()
agent, agent_priv = generate_agent("Alice's Assistant", "voice_agent")

now = int(time.time())
cert = DelegationCert(
    cert_id="cert-1", version=PROTOCOL_VERSION,
    issuer_id=root.id, issuer_pub_key=root.public_key,
    subject_id=agent.id, subject_pub_key=agent.public_key,
    scope=[SCOPE_MEETING_ATTEND],
    issued_at=now, expires_at=now + 7 * 24 * 3600,
    signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),  # filled by issue_delegation
)
issue_delegation(cert, root_priv)

# 2. PRESENT: agent builds a proof bundle on demand.
challenge = generate_challenge()
challenge_at = int(time.time())
bundle = ProofBundle(
    agent_id=agent.id,
    agent_pub_key=agent.public_key,
    delegations=[cert],
    challenge=challenge,
    challenge_at=challenge_at,
    challenge_sig=sign_challenge(challenge, challenge_at, agent_priv),
)

# 3. VERIFY: any third party checks the bundle.
result = verify_bundle(bundle, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND))
if result.valid:
    print(f"✅ Authorized agent {result.agent_id} for {result.human_id}, scope={result.granted_scope}")
else:
    print(f"❌ {result.identity_status}: {result.error_reason}")
```

## Key custody

The protocol supports three key-custody modes with different trust tradeoffs. See [SPEC.md §15.2](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full model.

### Self-custody (strongest)

The user generates and holds their own keypair. No third party can sign on their behalf.

```python
from ratify_protocol import generate_human_root, issue_delegation

# User generates keypair on their own device; private key never leaves
root, private_key = generate_human_root()

# User signs delegations locally
issue_delegation(cert, private_key)

# Only root.id and root.public_key are shared with registries
```

### Custodial

A registry operator generates and stores the keypair server-side (envelope-encrypted with KMS). The user never touches keys directly. The operator calls the same SDK functions on the user's behalf.

### Self-custody upgrade

A user who started in custodial mode can migrate to self-custody at any time using `KeyRotationStatement`:

```python
from ratify_protocol import (
    generate_human_root,
    issue_key_rotation_statement,
    KeyRotationStatement,
)

# User generates a NEW keypair on their device
new_root, new_private_key = generate_human_root()

# Rotation statement signed by BOTH old (custodial) and new (device) keys
stmt = KeyRotationStatement(
    version=1,
    old_id=old_root.id,
    old_pub_key=old_root.public_key,
    new_id=new_root.id,
    new_pub_key=new_root.public_key,
    rotated_at=int(time.time()),
    reason="routine",
)
issue_key_rotation_statement(stmt, old_custodial_private_key, new_private_key)

# From now on, only the user's device key can sign delegations.
# Auditors verify continuity via the rotation statement.
```

## Canonical serialization

```python
from ratify_protocol import canonical_json, delegation_sign_bytes, challenge_sign_bytes
```

These produce byte-identical output to the Go / TypeScript / Rust / C/C++ references. If your application needs to sign Ratify artifacts with custom code, always pass through `canonical_json` for the JSON pieces.

## Wire transport

Signed Ratify structures travel as canonical JSON. The wire codec turns typed structures into those bytes and back, so integrators never hand-roll the base64 and byte-length handling.

### Sending a proof bundle

```python
from ratify_protocol import encode_proof_bundle

body = encode_proof_bundle(bundle)  # canonical JSON string
requests.post("https://verifier.example.com/verify", data=body,
              headers={"content-type": "application/json"})
```

### Receiving a proof bundle

```python
from ratify_protocol import decode_proof_bundle, verify_bundle, VerifyOptions, SCOPE_MEETING_ATTEND

bundle = decode_proof_bundle(request_body)  # str or bytes
result = verify_bundle(bundle, VerifyOptions(required_scope=SCOPE_MEETING_ATTEND))
```

### Session tokens (Protocol v1 only)

`SessionToken`s cross the wire the same way (`DelegationCert`s too, via `encode_delegation_cert` / `decode_delegation_cert`):

```python
from ratify_protocol import encode_session_token, decode_session_token

# Verifier issues the token after the first full verify and sends it out:
token_json = encode_session_token(token)

# The agent presents it on later turns; the verifier decodes and checks it:
presented = decode_session_token(token_json)
```

### Strict decoding

Decoders fail closed. A document is rejected, with a `ValueError` naming the offending field, if it carries malformed UTF-8 or a byte-order mark; malformed or non-canonical base64; a wrong byte length for a key, signature, challenge, or 32-byte binding field; a missing or mistyped required field; an integer outside the IEEE-754 safe-integer range [-(2^53-1), 2^53-1] (SPEC §6.2); an empty delegation chain; unpaired stream fields; duplicated JSON object keys (at any nesting depth, with string escapes decoded before comparison); or an unknown field in a signed structure. Anything a conformant implementation would not have produced is treated as malformed at the transport boundary instead of surfacing later as a confusing verification failure.

The strictness applies to the signed structures themselves: `ProofBundle`, `DelegationCert`, `SessionToken` reject unknown fields because every byte of them is protocol surface. Your application's transport envelope is a different thing: it may carry whatever integration metadata you need, as long as that metadata stays outside the signed structure. For example, `{"proof_bundle": {...}, "app_metadata": {...}}` is fine. Decode `proof_bundle` strictly with `decode_proof_bundle` and treat the rest of the envelope as your own; a `request_id` inside the bundle itself would (correctly) be rejected.

### Vocabulary discovery

Consoles and policy editors that present scope choices should derive them from the protocol rather than hardcoding strings, so UI vocabularies cannot drift:

```python
from ratify_protocol import vocabulary, scope_wildcards

vocabulary()       # all 54 canonical scopes, lex-sorted tuple
scope_wildcards()  # wildcard shorthand -> non-sensitive member scopes
```

## Scope vocabulary

```python
from ratify_protocol import (
    SCOPE_MEETING_ATTEND,     # "meeting:attend"
    SCOPE_FILES_WRITE,         # sensitive: never rides a wildcard
    expand_scopes,
    intersect_scopes,
    is_sensitive,
    validate_scopes,
)

expand_scopes(["meeting:*"])
# ['meeting:attend', 'meeting:chat', 'meeting:share_screen', 'meeting:speak', 'meeting:video']

intersect_scopes(["meeting:*"], ["meeting:attend", "meeting:speak"])
# ['meeting:attend', 'meeting:speak']
```

### Full scope vocabulary at a glance

Ratify v1 ships 54 canonical scopes plus 14 wildcards and a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

For app-specific needs not covered by the canonical vocabulary, use the `custom:` prefix:

```python
from ratify_protocol import CUSTOM_SCOPE_PREFIX, validate_scopes

validate_scopes(["custom:acme:inventory:read"])  # → None (valid)
```

Custom scopes pass through `expand_scopes` unchanged and are non-sensitive by default.

## Running the conformance tests

From this SDK directory:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest
pytest -v
```

The suite loads every fixture from the [canonical test vectors](https://github.com/identities-ai/ratify-protocol/tree/main/testvectors/v1) and runs it through the Python implementation. All 79 must pass; any failure means this SDK has drifted from the Go reference.

## Notes on the ML-DSA-65 library

This SDK uses `pqcrypto` which wraps PQClean's ML-DSA-65 implementation. Two things to be aware of:

**Randomized signing.** `pqcrypto`'s default signing mode is randomized (two signings of the same message produce different bytes). This does NOT affect interop: signatures produced here verify correctly in Go, TypeScript, Rust, and C/C++ implementations, and vice versa. The canonical signable bytes (what gets fed into the signature function) are what must match across languages, and those do match byte-for-byte.

**Non-deterministic keygen from seeds.** `pqcrypto` does not expose seed-based ML-DSA-65 key generation through its public API: `crypto_sign_keypair` reads from the OS RNG internally. This means `hybrid_keypair_from_seeds()` is NOT truly deterministic on the ML-DSA side in Python. The practical consequence: **Python cannot regenerate the canonical test fixtures** (the Go reference does that). Python's conformance contract is verification-only. It verifies Go-generated fixtures byte-for-byte but does not regenerate them. This is a known limitation of the `pqcrypto` library, not a protocol limitation.

## v1 API added in alpha.16

The following surface first shipped in the v1 alpha.16 release and is available in every later v1 release.

- **Resource-bound verification.** The `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via a `Constraint`'s `resource_id` and optional `path_prefix`. At verify time the application supplies `requested_resource_id`, `requested_path`, and `has_resource` on `VerifierContext` (SPEC §5.16); `verify_bundle(bundle, VerifyOptions(context=...))` evaluates them. Helpers: `normalize_resource_path`, `resource_path_matches`, `validate_resource_constraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `operation_context_bytes`, `operation_context_hash`, `session_context_bytes`, and `build_session_context`; `verifier_context_hash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `encode_verification_receipt` and `decode_verification_receipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `verify_streamed_turn_with_options` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** A `Constraint`'s `params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `validate_params_value`; `is_canonical_constraint_type` guards which types may carry them.
- **Deeper delegation chains.** `MAX_DELEGATION_CHAIN_DEPTH` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MAX_PROOF_BUNDLE_BYTES`, `MAX_SCOPES_PER_CERT`, `MAX_CONSTRAINTS_PER_CERT`, `MAX_SCOPE_LENGTH_BYTES`, `MAX_IDENTIFIER_LENGTH_BYTES`, `MAX_AGENT_NAME_LENGTH_BYTES`, `MAX_JSON_NESTING_DEPTH`.

## Protocol v2

Protocol v2 (version `{{VERSION}}`, a prerelease) is the `ratify_protocol.v2`
module, installed with the `protocol-v2` extra:

```bash
pip install "ratify-protocol[protocol-v2]=={{VERSION_PYPI}}"
```

```python
from ratify_protocol.v2 import key_id_v2
```

v1 and v2 can be used in the same process: `ratify_protocol` keeps the v1
API (`PROTOCOL_VERSION` 1), and v2 uses its own key ID namespace and wire
schemas, so v1 keys and proofs are never accepted as v2. Without the extra,
`ratify_protocol.v2` still imports and verifies, but signing raises
`ImportError`, and `time_window` constraints fail closed unless `tzdata`
2025.3 is the installed release.

### Signing and verification

Key generation and signing run only in the native extension
`ratify-protocol-native-v2` (constant-time Ed25519 and ML-DSA-65), which pip
installs with the `protocol-v2` extra. There is no pure-Python signing path: without the
extension every signer raises `ImportError`. Hybrid signature verification
also runs in the extension by default, through the Rust core's strict v2
verifier. Verification handles only public data, so the package keeps a
pure-Python verifier as a fallback: a verify-only install without the
extension uses it, and `RATIFY_V2_PURE_VERIFY=1` selects it explicitly
(`signing_v2.native_verify_enabled()` reports which is active). The test suite
replays every signature check in the shared corpus through both verifiers and
requires identical verdicts and error classes. The pure-Python verifier is
about 35 times slower per signature; see
[Protocol v2 performance](#protocol-v2-performance). The extension is
versioned in lockstep with this package, and importing `ratify_protocol.v2`
fails if a mismatched extension, or one built without native verification, is
installed.

Every object is signed through a typed signer (`sign_delegation_cert_v2`,
`sign_proof_bundle_v2`, `sign_revocation_list_v2`, `sign_revocation_push_v2`,
`sign_key_rotation_statement_v2`, `sign_witness_entry_v2`,
`sign_transaction_receipt_party_v2`, `sign_verification_receipt_v2`), each
with a `*_with_signer(ctx, ..., signer)` variant (`sign_key_rotation_statement_v2_with_signers` for the two rotation keys) that accepts an external
signer (`SignerV2`) in direct mode (it receives the 77-byte message `M` and
the registered ML-DSA context) or external-μ mode (it receives only `mu`).
The SDK checks the signer's complete public key against the object before
any signer call, and verifies every returned signature before using it. No
function signs caller-selected bytes, codes, or contexts, and no local
`SignerV2` is exported: an in-process key signs only through the typed
signers, and the status publisher takes it through
`status_publisher_v2.new_v2_status_publisher_with_key`. Production signing
is hedged; byte-reproducible signing for the shared vectors is available only
to tests through `ratify_protocol.v2._testing.deterministic_test_vector_signing()`.

### Live verification and release

`verify_v2.verify_proof_bundle_v2(ctx, request, callbacks)` runs the SPEC-v2
§6 order: bounded strict decode, configuration bounds, every structural and
signature check, the authenticated challenge binding, the receiver-binding
hook, the atomic claim, and only then trust, local authorization, status
evidence applied through an anchored `SecurityJournalV2`, receiver audience,
`max_rate`, and finalization at a fresh authoritative time. It returns a
stage (`preflight`, `replay`, `evaluating`, `committed`) with an error class
from the closed list of SPEC-v2 §2.7.

A committed outcome is not a decision. `release_v2.release_v2_decision`
checks the published receipt, its checkpoint acknowledgement, the
authoritative clock and the exclusive deadlines, and returns a
`V2ReleasedDecision` only when every step passes. That class has no public
constructor, holds no state of its own, and cannot be subclassed or pickled;
only the exact instance `release_v2_decision` returned is in its release
registry, which lives in a closure rather than a module attribute, so a copy
or a hand-built instance is never actionable.
`decision.allowed(ctx, clock)` is the only value an application may use to
gate a side effect. This guards against API misuse and accidental
construction. It does not defend against hostile code in the same
interpreter (for example `gc` or closure introspection, or monkeypatching the
module), which could read the application's keys and stores anyway.

Every function whose Go counterpart takes a `context.Context` takes a
`context_v2.Context` as its first argument (`context_v2.background()`,
`with_cancel`, `with_timeout`).

The Part B storage contracts (`ClaimStoreV2`, `V2RateReservationStore`,
`V2RateAtFinalizationStore`, `V2ReleaseClaimStore`, `V2ReceiptPublisher`,
`V2ReceiptCheckpoint`, `SecurityJournalStoreV2`, `V2ChallengeIssuanceStore`)
are abstract classes. A deployment supplies durable implementations; the
in-memory stores under `ratify_protocol.v2.v2reference` exist only for tests
and conformance scenarios and must never be used in production.

`time_window` constraints are evaluated only against the IANA tzdata release
`2025c` from the pinned `tzdata` package; the host time-zone database is
never consulted, and a verifier must configure `tzdb_version="2025c"`.

### Conformance

The shared vectors live in `testvectors/v2/` of the protocol repository. The
v2 test suite (`tests_v2`) runs every file there and fails if a file has no
runner. From this SDK directory, with a Rust toolchain:

```bash
python -m venv .venv && source .venv/bin/activate
pip install 'maturin>=1.7,<2'
(cd ../python-native-v2 && maturin build --release --out dist)
pip install ../python-native-v2/dist/*.whl
pip install -e '.[dev,protocol-v2]'
RATIFY_REQUIRE_NATIVE=1 python -m pytest tests_v2/
```
 To run
the suite against an installed wheel, set `RATIFY_V2_VECTOR_DIR` to that
directory. Set `RATIFY_REQUIRE_NATIVE=1` to make a missing native extension a
hard error instead of skipping the signing tests.

This is a prerelease. Review so far is internal adversarial review; external
independent review is a gate for `2.0.0` (SPEC-v2 §8), and v2 carries no
production security claim yet. The per-SDK record is in
[`docs/V2_REFERENCE_COMPATIBILITY.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/V2_REFERENCE_COMPATIBILITY.md).

### Protocol v2 performance

`bench_v2/bench_v2.py` measures, on the in-memory reference stores: one hybrid
verification (`verify_v2_statement`); `verify_delegation_cert_v2_signature`
(structure and key-ID checks plus one verification); one complete decision on
the quickstart flow (verify with signed status, commit, publish the receipt,
checkpoint acknowledgement, release); and a dual-root call (two such decisions
under independent roots, one with a two-certificate chain). Challenge issuance
and presentation signing happen before the clock starts. `bench_v2/go` and
`bench_v2/rust` run the same flow on the Go and Rust SDKs.

```bash
python bench_v2/bench_v2.py              # from sdks/python; table; --json out.json; --check (CI floors)
go run ./sdks/python/bench_v2/go         # from the repository root
cd bench_v2/rust && cargo run --release  # from sdks/python
```

Measured on 2026-10-22 on an Apple M2 Pro (10 cores, 16 GB, macOS 26.6),
Python 3.12.10, Go 1.27.3, Rust 1.95.0, one process at a time on an otherwise
idle host. Operations per second, single thread:

| Measurement | Python, before | Python, pure fallback | Python, native | Go | Rust |
| --- | ---: | ---: | ---: | ---: | ---: |
| hybrid verify | 83 | 82 | 3,130 | n/a | n/a |
| certificate signature verify | n/a | 81 | 2,628 | 2,066 | 2,574 |
| decision | 5.4 | 6.7 | 68.7 | 63.0 | 99.7 |
| dual-root decision | 2.1 | 2.4 | 21.7 | 17.1 | 27.8 |

"Before" is the previous release line, which verified in pure Python and
encoded canonical JSON strings character by character. "Pure fallback" is the
current code with `RATIFY_V2_PURE_VERIFY=1`. Go does not export a raw hybrid
verifier, so the SDKs are compared on the certificate call.

With native verification a decision spends most of its time in Python
protocol logic: loading, validating and digesting the reference security
journal snapshot during the status stage, canonical JSON encoding, and strict
wire decoding. Signature verification is under a tenth of it.

The Google ADK reference's dual-root scale benchmark (8 worker threads, 76 KB
presentations) went from 1.3 / 1.6 / 1.6 calls/s to 13.2 / 15.6 / 14.2 calls/s
for the 10 / 100 / 1,000-call tiers on the same host. The earlier run shared
the host with other work for part of its duration.

CI runs `bench_v2/bench_v2.py --check`, which fails if verification is not
native or any measurement falls below a floor set between a tenth and a
quarter of the native numbers above, and above the pure-Python ones.

### Examples and upgrading

Runnable programs live in
[`examples/v2/python`](https://github.com/identities-ai/ratify-protocol/tree/main/examples/v2/python):
a quickstart (keys, delegation, challenge from the issuance helper, proof,
verify, receipt, checkpoint, release, `allowed`), signed status with a
revocation, an exact `custom:` scope with the `max_count/v1` evaluator
profile, and an external signer. They print the same output as the other
SDKs' programs, and CI checks it. They use the in-memory reference stores and
are development-only. Upgrading from v1 is covered in
[`docs/PROTOCOL_V2_MIGRATION.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/PROTOCOL_V2_MIGRATION.md).

## License

Apache-2.0. See the project-level LICENSE.
