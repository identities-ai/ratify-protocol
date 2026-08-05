<!-- GENERATED FILE — do not edit directly.
     Sources: sdks/readme-src/preamble.md + README.body.md in this directory.
     Regenerate: python3 scripts/gen-sdk-readmes.py -->
# ratify-protocol

**Python reference SDK of the Ratify Protocol v1 — delegated-authority proofs for human-agent and agent-agent interactions.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the Go, TypeScript, Rust, and C/C++ reference implementations. Validated against the **79 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), single-use challenge acceptance through a pluggable challenge store (SPEC §10), the SessionToken fast path (one hybrid signature verification per turn instead of N+1 — practical for live voice and video) with scope, single-use, and binding enforcement on the streamed path, canonical operation- and session-context binding for middleware custody deployments (SPEC §6.4.9, §15.2.1), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Install

```bash
pip install ratify-protocol==1.0.0a16
```

This pulls in two binary dependencies: `cryptography` (Ed25519 via OpenSSL) and `pqcrypto>=0.3.4` (ML-DSA-65). Both ship wheels for Linux / macOS / Windows on CPython 3.10+.

### Running the conformance suite from a clean checkout

If you cloned the repo and want to run `python -m pytest` against the committed fixtures, the package is not on your path until you install it. Do this:

```bash
cd sdks/python
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'              # installs ratify-protocol + cryptography + pqcrypto + pytest
python -m pytest tests/              # runs 79/79 conformance fixtures
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

# 1. DELEGATE — Alice creates her root and authorizes an agent.
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

# 2. PRESENT — agent builds a proof bundle on demand.
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

# 3. VERIFY — any third party checks the bundle.
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

# User generates keypair on their own device — private key never leaves
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

### Session tokens

`SessionToken`s cross the wire the same way (`DelegationCert`s too, via `encode_delegation_cert` / `decode_delegation_cert`):

```python
from ratify_protocol import encode_session_token, decode_session_token

# Verifier issues the token after the first full verify and sends it out:
token_json = encode_session_token(token)

# The agent presents it on later turns; the verifier decodes and checks it:
presented = decode_session_token(token_json)
```

### Strict decoding

Decoders fail closed. A document is rejected — with a `ValueError` naming the offending field — if it carries malformed UTF-8 or a byte-order mark; malformed or non-canonical base64; a wrong byte length for a key, signature, challenge, or 32-byte binding field; a missing or mistyped required field; an integer outside the IEEE-754 safe-integer range [-(2^53-1), 2^53-1] (SPEC §6.2); an empty delegation chain; unpaired stream fields; duplicated JSON object keys (at any nesting depth, with string escapes decoded before comparison); or an unknown field in a signed structure. Anything a conformant implementation would not have produced is treated as malformed at the transport boundary instead of surfacing later as a confusing verification failure.

The strictness applies to the signed structures themselves — `ProofBundle`, `DelegationCert`, `SessionToken` reject unknown fields because every byte of them is protocol surface. Your application's transport envelope is a different thing: it may carry whatever integration metadata you need, as long as that metadata stays outside the signed structure. For example, `{"proof_bundle": {...}, "app_metadata": {...}}` is fine — decode `proof_bundle` strictly with `decode_proof_bundle` and treat the rest of the envelope as your own; a `request_id` inside the bundle itself would (correctly) be rejected.

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
    SCOPE_FILES_WRITE,         # sensitive — never rides a wildcard
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

**Randomized signing.** `pqcrypto`'s default signing mode is randomized (two signings of the same message produce different bytes). This does NOT affect interop: signatures produced here verify correctly in Go, TypeScript, Rust, and C/C++ implementations, and vice versa. The canonical signable bytes (what gets fed into the signature function) are what must match across languages — those do match byte-for-byte.

**Non-deterministic keygen from seeds.** `pqcrypto` does not expose seed-based ML-DSA-65 key generation through its public API — `crypto_sign_keypair` reads from the OS RNG internally. This means `hybrid_keypair_from_seeds()` is NOT truly deterministic on the ML-DSA side in Python. The practical consequence: **Python cannot regenerate the canonical test fixtures** (the Go reference does that). Python's conformance contract is verification-only — it verifies Go-generated fixtures byte-for-byte but does not regenerate them. This is a known limitation of the `pqcrypto` library, not a protocol limitation.

## API added on main (ships in alpha.16, release unpublished)

The following surface is merged to `main` and ships in alpha.16. The tag is not yet published; install from `main` to use it ahead of the release.

- **Resource-bound verification.** The `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via a `Constraint`'s `resource_id` and optional `path_prefix`. At verify time the application supplies `requested_resource_id`, `requested_path`, and `has_resource` on `VerifierContext` (SPEC §5.16); `verify_bundle(bundle, VerifyOptions(context=...))` evaluates them. Helpers: `normalize_resource_path`, `resource_path_matches`, `validate_resource_constraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `operation_context_bytes`, `operation_context_hash`, `session_context_bytes`, and `build_session_context`; `verifier_context_hash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `encode_verification_receipt` and `decode_verification_receipt`.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `verify_streamed_turn_with_options` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** A `Constraint`'s `params` carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `validate_params_value`; `is_canonical_constraint_type` guards which types may carry them.
- **Deeper delegation chains.** `MAX_DELEGATION_CHAIN_DEPTH` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MAX_PROOF_BUNDLE_BYTES`, `MAX_SCOPES_PER_CERT`, `MAX_CONSTRAINTS_PER_CERT`, `MAX_SCOPE_LENGTH_BYTES`, `MAX_IDENTIFIER_LENGTH_BYTES`, `MAX_AGENT_NAME_LENGTH_BYTES`, `MAX_JSON_NESTING_DEPTH`.

## License

Apache-2.0. See the project-level LICENSE.
