# ratify-protocol

**Python reference SDK for the Ratify Protocol v1 — delegated-authority proofs for human-agent and agent-agent interactions.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the Go, TypeScript, Rust, and C/C++ reference implementations. Validated against the **63 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

Beyond the one-shot delegate → present → verify round trip, this SDK implements the full v1.1 feature set for continuous and multi-party interactions: session-bound challenges and stream sequence numbers (replay and reorder detection across a multi-turn conversation), the SessionToken fast path (~95% less per-turn crypto — practical for live voice and video), push-based revocation, multi-party transaction receipts, witness append-only logs, and key rotation statements. All normative in the spec, all covered by the 63 canonical fixtures.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Install

```bash
pip install ratify-protocol==1.0.0a14
```

This pulls in two binary dependencies: `cryptography` (Ed25519 via OpenSSL) and `pqcrypto>=0.3.4` (ML-DSA-65). Both ship wheels for Linux / macOS / Windows on CPython 3.10+.

### Running the conformance suite from a clean checkout

If you cloned the repo and want to run `python -m pytest` against the committed fixtures, the package is not on your path until you install it. Do this:

```bash
cd sdks/python
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'              # installs ratify-protocol + cryptography + pqcrypto + pytest
python -m pytest tests/              # runs 63/63 conformance fixtures
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
    derive_id, verify_bundle, HybridSignature,
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

Ratify v1 ships 54 canonical scopes across fourteen domains, plus a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

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

The suite loads every fixture from the [canonical test vectors](https://github.com/identities-ai/ratify-protocol/tree/main/testvectors/v1) and runs it through the Python implementation. All 63 must pass; any failure means this SDK has drifted from the Go reference.

## Notes on the ML-DSA-65 library

This SDK uses `pqcrypto` which wraps PQClean's ML-DSA-65 implementation. Two things to be aware of:

**Randomized signing.** `pqcrypto`'s default signing mode is randomized (two signings of the same message produce different bytes). This does NOT affect interop: signatures produced here verify correctly in Go, TypeScript, Rust, and C/C++ implementations, and vice versa. The canonical signable bytes (what gets fed into the signature function) are what must match across languages — those do match byte-for-byte.

**Non-deterministic keygen from seeds.** `pqcrypto` does not expose seed-based ML-DSA-65 key generation through its public API — `crypto_sign_keypair` reads from the OS RNG internally. This means `hybrid_keypair_from_seeds()` is NOT truly deterministic on the ML-DSA side in Python. The practical consequence: **Python cannot regenerate the canonical test fixtures** (the Go reference does that). Python's conformance contract is verification-only — it verifies Go-generated fixtures byte-for-byte but does not regenerate them. This is a known limitation of the `pqcrypto` library, not a protocol limitation.

## License

Apache-2.0. See the project-level LICENSE.
