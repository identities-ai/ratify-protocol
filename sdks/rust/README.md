# ratify-protocol (Rust)

**Rust reference SDK for the Ratify Protocol v1 — a cryptographic trust protocol for human-agent and agent-agent interactions as agents start to transact.**

Quantum-safe by design: every signature is hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204). Both must verify.

Byte-identical interoperability with the Go, TypeScript, Python, and C/C++ reference implementations. Validated against the **59 canonical test vectors** on every CI run.

## What is Ratify Protocol?

Ratify is an open cryptographic protocol that answers the question: *"Is this AI agent authorized to act, by whom, for what, and under what constraints?"*

A human issues a signed **delegation cert** to an agent. The agent presents a **proof bundle** when acting. Any third party can **verify** the proof — offline, without contacting a server — and get a cryptographically certain answer.

- Full protocol spec: [SPEC.md](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md)
- Explainer (how it works, threat model): [docs/EXPLAINED.md](https://github.com/identities-ai/ratify-protocol/blob/main/docs/EXPLAINED.md)
- Developer docs: [docs.identities.ai](https://docs.identities.ai)

## Install

```toml
[dependencies]
ratify-protocol = "1.0.0-alpha.10"
```

## Quickstart

```rust
use ratify_protocol::{
    generate_human_root, generate_agent,
    DelegationCert, HybridSignature, ProofBundle, VerifyOptions,
    PROTOCOL_VERSION, SCOPE_MEETING_ATTEND,
    issue_delegation, sign_challenge, generate_challenge,
    verify_bundle,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // 1. DELEGATE
    let (root, root_priv) = generate_human_root();
    let (agent, agent_priv) = generate_agent("Alice's Assistant", "voice_agent");

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let mut cert = DelegationCert {
        cert_id: "cert-1".into(),
        version: PROTOCOL_VERSION,
        issuer_id: root.id.clone(),
        issuer_pub_key: root.public_key.clone(),
        subject_id: agent.id.clone(),
        subject_pub_key: agent.public_key.clone(),
        scope: vec![SCOPE_MEETING_ATTEND.into()],
        constraints: Vec::new(),
        issued_at: now,
        expires_at: now + 7 * 24 * 3600,
        signature: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    };
    issue_delegation(&mut cert, &root_priv);

    // 2. PRESENT
    let challenge = generate_challenge();
    let challenge_at = now;
    let bundle = ProofBundle {
        agent_id: agent.id.clone(),
        agent_pub_key: agent.public_key.clone(),
        delegations: vec![cert],
        challenge: challenge.clone(),
        challenge_at,
        challenge_sig: sign_challenge(&challenge, challenge_at, &agent_priv),
        session_context: Vec::new(),
        stream_id: Vec::new(),
        stream_seq: 0,
    };

    // 3. VERIFY
    let opts = VerifyOptions {
        required_scope: SCOPE_MEETING_ATTEND.into(),
        ..Default::default()
    };
    let result = verify_bundle(&bundle, &opts);
    if result.valid {
        println!("✅ Authorized agent {} for {}", result.agent_id, result.human_id);
    } else {
        println!("❌ {:?}: {}", result.identity_status, result.error_reason);
    }
}
```

## Key custody

The protocol supports three key-custody modes with different trust tradeoffs. See [SPEC.md §15.2](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full model.

### Self-custody (strongest)

The user generates and holds their own keypair. No third party can sign on their behalf.

```rust
use ratify_protocol::{generate_human_root, issue_delegation};

// User generates keypair on their own device — private key never leaves
let (root, private_key) = generate_human_root();

// User signs delegations locally
issue_delegation(&mut cert, &private_key);

// Only root.id and root.public_key are shared with registries
```

### Custodial

A registry operator generates and stores the keypair server-side (envelope-encrypted with KMS). The user never touches keys directly. The operator calls the same SDK functions on the user's behalf.

### Self-custody upgrade

A user who started in custodial mode can migrate to self-custody at any time using `KeyRotationStatement`:

```rust
use ratify_protocol::{
    generate_human_root, issue_key_rotation_statement, KeyRotationStatement,
};

// User generates a NEW keypair on their device
let (new_root, new_private_key) = generate_human_root();

// Rotation statement signed by BOTH old (custodial) and new (device) keys
let mut stmt = KeyRotationStatement {
    version: 1,
    old_id: old_root.id.clone(),
    old_pub_key: old_root.public_key.clone(),
    new_id: new_root.id.clone(),
    new_pub_key: new_root.public_key.clone(),
    rotated_at: now_unix(),
    reason: "routine".into(),
    signature_old: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    signature_new: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
};
issue_key_rotation_statement(&mut stmt, &old_custodial_key, &new_private_key);

// From now on, only the user's device key can sign delegations.
// Auditors verify continuity via the rotation statement.
```

## Scope vocabulary

Ratify v1 ships 53 canonical scopes across fourteen domains, plus a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

For app-specific needs not covered by the canonical vocabulary, use the `custom:` prefix:

```rust
use ratify_protocol::{validate_scopes, CUSTOM_SCOPE_PREFIX};

assert!(validate_scopes(&["custom:acme:inventory:read".into()]).is_none());
```

Custom scopes pass through `expand_scopes` unchanged and are non-sensitive by default.

## Running the conformance tests

```bash
cargo test
```

The suite loads every fixture from the [canonical test vectors](https://github.com/identities-ai/ratify-protocol/tree/main/testvectors/v1) and runs it through the Rust implementation. All 59 must pass; any failure means this SDK has drifted from the Go reference.

## License

Apache-2.0. See the project-level LICENSE.
