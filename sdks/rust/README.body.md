## Install

```toml
[dependencies]
ratify-protocol = "{{VERSION}}"
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
    let (agent, agent_priv) =
        generate_agent("Alice's Assistant", "voice_agent").expect("agent generation");

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
    issue_delegation(&mut cert, &root_priv).expect("delegation issuance");

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
    rotated_at: 1_700_000_000, // current unix seconds
    reason: "routine".into(),
    signature_old: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
    signature_new: HybridSignature { ed25519: vec![], ml_dsa_65: vec![] },
};
issue_key_rotation_statement(&mut stmt, &old_custodial_key, &new_private_key);

// From now on, only the user's device key can sign delegations.
// Auditors verify continuity via the rotation statement.
```

## Scope vocabulary

Ratify v1 ships 54 canonical scopes plus 14 wildcards and a `custom:` extension pattern for application-specific scopes. See [SPEC.md §9](https://github.com/identities-ai/ratify-protocol/blob/main/SPEC.md) for the full table including sensitivity flags and wildcard expansions.

For app-specific needs not covered by the canonical vocabulary, use the `custom:` prefix:

```rust
use ratify_protocol::validate_scopes;

assert!(validate_scopes(&["custom:acme:inventory:read".into()]).is_none());
```

Custom scopes pass through `expand_scopes` unchanged and are non-sensitive by default.

## Running the conformance tests

```bash
cargo test
```

The suite loads every fixture from the [canonical test vectors](https://github.com/identities-ai/ratify-protocol/tree/main/testvectors/v1) and runs it through the Rust implementation. All 79 must pass; any failure means this SDK has drifted from the Go reference.

## API added in v1 alpha.16

The following surface first shipped in the v1 alpha.16 release and is available in every later v1 release.

- **Resource-bound verification.** The `resource_path` constraint (the 8th constraint type, SPEC §5.7.3) binds authority to a named resource via a `Constraint`'s `resource_id` and optional `path_prefix`. At verify time the application supplies `requested_resource_id` and `requested_path` on `VerifierContext` (SPEC §5.16); `verify_bundle(&bundle, &VerifyOptions { context, ..Default::default() })` evaluates them. Helpers: `normalize_resource_path`, `resource_path_matches`, `validate_resource_constraints`.
- **Operation / session verifier context.** `OperationContext` and `SessionContextInputs`, with `operation_context_bytes`, `operation_context_hash`, `session_context_bytes`, and `build_session_context`; `verifier_context_hash` produces the canonical hash bound into a `VerificationReceipt`.
- **VerificationReceipt wire codecs.** `encode_verification_receipt`; `decode_verification_receipt` requires the `std` feature.
- **Streamed-turn verify options.** `StreamedTurn` and `StreamedVerifyOptions`, with `verify_streamed_turn_with_options` (the options-object streamed fast path, SPEC §5.13).
- **Extension-constraint params.** A `Constraint`'s `params` (typed `ParamsValue`) carries parameters for non-canonical constraint types (SPEC §5.7.1), validated by `validate_params_value` and `validate_constraint_params`; `is_canonical_constraint_type` guards which types may carry them.
- **Deeper delegation chains.** `MAX_DELEGATION_CHAIN_DEPTH` is raised from 3 to 8 (SPEC §5.1).
- **Input bounds constants.** `MAX_PROOF_BUNDLE_BYTES`, `MAX_SCOPES_PER_CERT`, `MAX_CONSTRAINTS_PER_CERT`, `MAX_SCOPE_LENGTH_BYTES`, `MAX_IDENTIFIER_LENGTH_BYTES`, `MAX_AGENT_NAME_LENGTH_BYTES`, `MAX_JSON_NESTING_DEPTH`.

## Protocol v2 (2.0.0-alpha line)

Version `{{VERSION}}` is a prerelease on the separate v2 line. The v2 API lives
in the `ratify_protocol::v2` module next to the unchanged v1 API. It covers
strict decoding and canonical encoding of every v2 signed object, hybrid
signature verification with full 256-bit v2 key IDs, the stateful live
verifier `verify_proof_bundle_v2`, the revocation status reducer, witness and
verification-receipt log heads, key rotation acceptance, and the
`challenge_claim_digest_v2`, `protocol_claim_id_v2`, and
`protocol_claim_id_from_digest_v2` replay identifiers.

`cargo test` runs every file in `testvectors/v2`, including the verifier
ordering, status, log, and rotation sequences. This alpha is not a v2
conformance claim; the remaining gates are listed in SPEC-v2 §8 and
[`docs/V2_REFERENCE_COMPATIBILITY.md`](https://github.com/identities-ai/ratify-protocol/blob/main/docs/V2_REFERENCE_COMPATIBILITY.md).
Callers still supply authenticated challenge issuance and an atomic durable
claim store.

## License

Apache-2.0. See the project-level LICENSE.
