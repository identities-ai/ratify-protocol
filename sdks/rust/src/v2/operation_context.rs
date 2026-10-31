//! Operation, session, and challenge-claim constructions (SPEC-v2 §2.4, §4;
//! Go `operation_context_v2.go` and `challenge_claim_v2.go`).

use sha2::{Digest, Sha256, Sha384};

use super::crypto::lower_hex;
use super::errors::{err, V2ErrorClass, V2Result};
use super::limits::V2_MAX_SAFE_INTEGER;
use super::wire::validate_required_scope_v2;

const OPERATION_CONTEXT_V2_TAG: &[u8] = b"ratify/operation-context/v2";
const SESSION_CONTEXT_V2_TAG: &[u8] = b"ratify/session-context/v2";
const CLAIM_DIGEST_TAG: &[u8] = b"ratify-protocol-challenge-claim-v2\0";
const CLAIM_ID_TAG: &[u8] = b"ratify-protocol-claim-id-v2\0";

/// Action inputs bound to a Protocol v2 presentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationContextV2 {
    pub required_scope: String,
    pub operation: String,
    pub resource_id: String,
    pub requested_path: String,
    /// Empty or exactly 32 raw SHA-256 bytes.
    pub payload_digest: Vec<u8>,
}

/// Verifier session and invocation inputs bound to a Protocol v2 presentation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionContextV2Inputs {
    pub verifier_id: String,
    pub workspace_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub invocation_id: String,
    /// Exactly 32 raw SHA-256 bytes from [`operation_context_v2_hash`].
    pub request_hash: Vec<u8>,
}

fn append_field(preimage: &mut Vec<u8>, field: &[u8]) {
    preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
    preimage.extend_from_slice(field);
}

/// Decode the Verify API `sha256:<64 lowercase hex>` form. `None` means no
/// payload digest was supplied.
pub fn decode_payload_digest_v2(encoded: Option<&str>) -> V2Result<Option<Vec<u8>>> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    match encoded.strip_prefix("sha256:") {
        Some(h) if h.len() == 64 && lower_hex(h) => match hex::decode(h) {
            Ok(digest) => Ok(Some(digest)),
            Err(_) => err(V2ErrorClass::Malformed, "payload digest is not hexadecimal"),
        },
        _ => err(
            V2ErrorClass::Malformed,
            "payload digest must be sha256: followed by 64 lowercase hexadecimal characters",
        ),
    }
}

/// The operation-context v2 preimage in canonical field order. The required
/// scope must be one requestable scope (`invalid_required_scope`).
pub fn operation_context_v2_bytes(ctx: &OperationContextV2) -> V2Result<Vec<u8>> {
    validate_required_scope_v2(&ctx.required_scope)?;
    if !ctx.payload_digest.is_empty() && ctx.payload_digest.len() != 32 {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            format!("payload digest must be empty or 32 bytes, got {}", ctx.payload_digest.len()),
        );
    }
    let mut preimage = Vec::from(OPERATION_CONTEXT_V2_TAG);
    for field in [
        ctx.required_scope.as_bytes(),
        ctx.operation.as_bytes(),
        ctx.resource_id.as_bytes(),
        ctx.requested_path.as_bytes(),
        ctx.payload_digest.as_slice(),
    ] {
        append_field(&mut preimage, field);
    }
    Ok(preimage)
}

/// `request_hash = SHA-256(operation_context_bytes)`.
pub fn operation_context_v2_hash(ctx: &OperationContextV2) -> V2Result<Vec<u8>> {
    Ok(Sha256::digest(operation_context_v2_bytes(ctx)?).to_vec())
}

/// The session-context v2 preimage in canonical field order.
pub fn session_context_v2_bytes(inputs: &SessionContextV2Inputs) -> V2Result<Vec<u8>> {
    let invalid = |m: &str| err(V2ErrorClass::ConfigurationInvalid, m.to_string());
    if !is_key_id(&inputs.verifier_id) {
        return invalid("verifier ID must be 64 lowercase hexadecimal characters");
    }
    if !is_canonical_workspace_id(&inputs.workspace_id) {
        return invalid("workspace ID must be a canonical lowercase UUID");
    }
    if !is_key_id(&inputs.agent_id) {
        return invalid("agent ID must be 64 lowercase hexadecimal characters");
    }
    if inputs.request_hash.len() != 32 {
        return invalid("request hash must be 32 bytes");
    }
    let mut preimage = Vec::from(SESSION_CONTEXT_V2_TAG);
    for field in [
        inputs.verifier_id.as_bytes(),
        inputs.workspace_id.as_bytes(),
        inputs.agent_id.as_bytes(),
        inputs.session_id.as_bytes(),
        inputs.invocation_id.as_bytes(),
        inputs.request_hash.as_slice(),
    ] {
        append_field(&mut preimage, field);
    }
    Ok(preimage)
}

/// `session_context = SHA-256(session_context_bytes)`.
pub fn build_session_context_v2(inputs: &SessionContextV2Inputs) -> V2Result<Vec<u8>> {
    Ok(Sha256::digest(session_context_v2_bytes(inputs)?).to_vec())
}

fn is_key_id(value: &str) -> bool {
    value.len() == 64 && lower_hex(value)
}

fn is_canonical_workspace_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, b)| {
            if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

/// `ChallengeClaimDigest(c) = SHA-384("ratify-protocol-challenge-claim-v2"
/// || 0x00 || c)` for exactly 32 decoded challenge bytes.
pub fn challenge_claim_digest_v2(challenge: &[u8]) -> V2Result<Vec<u8>> {
    if challenge.len() != 32 {
        return err(
            V2ErrorClass::Malformed,
            "v2 challenge claim requires exactly 32 challenge bytes",
        );
    }
    let mut hash = Sha384::new();
    hash.update(CLAIM_DIGEST_TAG);
    hash.update(challenge);
    Ok(hash.finalize().to_vec())
}

/// The stable claim ID bound to the namespace and rollback-protected epoch.
pub fn protocol_claim_id_v2(namespace: &str, replay_epoch: i64, challenge: &[u8]) -> V2Result<String> {
    validate_namespace_epoch(namespace, replay_epoch)?;
    protocol_claim_id_from_digest_v2(namespace, replay_epoch, &challenge_claim_digest_v2(challenge)?)
}

/// The same claim ID from a precomputed 48-byte challenge claim digest.
pub fn protocol_claim_id_from_digest_v2(
    namespace: &str,
    replay_epoch: i64,
    claim_digest: &[u8],
) -> V2Result<String> {
    validate_namespace_epoch(namespace, replay_epoch)?;
    if claim_digest.len() != 48 {
        return err(
            V2ErrorClass::Malformed,
            "v2 challenge claim digest must be exactly 48 bytes",
        );
    }
    let mut hash = Sha256::new();
    hash.update(CLAIM_ID_TAG);
    hash.update((namespace.len() as u64).to_be_bytes());
    hash.update(namespace.as_bytes());
    hash.update((replay_epoch as u64).to_be_bytes());
    hash.update(claim_digest);
    Ok(hex::encode(hash.finalize()))
}

fn validate_namespace_epoch(namespace: &str, replay_epoch: i64) -> V2Result<()> {
    if namespace.is_empty() {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 verifier namespace must be non-empty valid UTF-8",
        );
    }
    if !(0..=V2_MAX_SAFE_INTEGER).contains(&replay_epoch) {
        return err(
            V2ErrorClass::ConfigurationInvalid,
            "v2 replay epoch is outside 0..2^53-1",
        );
    }
    Ok(())
}
