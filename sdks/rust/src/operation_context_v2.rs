//! Protocol v2 operation and session context constructions (SPEC-v2 §2.2).
//!
//! These helpers use v2 domain tags and do not change the v1 context API.

use alloc::{format, string::{String, ToString}, vec::Vec};

use sha2::{Digest, Sha256};
use crate::scope::vocabulary;

const OPERATION_CONTEXT_V2_TAG: &[u8] = b"ratify/operation-context/v2";
const SESSION_CONTEXT_V2_TAG: &[u8] = b"ratify/session-context/v2";

/// Action inputs bound to a Protocol v2 presentation.
#[derive(Debug, Clone, Default)]
pub struct OperationContextV2 {
    pub required_scope: String,
    pub operation: String,
    pub resource_id: String,
    pub requested_path: String,
    /// Empty or exactly 32 raw SHA-256 bytes.
    pub payload_digest: Vec<u8>,
}

/// Verifier session and invocation inputs bound to a Protocol v2 presentation.
#[derive(Debug, Clone, Default)]
pub struct SessionContextV2Inputs {
    pub verifier_id: String,
    pub workspace_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub invocation_id: String,
    /// Exactly 32 raw SHA-256 bytes from `operation_context_v2_hash`.
    pub request_hash: Vec<u8>,
}

fn append_field(preimage: &mut Vec<u8>, field: &[u8]) {
    preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
    preimage.extend_from_slice(field);
}

/// Decode the Verify API canonical `sha256:<64 lowercase hex>` form.
/// `None` means no payload digest was supplied.
pub fn decode_payload_digest_v2(encoded: Option<&str>) -> Result<Option<Vec<u8>>, String> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let hex = encoded
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or_else(|| "payload digest must be sha256: followed by 64 lowercase hexadecimal characters".to_string())?;
    let digest = hex::decode(hex)
        .map_err(|_| "payload digest must be sha256: followed by 64 lowercase hexadecimal characters".to_string())?;
    Ok(Some(digest))
}

/// Encode the operation-context v2 preimage in canonical field order.
pub fn operation_context_v2_bytes(ctx: &OperationContextV2) -> Result<Vec<u8>, String> {
    if !vocabulary().contains(&ctx.required_scope.as_str()) {
        return Err("required scope must be one registered canonical scope".into());
    }
    if !ctx.payload_digest.is_empty() && ctx.payload_digest.len() != 32 {
        return Err(format!("payload digest must be empty or 32 bytes, got {}", ctx.payload_digest.len()));
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

/// Return SHA-256 of the operation-context v2 preimage.
pub fn operation_context_v2_hash(ctx: &OperationContextV2) -> Result<Vec<u8>, String> {
    Ok(Sha256::digest(operation_context_v2_bytes(ctx)?).to_vec())
}

/// Encode the session-context v2 preimage in canonical field order.
pub fn session_context_v2_bytes(inputs: &SessionContextV2Inputs) -> Result<Vec<u8>, String> {
    if !is_key_id(&inputs.verifier_id) {
        return Err("verifier ID must be 64 lowercase hexadecimal characters".into());
    }
    if !is_canonical_workspace_id(&inputs.workspace_id) {
        return Err("workspace ID must be a canonical lowercase UUID".into());
    }
    if !is_key_id(&inputs.agent_id) {
        return Err("agent ID must be 64 lowercase hexadecimal characters".into());
    }
    if inputs.request_hash.len() != 32 {
        return Err(format!("request hash must be 32 bytes, got {}", inputs.request_hash.len()));
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

/// Return SHA-256 of the session-context v2 preimage.
pub fn build_session_context_v2(inputs: &SessionContextV2Inputs) -> Result<Vec<u8>, String> {
    Ok(Sha256::digest(session_context_v2_bytes(inputs)?).to_vec())
}

fn is_key_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_canonical_workspace_id(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23].iter().all(|index| value.as_bytes()[*index] == b'-')
        && value.bytes().enumerate().all(|(index, b)| {
            [8, 13, 18, 23].contains(&index) || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
        })
}
