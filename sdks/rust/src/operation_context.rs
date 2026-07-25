//! Operation-context and session-context canonical constructions
//! (SPEC §6.4.9).
//!
//! Both are raw binary, domain-separated, and length-prefixed — NOT JSON.
//! Length prefixes exist because raw concatenation is ambiguous
//! (`"ab" || "c"` equals `"a" || "bc"`); domain tags exist so a hash
//! computed for one construction can never collide with the other.

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec::Vec};

use sha2::{Digest, Sha256};

const OPERATION_CONTEXT_DOMAIN_TAG: &[u8] = b"ratify/operation-context/v1";
const SESSION_CONTEXT_DOMAIN_TAG: &[u8] = b"ratify/session-context/v1";

/// The inputs that identify one specific action a presentation authorizes
/// (SPEC §6.4.9). Which fields are populated is deployment-defined —
/// empty fields encode as zero-length and the construction stays
/// well-defined.
#[derive(Debug, Clone, Default)]
pub struct OperationContext {
    /// Scope the action requires (e.g. "files:write").
    pub required_scope: String,
    /// Action/operation type (e.g. "git.push", "tool.invoke").
    pub operation: String,
    /// Target resource identity.
    pub resource_id: String,
    /// Path within the resource.
    pub requested_path: String,
    /// Empty, or exactly 32 bytes: the SHA-256 of the canonical request
    /// payload, where one exists.
    pub payload_digest: Vec<u8>,
}

/// The inputs that identify the session a presentation belongs to, plus
/// the `request_hash` binding the specific operation (SPEC §6.4.9). The
/// Middleware Custody Profile (SPEC §15.2.1) requires all of them; other
/// deployments populate what they have.
#[derive(Debug, Clone, Default)]
pub struct SessionContextInputs {
    /// The verifier's identity (e.g. its public key ID). Including it
    /// makes cross-verifier challenge forwarding detectable at the
    /// cryptographic layer (SPEC §15.1).
    pub verifier_id: String,
    /// The deployment's workspace/tenant identifier.
    pub workspace_id: String,
    /// The presenting agent's identity.
    pub agent_id: String,
    /// The session identifier.
    pub session_id: String,
    /// The specific invocation within the session.
    pub invocation_id: String,
    /// Exactly 32 bytes — the [`operation_context_hash`] of the action
    /// being authorized. A deployment with no operation-specific inputs
    /// derives it from an all-empty [`OperationContext`]. Binding the
    /// session but not the operation would let an intermediary attach a
    /// valid proof to the wrong action inside the right session.
    pub request_hash: Vec<u8>,
}

/// Append big-endian uint64 length || field bytes.
fn length_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
    buf.extend_from_slice(field);
}

/// The SPEC §6.4.9 operation-context preimage: the domain tag followed
/// by every field length-prefixed, in canonical order. Errors if
/// `payload_digest` is neither empty nor exactly 32 bytes.
pub fn operation_context_bytes(ctx: &OperationContext) -> Result<Vec<u8>, String> {
    if !ctx.payload_digest.is_empty() && ctx.payload_digest.len() != 32 {
        return Err(format!(
            "payload digest must be empty or 32 bytes, got {}",
            ctx.payload_digest.len()
        ));
    }
    let mut buf = Vec::from(OPERATION_CONTEXT_DOMAIN_TAG);
    length_prefixed(&mut buf, ctx.required_scope.as_bytes());
    length_prefixed(&mut buf, ctx.operation.as_bytes());
    length_prefixed(&mut buf, ctx.resource_id.as_bytes());
    length_prefixed(&mut buf, ctx.requested_path.as_bytes());
    length_prefixed(&mut buf, &ctx.payload_digest);
    Ok(buf)
}

/// The 32-byte `request_hash`: SHA-256 over the SPEC §6.4.9
/// operation-context bytes.
pub fn operation_context_hash(ctx: &OperationContext) -> Result<Vec<u8>, String> {
    Ok(Sha256::digest(operation_context_bytes(ctx)?).to_vec())
}

/// The SPEC §6.4.9 session-context preimage: the domain tag followed by
/// every field length-prefixed, in canonical order. Errors unless
/// `request_hash` is exactly 32 bytes — use [`operation_context_hash`]
/// to derive it, over an all-empty [`OperationContext`] when the
/// deployment has no operation-specific inputs.
pub fn session_context_bytes(inputs: &SessionContextInputs) -> Result<Vec<u8>, String> {
    if inputs.request_hash.len() != 32 {
        return Err(format!(
            "request hash must be exactly 32 bytes, got {}",
            inputs.request_hash.len()
        ));
    }
    let mut buf = Vec::from(SESSION_CONTEXT_DOMAIN_TAG);
    length_prefixed(&mut buf, inputs.verifier_id.as_bytes());
    length_prefixed(&mut buf, inputs.workspace_id.as_bytes());
    length_prefixed(&mut buf, inputs.agent_id.as_bytes());
    length_prefixed(&mut buf, inputs.session_id.as_bytes());
    length_prefixed(&mut buf, inputs.invocation_id.as_bytes());
    length_prefixed(&mut buf, &inputs.request_hash);
    Ok(buf)
}

/// The 32-byte `session_context`: SHA-256 over the SPEC §6.4.9
/// session-context bytes — what a session-bound deployment passes as
/// `VerifyOptions.session_context` (and what the agent side includes in
/// the challenge signing bytes, SPEC §6.4.2). Verification receipts and
/// audit records bind this hash, never the preimage.
pub fn build_session_context(inputs: &SessionContextInputs) -> Result<Vec<u8>, String> {
    Ok(Sha256::digest(session_context_bytes(inputs)?).to_vec())
}
