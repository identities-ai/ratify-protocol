//! Operation context, session context and context policy digests.

use std::sync::Arc;

use ratify_protocol::v2::V2ContextPolicy;
use ratify_protocol::{
    build_session_context_v2, decode_payload_digest_v2, operation_context_v2_hash,
    session_context_v2_bytes, OperationContextV2, SessionContextV2Inputs,
};

use crate::error::FfiResult;

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiOperationContext {
    pub required_scope: String,
    pub operation: String,
    pub resource_id: String,
    pub requested_path: String,
    pub payload_digest: Vec<u8>,
}

impl From<FfiOperationContext> for OperationContextV2 {
    fn from(c: FfiOperationContext) -> Self {
        OperationContextV2 {
            required_scope: c.required_scope,
            operation: c.operation,
            resource_id: c.resource_id,
            requested_path: c.requested_path,
            payload_digest: c.payload_digest,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct FfiSessionContextInputs {
    pub verifier_id: String,
    pub workspace_id: String,
    pub agent_id: String,
    pub session_id: String,
    pub invocation_id: String,
    pub request_hash: Vec<u8>,
}

impl From<FfiSessionContextInputs> for SessionContextV2Inputs {
    fn from(c: FfiSessionContextInputs) -> Self {
        SessionContextV2Inputs {
            verifier_id: c.verifier_id,
            workspace_id: c.workspace_id,
            agent_id: c.agent_id,
            session_id: c.session_id,
            invocation_id: c.invocation_id,
            request_hash: c.request_hash,
        }
    }
}

#[uniffi::export]
pub fn ffi_operation_context_hash(context: FfiOperationContext) -> FfiResult<Vec<u8>> {
    Ok(operation_context_v2_hash(&context.into())?)
}

#[uniffi::export]
pub fn ffi_session_context_bytes(inputs: FfiSessionContextInputs) -> FfiResult<Vec<u8>> {
    Ok(session_context_v2_bytes(&inputs.into())?)
}

#[uniffi::export]
pub fn ffi_build_session_context(inputs: FfiSessionContextInputs) -> FfiResult<Vec<u8>> {
    Ok(build_session_context_v2(&inputs.into())?)
}

/// Decode `sha256:<64 hex>` into 32 raw bytes; `None` in, `None` out.
#[uniffi::export]
pub fn ffi_decode_payload_digest(encoded: Option<String>) -> FfiResult<Option<Vec<u8>>> {
    Ok(decode_payload_digest_v2(encoded.as_deref())?)
}

/// A validated, fingerprinted context policy (SPEC-v2 context policy).
#[derive(uniffi::Object)]
pub struct FfiContextPolicy {
    pub(crate) inner: V2ContextPolicy,
}

#[uniffi::export]
impl FfiContextPolicy {
    #[uniffi::constructor]
    pub fn new(
        profile: String,
        require_bound: bool,
        required_fields: Vec<String>,
        expected_session_context: Vec<u8>,
    ) -> FfiResult<Arc<Self>> {
        let inner = V2ContextPolicy::new(
            &profile,
            require_bound,
            &required_fields,
            &expected_session_context,
        )?;
        Ok(Arc::new(FfiContextPolicy { inner }))
    }

    pub fn digest(&self) -> String {
        self.inner.digest().to_string()
    }
    pub fn require_bound(&self) -> bool {
        self.inner.require_bound()
    }
    pub fn profile(&self) -> String {
        self.inner.profile().to_string()
    }
    pub fn required_fields(&self) -> Vec<String> {
        self.inner.required_fields()
    }
    pub fn expected_session_context(&self) -> Vec<u8> {
        self.inner.expected_session_context()
    }
}
