//! Operation context, session context and context policy digests.

use std::sync::Arc;

use ratify_protocol::v2::V2ContextPolicy;
use ratify_protocol::{
    build_session_context_v2, decode_payload_digest_v2, operation_context_v2_hash,
    session_context_v2_bytes, OperationContextV2, SessionContextV2Inputs,
};

use crate::error::FfiResult;
use crate::guard::{call, call_on, Poison};

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
    call(|| Ok(operation_context_v2_hash(&context.into())?))
}

#[uniffi::export]
pub fn ffi_session_context_bytes(inputs: FfiSessionContextInputs) -> FfiResult<Vec<u8>> {
    call(|| Ok(session_context_v2_bytes(&inputs.into())?))
}

#[uniffi::export]
pub fn ffi_build_session_context(inputs: FfiSessionContextInputs) -> FfiResult<Vec<u8>> {
    call(|| Ok(build_session_context_v2(&inputs.into())?))
}

/// Decode `sha256:<64 hex>` into 32 raw bytes; `None` in, `None` out.
#[uniffi::export]
pub fn ffi_decode_payload_digest(encoded: Option<String>) -> FfiResult<Option<Vec<u8>>> {
    call(|| Ok(decode_payload_digest_v2(encoded.as_deref())?))
}

/// A validated, fingerprinted context policy (SPEC-v2 context policy).
#[derive(uniffi::Object)]
pub struct FfiContextPolicy {
    poison: Poison,
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
        call(|| {
            let inner =
                V2ContextPolicy::new(&profile, require_bound, &required_fields, &expected_session_context)?;
            Ok(Arc::new(FfiContextPolicy { poison: Poison::default(), inner }))
        })
    }

    pub fn digest(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.inner.digest().to_string()))
    }
    pub fn require_bound(&self) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.inner.require_bound()))
    }
    pub fn profile(&self) -> FfiResult<String> {
        call_on(&self.poison, || Ok(self.inner.profile().to_string()))
    }
    pub fn required_fields(&self) -> FfiResult<Vec<String>> {
        call_on(&self.poison, || Ok(self.inner.required_fields()))
    }
    pub fn expected_session_context(&self) -> FfiResult<Vec<u8>> {
        call_on(&self.poison, || Ok(self.inner.expected_session_context()))
    }
}

/// One public call's cancellation: a child of the background context that
/// the Swift task or Kotlin coroutine cancels. Cancellation is cooperative
/// (SPEC-v2 §1.3): the core and callbacks observe it; nothing is interrupted.
#[derive(uniffi::Object)]
pub struct FfiCancelToken {
    poison: Poison,
    ctx: ratify_protocol::v2::V2Context,
    handle: ratify_protocol::v2::V2CancelHandle,
}

#[uniffi::export]
impl FfiCancelToken {
    /// A token with no deadline (`timeout_ms` = None) or one that cancels
    /// itself after `timeout_ms` milliseconds.
    #[uniffi::constructor]
    pub fn new(timeout_ms: Option<u64>) -> FfiResult<Arc<Self>> {
        call(|| {
            let root = ratify_protocol::v2::V2Context::background();
            let (ctx, handle) = match timeout_ms {
                Some(ms) => root.with_timeout(std::time::Duration::from_millis(ms)),
                None => root.with_cancel(),
            };
            Ok(Arc::new(FfiCancelToken { poison: Poison::default(), ctx, handle }))
        })
    }

    pub fn cancel(&self) -> FfiResult<()> {
        call_on(&self.poison, || {
            self.handle.cancel();
            Ok(())
        })
    }

    /// Whether the token was cancelled or its deadline passed.
    pub fn is_cancelled(&self) -> FfiResult<bool> {
        call_on(&self.poison, || Ok(self.ctx.is_done()))
    }
}

impl FfiCancelToken {
    /// The context passed to core calls made under this token.
    #[allow(dead_code)] // used by the callback-invoking operations (next milestone)
    pub(crate) fn context(&self) -> &ratify_protocol::v2::V2Context {
        &self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_and_deadline_reach_the_core_context() {
        let t = FfiCancelToken::new(None).unwrap();
        assert!(!t.is_cancelled().unwrap() && !t.context().is_done());
        t.cancel().unwrap();
        assert!(t.is_cancelled().unwrap() && t.context().is_done());

        let d = FfiCancelToken::new(Some(20)).unwrap();
        assert!(!d.is_cancelled().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(d.is_cancelled().unwrap());
    }
}
