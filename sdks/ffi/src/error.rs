//! The three closed error families every FFI function returns.

use ratify_protocol::v2::{V2Error, V2ErrorClass};

/// Every failure crossing the FFI boundary. `class` is the SPEC-v2 §2.7
/// spelling; the hand-written layers map it to their public `ErrorClass`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// A core `V2Error`: decode, check, digest, journal, configuration.
    #[error("{message} ({class})")]
    Protocol { class: String, message: String },
    /// A `V2SignError`: signing refused or the signer failed.
    #[error("{message} ({class}, {kind})")]
    Signing {
        class: String,
        kind: String,
        message: String,
    },
    /// An internal failure (`panic` or `poisoned`); never a protocol result.
    #[error("internal {kind}: {message}")]
    Internal { kind: String, message: String },
}

impl From<V2Error> for FfiError {
    fn from(e: V2Error) -> Self {
        FfiError::Protocol {
            class: e.class.as_str().to_string(),
            message: e.message,
        }
    }
}

pub(crate) fn protocol(class: V2ErrorClass, message: impl Into<String>) -> FfiError {
    FfiError::Protocol {
        class: class.as_str().to_string(),
        message: message.into(),
    }
}

pub(crate) type FfiResult<T> = Result<T, FfiError>;

/// Every §2.7 class spelling in table order. The Swift and Kotlin
/// `ErrorClass` enums are pinned to this list by a test.
#[uniffi::export]
pub fn ffi_error_class_spellings() -> Vec<String> {
    V2ErrorClass::ALL
        .iter()
        .map(|c| c.as_str().to_string())
        .collect()
}
