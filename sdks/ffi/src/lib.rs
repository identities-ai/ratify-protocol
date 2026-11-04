//! Internal FFI layer for the Ratify Protocol Swift and Kotlin SDKs.
//!
//! Everything here is generated into internal (non-public) Swift and Kotlin
//! declarations. The public SDK APIs are written by hand over it, so this
//! layer can change without breaking applications. It contains no protocol
//! logic: each function converts owned records to core types, calls the
//! Rust core once, and converts the result back.

uniffi::setup_scaffolding!("ratify_ffi");

mod archival;
mod context;
mod device_state;
mod claim;
mod live_verify;
mod release;
mod transaction_verify;
mod live_providers;
mod error;
mod evaluator;
mod guard;
mod journal;
mod status_publisher;
mod store;
mod challenge_issuance;
mod keys;
mod objects;
mod rotation;
mod scope;
mod sign;
mod split;
mod status;
mod storage;
mod verify;

pub use archival::*;
pub use context::*;
pub use device_state::*;
pub use claim::*;
pub use live_verify::*;
pub use release::*;
pub use transaction_verify::*;
pub use live_providers::*;
pub use error::*;
pub use evaluator::*;
pub use keys::*;
pub use journal::*;
pub use status_publisher::*;
pub use store::*;
pub use challenge_issuance::*;
pub use objects::*;
pub use rotation::*;
pub use scope::*;
pub use sign::*;
pub use split::*;
pub use status::*;
pub use storage::*;
pub use verify::*;
