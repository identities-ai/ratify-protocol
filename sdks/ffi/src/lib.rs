//! Internal FFI layer for the Ratify Protocol Swift and Kotlin SDKs.
//!
//! Everything here is generated into internal (non-public) Swift and Kotlin
//! declarations. The public SDK APIs are written by hand over it, so this
//! layer can change without breaking applications. It contains no protocol
//! logic: each function converts owned records to core types, calls the
//! Rust core once, and converts the result back.

uniffi::setup_scaffolding!("ratify_ffi");

mod context;
mod error;
mod guard;
mod keys;
mod objects;
mod scope;
mod sign;
mod verify;

pub use context::*;
pub use error::*;
pub use keys::*;
pub use objects::*;
pub use scope::*;
pub use sign::*;
pub use verify::*;
