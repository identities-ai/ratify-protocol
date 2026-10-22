//! TEST/REFERENCE ONLY implementations of the Protocol v2 store contracts
//! (Go package `v2reference`). They are in-process and are not independent,
//! rollback-resistant, or durable; production deployments supply their own.

pub mod journal;

pub use journal::JournalStore;
