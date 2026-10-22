//! TEST/REFERENCE ONLY implementations of the Protocol v2 store contracts
//! (Go package `v2reference`). They are in-process and are not independent,
//! rollback-resistant, or durable; production deployments supply their own.

pub mod challenges;
pub mod journal;
pub mod store;

pub use challenges::{PersistFault, TestOnlyChallengeIssuanceStore};
pub use journal::JournalStore;
pub use store::{RateAtFinalizationStore, Store};
