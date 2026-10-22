//! TEST/REFERENCE ONLY implementations of the Protocol v2 store contracts
//! (Go package `v2reference`). They are in-process and are not independent,
//! rollback-resistant, or durable; production deployments supply their own.

pub mod approval_ledger;
pub mod challenges;
pub mod device_state;
pub mod journal;
pub mod offline_device;
pub mod store;
pub mod trust_registry;

pub use approval_ledger::{ApprovalErrorTestOnly, ApprovalLedgerTestOnly, ApprovalSetTestOnly};
pub use challenges::{PersistFault, TestOnlyChallengeIssuanceStore};
pub use device_state::{
    DeviceIssuanceTestOnly, DeviceJournalTestOnly, DevicePrimaryTestOnly, DeviceStateProjectionTestOnly,
};
pub use journal::JournalStore;
pub use offline_device::{
    verify_device_acknowledgement_test_only, DeviceAcknowledgementTestOnly, DeviceCheckpointTestOnly,
    DeviceComponentTestOnly, DeviceErrorTestOnly, DevicePowerLoss, DeviceStartupStatus, DeviceUplinkTestOnly,
};
pub use store::{RateAtFinalizationStore, Store};
pub use trust_registry::TrustRegistry;
