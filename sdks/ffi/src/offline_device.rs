//! TestSupport bridge to the single-device offline reference checkpoint.

use std::sync::Arc;

use ratify_protocol::v2::reference::{DeviceCheckpointTestOnly, DeviceComponentTestOnly,
    DeviceErrorTestOnly, DevicePowerLoss, DevicePrimaryTestOnly, DeviceUplinkTestOnly};
use ratify_protocol::v2::{V2Context, V2ReceiptCheckpoint};

use crate::error::FfiResult;
use crate::guard::{call_on, call_with, Poison};
use crate::reference_store::{FfiReferenceStore, FfiReferenceStoreFailure};
use crate::release::FfiCheckpointAcknowledgement;

#[derive(Default, uniffi::Record)]
pub struct FfiDeviceReply {
    pub acknowledged: Vec<i64>,
    pub uploaded: Vec<i64>,
    pub ack_time: Option<i64>,
    pub acknowledgement: Option<FfiCheckpointAcknowledgement>,
    pub status: Option<String>,
    pub failure: Option<String>,
    pub store_failure: Option<FfiReferenceStoreFailure>,
}

fn error_reply(error: DeviceErrorTestOnly) -> FfiDeviceReply {
    if let DeviceErrorTestOnly::Store(store_error) = &error {
        let store_failure: FfiReferenceStoreFailure = store_error.clone().into();
        return FfiDeviceReply {
            failure: Some(store_error.class().map(|class| class.as_str().to_string())
                .unwrap_or_else(|| store_failure.kind.clone())),
            store_failure: Some(store_failure), ..Default::default()
        };
    }
    let failure = match error {
        DeviceErrorTestOnly::PowerLoss => "power_loss",
        DeviceErrorTestOnly::StorageFull => "storage_full",
        DeviceErrorTestOnly::StateMismatch => "state_mismatch",
        DeviceErrorTestOnly::Frozen => "checkpoint_frozen",
        DeviceErrorTestOnly::NotAcknowledged => "not_acknowledged",
        DeviceErrorTestOnly::Store(_) => unreachable!(),
    };
    FfiDeviceReply { failure: Some(failure.into()), ..Default::default() }
}

#[derive(uniffi::Object)]
pub struct FfiOfflineDevice {
    poison: Poison,
    primary: DevicePrimaryTestOnly,
    component: Arc<DeviceComponentTestOnly>,
    checkpoint: Arc<DeviceCheckpointTestOnly>,
    uplink: DeviceUplinkTestOnly,
}

#[derive(uniffi::Object)]
pub struct FfiDeviceSnapshot {
    poison: Poison,
    primary: DevicePrimaryTestOnly,
}

#[uniffi::export]
impl FfiOfflineDevice {
    #[uniffi::constructor]
    pub fn new(store: Arc<FfiReferenceStore>, replay_epoch: i64, seed: Vec<u8>, capacity: u32) -> FfiResult<Arc<Self>> {
        call_with(&[&store.poison], || {
            let primary = DevicePrimaryTestOnly::new(Arc::clone(&store.inner), replay_epoch)?;
            let component = Arc::new(DeviceComponentTestOnly::new(&seed, capacity as usize,
                Arc::clone(&store.inner) as Arc<dyn ratify_protocol::v2::V2AuthoritativeClock>)?);
            store.inner.set_acknowledgement_withheld(true);
            let checkpoint = Arc::new(DeviceCheckpointTestOnly::new(&primary, Arc::clone(&component),
                &component.public_key())?);
            checkpoint.provision()?;
            let uplink = DeviceUplinkTestOnly::new(Arc::clone(&checkpoint));
            Ok(Arc::new(Self { poison: Poison::default(), primary, component, checkpoint, uplink }))
        })
    }

    pub fn snapshot(&self) -> FfiResult<Arc<FfiDeviceSnapshot>> {
        call_on(&self.poison, || Ok(Arc::new(FfiDeviceSnapshot {
            poison: Poison::default(), primary: self.primary.clone_primary(),
        })))
    }

    pub fn restore(&self, snapshot: Arc<FfiDeviceSnapshot>) -> FfiResult<Arc<Self>> {
        call_with(&[&self.poison, &snapshot.poison], || {
            let primary = snapshot.primary.clone_primary();
            let component = Arc::clone(&self.component);
            let checkpoint = Arc::new(DeviceCheckpointTestOnly::new(&primary, Arc::clone(&component),
                &component.public_key())?);
            let uplink = DeviceUplinkTestOnly::new(Arc::clone(&checkpoint));
            Ok(Arc::new(Self { poison: Poison::default(), primary, component, checkpoint, uplink }))
        })
    }

    pub fn primary_store(&self) -> FfiResult<Arc<FfiReferenceStore>> {
        call_on(&self.poison, || Ok(Arc::new(FfiReferenceStore {
            poison: Poison::default(), inner: Arc::clone(&self.primary.store),
        })))
    }

    pub fn startup(&self) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || Ok(FfiDeviceReply {
            status: Some(self.checkpoint.startup().as_str().into()), ..Default::default()
        }))
    }

    pub fn set_power_loss(&self, mode: String) -> FfiResult<()> {
        call_on(&self.poison, || {
            let fault = match mode.as_str() {
                "before_commit" => DevicePowerLoss::BeforeCommit,
                "after_commit" => DevicePowerLoss::AfterCommit,
                _ => return Err(crate::error::protocol(ratify_protocol::v2::V2ErrorClass::ConfigurationInvalid,
                    "unknown device power-loss mode")),
            };
            self.component.set_power_loss(fault);
            Ok(())
        })
    }

    pub fn submit_pending(&self) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || {
            let (acknowledged, error) = self.checkpoint.submit_pending(&V2Context::background());
            let mut reply = error.map(error_reply).unwrap_or_default();
            reply.acknowledged = acknowledged;
            Ok(reply)
        })
    }

    pub fn resubmit(&self, sequence: i64) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || Ok(match self.checkpoint.resubmit(&V2Context::background(), sequence) {
            Ok(ack) => FfiDeviceReply { ack_time: Some(ack.timestamp), ..Default::default() },
            Err(error) => error_reply(error),
        }))
    }

    pub fn upload(&self) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || Ok(FfiDeviceReply {
            uploaded: self.uplink.upload(&V2Context::background()), ..Default::default()
        }))
    }

    pub fn get_acknowledgement(&self, log_id: String, sequence: i64) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || Ok(match self.checkpoint.get_v2_acknowledgement(
            &V2Context::background(), &log_id, sequence) {
            Ok(ack) => FfiDeviceReply { ack_time: Some(ack.timestamp), acknowledgement: Some(ack.into()),
                ..Default::default() },
            Err(error) => error_reply(DeviceErrorTestOnly::Store(error)),
        }))
    }

    pub fn acknowledge_receipt(&self, log_id: String, sequence: i64, previous_entry_hash: Vec<u8>,
                               entry_hash: Vec<u8>) -> FfiResult<FfiDeviceReply> {
        call_on(&self.poison, || Ok(match self.checkpoint.acknowledge(&V2Context::background(),
            &log_id, sequence, &previous_entry_hash, &entry_hash) {
            Ok(ack) => FfiDeviceReply { ack_time: Some(ack.timestamp), acknowledgement: Some(ack.into()),
                ..Default::default() },
            Err(error) => error_reply(error),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratify_protocol::v2::{V2Error, V2ErrorClass, V2StoreError};
    use ratify_protocol::v2::reference::Store;

    #[test]
    fn provisioned_device_starts_ready_and_has_no_acknowledgements() {
        let (_, key) = ratify_protocol::hybrid_keypair_from_seeds(&[1; 32], &[2; 32]);
        let store = Arc::new(FfiReferenceStore {
            poison: Poison::default(),
            inner: Arc::new(Store::new(1_800_000_000, 30,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &key).unwrap()),
        });
        let device = FfiOfflineDevice::new(store, 0, vec![3; 32], 2).unwrap();
        assert_eq!(device.startup().unwrap().status.as_deref(), Some("ready"));
        assert!(device.submit_pending().unwrap().acknowledged.is_empty());
        assert!(device.upload().unwrap().uploaded.is_empty());
        assert_eq!(device.get_acknowledgement("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(), 1)
            .unwrap().failure.as_deref(), Some("acknowledgement_not_found"));
        assert!(device.set_power_loss("invalid".into()).is_err());
    }

    #[test]
    fn snapshot_restores_a_separate_primary_bound_to_the_same_component() {
        let (_, key) = ratify_protocol::hybrid_keypair_from_seeds(&[1; 32], &[2; 32]);
        let store = Arc::new(FfiReferenceStore {
            poison: Poison::default(),
            inner: Arc::new(Store::new(1_800_000_000, 30,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &key).unwrap()),
        });
        let device = FfiOfflineDevice::new(Arc::clone(&store), 0, vec![3; 32], 2).unwrap();
        let snapshot = device.snapshot().unwrap();
        let restored = device.restore(snapshot).unwrap();
        let restored_store = restored.primary_store().unwrap();
        assert!(!Arc::ptr_eq(&store.inner, &restored_store.inner));
        assert_eq!(restored.startup().unwrap().status.as_deref(), Some("ready"));
        assert!(Arc::ptr_eq(&device.component, &restored.component));
    }

    #[test]
    fn classified_clock_failure_survives_device_reply() {
        let reply = error_reply(DeviceErrorTestOnly::Store(V2StoreError::Classified(
            V2Error::new(V2ErrorClass::ClockRegressed, "clock moved backward"))));
        assert_eq!(reply.failure.as_deref(), Some("clock_regressed"));
        let failure = reply.store_failure.unwrap();
        assert_eq!(failure.kind, "classified");
        assert_eq!(failure.class, "clock_regressed");
        assert_eq!(failure.detail, "clock moved backward");
    }
}
