// Test-only Part B reference implementations
// (`@identities-ai/ratify-protocol/v2/reference`). FOR TESTS AND CONFORMANCE
// SCENARIOS ONLY: nothing here is durable, spans processes, or provides an
// independent failure domain. Never use these as production stores and never
// release decisions on their authority (SPEC-v2 §7.1).

export {
  StoreTestOnly,
  RateAtFinalizationStoreTestOnly,
  MutexTestOnly,
  ErrNotAcknowledgedTestOnly,
  ErrHeadOfLineBlockedTestOnly,
  ErrSignerUnavailableTestOnly,
  ErrLogFrozenTestOnly,
  type StoreOptionsTestOnly,
  type StoreStateTestOnly,
} from "./v2reference/store.js";
export { JournalStoreTestOnly, newJournalStoreTestOnly } from "./v2reference/journal.js";
export { TrustRegistryTestOnly } from "./v2reference/trust_registry.js";
export { ChallengeIssuanceStoreTestOnly, ErrPersistFailedTestOnly, type PersistFaultTestOnly } from "./v2reference/challenges.js";
export {
  DeviceComponentTestOnly,
  DevicePrimaryTestOnly,
  DeviceJournalTestOnly,
  DeviceIssuanceTestOnly,
  DeviceCheckpointTestOnly,
  DeviceUplinkTestOnly,
  verifyDeviceAcknowledgementTestOnly,
  ErrDevicePowerLossTestOnly,
  ErrDeviceStorageFullTestOnly,
  ErrDeviceStateMismatchTestOnly,
  ErrDeviceFrozenTestOnly,
  type DeviceAcknowledgementTestOnly,
  type DevicePowerLossTestOnly,
  type DeviceStartupStatusTestOnly,
} from "./v2reference/device.js";
export {
  ApprovalLedgerTestOnly,
  ErrApprovalNotReleasedTestOnly,
  ErrApprovalActionMismatchTestOnly,
  ErrApprovalRootMismatchTestOnly,
  ErrApprovalSlotFilledTestOnly,
  ErrApprovalReusedTestOnly,
  ErrApprovalIncompleteTestOnly,
  ErrApprovalExpiredTestOnly,
  ErrApprovalAlreadyExecutedTestOnly,
  ErrApprovalSetInvalidTestOnly,
  ErrApprovalSetUnknownTestOnly,
  ErrApprovalSetAlreadyExistsTestOnly,
  type ApprovalSetTestOnly,
} from "./v2reference/approval_ledger.js";
