// Ratify Protocol v2 public entry point (`@identities-ai/ratify-protocol/v2`).
// The package root re-exports this surface alongside the v1 API.
//
// There is deliberately no export that signs caller-selected bytes, codes,
// or contexts: every signature comes from a typed object signer (SPEC-v2
// §3.2). The only actionable value is V2ReleasedDecision, produced only by
// releaseV2Decision (§6.9). Test-only Part B reference stores live under
// `@identities-ai/ratify-protocol/v2/reference`.

// Errors, limits, clock bounds.
export {
  V2Error,
  V2SentinelError,
  V2_ERROR_CLASSES,
  v2ErrorClassOf,
  ErrWitnessLogFork,
  ErrWitnessLogGap,
  ErrWitnessLogOrphan,
  ErrWitnessLogFrozen,
  ErrV2ClaimProofConflict,
  ErrKeyRotationForkV2,
  ErrKeyRotationFrozenV2,
  ErrV2RateLimitExceeded,
  type V2ErrorClass,
} from "./errors_v2.js";
export {
  MAX_DELEGATION_CERT_BYTES_V2,
  MAX_PROOF_BUNDLE_BYTES_V2,
  MAX_KEY_ROTATION_STATEMENT_BYTES_V2,
  MAX_REVOCATION_PUSH_BYTES_V2,
  MAX_REVOCATION_PUSH_REFS_V2,
  MAX_REVOCATION_LIST_BYTES_V2,
  MAX_REVOCATION_LIST_REFS_V2,
  MAX_WITNESS_ENTRY_BYTES_V2,
  MAX_WITNESS_ENTRY_DATA_BYTES_V2,
  MAX_VERIFICATION_RECEIPT_BYTES_V2,
  MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2,
  MAX_STATUS_EVIDENCE_BATCH_BYTES_V2,
  MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2,
  MAX_TRANSACTION_RECEIPT_BYTES_V2,
} from "./limits_v2.js";
export {
  V2_MAX_TIMESTAMP_SECONDS,
  V2_MAX_FUTURE_SKEW_SECONDS,
  V2_MAX_CHALLENGE_AGE_SECONDS,
  V2_MAX_STATUS_LIFETIME_SECONDS,
  V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS,
  V2_MAX_RATE_WINDOW_SECONDS,
  V2_MAX_DELEGATION_LIFETIME_SECONDS,
  validV2Timestamp,
} from "./clock_bounds_v2.js";

// Canonical JSON, key IDs, signing transcript, typed and external signers.
export { canonicalJSONV2 } from "./json_v2.js";
export {
  deriveKeyIDV2,
  verifyV2DelegationCertificateSignature,
  V2_OBJECT_TYPE,
  v2SigningMessage,
  v2MLDSAContext,
  validateHybridKeyPairV2,
  type HybridKeyPairV2,
  type V2SignOptions,
} from "./crypto_v2.js";
export {
  keyIDV2,
  externalMuV2,
  SIGNER_MODE_DIRECT_V2,
  SIGNER_MODE_EXTERNAL_MU_V2,
  type SignerModeV2,
  type SignRequestV2,
  type SignerV2,
  type SignOptionsV2,
} from "./signer_v2.js";

// Operation, session and challenge-claim digests; scopes.
export {
  operationContextV2Bytes,
  operationContextV2Hash,
  sessionContextV2Bytes,
  buildSessionContextV2,
  type OperationContextV2,
  type SessionContextV2Inputs,
} from "./operation_context_v2.js";
export { challengeClaimDigestV2, protocolClaimIDV2, protocolClaimIDFromDigestV2 } from "./challenge_claim_v2.js";
export { SCOPE_IDENTITY_DELEGATE_V2, validateScopesV2, validateRequiredScopeV2, expandScopesV2, intersectScopesV2 } from "./scope_v2.js";

// Constraint registry, pinned tzdata, extension evaluator profiles.
export {
  CONSTRAINT_TIME_WINDOW_V2,
  CONSTRAINT_MAX_AMOUNT_V2,
  CONSTRAINT_MAX_RATE_V2,
  CONSTRAINT_RESOURCE_PATH_V2,
  CONSTRAINT_RECEIVER_AUDIENCE_V2,
  MAX_AUDIENCE_IDS_V2,
  isRegisteredConstraintTypeV2,
  encodeConstraintV2,
  type ConstraintV2,
  type ConstraintContextV2,
} from "./constraints_v2.js";
export { TZDB_VERSION_V2, TZDB_ZIP_SHA256_V2 } from "./tzdb_v2.js";
export {
  CONSTRAINT_MAX_COUNT_V2,
  CONSTRAINT_ALLOWED_VALUES_V2,
  PROFILE_MAX_COUNT_V2,
  PROFILE_ALLOWED_VALUES_V2,
  MAX_CONSTRAINT_EVALUATORS_V2,
  MAX_CONSTRAINT_EVALUATOR_TIMEOUT_MS_V2,
  ConstraintEvaluatorRegistryV2,
  newConstraintEvaluatorRegistryV2,
  constraintProfileDigestV2,
  validExtensionTypeV2,
  validProfileIDV2,
  standardMaxCountEvaluatorV2,
  standardAllowedValuesEvaluatorV2,
  type ConstraintProfileDescriptorV2,
  type ConstraintEvaluatorRefV2,
  type ConstraintEvaluationInputV2,
  type ConstraintOutcomeV2,
  type ConstraintEvaluationResultV2,
  type ConstraintEvaluatorFuncV2,
  type ConstraintEvaluatorRegistrationV2,
} from "./constraint_evaluator_v2.js";

// Wire objects: certificates, proof bundles, revocation list and push.
export {
  bundleHashV2,
  decodeDelegationCertV2,
  encodeDelegationCertV2,
  delegationCertV2SignBytes,
  signDelegationCertV2,
  signDelegationCertV2WithSigner,
  verifyDelegationCertV2Signature,
  decodeProofBundleV2,
  encodeProofBundleV2,
  presentationV2SignBytes,
  delegationDigestV2,
  signProofBundleV2,
  signProofBundleV2WithSigner,
  verifyProofBundleV2Signatures,
  decodeRevocationListV2,
  encodeRevocationListV2,
  revocationListV2SignBytes,
  signRevocationListV2,
  signRevocationListV2WithSigner,
  verifyRevocationListV2Signature,
  decodeRevocationPushV2,
  encodeRevocationPushV2,
  revocationPushV2SignBytes,
  signRevocationPushV2,
  signRevocationPushV2WithSigner,
  verifyRevocationPushV2Signature,
  statusEvidenceDigestV2,
  type DelegationCertV2,
  type ProofBundleV2,
  type RevocationListV2,
  type RevocationPushV2,
  type RevokedCertV2,
} from "./protocol_v2_wire.js";

// Key rotation, witness log, verification receipts, transaction receipts.
export {
  statementBodyDigestV2,
  decodeKeyRotationStatementV2,
  encodeKeyRotationStatementV2,
  keyRotationStatementV2SignBytes,
  keyRotationStatementV2Digest,
  signKeyRotationStatementV2,
  signKeyRotationStatementV2WithSigners,
  verifyKeyRotationStatementV2,
  newKeyRotationV2Journal,
  acceptKeyRotationStatementV2,
  recoverKeyRotationV2,
  type V2AppendResult,
  type KeyRotationStatementV2,
  type KeyRotationV2State,
  type KeyRotationV2Journal,
  type KeyRotationV2AcceptedEntry,
  type KeyRotationV2AcceptOutcome,
} from "./key_rotation_v2.js";
export {
  decodeWitnessEntryV2,
  encodeWitnessEntryV2,
  witnessEntryV2SignBytes,
  witnessEntryV2Digest,
  signWitnessEntryV2,
  signWitnessEntryV2WithSigner,
  verifyWitnessEntryV2,
  type WitnessEntryV2,
  type WitnessV2Head,
} from "./witness_v2.js";
export {
  decodeVerificationReceiptV2,
  encodeVerificationReceiptV2,
  verificationReceiptV2SignBytes,
  verificationReceiptV2Digest,
  signVerificationReceiptV2,
  signVerificationReceiptV2WithSigner,
  verifyVerificationReceiptV2,
  checkVerificationReceiptV2BundleBinding,
  verificationReceiptV2Body,
  decodeVerificationReceiptBodyV2,
  bindVerificationReceiptBodyV2,
  signPreparedVerificationReceiptV2,
  signPreparedVerificationReceiptV2WithSigner,
  type VerificationReceiptV2,
  type ReceiptV2Head,
  type StatusEvidenceEntryV2,
} from "./verification_receipt_v2.js";
export {
  decodeTransactionReceiptV2,
  encodeTransactionReceiptV2,
  transactionReceiptV2SignBytes,
  signTransactionReceiptPartyV2,
  signTransactionReceiptPartyV2WithSigner,
  verifyTransactionReceiptV2Signatures,
  transactionContextHashV2,
  transactionPartyRequestHashV2,
  MAX_TRANSACTION_RECEIPT_BYTES,
  MAX_TRANSACTION_PARTIES,
  type TransactionReceiptV2,
  type TransactionReceiptPartyV2,
  type TransactionReceiptSignatureV2,
} from "./transaction_receipt_v2.js";
export {
  verifyTransactionReceiptV2,
  type TransactionVerifySourcesV2,
  type TransactionVerifyRequestV2,
  type TransactionPartyVerificationV2,
  type TransactionReceiptVerificationV2,
} from "./transaction_verify_v2.js";
export {
  FRESHNESS_UNVERIFIED_V2,
  verifyArchivalProofBundleV2,
  encodeArchivalProofBundleResultV2,
  verifyArchivalDelegationCertV2,
  verifyArchivalRevocationListV2,
  verifyArchivalRevocationPushV2,
  verifyArchivalKeyRotationStatementV2,
  verifyArchivalWitnessEntryV2,
  verifyArchivalVerificationReceiptV2,
  verifyArchivalTransactionReceiptV2,
  type ArchivalVerificationV2,
  type ArchivalProofBundleResultV2,
} from "./archival_v2.js";

// Status reducer, SecurityJournalV2, evidence batches, publisher.
export {
  emptyRevocationStatusStateV2,
  applyRevocationListV2,
  applyRevocationPushV2,
  transitionRevocationStatusEpochV2,
  revocationStatusForCertV2,
  revokedSetDigestV2,
  type RevocationStatusPolicyV2,
  type RevocationStatusStateV2,
  type RevocationStatusResultV2,
  type RevocationObservationV2,
} from "./status_state_v2.js";
export {
  ErrSecurityJournalConflictV2,
  emptySecurityJournalV2,
  loadAnchoredSecurityJournalV2,
  recordSecurityKeyRoleV2,
  configureStatusKeyEpochV2,
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  revocationStatusFromJournalV2,
  validateSecurityJournalV2,
  validateSecurityJournalTransitionV2,
  type SecurityJournalV2,
  type SecurityJournalHeadV2,
  type SecurityJournalLoadV2,
  type SecurityJournalStoreV2,
  type KeyRoleBindingV2,
  type StatusKeyBindingV2,
} from "./security_journal_v2.js";
export {
  MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES,
  exportSecurityJournalSnapshotV2,
  importSecurityJournalSnapshotV2,
  securityJournalSnapshotDigestV2,
  migrateSecurityJournalV2,
  decodeLegacySecurityJournalV1,
} from "./security_journal_snapshot_v2.js";
export {
  encodeV2StatusEvidenceBatch,
  decodeV2StatusEvidenceBatch,
  type V2StatusEvidenceObject,
  type V2StatusEvidenceBatch,
} from "./status_batch_v2.js";
export {
  type V2StatusKeyConfig,
  type CertificateRefV2,
  type V2StatusEvidenceRequest,
  type V2StatusEvidenceProvider,
} from "./status_provenance_v2.js";
export {
  V2StatusPublisher,
  newV2StatusPublisher,
  newV2StatusPublisherWithKey,
  type V2StatusPublisherState,
  type V2StatusPublication,
} from "./status_publisher_v2.js";

// Live verifier: preflight, claim, staged evaluation, committed outcome, release.
export { newV2ContextPolicy, evaluateProofBundleV2ContextPolicy, type V2ContextPolicy, type V2ContextPolicyAssessment } from "./context_policy_v2.js";
export {
  evaluateReceiverAudienceV2,
  buildV2RateReservationBatch,
  type V2DeferredConstraint,
  type V2AudienceMembership,
  type V2AudienceAssessment,
  type V2RateReservation,
} from "./audience_v2.js";
export {
  validateProofBundleV2Preflight,
  preflightProofBundleV2,
  V2PreflightResult,
  type ExpectedChallengeV2,
  type V2ReceiverBindingHook,
} from "./verify_v2_preflight.js";
export {
  claimProofBundleV2,
  finalizeClaimProofBundleV2,
  challengeClaimTimeCurrentV2,
  V2EvaluationToken,
  type V2ChallengeClaim,
  type V2ClaimDisposition,
  type V2ClaimResult,
  type V2ClaimOutcome,
  type V2AuthoritativeClock,
  type ClaimStoreV2,
  type V2RateReservationStore,
  type V2RateAtFinalizationStore,
} from "./claim_store_v2.js";
export {
  evaluateProofBundleV2LocalAuthorization,
  resolveClaimProofBundleV2AfterAudience,
  resolveClaimProofBundleV2AfterRate,
  type V2LocalAuthorizationOptions,
  type V2LocalAuthorizationAssessment,
  type V2LocalPolicyFailure,
  type V2CertificateStatusCheck,
} from "./authorization_v2.js";
export {
  initialV2EvaluationProgress,
  validateV2EvaluationProgress,
  encodeV2EvaluationProgress,
  v2EvaluationInterruptedResult,
  recoverInterruptedClaimV2,
  type V2EvaluationProgress,
  type V2InterruptedClaim,
} from "./evaluation_progress_v2.js";
export { checkV2StreamSequence } from "./stream_sequence_v2.js";
export {
  ErrV2ChallengeIssuanceConflict,
  ErrV2ChallengeIssuanceNotFound,
  issueChallengeV2,
  loadExpectedChallengeV2,
  type V2ChallengeIssuanceStore,
  type V2ChallengeIssueRequest,
  type V2ChallengeIssuer,
  type V2RandomSource,
} from "./challenge_issuance_v2.js";
export {
  MAX_CHECKPOINT_ACKNOWLEDGEMENT_BYTES_V2,
  encodeV2CheckpointAcknowledgement,
  decodeV2CheckpointAcknowledgement,
  type V2CheckpointAcknowledgement,
} from "./checkpoint_ack_v2.js";
export {
  CommittedV2Outcome,
  V2ReleasedDecision,
  receiptOutboxDigestV2,
  releaseV2Decision,
  ErrV2AcknowledgementNotFound,
  ErrV2ReleaseStateMismatch,
  type V2ReceiptPublisher,
  type V2ReceiptCheckpoint,
  type V2ReleaseRecord,
  type V2TerminalClaimRecord,
  type V2ReleaseClaimStore,
  type V2ReleaseConfig,
  type V2ReleaseStatus,
  type V2ReleaseResult,
} from "./release_v2.js";
export {
  verifyProofBundleV2,
  type V2TrustOutcome,
  type V2TrustResolution,
  type V2VerifyCallbacks,
  type V2VerifyRequest,
  type V2VerifyStage,
  type V2VerifyOutcome,
  type V2VerifyOptions,
} from "./verify_v2.js";
