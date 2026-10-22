// SPEC-v2 §2.7: every error returned by a public v2 API carries exactly one
// class from the closed list, never "unclassified". Each public entry point
// is called with an input it must reject, mirroring the reference SDK's
// table of 117 entry points; where the specification fixes the class it is
// asserted exactly, so this SDK reports the same class for the same input.

import { test } from "node:test";
import assert from "node:assert/strict";

import { V2_ERROR_CLASSES, v2ErrorClassOf, type V2ErrorClass } from "../../src/errors_v2.js";
import { hybridKeypairFromSeeds } from "../../src/crypto.js";
import type { HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { SIGNER_MODE_DIRECT_V2, keyIDV2, newLocalSignerV2, type SignerV2 } from "../../src/signer_v2.js";
import type { HybridPublicKey } from "../../src/types.js";
import {
  bundleHashV2,
  decodeDelegationCertV2,
  decodeProofBundleV2,
  decodeRevocationListV2,
  decodeRevocationPushV2,
  encodeDelegationCertV2,
  encodeProofBundleV2,
  encodeRevocationListV2,
  encodeRevocationPushV2,
  signDelegationCertV2,
  signDelegationCertV2WithSigner,
  signProofBundleV2,
  signRevocationListV2,
  signRevocationListV2WithSigner,
  signRevocationPushV2,
  statusEvidenceDigestV2,
  verifyDelegationCertV2Signature,
  verifyProofBundleV2Signatures,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
  type DelegationCertV2,
  type ProofBundleV2,
  type RevocationListV2,
  type RevocationPushV2,
} from "../../src/protocol_v2_wire.js";
import {
  acceptKeyRotationStatementV2,
  decodeKeyRotationStatementV2,
  encodeKeyRotationStatementV2,
  keyRotationStatementV2Digest,
  newKeyRotationV2Journal,
  recoverKeyRotationV2,
  signKeyRotationStatementV2,
  statementBodyDigestV2,
  verifyKeyRotationStatementV2,
  type KeyRotationStatementV2,
  type KeyRotationV2Journal,
  type KeyRotationV2State,
} from "../../src/key_rotation_v2.js";
import {
  decodeWitnessEntryV2,
  encodeWitnessEntryV2,
  signWitnessEntryV2,
  verifyWitnessEntryV2,
  witnessEntryV2Digest,
  type WitnessEntryV2,
  type WitnessV2Head,
} from "../../src/witness_v2.js";
import {
  bindVerificationReceiptBodyV2,
  checkVerificationReceiptV2BundleBinding,
  decodeVerificationReceiptBodyV2,
  decodeVerificationReceiptV2,
  encodeVerificationReceiptV2,
  signPreparedVerificationReceiptV2,
  signVerificationReceiptV2,
  verificationReceiptV2Body,
  verificationReceiptV2Digest,
  verifyVerificationReceiptV2,
  type ReceiptV2Head,
  type VerificationReceiptV2,
} from "../../src/verification_receipt_v2.js";
import {
  decodeTransactionReceiptV2,
  encodeTransactionReceiptV2,
  signTransactionReceiptPartyV2,
  transactionReceiptV2SignBytes,
  verifyTransactionReceiptV2Signatures,
  type TransactionReceiptV2,
} from "../../src/transaction_receipt_v2.js";
import { verifyTransactionReceiptV2 } from "../../src/transaction_verify_v2.js";
import {
  verifyArchivalDelegationCertV2,
  verifyArchivalKeyRotationStatementV2,
  verifyArchivalRevocationListV2,
  verifyArchivalRevocationPushV2,
  verifyArchivalTransactionReceiptV2,
  verifyArchivalVerificationReceiptV2,
  verifyArchivalWitnessEntryV2,
} from "../../src/archival_v2.js";
import { decodeV2CheckpointAcknowledgement, encodeV2CheckpointAcknowledgement } from "../../src/checkpoint_ack_v2.js";
import { decodeV2StatusEvidenceBatch, encodeV2StatusEvidenceBatch } from "../../src/status_batch_v2.js";
import { encodeConstraintV2 } from "../../src/constraints_v2.js";
import { challengeClaimDigestV2, protocolClaimIDFromDigestV2, protocolClaimIDV2 } from "../../src/challenge_claim_v2.js";
import { buildSessionContextV2, operationContextV2Hash } from "../../src/operation_context_v2.js";
import { buildV2RateReservationBatch, evaluateReceiverAudienceV2 } from "../../src/audience_v2.js";
import {
  applyRevocationListV2,
  applyRevocationPushV2,
  emptyRevocationStatusStateV2,
  revocationStatusForCertV2,
  transitionRevocationStatusEpochV2,
  type RevocationStatusPolicyV2,
  type RevocationStatusStateV2,
} from "../../src/status_state_v2.js";
import {
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  configureStatusKeyEpochV2,
  emptySecurityJournalV2,
  recordSecurityKeyRoleV2,
  registerKeyRoleV2,
  registerStatusKeyEpochV2,
  revocationStatusFromJournalV2,
  validateSecurityJournalTransitionV2,
  validateSecurityJournalV2,
  type SecurityJournalStoreV2,
  type SecurityJournalV2,
} from "../../src/security_journal_v2.js";
import {
  exportSecurityJournalSnapshotV2,
  importSecurityJournalSnapshotV2,
  migrateSecurityJournalV2,
} from "../../src/security_journal_snapshot_v2.js";
import { V2StatusPublisher, newV2StatusPublisher } from "../../src/status_publisher_v2.js";
import { newV2ContextPolicy } from "../../src/context_policy_v2.js";
import { constraintProfileDigestV2, newConstraintEvaluatorRegistryV2 } from "../../src/constraint_evaluator_v2.js";
import { preflightProofBundleV2, validateProofBundleV2Preflight } from "../../src/verify_v2_preflight.js";
import { claimProofBundleV2, finalizeClaimProofBundleV2 } from "../../src/claim_store_v2.js";
import { resolveClaimProofBundleV2AfterAudience, resolveClaimProofBundleV2AfterRate } from "../../src/authorization_v2.js";
import { recoverInterruptedClaimV2, v2EvaluationInterruptedResult, validateV2EvaluationProgress } from "../../src/evaluation_progress_v2.js";
import { issueChallengeV2, loadExpectedChallengeV2 } from "../../src/challenge_issuance_v2.js";
import { checkV2StreamSequence } from "../../src/stream_sequence_v2.js";
import { V2ReleasedDecision } from "../../src/release_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";

type Any = any; // eslint-disable-line @typescript-eslint/no-explicit-any

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const empty = (): Uint8Array => new Uint8Array(0);
const zeroKey = (): HybridPublicKey => ({ ed25519: empty(), ml_dsa_65: empty() });

// Go zero values of each structure.
const zeroCert = (): DelegationCertV2 => ({
  version: 0, cert_id: "", issuer_id: "", issuer_pub_key: zeroKey(), subject_id: "", subject_pub_key: zeroKey(),
  scope: null, constraints: null, issued_at: 0, expires_at: 0, signature: zeroKey(),
});
const zeroBundle = (): ProofBundleV2 => ({
  version: 0, verifier_id: "", agent_id: "", agent_pub_key: zeroKey(), delegations: null, delegation_digest: empty(),
  challenge: empty(), challenge_at: 0, challenge_sig: zeroKey(), session_context: null, stream_id: null, stream_seq: null,
});
const zeroList = (): RevocationListV2 => ({ version: 0, issuer_id: "", updated_at: 0, next_update: 0, sequence: 0, revoked: null, signature: zeroKey() });
const zeroPush = (): RevocationPushV2 => ({ version: 0, issuer_id: "", sequence: 0, pushed_at: 0, revoked: null, signature: zeroKey() });
const zeroRotation = (): KeyRotationStatementV2 => ({
  version: 0, authority_id: "", recovery_epoch: 0, role: "", sequence: 0, previous_statement_hash: empty(),
  old_key: zeroKey(), new_key: zeroKey(), old_key_id: "", new_key_id: "", issued_at: 0, not_before: 0,
  old_signature: zeroKey(), new_signature: zeroKey(),
});
const zeroWitness = (): WitnessEntryV2 => ({ version: 0, log_id: "", sequence: 0, prev_hash: empty(), entry_data: null, timestamp: 0, witness_id: "", signature: zeroKey() });
const zeroReceipt = (): VerificationReceiptV2 => ({
  version: 0, log_id: "", sequence: 0, verifier_id: "", agent_id: "", human_id: "", bundle_hash: "", issuer_ids: null,
  decision: "", decision_reason: "", identity_status: "", trust_assessment: "", status_assessment: "",
  challenge_assessment: "", context_assessment: "", context_policy_digest: null, verified_at: 0, required_scope: "",
  granted_scope: null, status_evidence_digests: null, previous_receipt_hash: empty(), signature: zeroKey(),
}) as VerificationReceiptV2;
const zeroTransaction = (): TransactionReceiptV2 => ({
  version: 0, transaction_id: "", created_at: 0, terms_schema_uri: "", terms_canonical_json: empty(), parties: [], party_signatures: [],
});
const zeroWitnessHead = (): WitnessV2Head => ({ logID: "", sequence: 0, headHash: empty(), acceptedDigests: new Map(), frozen: false });
const zeroReceiptHead = (): ReceiptV2Head => ({ ...zeroWitnessHead(), verifierID: "" });
const zeroRotationState = (): KeyRotationV2State => ({ authorityID: "", recoveryEpoch: 0, role: "", sequence: 0, headHash: empty(), currentKey: zeroKey(), usedKeyIDs: [] });
const zeroRotationJournal = (): KeyRotationV2Journal => ({ state: zeroRotationState(), accepted: [], frozen: false });
const zeroJournal = (): SecurityJournalV2 => ({
  version: 0, generation: 0, previousDigest: "", digest: "", statusByIssuer: new Map(), keyRoleHistory: [], statusKeyHistory: [],
});

/** Fails every load and commit. */
const failingJournalStore: SecurityJournalStoreV2 = {
  load: async () => { throw new Error("journal backend down"); },
  compareAndSwap: async () => { throw new Error("journal backend down"); },
};

/** Reports a key and then fails every signing request. */
function failingSigner(pub: HybridPublicKey): SignerV2 {
  return {
    publicKeyV2: () => pub,
    modeV2: () => SIGNER_MODE_DIRECT_V2,
    signV2: async () => { throw new Error("hardware signer unavailable"); },
  } as SignerV2;
}

async function keyPair(seed: number): Promise<HybridKeyPairV2> {
  const { publicKey, privateKey } = await hybridKeypairFromSeeds(new Uint8Array(32).fill(seed), new Uint8Array(32).fill(seed + 1));
  return { publicKey, privateKey };
}

interface Call {
  name: string;
  /** "" accepts any listed class. */
  want: V2ErrorClass | "";
  run: () => unknown;
}

test("public v2 API: every rejected input carries exactly one listed class", async (t) => {
  const listed = new Set<string>(V2_ERROR_CLASSES);
  assert.equal(listed.size, 49);
  const pair = await keyPair(1);
  const other = await keyPair(3);
  const pub = pair.publicKey;
  const keyID = keyIDV2(pub);
  const cancelled = new AbortController();
  cancelled.abort();
  const garbage = enc('{"version":2}');
  const badKey: HybridPublicKey = { ed25519: new Uint8Array(3), ml_dsa_65: empty() };
  const policy: RevocationStatusPolicyV2 = { maxListLifetimeSeconds: 3600, maxStatusAgeSeconds: 3600, clockSkewSeconds: 5 };
  const list = (): RevocationListV2 => ({ ...zeroList(), version: 2, issuer_id: keyID, updated_at: 100, next_update: 200, sequence: 1, revoked: [] });
  const push = (): RevocationPushV2 => ({ ...zeroPush(), version: 2, issuer_id: keyID, sequence: 1, pushed_at: 100, revoked: [{ cert_id: "c1" }] });
  const state = (): RevocationStatusStateV2 => ({ ...emptyRevocationStatusStateV2(), issuerID: keyID, statusKeyEpoch: 1, statusKeyID: keyID });
  const nil = null as Any;

  const calls: Call[] = [
    // Decoders and archival verification.
    { name: "decodeDelegationCertV2", want: "malformed", run: () => decodeDelegationCertV2(garbage) },
    { name: "decodeProofBundleV2", want: "malformed", run: () => decodeProofBundleV2(garbage) },
    { name: "decodeRevocationListV2", want: "malformed", run: () => decodeRevocationListV2(garbage) },
    { name: "decodeRevocationPushV2", want: "malformed", run: () => decodeRevocationPushV2(garbage) },
    { name: "decodeKeyRotationStatementV2", want: "malformed", run: () => decodeKeyRotationStatementV2(garbage) },
    { name: "decodeWitnessEntryV2", want: "malformed", run: () => decodeWitnessEntryV2(garbage) },
    { name: "decodeTransactionReceiptV2", want: "malformed", run: () => decodeTransactionReceiptV2(garbage) },
    { name: "decodeVerificationReceiptV2", want: "malformed", run: () => decodeVerificationReceiptV2(garbage) },
    { name: "decodeVerificationReceiptBodyV2", want: "malformed", run: () => decodeVerificationReceiptBodyV2(garbage) },
    { name: "decodeV2CheckpointAcknowledgement", want: "malformed", run: () => decodeV2CheckpointAcknowledgement(garbage) },
    { name: "decodeV2StatusEvidenceBatch", want: "malformed", run: () => decodeV2StatusEvidenceBatch(garbage) },
    { name: "importSecurityJournalSnapshotV2", want: "malformed", run: () => importSecurityJournalSnapshotV2(garbage, { generation: 0, digest: "" }) },
    { name: "decodeDelegationCertV2 incomplete constraint", want: "malformed", run: () => decodeDelegationCertV2(enc('{"constraints":[{"type":"time_window"}]}')) },
    { name: "encodeConstraintV2", want: "malformed", run: () => encodeConstraintV2({ type: "time_window" }) },
    { name: "verifyArchivalDelegationCertV2", want: "malformed", run: () => verifyArchivalDelegationCertV2(garbage) },
    { name: "verifyArchivalRevocationListV2", want: "malformed", run: () => verifyArchivalRevocationListV2(garbage, keyID, pub) },
    { name: "verifyArchivalRevocationPushV2", want: "malformed", run: () => verifyArchivalRevocationPushV2(garbage, keyID, pub) },
    { name: "verifyArchivalKeyRotationStatementV2", want: "malformed", run: () => verifyArchivalKeyRotationStatementV2(garbage) },
    { name: "verifyArchivalWitnessEntryV2", want: "malformed", run: () => verifyArchivalWitnessEntryV2(garbage, pub) },
    { name: "verifyArchivalVerificationReceiptV2", want: "malformed", run: () => verifyArchivalVerificationReceiptV2(garbage, pub) },
    { name: "verifyArchivalTransactionReceiptV2", want: "malformed", run: () => verifyArchivalTransactionReceiptV2(garbage) },

    // Encoders, digests and identifiers.
    { name: "keyIDV2", want: "malformed", run: () => keyIDV2(badKey) },
    { name: "bundleHashV2", want: "malformed", run: () => bundleHashV2(zeroBundle()) },
    { name: "encodeDelegationCertV2", want: "malformed", run: () => encodeDelegationCertV2(zeroCert()) },
    { name: "encodeProofBundleV2", want: "malformed", run: () => encodeProofBundleV2(zeroBundle()) },
    { name: "encodeRevocationListV2", want: "malformed", run: () => encodeRevocationListV2(zeroList()) },
    { name: "encodeRevocationPushV2", want: "malformed", run: () => encodeRevocationPushV2(zeroPush()) },
    { name: "encodeKeyRotationStatementV2", want: "malformed", run: () => encodeKeyRotationStatementV2(zeroRotation()) },
    { name: "encodeWitnessEntryV2", want: "malformed", run: () => encodeWitnessEntryV2(zeroWitness()) },
    { name: "encodeTransactionReceiptV2", want: "", run: () => encodeTransactionReceiptV2(zeroTransaction()) },
    { name: "encodeVerificationReceiptV2", want: "malformed", run: () => encodeVerificationReceiptV2(zeroReceipt()) },
    { name: "encodeV2CheckpointAcknowledgement", want: "malformed", run: () => encodeV2CheckpointAcknowledgement({ logID: "", sequence: 0, entryHash: empty(), timestamp: 0 }) },
    { name: "encodeV2StatusEvidenceBatch", want: "malformed", run: () => encodeV2StatusEvidenceBatch({ objects: [{ objectType: 9, wire: empty() }] }) },
    { name: "verificationReceiptV2Body", want: "malformed", run: () => verificationReceiptV2Body(zeroReceipt()) },
    { name: "verificationReceiptV2Digest", want: "malformed", run: () => verificationReceiptV2Digest(zeroReceipt()) },
    { name: "witnessEntryV2Digest", want: "malformed", run: () => witnessEntryV2Digest(zeroWitness()) },
    { name: "keyRotationStatementV2Digest", want: "malformed", run: () => keyRotationStatementV2Digest(zeroRotation()) },
    { name: "transactionReceiptV2SignBytes", want: "malformed", run: () => transactionReceiptV2SignBytes(zeroTransaction()) },
    { name: "statementBodyDigestV2 unregistered code", want: "unsupported_object_type", run: () => statementBodyDigestV2(0x0001, enc("{}")) },
    { name: "statementBodyDigestV2 bad body", want: "malformed", run: () => statementBodyDigestV2(0x0006, enc("{}")) },
    { name: "statusEvidenceDigestV2 unregistered code", want: "unsupported_object_type", run: () => statusEvidenceDigestV2(0x0001, list()) },
    { name: "statusEvidenceDigestV2 wrong value", want: "malformed", run: () => statusEvidenceDigestV2(0x0003, push()) },
    { name: "challengeClaimDigestV2", want: "malformed", run: () => challengeClaimDigestV2(enc("short")) },
    { name: "protocolClaimIDV2 namespace", want: "configuration_invalid", run: () => protocolClaimIDV2("", 0, new Uint8Array(32)) },
    { name: "protocolClaimIDV2 challenge", want: "malformed", run: () => protocolClaimIDV2("ns", 0, enc("short")) },
    { name: "protocolClaimIDFromDigestV2", want: "malformed", run: () => protocolClaimIDFromDigestV2("ns", 0, enc("short")) },
    { name: "operationContextV2Hash", want: "", run: () => operationContextV2Hash({ required_scope: "" }) },
    {
      name: "buildSessionContextV2", want: "configuration_invalid",
      run: () => buildSessionContextV2({ verifier_id: "", workspace_id: "", agent_id: "", session_id: "", invocation_id: "", request_hash: empty() }),
    },
    {
      name: "buildV2RateReservationBatch", want: "malformed",
      run: () => buildV2RateReservationBatch([{ delegationIndex: 0, constraintIndex: 0, issuerID: "", certID: "", type: "max_rate", canonicalJSON: garbage }]),
    },

    // Signing.
    { name: "newLocalSignerV2", want: "configuration_invalid", run: () => newLocalSignerV2({ publicKey: zeroKey(), privateKey: { ed25519: empty(), ml_dsa_65: empty() } }) },
    { name: "signDelegationCertV2", want: "malformed", run: () => signDelegationCertV2(zeroCert(), pair) },
    { name: "signDelegationCertV2WithSigner failing signer", want: "", run: () => signDelegationCertV2WithSigner(zeroCert(), failingSigner(pub)) },
    { name: "signProofBundleV2 agent key binding", want: "key_id_mismatch", run: () => signProofBundleV2(zeroBundle(), pair) },
    { name: "signProofBundleV2", want: "malformed", run: () => signProofBundleV2({ ...zeroBundle(), agent_id: keyID, agent_pub_key: pub }, pair) },
    { name: "signRevocationListV2 issuer binding", want: "status_key_binding_mismatch", run: () => signRevocationListV2(list(), "other", pub, pair) },
    { name: "signRevocationListV2 status key binding", want: "status_key_binding_mismatch", run: () => signRevocationListV2(list(), keyID, other.publicKey, pair) },
    { name: "signRevocationListV2WithSigner failing signer", want: "configuration_invalid", run: () => signRevocationListV2WithSigner(list(), keyID, pub, failingSigner(pub)) },
    {
      name: "signRevocationListV2WithSigner cancelled", want: "evaluation_cancelled",
      run: () => signRevocationListV2WithSigner(list(), keyID, pub, failingSigner(pub), { signal: cancelled.signal }),
    },
    { name: "signRevocationPushV2 issuer binding", want: "status_key_binding_mismatch", run: () => signRevocationPushV2(push(), "other", pub, pair) },
    { name: "signKeyRotationStatementV2", want: "malformed", run: () => signKeyRotationStatementV2(zeroRotation(), pair, pair) },
    { name: "signWitnessEntryV2", want: "malformed", run: () => signWitnessEntryV2(zeroWitness(), pair) },
    { name: "signVerificationReceiptV2", want: "malformed", run: () => signVerificationReceiptV2(zeroReceipt(), pair) },
    { name: "signPreparedVerificationReceiptV2", want: "configuration_invalid", run: () => signPreparedVerificationReceiptV2(garbage, zeroReceiptHead(), pair) },
    { name: "bindVerificationReceiptBodyV2", want: "configuration_invalid", run: () => bindVerificationReceiptBodyV2(garbage, zeroReceiptHead()) },
    { name: "signTransactionReceiptPartyV2", want: "", run: () => signTransactionReceiptPartyV2(zeroTransaction(), "p", pair) },

    // Signature and object verification.
    { name: "verifyDelegationCertV2Signature", want: "malformed", run: () => verifyDelegationCertV2Signature(zeroCert()) },
    { name: "verifyProofBundleV2Signatures", want: "malformed", run: () => verifyProofBundleV2Signatures(zeroBundle()) },
    { name: "verifyRevocationListV2Signature", want: "malformed", run: () => verifyRevocationListV2Signature(zeroList(), keyID, pub) },
    { name: "verifyRevocationPushV2Signature", want: "status_key_binding_mismatch", run: () => verifyRevocationPushV2Signature(push(), "other", pub) },
    { name: "verifyKeyRotationStatementV2", want: "", run: () => verifyKeyRotationStatementV2(zeroRotation(), zeroRotationState(), 0, 0) },
    { name: "verifyWitnessEntryV2", want: "malformed", run: () => verifyWitnessEntryV2(zeroWitness(), zeroWitnessHead(), pub) },
    { name: "verifyVerificationReceiptV2", want: "malformed", run: () => verifyVerificationReceiptV2(zeroReceipt(), pub, zeroReceiptHead()) },
    { name: "verifyTransactionReceiptV2Signatures", want: "", run: () => verifyTransactionReceiptV2Signatures(zeroTransaction()) },
    { name: "checkVerificationReceiptV2BundleBinding", want: "", run: () => checkVerificationReceiptV2BundleBinding(zeroReceipt(), zeroBundle()) },

    // Key rotation journal.
    { name: "newKeyRotationV2Journal", want: "", run: () => newKeyRotationV2Journal("", -1, "", badKey) },
    {
      name: "acceptKeyRotationStatementV2", want: "",
      run: async () => {
        const outcome = await acceptKeyRotationStatementV2(zeroRotation(), zeroRotationJournal(), 0, 0);
        if (outcome.error) throw outcome.error;
      },
    },
    { name: "recoverKeyRotationV2", want: "", run: () => recoverKeyRotationV2(zeroRotationJournal(), 0, badKey) },

    // Status reducer and SecurityJournalV2 operations (§5.4, §6.6).
    { name: "transitionRevocationStatusEpochV2", want: "status_object_rejected", run: () => transitionRevocationStatusEpochV2(state(), keyID, 3, other.publicKey) },
    { name: "transitionRevocationStatusEpochV2 reused key", want: "status_object_rejected", run: () => transitionRevocationStatusEpochV2(state(), keyID, 2, pub) },
    { name: "applyRevocationListV2 unsigned", want: "invalid_signature", run: () => applyRevocationListV2(state(), list(), keyID, 1, pub, policy, 150) },
    { name: "applyRevocationPushV2 unsigned", want: "invalid_signature", run: () => applyRevocationPushV2(state(), push(), keyID, 1, pub, policy, 150) },
    { name: "revocationStatusForCertV2", want: "", run: () => revocationStatusForCertV2(state(), keyID, "", 1, pub, policy, 150) },
    { name: "recordSecurityKeyRoleV2", want: "status_object_rejected", run: () => recordSecurityKeyRoleV2(failingJournalStore, "verifier", pub) },
    { name: "recordSecurityKeyRoleV2 status role", want: "status_object_rejected", run: () => recordSecurityKeyRoleV2(nil, "status", pub) },
    { name: "configureStatusKeyEpochV2", want: "status_object_rejected", run: () => configureStatusKeyEpochV2(failingJournalStore, keyID, 1, pub) },
    {
      name: "applyRevocationListToJournalV2", want: "status_object_rejected",
      run: () => applyRevocationListToJournalV2(failingJournalStore, list(), keyID, 1, pub, policy, 150),
    },
    { name: "applyRevocationPushToJournalV2", want: "status_object_rejected", run: () => applyRevocationPushToJournalV2(nil, push(), keyID, 1, pub, policy, 150) },
    {
      name: "revocationStatusFromJournalV2", want: "status_object_rejected",
      run: () => revocationStatusFromJournalV2(failingJournalStore, keyID, "c1", 1, pub, policy, 150),
    },
    { name: "registerKeyRoleV2", want: "status_object_rejected", run: () => registerKeyRoleV2(emptySecurityJournalV2(), "nonsense", pub) },
    { name: "registerStatusKeyEpochV2", want: "status_object_rejected", run: () => registerStatusKeyEpochV2(emptySecurityJournalV2(), keyID, 0, pub) },
    { name: "validateSecurityJournalV2", want: "malformed", run: () => validateSecurityJournalV2(zeroJournal()) },
    { name: "validateSecurityJournalTransitionV2", want: "", run: () => validateSecurityJournalTransitionV2(emptySecurityJournalV2(), zeroJournal()) },
    { name: "exportSecurityJournalSnapshotV2", want: "configuration_invalid", run: () => exportSecurityJournalSnapshotV2(zeroJournal()) },
    { name: "migrateSecurityJournalV2", want: "configuration_invalid", run: () => migrateSecurityJournalV2(zeroJournal()) },
    { name: "newV2StatusPublisher", want: "configuration_invalid", run: () => newV2StatusPublisher(nil, pub, nil, 0) },
    {
      name: "V2StatusPublisher.heartbeat", want: "configuration_invalid",
      run: () => (Object.create(V2StatusPublisher.prototype) as V2StatusPublisher).heartbeat({ issuerID: "", statusKeyID: "", sequence: 0, updatedAt: 0, revoked: [] }, 1),
    },
    {
      name: "V2StatusPublisher.revoke", want: "configuration_invalid",
      run: () => (Object.create(V2StatusPublisher.prototype) as V2StatusPublisher).revoke({ issuerID: "", statusKeyID: "", sequence: 0, updatedAt: 0, revoked: [] }, nil, 1),
    },
    { name: "V2StatusPublisher.genesis", want: "configuration_invalid", run: () => (Object.create(V2StatusPublisher.prototype) as V2StatusPublisher).genesis(-1) },

    // Verifier configuration, preflight, claim and evaluation (§6, §7).
    { name: "newV2ContextPolicy", want: "configuration_invalid", run: () => newV2ContextPolicy("", true, null, null) },
    { name: "newConstraintEvaluatorRegistryV2", want: "configuration_invalid", run: () => newConstraintEvaluatorRegistryV2(-1000) },
    { name: "constraintProfileDigestV2", want: "configuration_invalid", run: () => constraintProfileDigestV2({ profile: "", type: "" }) },
    { name: "evaluateReceiverAudienceV2", want: "configuration_invalid", run: () => evaluateReceiverAudienceV2(nil, "", null, -1, 0) },
    { name: "preflightProofBundleV2", want: "", run: () => preflightProofBundleV2(zeroBundle(), null, null, "data:read", "ns", 0, 0, 0, 0) },
    {
      name: "validateProofBundleV2Preflight", want: "",
      run: () => validateProofBundleV2Preflight(zeroBundle(), { value: empty(), issuedAt: 0, expiresAt: 0, verifierNamespace: "", replayEpoch: 0, verifierID: "" }, "data:read", "ns", 0, 0, 0, 0),
    },
    { name: "claimProofBundleV2", want: "configuration_invalid", run: () => claimProofBundleV2(nil, zeroBundle(), nil, "ns", 0, 0) },
    { name: "finalizeClaimProofBundleV2", want: "configuration_invalid", run: () => finalizeClaimProofBundleV2(nil, nil, nil, nil) },
    { name: "resolveClaimProofBundleV2AfterAudience", want: "configuration_invalid", run: () => resolveClaimProofBundleV2AfterAudience(nil, null) },
    { name: "resolveClaimProofBundleV2AfterRate", want: "configuration_invalid", run: () => resolveClaimProofBundleV2AfterRate(nil, nil) },
    {
      name: "validateV2EvaluationProgress", want: "malformed",
      run: () => validateV2EvaluationProgress({ trustAssessment: "", statusAssessment: "", contextAssessment: "", contextPolicyDigest: null, statusEvidence: [] }),
    },
    {
      name: "v2EvaluationInterruptedResult", want: "configuration_invalid",
      run: () => v2EvaluationInterruptedResult({} as Any, -1, { trustAssessment: "", statusAssessment: "", contextAssessment: "", contextPolicyDigest: null, statusEvidence: [] }),
    },
    { name: "recoverInterruptedClaimV2", want: "configuration_invalid", run: () => recoverInterruptedClaimV2(nil, "") },
    { name: "issueChallengeV2", want: "configuration_invalid", run: () => issueChallengeV2({} as Any, {} as Any) },
    { name: "loadExpectedChallengeV2", want: "configuration_invalid", run: () => loadExpectedChallengeV2(nil, "ns", 0, nil) },
    { name: "checkV2StreamSequence", want: "stream_sequence_mismatch", run: () => checkV2StreamSequence(true, 5, 5) },
    { name: "V2ReleasedDecision.receipt", want: "configuration_invalid", run: () => (Object.create(V2ReleasedDecision.prototype) as V2ReleasedDecision).receipt() },
    {
      name: "verifyTransactionReceiptV2", want: "configuration_invalid",
      run: () => verifyTransactionReceiptV2({ receipt: nil, now: -1, futureSkewSeconds: 0 }, {} as Any),
    },
  ];

  // The reference table has 117 entries: the 116 calls above (Go's
  // DecodePayloadDigest has no counterpart here; its ConstraintV2 JSON
  // unmarshalling is reached through decodeDelegationCertV2) and the live
  // verifier below.
  assert.equal(calls.length, 116);
  assert.equal(new Set(calls.map((c) => c.name)).size, calls.length, "duplicate entry point name");

  for (const c of calls) {
    await t.test(c.name, async () => {
      let thrown: unknown = undefined;
      try {
        await c.run();
      } catch (err) {
        thrown = err ?? new Error("null thrown");
      }
      assert.ok(thrown !== undefined, "bad input was accepted");
      const cls = v2ErrorClassOf(thrown);
      assert.ok(listed.has(cls), `class ${JSON.stringify(cls)} is not in the SPEC-v2 §2.7 list: ${(thrown as Error)?.message}`);
      if (c.want !== "") assert.equal(cls, c.want, (thrown as Error)?.message);
    });
  }

  await t.test("verifyProofBundleV2 without a claim store", async () => {
    const outcome = await verifyProofBundleV2({
      bundle: garbage, expected: null, contextPolicy: null, requiredScope: "", verifierNamespace: "", replayEpoch: 0, now: 0,
      maxChallengeAgeSeconds: 0, futureSkewSeconds: 0, statusPolicy: policy,
    }, { claimStore: nil });
    assert.equal(outcome.stage, "preflight");
    assert.equal(outcome.errorClass, "configuration_invalid");
  });
});
