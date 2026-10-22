// Authenticated status at the verifier boundary (SPEC-v2 §6.5; Go
// status_provenance_v2.go).
//
// A status provider never supplies a result. For each distinct issuer in the
// verified chain, in ascending byte order of issuer ID, the verifier:
//  1. loads the committed SecurityJournalV2 at its anchored head and requires
//     the caller-authenticated status key to equal the journal's current
//     epoch binding for the issuer;
//  2. checks role separation by complete key ID and both component digests;
//  3. asks the provider for a bounded batch of signed lists and pushes;
//  4. decodes every object and verifies it under the selected key (any
//     failure rejects the whole batch);
//  5. applies the batch, sorted by sequence, then code, then
//     StatusEvidenceDigest, as one journal transition committed by
//     compare-and-swap against the head loaded in step 1; on a conflict it
//     reloads, rechecks steps 1 and 2, and reapplies the same batch exactly
//     once more;
//  6. derives each CertificateRef result from the committed journal state.
//
// Any failure makes every reference of that issuer indeterminate/unavailable
// with no evidence. These are terminal status outcomes. If the caller's
// signal is aborted during the stage, nothing is committed and the stage
// reports the cancellation.

import { V2_OBJECT_TYPE, keyIDV2 } from "./crypto_v2.js";
import { errorIs } from "./errors_v2.js";
import { compareBytes, compareStrings } from "./json_v2.js";
import { MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 } from "./limits_v2.js";
import {
  decodeRevocationListV2,
  decodeRevocationPushV2,
  statusEvidenceDigestV2,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
  type ProofBundleV2,
  type RevocationListV2,
  type RevocationPushV2,
} from "./protocol_v2_wire.js";
import {
  ErrSecurityJournalConflictV2,
  cloneSecurityJournalV2,
  commitSecurityJournalTransitionV2,
  keyRoleBindingV2,
  loadAnchoredSecurityJournalV2,
  requireJournalStatusKeyV2,
  sameRoleBinding,
  type SecurityJournalStoreV2,
  type SecurityJournalV2,
} from "./security_journal_v2.js";
import { v2StatusEvidenceBatchEncodedLength, type V2StatusEvidenceBatch } from "./status_batch_v2.js";
import { aggregateCertificateStatusV2, type V2CertificateStatusCheck, type V2StatusAssessment, type V2StatusRoleBindings } from "./status_evaluation_v2.js";
import {
  applyRevocationListV2,
  applyRevocationPushV2,
  revocationStatusForCertV2,
  type RevocationStatusPolicyV2,
  type RevocationStatusResultV2,
} from "./status_state_v2.js";
import type { HybridPublicKey } from "./types.js";

export type { V2StatusEvidenceBatch, V2StatusEvidenceObject } from "./status_batch_v2.js";

/**
 * The caller-authenticated status-key binding for one issuer. It must equal
 * the binding retained in the journal at that epoch, and the epoch must be
 * the issuer's current journal epoch.
 */
export interface V2StatusKeyConfig {
  epoch: number;
  key: HybridPublicKey;
}

/** An issuer-scoped certificate reference. A bare cert ID is never a status key. */
export interface CertificateRefV2 {
  issuer_id: string;
  cert_id: string;
}

/**
 * What the verifier asks a status provider for, chosen from authenticated
 * configuration, never from the proof. refs are the issuer's references in
 * chain order.
 */
export interface V2StatusEvidenceRequest {
  issuerID: string;
  statusKeyEpoch: number;
  statusKeyID: string;
  refs: CertificateRefV2[];
}

/** A status evidence provider. It returns evidence, never a result. */
export type V2StatusEvidenceProvider = (req: V2StatusEvidenceRequest, signal?: AbortSignal) => Promise<V2StatusEvidenceBatch> | V2StatusEvidenceBatch;

/**
 * Exactly the inputs the Go runV2StatusStage reads from V2VerifyRequest and
 * V2VerifyCallbacks: req.StatusKeys, req.StatusPolicy, cb.StatusJournal, and
 * cb.StatusEvidence. The caller context and the authoritative claim time
 * T_claim are separate runV2StatusStage arguments.
 */
export interface V2StatusStageInputs {
  statusKeys: ReadonlyMap<string, V2StatusKeyConfig> | null | undefined;
  statusPolicy: RevocationStatusPolicyV2;
  statusJournal: SecurityJournalStoreV2 | null | undefined;
  statusEvidence: V2StatusEvidenceProvider | null | undefined;
}

/** The stage outcome. cancelled is the abort reason when the signal ended the stage. */
export interface V2StatusStageResult {
  assessment: V2StatusAssessment;
  cancelled: unknown;
  /** Number of provider calls made (the "status" callback count). */
  queries: number;
}

interface VerifiedStatusObject {
  code: number;
  sequence: number;
  digest: Uint8Array;
  list: RevocationListV2 | null;
  push: RevocationPushV2 | null;
}

const LIST = V2_OBJECT_TYPE.revocationList;
const PUSH = V2_OBJECT_TYPE.revocationPush;

export function unavailableV2StatusResultValue(): RevocationStatusResultV2 {
  return { status: "indeterminate", reason: "unavailable", evidence: [], freshUntil: 0 };
}

function abortReason(signal: AbortSignal | undefined): unknown {
  if (!signal?.aborted) return null;
  return signal.reason ?? new Error("v2 status stage cancelled");
}

/** Executes the status stage for every CertificateRef check (Go runV2StatusStage). */
export async function runV2StatusStage(
  signal: AbortSignal | undefined,
  bundle: ProofBundleV2,
  checks: readonly V2CertificateStatusCheck[],
  inputs: V2StatusStageInputs,
  now: number,
): Promise<V2StatusStageResult> {
  const issuerIDs: string[] = [];
  const refsByIssuer = new Map<string, CertificateRefV2[]>();
  for (const check of checks) {
    if (!refsByIssuer.has(check.issuerID)) {
      issuerIDs.push(check.issuerID);
      refsByIssuer.set(check.issuerID, []);
    }
    refsByIssuer.get(check.issuerID)!.push({ issuer_id: check.issuerID, cert_id: check.certID });
  }
  issuerIDs.sort(compareStrings);
  const results: RevocationStatusResultV2[] = checks.map(() => unavailableV2StatusResultValue());
  const roles: V2StatusRoleBindings = { statusKeyIssuers: new Map(), currentStatusKeyIDs: new Map(), reservedKeyIDs: new Set() } as V2StatusRoleBindings;
  let queries = 0;
  const cancelled = () => abortReason(signal);
  for (const issuerID of issuerIDs) {
    if (cancelled()) return { assessment: unavailableAssessment(), cancelled: cancelled(), queries };
    const config = inputs.statusKeys?.get(issuerID);
    const journalStore = inputs.statusJournal;
    const provider = inputs.statusEvidence;
    if (!config || !journalStore || !provider) continue;
    // 1. Anchored journal and current epoch binding.
    let current: SecurityJournalV2;
    try {
      current = await loadAnchoredSecurityJournalV2(journalStore, signal);
    } catch {
      if (cancelled()) return { assessment: unavailableAssessment(), cancelled: cancelled(), queries };
      continue;
    }
    // 2. Role separation.
    try {
      checkV2StatusRoleSeparation(current, issuerID, config, bundle);
    } catch {
      continue;
    }
    const statusKeyID = keyIDV2(config.key);
    // 3. Provider.
    queries++;
    let batch: V2StatusEvidenceBatch;
    try {
      batch = await provider({
        issuerID, statusKeyEpoch: config.epoch, statusKeyID, refs: (refsByIssuer.get(issuerID) ?? []).map((r) => ({ ...r })),
      }, signal);
    } catch {
      if (cancelled()) return { assessment: unavailableAssessment(), cancelled: cancelled(), queries };
      continue;
    }
    // 4. Authenticate.
    let objects: VerifiedStatusObject[];
    try {
      objects = await verifyV2StatusEvidenceBatch(batch, issuerID, config.key);
    } catch {
      continue;
    }
    // 5. Apply as one transition against the loaded head, with one bounded
    // retry after a compare-and-swap conflict (no second provider call).
    let committed: SecurityJournalV2 | null = null;
    for (let attempt = 0; attempt < 2 && committed === null; attempt++) {
      if (attempt > 0) {
        try {
          current = await loadAnchoredSecurityJournalV2(journalStore, signal);
          checkV2StatusRoleSeparation(current, issuerID, config, bundle);
        } catch {
          break;
        }
      }
      try {
        committed = await applyV2StatusBatchToJournal(journalStore, current, issuerID, config, objects, inputs.statusPolicy, now, signal);
      } catch (err) {
        if (!errorIs(err, ErrSecurityJournalConflictV2)) break;
      }
    }
    if (cancelled()) return { assessment: unavailableAssessment(), cancelled: cancelled(), queries };
    if (committed === null) continue;
    // 6. Derive from committed state.
    for (const binding of committed.statusKeyHistory) {
      if (binding.issuerID === issuerID) roles.statusKeyIssuers!.set(binding.statusKeyID, issuerID);
    }
    roles.currentStatusKeyIDs!.set(issuerID, statusKeyID);
    for (let i = 0; i < checks.length; i++) {
      const check = checks[i]!;
      if (check.issuerID !== issuerID) continue;
      try {
        results[i] = await revocationStatusForCertV2(committed.statusByIssuer.get(issuerID)!, issuerID, check.certID, config.epoch, config.key, inputs.statusPolicy, now);
      } catch {
        results[i] = unavailableV2StatusResultValue();
      }
    }
  }
  let assessment: V2StatusAssessment;
  try {
    assessment = aggregateCertificateStatusV2(checks, results, roles, true);
  } catch {
    assessment = unavailableAssessment();
  }
  return { assessment, cancelled: null, queries };
}

function unavailableAssessment(): V2StatusAssessment {
  return { assessment: "unavailable", reason: "status_unavailable", evidence: [], freshUntil: 0 };
}

/**
 * Decodes and authenticates every object before any is applied, and returns
 * them in application order: ascending sequence, then code (list before
 * push), then evidence digest bytes.
 */
async function verifyV2StatusEvidenceBatch(batch: V2StatusEvidenceBatch, issuerID: string, key: HybridPublicKey): Promise<VerifiedStatusObject[]> {
  const objects = batch?.objects;
  if (!Array.isArray(objects)) throw new Error("v2 status batch is malformed");
  if (objects.length > MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2) throw new Error(`v2 status batch exceeds ${MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2} objects`);
  for (const o of objects) {
    if (!o || !(o.wire instanceof Uint8Array) || !Number.isInteger(o.objectType)) throw new Error("v2 status batch object is malformed");
  }
  if (v2StatusEvidenceBatchEncodedLength(batch) > MAX_STATUS_EVIDENCE_BATCH_BYTES_V2) {
    throw new Error(`v2 status batch exceeds ${MAX_STATUS_EVIDENCE_BATCH_BYTES_V2} bytes`);
  }
  const out: VerifiedStatusObject[] = [];
  for (const object of objects) {
    if (object.objectType === LIST) {
      const list = decodeRevocationListV2(object.wire);
      await verifyRevocationListV2Signature(list, issuerID, key);
      out.push({ code: LIST, sequence: list.sequence, digest: statusEvidenceDigestV2(LIST, list), list, push: null });
    } else if (object.objectType === PUSH) {
      const push = decodeRevocationPushV2(object.wire);
      await verifyRevocationPushV2Signature(push, issuerID, key);
      out.push({ code: PUSH, sequence: push.sequence, digest: statusEvidenceDigestV2(PUSH, push), list: null, push });
    } else {
      throw new Error(`v2 status batch contains unsupported object type 0x${object.objectType.toString(16).padStart(4, "0")}`);
    }
  }
  out.sort((a, b) => (a.sequence !== b.sequence ? (a.sequence < b.sequence ? -1 : 1) : a.code !== b.code ? (a.code < b.code ? -1 : 1) : compareBytes(a.digest, b.digest)));
  return out;
}

async function applyV2StatusBatchToJournal(
  store: SecurityJournalStoreV2, current: SecurityJournalV2, issuerID: string, config: V2StatusKeyConfig,
  objects: readonly VerifiedStatusObject[], policy: RevocationStatusPolicyV2, now: number, signal?: AbortSignal,
): Promise<SecurityJournalV2> {
  const next = cloneSecurityJournalV2(current);
  let state = next.statusByIssuer.get(issuerID)!;
  for (const object of objects) {
    state = object.list !== null
      ? await applyRevocationListV2(state, object.list, issuerID, config.epoch, config.key, policy, now)
      : await applyRevocationPushV2(state, object.push!, issuerID, config.epoch, config.key, policy, now);
  }
  next.statusByIssuer.set(issuerID, state);
  return commitSecurityJournalTransitionV2(store, current, next, signal);
}

/**
 * SPEC-v2 §5.4 and §6.5 permanent role separation: the configured status key
 * must be the issuer's current journal epoch binding with exactly the status
 * role, and neither its key ID nor either component may equal any other
 * journal role's; no proof key (agent, every issuer and subject) may share
 * an ID or component with any current or retired status binding; and the
 * status key may not equal the proof's verifier ID.
 */
export function checkV2StatusRoleSeparation(journal: SecurityJournalV2, issuerID: string, config: V2StatusKeyConfig, bundle: ProofBundleV2): void {
  requireJournalStatusKeyV2(journal, issuerID, config.epoch, config.key);
  const status = keyRoleBindingV2("status", config.key);
  let recorded = false;
  const components = [status.ed25519Digest, status.mlDsa65Digest];
  for (const binding of journal.keyRoleHistory) {
    if (sameRoleBinding(binding, status)) {
      recorded = true;
      continue;
    }
    if (binding.keyID === status.keyID || components.includes(binding.ed25519Digest) || components.includes(binding.mlDsa65Digest)) {
      throw new Error(`status key shares a key ID or component with journal role "${binding.role}"`);
    }
  }
  if (!recorded) throw new Error("status key lacks its permanent status role in the journal");
  const keys: HybridPublicKey[] = [bundle.agent_pub_key];
  for (const cert of bundle.delegations ?? []) keys.push(cert.issuer_pub_key, cert.subject_pub_key);
  for (const key of keys) {
    const chainKey = keyRoleBindingV2("other", key);
    for (const binding of journal.keyRoleHistory) {
      if (binding.role !== "status") continue;
      const bc = [binding.ed25519Digest, binding.mlDsa65Digest];
      if (chainKey.keyID === binding.keyID || bc.includes(chainKey.ed25519Digest) || bc.includes(chainKey.mlDsa65Digest)) {
        throw new Error("a proof key shares a key ID or component with a status key");
      }
    }
  }
  if (status.keyID === bundle.verifier_id) throw new Error("status key equals the verifier identity");
}
