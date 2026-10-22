// SecurityJournalV2 (SPEC-v2 §5.4, §6.6, §7.10; Go security_journal_v2.go):
// the verifier deployment's rollback-protected status, role, and status-key
// state. Durability and anti-rollback guarantees come from the store; a
// valid digest chain is not rollback protection.

import { sha384 } from "@noble/hashes/sha2";

import { keyIDV2 } from "./crypto_v2.js";
import { V2SentinelError, errorIs, wrapError } from "./errors_v2.js";
import { MAX_SAFE_INTEGER_V2, compareStrings, hexOf } from "./json_v2.js";
import type { RevocationListV2, RevocationPushV2 } from "./protocol_v2_wire.js";
import {
  SECURITY_JOURNAL_LEGACY_VERSION_V2,
  canonicalizeSecurityJournalV2,
  sameSecurityJournalContentV2,
  securityJournalDigestV2,
} from "./security_journal_snapshot_v2.js";
import {
  applyRevocationListV2,
  applyRevocationPushV2,
  cloneRevocationStatusStateV2,
  compactRevocationStatusObservationsV2,
  containsAllStringSetV2,
  emptyRevocationStatusStateV2,
  equalStringSetsV2,
  mustRetainStatusObservationV2,
  revocationStatusForCertV2,
  securityObservationSemanticKeyV2,
  transitionRevocationStatusEpochV2,
  validateAcceptedStatusStateV2,
  validateStatusStateBindingV2,
  type RevocationObservationV2,
  type RevocationStatusPolicyV2,
  type RevocationStatusResultV2,
  type RevocationStatusStateV2,
} from "./status_state_v2.js";
import type { HybridPublicKey } from "./types.js";

/** The current record version: canonical snapshot digest. */
export const SECURITY_JOURNAL_VERSION_V2 = 2;

/** The independently anchored head of a deployment's security journal. */
export interface SecurityJournalHeadV2 {
  generation: number;
  digest: string;
}

/** Permanently assigns a key ID and both components to one role. */
export interface KeyRoleBindingV2 {
  keyID: string;
  ed25519Digest: string;
  mlDsa65Digest: string;
  role: string;
}

/** One authenticated status-key epoch of one issuer, retained forever. */
export interface StatusKeyBindingV2 {
  issuerID: string;
  epoch: number;
  statusKeyID: string;
  ed25519Digest: string;
  mlDsa65Digest: string;
}

/** The logical journal record. */
export interface SecurityJournalV2 {
  version: number;
  generation: number;
  /** "" at genesis (the snapshot encodes it as 96 zeros). */
  previousDigest: string;
  digest: string;
  statusByIssuer: Map<string, RevocationStatusStateV2>;
  keyRoleHistory: KeyRoleBindingV2[];
  statusKeyHistory: StatusKeyBindingV2[];
}

/** The result of loading a journal: the record and the anchored head it was read against. */
export interface SecurityJournalLoadV2 {
  journal: SecurityJournalV2;
  head: SecurityJournalHeadV2;
}

/**
 * An atomic compare-and-swap store backed by an independent,
 * rollback-resistant head (SPEC-v2 §7.10). load must return the record
 * matching that head or fail closed; compareAndSwap must atomically advance
 * the record and its head and reject a writer whose expected head is not
 * current by throwing ErrSecurityJournalConflictV2.
 */
export interface SecurityJournalStoreV2 {
  load(signal?: AbortSignal): Promise<SecurityJournalLoadV2>;
  compareAndSwap(expected: SecurityJournalHeadV2, next: SecurityJournalV2, signal?: AbortSignal): Promise<void>;
}

/** Another writer advanced the anchored journal; reload and re-evaluate. */
export const ErrSecurityJournalConflictV2 = new V2SentinelError("security journal compare-and-swap conflict");

const LIST = 3;
const PUSH = 5;
const MAX_SAFE = MAX_SAFE_INTEGER_V2;

/** The only valid genesis record. */
export function emptySecurityJournalV2(): SecurityJournalV2 {
  const journal: SecurityJournalV2 = {
    version: SECURITY_JOURNAL_VERSION_V2, generation: 0, previousDigest: "", digest: "",
    statusByIssuer: new Map(), keyRoleHistory: [], statusKeyHistory: [],
  };
  journal.digest = securityJournalDigestV2(journal);
  return journal;
}

/** Deep copy of a journal record. */
export function cloneSecurityJournalV2(journal: SecurityJournalV2): SecurityJournalV2 {
  const states = new Map<string, RevocationStatusStateV2>();
  for (const [issuerID, state] of journal.statusByIssuer) states.set(issuerID, cloneRevocationStatusStateV2(state));
  return {
    version: journal.version, generation: journal.generation, previousDigest: journal.previousDigest, digest: journal.digest,
    statusByIssuer: states,
    keyRoleHistory: journal.keyRoleHistory.map((b) => ({ ...b })),
    statusKeyHistory: journal.statusKeyHistory.map((b) => ({ ...b })),
  };
}

async function updateSecurityJournalV2(
  store: SecurityJournalStoreV2,
  update: (journal: SecurityJournalV2) => void | Promise<void>,
  signal?: AbortSignal,
): Promise<SecurityJournalV2> {
  if (!store || !update) throw new Error("security journal store and update are required");
  const current = await loadAnchoredSecurityJournalV2(store, signal);
  const next = cloneSecurityJournalV2(current);
  await update(next);
  return commitSecurityJournalTransitionV2(store, current, next, signal);
}

/**
 * Compacts and canonicalizes next; returns current unchanged when the
 * canonical content is identical (no-op); otherwise chains, validates, and
 * commits by compare-and-swap against current's head. A conflict is
 * rethrown as ErrSecurityJournalConflictV2, never retried.
 */
export async function commitSecurityJournalTransitionV2(
  store: SecurityJournalStoreV2,
  current: SecurityJournalV2,
  next: SecurityJournalV2,
  signal?: AbortSignal,
): Promise<SecurityJournalV2> {
  pruneSecurityJournalObservationsV2(next);
  canonicalizeSecurityJournalV2(next);
  if (sameSecurityJournalContentV2(next, current)) return current;
  next.generation = current.generation + 1;
  if (next.generation === 0 || next.generation > MAX_SAFE) throw new Error("security journal generation exhausted");
  next.version = SECURITY_JOURNAL_VERSION_V2;
  next.previousDigest = current.digest;
  next.digest = "";
  next.digest = securityJournalDigestV2(next);
  try {
    validateSecurityJournalTransitionV2(current, next);
  } catch (err) {
    throw wrapError("invalid security journal transition", err);
  }
  const head: SecurityJournalHeadV2 = { generation: current.generation, digest: current.digest };
  try {
    await store.compareAndSwap(head, next, signal);
  } catch (err) {
    if (errorIs(err, ErrSecurityJournalConflictV2)) throw err;
    throw wrapError("commit rollback-protected security journal", err);
  }
  return next;
}

/** Loads a version 2 record and requires it to match the anchored head returned with it. */
export async function loadAnchoredSecurityJournalV2(store: SecurityJournalStoreV2, signal?: AbortSignal): Promise<SecurityJournalV2> {
  let loaded: SecurityJournalLoadV2;
  try {
    loaded = await store.load(signal);
  } catch (err) {
    throw wrapError("load rollback-protected security journal", err);
  }
  const { journal: current, head } = loaded ?? ({} as SecurityJournalLoadV2);
  if (!current || !head || head.generation !== current.generation || head.digest === "" || head.digest !== current.digest) {
    throw new Error("loaded security journal is not anchored by the store head");
  }
  if (current.version !== SECURITY_JOURNAL_VERSION_V2) throw new Error(`security journal version ${current.version} requires migration`);
  try {
    validateSecurityJournalV2(current);
  } catch (err) {
    throw wrapError("validate loaded security journal", err);
  }
  return current;
}

/** Durably adds a non-status key role after the caller authenticated its admission. */
export async function recordSecurityKeyRoleV2(store: SecurityJournalStoreV2, role: string, pub: HybridPublicKey, signal?: AbortSignal): Promise<SecurityJournalV2> {
  if (role === "status") throw new Error("status keys must be recorded with their issuer and epoch");
  return updateSecurityJournalV2(store, (journal) => registerKeyRoleV2(journal, role, pub), signal);
}

/**
 * Persists an authenticated status-key binding. A first binding starts at
 * epoch 1; later bindings advance exactly one epoch and keep prior denials.
 */
export async function configureStatusKeyEpochV2(store: SecurityJournalStoreV2, issuerID: string, epoch: number, pub: HybridPublicKey, signal?: AbortSignal): Promise<SecurityJournalV2> {
  return updateSecurityJournalV2(store, (journal) => {
    registerStatusKeyEpochV2(journal, issuerID, epoch, pub);
    const prior = journal.statusByIssuer.get(issuerID);
    if (prior !== undefined) {
      if (epoch === prior.statusKeyEpoch) {
        requireJournalStatusKeyV2(journal, issuerID, epoch, pub);
        return;
      }
      journal.statusByIssuer.set(issuerID, transitionRevocationStatusEpochV2(prior, issuerID, epoch, pub));
      return;
    }
    if (epoch !== 1) throw new Error("first status-key epoch must be 1");
    const state = emptyRevocationStatusStateV2();
    state.issuerID = issuerID;
    state.statusKeyEpoch = epoch;
    state.statusKeyID = keyIDV2(pub);
    journal.statusByIssuer.set(issuerID, state);
  }, signal);
}

/** Authenticates, reduces, and atomically persists one full snapshot. */
export async function applyRevocationListToJournalV2(
  store: SecurityJournalStoreV2, list: RevocationListV2, issuerID: string, epoch: number, pub: HybridPublicKey,
  policy: RevocationStatusPolicyV2, now: number, signal?: AbortSignal,
): Promise<SecurityJournalV2> {
  return updateSecurityJournalV2(store, async (journal) => {
    requireJournalStatusKeyV2(journal, issuerID, epoch, pub);
    const state = await applyRevocationListV2(journal.statusByIssuer.get(issuerID)!, list, issuerID, epoch, pub, policy, now);
    journal.statusByIssuer.set(issuerID, state);
  }, signal);
}

/** Authenticates, reduces, and atomically persists one push. */
export async function applyRevocationPushToJournalV2(
  store: SecurityJournalStoreV2, push: RevocationPushV2, issuerID: string, epoch: number, pub: HybridPublicKey,
  policy: RevocationStatusPolicyV2, now: number, signal?: AbortSignal,
): Promise<SecurityJournalV2> {
  return updateSecurityJournalV2(store, async (journal) => {
    requireJournalStatusKeyV2(journal, issuerID, epoch, pub);
    const state = await applyRevocationPushV2(journal.statusByIssuer.get(issuerID)!, push, issuerID, epoch, pub, policy, now);
    journal.statusByIssuer.set(issuerID, state);
  }, signal);
}

const unavailableResult = (): RevocationStatusResultV2 => ({ status: "indeterminate", reason: "unavailable", evidence: [], freshUntil: 0 });

/**
 * Reads anchored state and returns a fail-closed status for one
 * issuer-scoped certificate reference. Any failure throws; callers that
 * need a value use the unavailable result.
 */
export async function revocationStatusFromJournalV2(
  store: SecurityJournalStoreV2, issuerID: string, certID: string, epoch: number, pub: HybridPublicKey,
  policy: RevocationStatusPolicyV2, now: number, signal?: AbortSignal,
): Promise<RevocationStatusResultV2> {
  if (!store) throw new Error("security journal store is required");
  const journal = await loadAnchoredSecurityJournalV2(store, signal);
  requireJournalStatusKeyV2(journal, issuerID, epoch, pub);
  return revocationStatusForCertV2(journal.statusByIssuer.get(issuerID)!, issuerID, certID, epoch, pub, policy, now);
}

export { unavailableResult as unavailableV2StatusResult };

/** The issuer's binding at epoch must equal pub and be the issuer's current epoch. */
export function requireJournalStatusKeyV2(journal: SecurityJournalV2, issuerID: string, epoch: number, pub: HybridPublicKey): void {
  if (!journal || issuerID === "" || !(epoch > 0)) throw new Error("issuer and status-key epoch are required");
  const binding = statusBindingAtEpochV2(journal.statusKeyHistory, issuerID, epoch);
  if (binding === null) throw new Error("issuer status key is not present in the retained trust history");
  const actual = statusKeyBindingV2(issuerID, epoch, pub);
  if (!sameStatusBinding(binding, actual)) throw new Error("status key does not match the retained issuer and epoch binding");
  const state = journal.statusByIssuer.get(issuerID);
  if (state === undefined || state.statusKeyEpoch !== epoch || state.statusKeyID !== binding.statusKeyID) {
    throw new Error("status key is not the current issuer epoch");
  }
}

/** Validates record integrity and internal indexes. */
export function validateSecurityJournalV2(journal: SecurityJournalV2): void {
  if (!journal || (journal.version !== SECURITY_JOURNAL_VERSION_V2 && journal.version !== SECURITY_JOURNAL_LEGACY_VERSION_V2) ||
      !(journal.statusByIssuer instanceof Map) || !Array.isArray(journal.keyRoleHistory) || !Array.isArray(journal.statusKeyHistory)) {
    throw new Error("security journal has unsupported or incomplete shape");
  }
  if (!Number.isSafeInteger(journal.generation) || journal.generation < 0) throw new Error("security journal generation is invalid");
  if (journal.generation === 0 && journal.previousDigest !== "") throw new Error("security journal genesis has a predecessor");
  if (journal.generation === 0 && (journal.statusByIssuer.size !== 0 || journal.keyRoleHistory.length !== 0 || journal.statusKeyHistory.length !== 0)) {
    throw new Error("security journal genesis must be empty");
  }
  if (journal.generation > 0 && (journal.previousDigest === "" || journal.previousDigest.length !== 96)) {
    throw new Error("security journal record is missing its predecessor digest");
  }
  if (journal.digest !== securityJournalDigestV2(journal)) throw new Error("security journal digest mismatch");
  for (const [issuerID, state] of journal.statusByIssuer) {
    if (issuerID === "" || state.issuerID !== issuerID || !(state.statusKeyEpoch > 0)) {
      throw new Error("security journal contains a misbound issuer status state");
    }
    try {
      validateStatusStateBindingV2(state, issuerID, state.statusKeyEpoch);
    } catch (err) {
      throw wrapError(`invalid status state for issuer "${issuerID}"`, err);
    }
    try {
      validateAcceptedStatusStateV2(state);
    } catch (err) {
      throw wrapError(`invalid accepted status state for issuer "${issuerID}"`, err);
    }
    const binding = statusBindingAtEpochV2(journal.statusKeyHistory, issuerID, state.statusKeyEpoch);
    if (binding === null || binding.statusKeyID !== state.statusKeyID) throw new Error("current status state has no matching retained key binding");
    let maxObserved = 0;
    const retired: string[] = [];
    for (const old of journal.statusKeyHistory) {
      if (old.issuerID === issuerID && old.epoch < state.statusKeyEpoch) retired.push(old.statusKeyID);
    }
    for (const o of state.observations) {
      const ob = statusBindingAtEpochV2(journal.statusKeyHistory, issuerID, o.statusKeyEpoch);
      if (ob === null || o.statusKeyID !== ob.statusKeyID || !(o.sequence > 0) || o.sequence > MAX_SAFE ||
          o.evidenceDigest.length !== 48 || o.bodyDigest.length !== 48 || (o.objectType !== LIST && o.objectType !== PUSH)) {
        throw new Error("security journal contains malformed or misbound status evidence");
      }
      if (o.statusKeyEpoch === state.statusKeyEpoch && o.sequence > maxObserved) maxObserved = o.sequence;
    }
    if (state.maxObservedSequence !== maxObserved || !equalStringSetsV2(state.retiredStatusKeyIDs, retired)) {
      throw new Error("status state does not match retained sequence and key history");
    }
  }
  validateKeyRoleHistoryV2(journal.keyRoleHistory);
  validateStatusKeyHistoryV2(journal.statusKeyHistory, journal.keyRoleHistory);
  const latest = new Map<string, number>();
  for (const b of journal.statusKeyHistory) if (b.epoch > (latest.get(b.issuerID) ?? 0)) latest.set(b.issuerID, b.epoch);
  for (const [issuerID, epoch] of latest) {
    const state = journal.statusByIssuer.get(issuerID);
    if (state === undefined || state.statusKeyEpoch !== epoch) {
      throw new Error("security journal status state is not at the latest retained issuer epoch");
    }
  }
}

/** Generation continuity and append-only key histories (Go ValidateSecurityJournalTransitionV2). */
export function validateSecurityJournalTransitionV2(current: SecurityJournalV2, next: SecurityJournalV2): void {
  try {
    validateSecurityJournalV2(current);
  } catch (err) {
    throw wrapError("invalid current journal", err);
  }
  try {
    validateSecurityJournalV2(next);
  } catch (err) {
    throw wrapError("invalid next journal", err);
  }
  if (next.generation !== current.generation + 1 || next.previousDigest !== current.digest) {
    throw new Error("journal generation or predecessor is not contiguous");
  }
  if (next.version !== SECURITY_JOURNAL_VERSION_V2) throw new Error(`journal transitions must produce a version ${SECURITY_JOURNAL_VERSION_V2} record`);
  if (current.version === SECURITY_JOURNAL_LEGACY_VERSION_V2 && !sameSecurityJournalContentV2(current, next)) {
    throw new Error("journal migration must not change logical content");
  }
  if (!appendOnly(current.keyRoleHistory, next.keyRoleHistory, sameRoleBinding) ||
      !appendOnly(current.statusKeyHistory, next.statusKeyHistory, sameStatusBinding)) {
    throw new Error("journal key binding history was removed or rewritten");
  }
  for (const [issuerID, state] of current.statusByIssuer) {
    const nextState = next.statusByIssuer.get(issuerID);
    if (nextState === undefined || !containsAllStringSetV2(nextState.denyUnionCertIDs, state.denyUnionCertIDs)) {
      throw new Error("journal transition removed issuer status or a retained revocation");
    }
    const nextKeys = new Set(nextState.observations.map(securityObservationKeyV2));
    const nextSemantic = new Map<string, RevocationObservationV2>();
    for (const o of nextState.observations) nextSemantic.set(securityObservationSemanticKeyV2(o), o);
    for (const old of state.observations) {
      if (nextKeys.has(securityObservationKeyV2(old))) continue;
      if (!mustRetainStatusObservationV2(nextState, old)) continue;
      const compacted = nextSemantic.get(securityObservationSemanticKeyV2(old));
      if (compacted === undefined || !containsAllStringSetV2(compacted.revokedCertIDs, old.revokedCertIDs) ||
          (old.fork && !compacted.fork) || (old.gap && nextState.reconciliationRequired && !compacted.gap) ||
          (old.futureDated && nextState.futureDatedObjectObserved && !compacted.futureDated)) {
        throw new Error("journal transition removed authenticated status evidence");
      }
    }
    if (nextState.statusKeyEpoch < state.statusKeyEpoch) throw new Error("journal transition rolled back a status-key epoch");
    if (nextState.statusKeyEpoch > state.statusKeyEpoch) {
      if (nextState.statusKeyID === state.statusKeyID || state.retiredStatusKeyIDs.includes(nextState.statusKeyID) ||
          !equalStringSetsV2(nextState.retiredStatusKeyIDs, [...state.retiredStatusKeyIDs, state.statusKeyID]) ||
          nextState.hasFloor || nextState.floor !== 0 || nextState.acceptedSnapshot !== null || nextState.acceptedCertIDs.length !== 0 ||
          nextState.hasPrecedingCheckpoint || nextState.precedingFloor !== 0 || nextState.precedingAcceptedCertIDs.length !== 0 ||
          nextState.maxObservedSequence !== 0 || nextState.forkSequence !== 0 || nextState.reconciliationRequired || nextState.futureDatedObjectObserved) {
        throw new Error("status-key epoch transition did not perform the required fail-closed reset");
      }
      for (const o of nextState.observations) {
        if (o.statusKeyEpoch >= nextState.statusKeyEpoch) {
          throw new Error("status-key epoch transition contains evidence from the new epoch before bootstrap");
        }
      }
    }
    if (nextState.statusKeyEpoch === state.statusKeyEpoch && state.hasFloor && (!nextState.hasFloor || nextState.floor < state.floor)) {
      throw new Error("journal transition rolled back the accepted status floor");
    }
    if (nextState.statusKeyEpoch === state.statusKeyEpoch && nextState.maxObservedSequence < state.maxObservedSequence) {
      throw new Error("journal transition rolled back the observed status sequence");
    }
    if (nextState.statusKeyEpoch === state.statusKeyEpoch && state.reconciliationRequired && !nextState.reconciliationRequired) {
      if (!hasAcceptedSnapshotAfterV2(nextState, state.statusKeyEpoch, state.maxObservedSequence, state.forkSequence, state.denyUnionCertIDs) ||
          !containsAllStringSetV2(nextState.acceptedCertIDs, state.denyUnionCertIDs)) {
        throw new Error("journal transition cleared reconciliation without a caught-up full snapshot");
      }
    }
  }
  for (const [issuerID, state] of next.statusByIssuer) {
    if (!current.statusByIssuer.has(issuerID) && statusBindingAtEpochV2(next.statusKeyHistory, issuerID, state.statusKeyEpoch) === null) {
      throw new Error("new issuer status state lacks authenticated key history");
    }
  }
}

/** Go pruneSecurityJournalObservationsV2: compacts every issuer state in place. */
export function pruneSecurityJournalObservationsV2(journal: SecurityJournalV2): void {
  for (const [issuerID, state] of journal.statusByIssuer) {
    journal.statusByIssuer.set(issuerID, compactRevocationStatusObservationsV2(state));
  }
}

function hex48(b: Uint8Array): string {
  return hexOf(b);
}

/** Go securityObservationKeyV2: the full observation identity (json.Marshal of the record). */
export function securityObservationKeyV2(o: RevocationObservationV2): string {
  return JSON.stringify([o.objectType, o.statusKeyEpoch, o.statusKeyID, o.sequence, hex48(o.evidenceDigest), hex48(o.bodyDigest),
    hex48(o.revokedSetDigest), o.revokedCertIDs, o.futureDated, o.fork, o.gap, o.accepted]);
}

function hasAcceptedSnapshotAfterV2(state: RevocationStatusStateV2, epoch: number, minSequence: number, forkSequence: number, denyUnion: readonly string[]): boolean {
  return state.observations.some((o) => o.statusKeyEpoch === epoch && o.objectType === LIST && o.accepted &&
    o.sequence >= minSequence && (forkSequence === 0 || o.sequence > forkSequence) && containsAllStringSetV2(o.revokedCertIDs, denyUnion));
}

const SECURITY_KEY_ROLES = new Set(["status", "delegation", "rotation", "verifier", "witness", "receiver", "issuer", "other"]);

export function validSecurityKeyRoleV2(role: string): boolean {
  return SECURITY_KEY_ROLES.has(role);
}

/**
 * Records a permanent global role assignment. Repeating the identical
 * assignment is idempotent; any key-ID or component reuse is denied.
 */
export function registerKeyRoleV2(journal: SecurityJournalV2, role: string, pub: HybridPublicKey): void {
  if (!journal || !validSecurityKeyRoleV2(role) || role === "status") throw new Error("security key role is invalid");
  registerKeyRoleUncheckedV2(journal, role, pub);
}

function registerKeyRoleUncheckedV2(journal: SecurityJournalV2, role: string, pub: HybridPublicKey): void {
  const binding = keyRoleBindingV2(role, pub);
  for (const existing of journal.keyRoleHistory) {
    if (sameRoleBinding(existing, binding)) return;
    if (existing.keyID === binding.keyID || existing.ed25519Digest === binding.ed25519Digest || existing.mlDsa65Digest === binding.mlDsa65Digest ||
        existing.ed25519Digest === binding.mlDsa65Digest || existing.mlDsa65Digest === binding.ed25519Digest) {
      throw new Error(`hybrid key ID or component is already permanently assigned to role "${existing.role}"`);
    }
  }
  journal.keyRoleHistory.push(binding);
  sortKeyRoleHistoryV2(journal.keyRoleHistory);
}

/** Records caller-authenticated status-key history and the permanent status role. */
export function registerStatusKeyEpochV2(journal: SecurityJournalV2, issuerID: string, epoch: number, pub: HybridPublicKey): void {
  if (!journal || issuerID === "" || !Number.isSafeInteger(epoch) || epoch <= 0) throw new Error("status-key binding has invalid issuer or epoch");
  const binding = statusKeyBindingV2(issuerID, epoch, pub);
  for (const existing of journal.statusKeyHistory) {
    if (existing.issuerID === issuerID && existing.epoch === epoch) {
      if (sameStatusBinding(existing, binding)) return;
      throw new Error("status-key epoch is permanently bound to a different key");
    }
    if (existing.statusKeyID === binding.statusKeyID || existing.ed25519Digest === binding.ed25519Digest || existing.mlDsa65Digest === binding.mlDsa65Digest) {
      throw new Error("status key was previously bound in this deployment");
    }
  }
  let highest = 0;
  for (const existing of journal.statusKeyHistory) if (existing.issuerID === issuerID && existing.epoch > highest) highest = existing.epoch;
  if (epoch !== highest + 1) throw new Error("status-key epoch must advance by one from retained issuer history");
  registerKeyRoleUncheckedV2(journal, "status", pub);
  journal.statusKeyHistory.push(binding);
  sortStatusKeyHistoryV2(journal.statusKeyHistory);
}

/** The key-role binding of a complete key: its key ID and SHA-384 of each component. */
export function keyRoleBindingV2(role: string, pub: HybridPublicKey): KeyRoleBindingV2 {
  const keyID = keyIDV2(pub);
  return { keyID, ed25519Digest: hexOf(sha384(pub.ed25519)), mlDsa65Digest: hexOf(sha384(pub.ml_dsa_65)), role };
}

export function statusKeyBindingV2(issuerID: string, epoch: number, pub: HybridPublicKey): StatusKeyBindingV2 {
  const role = keyRoleBindingV2("status", pub);
  return { issuerID, epoch, statusKeyID: role.keyID, ed25519Digest: role.ed25519Digest, mlDsa65Digest: role.mlDsa65Digest };
}

export function sameRoleBinding(a: KeyRoleBindingV2, b: KeyRoleBindingV2): boolean {
  return a.keyID === b.keyID && a.ed25519Digest === b.ed25519Digest && a.mlDsa65Digest === b.mlDsa65Digest && a.role === b.role;
}

export function sameStatusBinding(a: StatusKeyBindingV2, b: StatusKeyBindingV2): boolean {
  return a.issuerID === b.issuerID && a.epoch === b.epoch && a.statusKeyID === b.statusKeyID &&
    a.ed25519Digest === b.ed25519Digest && a.mlDsa65Digest === b.mlDsa65Digest;
}

function validDigestHexV2(value: string): boolean {
  return typeof value === "string" && /^[0-9a-f]{96}$/.test(value);
}

function validateKeyRoleHistoryV2(history: readonly KeyRoleBindingV2[]): void {
  const ids = new Map<string, KeyRoleBindingV2>();
  const components = new Map<string, KeyRoleBindingV2>();
  for (const b of history) {
    if (!b || b.keyID === "" || !validSecurityKeyRoleV2(b.role) || !validDigestHexV2(b.ed25519Digest) || !validDigestHexV2(b.mlDsa65Digest)) {
      throw new Error("security journal contains malformed key-role history");
    }
    const prior = ids.get(b.keyID);
    if (prior && !sameRoleBinding(prior, b)) throw new Error("security journal reuses a key ID across roles");
    ids.set(b.keyID, b);
    for (const c of [b.ed25519Digest, b.mlDsa65Digest]) {
      const p = components.get(c);
      if (p && !sameRoleBinding(p, b)) throw new Error("security journal reuses key material across roles");
      components.set(c, b);
    }
  }
}

function validateStatusKeyHistoryV2(history: readonly StatusKeyBindingV2[], roles: readonly KeyRoleBindingV2[]): void {
  const lastEpoch = new Map<string, number>();
  const ids = new Set<string>();
  const components = new Set<string>();
  for (const b of history) {
    if (!b || b.issuerID === "" || !(b.epoch > 0) || b.statusKeyID === "" || !validDigestHexV2(b.ed25519Digest) || !validDigestHexV2(b.mlDsa65Digest)) {
      throw new Error("security journal contains malformed status-key history");
    }
    if (b.epoch !== (lastEpoch.get(b.issuerID) ?? 0) + 1) throw new Error("security journal status-key epochs are missing or out of order");
    lastEpoch.set(b.issuerID, b.epoch);
    const role = roles.find((r) => r.keyID === b.statusKeyID && r.ed25519Digest === b.ed25519Digest && r.mlDsa65Digest === b.mlDsa65Digest);
    if (!role || role.role !== "status") throw new Error("status-key history lacks its global status role assignment");
    if (ids.has(b.statusKeyID)) throw new Error("security journal reuses a status key ID");
    ids.add(b.statusKeyID);
    for (const c of [b.ed25519Digest, b.mlDsa65Digest]) {
      if (components.has(c)) throw new Error("security journal reuses a status-key component");
      components.add(c);
    }
  }
}

export function statusBindingAtEpochV2(history: readonly StatusKeyBindingV2[], issuerID: string, epoch: number): StatusKeyBindingV2 | null {
  return history.find((b) => b.issuerID === issuerID && b.epoch === epoch) ?? null;
}

function appendOnly<T>(before: readonly T[], after: readonly T[], same: (a: T, b: T) => boolean): boolean {
  return before.every((b) => after.some((a) => same(b, a)));
}

/** Sorted by key ID then role (byte order). */
export function sortKeyRoleHistoryV2(history: KeyRoleBindingV2[]): void {
  history.sort((a, b) => (a.keyID !== b.keyID ? compareStrings(a.keyID, b.keyID) : compareStrings(a.role, b.role)));
}

/** Sorted by issuer ID then epoch. */
export function sortStatusKeyHistoryV2(history: StatusKeyBindingV2[]): void {
  history.sort((a, b) => (a.issuerID !== b.issuerID ? compareStrings(a.issuerID, b.issuerID) : a.epoch - b.epoch));
}
