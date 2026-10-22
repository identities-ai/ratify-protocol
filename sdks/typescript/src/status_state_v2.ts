// Protocol v2 issuer status reducer (SPEC-v2 §5.3): rollback-protected
// state, list and push application, epoch transitions, and per-reference
// status results with deterministic evidence. Port of status_state_v2.go
// plus the observation compaction and accepted-state validation from
// security_journal_v2.go.

import { sha384 } from "@noble/hashes/sha2";

import { V2_OBJECT_TYPE } from "./crypto_v2.js";
import { v2Classify } from "./errors_v2.js";
import { V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_STATUS_LIFETIME_SECONDS, validV2Timestamp } from "./clock_bounds_v2.js";
import { MAX_SAFE_INTEGER_V2, bytesEqual, canonicalJSONV2, compareBytes, compareStrings, concatBytes, hexOf, isWellFormedString, utf8 } from "./json_v2.js";
import {
  cloneRevocationListV2,
  keyIDV2,
  revocationListV2SignBytes,
  revocationPushV2SignBytes,
  statusEvidenceDigestV2,
  validV2ID,
  verifyRevocationListV2Signature,
  verifyRevocationPushV2Signature,
  type RevocationListV2,
  type RevocationPushV2,
  type RevokedCertV2,
} from "./protocol_v2_wire.js";
import type { StatusEvidenceEntryV2 } from "./verification_receipt_v2.js";
import type { HybridPublicKey } from "./types.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;
const LIST = V2_OBJECT_TYPE.revocationList;
const PUSH = V2_OBJECT_TYPE.revocationPush;

/** Finite freshness bounds; a zero maximum means the bound is not configured. */
export interface RevocationStatusPolicyV2 {
  maxListLifetimeSeconds: number;
  maxStatusAgeSeconds: number;
  clockSkewSeconds: number;
}

export interface RevocationObservationV2 {
  objectType: number;
  statusKeyEpoch: number;
  statusKeyID: string;
  sequence: number;
  evidenceDigest: Uint8Array;
  bodyDigest: Uint8Array;
  revokedSetDigest: Uint8Array;
  revokedCertIDs: string[];
  futureDated: boolean;
  fork: boolean;
  gap: boolean;
  accepted: boolean;
}

export interface RevocationStatusResultV2 {
  status: string;
  reason: string;
  evidence: StatusEvidenceEntryV2[];
  freshUntil: number;
}

/**
 * One issuer's rollback-protected reducer state. Callers serialize
 * applications and persist the returned value atomically.
 */
export interface RevocationStatusStateV2 {
  issuerID: string;
  statusKeyEpoch: number;
  statusKeyID: string;
  retiredStatusKeyIDs: string[];
  hasFloor: boolean;
  floor: number;
  acceptedSnapshot: RevocationListV2 | null;
  acceptedCertIDs: string[];
  hasPrecedingCheckpoint: boolean;
  precedingFloor: number;
  precedingAcceptedCertIDs: string[];
  denyUnionCertIDs: string[];
  observations: RevocationObservationV2[];
  maxObservedSequence: number;
  forkSequence: number;
  reconciliationRequired: boolean;
  futureDatedObjectObserved: boolean;
}

export function emptyRevocationStatusStateV2(): RevocationStatusStateV2 {
  return {
    issuerID: "", statusKeyEpoch: 0, statusKeyID: "", retiredStatusKeyIDs: [], hasFloor: false, floor: 0,
    acceptedSnapshot: null, acceptedCertIDs: [], hasPrecedingCheckpoint: false, precedingFloor: 0,
    precedingAcceptedCertIDs: [], denyUnionCertIDs: [], observations: [], maxObservedSequence: 0, forkSequence: 0,
    reconciliationRequired: false, futureDatedObjectObserved: false,
  };
}

// ---------------------------------------------------------------------------
// Set helpers

export function sortedUniqueStringsV2(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareStrings);
}

export function containsAllStringSetV2(have: readonly string[], want: readonly string[]): boolean {
  const set = new Set(have);
  return want.every((w) => set.has(w));
}

export function equalStringSetsV2(a: readonly string[], b: readonly string[]): boolean {
  return sortedUniqueStringsV2(a).length === sortedUniqueStringsV2(b).length && containsAllStringSetV2(a, b);
}

const containsNovelRevocationV2 = (values: readonly string[], accepted: readonly string[]) => !containsAllStringSetV2(accepted, values);

export function revokedCertIDsV2(refs: readonly RevokedCertV2[] | null): string[] {
  return (refs ?? []).map((r) => r.cert_id);
}

/**
 * RevokedSetDigest (SPEC-v2 §4): SHA-384("ratify-protocol-revoked-set-v2" ||
 * 0x00 || RatifyCanonicalJSON(sorted, deduplicated cert_ids)).
 */
export function revokedSetDigestV2(revoked: readonly RevokedCertV2[] | null): Uint8Array {
  return sha384(concatBytes(utf8("ratify-protocol-revoked-set-v2\0"), canonicalJSONV2(sortedUniqueStringsV2(revokedCertIDsV2(revoked)))));
}

export function cloneObservation(o: RevocationObservationV2): RevocationObservationV2 {
  return {
    ...o, evidenceDigest: Uint8Array.from(o.evidenceDigest), bodyDigest: Uint8Array.from(o.bodyDigest),
    revokedSetDigest: Uint8Array.from(o.revokedSetDigest), revokedCertIDs: [...o.revokedCertIDs],
  };
}

export function cloneRevocationStatusStateV2(state: RevocationStatusStateV2): RevocationStatusStateV2 {
  return {
    ...state,
    retiredStatusKeyIDs: [...state.retiredStatusKeyIDs],
    acceptedCertIDs: [...state.acceptedCertIDs],
    precedingAcceptedCertIDs: [...state.precedingAcceptedCertIDs],
    denyUnionCertIDs: [...state.denyUnionCertIDs],
    observations: state.observations.map(cloneObservation),
    acceptedSnapshot: state.acceptedSnapshot === null ? null : cloneRevocationListV2(state.acceptedSnapshot),
  };
}

const timestampBeyondSkewV2 = (timestamp: number, now: number, skew: number) => timestamp > now && timestamp - now > skew;

function revocationListFreshV2(list: RevocationListV2, policy: RevocationStatusPolicyV2, now: number): boolean {
  if (policy.maxListLifetimeSeconds === 0 || policy.maxStatusAgeSeconds === 0 ||
      list.next_update - list.updated_at > policy.maxListLifetimeSeconds ||
      timestampBeyondSkewV2(list.updated_at, now, policy.clockSkewSeconds) || now >= list.next_update) {
    // Exclusive deadline: a list is fresh only while now < next_update.
    return false;
  }
  // Exclusive age deadline: fresh only while now < updated_at + max_status_age.
  return now < list.updated_at || now - list.updated_at < policy.maxStatusAgeSeconds;
}

export function validateRevocationStatusPolicyV2(p: RevocationStatusPolicyV2): void {
  // Zero lifetime or age means "not configured" (status is then never
  // current); configured values are bounded by SPEC-v2 §2.5.
  const bad = (n: number, max: number) => !Number.isInteger(n) || n < 0 || n > max;
  if (!p || bad(p.maxListLifetimeSeconds, V2_MAX_STATUS_LIFETIME_SECONDS) || bad(p.maxStatusAgeSeconds, V2_MAX_STATUS_LIFETIME_SECONDS) ||
      bad(p.clockSkewSeconds, V2_MAX_FUTURE_SKEW_SECONDS)) {
    throw new Error("revocation status policy contains invalid time bounds");
  }
}

export function validateStatusStateBindingV2(state: RevocationStatusStateV2, issuerID: string, epoch: number): void {
  if (state.issuerID !== "" && state.issuerID !== issuerID) throw new Error("revocation status state belongs to a different issuer");
  if (state.issuerID !== "" && state.statusKeyEpoch !== epoch) throw new Error("revocation status state belongs to a different status-key epoch");
  if (state.floor < 0 || state.maxObservedSequence < 0 || state.forkSequence < 0) throw new Error("revocation status state has negative sequence state");
  if (state.precedingFloor < 0 || state.precedingFloor > MAX_SAFE || (state.precedingFloor === 0 && state.precedingAcceptedCertIDs.length !== 0) ||
      sortedUniqueStringsV2(state.precedingAcceptedCertIDs).length !== state.precedingAcceptedCertIDs.length) {
    throw new Error("revocation status state has invalid preceding checkpoint");
  }
  if (state.hasFloor && (state.floor === 0 || state.floor > MAX_SAFE || state.acceptedSnapshot === null ||
      state.acceptedSnapshot.sequence <= 0 || state.acceptedSnapshot.sequence > state.floor)) {
    throw new Error("revocation status state has inconsistent accepted floor");
  }
  if (!state.hasFloor && (state.floor !== 0 || state.acceptedSnapshot !== null || state.acceptedCertIDs.length !== 0)) {
    throw new Error("revocation status state has accepted data without a floor");
  }
  if (state.maxObservedSequence > MAX_SAFE || state.forkSequence > MAX_SAFE || !(epoch > 0) || epoch > MAX_SAFE) {
    throw new Error("revocation status state has invalid sequence or epoch");
  }
  if (state.issuerID !== "" && !validV2ID(state.statusKeyID)) throw new Error("revocation status state has an invalid status-key ID");
  if (sortedUniqueStringsV2(state.retiredStatusKeyIDs).length !== state.retiredStatusKeyIDs.length ||
      state.retiredStatusKeyIDs.includes(state.statusKeyID)) {
    throw new Error("revocation status state has invalid retired status-key history");
  }
  for (const k of state.retiredStatusKeyIDs) if (!validV2ID(k)) throw new Error("revocation status state has an invalid retired status-key ID");
}

export function hasAcceptedStatusObservationV2(obs: readonly RevocationObservationV2[], epoch: number, objectType: number, sequence: number, digest: Uint8Array): boolean {
  return obs.some((o) => o.statusKeyEpoch === epoch && o.objectType === objectType && o.sequence === sequence &&
    bytesEqual(o.evidenceDigest, digest) && o.accepted && !o.fork && !o.futureDated);
}

/** Go validateAcceptedStatusStateV2 (security_journal_v2.go). */
export function validateAcceptedStatusStateV2(state: RevocationStatusStateV2): void {
  if (sortedUniqueStringsV2(state.denyUnionCertIDs).length !== state.denyUnionCertIDs.length ||
      sortedUniqueStringsV2(state.acceptedCertIDs).length !== state.acceptedCertIDs.length) {
    throw new Error("revocation status sets are not canonical");
  }
  const observedRevocations: string[] = [];
  let forkRecorded = false;
  for (const o of state.observations) {
    if (!(o.sequence > 0) || o.sequence > MAX_SAFE || !validV2ID(o.statusKeyID) || (o.objectType !== LIST && o.objectType !== PUSH) ||
        o.evidenceDigest.length !== 48 || o.bodyDigest.length !== 48 || o.revokedSetDigest.length !== 48 ||
        sortedUniqueStringsV2(o.revokedCertIDs).length !== o.revokedCertIDs.length) {
      throw new Error("security journal contains a malformed status observation");
    }
    for (const id of o.revokedCertIDs) {
      if (id === "" || !isWellFormedString(id)) throw new Error("status observation contains an invalid certificate ID");
    }
    forkRecorded = forkRecorded || (o.statusKeyEpoch === state.statusKeyEpoch && o.fork);
    observedRevocations.push(...o.revokedCertIDs);
    if (o.statusKeyEpoch === state.statusKeyEpoch && o.sequence > state.maxObservedSequence) {
      throw new Error("observed sequence exceeds its high-water mark");
    }
    if (!containsAllStringSetV2(state.denyUnionCertIDs, o.revokedCertIDs)) throw new Error("deny union omits a revocation from authenticated evidence");
  }
  if (!containsAllStringSetV2(observedRevocations, state.denyUnionCertIDs)) {
    throw new Error("deny union contains a revocation without a retained authenticated witness");
  }
  if (state.forkSequence > 0 && (!state.reconciliationRequired || !forkRecorded)) throw new Error("unresolved fork state lacks its retained fork marker");
  if (state.hasFloor && state.floor > state.maxObservedSequence) throw new Error("accepted floor exceeds the observed sequence high-water mark");
  if (!state.hasFloor) return;
  const snapshot = state.acceptedSnapshot!;
  if (snapshot.issuer_id !== state.issuerID || snapshot.sequence > state.floor) throw new Error("accepted snapshot does not match issuer or floor");
  const digest = statusEvidenceDigestV2(LIST, snapshot);
  if (!hasAcceptedStatusObservationV2(state.observations, state.statusKeyEpoch, LIST, snapshot.sequence, digest)) {
    throw new Error("accepted snapshot has no matching authenticated observation");
  }
  const accepted = revokedCertIDsV2(snapshot.revoked);
  const pushes = state.observations.filter((o) => o.statusKeyEpoch === state.statusKeyEpoch && o.objectType === PUSH && o.accepted &&
    o.sequence > snapshot.sequence && o.sequence <= state.floor);
  for (const p of pushes) accepted.push(...p.revokedCertIDs);
  pushes.sort((a, b) => a.sequence - b.sequence);
  let expected = snapshot.sequence;
  for (const p of pushes) {
    if (expected >= MAX_SAFE || p.sequence !== expected + 1) throw new Error("accepted push observations are not contiguous after the accepted snapshot");
    expected = p.sequence;
  }
  if (expected !== state.floor) throw new Error("accepted push history does not reach the recorded floor");
  if (!equalStringSetsV2(accepted, state.acceptedCertIDs)) throw new Error("accepted certificate set does not follow the accepted snapshot and pushes");
}

export function mustRetainStatusObservationV2(state: RevocationStatusStateV2, o: RevocationObservationV2): boolean {
  if (o.statusKeyEpoch !== state.statusKeyEpoch) return false;
  if (state.acceptedSnapshot !== null && o.objectType === PUSH && o.accepted && o.sequence > state.acceptedSnapshot.sequence && o.sequence <= state.floor) {
    return true;
  }
  return state.reconciliationRequired && (o.sequence > state.floor || o.fork || o.gap || o.futureDated);
}

export function securityObservationSemanticKeyV2(o: RevocationObservationV2): string {
  const digest = o.objectType === LIST ? o.revokedSetDigest : o.bodyDigest;
  return `${o.statusKeyEpoch}:${o.objectType}:${o.sequence}:${hexOf(digest)}:future=${o.futureDated}:fork=${o.fork}`;
}

/** Go compactRevocationStatusObservationsV2 / pruneSecurityJournalObservationsV2. */
export function compactRevocationStatusObservationsV2(state: RevocationStatusStateV2): RevocationStatusStateV2 {
  const baseDigest = state.acceptedSnapshot !== null ? statusEvidenceDigestV2(LIST, state.acceptedSnapshot) : null;
  const observations = state.observations.map(cloneObservation);
  observations.sort((a, b) => {
    if (a.statusKeyEpoch !== b.statusKeyEpoch) return a.statusKeyEpoch - b.statusKeyEpoch;
    if (a.sequence !== b.sequence) return a.sequence - b.sequence;
    if (a.objectType !== b.objectType) return a.objectType - b.objectType;
    const c = compareBytes(a.revokedSetDigest, b.revokedSetDigest);
    if (c !== 0) return c;
    return compareBytes(a.bodyDigest, b.bodyDigest);
  });
  const retained: RevocationObservationV2[] = [];
  const witnessed = new Set<string>();
  const semanticSeen = new Map<string, number>();
  for (const o of observations) {
    const acceptedBase = baseDigest !== null && baseDigest.length !== 0 && o.statusKeyEpoch === state.statusKeyEpoch &&
      o.objectType === LIST && o.sequence === state.acceptedSnapshot!.sequence && bytesEqual(o.evidenceDigest, baseDigest);
    const fullRecord = acceptedBase || mustRetainStatusObservationV2(state, o);
    const newWitnesses: string[] = [];
    for (const id of o.revokedCertIDs) {
      if (!witnessed.has(id)) {
        witnessed.add(id);
        newWitnesses.push(id);
      }
    }
    if (!fullRecord) o.revokedCertIDs = newWitnesses;
    const key = securityObservationSemanticKeyV2(o);
    const index = semanticSeen.get(key);
    if (index !== undefined) {
      const prior = retained[index]!;
      prior.accepted = prior.accepted || o.accepted;
      prior.fork = prior.fork || o.fork;
      prior.gap = prior.gap || o.gap;
      prior.futureDated = (prior.futureDated || o.futureDated) && !prior.accepted;
      prior.revokedCertIDs = sortedUniqueStringsV2([...prior.revokedCertIDs, ...o.revokedCertIDs]);
      if (acceptedBase) {
        prior.evidenceDigest = o.evidenceDigest;
        prior.accepted = true;
        if (!state.reconciliationRequired) prior.gap = false;
        prior.futureDated = false;
      }
      continue;
    }
    semanticSeen.set(key, retained.length);
    retained.push(o);
  }
  if (!state.reconciliationRequired && state.acceptedSnapshot !== null) {
    for (const o of retained) {
      if (o.statusKeyEpoch === state.statusKeyEpoch && o.objectType === LIST && o.sequence === state.acceptedSnapshot.sequence &&
          o.accepted && !o.futureDated && bytesEqual(o.evidenceDigest, baseDigest)) {
        o.gap = false;
        break;
      }
    }
  }
  return canonicalizeRevocationStatusStateV2({ ...state, observations: retained });
}

/** Go canonicalizeRevocationStatusStateV2: every set in snapshot order. */
export function canonicalizeRevocationStatusStateV2(state: RevocationStatusStateV2): RevocationStatusStateV2 {
  return {
    ...state,
    retiredStatusKeyIDs: sortedUniqueStringsV2(state.retiredStatusKeyIDs),
    acceptedCertIDs: sortedUniqueStringsV2(state.acceptedCertIDs),
    precedingAcceptedCertIDs: sortedUniqueStringsV2(state.precedingAcceptedCertIDs),
    denyUnionCertIDs: sortedUniqueStringsV2(state.denyUnionCertIDs),
    observations: state.observations.map((o) => ({ ...o, revokedCertIDs: sortedUniqueStringsV2(o.revokedCertIDs) })),
  };
}

function initializeState(state: RevocationStatusStateV2, issuerID: string, epoch: number): void {
  if (state.issuerID === "") {
    state.issuerID = issuerID;
    state.statusKeyEpoch = epoch;
  }
  state.acceptedCertIDs = sortedUniqueStringsV2(state.acceptedCertIDs);
  state.denyUnionCertIDs = sortedUniqueStringsV2(state.denyUnionCertIDs);
}

function addRevocationsV2(state: RevocationStatusStateV2, values: readonly string[]): void {
  state.denyUnionCertIDs = sortedUniqueStringsV2([...state.denyUnionCertIDs, ...values]);
}

function requiredRevocationsForSnapshotV2(obs: readonly RevocationObservationV2[], epoch: number, sequence: number): string[] {
  const values: string[] = [];
  for (const o of obs) if (o.statusKeyEpoch === epoch && o.sequence <= sequence) values.push(...o.revokedCertIDs);
  return sortedUniqueStringsV2(values);
}

function findStatusObservationV2(obs: readonly RevocationObservationV2[], epoch: number, objectType: number, sequence: number, digest: Uint8Array): number {
  for (let i = obs.length - 1; i >= 0; i--) {
    const o = obs[i]!;
    if (o.statusKeyEpoch === epoch && o.objectType === objectType && o.sequence === sequence && bytesEqual(o.evidenceDigest, digest)) return i;
  }
  return -1;
}

function snapshotConflictsWithObservedPushV2(state: RevocationStatusStateV2, epoch: number, sequence: number, snapshotIDs: readonly string[]): boolean {
  for (const o of state.observations) {
    if (o.statusKeyEpoch !== epoch || o.objectType !== PUSH || o.sequence !== sequence) continue;
    if (state.hasFloor && state.floor === sequence - 1) {
      if (!equalStringSetsV2(snapshotIDs, [...state.acceptedCertIDs, ...o.revokedCertIDs])) return true;
    } else if (!containsAllStringSetV2(snapshotIDs, o.revokedCertIDs)) {
      return true;
    }
  }
  return false;
}

function findStatusSetObservationV2(obs: readonly RevocationObservationV2[], incoming: RevocationObservationV2): RevocationObservationV2 | null {
  for (let i = obs.length - 1; i >= 0; i--) {
    const o = obs[i]!;
    if (o.statusKeyEpoch === incoming.statusKeyEpoch && o.objectType === incoming.objectType && o.sequence === incoming.sequence &&
        bytesEqual(o.revokedSetDigest, incoming.revokedSetDigest)) {
      return o;
    }
  }
  return null;
}

function hasForkedStatusSequenceV2(obs: readonly RevocationObservationV2[], epoch: number, objectType: number, sequence: number): boolean {
  return obs.some((o) => o.statusKeyEpoch === epoch && (objectType === 0 || o.objectType === objectType) && o.sequence === sequence && o.fork);
}

function hasStatusPushBodyV2(obs: readonly RevocationObservationV2[], epoch: number, sequence: number, bodyDigest: Uint8Array): boolean {
  return obs.some((o) => o.statusKeyEpoch === epoch && o.objectType === PUSH && o.sequence === sequence && bytesEqual(o.bodyDigest, bodyDigest));
}

function findStatusSequenceConflictV2(obs: readonly RevocationObservationV2[], incoming: RevocationObservationV2): boolean {
  for (const o of obs) {
    if (o.statusKeyEpoch !== incoming.statusKeyEpoch || o.sequence !== incoming.sequence || o.objectType !== incoming.objectType) continue;
    if (incoming.objectType === LIST && !bytesEqual(o.revokedSetDigest, incoming.revokedSetDigest)) return true;
    if (incoming.objectType === PUSH && !bytesEqual(o.bodyDigest, incoming.bodyDigest)) return true;
  }
  return false;
}

function snapshotOmissionForPushV2(state: RevocationStatusStateV2, epoch: number, push: RevocationObservationV2): number {
  let conflicting = 0;
  const check = (sequence: number, revoked: readonly string[]) => {
    if (sequence >= push.sequence && !containsAllStringSetV2(revoked, push.revokedCertIDs) && sequence > conflicting) conflicting = sequence;
  };
  if (state.acceptedSnapshot !== null && state.statusKeyEpoch === epoch) {
    check(state.acceptedSnapshot.sequence, revokedCertIDsV2(state.acceptedSnapshot.revoked));
  }
  if (state.reconciliationRequired) {
    for (const o of state.observations) {
      if (o.statusKeyEpoch === epoch && o.objectType === LIST && o.sequence > state.floor && o.sequence >= push.sequence &&
          (o.fork || o.gap || o.futureDated)) {
        check(o.sequence, o.revokedCertIDs);
      }
    }
  }
  return conflicting;
}

function markStatusForkV2(state: RevocationStatusStateV2, o: RevocationObservationV2, sequence: number): void {
  o.fork = true;
  state.reconciliationRequired = true;
  state.forkSequence = Math.max(0, state.forkSequence, state.floor, sequence);
}

function heartbeatPreferredV2(incoming: RevocationListV2, incomingDigest: Uint8Array, accepted: RevocationListV2): boolean {
  if (incoming.updated_at !== accepted.updated_at) return incoming.updated_at > accepted.updated_at;
  try {
    return compareBytes(incomingDigest, statusEvidenceDigestV2(LIST, accepted)) < 0;
  } catch {
    return false;
  }
}

function checkApplyInputs(policy: RevocationStatusPolicyV2, now: number, epoch: number, kind: string): void {
  validateRevocationStatusPolicyV2(policy);
  if (!validV2Timestamp(now) || !Number.isInteger(epoch) || epoch === 0 || epoch < 0 || epoch > MAX_SAFE) {
    throw new Error(`revocation ${kind} application has invalid time or status-key epoch`);
  }
}

async function finishApply(run: () => Promise<RevocationStatusStateV2>): Promise<RevocationStatusStateV2> {
  let result: RevocationStatusStateV2;
  try {
    result = await run();
  } catch (err) {
    throw v2Classify("status_object_rejected", err);
  }
  return result.issuerID !== "" ? compactRevocationStatusObservationsV2(result) : result;
}

/**
 * Verifies the caller-authenticated status-key binding and applies one full
 * snapshot. Invalid input leaves state untouched; the result is a copy for
 * atomic persistence.
 */
export function applyRevocationListV2(
  state: RevocationStatusStateV2,
  list: RevocationListV2,
  boundIssuerID: string,
  statusKeyEpoch: number,
  statusKey: HybridPublicKey,
  policy: RevocationStatusPolicyV2,
  now: number,
): Promise<RevocationStatusStateV2> {
  return finishApply(async () => {
    checkApplyInputs(policy, now, statusKeyEpoch, "list");
    await verifyRevocationListV2Signature(list, boundIssuerID, statusKey);
    validateStatusStateBindingV2(state, boundIssuerID, statusKeyEpoch);
    const digest = statusEvidenceDigestV2(LIST, list);
    const bodyDigest = sha384(revocationListV2SignBytes(list));
    const setDigest = revokedSetDigestV2(list.revoked);
    const next = cloneRevocationStatusStateV2(state);
    initializeState(next, boundIssuerID, statusKeyEpoch);
    const statusKeyID = keyIDV2(statusKey);
    if (next.statusKeyID !== "" && next.statusKeyID !== statusKeyID) {
      throw new Error("revocation list status key does not match configured epoch binding");
    }
    next.statusKeyID = statusKeyID;
    const duplicateIndex = findStatusObservationV2(next.observations, statusKeyEpoch, LIST, list.sequence, digest);
    const duplicate = duplicateIndex >= 0;
    const future = timestampBeyondSkewV2(list.updated_at, now, policy.clockSkewSeconds);
    const obs: RevocationObservationV2 = {
      objectType: LIST, statusKeyEpoch, statusKeyID, sequence: list.sequence, evidenceDigest: Uint8Array.from(digest),
      bodyDigest: Uint8Array.from(bodyDigest), revokedSetDigest: setDigest, revokedCertIDs: revokedCertIDsV2(list.revoked),
      futureDated: future, fork: false, gap: false, accepted: false,
    };
    const fresh = () => revocationListFreshV2(list, policy, now);
    if (!duplicate) {
      const prior = findStatusSetObservationV2(next.observations, obs);
      if (prior !== null) {
        if (prior.fork) return next;
        if ((prior.futureDated || prior.gap) && !future && fresh()) {
          if ((next.hasFloor && list.sequence < next.floor) || hasForkedStatusSequenceV2(next.observations, statusKeyEpoch, 0, list.sequence)) return next;
        } else if (!prior.accepted && !prior.fork && next.hasFloor && list.sequence === next.floor && next.acceptedSnapshot !== null &&
                   next.acceptedSnapshot.sequence < next.floor && !future && fresh()) {
          // A fresh same-set snapshot at a push-advanced floor becomes the new base.
        } else if (prior.accepted && next.hasFloor && list.sequence === next.floor && heartbeatPreferredV2(list, digest, next.acceptedSnapshot!)) {
          // A newer same-set current-floor heartbeat may refresh freshness.
        } else {
          return next;
        }
      }
    }
    if (duplicate) {
      const prior = next.observations[duplicateIndex]!;
      if (prior.accepted || (!prior.futureDated && !prior.gap) || future || !fresh()) return next;
      if (next.hasFloor && list.sequence < next.floor) return next;
      if (hasForkedStatusSequenceV2(next.observations, statusKeyEpoch, 0, list.sequence)) return next;
    } else {
      addRevocationsV2(next, obs.revokedCertIDs);
      if (list.sequence > next.maxObservedSequence) next.maxObservedSequence = list.sequence;
    }
    if (future) {
      next.futureDatedObjectObserved = true;
      next.reconciliationRequired = true;
    }
    if (findStatusSequenceConflictV2(next.observations, obs)) {
      markStatusForkV2(next, obs, list.sequence);
    } else if (next.hasFloor && list.sequence === next.floor && !equalStringSetsV2(obs.revokedCertIDs, next.acceptedCertIDs)) {
      markStatusForkV2(next, obs, list.sequence);
    } else if (next.hasFloor && list.sequence < next.floor && containsNovelRevocationV2(obs.revokedCertIDs, next.acceptedCertIDs)) {
      markStatusForkV2(next, obs, list.sequence);
    }
    const applicable = requiredRevocationsForSnapshotV2(next.observations, statusKeyEpoch, list.sequence);
    if (!containsAllStringSetV2(obs.revokedCertIDs, applicable)) markStatusForkV2(next, obs, list.sequence);
    if (snapshotConflictsWithObservedPushV2(next, statusKeyEpoch, list.sequence, obs.revokedCertIDs)) markStatusForkV2(next, obs, list.sequence);

    const record = () => {
      if (!duplicate) next.observations.push(obs);
    };
    if (!fresh()) {
      if (next.hasFloor && list.sequence <= next.floor) {
        record();
        return next;
      }
      next.reconciliationRequired = true;
      obs.gap = true;
      record();
      return next;
    }
    if (obs.fork) {
      record();
      return next;
    }
    if (!next.hasFloor && !containsAllStringSetV2(obs.revokedCertIDs, next.denyUnionCertIDs)) {
      next.reconciliationRequired = true;
      obs.gap = true;
      record();
      return next;
    }
    if (!next.hasFloor && list.sequence < next.maxObservedSequence) {
      next.reconciliationRequired = true;
      obs.gap = true;
      record();
      return next;
    }
    if (next.hasFloor && list.sequence < next.floor) {
      record();
      return next;
    }
    if (next.hasFloor && list.sequence === next.floor) {
      if (!equalStringSetsV2(obs.revokedCertIDs, next.acceptedCertIDs)) {
        markStatusForkV2(next, obs, list.sequence);
        record();
        return next;
      }
      if (next.acceptedSnapshot === null || next.acceptedSnapshot.sequence < list.sequence || heartbeatPreferredV2(list, digest, next.acceptedSnapshot)) {
        next.acceptedSnapshot = cloneRevocationListV2(list);
      }
      obs.accepted = true;
    } else {
      const copy = cloneRevocationListV2(list);
      if (next.hasFloor && list.sequence === next.floor + 1) {
        next.hasPrecedingCheckpoint = true;
        next.precedingFloor = next.floor;
        next.precedingAcceptedCertIDs = sortedUniqueStringsV2(next.acceptedCertIDs);
      } else {
        next.hasPrecedingCheckpoint = false;
        next.precedingFloor = 0;
        next.precedingAcceptedCertIDs = [];
      }
      next.acceptedSnapshot = copy;
      next.acceptedCertIDs = sortedUniqueStringsV2(obs.revokedCertIDs);
      next.hasFloor = true;
      next.floor = list.sequence;
      obs.accepted = true;
    }
    if (next.reconciliationRequired) {
      const recoverableFork = next.forkSequence === 0 || (list.sequence > next.forkSequence && list.sequence >= next.maxObservedSequence);
      const fullyObserved = containsAllStringSetV2(obs.revokedCertIDs, next.denyUnionCertIDs);
      if (recoverableFork && fullyObserved && list.sequence >= next.maxObservedSequence) {
        next.reconciliationRequired = false;
        next.futureDatedObjectObserved = false;
        next.forkSequence = 0;
      }
    } else if (list.sequence >= next.maxObservedSequence && containsAllStringSetV2(obs.revokedCertIDs, next.denyUnionCertIDs)) {
      next.reconciliationRequired = false;
    }
    if (!duplicate || (obs.accepted && !next.observations[duplicateIndex]!.accepted)) next.observations.push(obs);
    return next;
  });
}

/**
 * Verifies the status-key binding and applies one signed push.
 * Noncontiguous or future pushes contribute to deny_union but make current
 * status unavailable until a full snapshot repairs the gap or conflict.
 */
export function applyRevocationPushV2(
  state: RevocationStatusStateV2,
  push: RevocationPushV2,
  boundIssuerID: string,
  statusKeyEpoch: number,
  statusKey: HybridPublicKey,
  policy: RevocationStatusPolicyV2,
  now: number,
): Promise<RevocationStatusStateV2> {
  return finishApply(async () => {
    checkApplyInputs(policy, now, statusKeyEpoch, "push");
    await verifyRevocationPushV2Signature(push, boundIssuerID, statusKey);
    validateStatusStateBindingV2(state, boundIssuerID, statusKeyEpoch);
    const digest = statusEvidenceDigestV2(PUSH, push);
    const bodyDigest = sha384(revocationPushV2SignBytes(push));
    const setDigest = revokedSetDigestV2(push.revoked);
    const next = cloneRevocationStatusStateV2(state);
    initializeState(next, boundIssuerID, statusKeyEpoch);
    const statusKeyID = keyIDV2(statusKey);
    if (next.statusKeyID !== "" && next.statusKeyID !== statusKeyID) {
      throw new Error("revocation push status key does not match configured epoch binding");
    }
    next.statusKeyID = statusKeyID;
    if (findStatusObservationV2(next.observations, statusKeyEpoch, PUSH, push.sequence, digest) >= 0 ||
        hasStatusPushBodyV2(next.observations, statusKeyEpoch, push.sequence, bodyDigest)) {
      return next;
    }
    const future = timestampBeyondSkewV2(push.pushed_at, now, policy.clockSkewSeconds);
    const obs: RevocationObservationV2 = {
      objectType: PUSH, statusKeyEpoch, statusKeyID, sequence: push.sequence, evidenceDigest: Uint8Array.from(digest),
      bodyDigest: Uint8Array.from(bodyDigest), revokedSetDigest: setDigest, revokedCertIDs: revokedCertIDsV2(push.revoked),
      futureDated: future, fork: false, gap: false, accepted: false,
    };
    addRevocationsV2(next, obs.revokedCertIDs);
    if (push.sequence > next.maxObservedSequence) next.maxObservedSequence = push.sequence;
    if (future) {
      next.futureDatedObjectObserved = true;
      next.reconciliationRequired = true;
    }
    if (findStatusSequenceConflictV2(next.observations, obs)) markStatusForkV2(next, obs, push.sequence);
    const conflicting = snapshotOmissionForPushV2(next, statusKeyEpoch, obs);
    if (conflicting !== 0) markStatusForkV2(next, obs, conflicting);
    const expected = next.hasFloor ? next.floor + 1 : 1;
    if (next.hasFloor && push.sequence <= next.floor) {
      if (push.sequence === next.floor) {
        if (next.hasPrecedingCheckpoint && next.precedingFloor === push.sequence - 1 &&
            !equalStringSetsV2(next.acceptedCertIDs, [...next.precedingAcceptedCertIDs, ...obs.revokedCertIDs])) {
          markStatusForkV2(next, obs, push.sequence);
        } else if (containsNovelRevocationV2(obs.revokedCertIDs, next.acceptedCertIDs)) {
          markStatusForkV2(next, obs, push.sequence);
        } else if (!obs.fork && containsAllStringSetV2(next.acceptedCertIDs, obs.revokedCertIDs)) {
          // The accepted full set already proves these entries.
        } else {
          obs.gap = true;
          next.reconciliationRequired = true;
        }
        next.observations.push(obs);
        return next;
      }
      if (containsNovelRevocationV2(obs.revokedCertIDs, next.acceptedCertIDs)) markStatusForkV2(next, obs, push.sequence);
      next.observations.push(obs);
      return next;
    }
    if (!next.hasFloor || push.sequence !== expected || next.reconciliationRequired || future) {
      obs.gap = !obs.fork;
      next.reconciliationRequired = true;
      next.observations.push(obs);
      return next;
    }
    next.acceptedCertIDs = sortedUniqueStringsV2([...next.acceptedCertIDs, ...obs.revokedCertIDs]);
    next.hasPrecedingCheckpoint = false;
    next.precedingFloor = 0;
    next.precedingAcceptedCertIDs = [];
    next.hasFloor = true;
    next.floor = push.sequence;
    obs.accepted = true;
    next.observations.push(obs);
    return next;
  });
}

/**
 * Applies an already-authenticated trust configuration transition. Issuer-wide
 * denials and prior evidence are preserved; old accepted state is unusable.
 */
export function transitionRevocationStatusEpochV2(state: RevocationStatusStateV2, issuerID: string, nextEpoch: number, nextStatusKey: HybridPublicKey): RevocationStatusStateV2 {
  try {
    if (issuerID === "" || !Number.isInteger(nextEpoch) || nextEpoch <= 0 || nextEpoch > MAX_SAFE) {
      throw new Error("status-key epoch transition has invalid issuer or epoch");
    }
    if (state.issuerID !== issuerID || state.statusKeyEpoch === 0 || state.statusKeyEpoch >= MAX_SAFE || nextEpoch !== state.statusKeyEpoch + 1) {
      throw new Error("status-key epoch transition must advance exactly one configured issuer epoch");
    }
    try {
      validateStatusStateBindingV2(state, issuerID, state.statusKeyEpoch);
    } catch (err) {
      throw new Error(`cannot transition malformed status state: ${(err as Error).message}`);
    }
    try {
      validateAcceptedStatusStateV2(state);
    } catch (err) {
      throw new Error(`cannot transition invalid accepted status state: ${(err as Error).message}`);
    }
    const statusKeyID = keyIDV2(nextStatusKey);
    if (statusKeyID === state.statusKeyID || state.retiredStatusKeyIDs.includes(statusKeyID)) {
      throw new Error("status-key epoch transition cannot reuse a current or retired status key");
    }
    const next = cloneRevocationStatusStateV2(state);
    next.retiredStatusKeyIDs = sortedUniqueStringsV2([...next.retiredStatusKeyIDs, state.statusKeyID]);
    next.statusKeyEpoch = nextEpoch;
    next.statusKeyID = statusKeyID;
    next.hasFloor = false;
    next.floor = 0;
    next.acceptedSnapshot = null;
    next.acceptedCertIDs = [];
    next.hasPrecedingCheckpoint = false;
    next.precedingFloor = 0;
    next.precedingAcceptedCertIDs = [];
    next.maxObservedSequence = 0;
    next.forkSequence = 0;
    next.reconciliationRequired = false;
    next.futureDatedObjectObserved = false;
    return next;
  } catch (err) {
    throw v2Classify("configuration_invalid", err);
  }
}

// ---------------------------------------------------------------------------
// Query and evidence selection

function sortStatusEvidenceV2(evidence: StatusEvidenceEntryV2[]): StatusEvidenceEntryV2[] {
  return evidence.sort((a, b) => {
    if (a.issuer_id !== b.issuer_id) return compareStrings(a.issuer_id, b.issuer_id);
    if (a.status_key_id !== b.status_key_id) return compareStrings(a.status_key_id, b.status_key_id);
    if (a.sequence !== b.sequence) return a.sequence - b.sequence;
    if (a.object_type_code !== b.object_type_code) return a.object_type_code - b.object_type_code;
    return compareStrings(a.digest, b.digest);
  });
}

export { sortStatusEvidenceV2 };

function sameEvidence(a: StatusEvidenceEntryV2, b: StatusEvidenceEntryV2): boolean {
  return a.issuer_id === b.issuer_id && a.status_key_id === b.status_key_id && a.sequence === b.sequence &&
    a.object_type_code === b.object_type_code && a.digest === b.digest;
}

export { sameEvidence as sameStatusEvidenceV2 };

function appendStatusEvidenceV2(evidence: StatusEvidenceEntryV2[], issuerID: string, statusKeyID: string, o: RevocationObservationV2): StatusEvidenceEntryV2[] {
  const entry: StatusEvidenceEntryV2 = {
    issuer_id: issuerID, status_key_id: o.statusKeyID !== "" ? o.statusKeyID : statusKeyID, sequence: o.sequence,
    object_type_code: o.objectType, digest: "sha384:" + hexOf(o.evidenceDigest),
  };
  if (evidence.some((p) => sameEvidence(p, entry))) return evidence;
  evidence.push(entry);
  return evidence;
}

function acceptedStatusEvidenceV2(state: RevocationStatusStateV2, issuerID: string, statusKeyID: string): StatusEvidenceEntryV2[] {
  const evidence: StatusEvidenceEntryV2[] = [];
  if (state.acceptedSnapshot === null) return evidence;
  try {
    const digest = statusEvidenceDigestV2(LIST, state.acceptedSnapshot);
    evidence.push({ issuer_id: issuerID, status_key_id: statusKeyID, sequence: state.acceptedSnapshot.sequence, object_type_code: LIST, digest: "sha384:" + hexOf(digest) });
  } catch {
    // Go omits an undigestable snapshot.
  }
  for (const o of state.observations) {
    if (o.statusKeyEpoch === state.statusKeyEpoch && o.objectType === PUSH && o.accepted &&
        o.sequence > state.acceptedSnapshot.sequence && o.sequence <= state.floor) {
      appendStatusEvidenceV2(evidence, issuerID, statusKeyID, o);
    }
  }
  return sortStatusEvidenceV2(evidence);
}

function unavailableStatusEvidenceV2(state: RevocationStatusStateV2, issuerID: string, statusKeyID: string): StatusEvidenceEntryV2[] {
  const evidence = acceptedStatusEvidenceV2(state, issuerID, statusKeyID);
  for (const o of state.observations) {
    if (o.statusKeyEpoch !== state.statusKeyEpoch) continue;
    if (o.sequence > state.floor || o.fork || o.gap || o.futureDated || (state.reconciliationRequired && !o.accepted)) {
      appendStatusEvidenceV2(evidence, issuerID, statusKeyID, o);
    }
  }
  return sortStatusEvidenceV2(evidence);
}

/** Derives a fail-closed answer and deterministic evidence for one CertificateRef. */
export async function revocationStatusForCertV2(
  state: RevocationStatusStateV2,
  issuerID: string,
  certID: string,
  statusKeyEpoch: number,
  statusKey: HybridPublicKey,
  policy: RevocationStatusPolicyV2,
  now: number,
): Promise<RevocationStatusResultV2> {
  validateRevocationStatusPolicyV2(policy);
  validateStatusStateBindingV2(state, issuerID, statusKeyEpoch);
  validateAcceptedStatusStateV2(state);
  if (certID === "" || !validV2Timestamp(now)) throw new Error("status query has invalid certificate ID or time");
  const statusKeyID = keyIDV2(statusKey);
  if (state.issuerID !== issuerID || state.statusKeyEpoch !== statusKeyEpoch || state.statusKeyID !== statusKeyID) {
    throw new Error("status query does not match the configured issuer status-key binding");
  }
  if (state.acceptedSnapshot !== null) {
    try {
      await verifyRevocationListV2Signature(state.acceptedSnapshot, issuerID, statusKey);
    } catch (err) {
      throw new Error(`accepted status snapshot signature is invalid: ${(err as Error).message}`);
    }
  }
  if (state.denyUnionCertIDs.includes(certID)) {
    let evidence = acceptedStatusEvidenceV2(state, issuerID, statusKeyID);
    for (const o of state.observations) if (o.revokedCertIDs.includes(certID)) evidence = appendStatusEvidenceV2(evidence, issuerID, statusKeyID, o);
    return { status: "revoked", reason: "", evidence: sortStatusEvidenceV2(evidence), freshUntil: 0 };
  }
  const snapshot = state.acceptedSnapshot;
  if (!state.hasFloor || snapshot === null || policy.maxListLifetimeSeconds === 0 || policy.maxStatusAgeSeconds === 0 ||
      state.futureDatedObjectObserved || state.reconciliationRequired || state.floor < state.maxObservedSequence ||
      !containsAllStringSetV2(state.acceptedCertIDs, state.denyUnionCertIDs)) {
    return { status: "indeterminate", reason: "unavailable", evidence: unavailableStatusEvidenceV2(state, issuerID, statusKeyID), freshUntil: 0 };
  }
  if (!revocationListFreshV2(snapshot, policy, now)) {
    return { status: "indeterminate", reason: "stale", evidence: acceptedStatusEvidenceV2(state, issuerID, statusKeyID), freshUntil: 0 };
  }
  return {
    status: "not_revoked", reason: "", evidence: acceptedStatusEvidenceV2(state, issuerID, statusKeyID),
    freshUntil: Math.min(snapshot.next_update, snapshot.updated_at + policy.maxStatusAgeSeconds),
  };
}
