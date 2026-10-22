// Protocol v2 claim-store boundary, single-use evaluator capability and
// terminal finalization (SPEC-v2 §6.3, §7.2 to §7.6; Go claim_store_v2.go).

import { sha256 } from "@noble/hashes/sha2";

import { buildV2RateReservationBatch, type V2DeferredConstraint, type V2RateReservation } from "./audience_v2.js";
import { challengeClaimDigestV2, protocolClaimIDV2 } from "./challenge_claim_v2.js";
import { v2ChallengeTimeCurrent } from "./clock_bounds_v2.js";
import { CONSTRAINT_MAX_RATE_V2 } from "./constraints_v2.js";
import { cloneConstraintEvaluatorRefsV2, type ConstraintEvaluatorRefV2 } from "./constraint_evaluator_v2.js";
import { classifiedAsync, errorIs, ErrV2RateLimitExceeded, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import { bytesEqual, concatBytes, hexOf, isValidUTF8, parseJSONV2, uint64BE } from "./json_v2.js";
import { bundleHashV2, constraintCanonicalJSONV2, type ProofBundleV2 } from "./protocol_v2_wire.js";
import type { V2LocalAuthorizationAssessment } from "./authorization_v2.js";
import type { V2EvaluationProgress, V2InterruptedClaim } from "./evaluation_progress_v2.js";
import {
  cloneExpectedChallengeStateV2,
  preflightStateV2,
  validateProofBundleV2Preflight,
  type ExpectedChallengeStateV2,
  type V2PreflightResult,
} from "./verify_v2_preflight.js";

/**
 * The immutable identity a verifier persists when it consumes a fresh
 * challenge. A store enforces uniqueness on (namespace, replay_epoch,
 * challenge_digest) and stores every other field as an immutable value.
 */
export interface V2ChallengeClaim {
  claimID: string;
  namespace: string;
  replayEpoch: number;
  challengeDigest: string;
  proofDigest: string;
  bundleHash: string;
  issuerIDs: string[];
  requiredScope: string;
  contextPolicyDigest: string;
  verifierID: string;
  agentID: string;
  requiresRate: boolean;
  rateBatch: V2RateReservation[];
  issuedAt: number;
  expiresAt: number;
  maxAgeSeconds: number;
  clockSkewSeconds: number;
  streamID: Uint8Array | null;
  streamSeq: number | null;
  /** The sealed extension evaluator snapshot, sorted by type. */
  constraintEvaluators: ConstraintEvaluatorRefV2[];
}

export type V2ClaimDisposition = "created" | "in_progress" | "terminal_replay";

/** A claim result. claimedAt comes from the store's authoritative clock. */
export interface V2ClaimResult {
  disposition: V2ClaimDisposition;
  claimedAt: number;
  /** Returned only to the creator; stores persist only its SHA-256 digest. */
  ownerToken: Uint8Array | null;
}

/** A Part B authoritative security clock in integer seconds. */
export interface V2AuthoritativeClock {
  authoritativeTimeV2(signal?: AbortSignal): Promise<number>;
}

/**
 * The storage boundary for challenge consumption (Go ClaimStoreV2); see
 * SPEC-v2 §7.2 to §7.5 for the exact contract of each operation. An
 * in-memory implementation is never safe for production.
 */
export interface ClaimStoreV2 extends V2AuthoritativeClock {
  claimV2(claim: V2ChallengeClaim, signal?: AbortSignal): Promise<V2ClaimResult>;
  finalizeV2Claim(claimID: string, ownerToken: Uint8Array, terminalResult: Uint8Array, receiptBody: Uint8Array,
    allowValidUntil: number, signal?: AbortSignal): Promise<boolean>;
  recordV2EvaluationProgress(claimID: string, ownerToken: Uint8Array, progress: V2EvaluationProgress, signal?: AbortSignal): Promise<void>;
  loadV2InterruptedClaim(claimID: string, signal?: AbortSignal): Promise<V2InterruptedClaim>;
  recoverInterruptedV2Claim(claimID: string, terminalResult: Uint8Array, receiptBody: Uint8Array, signal?: AbortSignal): Promise<boolean>;
}

/**
 * Atomically reserves the complete claim-sealed rate batch. An exact live
 * retry is idempotent. ErrV2RateLimitExceeded means definitive exhaustion.
 */
export interface V2RateReservationStore {
  reserveV2RateBatch(claimID: string, ownerToken: Uint8Array, bundleHash: string, batch: V2RateReservation[], signal?: AbortSignal): Promise<void>;
}

/** A store that admits the sealed rate batch atomically at finalization. */
export interface V2RateAtFinalizationStore extends ClaimStoreV2, V2RateReservationStore {
  admitsV2RateAtFinalization(): void;
}

export function isV2RateAtFinalizationStore(store: unknown): store is V2RateAtFinalizationStore {
  return !!store && typeof (store as V2RateAtFinalizationStore).admitsV2RateAtFinalization === "function" &&
    typeof (store as ClaimStoreV2).finalizeV2Claim === "function";
}

/** Exclusive challenge deadlines at an authoritative time (Go ChallengeClaimTimeCurrentV2). */
export function challengeClaimTimeCurrentV2(claim: V2ChallengeClaim, now: number): boolean {
  return v2ChallengeTimeCurrent(now, claim.issuedAt, claim.expiresAt, claim.maxAgeSeconds, claim.clockSkewSeconds);
}

/** A minimal async mutex (Go sync.Mutex across awaits). */
class AsyncMutex {
  #tail: Promise<void> = Promise.resolve();
  async lock(): Promise<() => void> {
    let release!: () => void;
    const next = new Promise<void>((r) => (release = r));
    const prior = this.#tail;
    this.#tail = prior.then(() => next);
    await prior;
    return release;
  }
}

/** @internal The single-use evaluator capability state (Go v2EvaluationTokenState). */
export interface V2EvaluationTokenState {
  claimID: string;
  proofDigest: string;
  requiredScope: string;
  futureSkew: number;
  expected: ExpectedChallengeStateV2;
  used: boolean;
  evaluationComplete: boolean;
  mutex: AsyncMutex;
  finalizationDigest: Uint8Array | null;
  finalizationStarted: boolean;
  claimTimeValid: boolean;
  claimedAt: number;
  evaluatedAt: number;
  rateBatch: V2RateReservation[];
  rateAtFinalization: boolean;
  allowValidUntil: number;
  ownerToken: Uint8Array;
  evaluationStatus: string;
  evaluationReason: string;
  pendingAssessment: V2LocalAuthorizationAssessment | null;
}

const tokenStates = new WeakMap<V2EvaluationToken, V2EvaluationTokenState>();

/**
 * Grants one local evaluation of a newly created claim. Single-use; never
 * returned for an exact retry; its state is private.
 */
export class V2EvaluationToken {
  private constructor() {}
  /** @internal */
  static create(state: V2EvaluationTokenState): V2EvaluationToken {
    const t = new V2EvaluationToken();
    tokenStates.set(t, state);
    return t;
  }
}

/** @internal */
export function tokenStateV2(token: V2EvaluationToken | null | undefined): V2EvaluationTokenState | null {
  return token ? (tokenStates.get(token) ?? null) : null;
}

/** @internal Runs fn while holding the token's finalization mutex. */
export async function withTokenLockV2<T>(state: V2EvaluationTokenState, fn: () => Promise<T> | T): Promise<T> {
  const release = await state.mutex.lock();
  try {
    return await fn();
  } finally {
    release();
  }
}

/** Seals every max_rate counter of an already verified proof (Go signedV2RateReservationBatch). */
export function signedV2RateReservationBatch(bundle: ProofBundleV2): V2RateReservation[] {
  const deferred: V2DeferredConstraint[] = [];
  (bundle.delegations ?? []).forEach((cert, i) => {
    (cert.constraints ?? []).forEach((c, j) => {
      if (c.type !== CONSTRAINT_MAX_RATE_V2) return;
      deferred.push({ delegationIndex: i, constraintIndex: j, issuerID: cert.issuer_id, certID: cert.cert_id, type: CONSTRAINT_MAX_RATE_V2, canonicalJSON: constraintCanonicalJSONV2(c) });
    });
  });
  return buildV2RateReservationBatch(deferred);
}

/** Deep copy of a claim (Go cloneV2ChallengeClaim). */
export function cloneV2ChallengeClaim(claim: V2ChallengeClaim): V2ChallengeClaim {
  return {
    ...claim,
    issuerIDs: [...claim.issuerIDs],
    rateBatch: claim.rateBatch.map((r) => ({ ...r })),
    streamID: claim.streamID === null ? null : Uint8Array.from(claim.streamID),
    constraintEvaluators: cloneConstraintEvaluatorRefsV2(claim.constraintEvaluators),
  };
}

export interface V2ClaimOutcome {
  claim: V2ChallengeClaim;
  disposition: V2ClaimDisposition;
  token: V2EvaluationToken | null;
}

/**
 * Repeats the freshness and binding checks immediately before the atomic
 * claim (Go ClaimProofBundleV2). Callers run preflight first; no trust,
 * status, or policy callback runs before this succeeds.
 */
export async function claimProofBundleV2(
  store: ClaimStoreV2,
  bundle: ProofBundleV2,
  preflight: V2PreflightResult,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
  signal?: AbortSignal,
): Promise<V2ClaimOutcome> {
  return classifiedAsync("claim_store_unavailable", async () => {
    if (!store) throw v2Errorf("configuration_invalid", "v2 claim store and context are required");
    const state = preflightStateV2(preflight);
    if (!state || (state.contextPolicy === null && !state.noContextPolicy)) {
      throw v2Errorf("configuration_invalid", "v2 successful preflight state is required before claim");
    }
    const sealed = cloneExpectedChallengeStateV2(state);
    let bundleHash: string;
    try {
      bundleHash = bundleHashV2(bundle);
    } catch {
      throw v2Errorf("configuration_invalid", "v2 proof bundle differs from successful preflight");
    }
    if (bundleHash !== sealed.bundleHash) throw v2Errorf("configuration_invalid", "v2 proof bundle differs from successful preflight");
    try {
      await validateProofBundleV2Preflight(bundle, {
        value: sealed.value, issuedAt: sealed.issuedAt, expiresAt: sealed.expiresAt,
        verifierNamespace: sealed.verifierNamespace, replayEpoch: sealed.replayEpoch, verifierID: sealed.verifierID,
        expectedAgentID: sealed.expectedAgentID, expectedAgentPublicKey: sealed.expectedAgentPublicKey,
        expectedReceiverID: sealed.expectedReceiverID, expectedSessionContext: sealed.expectedSessionContext,
        contextPolicy: sealed.contextPolicy,
      }, sealed.requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, sealed.maxAge, sealed.futureSkew);
    } catch (err) {
      throw wrapError("v2 claim-time preflight", err);
    }
    const challengeDigest = challengeClaimDigestV2(sealed.value);
    const claimID = protocolClaimIDV2(sealed.verifierNamespace, sealed.replayEpoch, sealed.value);
    const claim: V2ChallengeClaim = {
      claimID, namespace: sealed.verifierNamespace, replayEpoch: sealed.replayEpoch,
      challengeDigest: "sha384:" + hexOf(challengeDigest), proofDigest: bundleHash, bundleHash: sealed.bundleHash,
      issuerIDs: [...sealed.issuerIDs], requiredScope: sealed.requiredScope, contextPolicyDigest: sealed.contextPolicyDigest,
      verifierID: sealed.verifierID, agentID: bundle.agent_id, requiresRate: false, rateBatch: [],
      issuedAt: sealed.issuedAt, expiresAt: sealed.expiresAt, maxAgeSeconds: sealed.maxAge, clockSkewSeconds: sealed.futureSkew,
      streamID: bundle.stream_id === null ? null : Uint8Array.from(bundle.stream_id),
      streamSeq: bundle.stream_seq,
      constraintEvaluators: cloneConstraintEvaluatorRefsV2(sealed.evaluatorRefs),
    };
    try {
      claim.rateBatch = signedV2RateReservationBatch(bundle);
    } catch (err) {
      throw v2Classify("malformed", wrapError("v2 signed rate batch", err));
    }
    claim.requiresRate = claim.rateBatch.length !== 0;
    // SPEC-v2 §6.11: cancellation before the claim consumes nothing, so a
    // caller that has already cancelled never reaches the store.
    if (signal?.aborted) {
      throw v2Classify("evaluation_cancelled", wrapError("v2 claim cancelled before the store was called", signal.reason ?? new Error("cancelled")));
    }
    const result = await store.claimV2(cloneV2ChallengeClaim(claim), signal);
    switch (result?.disposition) {
      case "created": {
        if (!(result.ownerToken instanceof Uint8Array) || result.ownerToken.length !== 32) {
          throw new Error("v2 claim store returned an invalid evaluator owner token");
        }
        const claimTimeValid = v2ChallengeTimeCurrent(result.claimedAt, sealed.issuedAt, sealed.expiresAt, sealed.maxAge, sealed.futureSkew);
        const token = V2EvaluationToken.create({
          claimID: claim.claimID, proofDigest: claim.proofDigest, requiredScope: sealed.requiredScope, futureSkew: sealed.futureSkew,
          expected: sealed, used: false, evaluationComplete: false, mutex: new AsyncMutex(), finalizationDigest: null,
          finalizationStarted: false, claimTimeValid, claimedAt: result.claimedAt, evaluatedAt: 0,
          rateBatch: claim.rateBatch.map((r) => ({ ...r })), rateAtFinalization: false, allowValidUntil: 0,
          ownerToken: Uint8Array.from(result.ownerToken), evaluationStatus: "", evaluationReason: "", pendingAssessment: null,
        });
        return { claim, disposition: "created", token };
      }
      case "in_progress":
      case "terminal_replay":
        if (result.ownerToken !== null && result.ownerToken !== undefined && result.ownerToken.length !== 0) {
          throw new Error("v2 exact retry must not receive evaluator ownership");
        }
        return { claim, disposition: result.disposition, token: null };
      default:
        throw new Error("v2 claim store returned an invalid disposition");
    }
  });
}

/** Go terminalDecisionForV2Evaluation: the decision for a terminal status/reason, or null. */
export function terminalDecisionForV2Evaluation(status: string, reason: string): string | null {
  if (reason === "evaluation_interrupted") return status === "authorization_unverified" ? "indeterminate" : null;
  const ok = (decision: string, valid: boolean) => (valid ? decision : null);
  switch (status) {
    case "authorization_unverified":
      return ok("indeterminate", reason === "trust_unavailable" || reason === "action_context_unverified" || reason === "status_unavailable" || reason === "status_stale");
    case "authorized_agent":
      return ok("allow", reason === "authorized");
    case "constraint_denied": case "constraint_unverifiable": case "constraint_unknown": case "unauthorized": case "invalid_scope": case "scope_denied":
      return ok("deny", reason === status);
    case "revoked":
      return ok("deny", reason === "delegation_revoked");
    case "invalid":
      return ok("deny", reason === "proof_invalid");
    case "delegation_not_authorized":
      return ok("deny", reason === "not_delegated" || reason === "delegation_not_authorized");
    case "expired":
      return ok("deny", reason === "delegation_expired");
    default:
      return null;
  }
}

function readTerminalPayload(value: Uint8Array): [string, string] | null {
  if (!isValidUTF8(value)) return null;
  try {
    const root = parseJSONV2(value, { rejectDuplicates: true });
    if (root.k !== "obj") return null;
    const d = root.m.get("decision");
    const r = root.m.get("decision_reason");
    if (!d || !r || d.k !== "str" || r.k !== "str") return null;
    return [d.v, r.v];
  } catch {
    return null;
  }
}

/** Go terminalPayloadMatchesV2. */
export function terminalPayloadMatchesV2(terminalResult: Uint8Array, receiptBody: Uint8Array, wantDecision: string, wantReason: string): boolean {
  const a = readTerminalPayload(terminalResult);
  const b = readTerminalPayload(receiptBody);
  return a !== null && b !== null && a[0] === wantDecision && b[0] === wantDecision && a[1] === wantReason && b[1] === wantReason;
}

function v2FinalizationPayloadDigest(terminalResult: Uint8Array, receiptBody: Uint8Array): Uint8Array {
  return sha256(concatBytes(uint64BE(terminalResult.length), terminalResult, uint64BE(receiptBody.length), receiptBody));
}

/**
 * Commits a terminal local evaluation through the capability that won the
 * claim (Go FinalizeClaimProofBundleV2). An ambiguous store failure can be
 * retried only with the identical result and receipt body.
 */
export async function finalizeClaimProofBundleV2(
  store: ClaimStoreV2,
  token: V2EvaluationToken,
  terminalResult: Uint8Array,
  receiptBody: Uint8Array,
  signal?: AbortSignal,
): Promise<boolean> {
  return classifiedAsync("claim_store_unavailable", async () => {
    const state = tokenStateV2(token);
    if (!store || !state || state.ownerToken.length !== 32 || state.claimID === "") {
      throw v2Errorf("configuration_invalid", "v2 claim store and valid evaluator capability are required");
    }
    const terminal = Uint8Array.from(terminalResult);
    const body = Uint8Array.from(receiptBody);
    if (signal?.aborted) throw v2Classify("evaluation_cancelled", signal.reason ?? new Error("cancelled"));
    return withTokenLockV2(state, async () => {
      if (!state.evaluationComplete) throw v2Errorf("configuration_invalid", "v2 proof evaluation has not completed");
      const decision = terminalDecisionForV2Evaluation(state.evaluationStatus, state.evaluationReason);
      if (decision === null) throw v2Errorf("configuration_invalid", "v2 proof evaluation has not reached a terminal local result");
      if (!terminalPayloadMatchesV2(terminal, body, decision, state.evaluationReason)) {
        throw v2Errorf("configuration_invalid", "v2 terminal result does not match the completed local evaluation");
      }
      if ((decision === "allow" && state.allowValidUntil <= 0) || (decision !== "allow" && state.allowValidUntil !== 0)) {
        throw v2Errorf("configuration_invalid", "v2 terminal result lacks a valid allow freshness horizon");
      }
      if (state.rateAtFinalization && !isV2RateAtFinalizationStore(store)) {
        throw v2Errorf("configuration_invalid", "v2 rate-at-finalization requires an atomic rate store");
      }
      const digest = v2FinalizationPayloadDigest(terminal, body);
      if (state.finalizationStarted && !bytesEqual(state.finalizationDigest, digest)) {
        throw v2Errorf("configuration_invalid", "v2 evaluator capability cannot change its terminal result or receipt body");
      }
      state.finalizationStarted = true;
      state.finalizationDigest = digest;
      try {
        return await store.finalizeV2Claim(state.claimID, Uint8Array.from(state.ownerToken), terminal, body, state.allowValidUntil, signal);
      } catch (err) {
        if (state.rateAtFinalization && decision === "allow" && err === ErrV2RateLimitExceeded && isV2RateAtFinalizationStore(store)) {
          state.evaluationStatus = "constraint_denied";
          state.evaluationReason = "constraint_denied";
          state.allowValidUntil = 0;
          state.rateAtFinalization = false;
          state.finalizationStarted = false;
          state.finalizationDigest = null;
        }
        throw err;
      }
    });
  });
}
