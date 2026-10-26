// In-memory REFERENCE implementation of the Ratify Protocol v2 Part B
// deployment interfaces (Go v2reference/store.go): claim store with stream
// sequence and evaluation progress, authoritative clock with a high-water
// mark, receipt outbox and publisher, independent checkpoint, and optional
// rate admission at finalization.
//
// FOR TESTS AND CONFORMANCE SCENARIOS ONLY. Nothing here is durable,
// survives a restart, spans processes, or provides an independent failure
// domain. It must never be offered as a default or used to release decisions
// in production.

import { sha256 } from "@noble/hashes/sha2";

import type { V2RateReservation } from "../audience_v2.js";
import {
  challengeClaimTimeCurrentV2,
  validateV2FinalizationPayload,
  type ClaimStoreV2,
  type V2ChallengeClaim,
  type V2ClaimResult,
  type V2RateAtFinalizationStore,
} from "../claim_store_v2.js";
import type { V2CheckpointAcknowledgement } from "../checkpoint_ack_v2.js";
import { keyIDV2 } from "../crypto_v2.js";
import type { HybridKeyPairV2 } from "../crypto_v2.js";
import { ErrV2ClaimProofConflict, ErrV2RateLimitExceeded, V2Error, V2SentinelError } from "../errors_v2.js";
import { cloneV2EvaluationProgress, initialV2EvaluationProgress, validateV2EvaluationProgress, type V2EvaluationProgress, type V2InterruptedClaim } from "../evaluation_progress_v2.js";
import { base64Encode, bytesEqual, canonicalJSONV2, compareBytes, compareStrings, hexOf, parseJSONV2 } from "../json_v2.js";
import {
  ErrV2AcknowledgementNotFound,
  ErrV2ReleaseStateMismatch,
  receiptOutboxDigestV2,
  validV2ReleaseRecordOutcome,
  type V2ReceiptCheckpoint,
  type V2ReceiptPublisher,
  type V2ReleaseClaimStore,
  type V2ReleaseRecord,
  type V2TerminalClaimRecord,
} from "../release_v2.js";
import { protocolClaimIDFromDigestV2 } from "../challenge_claim_v2.js";
import { V2_MAX_TIMESTAMP_SECONDS } from "../clock_bounds_v2.js";
import { checkV2StreamSequence } from "../stream_sequence_v2.js";
import {
  decodeVerificationReceiptBodyV2,
  encodeVerificationReceiptV2,
  signPreparedVerificationReceiptV2,
  verificationReceiptV2Digest,
  type ReceiptV2Head,
} from "../verification_receipt_v2.js";

export const ErrNotAcknowledgedTestOnly = new V2SentinelError("v2reference: checkpoint refused the acknowledgement");
export const ErrHeadOfLineBlockedTestOnly = new V2SentinelError("v2reference: an earlier receipt-log entry is still pending");
export const ErrSignerUnavailableTestOnly = new V2SentinelError("v2reference: receipt signer unavailable");
export const ErrLogFrozenTestOnly = new V2SentinelError("v2reference: the receipt log is frozen after abandonment");

type ClaimState = "evaluating" | "terminal";

interface ClaimRecord {
  claim: V2ChallengeClaim;
  ownerDigest: Uint8Array;
  leaseExpiresAt: number;
  state: ClaimState;
  terminal: Uint8Array;
  receiptBody: Uint8Array;
  allowHorizon: number;
  claimedAt: number;
  finalizedAt: number;
  release: V2ReleaseRecord | null;
  progress: V2EvaluationProgress;
  abandoned: boolean;
  outboxIndex: number;
}

interface OutboxEntry {
  claimID: string;
  body: Uint8Array;
  wire: Uint8Array | null;
  digest: Uint8Array;
  ack: V2CheckpointAcknowledgement | null;
}

/** Member digests of a store's durable state (single-device profile). */
export interface StoreStateTestOnly {
  claims: string;
  streams: string;
  rateCounters: string;
  receiptLog: string;
}

/** A serializing async mutex: every store operation is one atomic step. */
export class MutexTestOnly {
  #tail: Promise<void> = Promise.resolve();
  async run<T>(fn: () => Promise<T> | T): Promise<T> {
    let release!: () => void;
    const next = new Promise<void>((r) => (release = r));
    const prior = this.#tail;
    this.#tail = prior.then(() => next);
    await prior;
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

const storeError = (cls: V2Error["v2Class"], message: string, cause?: unknown) => new V2Error(cls, message, cause);

/**
 * Whether the claim ID is the stable claim ID of the claim's (namespace,
 * replay_epoch, ChallengeClaimDigest) key (SPEC-v2 §2.4, §7.3). The store is
 * keyed by claim ID, so a supplied ID that is not derived from that key could
 * create a second claim for one challenge.
 */
function claimIDMatchesKey(claim: V2ChallengeClaim | null | undefined): boolean {
  const match = /^sha384:([0-9a-f]{96})$/.exec(typeof claim?.challengeDigest === "string" ? claim.challengeDigest : "");
  if (!claim || !match) return false;
  const digest = Uint8Array.from(match[1]!.match(/../g)!, (h) => parseInt(h, 16));
  try {
    return protocolClaimIDFromDigestV2(claim.namespace, claim.replayEpoch, digest) === claim.claimID;
  } catch {
    return false;
  }
}

function cloneClaim(c: V2ChallengeClaim): V2ChallengeClaim {
  return {
    ...c, issuerIDs: [...c.issuerIDs], rateBatch: c.rateBatch.map((r) => ({ ...r })),
    streamID: c.streamID === null ? null : Uint8Array.from(c.streamID), constraintEvaluators: c.constraintEvaluators.map((r) => ({ ...r })),
  };
}

/** A deterministic encoding of every immutable claim field. */
export function claimBytesTestOnly(c: V2ChallengeClaim): Uint8Array {
  return canonicalJSONV2({
    agent_id: c.agentID, bundle_hash: c.bundleHash, challenge_digest: c.challengeDigest, claim_id: c.claimID,
    clock_skew_seconds: c.clockSkewSeconds, constraint_evaluators: c.constraintEvaluators.map((r) => ({ profile_digest: r.profile_digest, type: r.type })),
    context_policy_digest: c.contextPolicyDigest, expires_at: c.expiresAt, issued_at: c.issuedAt, issuer_ids: c.issuerIDs,
    max_age_seconds: c.maxAgeSeconds, namespace: c.namespace, proof_digest: c.proofDigest,
    rate_batch: c.rateBatch.map((r) => ({ cert_id: r.certID, issuer_id: r.issuerID, limit: r.limit, window_s: r.windowS })),
    replay_epoch: c.replayEpoch, required_scope: c.requiredScope, requires_rate: c.requiresRate,
    stream_id: c.streamID, stream_seq: c.streamSeq, verifier_id: c.verifierID,
  });
}

/**
 * Durable stream state, keyed by (namespace, agent_id, stream_id) (SPEC-v2
 * §7.4); streamID holds the raw stream ID bytes.
 */
export interface StreamStateTestOnly {
  namespace: string;
  agentID: string;
  streamID: Uint8Array;
  lastSequence: number;
}

/** An injective map key for the structured stream key. */
export function streamKeyTestOnly(namespace: string, agentID: string, streamID: Uint8Array): string {
  return JSON.stringify([namespace, agentID, hexOf(streamID)]);
}

/** The structured key of a claim's stream (Go streamKeyV2). */
function streamKey(c: V2ChallengeClaim): string {
  return streamKeyTestOnly(c.namespace, c.agentID, c.streamID ?? new Uint8Array(0));
}

export const rateKeyOf = (issuerID: string, certID: string, windowS: number) => JSON.stringify([issuerID, certID, windowS]);

/** Options for a reference store. */
export interface StoreOptionsTestOnly {
  /** The ML-DSA mode of the reference receipt signer (deterministic only for fixed vectors). */
  deterministicSigner?: boolean;
  /** Source of evaluator owner tokens (tests only). */
  ownerTokenSource?: () => Uint8Array;
}

/**
 * The reference Part B store (Go v2reference.Store). Every operation runs
 * under one mutex, which makes the claim and its stream advance one atomic
 * step, and terminal commit and outbox sequence assignment another.
 */
export class StoreTestOnly implements ClaimStoreV2, V2ReleaseClaimStore, V2ReceiptPublisher, V2ReceiptCheckpoint {
  readonly mutex = new MutexTestOnly();
  private nowSeconds: number;
  highWater: number;
  readonly leaseSeconds: number;
  claims = new Map<string, ClaimRecord>();
  streams = new Map<string, StreamStateTestOnly>();
  readonly verifierKey: HybridKeyPairV2;
  readonly verifierID: string;
  readonly logID: string;
  outbox: OutboxEntry[] = [];
  ackWithheld = false;
  logFrozen = false;
  checkpointFrozen = false;
  signerFailure = false;
  rateAtFinalization = false;
  rateCommits = new Map<string, { issuerID: string; certID: string; windowS: number; times: number[] }>();
  readonly options: StoreOptionsTestOnly;
  /** Set by a single-device primary: anchors every durable change before it takes effect. */
  anchor: ((previous: StoreStateTestOnly, next: StoreStateTestOnly) => void) | null = null;

  constructor(now: number, leaseSeconds: number, logID: string, verifierKey: HybridKeyPairV2, options: StoreOptionsTestOnly = {}) {
    if (!(leaseSeconds > 0) || logID.length !== 32) throw new Error("v2reference: lease must be positive and log ID 32 hex characters");
    this.nowSeconds = now;
    this.highWater = now;
    this.leaseSeconds = leaseSeconds;
    this.logID = logID;
    this.verifierKey = verifierKey;
    this.verifierID = keyIDV2(verifierKey.publicKey);
    this.options = options;
  }

  /** An independent copy of the complete state (a restore equal to the anchored state). */
  clone(): StoreTestOnly {
    const out = new StoreTestOnly(this.nowSeconds, this.leaseSeconds, this.logID, this.verifierKey, this.options);
    this.copyStateInto(out);
    return out;
  }

  copyStateInto(out: StoreTestOnly): void {
    out.nowSeconds = this.nowSeconds;
    out.highWater = this.highWater;
    out.ackWithheld = this.ackWithheld;
    out.logFrozen = this.logFrozen;
    out.checkpointFrozen = this.checkpointFrozen;
    out.signerFailure = this.signerFailure;
    out.rateAtFinalization = this.rateAtFinalization;
    out.claims = new Map([...this.claims].map(([id, r]) => [id, {
      ...r, claim: cloneClaim(r.claim), terminal: Uint8Array.from(r.terminal), receiptBody: Uint8Array.from(r.receiptBody),
      progress: cloneV2EvaluationProgress(r.progress), release: r.release ? { ...r.release, entryHash: Uint8Array.from(r.release.entryHash) } : null,
    }]));
    out.streams = new Map([...this.streams].map(([k, v]) => [k, { ...v, streamID: Uint8Array.from(v.streamID) }]));
    out.outbox = this.outbox.map((e) => ({
      claimID: e.claimID, body: Uint8Array.from(e.body), wire: e.wire ? Uint8Array.from(e.wire) : null, digest: Uint8Array.from(e.digest),
      ack: e.ack ? { ...e.ack, entryHash: Uint8Array.from(e.ack.entryHash) } : null,
    }));
    out.rateCommits = new Map([...this.rateCommits].map(([k, v]) => [k, { ...v, times: [...v.times] }]));
  }

  /** Applies mutate as one durable change, anchored first when bound to a device. */
  change(mutate: () => void): void {
    if (this.anchor === null) {
      mutate();
      return;
    }
    const before = this.clone();
    let err: unknown = null;
    try {
      const previous = this.stateDigests();
      mutate();
      this.anchor(previous, this.stateDigests());
    } catch (e) {
      err = e;
    }
    if (err !== null) {
      this.claims = before.claims;
      this.streams = before.streams;
      this.outbox = before.outbox;
      this.rateCommits = before.rateCommits;
      this.logFrozen = before.logFrozen;
      throw storeError("claim_store_unavailable", `v2reference: durable state change was not anchored: ${(err as Error)?.message ?? err}`, err);
    }
  }

  /** Sets the authoritative clock (tests may move it backward). */
  setTime(now: number): void {
    this.nowSeconds = now;
  }

  /**
   * The store's current clock setting, without taking an authoritative
   * reading (for test harnesses that derive request times). Move the clock
   * with setTime.
   */
  now(): number {
    return this.nowSeconds;
  }

  /** Makes the reference receipt signer fail (or recover). */
  setSignerFailure(failing: boolean): void {
    this.signerFailure = failing;
  }

  /** Stops (or resumes) checkpoint acknowledgement; resuming acknowledges pending entries in order. */
  setAcknowledgementWithheld(withheld: boolean): void {
    this.ackWithheld = withheld;
    if (!withheld) this.acknowledgePending();
  }

  /**
   * Submits every appended, unacknowledged entry to the reference checkpoint
   * in log order. Acknowledgements are timestamped by one authoritative
   * reading (SPEC-v2 §7.2), which advances the high-water mark; while the
   * clock is regressed nothing is acknowledged.
   */
  private acknowledgePending(): void {
    if (this.checkpointFrozen) return;
    let now = 0;
    let read = false;
    for (let i = 0; i < this.outbox.length; i++) {
      const e = this.outbox[i]!;
      if (e.wire === null) return;
      if (e.ack !== null) continue;
      if (!read) {
        try {
          now = this.readClock();
        } catch {
          return;
        }
        read = true;
      }
      e.ack = { logID: this.logID, sequence: i + 1, entryHash: Uint8Array.from(e.digest), timestamp: now };
    }
  }

  /** The number of appended (signed) receipts. */
  logLength(): number {
    let n = 0;
    while (n < this.outbox.length && this.outbox[n]!.wire !== null) n++;
    return n;
  }

  /** One authoritative reading; a reading below the high-water mark is a regression. */
  readClock(): number {
    if (this.nowSeconds < this.highWater) {
      throw storeError("clock_regressed", `v2reference: authoritative clock ${this.nowSeconds} is below its high-water mark ${this.highWater}`);
    }
    this.highWater = this.nowSeconds;
    return this.nowSeconds;
  }

  async authoritativeTimeV2(): Promise<number> {
    return this.mutex.run(() => this.readClock());
  }

  async claimV2(claim: V2ChallengeClaim): Promise<V2ClaimResult> {
    return this.mutex.run(() => {
      if (!claimIDMatchesKey(claim)) {
        throw storeError("configuration_invalid", "v2reference: claim ID is not derived from the claim's namespace, replay epoch and challenge digest");
      }
      let now: number;
      try {
        now = this.readClock();
      } catch (err) {
        throw storeError("claim_store_unavailable", (err as Error).message, err);
      }
      const existing = this.claims.get(claim.claimID);
      if (existing) {
        if (!bytesEqual(claimBytesTestOnly(existing.claim), claimBytesTestOnly(claim))) throw ErrV2ClaimProofConflict;
        if (existing.abandoned) {
          throw storeError("receipt_abandoned", "v2reference: the receipt for this claim was abandoned; a fresh challenge is required");
        }
        return { disposition: existing.state === "terminal" ? "terminal_replay" : "in_progress", claimedAt: existing.claimedAt, ownerToken: null };
      }
      if (!challengeClaimTimeCurrentV2(claim, now)) {
        throw storeError("challenge_not_fresh", "v2reference: challenge is not current at the store clock");
      }
      let key = "";
      if (claim.streamID !== null || claim.streamSeq !== null) {
        if (claim.streamID === null || claim.streamSeq === null) {
          throw storeError("malformed", "v2reference: stream_id and stream_seq must appear together");
        }
        key = streamKey(claim);
        const last = this.streams.get(key)?.lastSequence;
        checkV2StreamSequence(last !== undefined, last ?? 0, claim.streamSeq);
      }
      const owner = this.options.ownerTokenSource ? Uint8Array.from(this.options.ownerTokenSource()) : globalThis.crypto.getRandomValues(new Uint8Array(32));
      this.change(() => {
        if (key !== "") {
          this.streams.set(key, { namespace: claim.namespace, agentID: claim.agentID, streamID: Uint8Array.from(claim.streamID!), lastSequence: claim.streamSeq! });
        }
        this.claims.set(claim.claimID, {
          claim: cloneClaim(claim), ownerDigest: sha256(owner), leaseExpiresAt: now + this.leaseSeconds, state: "evaluating",
          terminal: new Uint8Array(0), receiptBody: new Uint8Array(0), allowHorizon: 0, claimedAt: now, finalizedAt: 0, release: null,
          progress: initialV2EvaluationProgress(), abandoned: false, outboxIndex: -1,
        });
      });
      return { disposition: "created", claimedAt: now, ownerToken: owner };
    });
  }

  /** The evaluator capability of a live, evaluating claim. Throws a classified error. */
  private owner(claimID: string, ownerToken: Uint8Array): { record: ClaimRecord; now: number } {
    const record = this.claims.get(claimID);
    if (!record) throw storeError("claim_not_found", "v2reference: unknown claim");
    if (!constantTimeEqual(sha256(ownerToken), record.ownerDigest)) throw storeError("claim_lease_lost", "v2reference: evaluator owner mismatch");
    // The error carries no store state: it reaches callers through the
    // verify outcome, and the committed record is immutable (SPEC-v2 §7.3).
    if (record.state === "terminal") throw storeError("claim_already_terminal", "v2reference: claim already terminal");
    const now = this.readClock();
    if (now < record.claimedAt) throw storeError("clock_regressed", `v2reference: clock ${now} is before T_claim ${record.claimedAt}`);
    if (now >= record.leaseExpiresAt) throw storeError("claim_lease_lost", "v2reference: evaluator lease expired");
    return { record, now };
  }

  private commitTerminal(record: ClaimRecord, terminal: Uint8Array, body: Uint8Array, allowHorizon: number, finalAt: number): void {
    record.state = "terminal";
    record.terminal = Uint8Array.from(terminal);
    record.receiptBody = Uint8Array.from(body);
    record.allowHorizon = allowHorizon;
    record.finalizedAt = finalAt;
    record.outboxIndex = this.outbox.length;
    this.outbox.push({ claimID: record.claim.claimID, body: Uint8Array.from(body), wire: null, digest: new Uint8Array(0), ack: null });
  }

  async finalizeV2Claim(claimID: string, ownerToken: Uint8Array, terminalResult: Uint8Array, receiptBody: Uint8Array, allowValidUntil: number): Promise<boolean> {
    return this.mutex.run(() => {
      let owned;
      try {
        owned = this.owner(claimID, ownerToken);
      } catch (err) {
        const record = err instanceof V2Error && err.v2Class === "claim_already_terminal" ? this.claims.get(claimID) : undefined;
        if (record && record.state === "terminal" && bytesEqual(record.terminal, terminalResult) && bytesEqual(record.receiptBody, receiptBody)) return false;
        throw err;
      }
      const { record, now: finalAt } = owned;
      validateV2FinalizationPayload(record.claim, terminalResult, receiptBody);
      // SPEC-v2 §6.8: an allow carries a positive allow horizon and every
      // other decision carries none, so the horizon and the rate admission
      // below always apply to exactly the allows.
      const decision = decodeVerificationReceiptBodyV2(receiptBody).decision;
      if (decision === "allow" ? !(allowValidUntil > 0 && allowValidUntil <= V2_MAX_TIMESTAMP_SECONDS) : allowValidUntil !== 0) {
        throw storeError("configuration_invalid", "v2reference: the allow horizon does not match the decision");
      }
      if (allowValidUntil > 0 && (finalAt >= allowValidUntil || finalAt >= record.claim.expiresAt)) {
        throw storeError("allow_horizon_passed", "v2reference: allow is at or beyond its horizon");
      }
      const admitRate = allowValidUntil > 0 && this.rateAtFinalization && record.claim.rateBatch.length !== 0;
      if (admitRate) {
        for (const item of record.claim.rateBatch) {
          const times = this.rateCommits.get(rateKeyOf(item.issuerID, item.certID, item.windowS))?.times ?? [];
          const active = times.filter((at) => at > finalAt - item.windowS).length;
          if (active >= item.limit) throw ErrV2RateLimitExceeded;
        }
      }
      this.change(() => {
        if (admitRate) {
          for (const item of record.claim.rateBatch) {
            const k = rateKeyOf(item.issuerID, item.certID, item.windowS);
            const entry = this.rateCommits.get(k) ?? { issuerID: item.issuerID, certID: item.certID, windowS: item.windowS, times: [] };
            entry.times.push(finalAt);
            this.rateCommits.set(k, entry);
          }
        }
        this.commitTerminal(record, terminalResult, receiptBody, allowValidUntil, finalAt);
      });
      return true;
    });
  }

  async recordV2EvaluationProgress(claimID: string, ownerToken: Uint8Array, progress: V2EvaluationProgress): Promise<void> {
    return this.mutex.run(() => {
      const { record } = this.owner(claimID, ownerToken);
      try {
        validateV2EvaluationProgress(progress);
      } catch (err) {
        throw storeError("malformed", (err as Error).message, err);
      }
      this.change(() => {
        record.progress = cloneV2EvaluationProgress(progress);
      });
    });
  }

  async loadV2InterruptedClaim(claimID: string): Promise<V2InterruptedClaim> {
    return this.mutex.run(() => {
      const record = this.claims.get(claimID);
      if (!record) throw storeError("claim_not_found", "v2reference: unknown claim");
      const now = this.readClock();
      if (record.state === "evaluating" && now < record.leaseExpiresAt) throw storeError("claim_lease_live", "v2reference: evaluator lease is still live");
      return { claim: cloneClaim(record.claim), claimedAt: record.claimedAt, progress: cloneV2EvaluationProgress(record.progress) };
    });
  }

  async recoverInterruptedV2Claim(claimID: string, terminalResult: Uint8Array, receiptBody: Uint8Array): Promise<boolean> {
    return this.mutex.run(() => {
      const record = this.claims.get(claimID);
      if (!record) throw storeError("claim_not_found", "v2reference: unknown claim");
      if (record.state === "terminal") {
        if (bytesEqual(record.terminal, terminalResult) && bytesEqual(record.receiptBody, receiptBody)) return false;
        throw storeError("claim_already_terminal", "v2reference: claim already terminal");
      }
      const now = this.readClock();
      if (now < record.leaseExpiresAt) throw storeError("claim_lease_live", "v2reference: evaluator lease is still live");
      // Validated exactly as finalization (SPEC-v2 §7.5): malformed or
      // configuration_invalid, committing nothing.
      validateV2FinalizationPayload(record.claim, terminalResult, receiptBody);
      let fields: { decision?: string; reason?: string } = {};
      try {
        const root = parseJSONV2(terminalResult);
        if (root.k === "obj") {
          const d = root.m.get("decision");
          const r = root.m.get("decision_reason");
          fields = { decision: d?.k === "str" ? d.v : undefined, reason: r?.k === "str" ? r.v : undefined };
        }
      } catch {
        fields = {};
      }
      if (fields.decision !== "indeterminate" || fields.reason !== "evaluation_interrupted") {
        throw storeError("configuration_invalid", "v2reference: recovery may commit only indeterminate/evaluation_interrupted");
      }
      this.change(() => this.commitTerminal(record, terminalResult, receiptBody, 0, now));
      return true;
    });
  }

  async loadV2TerminalClaim(claimID: string): Promise<V2TerminalClaimRecord> {
    return this.mutex.run(() => {
      const record = this.claims.get(claimID);
      if (!record) throw storeError("claim_not_found", "v2reference: unknown claim");
      const terminal = record.state === "terminal";
      return {
        terminal, receiptOutboxDigest: terminal ? receiptOutboxDigestV2(record.receiptBody) : "", challengeExpiresAt: record.claim.expiresAt,
        allowHorizon: record.allowHorizon, finalizedAt: record.finalizedAt, receiptAbandoned: record.abandoned,
        release: record.release ? { ...record.release, entryHash: Uint8Array.from(record.release.entryHash) } : null,
      };
    });
  }

  /**
   * Records a release or a withheld result (SPEC-v2 §6.9): the first record
   * for a claim wins, an identical repeat is a no-op, and any different
   * record is ErrV2ReleaseStateMismatch. A new record is a durable
   * security-state change, anchored like any other.
   */
  async recordV2Release(release: V2ReleaseRecord): Promise<void> {
    return this.mutex.run(() => {
      if (!validV2ReleaseRecordOutcome(release.outcome, release.reason)) {
        throw storeError("configuration_invalid", `v2reference: invalid release record outcome ${JSON.stringify(release.outcome)} reason ${JSON.stringify(release.reason)}`);
      }
      const record = this.claims.get(release.claimID);
      if (!record || record.state !== "terminal") throw ErrV2ReleaseStateMismatch;
      if (record.release !== null) {
        if (bytesEqual(record.release.entryHash, release.entryHash) && record.release.ackTimestamp === release.ackTimestamp &&
            record.release.outcome === release.outcome && record.release.reason === release.reason) return;
        throw ErrV2ReleaseStateMismatch;
      }
      const copy: V2ReleaseRecord = {
        claimID: release.claimID, entryHash: Uint8Array.from(release.entryHash), ackTimestamp: release.ackTimestamp,
        outcome: release.outcome, reason: release.reason,
      };
      this.change(() => {
        record.release = copy;
      });
    });
  }

  /** Writes a release record directly into primary storage, bypassing release and anchoring. */
  plantReleaseTestOnly(claimID: string, ackTimestamp: number): void {
    const record = this.claims.get(claimID);
    if (record && record.outboxIndex >= 0 && this.outbox[record.outboxIndex]!.wire !== null) {
      record.release = { claimID, entryHash: Uint8Array.from(this.outbox[record.outboxIndex]!.digest), ackTimestamp, outcome: "released", reason: "" };
    }
  }

  /** Flips one bit of a claim's sealed terminal result in primary storage. */
  corruptSealedStateTestOnly(claimID: string): void {
    const record = this.claims.get(claimID);
    if (record && record.terminal.length > 0) {
      record.terminal = Uint8Array.from(record.terminal);
      record.terminal[0]! ^= 1;
    }
  }

  /** The digest of the appended entry at sequence, or null. */
  appendedEntry(sequence: number): Uint8Array | null {
    if (sequence < 1 || sequence > this.outbox.length || this.outbox[sequence - 1]!.wire === null) return null;
    return Uint8Array.from(this.outbox[sequence - 1]!.digest);
  }

  async publishV2Receipt(claimID: string, receiptBody: Uint8Array): Promise<Uint8Array> {
    return this.mutex.run(async () => {
      const record = this.claims.get(claimID);
      if (!record || record.state !== "terminal" || !bytesEqual(record.receiptBody, receiptBody)) {
        throw new Error("v2reference: no committed outbox body for this claim matches");
      }
      const index = record.outboxIndex;
      const entry = this.outbox[index]!;
      if (entry.wire !== null) return Uint8Array.from(entry.wire);
      if (this.logFrozen) throw ErrLogFrozenTestOnly;
      if (index > 0 && this.outbox[index - 1]!.wire === null) throw ErrHeadOfLineBlockedTestOnly;
      if (this.signerFailure) throw ErrSignerUnavailableTestOnly;
      const head: ReceiptV2Head = {
        logID: this.logID, verifierID: this.verifierID, sequence: index, headHash: new Uint8Array(48), acceptedDigests: new Map(), frozen: false,
      };
      for (let i = 0; i < index; i++) head.acceptedDigests.set(i + 1, Uint8Array.from(this.outbox[i]!.digest));
      if (index > 0) head.headHash = Uint8Array.from(this.outbox[index - 1]!.digest);
      const receipt = await signPreparedVerificationReceiptV2(receiptBody, head, this.verifierKey, { deterministic: this.options.deterministicSigner === true });
      const wire = encodeVerificationReceiptV2(receipt);
      const digest = verificationReceiptV2Digest(receipt);
      this.change(() => {
        entry.wire = wire;
        entry.digest = digest;
      });
      if (!this.ackWithheld) this.acknowledgePending();
      return Uint8Array.from(wire);
    });
  }

  /**
   * Accepts only the next appended entry of the log, linked by
   * previousEntryHash, and returns the original acknowledgement for an
   * identical retry. A different entry hash at an acknowledged sequence is a
   * fork (SPEC-v2 §7.8): it is refused and freezes the log, after which the
   * checkpoint acknowledges nothing further for it, neither here nor from the
   * publisher's submissions. Identical retries of acknowledgements made
   * before the fork still return the original acknowledgement.
   */
  async acknowledgeV2Receipt(logID: string, sequence: number, previousEntryHash: Uint8Array, entryHash: Uint8Array): Promise<V2CheckpointAcknowledgement> {
    return this.mutex.run(() => {
      const entry = this.outbox[sequence - 1];
      if (logID !== this.logID || sequence < 1 || !entry) throw ErrNotAcknowledgedTestOnly;
      if (entry.ack !== null && !bytesEqual(entry.ack.entryHash, entryHash)) {
        this.checkpointFrozen = true;
        throw new Error(`v2reference: a different entry hash at acknowledged sequence ${sequence} is a fork; the log is frozen`, { cause: ErrNotAcknowledgedTestOnly });
      }
      if (this.checkpointFrozen && entry.ack === null) {
        throw new Error("v2reference: the log is frozen after a fork", { cause: ErrNotAcknowledgedTestOnly });
      }
      if (entry.wire === null || !bytesEqual(entry.digest, entryHash)) throw ErrNotAcknowledgedTestOnly;
      let previous: Uint8Array = new Uint8Array(48);
      if (sequence > 1) {
        const prior = this.outbox[sequence - 2]!;
        previous = prior.digest;
        if (prior.ack === null) throw ErrNotAcknowledgedTestOnly;
      }
      if (!bytesEqual(previous, previousEntryHash)) throw ErrNotAcknowledgedTestOnly;
      if (entry.ack === null) {
        const now = this.readClock();
        if (now < 0 || now > V2_MAX_TIMESTAMP_SECONDS) {
          throw new Error(`v2reference: checkpoint time ${now} is outside the timestamp domain`, { cause: ErrNotAcknowledgedTestOnly });
        }
        entry.ack = { logID, sequence, entryHash: Uint8Array.from(entryHash), timestamp: now };
      }
      return { ...entry.ack, entryHash: Uint8Array.from(entry.ack.entryHash) };
    });
  }

  async getV2Acknowledgement(logID: string, sequence: number): Promise<V2CheckpointAcknowledgement> {
    return this.mutex.run(() => {
      const entry = this.outbox[sequence - 1];
      if (logID !== this.logID || sequence < 1 || !entry || entry.ack === null) throw ErrV2AcknowledgementNotFound;
      return { ...entry.ack, entryHash: Uint8Array.from(entry.ack.entryHash) };
    });
  }

  /**
   * The reference receipt-abandonment procedure (SPEC-v2 §7.7): freezes the
   * log and marks every claim whose outbox entry was not yet appended as
   * receipt_abandoned. Returns the abandoned claim IDs in log order.
   */
  async abandonPendingReceipts(): Promise<string[]> {
    return this.mutex.run(() => {
      const abandoned: string[] = [];
      try {
        this.change(() => {
          this.logFrozen = true;
          for (const entry of this.outbox) {
            if (entry.wire === null) {
              this.claims.get(entry.claimID)!.abandoned = true;
              abandoned.push(entry.claimID);
            }
          }
        });
      } catch {
        return [];
      }
      return abandoned;
    });
  }

  /**
   * Enables rate admission at finalization and returns the view that
   * advertises it. This is the single-store max_rate implementation of
   * SPEC-v2 §7.6.
   */
  withRateAtFinalization(): RateAtFinalizationStoreTestOnly {
    this.rateAtFinalization = true;
    return new RateAtFinalizationStoreTestOnly(this);
  }

  /**
   * The RatifyCanonicalJSON of the claims, streams, rate_counters, and
   * receipt_log members in the normative record encodings of SPEC-v2 §7.13:
   * every claim in every state with its sealed values and release record,
   * every stream sequence, every rate counter, and the receipt log with its
   * outbox. Checkpoint acknowledgements and clock readings are excluded.
   */
  storeMembers(): { claims: Uint8Array; streams: Uint8Array; rateCounters: Uint8Array; receiptLog: Uint8Array } {
    const claims = [...this.claims.keys()].sort(compareStrings).map((id) => claimProjection(id, this.claims.get(id)!));
    const streams = [...this.streams.values()]
      .sort((a, b) => compareStrings(a.namespace, b.namespace) || compareStrings(a.agentID, b.agentID) || compareBytes(a.streamID, b.streamID))
      .map((v) => ({ agent_id: v.agentID, last_sequence: v.lastSequence, namespace: v.namespace, stream_id: base64Encode(v.streamID) }));
    const rates = [...this.rateCommits.values()]
      .sort((a, b) => compareStrings(a.issuerID, b.issuerID) || compareStrings(a.certID, b.certID) || a.windowS - b.windowS)
      .map((v) => ({ cert_id: v.certID, commits: [...v.times], issuer_id: v.issuerID, window_s: v.windowS }));
    const log = {
      entries: this.outbox.map((e, i) => ({ body_sha384: sha384Hex(e.body), claim_id: e.claimID, entry_hash: bytesOrNull(e.digest), sequence: i + 1 })),
      frozen: this.logFrozen, log_id: this.logID,
    };
    return { claims: canonicalJSONV2(claims), streams: canonicalJSONV2(streams), rateCounters: canonicalJSONV2(rates), receiptLog: canonicalJSONV2(log) };
  }

  /** Member digests of every durable security record (claims, streams, rates, receipt log). */
  stateDigests(): StoreStateTestOnly {
    const m = this.storeMembers();
    return { claims: sha384Hex(m.claims), streams: sha384Hex(m.streams), rateCounters: sha384Hex(m.rateCounters), receiptLog: sha384Hex(m.receiptLog) };
  }
}

import { sha384 } from "@noble/hashes/sha2";

/** Lowercase hex SHA-384, without a label. */
export const sha384Hex = (b: Uint8Array): string => hexOf(sha384(b));

// Projection values follow the normative record encodings of SPEC-v2 §7.13.

/** Padded base64 of a stored byte string, or null when the store holds none. */
export const bytesOrNull = (b: Uint8Array | null | undefined): string | null => (b && b.length > 0 ? base64Encode(b) : null);

/** Lowercase hex SHA-384 of exact stored bytes, or null when the store holds none. */
const sha384OrNull = (b: Uint8Array): string | null => (b.length > 0 ? sha384Hex(b) : null);

function sealedClaimProjection(c: V2ChallengeClaim): Record<string, unknown> {
  return {
    agent_id: c.agentID, bundle_hash: c.bundleHash, challenge_digest: c.challengeDigest, claim_id: c.claimID,
    clock_skew_seconds: c.clockSkewSeconds,
    constraint_evaluators: c.constraintEvaluators.map((e) => ({ profile_digest: e.profile_digest, type: e.type })),
    context_policy_digest: c.contextPolicyDigest === "" ? null : c.contextPolicyDigest,
    expires_at: c.expiresAt, issued_at: c.issuedAt, issuer_ids: [...c.issuerIDs], max_age_seconds: c.maxAgeSeconds,
    namespace: c.namespace, proof_digest: c.proofDigest,
    rate_batch: c.rateBatch.map((r) => ({ cert_id: r.certID, issuer_id: r.issuerID, limit: r.limit, window_s: r.windowS })),
    replay_epoch: c.replayEpoch, required_scope: c.requiredScope, requires_rate: c.requiresRate,
    stream_id: bytesOrNull(c.streamID), stream_seq: c.streamSeq, verifier_id: c.verifierID,
  };
}

function progressProjection(p: V2EvaluationProgress): Record<string, unknown> {
  return {
    context_assessment: p.contextAssessment, context_policy_digest: p.contextPolicyDigest, status_assessment: p.statusAssessment,
    status_evidence_digests: p.statusEvidence.map((e) => ({
      digest: e.digest, issuer_id: e.issuer_id, object_type_code: e.object_type_code, sequence: e.sequence, status_key_id: e.status_key_id,
    })),
    trust_assessment: p.trustAssessment,
  };
}

function claimProjection(id: string, r: ClaimRecord): Record<string, unknown> {
  return {
    abandoned: r.abandoned, allow_horizon: r.allowHorizon, claim: sealedClaimProjection(r.claim), claim_id: id,
    claimed_at: r.claimedAt, finalized_at: r.finalizedAt, lease_expires_at: r.leaseExpiresAt,
    log_sequence: r.outboxIndex >= 0 ? r.outboxIndex + 1 : null, owner_digest: base64Encode(r.ownerDigest),
    progress: progressProjection(r.progress), receipt_body_sha384: sha384OrNull(r.receiptBody),
    release: r.release ? {
      ack_timestamp: r.release.ackTimestamp, claim_id: r.release.claimID, entry_hash: base64Encode(r.release.entryHash),
      outcome: r.release.outcome, reason: r.release.reason === "" ? null : r.release.reason,
    } : null,
    state: r.state, terminal_sha384: sha384OrNull(r.terminal),
  };
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** The reference store with max_rate admission moved into finalization. */
export class RateAtFinalizationStoreTestOnly implements V2RateAtFinalizationStore {
  constructor(readonly store: StoreTestOnly) {}
  admitsV2RateAtFinalization(): void {}
  /**
   * Exists only to satisfy V2RateReservationStore. The verifier never calls
   * it for a store that admits at finalization, and it always fails (SPEC-v2
   * §7.1, §7.6).
   */
  async reserveV2RateBatch(_claimID: string, _owner: Uint8Array, _bundleHash: string, _batch: V2RateReservation[]): Promise<void> {
    throw new Error("v2reference: provisional rate reservation is not used with admission at finalization");
  }
  authoritativeTimeV2(): Promise<number> {
    return this.store.authoritativeTimeV2();
  }
  claimV2(claim: V2ChallengeClaim): Promise<V2ClaimResult> {
    return this.store.claimV2(claim);
  }
  finalizeV2Claim(claimID: string, ownerToken: Uint8Array, terminalResult: Uint8Array, receiptBody: Uint8Array, allowValidUntil: number): Promise<boolean> {
    return this.store.finalizeV2Claim(claimID, ownerToken, terminalResult, receiptBody, allowValidUntil);
  }
  recordV2EvaluationProgress(claimID: string, ownerToken: Uint8Array, progress: V2EvaluationProgress): Promise<void> {
    return this.store.recordV2EvaluationProgress(claimID, ownerToken, progress);
  }
  loadV2InterruptedClaim(claimID: string): Promise<V2InterruptedClaim> {
    return this.store.loadV2InterruptedClaim(claimID);
  }
  recoverInterruptedV2Claim(claimID: string, terminalResult: Uint8Array, receiptBody: Uint8Array): Promise<boolean> {
    return this.store.recoverInterruptedV2Claim(claimID, terminalResult, receiptBody);
  }
}
