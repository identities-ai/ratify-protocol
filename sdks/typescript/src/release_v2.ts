// Committed versus released (SPEC-v2 §6.9, §7.9; Go release_v2.go).
//
// verifyProofBundleV2 commits a terminal Protocol result and returns an
// opaque CommittedV2Outcome holding the handoff tuple {claim_id,
// receipt_body_digest, challenge_expires_at, allow_horizon} and the sealed
// receipt outbox body. It exposes no decision. releaseV2Decision is the only
// path to an actionable decision; it returns released, pending (retryable),
// withheld (permanent for the claim once recorded), or rejected (a result of
// that call's inputs that changes no claim state).

import { sha384 } from "@noble/hashes/sha2";

import { validV2Timestamp } from "./clock_bounds_v2.js";
import type { V2CheckpointAcknowledgement } from "./checkpoint_ack_v2.js";
import type { V2AuthoritativeClock, V2ChallengeClaim } from "./claim_store_v2.js";
import { V2_OBJECT_TYPE, keyIDV2, verifyV2Statement } from "./crypto_v2.js";
import { classified, errorIs, v2ErrorClassOf, V2SentinelError } from "./errors_v2.js";
import { bytesEqual, concatBytes, hexOf, utf8 } from "./json_v2.js";
import { lowerHexString } from "./protocol_v2_wire.js";
import type { HybridPublicKey } from "./types.js";
import {
  decodeVerificationReceiptV2,
  verificationReceiptV2Body,
  verificationReceiptV2Digest,
  verificationReceiptV2SignBytes,
  type VerificationReceiptV2,
} from "./verification_receipt_v2.js";

export type { V2CheckpointAcknowledgement };

/** "sha384:" + hex(SHA-384("ratify-protocol-receipt-outbox-v2" || 0x00 || body)). */
export function receiptOutboxDigestV2(body: Uint8Array): string {
  return "sha384:" + hexOf(sha384(concatBytes(utf8("ratify-protocol-receipt-outbox-v2\0"), body)));
}

interface CommittedState {
  claimID: string;
  verifierID: string;
  receiptBody: Uint8Array;
  challengeExpiresAt: number;
  allowHorizon: number;
}

const committedStates = new WeakMap<CommittedV2Outcome, CommittedState>();

// Module-private construction capabilities. Neither symbol is exported, so a
// constructor call from outside this module throws. The state maps above and
// below are the registries of genuine instances: an object that is not a key
// there (built with Object.create, structuredClone, a prototype change, or a
// spread copy) carries no state and is never actionable.
const COMMITTED_TOKEN: unique symbol = Symbol("v2 committed outcome");
const RELEASED_TOKEN: unique symbol = Symbol("v2 released decision");

/**
 * The immutable, non-actionable handoff from a committed verification to
 * publication and releaseV2Decision. It exposes no decision; applications
 * must not parse the receipt body to authorize. Only the verifier and
 * interruption recovery construct one; its constructor throws for any other
 * caller.
 */
export class CommittedV2Outcome {
  /** Not constructible outside the SDK: the constructor throws without a module-private token. */
  private constructor(token?: unknown) {
    if (token !== COMMITTED_TOKEN) throw new TypeError("CommittedV2Outcome is created only by the v2 verifier and recovery");
  }
  get #s(): CommittedState {
    const s = committedStates.get(this);
    if (!s) throw new Error("v2 committed outcome is not a verifier-produced handoff");
    return s;
  }
  /** The Protocol claim ID of the committed evaluation. */
  claimID(): string {
    return this.#s.claimID;
  }
  /** A copy of the sealed receipt outbox body, for the receipt publisher only. */
  receiptBody(): Uint8Array {
    return Uint8Array.from(this.#s.receiptBody);
  }
  /** ReceiptOutboxDigest of the sealed body. */
  receiptBodyDigest(): string {
    return receiptOutboxDigestV2(this.#s.receiptBody);
  }
  /** The sealed exclusive challenge deadline. */
  challengeExpiresAt(): number {
    return this.#s.challengeExpiresAt;
  }
  /** The exclusive allow deadline, or null unless the result can become an allow. */
  allowHorizon(): number | null {
    return this.#s.allowHorizon > 0 ? this.#s.allowHorizon : null;
  }
}

/** @internal */
export function committedStateV2(c: CommittedV2Outcome | null | undefined): CommittedState | null {
  return c ? (committedStates.get(c) ?? null) : null;
}

/**
 * @internal Only the verifier and recovery construct a committed outcome.
 * Not exported from any package entry point.
 */
export function newCommittedV2Outcome(claim: V2ChallengeClaim, body: Uint8Array, allowHorizon: number): CommittedV2Outcome {
  const c = new (CommittedV2Outcome as unknown as new (token: symbol) => CommittedV2Outcome)(COMMITTED_TOKEN);
  committedStates.set(c, {
    claimID: claim.claimID, verifierID: claim.verifierID, receiptBody: Uint8Array.from(body),
    challengeExpiresAt: claim.expiresAt, allowHorizon,
  });
  Object.freeze(c);
  return c;
}

/**
 * The Part B receipt outbox drain (§7.7): signs and appends the exact
 * committed body for claimID at the next log position, or returns the
 * receipt already appended for that claim.
 */
export interface V2ReceiptPublisher {
  publishV2Receipt(claimID: string, receiptBody: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/** Returned by getV2Acknowledgement for an entry the checkpoint has not acknowledged. */
export const ErrV2AcknowledgementNotFound = new V2SentinelError("v2 checkpoint acknowledgement not found");

/** The caller-configured independent checkpoint (§7.8). */
export interface V2ReceiptCheckpoint {
  acknowledgeV2Receipt(logID: string, sequence: number, previousEntryHash: Uint8Array, entryHash: Uint8Array, signal?: AbortSignal): Promise<V2CheckpointAcknowledgement>;
  getV2Acknowledgement(logID: string, sequence: number, signal?: AbortSignal): Promise<V2CheckpointAcknowledgement>;
}

/**
 * The durable release record of SPEC-v2 §6.9: the release of step 9 (outcome
 * released, reason "") or a withheld result of steps 7 and 8 (outcome
 * withheld, reason clock_regressed, challenge_expired, or
 * allow_horizon_passed). entryHash and ackTimestamp name the verified receipt
 * entry and its acknowledgement. The first record for a claim wins; a claim
 * store throws ErrV2ReleaseStateMismatch for any different later record and
 * must persist and return every field unchanged.
 */
export interface V2ReleaseRecord {
  claimID: string;
  entryHash: Uint8Array;
  ackTimestamp: number;
  outcome: V2ReleaseStatus;
  reason: string;
}

/**
 * Reports whether outcome and reason form a release record: released with no
 * reason, or withheld with one of the reasons release steps 7 and 8 record.
 */
export function validV2ReleaseRecordOutcome(outcome: unknown, reason: unknown): boolean {
  switch (outcome) {
    case "released":
      return reason === "";
    case "withheld":
      return reason === "clock_regressed" || reason === "challenge_expired" || reason === "allow_horizon_passed";
    default:
      return false;
  }
}

/** What the claim store returns to release (§7.3). */
export interface V2TerminalClaimRecord {
  terminal: boolean;
  receiptOutboxDigest: string;
  challengeExpiresAt: number;
  allowHorizon: number;
  finalizedAt: number;
  receiptAbandoned: boolean;
  release: V2ReleaseRecord | null;
}

/** Thrown by recordV2Release when a different release or withheld record already exists. */
export const ErrV2ReleaseStateMismatch = new V2SentinelError("v2 claim already records a different release");

/** The claim-store view release needs. */
export interface V2ReleaseClaimStore extends V2AuthoritativeClock {
  loadV2TerminalClaim(claimID: string, signal?: AbortSignal): Promise<V2TerminalClaimRecord>;
  recordV2Release(record: V2ReleaseRecord, signal?: AbortSignal): Promise<void>;
}

/** Caller-authenticated release configuration. */
export interface V2ReleaseConfig {
  verifierPublicKey: HybridPublicKey;
  logID: string;
  claimStore: V2ReleaseClaimStore;
  checkpoint: V2ReceiptCheckpoint;
}

export type V2ReleaseStatus = "released" | "pending" | "withheld" | "rejected";

interface ReleasedState {
  claimID: string;
  decision: string;
  reason: string;
  identityStatus: string;
  grantedScope: string[];
  receiptWire: Uint8Array;
  releaseTime: number;
  challengeExpiresAt: number;
  allowHorizon: number;
}

// The registry of genuine released decisions. Only mintReleasedDecision adds
// to it, and only releaseV2Decision calls mintReleasedDecision; neither is
// exported.
const releasedStates = new WeakMap<V2ReleasedDecision, ReleasedState>();
const releasedStateOf = (d: V2ReleasedDecision): ReleasedState | null => releasedStates.get(d) ?? null;

function mintReleasedDecision(state: ReleasedState): V2ReleasedDecision {
  const d = new (V2ReleasedDecision as unknown as new (token: symbol) => V2ReleasedDecision)(RELEASED_TOKEN);
  releasedStates.set(d, state);
  Object.freeze(d);
  return d;
}

/**
 * The only actionable value of this SDK (SPEC-v2 §6.9). Sealed:
 * releaseV2Decision is its only producer, its constructor throws for any
 * other caller, and its state lives in a module-private registry rather than
 * on the instance. Every accessor returns a copy. An object that
 * releaseV2Decision did not return (one built with Object.create,
 * structuredClone, Object.setPrototypeOf, or a copy of a genuine instance)
 * is not in the registry and is never actionable.
 *
 * This protects against API misuse and accidental construction. It is not a
 * defense against hostile code running in the same process, which can
 * already read the application's keys and stores (SPEC-v2 §1.3).
 */
export class V2ReleasedDecision {
  /** Not constructible outside the SDK: the constructor throws without a module-private token. */
  private constructor(token?: unknown) {
    if (token !== RELEASED_TOKEN) throw new TypeError("V2ReleasedDecision is created only by releaseV2Decision");
  }
  claimID(): string {
    return releasedStateOf(this)?.claimID ?? "";
  }
  /** "allow", "deny", or "indeterminate". Use allowed(), not this value, to gate a side effect. */
  decision(): string {
    return releasedStateOf(this)?.decision ?? "";
  }
  reason(): string {
    return releasedStateOf(this)?.reason ?? "";
  }
  identityStatus(): string {
    return releasedStateOf(this)?.identityStatus ?? "";
  }
  grantedScope(): string[] {
    return [...(releasedStateOf(this)?.grantedScope ?? [])];
  }
  /** A copy of the signed receipt wire verified during release. */
  receiptWire(): Uint8Array {
    return Uint8Array.from(releasedStateOf(this)?.receiptWire ?? []);
  }
  /** A freshly decoded copy of the verified signed receipt. */
  receipt(): VerificationReceiptV2 {
    return classified("configuration_invalid", () => {
      const s = releasedStateOf(this);
      if (!s || s.receiptWire.length === 0) throw new Error("v2 released decision carries no receipt");
      return decodeVerificationReceiptV2(s.receiptWire);
    });
  }
  /** The checkpoint acknowledgement time of the release. */
  releaseTime(): number {
    return releasedStateOf(this)?.releaseTime ?? 0;
  }
  challengeExpiresAt(): number {
    return releasedStateOf(this)?.challengeExpiresAt ?? 0;
  }
  /** The sealed exclusive allow deadline, or null unless the decision is an allow. */
  allowHorizon(): number | null {
    const h = releasedStateOf(this)?.allowHorizon ?? 0;
    return h > 0 ? h : null;
  }
  /**
   * True only when this released decision is an allow and the receiver's
   * authoritative clock reads now < challenge_expires_at and now <
   * allow_horizon. A clock error, regression, or out-of-domain reading is
   * false. Call immediately before the side effect.
   */
  async allowed(clock: V2AuthoritativeClock, signal?: AbortSignal): Promise<boolean> {
    const s = releasedStateOf(this);
    if (!s || !clock || s.decision !== "allow" || s.receiptWire.length === 0 || s.allowHorizon <= 0) return false;
    let now: number;
    try {
      now = await readV2AuthoritativeTime(clock, signal);
    } catch {
      return false;
    }
    return now < s.challengeExpiresAt && now < s.allowHorizon;
  }
}

// Freeze both classes and their prototypes so no caller can replace an
// accessor such as allowed() for every instance.
Object.freeze(CommittedV2Outcome.prototype);
Object.freeze(CommittedV2Outcome);
Object.freeze(V2ReleasedDecision.prototype);
Object.freeze(V2ReleasedDecision);

/** The result of releaseV2Decision. decision is non-null only when released. */
export interface V2ReleaseResult {
  status: V2ReleaseStatus;
  reason: string;
  decision: V2ReleasedDecision | null;
}

const result = (status: V2ReleaseStatus, reason: string): V2ReleaseResult => ({ status, reason, decision: null });

/**
 * Performs the release steps of SPEC-v2 §6.9 in order and stops at the first
 * that does not pass. signedReceipt is the publisher's signed receipt, or
 * null when it has not been appended yet.
 */
export async function releaseV2Decision(
  committed: CommittedV2Outcome,
  signedReceipt: Uint8Array | null,
  config: V2ReleaseConfig,
  signal?: AbortSignal,
): Promise<V2ReleaseResult> {
  const c = committedStateV2(committed);
  if (!c || c.claimID === "" || c.receiptBody.length === 0 || !config?.claimStore || !config.checkpoint) {
    return result("rejected", "release_state_mismatch");
  }
  if (typeof config.logID !== "string" || config.logID.length !== 32 || !lowerHexString(config.logID)) {
    return result("rejected", "release_state_mismatch");
  }
  // 1. Committed state.
  let record: V2TerminalClaimRecord;
  try {
    record = await config.claimStore.loadV2TerminalClaim(c.claimID, signal);
  } catch {
    return result("pending", "claim_store_unavailable");
  }
  if (record.receiptAbandoned) return result("withheld", "receipt_abandoned");
  let verifierID = "";
  try {
    verifierID = keyIDV2(config.verifierPublicKey);
  } catch {
    verifierID = "";
  }
  if (!record.terminal || record.receiptOutboxDigest !== receiptOutboxDigestV2(c.receiptBody) ||
      record.challengeExpiresAt !== c.challengeExpiresAt || record.allowHorizon !== c.allowHorizon ||
      verifierID === "" || verifierID !== c.verifierID) {
    return result("rejected", "release_state_mismatch");
  }
  // A recorded withheld result is permanent for the claim and is returned
  // before any other step. A record that is neither a valid withheld nor a
  // valid released record for this claim is a state mismatch.
  const prior = record.release ?? null;
  if (prior !== null) {
    if (prior.claimID !== c.claimID || !validV2ReleaseRecordOutcome(prior.outcome, prior.reason)) {
      return result("rejected", "release_state_mismatch");
    }
    if (prior.outcome === "withheld") return result("withheld", prior.reason);
  }
  // 2. Receipt.
  if (!signedReceipt || signedReceipt.length === 0) return result("pending", "receipt_not_appended");
  let receipt: VerificationReceiptV2;
  try {
    receipt = await verifyPublishedV2Receipt(signedReceipt, config);
  } catch {
    return result("rejected", "receipt_invalid");
  }
  if (receipt.verifier_id !== c.verifierID) return result("rejected", "receipt_invalid");
  // 3. Body binding.
  let body: Uint8Array | null = null;
  try {
    body = verificationReceiptV2Body(receipt);
  } catch {
    body = null;
  }
  if (body === null || !bytesEqual(body, c.receiptBody)) return result("rejected", "receipt_body_mismatch");
  let entryHash: Uint8Array;
  try {
    entryHash = verificationReceiptV2Digest(receipt);
  } catch {
    return result("rejected", "receipt_invalid");
  }
  // 4. Prior release: the same entry. Never evidence of acknowledgement.
  if (prior !== null && !bytesEqual(prior.entryHash, entryHash)) {
    return result("rejected", "release_state_mismatch");
  }
  // 5. Predecessor.
  if (receipt.sequence > 1) {
    let previous: V2CheckpointAcknowledgement;
    try {
      previous = await config.checkpoint.getV2Acknowledgement(receipt.log_id, receipt.sequence - 1, signal);
    } catch {
      return result("pending", "acknowledgement_unavailable");
    }
    if (previous.logID !== receipt.log_id || previous.sequence !== receipt.sequence - 1 || !bytesEqual(previous.entryHash, receipt.previous_receipt_hash)) {
      return result("rejected", "log_predecessor_mismatch");
    }
  }
  // 6. Acknowledgement.
  let ack: V2CheckpointAcknowledgement;
  try {
    ack = await config.checkpoint.getV2Acknowledgement(receipt.log_id, receipt.sequence, signal);
  } catch {
    return result("pending", "acknowledgement_unavailable");
  }
  if (ack.logID !== receipt.log_id || ack.sequence !== receipt.sequence || !bytesEqual(ack.entryHash, entryHash)) {
    return result("rejected", "acknowledgement_mismatch");
  }
  if (prior !== null && prior.ackTimestamp !== ack.timestamp) return result("rejected", "release_state_mismatch");
  // withhold ends release at step 7 or 8. With no release recorded it
  // durably records the withheld result first, so it is permanent for the
  // claim; if the store is unavailable this call is still withheld. With a
  // release already recorded, that first record stands and this call alone
  // is withheld.
  const withhold = async (reason: string): Promise<V2ReleaseResult> => {
    if (prior === null) {
      try {
        await config.claimStore.recordV2Release({
          claimID: c.claimID, entryHash: Uint8Array.from(entryHash), ackTimestamp: ack.timestamp, outcome: "withheld", reason,
        }, signal);
      } catch (err) {
        if (errorIs(err, ErrV2ReleaseStateMismatch)) return result("rejected", "release_state_mismatch");
      }
    }
    return result("withheld", reason);
  };
  // 7. Clock.
  let now: number;
  try {
    now = await readV2AuthoritativeTime(config.claimStore, signal);
  } catch (err) {
    if (v2ErrorClassOf(err) === "clock_regressed") return withhold("clock_regressed");
    return result("pending", "clock_unavailable");
  }
  if (!validV2Timestamp(ack.timestamp) || record.finalizedAt > ack.timestamp || ack.timestamp > now) {
    return withhold("clock_regressed");
  }
  // 8. Deadlines.
  if (ack.timestamp >= c.challengeExpiresAt || now >= c.challengeExpiresAt) return withhold("challenge_expired");
  if (receipt.decision === "allow" && (c.allowHorizon <= 0 || ack.timestamp >= c.allowHorizon || now >= c.allowHorizon)) {
    return withhold("allow_horizon_passed");
  }
  // 9. Record.
  if (prior === null) {
    try {
      await config.claimStore.recordV2Release({
        claimID: c.claimID, entryHash: Uint8Array.from(entryHash), ackTimestamp: ack.timestamp, outcome: "released", reason: "",
      }, signal);
    } catch (err) {
      if (errorIs(err, ErrV2ReleaseStateMismatch)) return result("rejected", "release_state_mismatch");
      return result("pending", "claim_store_unavailable");
    }
  }
  // 10. Return.
  const decision = mintReleasedDecision({
    claimID: c.claimID, decision: receipt.decision, reason: receipt.decision_reason, identityStatus: receipt.identity_status,
    grantedScope: [...(receipt.granted_scope ?? [])], receiptWire: Uint8Array.from(signedReceipt), releaseTime: ack.timestamp,
    challengeExpiresAt: c.challengeExpiresAt, allowHorizon: receipt.decision === "allow" ? c.allowHorizon : 0,
  });
  return { status: "released", reason: "", decision };
}

async function verifyPublishedV2Receipt(wire: Uint8Array, config: V2ReleaseConfig): Promise<VerificationReceiptV2> {
  const receipt = decodeVerificationReceiptV2(wire);
  if (receipt.log_id !== config.logID) throw new Error("v2 published receipt belongs to an unconfigured log");
  await verifyV2Statement(V2_OBJECT_TYPE.verificationReceipt, verificationReceiptV2SignBytes(receipt), receipt.signature, config.verifierPublicKey);
  return receipt;
}

/**
 * Reads an authoritative clock (Go readV2AuthoritativeTime). A
 * clock_regressed error keeps its class; any other failure or an
 * out-of-domain reading is an unavailable clock.
 */
export async function readV2AuthoritativeTime(clock: V2AuthoritativeClock, signal?: AbortSignal): Promise<number> {
  const now = await clock.authoritativeTimeV2(signal);
  if (!validV2Timestamp(now)) throw new Error(`v2 authoritative clock returned ${now} outside the timestamp domain`);
  return now;
}
