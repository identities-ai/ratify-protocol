// Single-device offline profile reference models (SPEC-v2 §7.13; Go
// v2reference/device_state.go and offline_device.go). TEST ONLY.
//
// DevicePrimaryTestOnly groups every durable security record of the primary
// (claim store with release records, streams, rate counters and receipt log;
// its anchored SecurityJournalV2 store; its issuance records; its replay
// epoch). Its complete-state digest is a labelled SHA-384 over a versioned
// canonical projection. Once bound to a component, every durable change is
// anchored in the component before it takes effect; a refused change is
// undone. Every record uses the normative encoding of §7.13, so the digest is
// reproducible across implementations (testvectors/v2/device-state.json).

import { getPublicKeyAsync, signAsync, verifyAsync } from "@noble/ed25519";
import { sha384 } from "@noble/hashes/sha2";

import { ErrV2AcknowledgementNotFound, type V2ReceiptCheckpoint } from "../release_v2.js";
import type { V2CheckpointAcknowledgement } from "../checkpoint_ack_v2.js";
import type { V2AuthoritativeClock } from "../claim_store_v2.js";
import { type V2ChallengeIssuanceStore } from "../challenge_issuance_v2.js";
import { V2Error, V2SentinelError, v2ErrorClassOf } from "../errors_v2.js";
import { base64Encode, bytesEqual, canonicalJSONV2, compareBytes, compareStrings, concatBytes, uint64BE, utf8 } from "../json_v2.js";
import type { SecurityJournalHeadV2, SecurityJournalLoadV2, SecurityJournalStoreV2, SecurityJournalV2 } from "../security_journal_v2.js";
import type { ExpectedChallengeV2 } from "../verify_v2_preflight.js";
import { ChallengeIssuanceStoreTestOnly } from "./challenges.js";
import { JournalStoreTestOnly } from "./journal.js";
import { MutexTestOnly, StoreTestOnly, bytesOrNull, sha384Hex, type StoreStateTestOnly } from "./store.js";

export const ErrDevicePowerLossTestOnly = new V2SentinelError("v2reference: power lost during the device checkpoint submission");
export const ErrDeviceStorageFullTestOnly = new V2SentinelError("v2reference: device checkpoint storage is full");
export const ErrDeviceStateMismatchTestOnly = new V2SentinelError("v2reference: submission does not extend the device checkpoint head");
export const ErrDeviceFrozenTestOnly = new V2SentinelError("v2reference: device checkpoint is frozen after a conflicting entry");

export type DevicePowerLossTestOnly = "ok" | "before_commit" | "after_commit";
export type DeviceStartupStatusTestOnly = "ready" | "primary_behind" | "state_digest_mismatch" | "checkpoint_frozen";

const DEVICE_STATE_LABEL = "ratify/device-complete-state/v2";
const DEVICE_STATE_VERSION = 1;


/** One signed acknowledgement of the device component. */
export interface DeviceAcknowledgementTestOnly {
  logID: string;
  sequence: number;
  entryHash: Uint8Array;
  stateDigest: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
}

const lp = (b: Uint8Array) => concatBytes(uint64BE(b.length), b);

function deviceAckMessage(a: DeviceAcknowledgementTestOnly): Uint8Array {
  return concatBytes(utf8("ratify-test-device-checkpoint-v2\0"), lp(utf8(a.logID)), uint64BE(a.sequence), lp(a.entryHash), lp(a.stateDigest), uint64BE(a.timestamp));
}

export async function verifyDeviceAcknowledgementTestOnly(pub: Uint8Array, a: DeviceAcknowledgementTestOnly): Promise<void> {
  if (pub.length !== 32 || !(await verifyAsync(a.signature, deviceAckMessage(a), pub))) {
    throw new Error("v2reference: device acknowledgement signature does not verify");
  }
}

const cloneAck = (a: DeviceAcknowledgementTestOnly): DeviceAcknowledgementTestOnly => ({
  ...a, entryHash: Uint8Array.from(a.entryHash), stateDigest: Uint8Array.from(a.stateDigest), signature: Uint8Array.from(a.signature),
});

/**
 * The independent device component: holds its own key, the anchored
 * complete-state digest, and an append-only acknowledgement record; never
 * overwrites, freezes on a conflicting entry, refuses when full.
 */
export class DeviceComponentTestOnly {
  readonly mutex = new MutexTestOnly();
  records: DeviceAcknowledgementTestOnly[] = [];
  state: Uint8Array | null = null;
  frozen = false;
  fault: DevicePowerLossTestOnly = "ok";
  private constructor(readonly seed: Uint8Array, readonly publicKey: Uint8Array, readonly capacity: number, readonly clock: V2AuthoritativeClock) {}

  static async create(seed: Uint8Array, capacity: number, clock: V2AuthoritativeClock): Promise<DeviceComponentTestOnly> {
    if (seed.length !== 32 || !(capacity >= 1) || !clock) throw new Error("v2reference: device component needs a 32-byte seed, positive capacity, and a clock");
    return new DeviceComponentTestOnly(Uint8Array.from(seed), await getPublicKeyAsync(seed), capacity, clock);
  }

  setPowerLoss(fault: DevicePowerLossTestOnly): void {
    this.fault = fault;
  }

  head(): { sequence: number; state: Uint8Array | null; frozen: boolean } {
    return { sequence: this.records.length, state: this.state === null ? null : Uint8Array.from(this.state), frozen: this.frozen };
  }

  provisionState(digest: Uint8Array): void {
    if (this.state !== null || this.records.length !== 0 || digest.length !== 48) {
      throw new Error("v2reference: device component is already provisioned or the digest is not 48 bytes");
    }
    this.state = Uint8Array.from(digest);
  }

  /** Replaces the anchored state only through an anchor naming the anchored digest. */
  anchorState(previous: Uint8Array, next: Uint8Array): void {
    if (this.frozen) throw ErrDeviceFrozenTestOnly;
    if (this.state === null || !bytesEqual(this.state, previous) || next.length !== 48) throw ErrDeviceStateMismatchTestOnly;
    this.state = Uint8Array.from(next);
  }

  async commitAt(now: number, clockErr: unknown, logID: string, sequence: number, previousEntryHash: Uint8Array, entryHash: Uint8Array, state: Uint8Array): Promise<DeviceAcknowledgementTestOnly> {
    return this.mutex.run(async () => {
      if (this.frozen) throw ErrDeviceFrozenTestOnly;
      if (sequence >= 1 && sequence <= this.records.length) {
        const existing = this.records[sequence - 1]!;
        if (existing.logID === logID && bytesEqual(existing.entryHash, entryHash)) return cloneAck(existing);
        this.frozen = true;
        throw ErrDeviceFrozenTestOnly;
      }
      let headEntry: Uint8Array = new Uint8Array(48);
      const n = this.records.length;
      if (n > 0) {
        headEntry = this.records[n - 1]!.entryHash;
        if (this.records[n - 1]!.logID !== logID) throw ErrDeviceStateMismatchTestOnly;
      }
      if (sequence !== n + 1 || !bytesEqual(headEntry, previousEntryHash) || this.state === null || !bytesEqual(this.state, state)) {
        throw ErrDeviceStateMismatchTestOnly;
      }
      if (n >= this.capacity) throw ErrDeviceStorageFullTestOnly;
      const fault = this.fault;
      this.fault = "ok";
      if (fault === "before_commit") throw ErrDevicePowerLossTestOnly;
      if (clockErr !== null && clockErr !== undefined) throw clockErr;
      const ack: DeviceAcknowledgementTestOnly = { logID, sequence, entryHash: Uint8Array.from(entryHash), stateDigest: Uint8Array.from(state), timestamp: now, signature: new Uint8Array(0) };
      ack.signature = await signAsync(deviceAckMessage(ack), this.seed);
      this.records.push(ack);
      if (fault === "after_commit") throw ErrDevicePowerLossTestOnly;
      return cloneAck(ack);
    });
  }

  get(logID: string, sequence: number): DeviceAcknowledgementTestOnly {
    const r = this.records[sequence - 1];
    if (sequence < 1 || !r || r.logID !== logID) throw ErrV2AcknowledgementNotFound;
    return cloneAck(r);
  }
}

/** The primary of the single-device offline profile. */
export class DevicePrimaryTestOnly {
  readonly mutex = new MutexTestOnly();
  journal!: DeviceJournalTestOnly;
  issuance!: DeviceIssuanceTestOnly;
  component: DeviceComponentTestOnly | null = null;
  lastStore: StoreStateTestOnly | null = null;
  constructor(public store: StoreTestOnly, readonly replayEpoch: number) {
    if (!store || replayEpoch < 0) throw new Error("v2reference: device primary needs a store and a non-negative replay epoch");
    this.journal = new DeviceJournalTestOnly(this, new JournalStoreTestOnly());
    this.issuance = new DeviceIssuanceTestOnly(this, new ChallengeIssuanceStoreTestOnly());
  }

  /** A copy of the complete primary state (a backup or snapshot), unbound. */
  clone(): DevicePrimaryTestOnly {
    const out = new DevicePrimaryTestOnly(this.store.clone(), this.replayEpoch);
    out.journal.inner.restoreStateTestOnly(this.journal.inner.snapshotStateTestOnly());
    for (const [k, v] of this.issuance.inner.records) out.issuance.inner.records.set(k, { ...v, value: Uint8Array.from(v.value) });
    return out;
  }

  bind(component: DeviceComponentTestOnly): void {
    this.component = component;
    this.lastStore = this.store.stateDigests();
    this.store.anchor = (previous, next) => this.anchorStore(previous, next);
  }

  private anchorStore(previous: StoreStateTestOnly, next: StoreStateTestOnly): void {
    const before = this.compose(previous);
    const after = this.compose(next);
    this.component!.anchorState(before, after);
    this.lastStore = next;
  }

  /** The complete-state digest for the given store members and current journal and issuance records. */
  compose(store: StoreStateTestOnly): Uint8Array {
    return completeStateDigestTestOnly(this.projection(store, sha384Hex(this.issuanceMember())));
  }

  /**
   * The RatifyCanonicalJSON of the issuance_records member, sorted by
   * (verifier_namespace, replay_epoch, value) (SPEC-v2 §7.13).
   */
  issuanceMember(): Uint8Array {
    const records = [...this.issuance.inner.records.values()].sort((a, b) =>
      compareStrings(a.verifierNamespace, b.verifierNamespace) || a.replayEpoch - b.replayEpoch || compareBytes(a.value, b.value));
    return canonicalJSONV2(records.map(issuanceProjection));
  }

  /** The RatifyCanonicalJSON of the version 1 projection object. */
  projection(store: StoreStateTestOnly, issuanceDigest: string): Uint8Array {
    const journal = this.journal.inner.snapshotStateTestOnly();
    return canonicalJSONV2({
      claims: store.claims, issuance_records: issuanceDigest, log_id: this.store.logID,
      rate_counters: store.rateCounters, receipt_log: store.receiptLog, replay_epoch: this.replayEpoch,
      security_journal: { generation: journal.head.generation, snapshot_sha384: sha384Hex(journal.snapshot) },
      streams: store.streams, version: DEVICE_STATE_VERSION,
    });
  }

  /** Recomputes the complete-state digest from current records. */
  completeStateDigestTestOnly(): Uint8Array {
    return this.compose(this.store.stateDigests());
  }

  anchoredDigest(): Uint8Array {
    return this.compose(this.lastStore!);
  }

  /** Applies a journal or issuance change, anchored first when bound. */
  async changeOther(apply: () => Promise<void>, undo: () => void): Promise<void> {
    return this.mutex.run(async () => {
      if (this.component === null) return apply();
      const before = this.compose(this.lastStore!);
      let applyErr: unknown = null;
      try {
        await apply();
      } catch (err) {
        applyErr = err;
      }
      let err: unknown = null;
      try {
        const after = this.compose(this.lastStore!);
        if (!bytesEqual(before, after)) this.component.anchorState(before, after);
      } catch (e) {
        err = e;
      }
      if (err !== null) {
        undo();
        throw new V2Error("claim_store_unavailable", `v2reference: durable state change was not anchored: ${(err as Error).message}`, err);
      }
      if (applyErr !== null) throw applyErr;
    });
  }
}

/** The labelled SHA-384 of the projection bytes. */
export function completeStateDigestTestOnly(projection: Uint8Array): Uint8Array {
  return sha384(concatBytes(utf8(DEVICE_STATE_LABEL), new Uint8Array([0]), projection));
}

function issuanceProjection(r: ExpectedChallengeV2): Record<string, unknown> {
  const key = r.expectedAgentPublicKey;
  const policy = r.contextPolicy;
  return {
    context_policy: policy
      ? {
        expected_session_context: bytesOrNull(policy.expectedSessionContext), profile: policy.profile, require_bound: policy.requireBound,
        required_fields: [...policy.requiredFields], version: 1,
      }
      : null,
    expected_agent_id: r.expectedAgentID ?? "",
    expected_agent_pub_key: key ? { ed25519: base64Encode(key.ed25519), ml_dsa_65: base64Encode(key.ml_dsa_65) } : null,
    expected_receiver_id: r.expectedReceiverID ?? "", expected_session_context: bytesOrNull(r.expectedSessionContext),
    expires_at: r.expiresAt, issued_at: r.issuedAt, replay_epoch: r.replayEpoch, value: base64Encode(r.value),
    verifier_id: r.verifierID, verifier_namespace: r.verifierNamespace,
  };
}

/** The primary's anchored SecurityJournalV2 store. */
export class DeviceJournalTestOnly implements SecurityJournalStoreV2 {
  constructor(readonly primary: DevicePrimaryTestOnly, readonly inner: JournalStoreTestOnly) {}
  load(signal?: AbortSignal): Promise<SecurityJournalLoadV2> {
    return this.inner.load(signal);
  }
  async compareAndSwap(expected: SecurityJournalHeadV2, next: SecurityJournalV2, signal?: AbortSignal): Promise<void> {
    const saved = this.inner.snapshotStateTestOnly();
    return this.primary.changeOther(() => this.inner.compareAndSwap(expected, next, signal), () => this.inner.restoreStateTestOnly(saved));
  }
  head(): SecurityJournalHeadV2 {
    return this.inner.head();
  }
}

/** The primary's challenge issuance store. */
export class DeviceIssuanceTestOnly implements V2ChallengeIssuanceStore {
  constructor(readonly primary: DevicePrimaryTestOnly, readonly inner: ChallengeIssuanceStoreTestOnly) {}
  async persistV2Challenge(record: ExpectedChallengeV2): Promise<void> {
    const saved = new Map(this.inner.records);
    return this.primary.changeOther(() => this.inner.persistV2Challenge(record), () => {
      this.inner.records = saved;
    });
  }
  loadV2Challenge(namespace: string, epoch: number, digest: Uint8Array): Promise<ExpectedChallengeV2> {
    return this.inner.loadV2Challenge(namespace, epoch, digest);
  }
}

/** The independent checkpoint of the device: the primary's view of the component. */
export class DeviceCheckpointTestOnly implements V2ReceiptCheckpoint {
  readonly primary: StoreTestOnly;
  constructor(readonly device: DevicePrimaryTestOnly, readonly component: DeviceComponentTestOnly, readonly pinned: Uint8Array) {
    if (!device || !component) throw new Error("v2reference: device checkpoint needs a primary and a component");
    device.bind(component);
    this.primary = device.store;
  }

  /** Provisions the component once with the primary's initial complete-state digest. */
  provision(): void {
    this.component.provisionState(this.device.completeStateDigestTestOnly());
  }

  private async toAck(a: DeviceAcknowledgementTestOnly): Promise<V2CheckpointAcknowledgement> {
    await verifyDeviceAcknowledgementTestOnly(this.pinned, a);
    return { logID: a.logID, sequence: a.sequence, entryHash: Uint8Array.from(a.entryHash), timestamp: a.timestamp };
  }

  async acknowledgeV2Receipt(logID: string, sequence: number, previousEntryHash: Uint8Array, entryHash: Uint8Array): Promise<V2CheckpointAcknowledgement> {
    const appended = this.primary.appendedEntry(sequence);
    if (appended === null || !bytesEqual(appended, entryHash)) throw new V2SentinelError("v2reference: checkpoint refused the acknowledgement");
    let now = 0;
    let clockErr: unknown = null;
    try {
      now = await this.component.clock.authoritativeTimeV2();
    } catch (err) {
      clockErr = err;
    }
    const ack = await this.device.mutex.run(() => {
      const state = this.device.compose(this.device.lastStore!);
      return this.component.commitAt(now, clockErr, logID, sequence, previousEntryHash, entryHash, state);
    });
    return this.toAck(ack);
  }

  async getV2Acknowledgement(logID: string, sequence: number): Promise<V2CheckpointAcknowledgement> {
    return this.toAck(this.component.get(logID, sequence));
  }

  /** Submits every appended entry the component has not acknowledged, in log order. */
  async submitPending(): Promise<{ acknowledged: number[]; error: unknown }> {
    const acknowledged: number[] = [];
    for (let next = 1; ; next++) {
      const entry = this.primary.appendedEntry(next);
      if (entry === null) return { acknowledged, error: null };
      try {
        const existing = this.component.get(this.primary.logID, next);
        if (bytesEqual(existing.entryHash, entry)) continue;
      } catch {
        // not acknowledged yet
      }
      try {
        await this.resubmit(next);
      } catch (err) {
        return { acknowledged, error: err };
      }
      acknowledged.push(next);
    }
  }

  /** Resubmits the identical tuple for one appended sequence. */
  async resubmit(sequence: number): Promise<V2CheckpointAcknowledgement> {
    const entry = this.primary.appendedEntry(sequence);
    if (entry === null) throw new V2SentinelError("v2reference: checkpoint refused the acknowledgement");
    let previous: Uint8Array | null = new Uint8Array(48);
    if (sequence > 1) {
      previous = this.primary.appendedEntry(sequence - 1);
      if (previous === null) throw new V2SentinelError("v2reference: checkpoint refused the acknowledgement");
    }
    return this.acknowledgeV2Receipt(this.primary.logID, sequence, previous, entry);
  }

  /** Startup check before serving any request (SPEC-v2 §7.13). */
  startup(): DeviceStartupStatusTestOnly {
    const head = this.component.head();
    if (head.frozen) return "checkpoint_frozen";
    if (this.primary.logLength() < head.sequence) return "primary_behind";
    let state: Uint8Array | null = null;
    try {
      state = this.device.completeStateDigestTestOnly();
    } catch {
      state = null;
    }
    if (state === null || head.state === null || !bytesEqual(state, head.state)) return "state_digest_mismatch";
    return "ready";
  }
}

/** Uploads signed receipts from the component-acknowledged prefix, in order, once each. */
export class DeviceUplinkTestOnly {
  uploaded = 0;
  collected: Uint8Array[] = [];
  constructor(readonly device: DeviceCheckpointTestOnly) {}
  upload(): number[] {
    const head = this.device.component.head().sequence;
    const sent: number[] = [];
    while (this.uploaded < head) {
      const next = this.uploaded + 1;
      const entry = this.device.primary.outbox[next - 1];
      if (!entry || entry.wire === null) break;
      this.collected.push(Uint8Array.from(entry.wire));
      this.uploaded = next;
      sent.push(next);
    }
    return sent;
  }
}

/** Maps a device error to the vector's class names. */
export function deviceErrorClassTestOnly(err: unknown): string {
  if (err === null || err === undefined) return "";
  if (err === ErrDevicePowerLossTestOnly) return "power_loss";
  if (err === ErrDeviceStorageFullTestOnly) return "storage_full";
  if (err === ErrDeviceStateMismatchTestOnly) return "state_mismatch";
  if (err === ErrDeviceFrozenTestOnly) return "frozen";
  if (v2ErrorClassOf(err) === "clock_regressed") return "clock_regressed";
  return `unexpected: ${(err as Error)?.message ?? String(err)}`;
}
