// Reference anchored SecurityJournalV2 store (Go v2reference/journal.go). It
// persists the canonical snapshot bytes and an anchored head and advances
// both together by compare-and-swap. TEST/REFERENCE ONLY: an in-process
// anchor is not an independent, rollback-resistant head and must never be
// offered as a production store.

import {
  ErrSecurityJournalConflictV2,
  emptySecurityJournalV2,
  validateSecurityJournalTransitionV2,
  type SecurityJournalHeadV2,
  type SecurityJournalLoadV2,
  type SecurityJournalStoreV2,
  type SecurityJournalV2,
} from "../security_journal_v2.js";
import { exportSecurityJournalSnapshotV2, importSecurityJournalSnapshotV2 } from "../security_journal_snapshot_v2.js";

export class JournalStoreTestOnly implements SecurityJournalStoreV2 {
  #head: SecurityJournalHeadV2;
  #snapshot: Uint8Array;

  /** A store anchored at the genesis journal. */
  constructor() {
    const genesis = emptySecurityJournalV2();
    this.#snapshot = exportSecurityJournalSnapshotV2(genesis);
    this.#head = { generation: genesis.generation, digest: genesis.digest };
  }

  /** Imports the stored snapshot against the anchored head. */
  async load(_signal?: AbortSignal): Promise<SecurityJournalLoadV2> {
    const journal = importSecurityJournalSnapshotV2(this.#snapshot, this.#head);
    return { journal, head: { ...this.#head } };
  }

  /**
   * Advances snapshot and head together. The check and the write run with no
   * intervening await, so concurrent callers are serialized: exactly one of
   * two writers with the same expected head succeeds.
   */
  async compareAndSwap(expected: SecurityJournalHeadV2, next: SecurityJournalV2, _signal?: AbortSignal): Promise<void> {
    if (!expected || expected.generation !== this.#head.generation || expected.digest !== this.#head.digest) {
      throw ErrSecurityJournalConflictV2;
    }
    const current = importSecurityJournalSnapshotV2(this.#snapshot, this.#head);
    validateSecurityJournalTransitionV2(current, next);
    const snapshot = exportSecurityJournalSnapshotV2(next);
    this.#snapshot = snapshot;
    this.#head = { generation: next.generation, digest: next.digest };
  }

  /** The anchored head. */
  head(): SecurityJournalHeadV2 {
    return { ...this.#head };
  }

  /** Test-only: copies of the anchored head and stored snapshot bytes. */
  snapshotStateTestOnly(): { head: SecurityJournalHeadV2; snapshot: Uint8Array } {
    return { head: { ...this.#head }, snapshot: Uint8Array.from(this.#snapshot) };
  }

  /** Test-only: replaces the anchored head and stored snapshot (for rollback scenarios). */
  restoreStateTestOnly(state: { head: SecurityJournalHeadV2; snapshot: Uint8Array }): void {
    this.#head = { ...state.head };
    this.#snapshot = Uint8Array.from(state.snapshot);
  }
}

/** A reference store anchored at the genesis journal (Go NewJournalStore). */
export async function newJournalStoreTestOnly(): Promise<JournalStoreTestOnly> {
  return new JournalStoreTestOnly();
}
