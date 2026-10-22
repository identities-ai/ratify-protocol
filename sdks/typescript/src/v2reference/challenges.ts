// Test-only in-memory challenge issuance store (Go v2reference/challenges.go).
// Never durable; never offered as a default.

import { challengeClaimDigestV2 } from "../challenge_claim_v2.js";
import { ErrV2ChallengeIssuanceConflict, ErrV2ChallengeIssuanceNotFound, type V2ChallengeIssuanceStore } from "../challenge_issuance_v2.js";
import { V2SentinelError } from "../errors_v2.js";
import { hexOf } from "../json_v2.js";
import { cloneExpectedChallengeV2, type ExpectedChallengeV2 } from "../verify_v2_preflight.js";

/** A scripted persistence failure. */
export const ErrPersistFailedTestOnly = new V2SentinelError("v2reference: scripted issuance persistence failure");

export type PersistFaultTestOnly = "ok" | "fail_before_commit" | "fail_after_commit";

export function issuanceKeyTestOnly(namespace: string, epoch: number, digest: Uint8Array): string {
  return `${new TextEncoder().encode(namespace).length}:${namespace}|${epoch}|${hexOf(digest)}`;
}

/** The test-only issuance store. Never overwrites an existing record. */
export class ChallengeIssuanceStoreTestOnly implements V2ChallengeIssuanceStore {
  records = new Map<string, ExpectedChallengeV2>();
  fault: PersistFaultTestOnly = "ok";

  /** Makes the next persist fail before or after it commits. */
  failNextPersist(fault: PersistFaultTestOnly): void {
    this.fault = fault;
  }

  get size(): number {
    return this.records.size;
  }

  async persistV2Challenge(record: ExpectedChallengeV2): Promise<void> {
    const fault = this.fault;
    this.fault = "ok";
    if (fault === "fail_before_commit") throw ErrPersistFailedTestOnly;
    const key = issuanceKeyTestOnly(record.verifierNamespace, record.replayEpoch, challengeClaimDigestV2(record.value));
    if (this.records.has(key)) throw ErrV2ChallengeIssuanceConflict;
    this.records.set(key, cloneExpectedChallengeV2(record));
    if (fault === "fail_after_commit") throw ErrPersistFailedTestOnly;
  }

  async loadV2Challenge(namespace: string, replayEpoch: number, claimDigest: Uint8Array): Promise<ExpectedChallengeV2> {
    const record = this.records.get(issuanceKeyTestOnly(namespace, replayEpoch, claimDigest));
    if (!record) throw ErrV2ChallengeIssuanceNotFound;
    return cloneExpectedChallengeV2(record);
  }
}
