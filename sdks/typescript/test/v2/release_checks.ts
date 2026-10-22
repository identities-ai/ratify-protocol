// Shared committed-outcome and released-decision checks for the Part B runners.

import assert from "node:assert/strict";

import type { V2AuthoritativeClock } from "../../src/claim_store_v2.js";
import type { CommittedV2Outcome, V2ReleasedDecision } from "../../src/release_v2.js";
import { decodeVerificationReceiptBodyV2 } from "../../src/verification_receipt_v2.js";
import type { Any } from "./helpers.js";

export const fixedClock = (now: number): V2AuthoritativeClock => ({ authoritativeTimeV2: async () => now });

/** Committed decision check (test only; applications never parse the body). */
export function checkCommitted(step: number, c: CommittedV2Outcome, want: Any): void {
  const body = decodeVerificationReceiptBodyV2(c.receiptBody());
  assert.equal(body.decision, want.decision, `step ${step} committed decision`);
  assert.equal(body.decision_reason, want.decision_reason, `step ${step} committed reason`);
  if (want.trust_assessment) assert.equal(body.trust_assessment, want.trust_assessment, `step ${step} trust`);
  if (want.status_assessment) assert.equal(body.status_assessment, want.status_assessment, `step ${step} status`);
  if (want.context_assessment) assert.equal(body.context_assessment, want.context_assessment, `step ${step} context`);
  assert.equal(c.allowHorizon() ?? 0, want.allow_horizon ?? 0, `step ${step} allow horizon`);
}

/**
 * allowed() compares the receiver's time only with the sealed exclusive
 * deadlines, and changing returned copies never changes the decision.
 */
export async function checkReleasedDecisionAllowed(step: number, d: V2ReleasedDecision): Promise<void> {
  const at = (now: number) => d.allowed(fixedClock(now));
  const horizon = d.allowHorizon();
  assert.equal(horizon !== null, d.decision() === "allow", `step ${step} horizon presence`);
  if (horizon === null) {
    assert.equal(await at(d.releaseTime()), false, `step ${step}: a released ${d.decision()} is allowed`);
    return;
  }
  const deadline = Math.min(horizon, d.challengeExpiresAt());
  assert.ok(await at(d.releaseTime()), `step ${step} allowed at release`);
  assert.ok(await at(deadline - 1), `step ${step} allowed before deadline`);
  assert.equal(await at(deadline), false, `step ${step} exclusive deadline`);
  assert.equal(await at(deadline + 1), false, `step ${step} after deadline`);
  assert.equal(await d.allowed({ authoritativeTimeV2: async () => { throw new Error("clock down"); } }), false);
  assert.equal(await at(-1), false);
  const scope = d.grantedScope();
  const wire = d.receiptWire();
  const receipt = d.receipt();
  scope.fill("mutated");
  wire.fill(0);
  receipt.decision = "deny";
  receipt.sequence += 1;
  const again = d.receipt();
  assert.ok(again.decision === "allow" && again.sequence === receipt.sequence - 1 && !d.grantedScope().includes("mutated") && (await at(d.releaseTime())),
    `step ${step}: a returned copy changed the released decision`);
}

