// Resumption of committed work by claim ID from the claim store's persisted
// record (SPEC-v2 §7.11), mirroring Go resume_committed_v2_test.go.

import { test } from "node:test";
import assert from "node:assert/strict";

import { protocolClaimIDFromDigestV2 } from "../../src/challenge_claim_v2.js";
import { V2_MAX_TIMESTAMP_SECONDS } from "../../src/clock_bounds_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import {
  initialV2EvaluationProgress,
  resumeCommittedClaimV2,
  v2EvaluationInterruptedResult,
  type V2CommittedClaim,
  type V2CommittedClaimStore,
} from "../../src/evaluation_progress_v2.js";
import { releaseV2Decision, type CommittedV2Outcome, type V2ReleaseConfig } from "../../src/release_v2.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { corpusKeyPairs, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";

const lifecycle = load("lifecycle-scenarios.json");

/** Commits and publishes lifecycle request A (an allow) against a fresh reference store. */
async function releaseFixture(): Promise<{ store: StoreTestOnly; committed: CommittedV2Outcome; wire: Uint8Array; config: V2ReleaseConfig }> {
  const keys = await corpusKeyPairs();
  const verifier = keys.get(lifecycle.verifier_key)!;
  const request = lifecycle.requests.A;
  const store = new StoreTestOnly(request.now, lifecycle.lease_seconds, lifecycle.log_id, verifier);
  const { req, cb } = await buildVerifyRequest(request, unb64(lifecycle.bundles_b64[request.bundle]), zeroCounts());
  const outcome = await verifyProofBundleV2(req, { ...cb, claimStore: store });
  assert.equal(outcome.stage, "committed", `fixture did not commit: ${outcome.errorClass}`);
  const committed = outcome.committed!;
  const wire = await store.publishV2Receipt(committed.claimID(), committed.receiptBody());
  return { store, committed, wire, config: { verifierPublicKey: verifier.publicKey, logID: lifecycle.log_id, claimStore: store, checkpoint: store } };
}

/**
 * Answers loadV2CommittedClaim through edit, standing in for a claim store
 * that returns a damaged record. A non-async throw from edit reaches the
 * caller synchronously, as a store that throws outright (Go: panics).
 */
function committedRecordStore(base: StoreTestOnly, edit: (r: V2CommittedClaim) => void | Promise<void>, sync = false): V2CommittedClaimStore {
  if (sync) {
    return {
      loadV2CommittedClaim(): Promise<V2CommittedClaim> {
        edit({} as V2CommittedClaim);
        throw new Error("unreachable");
      },
    };
  }
  return {
    async loadV2CommittedClaim(claimID: string): Promise<V2CommittedClaim> {
      const record = await base.loadV2CommittedClaim(claimID);
      await edit(record);
      return record;
    },
  };
}

const hexToBytes = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16));

// SPEC-v2 §7.11: a service whose handoff died after the terminal commit
// resumes it from the store, and the resumed handoff is the committed one:
// release answers it exactly as the original.
test("resume: returns the committed handoff", async () => {
  const { store, committed, wire, config } = await releaseFixture();
  const resumed = await resumeCommittedClaimV2(store, committed.claimID());
  assert.notEqual(committed.allowHorizon(), null, "fixture is not an allow");
  assert.equal(resumed.claimID(), committed.claimID());
  assert.deepEqual(resumed.receiptBody(), committed.receiptBody());
  assert.equal(resumed.challengeExpiresAt(), committed.challengeExpiresAt());
  assert.equal(resumed.allowHorizon(), committed.allowHorizon());
  const result = await releaseV2Decision(resumed, wire, config);
  assert.equal(result.status, "released");
  assert.equal(result.decision?.decision(), "allow");
  const again = await releaseV2Decision(committed, wire, config);
  assert.equal(again.status, "released", "release of the original handoff after resumption is idempotent");
});

// The store's answers for a claim with no committed record pass through
// with their class; resumption commits nothing.
test("resume: refuses a claim with no committed record", async () => {
  const { store, committed } = await releaseFixture();
  await assert.rejects(resumeCommittedClaimV2(store, "unknown-claim"), (err) => v2ErrorClassOf(err) === "claim_not_found");
  const record = await store.loadV2CommittedClaim(committed.claimID());
  const lease = 30;
  const keys = await corpusKeyPairs();
  const evaluating = new StoreTestOnly(store.now(), lease, "ab".repeat(16), keys.get(lifecycle.verifier_key)!);
  await evaluating.claimV2(record.claim);
  await assert.rejects(resumeCommittedClaimV2(evaluating, record.claim.claimID), (err) => v2ErrorClassOf(err) === "claim_lease_live");
  evaluating.setTime(evaluating.now() + lease);
  await assert.rejects(resumeCommittedClaimV2(evaluating, record.claim.claimID), (err) => v2ErrorClassOf(err) === "claim_lease_lost");
  const terminal = await evaluating.loadV2TerminalClaim(record.claim.claimID);
  assert.equal(terminal.terminal, false, "resumption committed a result");
  await assert.rejects(resumeCommittedClaimV2(null as unknown as V2CommittedClaimStore, committed.claimID()), (err) => v2ErrorClassOf(err) === "configuration_invalid");
  await assert.rejects(resumeCommittedClaimV2(store, ""), (err) => v2ErrorClassOf(err) === "configuration_invalid");
});

const interruptedTerminal = (r: V2CommittedClaim): void => {
  const { terminalResult, receiptBody } = v2EvaluationInterruptedResult(r.claim, r.claim.issuedAt, initialV2EvaluationProgress());
  r.terminalResult = terminalResult;
  r.receiptBody = receiptBody;
};

// Resumption applies the terminal compare-and-set's checks to the record the
// store returns (§7.3, §7.5, §6.8). A record that fails one is the store's
// failure, never a handoff, so no damaged record can reach release.
test("resume: refuses a record that fails its checks", async (t) => {
  const { store: base, committed } = await releaseFixture();
  const cases: Record<string, { edit: (r: V2CommittedClaim) => void; sync?: boolean }> = {
    "record for another claim": { edit: (r) => { r.claim.claimID = "0".repeat(r.claim.claimID.length); } },
    "well-formed record of a different claim": {
      edit: (r) => {
        r.claim.replayEpoch++;
        r.claim.claimID = protocolClaimIDFromDigestV2(r.claim.namespace, r.claim.replayEpoch, hexToBytes(r.claim.challengeDigest.replace(/^sha384:/, "")));
      },
    },
    "claim ID not derived from the replay key": { edit: (r) => { r.claim.replayEpoch++; } },
    "challenge digest not a sha384 digest": { edit: (r) => { r.claim.challengeDigest = r.claim.challengeDigest.toUpperCase(); } },
    "body for another agent": { edit: (r) => { r.claim.agentID += "x"; } },
    "terminal result differs from the body": {
      edit: (r) => {
        const text = new TextDecoder().decode(r.terminalResult);
        r.terminalResult = new TextEncoder().encode(text.replace(`"allow"`, `"deny"`));
      },
    },
    "allow with no horizon": { edit: (r) => { r.allowHorizon = 0; } },
    "allow horizon outside the timestamp domain": { edit: (r) => { r.allowHorizon = V2_MAX_TIMESTAMP_SECONDS + 1; } },
    "interrupted result with an allow horizon": { edit: interruptedTerminal },
    "store failure without a class": { edit: () => { throw new Error("disk read failed"); } },
    "store throws": { edit: () => { throw "disk read failed"; }, sync: true },
  };
  for (const [name, { edit, sync }] of Object.entries(cases)) {
    await t.test(name, async () => {
      let resumed: CommittedV2Outcome | undefined;
      await assert.rejects(
        (async () => { resumed = await resumeCommittedClaimV2(committedRecordStore(base, edit, sync), committed.claimID()); })(),
        (err) => v2ErrorClassOf(err) === "claim_store_unavailable",
      );
      assert.equal(resumed, undefined, "a damaged record produced a handoff");
    });
  }
  // The interrupted result itself, with no horizon, is a valid record.
  const valid = committedRecordStore(base, (r) => {
    interruptedTerminal(r);
    r.allowHorizon = 0;
  });
  await resumeCommittedClaimV2(valid, committed.claimID());
});
