// Part B release, finalization and checkpoint rules (SPEC-v2 §6.9, §7.5,
// §7.6, §7.8), mirroring Go release_v2_withheld_test.go,
// TestFinalizeClaimProofBundleV2BindsReceiptBodyToSealedClaim,
// v2reference/checkpoint_test.go and
// TestRateAtFinalizationStoreNeverReservesProvisionally.

import { test } from "node:test";
import assert from "node:assert/strict";

import { evaluateProofBundleV2LocalAuthorization } from "../../src/authorization_v2.js";
import { claimProofBundleV2, finalizeClaimProofBundleV2, validateV2FinalizationPayload, type V2ChallengeClaim } from "../../src/claim_store_v2.js";
import { errorIs, v2ErrorClassOf } from "../../src/errors_v2.js";
import { initialV2EvaluationProgress, v2EvaluationInterruptedResult } from "../../src/evaluation_progress_v2.js";
import { canonicalJSONV2 } from "../../src/json_v2.js";
import { decodeProofBundleV2 } from "../../src/protocol_v2_wire.js";
import {
  ErrV2AcknowledgementNotFound,
  ErrV2ReleaseStateMismatch,
  releaseV2Decision,
  type CommittedV2Outcome,
  type V2ReleaseConfig,
  type V2ReleaseRecord,
} from "../../src/release_v2.js";
import {
  decodeVerificationReceiptBodyV2,
  decodeVerificationReceiptV2,
  verificationReceiptV2Body,
  verificationReceiptV2Digest,
  type VerificationReceiptV2,
} from "../../src/verification_receipt_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { preflightProofBundleV2 } from "../../src/verify_v2_preflight.js";
import { ErrNotAcknowledgedTestOnly, StoreTestOnly } from "../../src/v2reference/store.js";
import { keyIDV2 } from "../../src/crypto_v2.js";
import { corpusKeyPairs, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";

const lifecycle = load("lifecycle-scenarios.json");

/** Commits and publishes lifecycle request A against a fresh reference store. */
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

/** The reference store with every recordV2Release failing with err. */
function recordFailing(store: StoreTestOnly, err: unknown): { view: StoreTestOnly; calls: () => number } {
  let calls = 0;
  const view = new Proxy(store, {
    get(target, prop, receiver) {
      if (prop === "recordV2Release") {
        return async () => {
          calls++;
          throw err;
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { view, calls: () => calls };
}

// A withheld result must never become released (SPEC-v2 §6.9). If recording
// it fails, the call is still withheld: failing open to pending would let a
// later call with a recovered clock release a decision already withheld.
test("release: withheld when recording the withheld result fails", async () => {
  const { store, committed, wire, config } = await releaseFixture();
  const failing = recordFailing(store, new Error("store unavailable"));
  store.setTime(committed.challengeExpiresAt());
  const result = await releaseV2Decision(committed, wire, { ...config, claimStore: failing.view });
  assert.deepEqual([result.status, result.reason, result.decision], ["withheld", "challenge_expired", null]);
  assert.equal(failing.calls(), 1);
});

// The first record wins: a different record already present when release
// tries to record its withheld result is a state mismatch.
test("release: a conflicting record while withholding is rejected", async () => {
  const { store, committed, wire, config } = await releaseFixture();
  const failing = recordFailing(store, ErrV2ReleaseStateMismatch);
  store.setTime(committed.challengeExpiresAt());
  const result = await releaseV2Decision(committed, wire, { ...config, claimStore: failing.view });
  assert.deepEqual([result.status, result.reason], ["rejected", "release_state_mismatch"]);
});

// A recorded withheld result is returned right after the committed-state
// step, before any receipt or acknowledgement is consulted.
test("release: a recorded withheld result answers before the receipt step", async () => {
  const { store, committed, wire, config } = await releaseFixture();
  store.setTime(committed.challengeExpiresAt());
  let result = await releaseV2Decision(committed, wire, config);
  assert.deepEqual([result.status, result.reason], ["withheld", "challenge_expired"]);
  result = await releaseV2Decision(committed, null, { ...config, checkpoint: null as never });
  assert.equal(result.status, "rejected", "missing checkpoint configuration is still a state mismatch");
  result = await releaseV2Decision(committed, null, config);
  assert.deepEqual([result.status, result.reason], ["withheld", "challenge_expired"]);
});

// The reference store keeps the first release record: an identical repeat is
// a no-op, a different outcome or reason is a state mismatch, and an outcome
// that is not a release record is refused before anything is stored.
test("reference store: the first release or withheld record wins", async () => {
  const { store, committed, wire } = await releaseFixture();
  const entry = verificationReceiptV2Digest(decodeVerificationReceiptV2(wire));
  const base = { claimID: committed.claimID(), entryHash: entry, ackTimestamp: 7 };
  const withheld: V2ReleaseRecord = { ...base, outcome: "withheld", reason: "clock_regressed" };
  const invalid: Record<string, V2ReleaseRecord> = {
    "no outcome": { ...base, outcome: "" as never, reason: "" },
    "released with reason": { ...base, outcome: "released", reason: "clock_regressed" },
    "withheld, other cause": { ...base, outcome: "withheld", reason: "receipt_invalid" },
    "rejected outcome": { ...base, outcome: "rejected", reason: "receipt_invalid" },
  };
  for (const [name, record] of Object.entries(invalid)) {
    await assert.rejects(store.recordV2Release(record), (e) => v2ErrorClassOf(e) === "configuration_invalid", name);
  }
  await store.recordV2Release(withheld);
  await store.recordV2Release(withheld);
  const others: Record<string, V2ReleaseRecord> = {
    released: { ...base, outcome: "released", reason: "" },
    "other reason": { ...base, outcome: "withheld", reason: "challenge_expired" },
  };
  for (const [name, record] of Object.entries(others)) {
    await assert.rejects(store.recordV2Release(record), (e) => errorIs(e, ErrV2ReleaseStateMismatch), name);
  }
  const loaded = await store.loadV2TerminalClaim(committed.claimID());
  assert.deepEqual([loaded.release?.outcome, loaded.release?.reason], ["withheld", "clock_regressed"]);
});

// SPEC-v2 §7.5: a capability holder that changes any bound member of the
// receipt body could otherwise get a signed, log-appended receipt naming
// another proof, agent, or scope. Each mismatch is refused before the store is
// called, and the genuine body still finalizes afterwards.
test("finalization: the receipt body is bound to the sealed claim", async () => {
  const keys = await corpusKeyPairs();
  let finalizeCalls = 0;
  class Counting extends StoreTestOnly {
    override async finalizeV2Claim(...args: Parameters<StoreTestOnly["finalizeV2Claim"]>): Promise<boolean> {
      finalizeCalls++;
      return super.finalizeV2Claim(...args);
    }
  }
  const request = lifecycle.requests.A;
  const store = new Counting(request.now, lifecycle.lease_seconds, lifecycle.log_id, keys.get(lifecycle.verifier_key)!);
  const wire = unb64(lifecycle.bundles_b64[request.bundle]);
  const { req } = await buildVerifyRequest(request, wire, zeroCounts());
  const bundle = decodeProofBundleV2(wire);
  const pre = await preflightProofBundleV2(bundle, req.expected, req.contextPolicy, req.requiredScope, req.verifierNamespace,
    req.replayEpoch, request.now, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  const { claim, token } = await claimProofBundleV2(store, bundle, pre, req.verifierNamespace, req.replayEpoch, request.now);
  const assessment = await evaluateProofBundleV2LocalAuthorization(bundle, {
    futureSkewSeconds: req.futureSkewSeconds, requiredScope: req.requiredScope, context: req.context, tzdbVersion: req.tzdbVersion,
    contextPolicy: req.contextPolicy, claimToken: token, trustConfigured: false,
  });
  assert.equal(assessment.reason, "trust_unavailable");
  const genuineReceipt = decodeVerificationReceiptBodyV2(v2EvaluationInterruptedResult(claim, request.now, initialV2EvaluationProgress()).receiptBody);
  Object.assign(genuineReceipt, { decision_reason: "trust_unavailable", trust_assessment: "unavailable" });
  const genuine = verificationReceiptV2Body(genuineReceipt);
  const terminal = canonicalJSONV2({ decision: "indeterminate", decision_reason: "trust_unavailable", identity_status: "authorization_unverified" });
  const mutate = (edit: (r: VerificationReceiptV2) => void): Uint8Array => {
    const r = decodeVerificationReceiptBodyV2(genuine);
    edit(r);
    return verificationReceiptV2Body(r);
  };
  const otherID = keyIDV2(keys.get("root")!.publicKey);
  assert.ok(otherID !== claim.verifierID && otherID !== claim.agentID, "fixture root ID collides with a sealed ID");
  const otherDigest = "sha384:" + "2".repeat(96);
  const edits: Record<string, (r: VerificationReceiptV2) => void> = {
    verifier_id: (r) => (r.verifier_id = otherID),
    agent_id: (r) => (r.agent_id = otherID),
    bundle_hash: (r) => (r.bundle_hash = "sha384:" + "0".repeat(96)),
    issuer_ids: (r) => (r.issuer_ids = r.issuer_ids!.slice(0, -1)),
    required_scope: (r) => (r.required_scope = "data:write"),
    constraint_evaluators: (r) => (r.constraint_evaluators = [{ type: "com.ratifyprotocol.max_count", profile_digest: "sha384:" + "1".repeat(96) }]),
  };
  assert.notEqual(otherDigest, claim.contextPolicyDigest);
  for (const [name, edit] of Object.entries(edits)) {
    const body = mutate(edit);
    await assert.rejects(finalizeClaimProofBundleV2(store, token!, terminal, body), (e) => v2ErrorClassOf(e) === "configuration_invalid", name);
    assert.equal(finalizeCalls, 0, `${name}: the store was called`);
    assert.throws(() => validateV2FinalizationPayload(claim, terminal, body), (e) => v2ErrorClassOf(e) === "configuration_invalid", name);
  }
  // A trust_unavailable body cannot carry a context policy digest, so the
  // context_policy_digest binding is checked on an evaluation_interrupted
  // payload (the one Go's test finalizes).
  const interrupted = v2EvaluationInterruptedResult(claim, request.now, initialV2EvaluationProgress());
  const otherContext = decodeVerificationReceiptBodyV2(interrupted.receiptBody);
  Object.assign(otherContext, { trust_assessment: "trusted", context_assessment: "bound", context_policy_digest: otherDigest });
  validateV2FinalizationPayload(claim, interrupted.terminalResult, interrupted.receiptBody);
  assert.throws(() => validateV2FinalizationPayload(claim, interrupted.terminalResult, verificationReceiptV2Body(otherContext)),
    (e) => v2ErrorClassOf(e) === "configuration_invalid", "context_policy_digest");
  await assert.rejects(finalizeClaimProofBundleV2(store, token!, terminal, canonicalJSONV2({ decision: "indeterminate", decision_reason: "trust_unavailable" })),
    (e) => v2ErrorClassOf(e) === "malformed", "a non-receipt body is malformed");
  assert.equal(finalizeCalls, 0);
  assert.equal(await finalizeClaimProofBundleV2(store, token!, terminal, genuine), true);
  assert.equal(finalizeCalls, 1);
});

/** A reference store holding n claims committed by lease-expiry recovery, in log order. */
async function committedReceiptStore(n: number): Promise<{ store: StoreTestOnly; claims: V2ChallengeClaim[] }> {
  const now = 1800000000;
  const verifier = (await corpusKeyPairs()).get("verifier")!;
  const verifierID = keyIDV2(verifier.publicKey);
  const store = new StoreTestOnly(now, 30, "dddddddddddddddddddddddddddddd01", verifier);
  const claims: V2ChallengeClaim[] = [];
  for (let i = 0; i < n; i++) {
    const digest = "sha384:" + "0".repeat(95) + String(i + 1);
    const claim: V2ChallengeClaim = {
      claimID: "claim-" + String.fromCharCode(97 + i), namespace: "ns", replayEpoch: 0, challengeDigest: "sha384:" + "9".repeat(96),
      proofDigest: digest, bundleHash: digest, issuerIDs: ["b".repeat(64)], requiredScope: "data:read", contextPolicyDigest: "",
      verifierID, agentID: "a".repeat(64), requiresRate: false, rateBatch: [], issuedAt: now - 10, expiresAt: now + 290,
      maxAgeSeconds: 300, clockSkewSeconds: 5, streamID: null, streamSeq: null, constraintEvaluators: [],
    };
    await store.claimV2(claim);
    claims.push(claim);
  }
  store.setTime(now + 30);
  for (const claim of claims) {
    const loaded = await store.loadV2InterruptedClaim(claim.claimID);
    const r = v2EvaluationInterruptedResult(loaded.claim, loaded.claimedAt, loaded.progress);
    await store.recoverInterruptedV2Claim(claim.claimID, r.terminalResult, r.receiptBody);
  }
  return { store, claims };
}

async function publishedTuple(store: StoreTestOnly, claimID: string): Promise<{ receipt: VerificationReceiptV2; entry: Uint8Array }> {
  const loaded = await store.loadV2InterruptedClaim(claimID);
  const { receiptBody } = v2EvaluationInterruptedResult(loaded.claim, loaded.claimedAt, loaded.progress);
  const receipt = decodeVerificationReceiptV2(await store.publishV2Receipt(claimID, receiptBody));
  return { receipt, entry: verificationReceiptV2Digest(receipt) };
}

// A different entry hash at an acknowledged sequence is a fork (SPEC-v2
// §7.8). If the checkpoint kept acknowledging after it, a forked log could
// keep releasing decisions; it must acknowledge nothing further for the log.
test("reference checkpoint: a fork freezes the log", async () => {
  const { store, claims } = await committedReceiptStore(2);
  const now = 1800000000;
  const first = await publishedTuple(store, claims[0]!.claimID);
  store.setAcknowledgementWithheld(true);
  const second = await publishedTuple(store, claims[1]!.claimID);
  store.setTime(now + 40);
  const forked = Uint8Array.from(first.entry);
  forked[0]! ^= 1;
  await assert.rejects(store.acknowledgeV2Receipt(first.receipt.log_id, 1, first.receipt.previous_receipt_hash, forked),
    (e) => errorIs(e, ErrNotAcknowledgedTestOnly), "fork at an acknowledged sequence");
  const retry = await store.acknowledgeV2Receipt(first.receipt.log_id, 1, first.receipt.previous_receipt_hash, first.entry);
  assert.equal(retry.timestamp, now + 30, "identical retry of a pre-fork acknowledgement");
  store.setAcknowledgementWithheld(false);
  await assert.rejects(store.acknowledgeV2Receipt(second.receipt.log_id, 2, first.entry, second.entry),
    (e) => errorIs(e, ErrNotAcknowledgedTestOnly), "a frozen log acknowledged its next entry");
  await assert.rejects(store.getV2Acknowledgement(second.receipt.log_id, 2), (e) => errorIs(e, ErrV2AcknowledgementNotFound),
    "the publisher's submission was acknowledged after the fork");
  assert.deepEqual(second.receipt.previous_receipt_hash, first.entry, "fixture receipts are linked");
});

// A refusal that is not a fork, such as an out-of-order sequence, must not
// freeze the log.
test("reference checkpoint: a refusal without a fork does not freeze the log", async () => {
  const { store, claims } = await committedReceiptStore(2);
  store.setAcknowledgementWithheld(true);
  const first = await publishedTuple(store, claims[0]!.claimID);
  const second = await publishedTuple(store, claims[1]!.claimID);
  await assert.rejects(store.acknowledgeV2Receipt(second.receipt.log_id, 2, first.entry, second.entry));
  await store.acknowledgeV2Receipt(first.receipt.log_id, 1, first.receipt.previous_receipt_hash, first.entry);
  await store.acknowledgeV2Receipt(second.receipt.log_id, 2, first.entry, second.entry);
});

// The reference store admits max_rate inside its terminal compare-and-set
// (SPEC-v2 §7.1, §7.6). Its provisional reservation call exists only to
// satisfy the rate-store interface and must never report capacity.
test("reference store: rate admission at finalization never reserves provisionally", async () => {
  const keys = await corpusKeyPairs();
  const store = new StoreTestOnly(1800000000, 30, lifecycle.log_id, keys.get(lifecycle.verifier_key)!).withRateAtFinalization();
  await assert.rejects(store.reserveV2RateBatch("claim", new Uint8Array(32), "sha384:x", [{ issuerID: "i", certID: "c", windowS: 60, limit: 1 }]));
});
