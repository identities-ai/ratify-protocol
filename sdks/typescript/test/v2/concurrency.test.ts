// Concurrency and issuer-collision tests against the Part B reference store
// (SPEC-v2 §8.1 items 3 and 4): concurrent claims of one challenge,
// concurrent finalization and interruption recovery, concurrent stream
// advances, concurrent release, and same cert_id / rate-counter key under two
// issuers. (Concurrent journal compare-and-swap and status/journal issuer
// isolation are in security_journal.test.ts.)

import { test } from "node:test";
import assert from "node:assert/strict";

import type { V2RateReservation } from "../../src/audience_v2.js";
import { claimProofBundleV2, finalizeClaimProofBundleV2, type V2ChallengeClaim } from "../../src/claim_store_v2.js";
import { evaluateProofBundleV2LocalAuthorization } from "../../src/authorization_v2.js";
import { errorIs, v2ErrorClassOf, ErrV2ClaimProofConflict, ErrV2RateLimitExceeded } from "../../src/errors_v2.js";
import { decodeProofBundleV2 } from "../../src/protocol_v2_wire.js";
import { preflightProofBundleV2 } from "../../src/verify_v2_preflight.js";
import { canonicalJSONV2 } from "../../src/json_v2.js";
import { recoverInterruptedClaimV2, initialV2EvaluationProgress, v2EvaluationInterruptedResult } from "../../src/evaluation_progress_v2.js";
import { decodeVerificationReceiptBodyV2, verificationReceiptV2Body, type VerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { releaseV2Decision } from "../../src/release_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { corpusKeyPairs, keyedClaim, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";

const lifecycle = load("lifecycle-scenarios.json");
const START = 1800000000;
const ISSUER_A = "a".repeat(64);
const ISSUER_B = "b".repeat(64);

async function newStore(lease = 60): Promise<StoreTestOnly> {
  const keys = await corpusKeyPairs();
  return new StoreTestOnly(START, lease, "0123456789abcdef0123456789abcdef", keys.get("verifier")!);
}

function claimOf(n: number, extra: Partial<V2ChallengeClaim> = {}): V2ChallengeClaim {
  const hex = n.toString(16).padStart(64, "0");
  return keyedClaim({
    claimID: hex, namespace: "verify-test", replayEpoch: 3, challengeDigest: "sha384:" + hex.padEnd(96, "0"), proofDigest: "sha384:" + "1".repeat(96),
    bundleHash: "sha384:" + "1".repeat(96), issuerIDs: [ISSUER_A], requiredScope: "data:read", contextPolicyDigest: "", verifierID: "c".repeat(64),
    agentID: "d".repeat(64), requiresRate: false, rateBatch: [], issuedAt: START - 10, expiresAt: START + 290, maxAgeSeconds: 300,
    clockSkewSeconds: 5, streamID: null, streamSeq: null, constraintEvaluators: [], ...extra,
  });
}

/**
 * A terminal result and a canonical receipt body bound to claim (SPEC-v2
 * §7.5): the store refuses a body for any other claim. edit adjusts the
 * interrupted body to another terminal decision.
 */
function payloadFor(claim: V2ChallengeClaim, identityStatus: string, edit: (r: VerificationReceiptV2) => void = () => {}): { terminal: Uint8Array; body: Uint8Array } {
  const receipt = decodeVerificationReceiptBodyV2(v2EvaluationInterruptedResult(claim, START, initialV2EvaluationProgress()).receiptBody);
  edit(receipt);
  return {
    terminal: canonicalJSONV2({ decision: receipt.decision, decision_reason: receipt.decision_reason, identity_status: identityStatus }),
    body: verificationReceiptV2Body(receipt),
  };
}

const denyFor = (claim: V2ChallengeClaim) => payloadFor(claim, "unauthorized", (r) => {
  Object.assign(r, { decision: "deny", decision_reason: "unauthorized", identity_status: "unauthorized", trust_assessment: "untrusted" });
});
const interruptedFor = (claim: V2ChallengeClaim) => payloadFor(claim, "authorization_unverified");

test("concurrency: concurrent end-to-end verifications of one challenge commit exactly once", async () => {
  const store = await newStore();
  const request = { ...lifecycle.requests.A, now: START };
  const bundle = unb64(lifecycle.bundles_b64[request.bundle]);
  const runs = await Promise.all(Array.from({ length: 8 }, async () => {
    const { req, cb } = await buildVerifyRequest(request, bundle, zeroCounts());
    return verifyProofBundleV2(req, { ...cb, claimStore: store });
  }));
  const stages = runs.map((r) => r.stage).sort();
  assert.equal(stages.filter((s) => s === "committed").length, 1, stages.join(","));
  assert.equal(stages.filter((s) => s === "replay").length, 7, stages.join(","));
  assert.equal(store.outbox.length, 1);
});

test("concurrency: a different proof for an already claimed challenge is claim_replay", async () => {
  const store = await newStore();
  const results = await Promise.allSettled([
    store.claimV2(claimOf(1)),
    store.claimV2(claimOf(1, { proofDigest: "sha384:" + "2".repeat(96), bundleHash: "sha384:" + "2".repeat(96) })),
  ]);
  const created = results.filter((r) => r.status === "fulfilled" && r.value.disposition === "created");
  const conflicts = results.filter((r) => r.status === "rejected" && r.reason === ErrV2ClaimProofConflict);
  assert.equal(created.length, 1);
  assert.equal(conflicts.length, 1);
  assert.equal(v2ErrorClassOf(ErrV2ClaimProofConflict), "claim_replay");
});

test("concurrency: concurrent stream advances accept exactly one per sequence", async () => {
  const store = await newStore();
  const streamID = new Uint8Array(32).fill(0x5a);
  const attempts = Array.from({ length: 6 }, (_, i) => store.claimV2(claimOf(100 + i, { streamID, streamSeq: 1 })));
  const results = await Promise.allSettled(attempts);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  for (const r of results) if (r.status === "rejected") assert.equal(v2ErrorClassOf(r.reason), "stream_sequence_mismatch");
  // A rejected advance consumed nothing: those challenges are still claimable at the next sequence.
  const next = await Promise.allSettled([store.claimV2(claimOf(200, { streamID, streamSeq: 2 })), store.claimV2(claimOf(201, { streamID, streamSeq: 2 }))]);
  assert.equal(next.filter((r) => r.status === "fulfilled").length, 1);
});

test("concurrency: concurrent identical finalization commits exactly once", async () => {
  const store = await newStore();
  const { ownerToken } = await store.claimV2(claimOf(2));
  const deny = denyFor(claimOf(2));
  const results = await Promise.all(Array.from({ length: 5 }, () => store.finalizeV2Claim(claimOf(2).claimID, ownerToken!, deny.terminal, deny.body, 0)));
  assert.deepEqual(results.sort(), [false, false, false, false, true]);
  assert.equal(store.outbox.length, 1);
});

test("concurrency: finalization racing lease-expiry recovery yields one terminal result", async () => {
  const store = await newStore(30);
  const claim = claimOf(3);
  const { ownerToken } = await store.claimV2(claim);
  await store.recordV2EvaluationProgress(claim.claimID, ownerToken!, initialV2EvaluationProgress());
  store.setTime(START + 30);
  const deny = denyFor(claim);
  const interrupted = interruptedFor(claim);
  const [finalized, recovered] = await Promise.allSettled([
    store.finalizeV2Claim(claim.claimID, ownerToken!, deny.terminal, deny.body, 0),
    store.recoverInterruptedV2Claim(claim.claimID, interrupted.terminal, interrupted.body),
  ]);
  assert.equal(finalized.status, "rejected");
  assert.equal(v2ErrorClassOf((finalized as PromiseRejectedResult).reason), "claim_lease_lost");
  assert.equal(recovered.status, "fulfilled");
  assert.equal(store.outbox.length, 1);
  // A late evaluator cannot replace the recovered result.
  await assert.rejects(store.finalizeV2Claim(claim.claimID, ownerToken!, deny.terminal, deny.body, 0), (e) => v2ErrorClassOf(e) === "claim_already_terminal");
});

test("store: a claim_already_terminal error exposes no live store state", async () => {
  // SPEC-v2 §7.3: a committed claim, its release record and its abandonment
  // are immutable. A late evaluator receives the error through the verify
  // outcome, so nothing reachable from the error may alias the store's
  // record, or a caller could rewrite the horizon or abandonment that
  // release later reads.
  const store = await newStore(30);
  const claim = claimOf(7);
  const { ownerToken } = await store.claimV2(claim);
  store.setTime(START + 31);
  await recoverInterruptedClaimV2(store, claim.claimID);
  const before = await store.loadV2TerminalClaim(claim.claimID);
  const deny = denyFor(claim);
  const late = [
    () => store.recordV2EvaluationProgress(claim.claimID, ownerToken!, initialV2EvaluationProgress()),
    () => store.finalizeV2Claim(claim.claimID, ownerToken!, deny.terminal, deny.body, 0),
  ];
  for (const write of late) {
    const err = await write().then(() => assert.fail("a late write must be refused"), (e: unknown) => e);
    assert.equal(v2ErrorClassOf(err), "claim_already_terminal");
    const leaked = (err as { record?: { abandoned: boolean; allowHorizon: number; state: string } }).record;
    if (leaked) Object.assign(leaked, { abandoned: true, allowHorizon: 4102444800, state: "evaluating" });
    assert.deepEqual(await store.loadV2TerminalClaim(claim.claimID), before);
  }
});

test("concurrency: concurrent lease-expiry recovery of a verified claim commits once", async () => {
  const store = await newStore(30);
  const claim = claimOf(4);
  await store.claimV2(claim);
  store.setTime(START + 31);
  const results = await Promise.allSettled(Array.from({ length: 4 }, () => recoverInterruptedClaimV2(store, claim.claimID)));
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 4, "identical recovery is idempotent");
  assert.equal(store.outbox.length, 1);
});

test("concurrency: concurrent release of one committed outcome records one release", async () => {
  const keys = await corpusKeyPairs();
  const verifier = keys.get(lifecycle.verifier_key)!;
  const store = new StoreTestOnly(START, lifecycle.lease_seconds, lifecycle.log_id, verifier);
  const request = { ...lifecycle.requests.A, now: START };
  const { req, cb } = await buildVerifyRequest(request, unb64(lifecycle.bundles_b64[request.bundle]), zeroCounts());
  const outcome = await verifyProofBundleV2(req, { ...cb, claimStore: store });
  assert.equal(outcome.stage, "committed");
  const wire = await store.publishV2Receipt(outcome.committed!.claimID(), outcome.committed!.receiptBody());
  const config = { verifierPublicKey: verifier.publicKey, logID: lifecycle.log_id, claimStore: store, checkpoint: store };
  const results = await Promise.all(Array.from({ length: 6 }, () => releaseV2Decision(outcome.committed!, wire, config)));
  const statuses = new Set(results.map((r) => `${r.status}/${r.reason}/${r.decision?.decision() ?? ""}`));
  assert.equal(statuses.size, 1, [...statuses].join(" | "));
  const record = await store.loadV2TerminalClaim(outcome.committed!.claimID());
  if (results[0]!.status === "released") assert.ok(record.release !== null);
});

test("issuer collision: the same cert_id and window under two issuers use separate rate counters", async () => {
  const store = await newStore();
  const atFinal = store.withRateAtFinalization();
  const batch = (issuerID: string): V2RateReservation[] => [{ issuerID, certID: "cert-shared", windowS: 60, limit: 1 }];
  const finalizeAllow = async (n: number, issuerID: string) => {
    const claim = claimOf(n, { requiresRate: true, rateBatch: batch(issuerID), issuerIDs: [issuerID], contextPolicyDigest: "sha384:" + "7".repeat(96) });
    const { ownerToken } = await atFinal.claimV2(claim);
    const { terminal, body } = payloadFor(claim, "authorized_agent", (r) => Object.assign(r, {
      decision: "allow", decision_reason: "authorized", identity_status: "authorized_agent", trust_assessment: "trusted",
      status_assessment: "current", context_assessment: "not_required", context_policy_digest: claim.contextPolicyDigest,
      granted_scope: [claim.requiredScope],
      status_evidence_digests: [{ digest: "sha384:" + "e".repeat(96), issuer_id: issuerID, object_type_code: 3, sequence: 1, status_key_id: "f".repeat(64) }],
    }));
    return atFinal.finalizeV2Claim(claim.claimID, ownerToken!, terminal, body, START + 100);
  };
  assert.equal(await finalizeAllow(10, ISSUER_A), true);
  assert.equal(await finalizeAllow(11, ISSUER_B), true, "issuer B's counter is independent of issuer A's");
  await assert.rejects(finalizeAllow(12, ISSUER_A), (e) => e === ErrV2RateLimitExceeded, "issuer A's counter is exhausted");
  await assert.rejects(finalizeAllow(13, ISSUER_B), (e) => e === ErrV2RateLimitExceeded, "issuer B's counter is exhausted");
});

test("issuer collision: claims for bundles sharing a cert_id under two issuers are independent", async () => {
  const store = await newStore();
  const a = await store.claimV2(claimOf(20, { issuerIDs: [ISSUER_A] }));
  const b = await store.claimV2(claimOf(21, { issuerIDs: [ISSUER_B] }));
  assert.equal(a.disposition, "created");
  assert.equal(b.disposition, "created");
  assert.notDeepEqual(a.ownerToken, b.ownerToken);
});

// Go FinalizeClaimProofBundleV2 classifies a store's rate exhaustion as
// claim_store_unavailable while errors.Is still finds the sentinel; every SDK
// reports that one SPEC-v2 §2.7 class for this refusal.
test("finalization: a store's rate exhaustion keeps the sentinel and is claim_store_unavailable", async () => {
  class Exhausted extends StoreTestOnly {
    override async finalizeV2Claim(): Promise<boolean> {
      throw ErrV2RateLimitExceeded;
    }
  }
  const keys = await corpusKeyPairs();
  const store = new Exhausted(START, lifecycle.lease_seconds, lifecycle.log_id, keys.get(lifecycle.verifier_key)!);
  const request = { ...lifecycle.requests.A, now: START };
  const wire = unb64(lifecycle.bundles_b64[request.bundle]);
  const { req } = await buildVerifyRequest(request, wire, zeroCounts());
  const bundle = decodeProofBundleV2(wire);
  const pre = await preflightProofBundleV2(bundle, req.expected, req.contextPolicy, req.requiredScope, req.verifierNamespace,
    req.replayEpoch, req.verifierID, START, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  const { claim, token } = await claimProofBundleV2(store, bundle, pre, req.verifierNamespace, req.replayEpoch, START);
  const assessment = await evaluateProofBundleV2LocalAuthorization(bundle, {
    futureSkewSeconds: req.futureSkewSeconds, requiredScope: req.requiredScope, context: req.context, tzdbVersion: req.tzdbVersion,
    contextPolicy: req.contextPolicy, claimToken: token, trustConfigured: false,
  });
  assert.equal(assessment.reason, "trust_unavailable");
  const { terminal, body } = payloadFor(claim, "authorization_unverified", (r) => Object.assign(r, {
    decision_reason: "trust_unavailable", trust_assessment: "unavailable",
  }));
  await assert.rejects(finalizeClaimProofBundleV2(store, token!, terminal, body), (e) => {
    assert.ok(errorIs(e, ErrV2RateLimitExceeded), "the sentinel stays matchable");
    assert.equal(v2ErrorClassOf(e), "claim_store_unavailable");
    return true;
  });
});

test("reference store: now() reads the clock without an authoritative reading", async () => {
  // Harnesses derive request times from now(). It must report the setting,
  // including a backward move, and must not raise the high-water mark the
  // way an authoritative reading does, or the regression it reports could
  // never be detected.
  const store = await newStore();
  assert.equal(store.now(), START);
  store.setTime(START + 10);
  assert.equal(await store.authoritativeTimeV2(), START + 10);
  store.setTime(START + 5);
  assert.equal(store.now(), START + 5);
  assert.equal(store.highWater, START + 10);
  await assert.rejects(() => store.authoritativeTimeV2(), (e: unknown) => v2ErrorClassOf(e) === "clock_regressed");
});

test("store: a claim ID not derived from its replay key is refused and creates nothing", async () => {
  // SPEC-v2 §7.3: the store is unique by (namespace, replay_epoch,
  // ChallengeClaimDigest), so no caller can open a second claim for one
  // challenge by choosing another ID.
  const store = await newStore();
  const claim = claimOf(30);
  await assert.rejects(store.claimV2({ ...claim, claimID: "f".repeat(64) }), (e: unknown) => v2ErrorClassOf(e) === "configuration_invalid");
  assert.equal((await store.claimV2(claim)).disposition, "created");
  const race = claimOf(31);
  const results = await Promise.allSettled(Array.from({ length: 128 }, (_, i) =>
    store.claimV2(i % 2 ? { ...race, claimID: i.toString(16).padStart(64, "0") } : race)));
  const created = results.filter((r) => r.status === "fulfilled" && r.value.disposition === "created").length;
  const refused = results.filter((r) => r.status === "rejected" && v2ErrorClassOf(r.reason) === "configuration_invalid").length;
  assert.deepEqual({ created, refused }, { created: 1, refused: 64 });
});
