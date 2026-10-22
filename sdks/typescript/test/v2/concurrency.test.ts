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
import { recoverInterruptedClaimV2, initialV2EvaluationProgress } from "../../src/evaluation_progress_v2.js";
import { releaseV2Decision } from "../../src/release_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { corpusKeyPairs, load, unb64 } from "./helpers.js";
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
  return {
    claimID: hex, namespace: "verify-test", replayEpoch: 3, challengeDigest: "sha384:" + hex.padEnd(96, "0"), proofDigest: "sha384:" + "1".repeat(96),
    bundleHash: "sha384:" + "1".repeat(96), issuerIDs: [ISSUER_A], requiredScope: "data:read", contextPolicyDigest: "", verifierID: "c".repeat(64),
    agentID: "d".repeat(64), requiresRate: false, rateBatch: [], issuedAt: START - 10, expiresAt: START + 290, maxAgeSeconds: 300,
    clockSkewSeconds: 5, streamID: null, streamSeq: null, constraintEvaluators: [], ...extra,
  };
}

const TERMINAL_DENY = canonicalJSONV2({ decision: "deny", decision_reason: "unauthorized", identity_status: "unauthorized" });
const BODY_DENY = canonicalJSONV2({ decision: "deny", decision_reason: "unauthorized" });
const TERMINAL_INT = canonicalJSONV2({ decision: "indeterminate", decision_reason: "evaluation_interrupted", identity_status: "authorization_unverified" });
const BODY_INT = canonicalJSONV2({ decision: "indeterminate", decision_reason: "evaluation_interrupted" });

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
  const results = await Promise.all(Array.from({ length: 5 }, () => store.finalizeV2Claim(claimOf(2).claimID, ownerToken!, TERMINAL_DENY, BODY_DENY, 0)));
  assert.deepEqual(results.sort(), [false, false, false, false, true]);
  assert.equal(store.outbox.length, 1);
});

test("concurrency: finalization racing lease-expiry recovery yields one terminal result", async () => {
  const store = await newStore(30);
  const claim = claimOf(3);
  const { ownerToken } = await store.claimV2(claim);
  await store.recordV2EvaluationProgress(claim.claimID, ownerToken!, initialV2EvaluationProgress());
  store.setTime(START + 30);
  const [finalized, recovered] = await Promise.allSettled([
    store.finalizeV2Claim(claim.claimID, ownerToken!, TERMINAL_DENY, BODY_DENY, 0),
    store.recoverInterruptedV2Claim(claim.claimID, TERMINAL_INT, BODY_INT),
  ]);
  assert.equal(finalized.status, "rejected");
  assert.equal(v2ErrorClassOf((finalized as PromiseRejectedResult).reason), "claim_lease_lost");
  assert.equal(recovered.status, "fulfilled");
  assert.equal(store.outbox.length, 1);
  // A late evaluator cannot replace the recovered result.
  await assert.rejects(store.finalizeV2Claim(claim.claimID, ownerToken!, TERMINAL_DENY, BODY_DENY, 0), (e) => v2ErrorClassOf(e) === "claim_already_terminal");
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
    const claim = claimOf(n, { requiresRate: true, rateBatch: batch(issuerID) });
    const { ownerToken } = await atFinal.claimV2(claim);
    const terminal = canonicalJSONV2({ decision: "allow", decision_reason: "authorized", identity_status: "authorized_agent" });
    const body = canonicalJSONV2({ decision: "allow", decision_reason: "authorized", n });
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
    req.replayEpoch, START, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  const { token } = await claimProofBundleV2(store, bundle, pre, req.verifierNamespace, req.replayEpoch, START);
  const assessment = await evaluateProofBundleV2LocalAuthorization(bundle, {
    futureSkewSeconds: req.futureSkewSeconds, requiredScope: req.requiredScope, context: req.context, tzdbVersion: req.tzdbVersion,
    contextPolicy: req.contextPolicy, claimToken: token, trustConfigured: false,
  });
  assert.equal(assessment.reason, "trust_unavailable");
  const terminal = canonicalJSONV2({ decision: "indeterminate", decision_reason: "trust_unavailable", identity_status: "authorization_unverified" });
  const body = canonicalJSONV2({ decision: "indeterminate", decision_reason: "trust_unavailable" });
  await assert.rejects(finalizeClaimProofBundleV2(store, token!, terminal, body), (e) => {
    assert.ok(errorIs(e, ErrV2RateLimitExceeded), "the sentinel stays matchable");
    assert.equal(v2ErrorClassOf(e), "claim_store_unavailable");
    return true;
  });
});
