// testvectors/v2/lifecycle-scenarios.json: Part B scripts replayed against
// the test-only reference store (Go TestV2ConformanceLifecycleScenarios),
// plus cancellation after claim. The profile_scenarios member is run by
// profile_scenarios.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";

import { protocolClaimIDV2 } from "../../src/challenge_claim_v2.js";
import { claimProofBundleV2, type ClaimStoreV2 } from "../../src/claim_store_v2.js";
import { errorIs, v2ErrorClassOf } from "../../src/errors_v2.js";
import { recoverInterruptedClaimV2 } from "../../src/evaluation_progress_v2.js";
import { decodeProofBundleV2 } from "../../src/protocol_v2_wire.js";
import { CommittedV2Outcome, releaseV2Decision, type V2ReceiptCheckpoint, type V2ReleaseConfig, type V2ReleasedDecision } from "../../src/release_v2.js";
import {
  decodeVerificationReceiptBodyV2,
  decodeVerificationReceiptV2,
  encodeVerificationReceiptV2,
  verificationReceiptV2Digest,
} from "../../src/verification_receipt_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { preflightProofBundleV2 } from "../../src/verify_v2_preflight.js";
import {
  ErrHeadOfLineBlockedTestOnly,
  ErrLogFrozenTestOnly,
  ErrSignerUnavailableTestOnly,
  StoreTestOnly,
} from "../../src/v2reference/store.js";
import type { V2AuthoritativeClock, V2ChallengeClaim, V2ClaimResult } from "../../src/claim_store_v2.js";
import { type Any, corpusKeyPairs, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";
import { checkCommitted, checkReleasedDecisionAllowed } from "./release_checks.js";

const file = load("lifecycle-scenarios.json");

/** Reports acknowledgements for a different entry hash (Go v2WrongEntryCheckpoint). */
class WrongEntryCheckpoint implements V2ReceiptCheckpoint {
  constructor(readonly inner: V2ReceiptCheckpoint) {}
  acknowledgeV2Receipt(logID: string, sequence: number, previous: Uint8Array, entry: Uint8Array) {
    return this.inner.acknowledgeV2Receipt(logID, sequence, previous, entry);
  }
  async getV2Acknowledgement(logID: string, sequence: number) {
    const ack = await this.inner.getV2Acknowledgement(logID, sequence);
    const entryHash = Uint8Array.from(ack.entryHash);
    entryHash[0]! ^= 1;
    return { ...ack, entryHash };
  }
}

/**
 * Records the evaluator owner token a claim store returns to the creator, so
 * a finalize step can call the store directly (Go v2OwnerCapturingClaimStore).
 */
function ownerCapturing(inner: ClaimStoreV2): { store: ClaimStoreV2; owner: () => Uint8Array | null } {
  let owner: Uint8Array | null = null;
  const store = new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === "claimV2") {
        return async (claim: V2ChallengeClaim, signal?: AbortSignal): Promise<V2ClaimResult> => {
          const result = await target.claimV2(claim, signal);
          owner = result.ownerToken === null ? null : Uint8Array.from(result.ownerToken);
          return result;
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { store, owner: () => owner };
}

test("lifecycle-scenarios.json: corpus shape", () => {
  assert.equal(file.version, 2);
  assert.equal(file.scenarios.length, 48);
  assert.equal(file.scenarios.reduce((n: number, s: Any) => n + s.steps.length, 0), 271);
});

for (const sc of file.scenarios as Any[]) {
  test(`lifecycle: ${sc.name}`, async () => {
    const keys = await corpusKeyPairs();
    const verifier = keys.get(file.verifier_key)!;
    let store = new StoreTestOnly(sc.start_time, file.lease_seconds, file.log_id, verifier);
    const committed = new Map<string, CommittedV2Outcome>();
    const receipts = new Map<string, Uint8Array>();
    const claimIDs = new Map<string, string>();
    const owners = new Map<string, Uint8Array | null>();
    const requestOf = new Map<string, string>();
    let epochOverride = 0;
    const config: V2ReleaseConfig = { verifierPublicKey: verifier.publicKey, logID: file.log_id, claimStore: store, checkpoint: store };
    const claimStore = (): ClaimStoreV2 => (sc.rate_at_finalization ? store.withRateAtFinalization() : store);
    const recoverStep = async (i: number, request: string, want: Any) => {
      try {
        let claimID = claimIDs.get(request);
        if (claimID === undefined) {
          // Never claimed: the request's own claim ID (claim_not_found).
          const e = file.requests[request].expected_challenge;
          claimID = protocolClaimIDV2(e.verifier_namespace, e.replay_epoch, unb64(e.value_b64));
        }
        const outcome = await recoverInterruptedClaimV2(store, claimID);
        assert.equal(want.error_class ?? "", "", `step ${i} recover succeeded, want ${want.error_class}`);
        checkCommitted(i, outcome, want);
        committed.set(request, outcome);
      } catch (err) {
        if (!want.error_class) throw err;
        assert.equal(v2ErrorClassOf(err), want.error_class, `step ${i} recover class (${(err as Error).message})`);
      }
    };
    // runVerify runs one verify step; with mode "" it is safe for concurrent
    // use (verify_concurrent).
    const runVerify = async (i: number, name: string, mode: string, at: number, want: Any) => {
      const request = file.requests[name];
      const inputs = { ...request, now: store.now(), configured_replay_epoch: epochOverride !== 0 ? epochOverride : request.configured_replay_epoch };
      const { req, cb } = await buildVerifyRequest(inputs, unb64(file.bundles_b64[request.bundle]), zeroCounts());
      const cs = claimStore();
      const callbacks = { ...cb, claimStore: cs };
      if (sc.rate_at_finalization) callbacks.rate = cs as never;
      const claimID = protocolClaimIDV2(req.verifierNamespace, req.replayEpoch, req.expected!.value);
      claimIDs.set(name, claimID);
      requestOf.set(claimID, name);
      const controller = new AbortController();
      if (mode === "cancel_before_claim") controller.abort();
      else if (mode) {
        const provider = callbacks.statusEvidence!;
        let fired = false;
        callbacks.statusEvidence = async (r, signal) => {
          if (!fired) {
            fired = true;
            switch (mode) {
              case "cancel_during_status":
                controller.abort();
                throw signal?.reason ?? new Error("cancelled");
              case "recover_during_status":
                store.setTime(at);
                await recoverStep(i, name, want.recovered);
                break;
              case "expire_lease_during_status":
              case "regress_clock_during_status":
                store.setTime(at);
                break;
              default:
                throw new Error(`unknown verify mode ${mode}`);
            }
          }
          return provider(r, signal);
        };
      }
      return verifyProofBundleV2(req, callbacks, { signal: controller.signal });
    };
    for (let i = 0; i < sc.steps.length; i++) {
      const step = sc.steps[i];
      const want = step.expect ?? {};
      const now = store.now();
      const request = file.requests[step.request];
      switch (step.op) {
        case "set_time":
          store.setTime(step.time);
          break;
        case "set_ack_withheld":
          store.setAcknowledgementWithheld(step.withheld);
          break;
        case "verify": {
          const outcome = await runVerify(i, step.request, step.mode ?? "", step.time ?? 0, want);
          assert.equal(outcome.stage, want.stage, `step ${i} verify ${step.request} stage (${outcome.errorClass}: ${outcome.error?.message})`);
          assert.equal(outcome.errorClass, want.error_class ?? "", `step ${i} verify class (${outcome.error?.message})`);
          if (want.disposition) assert.equal(outcome.disposition, want.disposition, `step ${i} disposition`);
          if (outcome.stage === "committed") {
            checkCommitted(i, outcome.committed!, want);
            committed.set(step.request, outcome.committed!);
          }
          break;
        }
        case "verify_concurrent": {
          const results = await Promise.all((step.requests as string[]).map((name) => runVerify(i, name, "", 0, want)));
          const got = results.map((outcome, k) => {
            if (outcome.stage === "committed") committed.set(step.requests[k], outcome.committed!);
            return outcome.stage === "preflight" || outcome.stage === "evaluating" ? `${outcome.stage}/${outcome.errorClass}` : outcome.stage;
          });
          assert.deepEqual(got.sort(), want.outcomes, `step ${i} verify_concurrent ${step.requests}`);
          break;
        }
        case "claim_only": {
          const bundle = decodeProofBundleV2(unb64(file.bundles_b64[request.bundle]));
          const { req } = await buildVerifyRequest(request, new Uint8Array(0), zeroCounts());
          const pre = await preflightProofBundleV2(bundle, req.expected, req.contextPolicy, req.requiredScope, req.verifierNamespace, req.replayEpoch, now, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
          let disposition = "";
          let cls = "";
          try {
            const capturing = ownerCapturing(claimStore());
            const out = await claimProofBundleV2(capturing.store, bundle, pre, req.verifierNamespace, req.replayEpoch, now);
            disposition = out.disposition;
            owners.set(step.request, capturing.owner());
            claimIDs.set(step.request, out.claim.claimID);
            requestOf.set(out.claim.claimID, step.request);
          } catch (err) {
            cls = v2ErrorClassOf(err);
          }
          assert.equal(cls, want.error_class ?? "", `step ${i} claim_only class`);
          assert.equal(disposition, want.disposition ?? "", `step ${i} claim_only disposition`);
          break;
        }
        case "acknowledge": {
          const receipt = decodeVerificationReceiptV2(receipts.get(step.request)!);
          const entry = verificationReceiptV2Digest(receipt);
          if (step.mode === "fork") entry[0]! ^= 1;
          else if (step.mode !== "exact") throw new Error(`unknown acknowledge mode ${step.mode}`);
          let ack = null;
          let err: unknown = null;
          try {
            ack = await store.acknowledgeV2Receipt(receipt.log_id, receipt.sequence, receipt.previous_receipt_hash, entry);
          } catch (e) {
            err = e;
          }
          if (want.failed) {
            assert.ok(err !== null, `step ${i} acknowledge ${step.mode}: acknowledged at ${ack?.timestamp}, want refusal`);
            break;
          }
          if (err) throw err;
          assert.equal(ack!.timestamp, want.ack_timestamp, `step ${i} acknowledge timestamp`);
          assert.equal(ack!.sequence, receipt.sequence, `step ${i} acknowledge sequence`);
          assert.deepEqual(ack!.entryHash, entry, `step ${i} acknowledge entry hash`);
          break;
        }
        case "finalize": {
          let finalized = false;
          let err: unknown = null;
          try {
            finalized = await claimStore().finalizeV2Claim(claimIDs.get(step.request)!, owners.get(step.request) ?? new Uint8Array(0),
              unb64(step.terminal_b64), unb64(step.body_b64), step.allow_valid_until ?? 0);
          } catch (e) {
            err = e;
          }
          if (want.error_class) {
            assert.equal(finalized, false, `step ${i} finalize committed, want ${want.error_class}`);
            assert.equal(v2ErrorClassOf(err), want.error_class, `step ${i} finalize class (${(err as Error)?.message})`);
            break;
          }
          if (err) throw err;
          assert.equal(finalized ? "committed" : "identical", want.finalize_result, `step ${i} finalize result`);
          break;
        }
        case "recover":
          await recoverStep(i, step.request, want);
          break;
        case "publish": {
          const c = committed.get(step.request)!;
          if (step.mode === "signer_failure") store.setSignerFailure(true);
          let wire: Uint8Array | null = null;
          let err: unknown = null;
          try {
            wire = await store.publishV2Receipt(c.claimID(), c.receiptBody());
          } catch (e) {
            err = e;
          }
          store.setSignerFailure(false);
          if (want.failed) {
            const reasons: Record<string, Error> = { head_of_line_blocked: ErrHeadOfLineBlockedTestOnly, signer_unavailable: ErrSignerUnavailableTestOnly, log_frozen: ErrLogFrozenTestOnly };
            assert.ok(wire === null && errorIs(err, reasons[want.publish_error]!), `step ${i} publish: ${err}, want ${want.publish_error}`);
            break;
          }
          if (err) throw err;
          const receipt = decodeVerificationReceiptV2(wire!);
          assert.equal(receipt.sequence, want.receipt_sequence, `step ${i} receipt sequence`);
          if (step.mode === "corrupt_signature") {
            receipt.signature.ed25519[0]! ^= 1;
            wire = encodeVerificationReceiptV2(receipt);
          }
          receipts.set(step.request, wire!);
          break;
        }
        case "abandon": {
          const got = (await store.abandonPendingReceipts()).map((id) => requestOf.get(id));
          assert.deepEqual(got, want.abandoned, `step ${i} abandon`);
          break;
        }
        case "restore":
          if (step.mode === "exact") store = store.clone();
          else if (step.mode === "lost_state_epoch_bump") {
            store = new StoreTestOnly(now, file.lease_seconds, step.log_id, verifier);
            epochOverride = step.replay_epoch;
            config.logID = step.log_id;
          } else throw new Error(`unknown restore mode ${step.mode}`);
          config.claimStore = store;
          config.checkpoint = store;
          break;
        case "plant_release":
          store.plantReleaseTestOnly(committed.get(step.request)!.claimID(), step.time);
          break;
        case "release":
        case "release_forged": {
          let c = committed.get(step.request) as CommittedV2Outcome;
          let receipt: Uint8Array | null = receipts.get(step.receipt_of || step.request) ?? null;
          const cfg: V2ReleaseConfig = { ...config };
          if (step.checkpoint === "wrong_entry") cfg.checkpoint = new WrongEntryCheckpoint(store);
          if (step.mode === "no_receipt") receipt = null;
          if (step.op === "release_forged") {
            c = Object.create(CommittedV2Outcome.prototype) as CommittedV2Outcome;
            receipt = null;
          }
          const result = await releaseV2Decision(c, receipt, cfg);
          assert.deepEqual([result.status, result.reason], [want.release_status, want.release_reason ?? ""], `step ${i} release`);
          assert.equal(result.decision !== null, result.status === "released");
          if (result.decision) {
            const d = result.decision;
            assert.equal(d.decision(), want.decision, `step ${i} released decision`);
            assert.equal(d.releaseTime(), want.release_time, `step ${i} release time`);
            assert.equal(d.receipt().sequence, want.receipt_sequence, `step ${i} released receipt`);
            await checkReleasedDecisionAllowed(i, d);
          }
          break;
        }
        default:
          throw new Error(`unknown op ${step.op}`);
      }
    }
  });
}

test("lifecycle: cancellation after claim leaves the claim recoverable", async () => {
  const keys = await corpusKeyPairs();
  const start = 1800000000;
  const store = new StoreTestOnly(start, file.lease_seconds, file.log_id, keys.get("verifier")!);
  const request = { ...file.requests.A, now: start };
  const bundle = unb64(file.bundles_b64[request.bundle]);
  const controller = new AbortController();
  const { req, cb } = await buildVerifyRequest(request, bundle, zeroCounts());
  const provider = cb.statusEvidence!;
  const outcome = await verifyProofBundleV2(req, {
    ...cb, claimStore: store,
    statusEvidence: async (r, signal) => {
      controller.abort();
      await provider(r, signal);
      throw new Error("cancelled");
    },
  }, { signal: controller.signal });
  assert.equal(outcome.stage, "evaluating");
  assert.equal(outcome.errorClass, "evaluation_cancelled");
  assert.equal(outcome.committed, null);
  const retry = await buildVerifyRequest(request, bundle, zeroCounts());
  const again = await verifyProofBundleV2(retry.req, { ...retry.cb, claimStore: store });
  assert.equal(again.stage, "replay");
  assert.equal(again.disposition, "in_progress");
  await assert.rejects(recoverInterruptedClaimV2(store, outcome.claim!.claimID), (err) => v2ErrorClassOf(err) === "claim_lease_live");
  store.setTime(start + file.lease_seconds);
  const recovered = await recoverInterruptedClaimV2(store, outcome.claim!.claimID);
  assert.equal(decodeVerificationReceiptBodyV2(recovered.receiptBody()).decision_reason, "evaluation_interrupted");
});
