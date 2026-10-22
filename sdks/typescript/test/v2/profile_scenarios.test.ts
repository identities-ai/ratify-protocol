// lifecycle-scenarios.json profile_scenarios: the single-device offline
// profile (SPEC-v2 §7.13) and the dual-root composition profile (§7.14)
// against the test-only reference models (Go TestV2ConformanceProfileScenarios).

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSessionContextV2 } from "../../src/operation_context_v2.js";
import { releaseV2Decision, type CommittedV2Outcome, type V2ReleaseConfig, type V2ReleasedDecision } from "../../src/release_v2.js";
import { decodeVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { ApprovalLedgerTestOnly, ErrApprovalAlreadyExecutedTestOnly, ledgerErrorClassTestOnly } from "../../src/v2reference/approval_ledger.js";
import {
  DeviceCheckpointTestOnly,
  DeviceComponentTestOnly,
  DevicePrimaryTestOnly,
  DeviceUplinkTestOnly,
  deviceErrorClassTestOnly,
} from "../../src/v2reference/device.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import type { V2AuthoritativeClock } from "../../src/claim_store_v2.js";
import { type Any, corpusKeyPairs, load, toHex, unb64 } from "./helpers.js";
import { checkCommitted, checkReleasedDecisionAllowed } from "./release_checks.js";
import { buildVerifyRequest, populateStatusJournal, zeroCounts } from "./verify_harness.js";

const file = load("lifecycle-scenarios.json");

const catchErr = async (fn: () => Promise<unknown>): Promise<unknown> => {
  try {
    await fn();
    return null;
  } catch (err) {
    return err;
  }
};

test("profile_scenarios: corpus shape", () => {
  const profiles: Record<string, number> = {};
  for (const sc of file.profile_scenarios) profiles[sc.profile] = (profiles[sc.profile] ?? 0) + 1;
  assert.ok(profiles.single_device_offline! >= 16 && profiles.dual_root! >= 13 && Object.keys(profiles).length === 2, JSON.stringify(profiles));
  assert.equal(file.profile_scenarios.length, 29);
  assert.equal(file.profile_scenarios.reduce((n: number, s: Any) => n + s.steps.length, 0), 279);
});

for (const sc of file.profile_scenarios as Any[]) {
  test(`profile: ${sc.name}`, async () => {
    const keys = await corpusKeyPairs();
    const verifier = keys.get(file.verifier_key)!;
    let store = new StoreTestOnly(sc.start_time, file.lease_seconds, file.log_id, verifier);
    // The device's one security clock: whichever primary store is current.
    const deviceClock: V2AuthoritativeClock = { authoritativeTimeV2: () => store.authoritativeTimeV2() };
    let primary: DevicePrimaryTestOnly | null = null;
    let device: DeviceCheckpointTestOnly | null = null;
    let component: DeviceComponentTestOnly | null = null;
    let uplink: DeviceUplinkTestOnly | null = null;
    if (sc.profile === "single_device_offline") {
      store.setAcknowledgementWithheld(true);
      component = await DeviceComponentTestOnly.create(unb64(sc.device.component_seed_b64), sc.device.capacity, deviceClock);
      primary = new DevicePrimaryTestOnly(store, sc.device.replay_epoch);
      device = new DeviceCheckpointTestOnly(primary, component, component.publicKey);
      device.provision();
      uplink = new DeviceUplinkTestOnly(device);
    }
    const ledger = new ApprovalLedgerTestOnly();
    let setID = "";
    const committed = new Map<string, CommittedV2Outcome>();
    const receipts = new Map<string, Uint8Array>();
    const decisions = new Map<string, V2ReleasedDecision | null>();
    const snapshots = new Map<string, DevicePrimaryTestOnly>();
    for (let i = 0; i < sc.steps.length; i++) {
      const step = sc.steps[i];
      const want = step.expect ?? {};
      const request = file.requests[step.request];
      switch (step.op) {
        case "set_time":
          store.setTime(step.time);
          break;
        case "set_ack_withheld":
          store.setAcknowledgementWithheld(step.withheld);
          break;
        case "verify": {
          const { req, cb } = await buildVerifyRequest({ ...request, now: store.now }, unb64(file.bundles_b64[request.bundle]), zeroCounts());
          const callbacks = { ...cb, claimStore: store as never };
          if (sc.rate_at_finalization) {
            const rateStore = store.withRateAtFinalization();
            callbacks.claimStore = rateStore as never;
            callbacks.rate = rateStore;
          }
          const outcome = await verifyProofBundleV2(req, callbacks);
          assert.equal(outcome.stage, want.stage, `step ${i} verify ${step.request} stage (${outcome.errorClass}: ${outcome.error?.message})`);
          assert.equal(outcome.errorClass, want.error_class ?? "", `step ${i} verify class (${outcome.error?.message})`);
          if (outcome.stage === "committed") {
            checkCommitted(i, outcome.committed!, want);
            committed.set(step.request, outcome.committed!);
          }
          break;
        }
        case "publish": {
          const c = committed.get(step.request)!;
          const wire = await store.publishV2Receipt(c.claimID(), c.receiptBody());
          assert.equal(decodeVerificationReceiptV2(wire).sequence, want.receipt_sequence, `step ${i} publish sequence`);
          receipts.set(step.request, wire);
          break;
        }
        case "release": {
          const config: V2ReleaseConfig = { verifierPublicKey: verifier.publicKey, logID: file.log_id, claimStore: store, checkpoint: store };
          if (step.checkpoint === "device") config.checkpoint = device!;
          const result = await releaseV2Decision(committed.get(step.request)!, receipts.get(step.request) ?? null, config);
          assert.deepEqual([result.status, result.reason], [want.release_status, want.release_reason ?? ""], `step ${i} release ${step.request}`);
          decisions.set(step.request, result.decision);
          if (result.decision) {
            const d = result.decision;
            assert.equal(d.decision(), want.decision, `step ${i} released decision`);
            assert.equal(d.releaseTime(), want.release_time, `step ${i} release time`);
            assert.equal(d.receipt().sequence, want.receipt_sequence, `step ${i} released receipt`);
            await checkReleasedDecisionAllowed(i, d);
          }
          break;
        }
        case "device_power_loss":
          component!.setPowerLoss(step.mode === "before_commit" ? "before_commit" : "after_commit");
          break;
        case "device_submit": {
          const { acknowledged, error } = await device!.submitPending();
          assert.equal(deviceErrorClassTestOnly(error), want.device_error ?? "", `step ${i} device_submit error`);
          assert.deepEqual(acknowledged, want.acknowledged ?? [], `step ${i} device_submit acknowledged`);
          break;
        }
        case "device_resubmit": {
          let ack = null;
          let err: unknown = null;
          try {
            ack = await device!.resubmit(step.sequence);
          } catch (e) {
            err = e;
          }
          assert.equal(deviceErrorClassTestOnly(err), want.device_error ?? "", `step ${i} device_resubmit`);
          if (err === null) assert.equal(ack!.timestamp, want.ack_time, `step ${i} device_resubmit time`);
          break;
        }
        case "device_startup":
          assert.equal(device!.startup(), want.device_status, `step ${i} device_startup`);
          break;
        case "snapshot":
          snapshots.set(step.snapshot, primary!.clone());
          break;
        case "restore": {
          const now = store.now;
          primary = snapshots.get(step.snapshot)!.clone();
          store = primary.store;
          store.setTime(now);
          device = new DeviceCheckpointTestOnly(primary, component!, component!.publicKey);
          uplink = new DeviceUplinkTestOnly(device);
          break;
        }
        case "stage_status":
          await populateStatusJournal(primary!.journal, request);
          break;
        case "plant_release":
          store.plantReleaseTestOnly(committed.get(step.request)!.claimID(), step.time);
          break;
        case "corrupt_state":
          store.corruptSealedStateTestOnly(committed.get(step.request)!.claimID());
          break;
        case "upload":
          assert.deepEqual(uplink!.upload(), want.uploaded ?? [], `step ${i} upload`);
          break;
        case "ledger_open": {
          const s = step.approval_set;
          const derived = buildSessionContextV2({
            verifier_id: s.verifier_id, workspace_id: s.workspace_id, agent_id: toHex(Buffer.from(keyIDOf(keys, s.agent_key), "hex")),
            session_id: s.session_id, invocation_id: s.id, request_hash: unb64(s.request_hash_b64),
          });
          assert.equal(toHex(derived), toHex(unb64(s.session_context_b64)), `step ${i} known-answer session context`);
          const err = await catchErr(() => ledger.open({
            approvalSetID: s.id, verifierID: s.verifier_id, workspaceID: s.workspace_id, sessionID: s.session_id,
            agentPublicKey: keys.get(s.agent_key)!.publicKey, requiredScope: s.required_scope, requestHash: unb64(s.request_hash_b64),
            roots: [keys.get(s.root_keys[0])!.publicKey, keys.get(s.root_keys[1])!.publicKey],
          }));
          assert.equal(ledgerErrorClassTestOnly(err), want.ledger_error ?? "", `step ${i} ledger_open`);
          if (err === null) setID = s.id;
          break;
        }
        case "ledger_record": {
          const target = step.set || setID;
          let complete = false;
          const err = await catchErr(async () => {
            complete = await ledger.recordApproval(target, step.slot, decisions.get(step.request) ?? null, unb64(file.bundles_b64[request.bundle]));
          });
          assert.equal(ledgerErrorClassTestOnly(err), want.ledger_error ?? "", `step ${i} ledger_record ${step.request}`);
          assert.equal(complete, want.ledger_complete ?? false, `step ${i} ledger_record complete`);
          break;
        }
        case "ledger_record_concurrent": {
          await Promise.all(step.requests.map((name: string, slot: number) =>
            ledger.recordApproval(setID, slot, decisions.get(name) ?? null, unb64(file.bundles_b64[file.requests[name].bundle]))));
          const first = step.requests[0];
          const complete = await ledger.recordApproval(setID, 0, decisions.get(first) ?? null, unb64(file.bundles_b64[file.requests[first].bundle]));
          assert.equal(complete, want.ledger_complete ?? false, `step ${i} ledger_record_concurrent`);
          break;
        }
        case "ledger_execute": {
          const err = await catchErr(() => ledger.execute(step.set || setID, store));
          assert.equal(ledgerErrorClassTestOnly(err), want.ledger_error ?? "", `step ${i} ledger_execute`);
          break;
        }
        case "ledger_execute_concurrent": {
          const results = await Promise.allSettled(Array.from({ length: step.count }, () => ledger.execute(setID, store)));
          for (const r of results) if (r.status === "rejected") assert.equal(r.reason, ErrApprovalAlreadyExecutedTestOnly);
          assert.equal(results.filter((r) => r.status === "fulfilled").length, want.executed, `step ${i} executed count`);
          break;
        }
        default:
          throw new Error(`unknown profile op ${step.op}`);
      }
    }
  });
}

function keyIDOf(keys: Map<string, Any>, name: string): string {
  const all = load("keys.json").keys as Any[];
  const k = all.find((x) => x.name === name);
  assert.ok(k && keys.has(name), `unknown key ${name}`);
  return k.key_id_v2;
}
