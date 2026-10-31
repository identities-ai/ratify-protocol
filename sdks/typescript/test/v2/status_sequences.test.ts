// testvectors/v2/status-sequences.json: the status reducer state-to-result
// table, including exclusive next_update and status-age deadlines (SPEC-v2
// §5.4), plus the status evidence batch codec and the provenance stage.

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { hexOf } from "../../src/json_v2.js";
import { MAX_STATUS_EVIDENCE_BATCH_BYTES_V2, MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 } from "../../src/limits_v2.js";
import { decodeRevocationListV2, decodeRevocationPushV2, encodeRevocationListV2 } from "../../src/protocol_v2_wire.js";
import { decodeV2StatusEvidenceBatch, encodeV2StatusEvidenceBatch } from "../../src/status_batch_v2.js";
import {
  applyRevocationListV2,
  applyRevocationPushV2,
  emptyRevocationStatusStateV2,
  revocationStatusForCertV2,
  transitionRevocationStatusEpochV2,
  type RevocationStatusStateV2,
} from "../../src/status_state_v2.js";
import { type Any, corpusKeyPairs, load, unb64 } from "./helpers.js";

const f = load("status-sequences.json");
const policyOf = (p: Any) => ({ maxListLifetimeSeconds: p.max_list_lifetime_seconds, maxStatusAgeSeconds: p.max_status_age_seconds, clockSkewSeconds: p.clock_skew_seconds });

test("status-sequences.json: corpus shape", () => {
  assert.equal(f.scenarios.length, 22);
  assert.equal((f.scenarios as Any[]).reduce((n, sc) => n + sc.steps.filter((st: Any) => st.expect_body_digest !== undefined).length, 0), 63);
});

for (const sc of f.scenarios as Any[]) {
  test(`status-sequences.json: ${sc.name}`, async () => {
    const keys = await corpusKeyPairs();
    let state: RevocationStatusStateV2 = emptyRevocationStatusStateV2();
    for (const [i, step] of (sc.steps as Any[]).entries()) {
      const key = keys.get(step.status_key)!.publicKey;
      const policy = policyOf(step.policy ?? sc.policy);
      let next = state;
      let err: unknown = null;
      const where = `step ${i} ${step.op} ${step.label ?? ""}`;
      try {
        switch (step.op) {
          case "apply_list":
            next = await applyRevocationListV2(state, decodeRevocationListV2(unb64(step.wire_b64)), sc.issuer_id, step.status_key_epoch, key, policy, step.now);
            break;
          case "apply_push":
            next = await applyRevocationPushV2(state, decodeRevocationPushV2(unb64(step.wire_b64)), sc.issuer_id, step.status_key_epoch, key, policy, step.now);
            break;
          case "transition_epoch":
            next = transitionRevocationStatusEpochV2(state, sc.issuer_id, step.status_key_epoch, key);
            break;
          case "query": {
            const r = await revocationStatusForCertV2(state, sc.issuer_id, step.cert_id, step.status_key_epoch, key, policy, step.now);
            const want = step.expect_result;
            assert.deepEqual([r.status, r.reason ?? ""], [want.status, want.reason ?? ""], `${where}: ${step.cert_id}`);
            assert.deepEqual(r.evidence, want.evidence, `${where}: evidence`);
            continue;
          }
          default:
            assert.fail(`unknown op ${step.op}`);
        }
      } catch (e) {
        err = e;
      }
      if (step.expect_error_class) {
        assert.equal(v2ErrorClassOf(err), step.expect_error_class, `${where}: ${err}`);
        continue;
      }
      assert.equal(err, null, `${where}: ${err}`);
      state = next;
      const w = step.expect_state;
      if (step.expect_body_digest) {
        // The unlabelled SHA-384 of the signable body (SPEC-v2 §6.6).
        const code = step.op === "apply_push" ? 5 : 3;
        assert.ok(state.observations.some((o) => o.statusKeyEpoch === step.status_key_epoch && o.objectType === code &&
          `sha384:${hexOf(o.bodyDigest)}` === step.expect_body_digest), `${where}: no observation with body_digest ${step.expect_body_digest}`);
      }
      if (w) {
        if (w.has_floor !== undefined) assert.equal(state.hasFloor, w.has_floor, `${where}: has_floor`);
        if (w.floor !== undefined) assert.equal(state.floor, w.floor, `${where}: floor`);
        if (w.max_observed_sequence !== undefined) assert.equal(state.maxObservedSequence, w.max_observed_sequence, `${where}: max_observed_sequence`);
        if (w.fork_sequence !== undefined) assert.equal(state.forkSequence, w.fork_sequence, `${where}: fork_sequence`);
        if (w.reconciliation_required !== undefined) assert.equal(state.reconciliationRequired, w.reconciliation_required, `${where}: reconciliation_required`);
        if (w.future_dated_object_observed !== undefined) assert.equal(state.futureDatedObjectObserved, w.future_dated_object_observed, `${where}: future_dated_object_observed`);
        if (w.accepted_set !== undefined) assert.deepEqual(state.acceptedCertIDs, w.accepted_set, `${where}: accepted_set`);
        if (w.deny_union !== undefined) assert.deepEqual(state.denyUnionCertIDs, w.deny_union, `${where}: deny_union`);
      }
    }
  });
}

test("status evidence batch: canonical encoding round-trips corpus status objects", () => {
  const objects = load("objects.json").objects as Any[];
  const list = objects.find((o) => o.kind === "revocation_list")!;
  const push = objects.find((o) => o.kind === "revocation_push")!;
  const batch = { objects: [{ objectType: 3, wire: unb64(list.wire_b64) }, { objectType: 5, wire: unb64(push.wire_b64) }] };
  const encoded = encodeV2StatusEvidenceBatch(batch);
  const text = new TextDecoder().decode(encoded);
  assert.ok(text.startsWith('[{"object":{') && text.includes(',"object_type_code":3},{"object":'));
  const decoded = decodeV2StatusEvidenceBatch(encoded);
  assert.deepEqual(decoded.objects.map((o) => o.objectType), [3, 5]);
  assert.deepEqual(encodeV2StatusEvidenceBatch(decoded), encoded);
  assert.deepEqual(decodeV2StatusEvidenceBatch(new TextEncoder().encode("[]")).objects, []);
  const listWire = encodeRevocationListV2(decodeRevocationListV2(unb64(list.wire_b64)));
  const entry = `{"object":${new TextDecoder().decode(listWire)},"object_type_code":3}`;
  const tooMany = new TextEncoder().encode("[" + Array(MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2 + 1).fill(entry).join(",") + "]");
  assert.equal(classOfSync(() => decodeV2StatusEvidenceBatch(tooMany)), "malformed");
  for (const bad of ['{}', '[{"object":{}}]', '[{"object":{},"object_type_code":4}]', '[{"object":[],"object_type_code":3}]',
    '[{"object":{},"object_type_code":"3"}]', '[{"object":{},"object_type_code":3,"x":1}]', '[null]', '[1]']) {
    assert.equal(classOfSync(() => decodeV2StatusEvidenceBatch(new TextEncoder().encode(bad))), "malformed", bad);
  }
  const big = new Uint8Array(MAX_STATUS_EVIDENCE_BATCH_BYTES_V2 + 1).fill(0x20);
  assert.equal(classOfSync(() => decodeV2StatusEvidenceBatch(big)), "malformed");
});

function classOfSync(fn: () => unknown): string {
  try {
    fn();
    return "";
  } catch (err) {
    return v2ErrorClassOf(err);
  }
}

test("status evidence batch: decoder never crashes and fails only as malformed (property)", () => {
  const sample = '[{"object":{"issuer_id":"x"},"object_type_code":3}]';
  fc.assert(fc.property(
    fc.oneof(
      fc.uint8Array({ maxLength: 256 }),
      fc.json().map((s) => new TextEncoder().encode(s)),
      fc.tuple(fc.nat(sample.length), fc.string({ maxLength: 6 })).map(([i, s]) => new TextEncoder().encode(sample.slice(0, i) + s + sample.slice(i))),
    ),
    (data) => {
      try {
        const batch = decodeV2StatusEvidenceBatch(data);
        assert.ok(batch.objects.length <= MAX_STATUS_EVIDENCE_BATCH_OBJECTS_V2);
        for (const o of batch.objects) assert.ok(o.objectType === 3 || o.objectType === 5);
      } catch (err) {
        assert.equal(v2ErrorClassOf(err), "malformed");
      }
    },
  ), { numRuns: 500 });
});
