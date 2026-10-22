// testvectors/v2/rotation-sequences.json: AcceptRotation journal sequences.

import { test } from "node:test";
import assert from "node:assert/strict";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import {
  acceptKeyRotationStatementV2,
  decodeKeyRotationStatementV2,
  newKeyRotationV2Journal,
  recoverKeyRotationV2,
  type KeyRotationV2Journal,
} from "../../src/key_rotation_v2.js";
import { corpusKeyPairs, eqBytes, load, unb64, type Any } from "./helpers.js";
import { pubByName } from "./object_procedures.js";

const file = load("rotation-sequences.json");

test("rotation-sequences.json: AcceptRotation journal", async (t) => {
  const keys = await corpusKeyPairs();
  assert.ok(file.scenarios.length > 0, "no rotation scenarios");
  for (const sc of file.scenarios as Any[]) {
    await t.test(sc.name, async () => {
      let journal: KeyRotationV2Journal = newKeyRotationV2Journal(sc.authority_id, sc.recovery_epoch, sc.role, pubByName(keys, sc.genesis_key));
      for (let i = 0; i < sc.steps.length; i++) {
        const step = sc.steps[i];
        let got = "";
        let err: unknown = null;
        if (step.op === "recover") {
          try {
            journal = recoverKeyRotationV2(journal, step.new_recovery_epoch, pubByName(keys, step.new_genesis_key));
            got = "recovered";
          } catch (e) {
            err = e;
            got = v2ErrorClassOf(e);
          }
        } else {
          assert.equal(step.op, "accept");
          const s = decodeKeyRotationStatementV2(unb64(step.wire_b64));
          const out = await acceptKeyRotationStatementV2(s, journal, step.now, sc.future_skew_seconds);
          journal = out.journal;
          err = out.error ?? null;
          got = out.error ? v2ErrorClassOf(out.error) : out.result!;
        }
        assert.equal(got, step.expect, `step ${i} ${step.label} (${(err as Error)?.message})`);
        assert.equal(journal.state.sequence, step.expect_sequence, `step ${i}: sequence`);
        const want = pubByName(keys, step.expect_current_key);
        assert.ok(eqBytes(journal.state.currentKey.ml_dsa_65, want.ml_dsa_65) && eqBytes(journal.state.currentKey.ed25519, want.ed25519), `step ${i}: current key`);
        assert.equal(journal.state.recoveryEpoch, step.expect_recovery_epoch, `step ${i}: recovery epoch`);
        assert.equal(journal.frozen, step.expect_frozen, `step ${i}: frozen`);
      }
    });
  }
});
