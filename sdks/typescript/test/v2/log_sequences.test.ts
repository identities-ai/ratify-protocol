// testvectors/v2/log-sequences.json: witness and verification-receipt log
// sequences under caller-authenticated head state (head_rules).

import { test } from "node:test";
import assert from "node:assert/strict";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeVerificationReceiptV2, verificationReceiptV2Digest, verifyVerificationReceiptV2 } from "../../src/verification_receipt_v2.js";
import { decodeWitnessEntryV2, verifyWitnessEntryV2, witnessEntryV2Digest, type WitnessV2Head } from "../../src/witness_v2.js";
import { corpusKeyPairs, load, unb64, type Any } from "./helpers.js";
import { pubByName } from "./object_procedures.js";

const file = load("log-sequences.json");

test("log-sequences.json: witness and receipt logs", async (t) => {
  const keys = await corpusKeyPairs();
  assert.deepEqual(file.scenarios.map((s: Any) => s.kind).sort(), ["verification_receipt", "witness_entry"]);
  for (const sc of file.scenarios as Any[]) {
    await t.test(sc.name, async () => {
      const genesis = (logID: string): WitnessV2Head => ({ logID, sequence: 0, headHash: new Uint8Array(48), acceptedDigests: new Map(), frozen: false });
      let head = genesis(sc.initial_log_id);
      for (let i = 0; i < sc.steps.length; i++) {
        const step = sc.steps[i];
        if (step.op === "recover") {
          head = genesis(step.log_id);
          continue;
        }
        assert.equal(step.op, "verify");
        const wire = unb64(step.wire_b64);
        let got = "";
        let digest: Uint8Array | null = null;
        let seq = 0;
        try {
          if (sc.kind === "witness_entry") {
            const entry = decodeWitnessEntryV2(wire);
            digest = witnessEntryV2Digest(entry);
            seq = entry.sequence;
            got = await verifyWitnessEntryV2(entry, head, pubByName(keys, step.key));
          } else {
            const r = decodeVerificationReceiptV2(wire);
            digest = verificationReceiptV2Digest(r);
            seq = r.sequence;
            got = await verifyVerificationReceiptV2(r, pubByName(keys, step.key), { ...head, verifierID: sc.verifier_id });
          }
        } catch (err) {
          got = v2ErrorClassOf(err);
        }
        assert.equal(got, step.expect, `step ${i} ${step.label}`);
        if (got === "appended") {
          head.sequence = seq;
          head.headHash = digest!;
          head.acceptedDigests.set(seq, digest!);
        } else if (got === "log_fork") {
          head.frozen = true;
        }
      }
    });
  }
});
