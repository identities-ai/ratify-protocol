// testvectors/v2/transaction-verification.json: composed transaction
// receipt verification (SPEC-v2 §5.7; Go TestV2ConformanceTransactionVerification).

import { test } from "node:test";
import assert from "node:assert/strict";

import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { verifyTransactionReceiptV2, type TransactionVerifySourcesV2 } from "../../src/transaction_verify_v2.js";
import { type Any, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";

const file = load("transaction-verification.json");

test("transaction-verification.json: corpus shape", () => {
  assert.equal(file.version, 2);
  assert.equal(file.vectors.length, 13);
});

for (const v of file.vectors as Any[]) {
  test(`transaction-verification: ${v.name}`, async () => {
    const { req, cb } = await buildVerifyRequest(v, new Uint8Array(0), zeroCounts());
    const sources: TransactionVerifySourcesV2 = {
      statusEvidence: cb.statusEvidence ?? null, statusJournal: cb.statusJournal ?? null, statusKeys: req.statusKeys ?? null, statusPolicy: req.statusPolicy,
    };
    if (v.trust) sources.trust = cb.trust ?? null;
    let got = null;
    let err: unknown = null;
    try {
      got = await verifyTransactionReceiptV2({ receipt: unb64(v.receipt_b64), now: v.now, futureSkewSeconds: v.future_skew_seconds }, sources);
    } catch (e) {
      err = e;
    }
    if (v.expected.error_class) {
      assert.equal(v2ErrorClassOf(err), v.expected.error_class, `class (${(err as Error)?.message})`);
      return;
    }
    if (err) throw err;
    assert.deepEqual(JSON.parse(JSON.stringify(got)), v.expected.result);
  });
}
