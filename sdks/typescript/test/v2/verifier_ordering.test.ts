// testvectors/v2/verifier-ordering.json: end-to-end live verifier cases with
// scripted Part B dependencies (Go TestV2ConformanceVerifierOrdering).

import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeVerificationReceiptBodyV2 } from "../../src/verification_receipt_v2.js";
import { receiptOutboxDigestV2 } from "../../src/release_v2.js";
import { verifyProofBundleV2 } from "../../src/verify_v2.js";
import { type Any, b64, load, unb64 } from "./helpers.js";
import { ScriptedClaimStore, buildVerifyRequest, zeroCounts } from "./verify_harness.js";

const file = load("verifier-ordering.json");

test("verifier-ordering.json: corpus shape", () => {
  assert.equal(file.version, 2);
  assert.equal(file.vectors.length, 213);
});

for (const v of file.vectors as Any[]) {
  test(`verifier-ordering: ${v.name}`, async () => {
    const bundleB64 = file.bundles_b64[v.bundle];
    assert.ok(bundleB64, `unknown bundle ${v.bundle}`);
    const counts = zeroCounts();
    const { req, cb, rate } = await buildVerifyRequest(v, unb64(bundleB64), counts);
    const claimedAt = v.now + (v.claim_time_offset ?? 0);
    const store = new ScriptedClaimStore(v.claim_store, claimedAt, claimedAt + (v.finalize_time_offset ?? 0), counts);
    const outcome = await verifyProofBundleV2(req, { ...cb, claimStore: store });
    const want = v.expected;
    assert.equal(outcome.stage, want.stage, `stage (class ${outcome.errorClass}: ${outcome.error?.message})`);
    assert.equal(outcome.errorClass, want.error_class ?? "", `error class (${outcome.error?.message})`);
    if (want.disposition) assert.equal(outcome.disposition, want.disposition);
    assert.deepEqual(counts, { ...zeroCounts(), ...want.callback_counts }, "callback counts");
    if (want.stage !== "committed") {
      assert.equal(outcome.committed, null);
      return;
    }
    const committed = outcome.committed;
    assert.ok(committed);
    const body = committed.receiptBody();
    const r = decodeVerificationReceiptBodyV2(body);
    assert.deepEqual(
      [r.decision, r.decision_reason, r.identity_status, r.trust_assessment, r.status_assessment, r.context_assessment],
      [want.decision, want.decision_reason, want.identity_status, want.trust_assessment, want.status_assessment, want.context_assessment],
      "committed tuple",
    );
    assert.equal(r.verified_at, want.verified_at, "verified_at");
    assert.equal(b64(body), want.receipt_body_b64, "receipt body");
    assert.ok(store.finalBody && b64(store.finalBody) === want.receipt_body_b64, "finalized body");
    assert.equal(committed.receiptBodyDigest(), receiptOutboxDigestV2(unb64(want.receipt_body_b64)));
    assert.notEqual(committed.claimID(), "");
    const horizon = committed.allowHorizon();
    assert.equal(horizon !== null, want.decision === "allow");
    assert.equal(horizon ?? 0, want.allow_valid_until ?? 0, "allow horizon");
    if ((want.rate_batch ?? []).length !== 0) {
      assert.ok(rate);
      assert.deepEqual(rate.batch.map((x) => ({ issuer_id: x.issuerID, cert_id: x.certID, window_s: x.windowS, limit: x.limit })), want.rate_batch);
    }
  });
}
