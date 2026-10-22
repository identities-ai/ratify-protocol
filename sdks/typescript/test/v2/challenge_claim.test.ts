// testvectors/v2/challenge-claim.json: ChallengeClaimDigest and the stable
// claim ID with its verifier namespace and replay epoch (SPEC-v2 §4).

import { test } from "node:test";
import assert from "node:assert/strict";

import { challengeClaimDigestV2, protocolClaimIDFromDigestV2, protocolClaimIDV2 } from "../../src/challenge_claim_v2.js";
import { hex, load, toHex, type Any } from "./helpers.js";

const f = load("challenge-claim.json");
const challenge = hex(f.challenge_hex);

test("challenge-claim.json: claim digest and ID known answers", () => {
  assert.equal(toHex(challengeClaimDigestV2(challenge)), f.expected_challenge_claim_digest_hex);
  const { verifier_namespace, replay_epoch } = f.claim_id_input;
  assert.equal(protocolClaimIDV2(verifier_namespace, replay_epoch, challenge), f.expected_claim_id);
  assert.equal(protocolClaimIDFromDigestV2(verifier_namespace, replay_epoch, challengeClaimDigestV2(challenge)), f.expected_claim_id);
  assert.ok(f.additional_claim_id_cases.length > 0);
  for (const c of f.additional_claim_id_cases as Any[]) {
    assert.equal(protocolClaimIDV2(c.verifier_namespace, c.replay_epoch, challenge), c.expected_claim_id, JSON.stringify(c.verifier_namespace));
  }
});

test("challenge-claim.json: namespace and epoch are bound", () => {
  const { verifier_namespace, replay_epoch } = f.claim_id_input;
  assert.notEqual(protocolClaimIDV2(verifier_namespace + "x", replay_epoch, challenge), f.expected_claim_id);
  assert.notEqual(protocolClaimIDV2(verifier_namespace, replay_epoch + 1, challenge), f.expected_claim_id);
  assert.throws(() => protocolClaimIDV2(verifier_namespace, -1, challenge));
  assert.throws(() => protocolClaimIDV2(verifier_namespace, Number.MAX_SAFE_INTEGER + 1, challenge));
  assert.throws(() => challengeClaimDigestV2(new Uint8Array(31)));
});
