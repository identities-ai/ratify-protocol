import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { challengeClaimDigestV2, protocolClaimIDV2, protocolClaimIDFromDigestV2 } from "../src/index.js";

const fixture = JSON.parse(readFileSync(join(
  dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "testvectors", "v2", "challenge-claim.json",
), "utf8")) as {
  challenge_hex: string;
  expected_challenge_claim_digest_hex: string;
  claim_id_input: { verifier_namespace: string; replay_epoch: number };
  expected_claim_id: string;
  additional_claim_id_cases: { verifier_namespace: string; replay_epoch: number; expected_claim_id: string }[];
};
const challenge = new Uint8Array(fixture.challenge_hex.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));
const hex = (value: Uint8Array) => Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

test("v2 claim digest and ID match the shared Protocol vector", () => {
  assert.equal(hex(challengeClaimDigestV2(challenge)), fixture.expected_challenge_claim_digest_hex);
  assert.equal(protocolClaimIDV2(fixture.claim_id_input.verifier_namespace, fixture.claim_id_input.replay_epoch, challenge), fixture.expected_claim_id);
  assert.equal(protocolClaimIDFromDigestV2(fixture.claim_id_input.verifier_namespace, fixture.claim_id_input.replay_epoch,
    challengeClaimDigestV2(challenge)), fixture.expected_claim_id);
  assert.notEqual(protocolClaimIDV2("verify-other", fixture.claim_id_input.replay_epoch, challenge), fixture.expected_claim_id);
  assert.notEqual(protocolClaimIDV2(fixture.claim_id_input.verifier_namespace, 8, challenge), fixture.expected_claim_id);
  for (const item of fixture.additional_claim_id_cases) {
    assert.equal(protocolClaimIDV2(item.verifier_namespace, item.replay_epoch, challenge), item.expected_claim_id);
  }
});

test("v2 replay identifiers reject malformed input", () => {
  for (const length of [0, 31, 33]) {
    assert.throws(() => challengeClaimDigestV2(new Uint8Array(length)), /exactly 32/);
  }
  for (const namespace of ["", "\ud800", "a\udc00"]) {
    assert.throws(() => protocolClaimIDV2(namespace, 7, challenge), /namespace/);
  }
  assert.throws(() => protocolClaimIDV2(123 as unknown as string, 7, challenge), /namespace/);
  for (const wrong of ["x".repeat(32), new Array(32).fill(256)]) {
    assert.throws(() => protocolClaimIDV2("verify-prod", 7, wrong as unknown as Uint8Array), /exactly 32/);
  }
  assert.throws(() => protocolClaimIDFromDigestV2("verify-prod", 7, new Uint8Array(47)), /exactly 48/);
  for (const epoch of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => protocolClaimIDV2("verify-prod", epoch, challenge), /safe integer/);
  }
});
