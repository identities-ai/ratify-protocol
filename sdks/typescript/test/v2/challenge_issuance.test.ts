// testvectors/v2/challenge-issuance.json: the challenge issuance helper over
// the test-only issuance store and the reference claim store (SPEC-v2 §7.3;
// Go TestV2ConformanceChallengeIssuance).

import { test } from "node:test";
import assert from "node:assert/strict";

import { issueChallengeV2, loadExpectedChallengeV2, type V2ChallengeIssueRequest, type V2ChallengeIssuanceStore } from "../../src/challenge_issuance_v2.js";
import { claimProofBundleV2, type ClaimStoreV2 } from "../../src/claim_store_v2.js";
import { newV2ContextPolicy } from "../../src/context_policy_v2.js";
import { ErrV2ClaimProofConflict, v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeProofBundleV2 } from "../../src/protocol_v2_wire.js";
import { preflightProofBundleV2 } from "../../src/verify_v2_preflight.js";
import { ChallengeIssuanceStoreTestOnly } from "../../src/v2reference/challenges.js";
import { StoreTestOnly } from "../../src/v2reference/store.js";
import { type Any, b64, corpusKeyPairs, eqBytes, load, unb64 } from "./helpers.js";

const file = load("challenge-issuance.json");
const keysFile = load("keys.json");
const NAMESPACE = "verify-test";
const EPOCH = 3;

async function presentIssued(issuance: V2ChallengeIssuanceStore, claims: ClaimStoreV2, wire: Uint8Array, now: number): Promise<string> {
  let bundle;
  try {
    bundle = decodeProofBundleV2(wire);
  } catch (err) {
    return "preflight:" + v2ErrorClassOf(err);
  }
  let expected;
  try {
    expected = await loadExpectedChallengeV2(issuance, NAMESPACE, EPOCH, bundle.challenge);
  } catch (err) {
    return "preflight:" + v2ErrorClassOf(err);
  }
  const policy = expected.expectedSessionContext
    ? newV2ContextPolicy("ratify.verify.session-context/v1", true, ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"], expected.expectedSessionContext)
    : newV2ContextPolicy("ratify.conformance.context-not-required/v1", false, [], null);
  let preflight;
  try {
    preflight = await preflightProofBundleV2(bundle, expected, policy, "data:read", NAMESPACE, EPOCH, expected.verifierID, now, 300, 5);
  } catch (err) {
    return "preflight:" + v2ErrorClassOf(err);
  }
  try {
    const { disposition } = await claimProofBundleV2(claims, bundle, preflight, NAMESPACE, EPOCH, now);
    return disposition;
  } catch (err) {
    if (err === ErrV2ClaimProofConflict) return "proof_conflict";
    return `claim error: ${(err as Error).message}`;
  }
}

test("challenge-issuance.json: corpus shape", () => {
  assert.equal(file.scenarios.length, 10);
  assert.equal(file.scenarios.reduce((n: number, s: Any) => n + s.steps.length, 0), 36);
});

for (const sc of file.scenarios as Any[]) {
  test(`challenge-issuance: ${sc.name}`, async () => {
    const keys = await corpusKeyPairs();
    const randomBytes: number[] = [];
    for (const r of sc.random_b64 ?? []) randomBytes.push(...unb64(r));
    let offset = 0;
    const random = (n: number) => {
      if (offset + n > randomBytes.length) throw new Error("scripted random source exhausted");
      const out = Uint8Array.from(randomBytes.slice(offset, offset + n));
      offset += n;
      return out;
    };
    const claims = new StoreTestOnly(sc.steps[0].at, 60, "0123456789abcdef0123456789abcdef", keys.get("verifier")!);
    const issuance = new ChallengeIssuanceStoreTestOnly();
    const issuer = { clock: claims, store: issuance, random };
    for (let i = 0; i < sc.steps.length; i++) {
      const step = sc.steps[i];
      if (step.at) claims.setTime(step.at);
      const exp = step.expect ?? {};
      switch (step.op) {
        case "issue": {
          const r = step.request;
          const req: V2ChallengeIssueRequest = { verifierNamespace: r.verifier_namespace, replayEpoch: r.replay_epoch, verifierID: r.verifier_id, lifetimeSeconds: r.lifetime_seconds };
          if (r.expected_agent !== null && r.expected_agent !== undefined) {
            req.expectedAgentID = keysFile.keys.find((k: Any) => k.name === r.expected_agent).key_id_v2;
            req.expectedAgentPublicKey = keys.get(r.expected_agent)!.publicKey;
          }
          if (r.expected_receiver_id !== null && r.expected_receiver_id !== undefined) req.expectedReceiverID = r.expected_receiver_id;
          if (r.expected_session_context_b64 !== null && r.expected_session_context_b64 !== undefined) req.expectedSessionContext = unb64(r.expected_session_context_b64);
          if (step.persist_fault === "fail_before_commit" || step.persist_fault === "fail_after_commit") issuance.failNextPersist(step.persist_fault);
          let got = null;
          let err: unknown = null;
          try {
            got = await issueChallengeV2(issuer, req);
          } catch (e) {
            err = e;
          }
          if (exp.result === "issued") {
            assert.equal(err, null, `step ${i}: issuance failed: ${(err as Error)?.message}`);
            assert.equal(b64(got!.value), exp.challenge_b64, `step ${i} challenge`);
            assert.deepEqual([got!.issuedAt, got!.expiresAt], [exp.issued_at, exp.expires_at], `step ${i} times`);
            const stored = await loadExpectedChallengeV2(issuance, req.verifierNamespace, req.replayEpoch, got!.value);
            assert.equal(stored.expectedAgentID ?? "", req.expectedAgentID ?? "");
            assert.ok(eqBytes(stored.expectedSessionContext ?? new Uint8Array(0), req.expectedSessionContext ?? new Uint8Array(0)));
          } else if (exp.result === "error") {
            assert.ok(err !== null && got === null, `step ${i}: issuance returned a challenge`);
            if (exp.error_class) assert.equal(v2ErrorClassOf(err), exp.error_class, `step ${i} class (${(err as Error).message})`);
          } else throw new Error(`unknown issue result ${exp.result}`);
          if (exp.records_after !== undefined && exp.records_after !== null) assert.equal(issuance.size, exp.records_after, `step ${i} records`);
          break;
        }
        case "load": {
          let got = null;
          let cls = "";
          try {
            got = await loadExpectedChallengeV2(issuance, NAMESPACE, EPOCH, unb64(step.challenge_b64));
          } catch (err) {
            cls = v2ErrorClassOf(err);
          }
          if (exp.result === "found") assert.deepEqual([got?.issuedAt, got?.expiresAt], [exp.issued_at, exp.expires_at], `step ${i} load`);
          else assert.equal(cls, exp.result, `step ${i} load class`);
          break;
        }
        case "present":
        case "present_concurrent": {
          const outcomes = (await Promise.all((step.bundles_b64 as string[]).map((w) => presentIssued(issuance, claims, unb64(w), step.at)))).sort();
          let want: string[];
          if (exp.result === "preflight") want = ["preflight:" + exp.error_class];
          else if (exp.result === "claimed") want = [...exp.dispositions].sort();
          else throw new Error(`unknown present result ${exp.result}`);
          assert.deepEqual(outcomes, want, `step ${i} outcomes`);
          break;
        }
        default:
          throw new Error(`unknown op ${step.op}`);
      }
    }
  });
}
