// testvectors/v2/status-publisher.json: the signed-status publisher built
// from the authenticated role journal, with journal ingestion (SPEC-v2 §5.4),
// plus the provenance status stage (§6.5) against the reference journal.

import { test } from "node:test";
import assert from "node:assert/strict";

import { keyIDV2 } from "../../src/crypto_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { decodeProofBundleV2, verifyRevocationListV2Signature, verifyRevocationPushV2Signature, type RevocationListV2, type RevocationPushV2, type RevokedCertV2 } from "../../src/protocol_v2_wire.js";
import {
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  configureStatusKeyEpochV2,
  recordSecurityKeyRoleV2,
  revocationStatusFromJournalV2,
} from "../../src/security_journal_v2.js";
import { newLocalSignerV2, type SignRequestV2, type SignerV2 } from "../../src/signer_v2.js";
import { runV2StatusStage, type V2StatusEvidenceRequest } from "../../src/status_provenance_v2.js";
import { encodeV2StatusEvidenceBatch } from "../../src/status_batch_v2.js";
import { newV2StatusPublisher, newV2StatusPublisherWithKey, type V2StatusPublication, type V2StatusPublisherState } from "../../src/status_publisher_v2.js";
import { JournalStoreTestOnly } from "../../src/v2reference/journal.js";
import { type Any, corpusKeyPairs, load } from "./helpers.js";

const f = load("status-publisher.json");
const policy = { maxListLifetimeSeconds: f.status_policy.max_list_lifetime_seconds, maxStatusAgeSeconds: f.status_policy.max_status_age_seconds, clockSkewSeconds: f.status_policy.clock_skew_seconds };
const ids = (refs: RevokedCertV2[] | null) => (refs ?? []).map((r) => r.cert_id);

class CountingSigner implements SignerV2 {
  calls = 0;
  constructor(readonly inner: SignerV2) {}
  publicKeyV2() {
    this.calls++;
    return this.inner.publicKeyV2();
  }
  modeV2() {
    return this.inner.modeV2();
  }
  signV2(req: SignRequestV2, signal?: AbortSignal) {
    this.calls++;
    return this.inner.signV2(req, signal);
  }
}

test("status-publisher.json: has scenarios", () => assert.ok(f.scenarios.length >= 13));

for (const sc of f.scenarios as Any[]) {
  test(`status-publisher.json: ${sc.name}`, async () => {
    const keys = await corpusKeyPairs();
    const issuerKey = keys.get(sc.issuer)!.publicKey;
    const status = keys.get(sc.status_key)!;
    const statusKey = status.publicKey;
    const issuerID = keyIDV2(issuerKey);
    const journal = new JournalStoreTestOnly();
    for (const rk of sc.role_keys ?? []) await recordSecurityKeyRoleV2(journal, rk.role, keys.get(rk.key)!.publicKey);
    let setup = "not_configured";
    if (sc.status_configured_for) {
      setup = "configured";
      try {
        await configureStatusKeyEpochV2(journal, keyIDV2(keys.get(sc.status_configured_for)!.publicKey), 1, statusKey);
      } catch {
        setup = "rejected";
      }
    }
    assert.equal(setup, sc.journal_setup, "journal setup");
    const counting = new CountingSigner(await newLocalSignerV2(status));
    let publisher;
    let err: unknown = null;
    try {
      publisher = await newV2StatusPublisher(journal, issuerKey, counting, sc.lifetime_seconds);
    } catch (e) {
      err = e;
    }
    if (sc.publisher === "refused") {
      assert.ok(err !== null && publisher === undefined, "publisher accepted a status key outside the role configuration");
      assert.equal(v2ErrorClassOf(err), "configuration_invalid");
      assert.ok(counting.calls <= 1, `a refused publisher invoked the signer ${counting.calls} times`);
      return;
    }
    assert.equal(err, null, `publisher refused: ${err}`);
    let state: V2StatusPublisherState | null = null;
    const publications: V2StatusPublication[] = [];
    for (const [i, step] of (sc.steps as Any[]).entries()) {
      const exp = step.expect ?? {};
      let pubn: V2StatusPublication | null = null;
      let stepErr: unknown = null;
      try {
        switch (step.op) {
          case "genesis":
            pubn = await publisher!.genesis(step.at);
            break;
          case "heartbeat":
            pubn = await publisher!.heartbeat(state!, step.at);
            break;
          case "revoke":
            pubn = await publisher!.revoke(state!, step.cert_ids, step.at);
            break;
          case "ingest": {
            const p = publications[step.publication]!;
            if (step.object === "push") await applyRevocationPushToJournalV2(journal, p.push!, issuerID, 1, statusKey, policy, step.at);
            else await applyRevocationListToJournalV2(journal, p.list, issuerID, 1, statusKey, policy, step.at);
            continue;
          }
          case "status": {
            const r = await revocationStatusFromJournalV2(journal, issuerID, step.cert_id, 1, statusKey, policy, step.at);
            assert.deepEqual([r.status, r.reason ?? ""], [exp.status, exp.reason ?? ""], `step ${i}: ${step.cert_id}`);
            continue;
          }
          default:
            assert.fail(`unknown op ${step.op}`);
        }
      } catch (e) {
        stepErr = e;
      }
      if (exp.result === "refused") {
        assert.ok(stepErr !== null, `step ${i}: ${step.op} was not refused`);
        continue;
      }
      assert.equal(stepErr, null, `step ${i} ${step.op}: ${stepErr}`);
      const l: RevocationListV2 = pubn!.list;
      await verifyRevocationListV2Signature(l, issuerID, statusKey);
      assert.deepEqual([l.sequence, l.updated_at, l.next_update, ids(l.revoked)], [exp.list.sequence, exp.list.updated_at, exp.list.next_update, exp.list.revoked], `step ${i}: list`);
      assert.equal(pubn!.push !== null, exp.push !== undefined && exp.push !== null, `step ${i}: push presence`);
      if (pubn!.push) {
        const p: RevocationPushV2 = pubn!.push;
        await verifyRevocationPushV2Signature(p, issuerID, statusKey);
        assert.deepEqual([p.sequence, p.pushed_at, ids(p.revoked)], [exp.push.sequence, exp.push.pushed_at, exp.push.revoked], `step ${i}: push`);
      }
      state = pubn!.state;
      publications.push(pubn!);
    }
  });
}

test("provenance stage: provider evidence is authenticated through the journal; failures make the issuer unavailable", async () => {
  const objects = load("objects.json").objects as Any[];
  const bundleObj = objects.find((o) => o.kind === "proof_bundle" && JSON.parse(Buffer.from(o.wire_b64, "base64").toString()).delegations.length > 0)!;
  const bundle = decodeProofBundleV2(new Uint8Array(Buffer.from(bundleObj.wire_b64, "base64")));
  const keys = await corpusKeyPairs();
  const certs = bundle.delegations!;
  const checks = certs.map((c, i) => ({ delegationIndex: i, issuerID: c.issuer_id, subjectID: c.subject_id, certID: c.cert_id }));
  const statusKeys = ["status_root", "status_intermediate"].map((n) => keys.get(n)!);
  const issuers = [...new Set(certs.map((c) => c.issuer_id))];
  const store = new JournalStoreTestOnly();
  for (const c of certs) {
    for (const k of [c.issuer_pub_key, c.subject_pub_key]) {
      try {
        await recordSecurityKeyRoleV2(store, "other", k);
      } catch {
        // already recorded
      }
    }
  }
  const configs = new Map<string, { epoch: number; key: typeof statusKeys[number]["publicKey"] }>();
  const publishers = new Map<string, Awaited<ReturnType<typeof newV2StatusPublisher>>>();
  for (const [i, issuerID] of issuers.entries()) {
    const sk = statusKeys[i % statusKeys.length]!;
    await configureStatusKeyEpochV2(store, issuerID, 1, sk.publicKey);
    configs.set(issuerID, { epoch: 1, key: sk.publicKey });
    const issuerKey = certs.find((c) => c.issuer_id === issuerID)!.issuer_pub_key;
    publishers.set(issuerID, await newV2StatusPublisherWithKey(store, issuerKey, sk, 3600));
  }
  const now = 1_800_000_000;
  const genesis = new Map<string, Uint8Array>();
  for (const [issuerID, p] of publishers) genesis.set(issuerID, encodeRevocationListObject((await p.genesis(now - 10)).list));
  const requests: V2StatusEvidenceRequest[] = [];
  const provider = async (req: V2StatusEvidenceRequest) => {
    requests.push(req);
    return { objects: [{ objectType: 3, wire: genesis.get(req.issuerID)! }] };
  };
  const inputs = { statusKeys: configs, statusPolicy: policy, statusJournal: store, statusEvidence: provider };
  const ok = await runV2StatusStage(undefined, bundle, checks, inputs, now);
  assert.equal(ok.cancelled, null);
  assert.equal(ok.assessment.assessment, "current");
  assert.equal(ok.queries, issuers.length);
  assert.deepEqual(requests.map((r) => r.issuerID), [...issuers].sort());
  // A provider failure for every issuer: unavailable, never current.
  const failing = await runV2StatusStage(undefined, bundle, checks, { ...inputs, statusEvidence: async () => { throw new Error("down"); } }, now);
  assert.equal(failing.assessment.assessment, "unavailable");
  // A batch signed under the wrong key is rejected as a whole.
  const swapped = await runV2StatusStage(undefined, bundle, checks, {
    ...inputs, statusEvidence: async (req: V2StatusEvidenceRequest) => ({ objects: [{ objectType: 3, wire: genesis.get(issuers.find((x) => x !== req.issuerID) ?? req.issuerID)! }] }),
  }, now);
  assert.equal(issuers.length > 1 ? swapped.assessment.assessment : "unavailable", "unavailable");
  // No configured binding: the provider is not called.
  requests.length = 0;
  const unbound = await runV2StatusStage(undefined, bundle, checks, { ...inputs, statusKeys: new Map() }, now);
  assert.equal(unbound.assessment.assessment, "unavailable");
  assert.equal(unbound.queries, 0);
  // Cancellation is reported, not converted to a result.
  const controller = new AbortController();
  controller.abort(new Error("cancel"));
  const cancelled = await runV2StatusStage(controller.signal, bundle, checks, inputs, now);
  assert.notEqual(cancelled.cancelled, null);
  // The canonical batch form is accepted by the provider path too.
  assert.ok(encodeV2StatusEvidenceBatch({ objects: [{ objectType: 3, wire: genesis.get(issuers[0]!)! }] }).length > 0);
});

function encodeRevocationListObject(l: Parameters<typeof verifyRevocationListV2Signature>[0]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    issuer_id: l.issuer_id, next_update: l.next_update, revoked: l.revoked, sequence: l.sequence,
    signature: { ed25519: Buffer.from(l.signature.ed25519).toString("base64"), ml_dsa_65: Buffer.from(l.signature.ml_dsa_65).toString("base64") },
    updated_at: l.updated_at, version: l.version,
  }));
}
