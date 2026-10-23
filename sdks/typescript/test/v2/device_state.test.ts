// testvectors/v2/device-state.json: the single-device offline complete-state
// projection known answers (SPEC-v2 §7.13). Each case's records are loaded
// into a reference primary, which must reproduce every member's canonical
// bytes and digest, the projection object, and the complete-state digest.

import { test } from "node:test";
import assert from "node:assert/strict";

import { challengeClaimDigestV2 } from "../../src/challenge_claim_v2.js";
import { newV2ContextPolicy } from "../../src/context_policy_v2.js";
import type { ExpectedChallengeV2 } from "../../src/verify_v2_preflight.js";
import { issuanceKeyTestOnly } from "../../src/v2reference/challenges.js";
import { DevicePrimaryTestOnly, completeStateDigestTestOnly } from "../../src/v2reference/device.js";
import { StoreTestOnly, rateKeyOf, sha384Hex, streamKeyTestOnly } from "../../src/v2reference/store.js";
import { type Any, corpusKeyPairs, load, pubOf, toHex, unb64 } from "./helpers.js";

const file = load("device-state.json");
const utf8 = (b: Uint8Array): string => new TextDecoder().decode(b);
const bytesOf = (s: string | null): Uint8Array => (s === null ? new Uint8Array(0) : unb64(s));

/** Builds a primary holding exactly the case's records. */
async function loadCase(state: Any): Promise<DevicePrimaryTestOnly> {
  const keys = await corpusKeyPairs();
  const store = new StoreTestOnly(1_800_000_000, 30, state.log_id, keys.get("verifier")!);
  for (const c of state.claims as Any[]) {
    const sc = c.claim;
    store.claims.set(c.claim_id, {
      claim: {
        claimID: sc.claim_id, namespace: sc.namespace, replayEpoch: sc.replay_epoch, challengeDigest: sc.challenge_digest,
        proofDigest: sc.proof_digest, bundleHash: sc.bundle_hash, issuerIDs: [...sc.issuer_ids], requiredScope: sc.required_scope,
        contextPolicyDigest: sc.context_policy_digest ?? "", verifierID: sc.verifier_id, agentID: sc.agent_id, requiresRate: sc.requires_rate,
        rateBatch: (sc.rate_batch as Any[]).map((r) => ({ issuerID: r.issuer_id, certID: r.cert_id, windowS: r.window_s, limit: r.limit })),
        issuedAt: sc.issued_at, expiresAt: sc.expires_at, maxAgeSeconds: sc.max_age_seconds, clockSkewSeconds: sc.clock_skew_seconds,
        streamID: sc.stream_id === null ? null : unb64(sc.stream_id), streamSeq: sc.stream_seq,
        constraintEvaluators: (sc.constraint_evaluators as Any[]).map((e) => ({ profile_digest: e.profile_digest, type: e.type })),
      },
      ownerDigest: unb64(c.owner_digest), leaseExpiresAt: c.lease_expires_at, state: c.state,
      terminal: bytesOf(c.terminal_b64), receiptBody: bytesOf(c.receipt_body_b64), allowHorizon: c.allow_horizon,
      claimedAt: c.claimed_at, finalizedAt: c.finalized_at,
      release: c.release === null ? null : {
        claimID: c.release.claim_id, entryHash: unb64(c.release.entry_hash), ackTimestamp: c.release.ack_timestamp,
        outcome: c.release.outcome, reason: c.release.reason ?? "",
      },
      progress: {
        trustAssessment: c.progress.trust_assessment, statusAssessment: c.progress.status_assessment,
        contextAssessment: c.progress.context_assessment, contextPolicyDigest: c.progress.context_policy_digest,
        statusEvidence: (c.progress.status_evidence_digests as Any[]).map((e) => ({ ...e })),
      },
      abandoned: c.abandoned, outboxIndex: c.log_sequence === null ? -1 : c.log_sequence - 1,
    });
  }
  for (const s of state.streams as Any[]) {
    const streamID = unb64(s.stream_id);
    store.streams.set(streamKeyTestOnly(s.namespace, s.agent_id, streamID), { namespace: s.namespace, agentID: s.agent_id, streamID, lastSequence: s.last_sequence });
  }
  for (const r of state.rate_counters as Any[]) {
    store.rateCommits.set(rateKeyOf(r.issuer_id, r.cert_id, r.window_s), { issuerID: r.issuer_id, certID: r.cert_id, windowS: r.window_s, times: [...r.commits] });
  }
  for (const e of state.receipt_log.entries as Any[]) {
    store.outbox.push({ claimID: e.claim_id, body: unb64(e.body_b64), wire: null, digest: bytesOf(e.entry_hash), ack: null });
  }
  store.logFrozen = state.receipt_log.frozen;
  const primary = new DevicePrimaryTestOnly(store, state.replay_epoch);
  const journal = primary.journal.inner.snapshotStateTestOnly();
  primary.journal.inner.restoreStateTestOnly({
    head: { ...journal.head, generation: state.security_journal.generation }, snapshot: unb64(state.security_journal.snapshot_b64),
  });
  for (const r of state.issuance_records as Any[]) {
    const p = r.context_policy;
    const record: ExpectedChallengeV2 = {
      value: unb64(r.value), issuedAt: r.issued_at, expiresAt: r.expires_at, verifierNamespace: r.verifier_namespace, replayEpoch: r.replay_epoch,
      verifierID: r.verifier_id, expectedAgentID: r.expected_agent_id,
      expectedAgentPublicKey: r.expected_agent_pub_key === null ? null : pubOf(r.expected_agent_pub_key),
      expectedReceiverID: r.expected_receiver_id,
      expectedSessionContext: r.expected_session_context === null ? null : unb64(r.expected_session_context),
      contextPolicy: p === null ? null : newV2ContextPolicy(p.profile, p.require_bound, p.required_fields,
        p.expected_session_context === null ? null : unb64(p.expected_session_context)),
    };
    primary.issuance.inner.records.set(issuanceKeyTestOnly(record.verifierNamespace, record.replayEpoch, challengeClaimDigestV2(record.value)), record);
  }
  return primary;
}

test("device-state.json: corpus shape", () => {
  assert.equal(file.label, "ratify/device-complete-state/v2");
  assert.equal(file.version, 1);
  assert.equal(file.cases.length, 6);
});

for (const c of file.cases as Any[]) {
  test(`device-state: ${c.name}`, async () => {
    const primary = await loadCase(c.state);
    const m = primary.store.storeMembers();
    const members: Record<string, Uint8Array> = {
      claims: m.claims, streams: m.streams, rate_counters: m.rateCounters, receipt_log: m.receiptLog, issuance_records: primary.issuanceMember(),
    };
    for (const [name, got] of Object.entries(members)) {
      assert.equal(utf8(got), c.expect[`${name}_canonical_json`], `${name} canonical bytes`);
      assert.equal(sha384Hex(got), c.expect[`${name}_sha384`], `${name} digest`);
    }
    const projection = primary.projection(primary.store.stateDigests(), sha384Hex(members.issuance_records!));
    assert.equal(utf8(projection), c.expect.projection_canonical_json);
    const digest = primary.completeStateDigestTestOnly();
    assert.equal(toHex(digest), c.expect.complete_state_digest_hex);
    assert.equal(toHex(completeStateDigestTestOnly(projection)), c.expect.complete_state_digest_hex);
  });
}
