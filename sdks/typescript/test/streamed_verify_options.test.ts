// verifyStreamedTurnWithOptions tests — the options-object streamed fast
// path (SPEC §5.13): required_scope against token.granted_scope, single-use
// challenges with the §10 consumption order, and verifier-side session and
// stream binding checks.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateHumanRoot,
  generateAgent,
  issueDelegation,
  issueSessionToken,
  signChallenge,
  generateChallenge,
  verifyBundle,
  verifyStreamedTurnWithOptions,
  MemoryChallengeStore,
  UNKNOWN_CHALLENGE,
  PROTOCOL_VERSION,
  SCOPE_MEETING_ATTEND,
  SCOPE_FILES_READ,
  SCOPE_FILES_WRITE,
  type DelegationCert,
  type HybridPrivateKey,
  type ProofBundle,
  type SessionToken,
  type StreamedTurn,
} from "../src/index.js";

const NOW = () => Math.floor(Date.now() / 1000);
const UNKNOWN_REASON = `unknown_challenge: ${UNKNOWN_CHALLENGE}`;

interface Fixture {
  token: SessionToken;
  secret: Uint8Array;
  agentPriv: HybridPrivateKey;
  now: number;
}

async function fixture(scope: string[]): Promise<Fixture> {
  const { root, privateKey: rootPriv } = await generateHumanRoot();
  const { agent, privateKey: agentPriv } = await generateAgent("Turn Bot", "custom");
  const now = NOW();
  const cert: DelegationCert = {
    cert_id: "turn-cert-001",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.public_key,
    subject_id: agent.id,
    subject_pub_key: agent.public_key,
    scope,
    constraints: [],
    issued_at: now,
    expires_at: now + 86400,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, rootPriv);
  const challenge = generateChallenge();
  const sig = await signChallenge(challenge, now, agentPriv);
  const bundle: ProofBundle = {
    agent_id: agent.id,
    agent_pub_key: agent.public_key,
    delegations: [cert],
    challenge,
    challenge_at: now,
    challenge_sig: sig,
  };
  const res = await verifyBundle(bundle, { now });
  assert.equal(res.valid, true, res.error_reason);
  const secret = new Uint8Array(32).fill(0x42);
  const token = issueSessionToken(bundle, res, "session-turn", now, now + 1800, secret);
  return { token, secret, agentPriv, now };
}

async function turnFor(
  f: Fixture,
  challenge: Uint8Array,
  sessionContext?: Uint8Array,
  streamID?: Uint8Array,
  streamSeq?: number,
): Promise<StreamedTurn> {
  const sig = await signChallenge(challenge, f.now, f.agentPriv, sessionContext, streamID, streamSeq);
  return {
    challenge,
    challenge_at: f.now,
    challenge_sig: sig,
    session_context: sessionContext,
    stream_id: streamID,
    stream_seq: streamSeq,
  };
}

test("streamed options: required scope allowed and denied", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND, SCOPE_FILES_READ]);
  const turn = await turnFor(f, generateChallenge());

  const ok = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    required_scope: SCOPE_MEETING_ATTEND,
    now: f.now,
  });
  assert.equal(ok.valid, true, ok.error_reason);

  const denied = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    required_scope: SCOPE_FILES_WRITE,
    now: f.now,
  });
  assert.equal(denied.valid, false);
  assert.equal(denied.identity_status, "scope_denied");
});

test("streamed options: single-use challenge replay is rejected", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  const turn = await turnFor(f, challenge);
  const opts = { required_scope: SCOPE_MEETING_ATTEND, challenge_store: store, now: f.now };

  const first = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, opts);
  assert.equal(first.valid, true, first.error_reason);

  const replay = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, opts);
  assert.equal(replay.valid, false);
  assert.equal(replay.error_reason, UNKNOWN_REASON);
});

test("streamed options: forged signature does not consume", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  const turn = await turnFor(f, challenge);
  const opts = { challenge_store: store, now: f.now };

  const forgedSig = turn.challenge_sig.ed25519.slice();
  forgedSig[0]! ^= 0xff;
  const forged: StreamedTurn = {
    ...turn,
    challenge_sig: { ...turn.challenge_sig, ed25519: forgedSig },
  };
  const res = await verifyStreamedTurnWithOptions(f.token, f.secret, forged, opts);
  assert.equal(res.valid, false);
  assert.match(res.error_reason ?? "", /^bad_challenge_sig/);

  const legit = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, opts);
  assert.equal(legit.valid, true, legit.error_reason);
});

test("streamed options: scope denial still consumes", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const store = new MemoryChallengeStore(16);
  const { challenge } = await store.issue(undefined, 300);
  const turn = await turnFor(f, challenge);

  const denied = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    required_scope: SCOPE_FILES_WRITE,
    challenge_store: store,
    now: f.now,
  });
  assert.equal(denied.identity_status, "scope_denied");

  // The denial happened AFTER consumption: the challenge is spent.
  const retry = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    required_scope: SCOPE_MEETING_ATTEND,
    challenge_store: store,
    now: f.now,
  });
  assert.equal(retry.error_reason, UNKNOWN_REASON);
});

test("streamed options: unknown challenge rejected before crypto", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const store = new MemoryChallengeStore(16);
  const turn = await turnFor(f, generateChallenge());
  const res = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    challenge_store: store,
    now: f.now,
  });
  assert.equal(res.error_reason, UNKNOWN_REASON);
});

test("streamed options: session binding checks", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const ctx = new Uint8Array(32);
  ctx[0] = 7;
  const turn = await turnFor(f, generateChallenge(), ctx);

  const ok = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    session_context: ctx,
    now: f.now,
  });
  assert.equal(ok.valid, true, ok.error_reason);

  const other = new Uint8Array(32);
  other[0] = 8;
  const mismatch = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    session_context: other,
    now: f.now,
  });
  assert.match(mismatch.error_reason ?? "", /^session_context_mismatch/);

  const unverifiable = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, { now: f.now });
  assert.match(unverifiable.error_reason ?? "", /^session_context_unverifiable/);

  const unbound = await turnFor(f, generateChallenge());
  const missing = await verifyStreamedTurnWithOptions(f.token, f.secret, unbound, {
    session_context: ctx,
    now: f.now,
  });
  assert.match(missing.error_reason ?? "", /^missing_session_context/);
});

test("streamed options: stream tracking replay and skip", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const streamID = new Uint8Array(32);
  streamID[0] = 3;
  const turn = await turnFor(f, generateChallenge(), undefined, streamID, 4);

  const ok = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    stream: { stream_id: streamID, last_seen_seq: 3 },
    now: f.now,
  });
  assert.equal(ok.valid, true, ok.error_reason);

  const replay = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    stream: { stream_id: streamID, last_seen_seq: 4 },
    now: f.now,
  });
  assert.match(replay.error_reason ?? "", /^stream_seq_replay/);

  const skip = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    stream: { stream_id: streamID, last_seen_seq: 1 },
    now: f.now,
  });
  assert.match(skip.error_reason ?? "", /^stream_seq_skip/);

  const unverifiable = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, { now: f.now });
  assert.match(unverifiable.error_reason ?? "", /^stream_context_unverifiable/);
});

test("streamed options: stream state is a caller-owned snapshot", async () => {
  // The verifier reads the stream snapshot and never advances it: two
  // distinct valid challenges carrying the same stream_seq BOTH verify
  // against the same snapshot (documented caller-owned semantics). The
  // caller must atomically advance its tracked sequence on success, after
  // which the same-seq turn is rejected as a replay.
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const streamID = new Uint8Array(32);
  streamID[0] = 5;
  const turn1 = await turnFor(f, generateChallenge(), undefined, streamID, 4);
  const turn2 = await turnFor(f, generateChallenge(), undefined, streamID, 4);
  const snapshot = { stream_id: streamID, last_seen_seq: 3 };

  const res1 = await verifyStreamedTurnWithOptions(f.token, f.secret, turn1, {
    stream: snapshot,
    now: f.now,
  });
  const res2 = await verifyStreamedTurnWithOptions(f.token, f.secret, turn2, {
    stream: snapshot,
    now: f.now,
  });
  assert.equal(res1.valid, true, res1.error_reason);
  assert.equal(res2.valid, true, res2.error_reason);

  const advanced = { stream_id: streamID, last_seen_seq: 4 };
  const replay = await verifyStreamedTurnWithOptions(f.token, f.secret, turn2, {
    stream: advanced,
    now: f.now,
  });
  assert.match(replay.error_reason ?? "", /^stream_seq_replay/);
});

test("streamed options: full-verifier options are rejected, never silently ignored", async () => {
  // TypeScript's structural typing lets a full VerifyOptions variable be
  // assigned where StreamedVerifyOptions is expected, so the boundary
  // must hold at runtime: any options object carrying a
  // full-verifier-only field fails closed with unsupported_option.
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const turn = await turnFor(f, generateChallenge());

  const fullVerifierOnly: Record<string, unknown>[] = [
    { force_revocation_check: true },
    { revocation: { isRevoked: async () => [false, null] } },
    { is_revoked: () => false },
    { policy: { evaluatePolicy: async () => true } },
    { audit: { logVerification: async () => {} } },
    { context: { requested_amount: 5 } },
    { constraint_evaluators: {} },
    { policy_verdict: {} },
    { policy_secret: new Uint8Array(32) },
    { anchor_resolver: { resolveAnchor: async () => null } },
  ];
  for (const extra of fullVerifierOnly) {
    const res = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
      required_scope: SCOPE_MEETING_ATTEND,
      now: f.now,
      ...extra,
    } as never);
    assert.equal(res.valid, false, `option ${Object.keys(extra)[0]} must be rejected`);
    assert.match(res.error_reason ?? "", /^unsupported_option/);
  }

  // The same call without the foreign field verifies — proving the
  // rejection is about the option, not the turn.
  const ok = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    required_scope: SCOPE_MEETING_ATTEND,
    now: f.now,
  });
  assert.equal(ok.valid, true, ok.error_reason);
});

test("streamed options: token checks still apply", async () => {
  const f = await fixture([SCOPE_MEETING_ATTEND]);
  const turn = await turnFor(f, generateChallenge());

  const badSecret = await verifyStreamedTurnWithOptions(
    f.token,
    new Uint8Array(32).fill(0x99),
    turn,
    { now: f.now },
  );
  assert.match(badSecret.error_reason ?? "", /^session_token_invalid/);

  const expired = await verifyStreamedTurnWithOptions(f.token, f.secret, turn, {
    now: f.now + 31 * 60,
  });
  assert.match(expired.error_reason ?? "", /^session_token_invalid/);
});
