// testvectors/v2/concurrency-scenarios.json: shared concurrent workloads
// against the test-only reference store (Go
// TestV2ConformanceConcurrencyScenarios). Set RATIFY_RACE_ITERATIONS to
// change the per-scenario iteration count.
//
// What "concurrent" means here: JavaScript runs on one thread, so the
// participants are async calls started together with Promise.all against the
// one store. They interleave at every await (store calls, which the store
// serializes with its async mutex, async crypto and callbacks), so these
// scenarios exercise the store's async atomicity and the verifier's await
// points, not parallel threads. A single-threaded event loop is
// deterministic, so each participant first yields a number of microtask
// turns drawn from a generator seeded by the iteration: the start order
// varies across iterations the way a thread scheduler's would, and a failing
// iteration replays exactly.

import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";

import { protocolClaimIDV2 } from "../../src/challenge_claim_v2.js";
import { claimProofBundleV2, type ClaimStoreV2, type V2ChallengeClaim, type V2ClaimResult } from "../../src/claim_store_v2.js";
import { errorIs, v2ErrorClassOf } from "../../src/errors_v2.js";
import { recoverInterruptedClaimV2 } from "../../src/evaluation_progress_v2.js";
import { decodeProofBundleV2 } from "../../src/protocol_v2_wire.js";
import { releaseV2Decision, type CommittedV2Outcome, type V2ReleaseConfig } from "../../src/release_v2.js";
import { decodeVerificationReceiptBodyV2, decodeVerificationReceiptV2, verificationReceiptV2Digest } from "../../src/verification_receipt_v2.js";
import { verifyProofBundleV2, type V2VerifyCallbacks, type V2VerifyOutcome, type V2VerifyRequest } from "../../src/verify_v2.js";
import { preflightProofBundleV2 } from "../../src/verify_v2_preflight.js";
import { ErrHeadOfLineBlockedTestOnly, StoreTestOnly } from "../../src/v2reference/store.js";
import type { HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { type Any, corpusKeyPairs, load, unb64 } from "./helpers.js";
import { buildVerifyRequest, zeroCounts } from "./verify_harness.js";
import { checkCommitted } from "./release_checks.js";

const file = load("concurrency-scenarios.json");
const inputs = load(file.inputs);

/** The most microtask turns a participant yields before it starts. */
const MAX_START_JITTER = 8;

/**
 * Records the evaluator owner token a claim store returns to the creator, so
 * a finalize participant can call the store directly (as in
 * lifecycle_scenarios.test.ts).
 */
function ownerCapturing(inner: ClaimStoreV2): { store: ClaimStoreV2; owner: () => Uint8Array | null } {
  let owner: Uint8Array | null = null;
  const store = new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === "claimV2") {
        return async (claim: V2ChallengeClaim, signal?: AbortSignal): Promise<V2ClaimResult> => {
          const result = await target.claimV2(claim, signal);
          owner = result.ownerToken === null ? null : Uint8Array.from(result.ownerToken);
          return result;
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { store, owner: () => owner };
}

/** A small seeded generator (mulberry32), so an iteration's jitter replays. */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const yieldTurns = async (n: number) => {
  for (let i = 0; i < n; i++) await null;
};

const errorLabel = (err: unknown) => `error/${v2ErrorClassOf(err)}`;

/**
 * The default iteration count. Every participant verifies hybrid signatures
 * on the one JavaScript thread, so one iteration of all scenarios takes about
 * 6 s; the file's default_iterations (20) would add about two minutes to
 * `npm test`. Set RATIFY_RACE_ITERATIONS=20 to run the file's count.
 */
const TS_DEFAULT_ITERATIONS = 3;

function raceIterations(fileDefault: number): number {
  const s = process.env.RATIFY_RACE_ITERATIONS;
  if (s === undefined || s === "") return Math.min(fileDefault, TS_DEFAULT_ITERATIONS);
  const n = Number(s);
  assert.ok(Number.isInteger(n) && n >= 1, `RATIFY_RACE_ITERATIONS=${JSON.stringify(s)} is not a positive integer`);
  return n;
}

/** The state of one iteration of one scenario. */
class RaceIteration {
  readonly committed = new Map<string, CommittedV2Outcome>();
  readonly receipts = new Map<string, Uint8Array>();
  readonly owners = new Map<string, Uint8Array | null>();
  readonly recorded = new Map<string, Uint8Array>(); // claim ID -> committed receipt body
  readonly recordedAt: string[] = []; // claim IDs in first-recorded order

  constructor(readonly store: StoreTestOnly, readonly verifier: HybridKeyPairV2, readonly rateStore: boolean) {}

  claimStore(): ClaimStoreV2 {
    return this.rateStore ? this.store.withRateAtFinalization() : this.store;
  }

  /** The protocol claim ID of request's expected challenge, claimed or not. */
  claimID(request: string): string {
    const e = inputs.requests[request].expected_challenge;
    return protocolClaimIDV2(e.verifier_namespace, e.replay_epoch, unb64(e.value_b64));
  }

  record(claimID: string, body: Uint8Array): void {
    if (!this.recorded.has(claimID)) {
      this.recorded.set(claimID, Uint8Array.from(body));
      this.recordedAt.push(claimID);
    }
  }

  recordOutcome(request: string, c: CommittedV2Outcome): void {
    this.committed.set(request, c);
    this.record(c.claimID(), c.receiptBody());
  }

  /** Builds one verification of name at the current store clock, before any participant starts. */
  async prepareVerify(name: string): Promise<{ req: V2VerifyRequest; cb: V2VerifyCallbacks }> {
    const request = inputs.requests[name];
    const { req, cb } = await buildVerifyRequest({ ...request, now: this.store.now() }, unb64(inputs.bundles_b64[request.bundle]), zeroCounts());
    const cs = this.claimStore();
    const callbacks: V2VerifyCallbacks = { ...cb, claimStore: cs };
    if (this.rateStore) callbacks.rate = cs as never;
    return { req, cb: callbacks };
  }

  async verifyLabel(name: string, req: V2VerifyRequest, cb: V2VerifyCallbacks, signal?: AbortSignal): Promise<{ label: string; outcome: V2VerifyOutcome }> {
    const outcome = await verifyProofBundleV2(req, cb, { signal });
    switch (outcome.stage) {
      case "committed": {
        this.recordOutcome(name, outcome.committed!);
        const body = decodeVerificationReceiptBodyV2(outcome.committed!.receiptBody());
        return { label: `committed/${body.decision}/${body.decision_reason}`, outcome };
      }
      case "replay":
        return { label: `replay/${outcome.disposition}`, outcome };
      default:
        return { label: `${outcome.stage}/${outcome.errorClass}`, outcome };
    }
  }

  async releaseLabel(request: string): Promise<string> {
    const config: V2ReleaseConfig = { verifierPublicKey: this.verifier.publicKey, logID: inputs.log_id, claimStore: this.store, checkpoint: this.store };
    const result = await releaseV2Decision(this.committed.get(request)!, this.receipts.get(request) ?? null, config);
    if (result.status !== "released") return `${result.status}/${result.reason}`;
    const d = result.decision!;
    return `released/${d.decision()}/${d.releaseTime()}/${d.receipt().sequence}`;
  }

  /** Preflights and claims request without evaluating. */
  async claimOnly(name: string, claimStore: ClaimStoreV2) {
    const request = inputs.requests[name];
    const bundle = decodeProofBundleV2(unb64(inputs.bundles_b64[request.bundle]));
    const now = this.store.now();
    const { req } = await buildVerifyRequest(request, new Uint8Array(0), zeroCounts());
    const pre = await preflightProofBundleV2(bundle, req.expected, req.contextPolicy, req.requiredScope, req.verifierNamespace, req.replayEpoch, req.verifierID, now, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
    return { claim: () => claimProofBundleV2(claimStore, bundle, pre, req.verifierNamespace, req.replayEpoch, now) };
  }

  /** Runs one setup or after step; want overrides step.expect. */
  async step(i: number, s: Any, want: Any): Promise<void> {
    switch (s.op) {
      case "set_time":
        this.store.setTime(s.time);
        break;
      case "set_ack_withheld":
        this.store.setAcknowledgementWithheld(s.withheld);
        break;
      case "verify": {
        const { req, cb } = await this.prepareVerify(s.request);
        const { outcome } = await this.verifyLabel(s.request, req, cb);
        assert.equal(outcome.stage, want.stage, `step ${i} verify ${s.request} stage (${outcome.errorClass}: ${outcome.error?.message})`);
        assert.equal(outcome.errorClass, want.error_class ?? "", `step ${i} verify ${s.request} class (${outcome.error?.message})`);
        if (want.disposition) assert.equal(outcome.disposition, want.disposition, `step ${i} verify ${s.request} disposition`);
        if (outcome.stage === "committed") checkCommitted(i, outcome.committed!, want);
        break;
      }
      case "claim_only": {
        const capturing = ownerCapturing(this.claimStore());
        const { claim } = await this.claimOnly(s.request, capturing.store);
        let claimID = "";
        let disposition = "";
        let cls = "";
        try {
          const out = await claim();
          claimID = out.claim.claimID;
          disposition = out.disposition;
          this.owners.set(s.request, capturing.owner());
        } catch (err) {
          cls = v2ErrorClassOf(err);
        }
        assert.equal(cls, want.error_class ?? "", `step ${i} claim_only class`);
        assert.equal(disposition, want.disposition ?? "", `step ${i} claim_only disposition`);
        if (!cls) assert.equal(claimID, this.claimID(s.request), `step ${i} claim_only: claim ID is not the request's protocol claim ID`);
        break;
      }
      case "recover": {
        let outcome: CommittedV2Outcome;
        try {
          outcome = await recoverInterruptedClaimV2(this.store, this.claimID(s.request));
        } catch (err) {
          if (!want.error_class) throw err;
          assert.equal(v2ErrorClassOf(err), want.error_class, `step ${i} recover class (${(err as Error).message})`);
          return;
        }
        assert.equal(want.error_class ?? "", "", `step ${i} recover succeeded, want ${want.error_class}`);
        checkCommitted(i, outcome, want);
        this.recordOutcome(s.request, outcome);
        break;
      }
      case "publish": {
        const c = this.committed.get(s.request)!;
        const wire = await this.store.publishV2Receipt(c.claimID(), c.receiptBody());
        assert.equal(decodeVerificationReceiptV2(wire).sequence, want.receipt_sequence, `step ${i} publish sequence`);
        this.receipts.set(s.request, wire);
        break;
      }
      case "release": {
        const wantLabel = want.release_status === "released"
          ? `released/${want.decision}/${want.release_time}/${want.receipt_sequence}`
          : `${want.release_status}/${want.release_reason}`;
        assert.equal(await this.releaseLabel(s.request), wantLabel, `step ${i} release`);
        break;
      }
      default:
        throw new Error(`step ${i}: op ${s.op} is not a concurrency setup or after step`);
    }
  }

  /** Runs one participant's operation and returns its label; prepared runs a verify participant built before the start. */
  async participant(p: Any, prepared: (() => Promise<string>) | null): Promise<string> {
    switch (p.op) {
      case "verify":
        return prepared!();
      case "claim_only": {
        let claim;
        try {
          ({ claim } = await this.claimOnly(p.request, this.claimStore()));
        } catch (err) {
          return `preflight/${v2ErrorClassOf(err)}`;
        }
        try {
          return (await claim()).disposition;
        } catch (err) {
          return errorLabel(err);
        }
      }
      case "finalize":
      case "recover_direct": {
        const claimID = this.claimID(p.request);
        const body = unb64(p.body_b64);
        let ok: boolean;
        try {
          ok = p.op === "finalize"
            ? await this.claimStore().finalizeV2Claim(claimID, this.owners.get(p.request) ?? new Uint8Array(0), unb64(p.terminal_b64), body, p.allow_valid_until ?? 0)
            : await this.claimStore().recoverInterruptedV2Claim(claimID, unb64(p.terminal_b64), body);
        } catch (err) {
          return errorLabel(err);
        }
        if (!ok) return "identical";
        this.record(claimID, body);
        return "committed";
      }
      case "recover": {
        let outcome: CommittedV2Outcome;
        try {
          outcome = await recoverInterruptedClaimV2(this.store, this.claimID(p.request));
        } catch (err) {
          return errorLabel(err);
        }
        this.recordOutcome(p.request, outcome);
        const body = decodeVerificationReceiptBodyV2(outcome.receiptBody());
        return `committed/${body.decision}/${body.decision_reason}`;
      }
      case "release":
        return this.releaseLabel(p.request);
      case "acknowledge": {
        const receipt = decodeVerificationReceiptV2(this.receipts.get(p.request)!);
        const entry = verificationReceiptV2Digest(receipt);
        try {
          const ack = await this.store.acknowledgeV2Receipt(receipt.log_id, receipt.sequence, receipt.previous_receipt_hash, entry);
          return `acknowledged/${ack.timestamp}`;
        } catch {
          return "refused";
        }
      }
      case "set_time":
        this.store.setTime(p.time);
        return "done";
    }
    return `unknown op ${p.op}`;
  }

  /** Publishes every recorded result, retrying entries blocked behind an earlier one, and requires sequences 1..k. */
  async receiptLogContiguous(): Promise<void> {
    const published = new Map<string, Uint8Array>();
    for (let progress = true; progress;) {
      progress = false;
      for (const claimID of this.recordedAt) {
        if (published.has(claimID)) continue;
        let wire: Uint8Array;
        try {
          wire = await this.store.publishV2Receipt(claimID, this.recorded.get(claimID)!);
        } catch (err) {
          if (errorIs(err, ErrHeadOfLineBlockedTestOnly)) continue;
          throw new Error(`publish ${claimID}: ${(err as Error).message}`);
        }
        published.set(claimID, wire);
        progress = true;
      }
    }
    const sequences: number[] = [];
    for (const claimID of this.recordedAt) {
      const wire = published.get(claimID);
      if (!wire) throw new Error(`claim ${claimID} never published (head of line blocked)`);
      const again = await this.store.publishV2Receipt(claimID, this.recorded.get(claimID)!);
      assert.deepEqual(again, wire, `claim ${claimID} republished differently`);
      sequences.push(decodeVerificationReceiptV2(wire).sequence);
    }
    sequences.sort((a, b) => a - b);
    assert.ok(sequences.every((seq, i) => seq === i + 1), `receipt sequences ${sequences}, want 1..${sequences.length}`);
  }
}

function checkInvariant(inv: Any, labels: Map<string, string[]>, all: string[]): void {
  const of = (groups: string[] | undefined) => (groups && groups.length > 0 ? groups.flatMap((g) => labels.get(g) ?? []) : all);
  switch (inv.kind) {
    case "allowed":
      for (const l of of(inv.groups)) assert.ok(inv.outcomes.includes(l), `outcome ${l} of ${inv.groups ?? "all"} is not one of ${inv.outcomes}`);
      break;
    case "count": {
      const n = of(inv.groups).filter((l) => inv.outcomes.includes(l)).length;
      assert.ok((inv.equals === undefined || n === inv.equals) && (inv.at_most === undefined || n <= inv.at_most),
        `${n} outcomes of ${inv.groups ?? "all"} are in ${inv.outcomes}, want equals ${inv.equals} at most ${inv.at_most}`);
      break;
    }
    case "all_equal": {
      const got = of(inv.groups);
      assert.ok(got.every((l) => l === got[0]), `outcomes of ${inv.groups} differ: ${got}`);
      break;
    }
    case "one_winner": {
      const winners = Object.keys(inv.by_group).filter((g) => (labels.get(g) ?? []).some((l) => inv.winning.includes(l)));
      assert.ok(winners.length <= 1, `winning groups ${winners}, want at most one`);
      for (const [g, rule] of Object.entries(inv.by_group) as [string, Any][]) {
        const want: string[] = winners.includes(g) ? rule.if_winner : rule.if_loser;
        for (const l of labels.get(g) ?? []) assert.ok(want.includes(l), `group ${g} (winners ${winners}) has outcome ${l}, not one of ${want}`);
      }
      break;
    }
    default:
      throw new Error(`unknown invariant kind ${inv.kind}`);
  }
}

/** Times one uncancelled verification of the request that group target verifies, on a scratch store (ms). */
async function measureVerification(verifier: HybridKeyPairV2, sc: Any, target: string): Promise<number> {
  const p = (sc.participants as Any[]).find((q) => q.group === target && q.op === "verify");
  assert.ok(p, `cancel target ${target} has no verify participant`);
  const it = new RaceIteration(new StoreTestOnly(sc.start_time, inputs.lease_seconds, inputs.log_id, verifier), verifier, sc.rate_at_finalization === true);
  const { req, cb } = await it.prepareVerify(p.request);
  const began = performance.now();
  await it.verifyLabel(p.request, req, cb);
  return performance.now() - began;
}

test("concurrency-scenarios.json: corpus shape", () => {
  assert.equal(file.version, 1);
  assert.equal(file.inputs, "lifecycle-scenarios.json");
  assert.ok(file.scenarios.length > 0);
});

const iterations = raceIterations(file.default_iterations);

for (const sc of file.scenarios as Any[]) {
  test(`concurrency: ${sc.name}`, async (t: TestContext) => {
    const verifier = (await corpusKeyPairs()).get(inputs.verifier_key)!;
    // seen counts each distinct outcome per group across iterations, logged
    // so a run shows which interleavings occurred.
    const seen = new Map<string, number>();
    // span is the duration of one uncancelled verification of a cancel
    // target, measured once on a scratch store.
    let span = 0;
    try {
      for (let iter = 0; iter < iterations; iter++) {
        const store = new StoreTestOnly(sc.start_time, inputs.lease_seconds, inputs.log_id, verifier);
        const it = new RaceIteration(store, verifier, sc.rate_at_finalization === true);
        for (const [i, s] of (sc.setup as Any[]).entries()) await it.step(i, s, s.expect ?? {});
        // Prepare every participant before any starts, then start them together.
        const slots: { group: string; run: () => Promise<string> }[] = [];
        const controllers = new Map<string, AbortController[]>();
        for (const p of sc.participants as Any[]) {
          for (let n = 0; n < p.count; n++) {
            let prepared: (() => Promise<string>) | null = null;
            if (p.op === "verify") {
              const { req, cb } = await it.prepareVerify(p.request);
              const controller = new AbortController();
              controllers.set(p.group, [...(controllers.get(p.group) ?? []), controller]);
              prepared = async () => (await it.verifyLabel(p.request, req, cb, controller.signal)).label;
            }
            let run = () => it.participant(p, prepared);
            if (p.op === "cancel") {
              // Spread the signal over the target's verification across
              // iterations: 0 to 1.2 times its duration, in tenths (Go
              // iter % 13; fewer than 13 iterations spread over the range).
              if (span === 0) span = await measureVerification(verifier, sc, p.target);
              const tenths = iterations >= 13 ? iter % 13 : Math.floor((iter * 12) / Math.max(iterations - 1, 1));
              const delay = (span * tenths) / 10;
              run = async () => {
                if (delay > 0) await sleep(delay);
                for (const controller of controllers.get(p.target) ?? []) controller.abort();
                return "done";
              };
            }
            slots.push({ group: p.group, run });
          }
        }
        const random = seeded(iter);
        const jitter = slots.map(() => (iter === 0 ? 0 : Math.floor(random() * (MAX_START_JITTER + 1))));
        const results = await Promise.all(slots.map(async (s, k) => {
          await yieldTurns(jitter[k]!);
          return s.run();
        }));
        for (const list of controllers.values()) for (const controller of list) controller.abort();
        const labels = new Map<string, string[]>();
        const all: string[] = [];
        slots.forEach((s, k) => {
          labels.set(s.group, [...(labels.get(s.group) ?? []), results[k]!]);
          all.push(results[k]!);
          const key = `${s.group}:${results[k]}`;
          seen.set(key, (seen.get(key) ?? 0) + 1);
        });
        const context = `iteration ${iter} (start jitter ${jitter}), outcomes ${JSON.stringify(Object.fromEntries(labels))}`;
        for (const inv of sc.invariants as Any[]) {
          try {
            if (inv.kind === "receipt_log_contiguous") await it.receiptLogContiguous();
            else checkInvariant(inv, labels, all);
          } catch (err) {
            throw new Error(`${context}: invariant ${inv.kind}: ${(err as Error).message}`, { cause: err });
          }
        }
        for (const [i, s] of (sc.after as Any[]).entries()) {
          let want = s.expect ?? {};
          const b = s.expect_by_outcome;
          if (b) {
            const got = labels.get(b.group) ?? [];
            assert.equal(got.length, 1, `${context}: expect_by_outcome group ${b.group} has ${got.length} participants`);
            want = b.cases[got[0]!];
            assert.ok(want, `${context}: after step ${i}: no case for outcome ${got[0]}`);
          }
          try {
            await it.step(i, s, want);
          } catch (err) {
            throw new Error(`${context}: after step ${i}: ${(err as Error).message}`, { cause: err });
          }
        }
      }
    } finally {
      const outcomes = [...seen.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, n]) => `${k}=${n}`);
      t.diagnostic(`${iterations} iterations${span > 0 ? `, cancel span ${span.toFixed(1)} ms` : ""}, outcomes ${outcomes.join(" ")}`);
    }
  });
}
