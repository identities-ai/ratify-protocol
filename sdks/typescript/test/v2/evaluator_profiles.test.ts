// testvectors/v2/evaluator-profiles.json: the two standard extension
// evaluator profiles (SPEC-v2 §5.2). The profile digest only names the
// profile; these outcomes are what make two SDKs' implementations of one
// standard profile interchangeable. Port of
// evaluator_profiles_v2_conformance_test.go, plus registry and runner
// semantics (timeouts, throws, invalid outputs, horizons).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  CONSTRAINT_MAX_COUNT_V2,
  PROFILE_ALLOWED_VALUES_V2,
  PROFILE_MAX_COUNT_V2,
  constraintProfileDigestV2,
  newConstraintEvaluatorRegistryV2,
  runConstraintEvaluatorV2,
  snapshotConstraintEvaluatorsV2,
  standardAllowedValuesEvaluatorV2,
  standardMaxCountEvaluatorV2,
  validConstraintEvaluatorRefsV2,
  validExtensionTypeV2,
  validProfileIDV2,
  validateV2ExtensionContext,
  type ConstraintEvaluationInputV2,
  type ConstraintEvaluationResultV2,
  type ConstraintEvaluatorRegistrationV2,
} from "../../src/constraint_evaluator_v2.js";
import { ConstraintUnverifiableError, decodeConstraintNodeV2, type ConstraintContextV2 } from "../../src/constraints_v2.js";
import { v2ErrorClassOf } from "../../src/errors_v2.js";
import { canonicalJSONV2, parseJSONV2 } from "../../src/json_v2.js";
import type { ProofBundleV2 } from "../../src/protocol_v2_wire.js";
import { load, type Any } from "./helpers.js";

const file = load("evaluator-profiles.json");

function contextOf(c: Any): ConstraintContextV2 {
  return {
    extensionCounts: c?.extension_counts ? new Map(Object.entries(c.extension_counts) as [string, number][]) : undefined,
    extensionValues: c?.extension_values ? new Map(Object.entries(c.extension_values) as [string, string][]) : undefined,
  };
}

const standard: Record<string, ConstraintEvaluatorRegistrationV2> = {
  [PROFILE_MAX_COUNT_V2]: standardMaxCountEvaluatorV2(),
  [PROFILE_ALLOWED_VALUES_V2]: standardAllowedValuesEvaluatorV2(),
};

test("evaluator-profiles.json: file shape", () => {
  assert.equal(file.version, 1);
  assert.equal(file.profiles.length, 2);
  assert.ok(file.context_bounds.length > 0);
});

for (const suite of file.profiles) {
  const registration = standard[suite.profile];
  test(`evaluator-profiles.json: ${suite.profile} descriptor digest`, () => {
    assert.ok(registration, `unknown standard profile ${suite.profile}`);
    assert.equal(registration.descriptor.type, suite.type);
    assert.equal(constraintProfileDigestV2(registration.descriptor), suite.profile_digest);
  });
  const outcomes: Record<string, number> = {};
  for (const c of suite.cases) {
    outcomes[c.outcome] = (outcomes[c.outcome] ?? 0) + 1;
    test(`evaluator-profiles.json: ${suite.profile}/${c.name}`, async () => {
      let params: Uint8Array | null = null;
      if (!c.params_absent) {
        assert.ok("params" in c, "case has neither params nor params_absent");
        params = canonicalJSONV2(c.params);
        // SPEC-v2 §5.2: a certificate can carry these params only when they
        // are a JSON object; direct_api_only says not.
        const carried = new TextEncoder().encode(`{"params":${new TextDecoder().decode(params)},"type":${JSON.stringify(suite.type)}}`);
        let wireErr: unknown = null;
        try {
          decodeConstraintNodeV2(parseJSONV2(carried));
        } catch (err) {
          wireErr = err;
        }
        assert.equal(wireErr !== null, c.direct_api_only === true,
          `direct_api_only ${c.direct_api_only === true}, but a certificate constraint with these params decodes with error ${(wireErr as Error)?.message}`);
      }
      const ctx = contextOf(c.context);
      validateV2ExtensionContext(ctx);
      const result = await registration!.evaluate({
        type: registration!.descriptor.type, paramsJSON: params, delegationIndex: 0, constraintIndex: 0,
        certID: "cert-1", issuerID: "issuer-1", context: ctx, evaluationTime: 1000,
      }, new AbortController().signal);
      assert.equal(result.outcome, c.outcome, result.detail);
      assert.equal(result.validUntil ?? 0, 0);
    });
  }
  test(`evaluator-profiles.json: ${suite.profile} covers every outcome`, () => {
    assert.ok(outcomes.pass && outcomes.denied && outcomes.unverifiable, JSON.stringify(outcomes));
  });
}

for (const c of file.context_bounds) {
  test(`evaluator-profiles.json: context_bounds/${c.name}`, () => {
    let cls = "";
    try {
      validateV2ExtensionContext(contextOf(c.context));
    } catch (err) {
      cls = v2ErrorClassOf(err);
    }
    assert.equal(cls, c.error_class ?? "");
  });
}

// ---------------------------------------------------------------------------
// Registry and runner semantics (Go constraint_evaluator_v2 unit behavior).

const input = (over: Partial<ConstraintEvaluationInputV2> = {}): ConstraintEvaluationInputV2 => ({
  type: "com.example.ext.limit", paramsJSON: null, delegationIndex: 0, constraintIndex: 0, issuerID: "i", certID: "c",
  context: {}, evaluationTime: 1000, ...over,
});
const entryFor = (evaluate: (i: ConstraintEvaluationInputV2, s: AbortSignal) => ConstraintEvaluationResultV2 | Promise<ConstraintEvaluationResultV2>) => {
  const registry = newConstraintEvaluatorRegistryV2(50, { descriptor: { profile: "com.example.limit/v1", type: "com.example.ext.limit" }, evaluate });
  const bundle = { delegations: [{ constraints: [{ type: "com.example.ext.limit" }] }] } as unknown as ProofBundleV2;
  const snap = snapshotConstraintEvaluatorsV2(registry, bundle);
  return { entry: snap.evaluators.get("com.example.ext.limit")!, timeout: snap.timeoutMs, refs: snap.refs };
};

async function outcomeOf(p: Promise<number>): Promise<string> {
  try {
    return `pass:${await p}`;
  } catch (err) {
    return err instanceof ConstraintUnverifiableError ? "unverifiable" : "denied";
  }
}

test("evaluator registry: configuration bounds are configuration_invalid", () => {
  const ok = standardMaxCountEvaluatorV2();
  const cls = (fn: () => unknown) => {
    try {
      fn();
      return "";
    } catch (err) {
      return v2ErrorClassOf(err);
    }
  };
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(0, ok)), "configuration_invalid");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(10_001, ok)), "configuration_invalid");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(10_000, ok)), "");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(100, ok, ok)), "configuration_invalid");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(100, { descriptor: { profile: "x/v1", type: "time_window" }, evaluate: ok.evaluate })), "configuration_invalid");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(100, { descriptor: { profile: "x/v01", type: "com.a.b" }, evaluate: ok.evaluate })), "configuration_invalid");
  const many = Array.from({ length: 33 }, (_, i) => ({ descriptor: { profile: "p/v1", type: `com.a.t${i}` }, evaluate: ok.evaluate }));
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(100, ...many)), "configuration_invalid");
  assert.equal(cls(() => newConstraintEvaluatorRegistryV2(100, ...many.slice(0, 32))), "");
});

test("evaluator registry: type and profile identifier rules", () => {
  for (const t of ["time_window", "max_rate", "ratify.receiver_audience", "geo_circle", "a.b", "ratify.x.y", "com.A.b", "com..b", ""]) {
    assert.equal(validExtensionTypeV2(t), false, t);
  }
  assert.equal(validExtensionTypeV2("com.ratifyprotocol.max_count"), true);
  assert.equal(validExtensionTypeV2("a.b." + "c".repeat(124)), true);
  assert.equal(validExtensionTypeV2("a.b." + "c".repeat(125)), false);
  for (const id of ["x/v0", "x/v01", "x", "/v1", "X/v1", "x/v1/v2", "x/v1a"]) assert.equal(validProfileIDV2(id), false, id);
  for (const id of ["x/v1", "com.example.p/v12"]) assert.equal(validProfileIDV2(id), true, id);
});

test("evaluator snapshot: only chain types are sealed, sorted by type", () => {
  const registry = newConstraintEvaluatorRegistryV2(100, standardAllowedValuesEvaluatorV2(), standardMaxCountEvaluatorV2());
  assert.deepEqual(registry.refs().map((r) => r.type), ["com.ratifyprotocol.allowed_values", "com.ratifyprotocol.max_count"]);
  const bundle = { delegations: [{ constraints: [{ type: CONSTRAINT_MAX_COUNT_V2 }, { type: "max_rate" }] }] } as unknown as ProofBundleV2;
  const snap = snapshotConstraintEvaluatorsV2(registry, bundle);
  assert.deepEqual(snap.refs.map((r) => r.type), [CONSTRAINT_MAX_COUNT_V2]);
  assert.ok(validConstraintEvaluatorRefsV2(snap.refs));
  assert.equal(snapshotConstraintEvaluatorsV2(null, bundle).refs.length, 0);
  assert.equal(snapshotConstraintEvaluatorsV2(registry, { delegations: [] } as unknown as ProofBundleV2).refs.length, 0);
  assert.equal(validConstraintEvaluatorRefsV2([...snap.refs, ...snap.refs]), false);
});

test("evaluator runner: outcomes, horizons, failures, timeout", async () => {
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "pass" })).entry, 50, input())), "pass:0");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "pass", validUntil: 1001 })).entry, 50, input())), "pass:1001");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "pass", validUntil: 9e12 })).entry, 50, input())), "pass:253402300799");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "pass", validUntil: 1000 })).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "denied" })).entry, 50, input())), "denied");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "denied", validUntil: 2000 })).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "unverifiable" })).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "unverifiable", validUntil: 2000 })).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => ({ outcome: "maybe" as "pass" })).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => {
    throw new Error("boom");
  }).entry, 50, input())), "unverifiable");
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(entryFor(() => Promise.reject(new Error("no"))).entry, 50, input())), "unverifiable");
  let aborted = false;
  const slow = entryFor((_i, signal) => new Promise((resolve) => {
    signal.addEventListener("abort", () => {
      aborted = true;
    });
    setTimeout(() => resolve({ outcome: "pass" }), 500);
  }));
  assert.equal(await outcomeOf(runConstraintEvaluatorV2(slow.entry, slow.timeout, input())), "unverifiable");
  assert.ok(aborted, "the evaluator signal is aborted at the timeout");
});
