import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import { decodeProofBundle, encodeProofBundle, verifyBundle } from "../../sdks/typescript/src/index.js";
import native from "./native/index.js";
import { nativeEligible, verifyBundle as acceleratedVerifyBundle } from "./accelerator.js";

const vectorDir = new URL("../../testvectors/v1/", import.meta.url);
let checked = 0;
for (const name of readdirSync(vectorDir).filter((name) => name.endsWith(".json")).sort()) {
  const fixture = JSON.parse(readFileSync(new URL(name, vectorDir), "utf8"));
  const expected = fixture.expected?.verify_result;
  const verifyOptions = fixture.expected?.verify_options;
  if (!fixture.bundle || !expected || !verifyOptions) continue;
  const context = fixture.verifier_context ?? {};
  const options = { ...verifyOptions, context };
  if (expected.identity_status === "revoked" && fixture.bundle.delegations.length > 1) {
    options.revoked_cert_ids = [fixture.bundle.delegations[1].cert_id];
  }
  const result = JSON.parse(await native.verifyBundleJsonAsync(JSON.stringify(fixture.bundle), JSON.stringify(options)));
  for (const field of ["valid", "identity_status", "human_id", "agent_id", "granted_scope", "error_reason"]) {
    assert.deepEqual(result[field] ?? (field === "granted_scope" ? [] : ""), expected[field] ?? (field === "granted_scope" ? [] : ""), `${name}: ${field}`);
  }
  checked++;
}

for (const [bundle, options] of [["{}", "{}"], ["not-json", "{}"], ["{}", '{"unknown":1}']]) {
  assert.throws(() => native.verifyBundleJson(bundle, options));
}

const fixture = JSON.parse(readFileSync(new URL("happy_path_depth_1.json", vectorDir), "utf8"));
const bundle = decodeProofBundle(JSON.stringify(fixture.bundle));
const options = fixture.expected.verify_options;
const optionsJson = JSON.stringify(options);
const expectedFallback = await verifyBundle(bundle, { required_scope: options.required_scope, now: options.now });
assert.deepEqual(await acceleratedVerifyBundle(bundle, { required_scope: options.required_scope, now: options.now }, undefined), expectedFallback);
assert.deepEqual(await acceleratedVerifyBundle(bundle, { required_scope: options.required_scope, now: options.now }, { verifyBundleJson() { throw new Error("load failure"); } }), expectedFallback);
for (const option of [
  { is_revoked: () => false }, { revocation: {} }, { force_revocation_check: true },
  { policy: {} }, { audit: {} }, { constraint_evaluators: {} },
  { policy_verdict: {} }, { policy_secret: new Uint8Array([1]) },
  { anchor_resolver: {} }, { challenge_store: {} },
  { context: { invocations_in_window: () => 0 } },
] as any[]) assert.equal(nativeEligible(option), false);

async function measure(call: () => unknown | Promise<unknown>, iterations = 1_000) {
  for (let i = 0; i < 50; i++) await call();
  const samples = [];
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await call();
    samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return [samples[Math.floor(samples.length / 2)], samples[Math.floor(samples.length * 0.95)]];
}

async function repeated(call: () => unknown | Promise<unknown>, rounds = 5) {
  const values = [];
  for (let i = 0; i < rounds; i++) values.push(await measure(call));
  values.sort((a, b) => a[0] - b[0]);
  const medians = values.map((v) => v[0]).sort((a, b) => a - b);
  const p95s = values.map((v) => v[1]).sort((a, b) => a - b);
  return [medians[Math.floor(rounds / 2)], p95s[Math.floor(rounds / 2)]];
}

const ts = await repeated(() => verifyBundle(bundle, { required_scope: options.required_scope, now: options.now }));
const rust = await repeated(() => native.verifyBundleJson(encodeProofBundle(bundle), optionsJson));
const rustAsync = await repeated(() => native.verifyBundleJsonAsync(encodeProofBundle(bundle), optionsJson));
console.log(`${checked} native conformance decisions matched; malformed inputs contained`);
console.log("implementation,median_ms,p95_ms");
console.log(`typescript,${ts[0].toFixed(4)},${ts[1].toFixed(4)}`);
console.log(`rust_native_same_api,${rust[0].toFixed(4)},${rust[1].toFixed(4)}`);
console.log(`rust_native_async,${rustAsync[0].toFixed(4)},${rustAsync[1].toFixed(4)}`);
console.log(`median_speedup,${(ts[0] / rustAsync[0]).toFixed(2)}x`);
console.log(`p95_speedup,${(ts[1] / rustAsync[1]).toFixed(2)}x`);
if (ts[0] / rustAsync[0] < 5 || ts[1] / rustAsync[1] < 5) throw new Error("Node native accelerator did not clear the 5x median and p95 gates");
