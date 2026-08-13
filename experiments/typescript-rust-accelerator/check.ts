import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import { decodeProofBundle, encodeProofBundle, verifyBundle } from "../../sdks/typescript/src/index.js";
import native from "./native/index.js";

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
  const result = JSON.parse(native.verifyBundleJson(JSON.stringify(fixture.bundle), JSON.stringify(options)));
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

const ts = await measure(() => verifyBundle(bundle, { required_scope: options.required_scope, now: options.now }));
const rust = await measure(() => native.verifyBundleJson(encodeProofBundle(bundle), optionsJson));
console.log(`${checked} native conformance decisions matched; malformed inputs contained`);
console.log("implementation,median_ms,p95_ms");
console.log(`typescript,${ts[0].toFixed(4)},${ts[1].toFixed(4)}`);
console.log(`rust_native_same_api,${rust[0].toFixed(4)},${rust[1].toFixed(4)}`);
console.log(`median_speedup,${(ts[0] / rust[0]).toFixed(2)}x`);
console.log(`p95_speedup,${(ts[1] / rust[1]).toFixed(2)}x`);
