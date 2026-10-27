// testvectors/v2/cross-sdk/*.json: verifies every cross-SDK fixture present
// (SPEC-v2 §8.1), including this SDK's own, replays every fixture's verifier
// and release scenarios, and checks that a freshly generated TypeScript
// fixture verifies.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { generateCrossSDKFixture } from "../../scripts/generate-cross-sdk-v2.js";
import { CROSS_SCENARIO_NAMES, hasCrossScenarios, verifyCrossScenarios, verifyCrossSDKFixture } from "./cross_sdk_procedure.js";
import { type Any, VECTOR_DIR } from "./helpers.js";

const dir = join(VECTOR_DIR, "cross-sdk");
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

test("cross-sdk: the directory holds exactly the five <sdk>.json fixtures", () => {
  const all = readdirSync(dir);
  assert.deepEqual(all.filter((f) => !/^(go|typescript|python|rust|c)\.json$/.test(f)), []);
  assert.ok(files.includes("typescript.json"), "run npm run generate:cross-sdk");
  assert.deepEqual(files, ["c.json", "go.json", "python.json", "rust.json", "typescript.json"]);
});

for (const name of files) {
  test(`cross-sdk: ${name} verifies`, async () => {
    const f = JSON.parse(readFileSync(join(dir, name), "utf8"));
    const n = await verifyCrossSDKFixture(f, name.slice(0, -".json".length));
    assert.ok(n >= 15, `${name}: ${n} objects`);
  });
}

for (const name of files) {
  test(`cross-sdk: ${name} scenarios replay`, async () => {
    const f = JSON.parse(readFileSync(join(dir, name), "utf8"));
    assert.ok(hasCrossScenarios(f), `${name} has no verifier and release scenarios (SPEC-v2 §8.1)`);
    assert.equal(await verifyCrossScenarios(f), CROSS_SCENARIO_NAMES.length);
  });
}

test("cross-sdk: a freshly generated TypeScript fixture verifies and replays", async () => {
  const fixture = JSON.parse(JSON.stringify(await generateCrossSDKFixture("2.0.0-beta.1", "test")));
  assert.equal(await verifyCrossSDKFixture(fixture, "typescript"), 15);
  assert.equal(await verifyCrossScenarios(fixture), CROSS_SCENARIO_NAMES.length);
});

test("cross-sdk: scenario replay rejects a changed expectation, a foreign receipt, and a missing scenario", async () => {
  const data = JSON.stringify(await generateCrossSDKFixture("2.0.0-beta.1", "test"));
  const other: Any = await generateCrossSDKFixture("2.0.0-beta.1", "test");
  const check = async (what: string, edit: (f: Any) => void, want: string) => {
    const f = JSON.parse(data);
    edit(f);
    await assert.rejects(verifyCrossScenarios(f), (err: Error) => err.message.includes(want), what);
  };
  await check("release status", (f) => { f.scenarios[3].expected.release.status = "released"; }, "allow_withheld_past_horizon");
  await check("foreign receipt", (f) => { f.scenarios[0].expected.signed_receipt_b64 = other.scenarios[0].expected.signed_receipt_b64; }, "allow_released");
  await check("receipt body", (f) => { f.scenarios[1].expected.receipt_body_b64 = f.scenarios[0].expected.receipt_body_b64; }, "deny_revoked_released");
  await check("missing scenario", (f) => { f.scenarios = f.scenarios.slice(0, 3); }, "missing scenario");
  await check("configuration", (f) => { f.scenario_configuration.lease_seconds = 31; }, "scenario_configuration");
});
