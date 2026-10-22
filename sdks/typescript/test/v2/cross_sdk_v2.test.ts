// testvectors/v2/cross-sdk/*.json: verifies every cross-SDK fixture present
// (SPEC-v2 §8.1), including this SDK's own, and checks that a freshly
// generated TypeScript fixture verifies.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { generateCrossSDKFixture } from "../../scripts/generate-cross-sdk-v2.js";
import { verifyCrossSDKFixture } from "./cross_sdk_procedure.js";
import { VECTOR_DIR } from "./helpers.js";

const dir = join(VECTOR_DIR, "cross-sdk");
const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();

test("cross-sdk: the directory holds only <sdk>.json fixtures, including typescript.json", () => {
  const all = readdirSync(dir);
  assert.deepEqual(all.filter((f) => !/^(go|typescript|python|rust|c)\.json$/.test(f)), []);
  assert.ok(files.includes("typescript.json"), "run npm run generate:cross-sdk");
  assert.ok(files.includes("go.json"));
});

for (const name of files) {
  test(`cross-sdk: ${name} verifies`, async () => {
    const f = JSON.parse(readFileSync(join(dir, name), "utf8"));
    const n = await verifyCrossSDKFixture(f, name.slice(0, -".json".length));
    assert.ok(n >= 15, `${name}: ${n} objects`);
  });
}

test("cross-sdk: a freshly generated TypeScript fixture verifies", async () => {
  const fixture = await generateCrossSDKFixture("2.0.0-alpha.1", "test");
  assert.equal(await verifyCrossSDKFixture(JSON.parse(JSON.stringify(fixture)), "typescript"), 15);
});
