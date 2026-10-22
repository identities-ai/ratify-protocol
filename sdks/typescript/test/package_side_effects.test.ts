// The package root re-exports v2 next to v1, so a v1-only application stays
// small only if bundlers may drop the modules it does not import. That
// depends on "sideEffects": false in package.json, and the declaration is
// only safe while no module relies on being imported for its side effects:
// a bundler honoring it silently drops a bare `import "./x.js"`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const here = new URL("..", import.meta.url).pathname;

test("package.json lets bundlers drop unused modules", () => {
  const pkg = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
  assert.equal(pkg.sideEffects, false);
});

test("no source module is imported only for its side effects", () => {
  const files = (dir: string): string[] =>
    readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
      e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".ts") ? [join(dir, e.name)] : [],
    );
  for (const file of files(join(here, "src"))) {
    const bare = readFileSync(file, "utf8").match(/^\s*import\s+["'][^"']+["']/m);
    assert.equal(bare, null, `${file} has a side-effect-only import: ${bare?.[0]}`);
  }
});
