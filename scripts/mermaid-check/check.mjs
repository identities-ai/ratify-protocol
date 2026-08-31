// Parse every mermaid diagram in the repository's documentation.
//
// A broken diagram is invisible in a diff and obvious to every reader: GitHub
// renders "Unable to render rich display" where the picture should be. Counting
// diagrams is not checking them, and a lint only catches the pitfalls it has
// been taught, so this runs the real parser.
//
// mermaid needs a DOM, which is what jsdom is here for. It does not need a
// browser: parse() stops before rendering.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { JSDOM } from "jsdom";

const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();

const files = execFileSync(
  "git",
  ["-C", repoRoot, "ls-files", "*.md"],
  { encoding: "utf8" },
)
  .split("\n")
  .filter(Boolean);

const dom = new JSDOM("<!doctype html><body></body>", { pretendToBeVisual: true });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", {
  value: dom.window.navigator,
  configurable: true,
});

const mermaid = (await import("mermaid")).default;
mermaid.initialize({ startOnLoad: false });

const BLOCK = /```mermaid\n([\s\S]*?)```/g;
let checked = 0;
const failures = [];

for (const relative of files) {
  const text = readFileSync(`${repoRoot}/${relative}`, "utf8");
  let match;
  let index = 0;
  while ((match = BLOCK.exec(text)) !== null) {
    index += 1;
    checked += 1;
    try {
      await mermaid.parse(match[1]);
    } catch (error) {
      const detail = String(error?.message ?? error).split("\n").slice(0, 3).join("\n      ");
      failures.push(`${relative} (diagram ${index})\n      ${detail}`);
    }
  }
}

if (failures.length > 0) {
  console.log("mermaid-parse: FAIL");
  for (const failure of failures) console.log(`  ${failure}`);
  console.log("\n  See references/REFERENCE-README-STANDARD.md");
  process.exit(1);
}

console.log(`mermaid-parse: ok (${checked} diagram(s) across ${files.length} file(s))`);
