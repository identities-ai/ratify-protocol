// TypeScript side of scripts/wire-transport-check.sh — direct TS <-> Python
// wire-transport verification against the fixture corpus.
//
// Usage (from sdks/typescript, with dev dependencies installed):
//   node --import tsx/esm scripts/wire-transport-check.ts encode <out.json>
//     Walk testvectors/v1, encode every ProofBundle and SessionToken with
//     the TS codec, and write {"bundles":[{name,encoded}],"tokens":[...]}.
//   node --import tsx/esm scripts/wire-transport-check.ts check <in.json>
//     Read documents encoded by another SDK, decode and re-encode each with
//     the TS codec, and byte-compare. Non-zero exit on any drift.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decodeProofBundle,
  decodeSessionToken,
  encodeProofBundle,
  encodeSessionToken,
} from "../src/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = join(__dirname, "..", "..", "..", "testvectors", "v1");

interface Entry {
  name: string;
  encoded: string;
}

interface Doc {
  bundles: Entry[];
  tokens: Entry[];
}

function assertCorpusSize(bundles: number, tokens: number): void {
  if (bundles < 40 || tokens < 5) {
    throw new Error(
      `wire-transport-check: corpus too small (${bundles} bundles, ${tokens} tokens) — fixture walk broken?`,
    );
  }
}

function collect(): Doc {
  const bundles: Entry[] = [];
  const tokens: Entry[] = [];
  const addBundle = (name: string, raw: unknown) => {
    bundles.push({
      name,
      encoded: encodeProofBundle(decodeProofBundle(JSON.stringify(raw))),
    });
  };
  for (const file of readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".json")).sort()) {
    const fx = JSON.parse(readFileSync(join(FIXTURE_DIR, file), "utf8"));
    if (file === "cross_sdk_vectors.json") {
      for (const v of fx.vectors) {
        if (v.kind === "bundle_hash") addBundle(`${file}:${v.name}`, v.input.bundle);
      }
      continue;
    }
    if (fx.bundle) addBundle(file, fx.bundle);
    if (fx.session_token?.token) {
      tokens.push({
        name: file,
        encoded: encodeSessionToken(
          decodeSessionToken(JSON.stringify(fx.session_token.token)),
        ),
      });
    }
    fx.transaction_receipt?.parties?.forEach(
      (p: { proof_bundle: unknown }, i: number) =>
        addBundle(`${file}:party[${i}]`, p.proof_bundle),
    );
  }
  assertCorpusSize(bundles.length, tokens.length);
  return { bundles, tokens };
}

const [mode, file] = process.argv.slice(2);

if (mode === "encode" && file) {
  const doc = collect();
  writeFileSync(file, JSON.stringify(doc));
  console.log(`ts-encode: ${doc.bundles.length} bundles, ${doc.tokens.length} tokens`);
} else if (mode === "check" && file) {
  const doc = JSON.parse(readFileSync(file, "utf8")) as Doc;
  assertCorpusSize(doc.bundles.length, doc.tokens.length);
  const drifted: string[] = [];
  for (const e of doc.bundles) {
    if (encodeProofBundle(decodeProofBundle(e.encoded)) !== e.encoded) {
      drifted.push(`bundle ${e.name}`);
    }
  }
  for (const e of doc.tokens) {
    if (encodeSessionToken(decodeSessionToken(e.encoded)) !== e.encoded) {
      drifted.push(`token ${e.name}`);
    }
  }
  if (drifted.length > 0) {
    for (const d of drifted) console.error(`wire-transport drift: ${d}`);
    process.exit(1);
  }
  console.log(
    `ts-check: ${doc.bundles.length} bundles, ${doc.tokens.length} tokens byte-identical`,
  );
} else {
  console.error("usage: wire-transport-check.ts <encode|check> <file>");
  process.exit(2);
}
