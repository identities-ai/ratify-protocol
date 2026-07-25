// Wire codec tests.
//
// Round-trip guarantees against the Go-generated fixtures in testvectors/v1:
// every bundle, delegation cert, and session token in the corpus must
// decode, re-encode byte-identical to the canonical JSON of the original
// document, and survive decode(encode(x)) with deep equality.
//
// Strictness: the decoder fails closed on unknown fields, malformed base64,
// wrong cryptographic byte lengths, type mismatches, and unpaired v1.1
// stream fields — with errors that name the offending field.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalJSON,
  decodeDelegationCert,
  decodeProofBundle,
  decodeSessionToken,
  encodeDelegationCert,
  encodeProofBundle,
  encodeSessionToken,
} from "../src/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = join(__dirname, "..", "..", "..", "testvectors", "v1");

function canonicalText(value: unknown): string {
  return new TextDecoder().decode(canonicalJSON(value));
}

// ----- Collect every bundle / cert / token in the fixture corpus -----

interface RawDoc {
  name: string;
  raw: Record<string, unknown>;
}

const bundles: RawDoc[] = [];
const certs: RawDoc[] = [];
const tokens: RawDoc[] = [];

for (const file of readdirSync(FIXTURE_DIR).filter((f) => f.endsWith(".json")).sort()) {
  const fx = JSON.parse(readFileSync(join(FIXTURE_DIR, file), "utf8"));
  if (file === "cross_sdk_vectors.json") {
    for (const v of fx.vectors) {
      if (v.kind === "bundle_hash") {
        bundles.push({ name: `${file}:${v.name}`, raw: v.input.bundle });
      }
    }
    continue;
  }
  if (fx.bundle) {
    bundles.push({ name: file, raw: fx.bundle });
  }
  if (fx.cert_chain) {
    fx.cert_chain.forEach((c: Record<string, unknown>, i: number) => {
      certs.push({ name: `${file}:cert[${i}]`, raw: c });
    });
  }
  if (fx.session_token?.token) {
    tokens.push({ name: file, raw: fx.session_token.token });
  }
  if (fx.transaction_receipt?.parties) {
    fx.transaction_receipt.parties.forEach(
      (p: { proof_bundle: Record<string, unknown> }, i: number) => {
        bundles.push({ name: `${file}:party[${i}]`, raw: p.proof_bundle });
      },
    );
  }
}

test("wire: fixture corpus is non-trivial", () => {
  assert.ok(bundles.length > 40, `expected >40 bundles, found ${bundles.length}`);
  assert.ok(certs.length > 40, `expected >40 certs, found ${certs.length}`);
  assert.ok(tokens.length >= 5, `expected >=5 tokens, found ${tokens.length}`);
});

// ----- Round-trip: every fixture bundle / cert / token -----

for (const { name, raw } of bundles) {
  test(`wire round-trip bundle: ${name}`, () => {
    const canon = canonicalText(raw);
    const bundle = decodeProofBundle(JSON.stringify(raw));
    assert.equal(encodeProofBundle(bundle), canon, "encode(decode(json)) drift");
    assert.deepStrictEqual(decodeProofBundle(encodeProofBundle(bundle)), bundle);
  });
}

for (const { name, raw } of certs) {
  test(`wire round-trip cert: ${name}`, () => {
    const canon = canonicalText(raw);
    const cert = decodeDelegationCert(JSON.stringify(raw));
    assert.equal(encodeDelegationCert(cert), canon, "encode(decode(json)) drift");
    assert.deepStrictEqual(decodeDelegationCert(encodeDelegationCert(cert)), cert);
  });
}

for (const { name, raw } of tokens) {
  test(`wire round-trip token: ${name}`, () => {
    const canon = canonicalText(raw);
    const token = decodeSessionToken(JSON.stringify(raw));
    assert.equal(encodeSessionToken(token), canon, "encode(decode(json)) drift");
    assert.deepStrictEqual(decodeSessionToken(encodeSessionToken(token)), token);
  });
}

// ----- Negative wire-acceptance corpus (testvectors/wire-negative) -----
// Shared, byte-identical malformed documents consumed by all five SDKs.
// The TS codec is fully strict, so every corpus case is a decode error.

interface NegativeCase {
  name: string;
  target: "bundle" | "token";
  doc_b64: string;
  strictness: string;
}

const NEGATIVE_CASES = (
  JSON.parse(
    readFileSync(join(FIXTURE_DIR, "..", "wire-negative", "cases.json"), "utf8"),
  ) as { cases: NegativeCase[] }
).cases;

test("wire negative corpus: is non-trivial", () => {
  assert.ok(NEGATIVE_CASES.length >= 10, `only ${NEGATIVE_CASES.length} cases`);
});

for (const c of NEGATIVE_CASES) {
  test(`wire negative corpus: ${c.name}`, () => {
    const doc = Uint8Array.from(Buffer.from(c.doc_b64, "base64"));
    if (c.target === "bundle") {
      assert.throws(() => decodeProofBundle(doc), /wire: /);
    } else {
      assert.throws(() => decodeSessionToken(doc), /wire: /);
    }
  });
}

// ----- Strictness: fail closed with field-specific errors -----

function loadRawBundle(file: string): Record<string, unknown> {
  const fx = JSON.parse(readFileSync(join(FIXTURE_DIR, file), "utf8"));
  return fx.bundle as Record<string, unknown>;
}

function loadRawToken(): Record<string, unknown> {
  const fx = JSON.parse(readFileSync(join(FIXTURE_DIR, "session_token_valid.json"), "utf8"));
  return fx.session_token.token as Record<string, unknown>;
}

test("wire: decodeProofBundle accepts Uint8Array input", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  const fromBytes = decodeProofBundle(new TextEncoder().encode(JSON.stringify(raw)));
  assert.deepStrictEqual(fromBytes, decodeProofBundle(JSON.stringify(raw)));
});

test("wire: rejects unknown field on ProofBundle", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  raw.extra_field = 1;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /unknown field "extra_field"/,
  );
});

test("wire: rejects unknown field on DelegationCert", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  (raw.delegations as Record<string, unknown>[])[0]!.note = "x";
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /delegations\[0\]: unknown field "note"/,
  );
});

test("wire: rejects unknown field on HybridPublicKey", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  (raw.agent_pub_key as Record<string, unknown>).sphincs = "AA==";
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /agent_pub_key: unknown field "sphincs"/,
  );
});

test("wire: rejects unknown field on Constraint", () => {
  const fx = JSON.parse(
    readFileSync(join(FIXTURE_DIR, "constraint_geo_circle_inside.json"), "utf8"),
  );
  const raw = fx.bundle as Record<string, unknown>;
  const constraint = (raw.delegations as Record<string, unknown>[])[0]!
    .constraints as Record<string, unknown>[];
  constraint[0]!.altitude = 10;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /constraints\[0\]: unknown field "altitude"/,
  );
});

test("wire: rejects unknown field on SessionToken", () => {
  const raw = loadRawToken();
  raw.nonce = "AA==";
  assert.throws(() => decodeSessionToken(JSON.stringify(raw)), /unknown field "nonce"/);
});

test("wire: rejects malformed base64", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  raw.challenge = "!not-base64!";
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /ProofBundle\.challenge: malformed base64/,
  );
});

test("wire: rejects non-canonical base64", () => {
  const raw = loadRawToken();
  // 32 bytes with nonzero trailing bits in the final sextet: decodes to the
  // same bytes as the all-"A" form, so re-encoding does not reproduce it.
  raw.mac = "A".repeat(42) + "B=";
  assert.throws(
    () => decodeSessionToken(JSON.stringify(raw)),
    /SessionToken\.mac: non-canonical base64/,
  );
});

test("wire: rejects wrong Ed25519 public key length", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  (raw.agent_pub_key as Record<string, unknown>).ed25519 = "AAAA"; // 3 bytes
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /agent_pub_key\.ed25519: expected 32 bytes, got 3/,
  );
});

test("wire: rejects wrong ML-DSA-65 signature length", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  (raw.challenge_sig as Record<string, unknown>).ml_dsa_65 = "AAAA";
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /challenge_sig\.ml_dsa_65: expected 3309 bytes, got 3/,
  );
});

test("wire: rejects missing required field", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  delete raw.challenge_at;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /ProofBundle\.challenge_at: expected number/,
  );
});

test("wire: rejects missing constraints array", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  delete (raw.delegations as Record<string, unknown>[])[0]!.constraints;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /delegations\[0\]\.constraints: expected array/,
  );
});

test("wire: rejects wrong type for timestamps", () => {
  const raw = loadRawToken();
  raw.issued_at = "12345";
  assert.throws(
    () => decodeSessionToken(JSON.stringify(raw)),
    /SessionToken\.issued_at: expected number/,
  );
});

test("wire: rejects non-integer lexical forms on integer fields", () => {
  // JSON.parse normalizes these to plain integers; the pre-scan preserves
  // the original token form, matching the Python/Go/Rust parsers.
  for (const lexeme of ["1000.0", "1e3", "20000e-1"]) {
    const doc = JSON.stringify(loadRawToken()).replace(
      /"issued_at":\d+/,
      `"issued_at":${lexeme}`,
    );
    assert.throws(
      () => decodeSessionToken(doc),
      /issued_at: integer field must use plain decimal form/,
      `lexeme ${lexeme} must be rejected`,
    );
  }
});

test("wire: float constraint fields still accept fraction and exponent forms", () => {
  const raw = JSON.parse(
    readFileSync(join(FIXTURE_DIR, "constraint_geo_circle_inside.json"), "utf8"),
  ).bundle as Record<string, unknown>;
  const doc = JSON.stringify(raw).replace(/"radius_m":[0-9.]+/, '"radius_m":5e2');
  const bundle = decodeProofBundle(doc); // must not throw
  assert.equal(bundle.delegations[0]!.constraints[0]!.radius_m, 500);
});

test("wire: rejects stream_id without stream_seq", () => {
  const raw = loadRawBundle("stream_bound_first_turn.json");
  delete raw.stream_seq;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /stream_id and stream_seq must be present together/,
  );
});

test("wire: rejects stream_seq below 1", () => {
  const raw = loadRawBundle("stream_bound_first_turn.json");
  raw.stream_seq = 0;
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /stream_seq: must be >= 1/,
  );
});

test("wire: rejects wrong session_context length", () => {
  const raw = loadRawBundle("session_bound_challenge.json");
  raw.session_context = "AAAA"; // 3 bytes, must be 32
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /session_context: expected 32 bytes, got 3/,
  );
});

// Duplicate-key cases. Inputs are IDENTICAL to the Python suite
// (tests/test_wire.py) so both codecs demonstrably reject the same
// documents. The pre-scan runs before schema validation, so minimal
// documents suffice.
const DUPLICATE_KEY_CASES: [string, string, string][] = [
  ["top-level field", '{"agent_id":"x","agent_id":"y"}', "agent_id"],
  [
    "nested pubkey field",
    '{"agent_pub_key":{"ed25519":"AA==","ed25519":"BB=="}}',
    "ed25519",
  ],
  [
    "constraint field",
    '{"delegations":[{"constraints":[{"type":"geo_circle","type":"geo_circle"}]}]}',
    "type",
  ],
  [
    "signature field",
    '{"challenge_sig":{"ml_dsa_65":"AA==","ml_dsa_65":"AA=="}}',
    "ml_dsa_65",
  ],
  // "agent_id" spells "agent_id" with a Unicode escape — same key.
  ["unicode-escaped key", '{"agent_id":"x","agent\\u005fid":"y"}', "agent_id"],
];

for (const [name, input, key] of DUPLICATE_KEY_CASES) {
  test(`wire: rejects duplicate ${name}`, () => {
    assert.throws(
      () => decodeProofBundle(input),
      new RegExp(`duplicate key "${key}" in JSON object`),
    );
  });
}

test("wire: same key in different sibling objects is not a duplicate", () => {
  // The fixture carries "ed25519" and "ml_dsa_65" in many sibling objects
  // (agent, issuer, and subject keys; signatures) — that must decode fine.
  const raw = loadRawBundle("happy_path_depth_1.json");
  decodeProofBundle(JSON.stringify(raw));
});

test("wire: rejects empty delegations array", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  raw.delegations = [];
  assert.throws(
    () => decodeProofBundle(JSON.stringify(raw)),
    /ProofBundle\.delegations: must contain at least one certificate/,
  );
});

test("wire: rejects non-object input", () => {
  assert.throws(() => decodeProofBundle("[1,2,3]"), /expected JSON object/);
  assert.throws(() => decodeProofBundle("not json"), /invalid JSON/);
});

// Byte-decoding strictness. Inputs are byte-identical to the Python suite.

test("wire: rejects malformed UTF-8 bytes", () => {
  // 0xff is never valid in UTF-8.
  const bytes = Uint8Array.from([...new TextEncoder().encode('{"agent_id":"'), 0xff, ...new TextEncoder().encode('"}')]);
  assert.throws(() => decodeProofBundle(bytes), /wire: invalid UTF-8/);
});

test("wire: rejects BOM-prefixed JSON bytes", () => {
  // UTF-8 BOM (EF BB BF) is not stripped; U+FEFF is invalid JSON.
  const bytes = Uint8Array.from([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"agent_id":"x"}')]);
  assert.throws(() => decodeProofBundle(bytes), /wire: invalid JSON/);
});

test("wire: rejects string input with a leading U+FEFF", () => {
  assert.throws(() => decodeProofBundle('\uFEFF{"agent_id":"x"}'), /wire: invalid JSON/);
});

// Integer-domain boundaries (SPEC §6.2): JSON integer wire fields must
// lie within the IEEE-754 safe-integer range. Same field (issued_at on a
// SessionToken) as the Python suite.

test("wire: accepts issued_at at the safe-integer bounds", () => {
  for (const bound of [9007199254740991, -9007199254740991]) {
    const raw = loadRawToken();
    raw.issued_at = bound;
    const token = decodeSessionToken(JSON.stringify(raw));
    assert.equal(token.issued_at, bound);
  }
});

test("wire: rejects issued_at beyond the safe-integer bounds", () => {
  for (const outside of ["9007199254740992", "-9007199254740992"]) {
    const raw = loadRawToken();
    const doc = JSON.stringify(raw).replace(
      /"issued_at":\d+/,
      `"issued_at":${outside}`,
    );
    assert.throws(
      () => decodeSessionToken(doc),
      /issued_at: integer outside the safe-integer range/,
      `issued_at=${outside} must be rejected`,
    );
  }
});

// Encoder-side integer domain (mirrors the Python suite): encoders must
// never emit an integer their own decoder rejects. Same two fields as
// Python: a top-level timestamp and a nested constraint integer.

const SAFE_BOUNDS = [9007199254740991, -9007199254740991];
const OUTSIDE_BOUNDS = [9007199254740992, -9007199254740992];

test("wire: encoder accepts SessionToken.issued_at at the safe-integer bounds", () => {
  for (const bound of SAFE_BOUNDS) {
    const token = decodeSessionToken(JSON.stringify(loadRawToken()));
    token.issued_at = bound;
    assert.match(encodeSessionToken(token), new RegExp(`"issued_at":${bound}[,}]`));
  }
});

test("wire: encoder rejects SessionToken.issued_at beyond the safe-integer bounds", () => {
  for (const outside of OUTSIDE_BOUNDS) {
    const token = decodeSessionToken(JSON.stringify(loadRawToken()));
    token.issued_at = outside;
    assert.throws(
      () => encodeSessionToken(token),
      /issued_at: integer outside the safe-integer range/,
    );
  }
});

test("wire: encoder accepts constraint window_s at the safe-integer bounds", () => {
  for (const bound of SAFE_BOUNDS) {
    const raw = loadRawBundle("constraint_max_rate_denied.json");
    const bundle = decodeProofBundle(JSON.stringify(raw));
    bundle.delegations[0]!.constraints[0]!.window_s = bound;
    assert.match(encodeProofBundle(bundle), new RegExp(`"window_s":${bound}[,}]`));
  }
});

test("wire: encoder rejects constraint window_s beyond the safe-integer bounds", () => {
  for (const outside of OUTSIDE_BOUNDS) {
    const raw = loadRawBundle("constraint_max_rate_denied.json");
    const bundle = decodeProofBundle(JSON.stringify(raw));
    bundle.delegations[0]!.constraints[0]!.window_s = outside;
    assert.throws(
      () => encodeProofBundle(bundle),
      /constraints\[0\]\.window_s: integer outside the safe-integer range/,
    );
  }
});

test("wire: encoder rejects bigint values outright", () => {
  // canonicalJSON would serialize a bigint's digits, silently bypassing the
  // integer domain — so the codec rejects the type before serialization.
  const token = decodeSessionToken(JSON.stringify(loadRawToken()));
  (token as { issued_at: unknown }).issued_at = 2n ** 60n;
  assert.throws(
    () => encodeSessionToken(token),
    /issued_at: bigint is not a wire integer/,
  );
});

test("wire: empty constraints stay an empty array, not absent", () => {
  const raw = loadRawBundle("happy_path_depth_1.json");
  const encoded = encodeProofBundle(decodeProofBundle(JSON.stringify(raw)));
  assert.match(encoded, /"constraints":\[\]/);
});
