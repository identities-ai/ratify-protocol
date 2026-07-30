// Unit tests for the alpha.16 resource-bound authority additions — mirrors
// the Go reference resource_path_test.go. Covers the logical path model,
// segment-boundary matching, the extension-constraint params value model,
// issuance hygiene, path_prefix presence rejection through the wire decoder,
// the VerificationReceipt codec pair, input bounds, and the agent-name bound.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MAX_AGENT_NAME_LENGTH_BYTES,
  MAX_CONSTRAINTS_PER_CERT,
  MAX_IDENTIFIER_LENGTH_BYTES,
  MAX_JSON_NESTING_DEPTH,
  MAX_PROOF_BUNDLE_BYTES,
  MAX_SCOPES_PER_CERT,
  MAX_SCOPE_LENGTH_BYTES,
  PROTOCOL_VERSION,
  NO_EXPIRY_SENTINEL,
  SCOPE_FILES_WRITE,
  base64StandardEncode,
  decodeDelegationCert,
  decodeProofBundle,
  decodeVerificationReceipt,
  deriveID,
  encodeDelegationCert,
  encodeProofBundle,
  encodeVerificationReceipt,
  generateAgent,
  generateChallenge,
  generateHybridKeypair,
  isCanonicalConstraintType,
  issueDelegation,
  normalizeResourcePath,
  resourcePathMatches,
  signBoth,
  signChallenge,
  validateParamsValue,
  validateResourceConstraints,
  verificationReceiptSignBytesBuf,
  type Constraint,
  type DelegationCert,
  type HybridPrivateKey,
  type HybridPublicKey,
  type ProofBundle,
  type VerificationReceipt,
} from "../src/index.js";

// ---- test helpers ----

interface Entity {
  id: string;
  pub: HybridPublicKey;
  priv: HybridPrivateKey;
}

async function makeEntity(): Promise<Entity> {
  const { publicKey, privateKey } = await generateHybridKeypair();
  return { id: deriveID(publicKey), pub: publicKey, priv: privateKey };
}

// ---- NormalizeResourcePath ----

test("normalizeResourcePath: valid paths return comparison form", () => {
  const valid: Record<string, string> = {
    "/": "/",
    "/docs": "/docs",
    "/docs/": "/docs",
    "/docs/setup/g.md": "/docs/setup/g.md",
    "/docs/%2e%2e/notes": "/docs/%2e%2e/notes", // % is a literal byte
    "/a b/c": "/a b/c",
    "/UPPER/Case": "/UPPER/Case", // byte-exact; no case folding
  };
  for (const [input, want] of Object.entries(valid)) {
    assert.equal(normalizeResourcePath(input), want, `normalizeResourcePath(${input})`);
  }
});

test("normalizeResourcePath: invalid paths throw", () => {
  const invalid = [
    "", // empty
    "docs", // no leading slash
    "docs/", // no leading slash
    "/docs/../x", // dot-segment
    "/./x", // dot-segment
    "/..", // dot-segment
    "/a//b", // empty interior segment
    "/docs//", // empty segment after one-trailing-slash trim
    "//", // empty segment
    "/a\\b", // backslash
    "\\docs", // backslash, no leading slash
    "/a\u0000b", // NUL (escaped so the source stays text)
    "/docs/./g.md", // dot-segment mid-path
  ];
  for (const input of invalid) {
    assert.throws(() => normalizeResourcePath(input), `expected throw for ${JSON.stringify(input)}`);
  }
});

// ---- ResourcePathMatches (segment-boundary) ----

test("resourcePathMatches: segment-boundary semantics", () => {
  const cases: [string, string, boolean][] = [
    ["/docs", "/docs", true],
    ["/docs", "/docs/a.md", true],
    ["/docs/", "/docs", true], // trailing slash trims
    ["/docs", "/docs/", true], // both directions
    ["/", "/anything", true], // root matches everything
    ["/", "/", true], // root matches root
    ["/docs", "/docs-old", false], // segment boundary, not string prefix
    ["/docs", "/docsx/a", false], // segment boundary
    ["/docs", "/doc", false], // shorter
    ["/docs", "/", false], // parent of prefix
    ["/src/security", "/src", false], // narrower prefix does not match wider path
    ["/docs", "/docs/../x", false], // invalid path never matches
    ["/docs/../x", "/docs", false], // invalid prefix never matches
  ];
  for (const [prefix, path, want] of cases) {
    assert.equal(resourcePathMatches(prefix, path), want, `resourcePathMatches(${prefix}, ${path})`);
  }
});

// ---- validateResourceConstraints (issuance hygiene) ----

test("validateResourceConstraints: satisfiable sets accepted", () => {
  const rp = (id: string, prefix: string): Constraint => ({
    type: "resource_path",
    resource_id: id,
    ...(prefix === "" ? {} : { path_prefix: prefix }),
  });
  const ok: Constraint[][] = [
    [],
    [rp("git:github.com/acme/widgets", "/docs")],
    [rp("git:github.com/acme/widgets", "")], // whole resource
    [rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/src/security")], // nested
    [rp("git:github.com/acme/widgets", ""), rp("git:github.com/acme/widgets", "/docs")], // absent orders as /
    [{ type: "geo_circle", lat: 1, lon: 1, radius_m: 5 }], // non-resource untouched
  ];
  for (const cs of ok) {
    assert.doesNotThrow(() => validateResourceConstraints(cs));
  }
});

test("validateResourceConstraints: unsatisfiable sets rejected", () => {
  const rp = (id: string, prefix: string): Constraint => ({
    type: "resource_path",
    resource_id: id,
    ...(prefix === "" ? {} : { path_prefix: prefix }),
  });
  const bad: Constraint[][] = [
    [rp("", "/docs")], // empty resource_id
    [rp("x".repeat(MAX_IDENTIFIER_LENGTH_BYTES + 1), "")], // oversized id
    [rp("git:github.com/acme/widgets", "docs")], // invalid prefix
    [rp("git:github.com/acme/widgets", "/docs"), rp("git:github.com/acme/other", "/docs")], // different resources
    [rp("git:github.com/acme/widgets", "/src"), rp("git:github.com/acme/widgets", "/docs")], // incomparable prefixes
  ];
  for (let i = 0; i < bad.length; i++) {
    assert.throws(() => validateResourceConstraints(bad[i]!), `bad case ${i}`);
  }
});

// ---- validateParamsValue (restricted value model) ----

test("validateParamsValue: values within the model accepted", () => {
  const ok: unknown[] = [
    null,
    true,
    "s",
    5,
    42,
    -9007199254740991,
    [1, "two", null],
    { a: 1, b: [true] },
  ];
  for (const v of ok) {
    assert.doesNotThrow(() => validateParamsValue(v, 0), `ok value ${JSON.stringify(v)}`);
  }
});

test("validateParamsValue: values outside the model rejected", () => {
  const bad: unknown[] = [
    1.5, // non-integer number
    9007199254740992, // beyond safe range
    new Uint8Array([1]), // raw bytes
    { a: 1.25 }, // nested float
    [[[1.5]]], // nested float in arrays
  ];
  for (const v of bad) {
    assert.throws(() => validateParamsValue(v, 0), `bad value ${JSON.stringify(v)}`);
  }

  // Nesting bound: a chain of arrays deeper than MAX_JSON_NESTING_DEPTH.
  let deep: unknown = "leaf";
  for (let i = 0; i < MAX_JSON_NESTING_DEPTH + 1; i++) deep = [deep];
  assert.throws(() => validateParamsValue(deep, 0), "expected nesting-depth rejection");
});

test("isCanonicalConstraintType classifies canonical vs extension", () => {
  assert.equal(isCanonicalConstraintType("resource_path"), true);
  assert.equal(isCanonicalConstraintType("geo_circle"), true);
  assert.equal(isCanonicalConstraintType("com.example.limit"), false);
});

// ---- issueDelegation issuance hygiene ----

test("issueDelegation rejects unsatisfiable resource sets and params misuse", async () => {
  const root = await makeEntity();
  const agent = await makeEntity();
  const base = (): DelegationCert => ({
    cert_id: "t-issue-1",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.pub,
    subject_id: agent.id,
    subject_pub_key: agent.pub,
    scope: [SCOPE_FILES_WRITE],
    constraints: [],
    issued_at: 1000,
    expires_at: 2000,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  });

  // Different-resource pair — jointly unsatisfiable.
  const c1 = base();
  c1.constraints = [
    { type: "resource_path", resource_id: "r1", path_prefix: "/docs" },
    { type: "resource_path", resource_id: "r2", path_prefix: "/docs" },
  ];
  await assert.rejects(issueDelegation(c1, root.priv));

  // params on a canonical constraint type.
  const c2 = base();
  c2.constraints = [
    { type: "geo_circle", lat: 1, lon: 1, radius_m: 5, params: { x: 1 } },
  ];
  await assert.rejects(issueDelegation(c2, root.priv));

  // float params value on an extension type.
  const c3 = base();
  c3.constraints = [{ type: "com.example.limit" as any, params: { max: 1.5 } }];
  await assert.rejects(issueDelegation(c3, root.priv));
});

// ---- path_prefix presence rejection through the decoder ----

test("path_prefix presence: forbidden forms rejected at decode", async () => {
  const root = await makeEntity();
  const agent = await makeEntity();
  const cert: DelegationCert = {
    cert_id: "t-presence-1",
    version: PROTOCOL_VERSION,
    issuer_id: root.id,
    issuer_pub_key: root.pub,
    subject_id: agent.id,
    subject_pub_key: agent.pub,
    scope: [SCOPE_FILES_WRITE],
    constraints: [
      { type: "resource_path", resource_id: "git:github.com/acme/widgets", path_prefix: "/docs" },
    ],
    issued_at: 1000,
    expires_at: NO_EXPIRY_SENTINEL,
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  await issueDelegation(cert, root.priv);
  const certJSON = encodeDelegationCert(cert);
  // Valid form decodes.
  assert.doesNotThrow(() => decodeDelegationCert(certJSON));

  const forbidden: Record<string, string> = {
    "empty string": `"path_prefix":""`,
    null: `"path_prefix":null`,
    "non-string": `"path_prefix":42`,
  };
  for (const [name, replacement] of Object.entries(forbidden)) {
    const doc = certJSON.replace(`"path_prefix":"/docs"`, replacement);
    assert.notEqual(doc, certJSON, `${name}: mutation not applied`);
    assert.throws(
      () => decodeDelegationCert(doc),
      /wire: /,
      `${name}: forbidden path_prefix must be rejected — never widened to whole-resource authority`,
    );
  }

  // The same forbidden forms inside a full bundle are rejected by decodeProofBundle.
  const challenge = generateChallenge();
  const challengeAt = 2000;
  const challengeSig = await signChallenge(challenge, challengeAt, agent.priv);
  const bundle: ProofBundle = {
    agent_id: agent.id,
    agent_pub_key: agent.pub,
    delegations: [cert],
    challenge,
    challenge_at: challengeAt,
    challenge_sig: challengeSig,
  };
  const bundleJSON = encodeProofBundle(bundle);
  assert.doesNotThrow(() => decodeProofBundle(bundleJSON));
  for (const [name, replacement] of Object.entries(forbidden)) {
    const doc = bundleJSON.replace(`"path_prefix":"/docs"`, replacement);
    assert.notEqual(doc, bundleJSON, `${name}: bundle mutation not applied`);
    assert.throws(() => decodeProofBundle(doc), /wire: /, `${name}: bundle`);
  }
});

// ---- input bounds ----

test("decodeProofBundle rejects oversized payload before parsing", () => {
  const oversized = "x".repeat(MAX_PROOF_BUNDLE_BYTES + 1);
  assert.throws(() => decodeProofBundle(oversized), /MAX_PROOF_BUNDLE_BYTES/);
});

test("decodeProofBundle rejects nesting beyond MAX_JSON_NESTING_DEPTH", () => {
  const deep = "[".repeat(MAX_JSON_NESTING_DEPTH + 1) + "]".repeat(MAX_JSON_NESTING_DEPTH + 1);
  assert.throws(() => decodeProofBundle(deep), /MAX_JSON_NESTING_DEPTH/);
});

// Mirrors Go's TestInputBoundBoundaries: exercise every §5.1 input bound at
// exactly the limit (must accept) and one past it (must reject) through the
// public decoders, using the SDK's exported bound constants so the test
// tracks the constants. The at-limit ACCEPT cases matter as much as the
// rejects: an off-by-one that rejected a legal maximum would be a silent
// availability regression.
test("input bounds accept at the limit and reject one past it", () => {
  // A structurally decodable cert with correctly sized (zero-filled) keys and
  // signature. The encoder applies no bound checks (like Go's), so an
  // over-limit cert can be encoded and then round-tripped through the decoder
  // to observe where the decode-time bound (checkCertBounds) rejects it.
  const baseCert = (): DelegationCert => ({
    cert_id: "bound",
    version: PROTOCOL_VERSION,
    issuer_id: "aa",
    issuer_pub_key: { ed25519: new Uint8Array(32), ml_dsa_65: new Uint8Array(1952) },
    subject_id: "bb",
    subject_pub_key: { ed25519: new Uint8Array(32), ml_dsa_65: new Uint8Array(1952) },
    scope: ["meeting:attend"],
    constraints: [],
    issued_at: 1000,
    expires_at: 2000,
    signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) },
  });
  const decodeCert = (c: DelegationCert): void => {
    decodeDelegationCert(encodeDelegationCert(c));
  };

  // MAX_SCOPES_PER_CERT — vocabulary-valid custom scopes so only the count bound bites.
  const scopes = (n: number): string[] =>
    Array.from({ length: n }, (_, i) => `custom:com.example:s${i}`);
  {
    const c = baseCert();
    c.scope = scopes(MAX_SCOPES_PER_CERT);
    assert.doesNotThrow(() => decodeCert(c), `MAX_SCOPES_PER_CERT at limit (${MAX_SCOPES_PER_CERT}) must decode`);
    c.scope = scopes(MAX_SCOPES_PER_CERT + 1);
    assert.throws(() => decodeCert(c), /MAX_SCOPES_PER_CERT/, `MAX_SCOPES_PER_CERT+1 must be rejected`);
  }

  // MAX_CONSTRAINTS_PER_CERT — geo_circle: no cross-field satisfiability rule at decode.
  const geos = (n: number): Constraint[] =>
    Array.from({ length: n }, () => ({ type: "geo_circle", lat: 1, lon: 1, radius_m: 5 }));
  {
    const c = baseCert();
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT);
    assert.doesNotThrow(() => decodeCert(c), `MAX_CONSTRAINTS_PER_CERT at limit (${MAX_CONSTRAINTS_PER_CERT}) must decode`);
    c.constraints = geos(MAX_CONSTRAINTS_PER_CERT + 1);
    assert.throws(() => decodeCert(c), /MAX_CONSTRAINTS_PER_CERT/, `MAX_CONSTRAINTS_PER_CERT+1 must be rejected`);
  }

  // MAX_SCOPE_LENGTH_BYTES — a custom: scope so it is vocabulary-valid.
  const scopeOfLen = (n: number): string => "custom:x:" + "a".repeat(n - "custom:x:".length);
  {
    const c = baseCert();
    c.scope = [scopeOfLen(MAX_SCOPE_LENGTH_BYTES)];
    assert.doesNotThrow(() => decodeCert(c), `MAX_SCOPE_LENGTH_BYTES at limit (${MAX_SCOPE_LENGTH_BYTES}) must decode`);
    c.scope = [scopeOfLen(MAX_SCOPE_LENGTH_BYTES + 1)];
    assert.throws(() => decodeCert(c), /MAX_SCOPE_LENGTH_BYTES/, `MAX_SCOPE_LENGTH_BYTES+1 must be rejected`);
  }

  // MAX_IDENTIFIER_LENGTH_BYTES — resource_path resource_id.
  const rpID = (n: number): Constraint[] => [{ type: "resource_path", resource_id: "r".repeat(n) }];
  {
    const c = baseCert();
    c.constraints = rpID(MAX_IDENTIFIER_LENGTH_BYTES);
    assert.doesNotThrow(() => decodeCert(c), `MAX_IDENTIFIER_LENGTH_BYTES at limit (${MAX_IDENTIFIER_LENGTH_BYTES}) must decode`);
    c.constraints = rpID(MAX_IDENTIFIER_LENGTH_BYTES + 1);
    assert.throws(() => decodeCert(c), /MAX_IDENTIFIER_LENGTH_BYTES/, `MAX_IDENTIFIER_LENGTH_BYTES+1 must be rejected`);
  }

  // MAX_JSON_NESTING_DEPTH — the SDK's nesting check runs inside the wire
  // decoder (parseInput/scanWireText); there is no exported standalone
  // wire-check like Go's CheckWireJSON. So the boundary is observed through
  // decodeProofBundle: at exactly the limit the nesting check passes (the
  // decode then fails structurally, NOT with a nesting error), and one past
  // it the nesting check rejects.
  const atLimit = "[".repeat(MAX_JSON_NESTING_DEPTH) + "]".repeat(MAX_JSON_NESTING_DEPTH);
  assert.throws(
    () => decodeProofBundle(atLimit),
    (e: Error) => !/MAX_JSON_NESTING_DEPTH/.test(e.message),
    `MAX_JSON_NESTING_DEPTH at limit (${MAX_JSON_NESTING_DEPTH}) must pass the nesting check`,
  );
  const overLimit = "[".repeat(MAX_JSON_NESTING_DEPTH + 1) + "]".repeat(MAX_JSON_NESTING_DEPTH + 1);
  assert.throws(() => decodeProofBundle(overLimit), /MAX_JSON_NESTING_DEPTH/, `MAX_JSON_NESTING_DEPTH+1 must be rejected`);
});

// MAX_AGENT_NAME_LENGTH_BYTES is a construction bound (async); kept as its own
// test to match generateAgent's promise-returning shape. The dedicated
// generateAgent test below covers the same 256/257 boundary.

// ---- VerificationReceipt codec ----

function validReceipt(): VerificationReceipt {
  return {
    version: PROTOCOL_VERSION,
    verifier_id: "b4a4c71795d676b69f454881a8300000",
    verifier_pub: { ed25519: new Uint8Array(32), ml_dsa_65: new Uint8Array(1952) },
    bundle_hash: new Uint8Array(32).fill(0xab),
    decision: "authorized_agent",
    verified_at: 1800000000,
    prev_hash: new Uint8Array(32),
    signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) },
  };
}

test("VerificationReceipt codec round-trip is byte-identical", async () => {
  const verifier = await makeEntity();
  const r: VerificationReceipt = {
    version: PROTOCOL_VERSION,
    verifier_id: verifier.id,
    verifier_pub: verifier.pub,
    bundle_hash: new Uint8Array(32).fill(0xab),
    decision: "revoked",
    agent_id: "b4a4c71795d676b69f454881a8300000",
    error_reason: "delegation certificate has been revoked",
    verified_at: 1800000000,
    prev_hash: new Uint8Array(32),
    signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) },
  };
  // Real signature over the canonical signable — exercises the full shape.
  r.signature = await signBoth(verificationReceiptSignBytesBuf(r), verifier.priv);

  const encoded = encodeVerificationReceipt(r);
  const decoded = decodeVerificationReceipt(encoded);
  const reEncoded = encodeVerificationReceipt(decoded);
  assert.equal(reEncoded, encoded, "receipt round-trip is not byte-identical");
});

test("VerificationReceipt encoder rejects structurally invalid receipts", () => {
  assert.throws(() => encodeVerificationReceipt(null as any), /nil/);
  const mutations: [string, (r: VerificationReceipt) => void][] = [
    ["short bundle_hash", (r) => { r.bundle_hash = r.bundle_hash.slice(0, 16); }],
    ["short prev_hash", (r) => { r.prev_hash = r.prev_hash.slice(0, 31); }],
    ["unknown decision", (r) => { r.decision = "approved" as any; }],
    ["empty verifier_id", (r) => { r.verifier_id = ""; }],
    ["wrong version", (r) => { r.version = 2; }],
    ["short ed25519 sig", (r) => { r.signature.ed25519 = r.signature.ed25519.slice(0, 63); }],
    ["short ml_dsa_65 sig", (r) => { r.signature.ml_dsa_65 = r.signature.ml_dsa_65.slice(0, 100); }],
    ["short verifier pub", (r) => { r.verifier_pub.ml_dsa_65 = r.verifier_pub.ml_dsa_65.slice(0, 100); }],
  ];
  for (const [name, mutate] of mutations) {
    const r = validReceipt();
    mutate(r);
    assert.throws(() => encodeVerificationReceipt(r), `${name}: encoder emitted a document its decoder rejects`);
  }
});

test("VerificationReceipt decoder rejects malformed wire built by mutation", () => {
  const encoded = encodeVerificationReceipt(validReceipt());
  const mutate = (oldStr: string, newStr: string): string => {
    const out = encoded.replace(oldStr, newStr);
    assert.notEqual(out, encoded, `mutation ${oldStr} not applied`);
    return out;
  };
  const cases: Record<string, string> = {
    "unknown field": mutate(`"version":`, `"versionx":1,"version":`),
    "wrong version": mutate(`"version":1`, `"version":2`),
    "unknown decision": mutate(`"decision":"authorized_agent"`, `"decision":"approved"`),
    "empty verifier_id": mutate(
      `"verifier_id":"b4a4c71795d676b69f454881a8300000"`,
      `"verifier_id":""`,
    ),
    "truncated hash": mutate(
      `"bundle_hash":"${base64StandardEncode(new Uint8Array(32).fill(0xab))}"`,
      `"bundle_hash":"${base64StandardEncode(new Uint8Array(16).fill(0xab))}"`,
    ),
  };
  for (const [name, doc] of Object.entries(cases)) {
    assert.throws(() => decodeVerificationReceipt(doc), `${name}: expected decoder rejection`);
  }
  // Non-object document.
  assert.throws(() => decodeVerificationReceipt("[1,2,3]"), /wire: /, "non-object");
});

// ---- agent-name bound ----

test("generateAgent enforces the agent-name byte bound at 256/257", async () => {
  await assert.doesNotReject(
    generateAgent("n".repeat(MAX_AGENT_NAME_LENGTH_BYTES), "custom"),
    `name of exactly ${MAX_AGENT_NAME_LENGTH_BYTES} bytes must be accepted`,
  );
  await assert.rejects(
    generateAgent("n".repeat(MAX_AGENT_NAME_LENGTH_BYTES + 1), "custom"),
    `name of ${MAX_AGENT_NAME_LENGTH_BYTES + 1} bytes must be rejected`,
  );
});
