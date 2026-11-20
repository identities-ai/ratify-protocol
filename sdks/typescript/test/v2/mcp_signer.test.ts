// Verify MCP signer (Preview) over testvectors/v2/mcp.
//
// The hosted service recomputes every value below from the call it
// receives. A signer that differs in one byte produces proofs the service
// rejects, or, worse, a proof that binds something other than the call the
// client asked for. Every SDK runs these same files. They describe a
// managed-service contract, not SPEC-v2 conformance.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { hybridKeypairFromSeeds } from "../../src/crypto.js";
import type { HybridKeyPairV2 } from "../../src/crypto_v2.js";
import { decodeProofBundleV2, verifyProofBundleV2Signatures } from "../../src/protocol_v2_wire.js";
import { disposeLocalSignerV2, keyIDV2, newLocalSignerV2 } from "../../src/signer_v2.js";
import * as mcp from "../../src/v2mcp.js";
import { b64, hex, toHex, VECTOR_DIR, type Any } from "./helpers.js";

const MCP_DIR = join(VECTOR_DIR, "mcp");
const MCP_FILES = ["README.md", "binding.json", "client-config.json", "connect.json", "tool-call.json"];
const loadMcp = (name: string): Any => JSON.parse(readFileSync(join(MCP_DIR, name), "utf8"));
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

async function loadKey(k: Any): Promise<HybridKeyPairV2> {
  const pair = await hybridKeypairFromSeeds(hex(k.ed25519_seed_hex), hex(k.ml_dsa_65_seed_hex));
  assert.equal(keyIDV2(pair.publicKey), k.key_id_v2, `${k.name}: key_id_v2`);
  return pair;
}

/**
 * got and want are the same proof except for the hedged ML-DSA-65 component
 * of challenge_sig, and both verify.
 */
async function assertSameBundle(name: string, gotB64: string, wantB64: string): Promise<void> {
  const decode = async (s: string) => {
    const wire = new Uint8Array(Buffer.from(s, "base64"));
    assert.equal(b64(wire), s, `${name}: bundle is not canonical base64`);
    const bundle = decodeProofBundleV2(wire);
    await verifyProofBundleV2Signatures(bundle);
    return { bundle, wire };
  };
  const got = await decode(gotB64);
  const want = await decode(wantB64);
  const masked = text(got.wire).replace(b64(got.bundle.challenge_sig.ml_dsa_65), b64(want.bundle.challenge_sig.ml_dsa_65));
  assert.equal(masked, text(want.wire), `${name}: proof differs from the vector beyond the hedged ML-DSA-65 signature`);
}

test("mcp corpus: testvectors/v2/mcp holds exactly the files this runner reads", () => {
  assert.deepEqual(readdirSync(MCP_DIR).sort(), MCP_FILES);
  for (const name of MCP_FILES.filter((f) => f.endsWith(".json"))) {
    assert.equal(loadMcp(name).version, 1, `${name}: version`);
  }
});

test("mcp package: ./v2/mcp subpath", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.exports["./v2/mcp"].import, "./dist/v2mcp.js");
  assert.equal(pkg.exports["./v2/mcp"].types, "./dist/v2mcp.d.ts");
});

test("mcp binding.json: constants, tool table, canonical arguments, digests, contexts", () => {
  const f = loadMcp("binding.json");
  assert.equal(mcp.ACTION, f.action);
  assert.equal(mcp.PROOF_META_KEY, f.proof_meta_key);
  assert.equal(mcp.PROTOCOL_VERSION, "2026-07-28");
  assert.equal(mcp.MIN_CHALLENGE_SECONDS_LEFT, 10);
  assert.equal(mcp.MAX_ARGUMENT_DEPTH, 4);
  assert.deepEqual(mcp.TOOLS.map((t) => ({ name: t.name, scope: t.scope })), f.tools);
  for (const t of f.tools) assert.equal(mcp.toolScope(t.name), t.scope);
  assert.equal(mcp.toolScope("no_such_tool"), null);
  assert.ok(f.cases.length > 0 && f.invalid_arguments.length > 0);
  for (const c of f.cases) {
    // Bytes and text input give the same canonical bytes.
    const canonical = mcp.canonicalArguments(utf8(c.arguments_json));
    assert.equal(text(canonical), c.canonical_arguments, `${c.name}: canonical arguments`);
    assert.deepEqual(mcp.canonicalArguments(c.arguments_json), canonical, `${c.name}: string input`);
    const digest = mcp.payloadDigest(canonical);
    assert.equal(mcp.payloadDigestText(digest), c.payload_digest, `${c.name}: payload digest`);
    const req = mcp.requestHash(c.tool, c.connection_id, c.audience, digest);
    assert.equal(toHex(req), c.request_hash, `${c.name}: request hash`);
    const sess = mcp.sessionContext(c.verifier_id, c.workspace_id, c.agent_id, c.connection_id, c.invocation_id, req);
    assert.equal(toHex(sess), c.session_context, `${c.name}: session context`);
  }
  for (const c of f.invalid_arguments) {
    const input = c.arguments_base64 ? new Uint8Array(Buffer.from(c.arguments_base64, "base64")) : utf8(c.arguments_json);
    assert.throws(() => mcp.canonicalArguments(input), mcp.InvalidArgumentsError, `${c.name}: accepted`);
  }
});

test("mcp canonical arguments: keys sort by UTF-8 bytes, not UTF-16 code units", () => {
  // The server sorts by UTF-8 bytes. U+FF5A (EF BD 9A) comes before U+1F600
  // (F0 9F 98 80) in UTF-8, but after it in UTF-16 (0xFF5A > 0xD83D), which
  // is the order a default JavaScript string sort would give.
  assert.equal(text(mcp.canonicalArguments('{"\u{1F600}":1,"ｚ":2}')), '{"ｚ":2,"\u{1F600}":1}');
  // A lone surrogate in a string argument is refused rather than replaced.
  assert.throws(() => mcp.canonicalArguments('{"s":"\uD800"}'), mcp.InvalidArgumentsError);
});

test("mcp client-config.json: valid configurations parse, invalid ones are refused", () => {
  const f = loadMcp("client-config.json");
  assert.ok(f.valid.length > 0 && f.invalid.length > 0);
  for (const c of f.valid) {
    const cfg = mcp.parseClientConfig(c.config_json);
    const e = c.expected;
    assert.deepEqual(
      [cfg.endpoint, cfg.audience, cfg.verifierID, cfg.workspaceID, cfg.connectionID],
      [e.endpoint, e.audience, e.verifier_id, e.workspace_id, e.connection_id],
      c.name,
    );
    assert.deepEqual(cfg.delegations.map((d) => d.cert_id), e.delegation_cert_ids, `${c.name}: delegations`);
    assert.deepEqual(mcp.parseClientConfig(utf8(c.config_json)).delegations.map((d) => d.cert_id), e.delegation_cert_ids);
  }
  for (const c of f.invalid) {
    assert.throws(() => mcp.parseClientConfig(c.config_json), mcp.InvalidConfigError, `${c.name}: accepted`);
  }
});

test("mcp tool-call.json: challenge requests, challenge checks, and signed envelopes", async () => {
  const f = loadMcp("tool-call.json");
  assert.ok(f.cases.length > 0 && f.refused_challenges.length > 0);
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const agent = await loadKey(f.agent_key);
  const wrong = await loadKey(f.wrong_agent_key);
  for (const c of f.cases) {
    const call = mcp.newToolCall(c.tool, c.arguments_json);
    assert.equal(text(call.canonicalArguments), c.canonical_arguments, `${c.name}: canonical arguments`);
    assert.equal(text(mcp.challengeRequest(cfg, call)), c.challenge_request, `${c.name}: challenge request`);
    const req = mcp.requestHash(c.tool, cfg.connectionID, cfg.audience, call.payloadDigest);
    assert.equal(toHex(req), c.request_hash, `${c.name}: request hash`);
    const ch = mcp.checkChallenge(cfg, c.tool, c.challenge_response, c.now);
    assert.equal(toHex(mcp.sessionContext(cfg.verifierID, cfg.workspaceID, keyIDV2(agent.publicKey), cfg.connectionID, ch.invocationID, req)),
      c.session_context, `${c.name}: session context`);
    const env = await mcp.signToolCall(cfg, agent, call, ch);
    assert.deepEqual([env.connection_id, env.invocation_id, env.challenge],
      [c.envelope.connection_id, c.envelope.invocation_id, c.envelope.challenge], `${c.name}: envelope`);
    await assertSameBundle(c.name, env.bundle, c.envelope.bundle);
    await assert.rejects(mcp.signToolCall(cfg, wrong, call, ch), mcp.ChallengeRefusedError,
      `${c.name}: a key the delegation does not name signed`);
  }
  for (const c of f.refused_challenges) {
    assert.throws(() => mcp.checkChallenge(cfg, c.tool, c.challenge_response, c.now), mcp.ChallengeRefusedError, `${c.name}: accepted`);
  }
});

test("mcp tool-call.json refused_signings: an accepted challenge signs only its own tool and configuration", async () => {
  const f = loadMcp("tool-call.json");
  assert.ok(Array.isArray(f.refused_signings) && f.refused_signings.length > 0, "refused_signings is empty");
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const agent = await loadKey(f.agent_key);
  for (const c of f.refused_signings) {
    const ch = mcp.checkChallenge(cfg, c.checked_tool, c.challenge_response, c.now);
    const signingConfig = c.signing_config_json === "" ? cfg : mcp.parseClientConfig(c.signing_config_json);
    const call = mcp.newToolCall(c.signing_tool, c.signing_arguments_json);
    await assert.rejects(mcp.signToolCall(signingConfig, agent, call, ch), mcp.McpSignerError, `${c.name}: signed`);
  }
});

test("mcp tool call: a call whose digest does not match its arguments is refused", async () => {
  // A ToolCall is a plain object a caller can build or copy. If the signer
  // trusted its digest, it could bind one argument set while the client
  // sends another.
  const f = loadMcp("tool-call.json");
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const agent = await loadKey(f.agent_key);
  const c = f.cases[0];
  const ch = mcp.checkChallenge(cfg, c.tool, c.challenge_response, c.now);
  const call = mcp.newToolCall(c.tool, '{"limit":1}');
  const other = mcp.newToolCall(c.tool, '{"limit":2}');
  const swapped: mcp.ToolCall = { ...call, payloadDigest: other.payloadDigest };
  assert.throws(() => mcp.challengeRequest(cfg, swapped), mcp.InvalidArgumentsError);
  await assert.rejects(mcp.signToolCall(cfg, agent, swapped, ch), mcp.InvalidArgumentsError);
  const nonCanonical: mcp.ToolCall = { ...other, canonicalArguments: utf8('{ "limit":2}') };
  assert.throws(() => mcp.challengeRequest(cfg, nonCanonical), mcp.InvalidArgumentsError);
  await assert.rejects(mcp.signToolCall(cfg, agent, nonCanonical, ch), mcp.InvalidArgumentsError);
  const empty: mcp.ToolCall = { tool: c.tool, canonicalArguments: new Uint8Array(0), payloadDigest: mcp.payloadDigest(new Uint8Array(0)) };
  await assert.rejects(mcp.signToolCall(cfg, agent, empty, ch), mcp.InvalidArgumentsError);
  // The unchanged call still signs.
  await mcp.signToolCall(cfg, agent, call, ch);
});

test("mcp JSON inputs: invalid UTF-8 and lone surrogates are refused", () => {
  const f = loadMcp("tool-call.json");
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const c = f.cases[0];
  // Valid JSON with an invalid UTF-8 byte inside an ignored string field.
  const withBadByte = (json: string): Uint8Array => {
    const bytes = utf8(json.replace(/^\{/, '{"x":"?",'));
    bytes[bytes.indexOf(0x3f)] = 0xff;
    return bytes;
  };
  assert.ok(mcp.checkChallenge(cfg, c.tool, utf8(c.challenge_response.replace(/^\{/, '{"x":"?",')), c.now));
  assert.throws(() => mcp.checkChallenge(cfg, c.tool, withBadByte(c.challenge_response), c.now), mcp.ChallengeRefusedError);
  assert.throws(() => mcp.checkChallenge(cfg, c.tool, c.challenge_response.replace(/^\{/, '{"x":"\uD800",'), c.now), mcp.ChallengeRefusedError);
  assert.throws(() => mcp.parseClientConfig(withBadByte(f.client_config_json)), mcp.InvalidConfigError);
  assert.throws(() => mcp.parseClientConfig(f.client_config_json.replace(/^\{/, '{"x":"\uD800",')), mcp.InvalidConfigError);
});

test("mcp tool call: the external-signer variant produces the same proof", async () => {
  const f = loadMcp("tool-call.json");
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const agent = await loadKey(f.agent_key);
  const c = f.cases[0];
  const call = mcp.newToolCall(c.tool, c.arguments_json);
  const ch = mcp.checkChallenge(cfg, c.tool, c.challenge_response, c.now);
  const signer = await newLocalSignerV2(agent);
  try {
    const env = await mcp.signToolCallWithSigner(cfg, signer, call, ch);
    await assertSameBundle(`${c.name} (signer)`, env.bundle, c.envelope.bundle);
  } finally {
    disposeLocalSignerV2(signer);
  }
});

test("mcp tool call: a challenge checked for one tool cannot sign a call to another", async () => {
  // The server issues a challenge for the scope of the tool named in the
  // challenge request. Signing it for a different call would bind a proof
  // to an operation the challenge never authorized.
  const f = loadMcp("tool-call.json");
  const cfg = mcp.parseClientConfig(f.client_config_json);
  const agent = await loadKey(f.agent_key);
  const metrics = f.cases.find((c: Any) => c.tool === "get_metrics");
  const other = f.cases.find((c: Any) => c.tool !== "get_metrics" && mcp.toolScope(c.tool) !== mcp.toolScope("get_metrics"));
  assert.ok(metrics && other, "tool-call.json needs a get_metrics case and a case with another scope");
  const ch = mcp.checkChallenge(cfg, metrics.tool, metrics.challenge_response, metrics.now);
  const call = mcp.newToolCall(other.tool, other.arguments_json);
  await assert.rejects(mcp.signToolCall(cfg, agent, call, ch), mcp.ChallengeRefusedError);
  // The same response is not even a valid challenge for the other tool.
  assert.throws(() => mcp.checkChallenge(cfg, other.tool, metrics.challenge_response, metrics.now), mcp.ChallengeRefusedError);
  assert.throws(() => mcp.newToolCall("no_such_tool", "{}"), mcp.InvalidArgumentsError);
});

test("mcp connect.json: possession contexts, tokens, and proofs of possession", async () => {
  const f = loadMcp("connect.json");
  assert.equal(f.domain, mcp.CONNECT_POSSESSION_DOMAIN);
  assert.equal(f.token_prefix, mcp.CONNECT_TOKEN_PREFIX);
  assert.equal(mcp.MAX_CONNECT_TOKEN_LENGTH, 4096);
  assert.ok(f.contexts.length > 0 && f.proofs.length > 0 && f.invalid_tokens.length > 0);
  for (const c of f.contexts) {
    const got = mcp.connectPossessionContext(c.workspace_id, c.receiver_id, c.audience, c.challenge_id, c.agent_id);
    assert.equal(toHex(got), c.session_context, `${c.name}: context`);
  }
  const agent = await loadKey(f.agent_key);
  const agentID = keyIDV2(agent.publicKey);
  for (const c of f.proofs) {
    const t = mcp.parseConnectToken(c.token);
    const p = c.parsed;
    assert.deepEqual(
      [t.challengeID, b64(t.challenge), t.issuedAt, t.workspaceID, t.receiverID, t.audience, t.verifierID],
      [p.challenge_id, p.challenge, p.issued_at, p.workspace_id, p.receiver_id, p.audience, p.verifier_id],
      `${c.name}: parsed`,
    );
    const sess = mcp.connectPossessionContext(t.workspaceID, t.receiverID, t.audience, t.challengeID, agentID);
    assert.equal(toHex(sess), c.session_context, `${c.name}: session context`);
    const proof = await mcp.provePossession(c.token, agent);
    assert.equal(proof.connect_challenge_id, c.expected.connect_challenge_id, `${c.name}: challenge id`);
    await assertSameBundle(c.name, proof.possession_proof, c.expected.possession_proof);
  }
  const signer = await newLocalSignerV2(agent);
  try {
    const first = f.proofs[0];
    const proof = await mcp.provePossessionWithSigner(first.token, signer);
    await assertSameBundle(`${first.name} (signer)`, proof.possession_proof, first.expected.possession_proof);
  } finally {
    disposeLocalSignerV2(signer);
  }
  for (const c of f.invalid_tokens) {
    assert.throws(() => mcp.parseConnectToken(c.token), mcp.InvalidConnectTokenError, `${c.name}: parsed`);
    await assert.rejects(mcp.provePossession(c.token, agent), mcp.InvalidConnectTokenError, `${c.name}: signed`);
  }
});
