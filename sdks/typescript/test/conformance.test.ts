// Conformance tests — validate the TS SDK against the Go-generated canonical
// test vectors. If this suite passes, the TS implementation is byte-identical
// to the Go reference across canonical serialization, hybrid signing bytes,
// scope semantics, and verifier behavior.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  delegationSignBytes,
  challengeSignBytes,
  keyRotationSignBytes,
  revocationSignBytes,
  revocationPushSignBytes,
  witnessEntrySignBytes,
  sessionTokenSignBytes,
  transactionReceiptSignBytes,
  verifyKeyRotationStatementE,
  verifyRevocationList,
  verifyRevocationPush,
  verifyWitnessEntry,
  verifyBundle,
  verifyStreamedTurn,
  verifyTransactionReceipt,
  expandScopes,
  hexEncode,
  base64StandardDecode,
  type DelegationCert,
  type HybridPublicKey,
  type HybridSignature,
  type KeyRotationStatement,
  type ProofBundle,
  type ReceiptParty,
  type ReceiptPartySignature,
  type RevocationList,
  type RevocationPush,
  type SessionToken,
  type TransactionReceipt,
  type VerifyResult,
  type WitnessEntry,
} from "../src/index.js";

// ----- Locate fixture directory -----

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURE_DIR = join(__dirname, "..", "..", "..", "testvectors", "v1");

// ----- Fixture schema (mirrors the Go generator's JSON output) -----
// Hybrid pubkeys / signatures are JSON objects with base64-encoded byte fields.

interface FixtureEntity {
  role: string;
  ed25519_seed_hex: string;
  ml_dsa_65_seed_hex: string;
  public_key: JsonHybridPublicKey;
  id: string;
}

interface JsonHybridPublicKey {
  ed25519: string; // base64-standard
  ml_dsa_65: string; // base64-standard
}

interface JsonHybridSignature {
  ed25519: string;
  ml_dsa_65: string;
}

interface FixtureVerifyOpts {
  required_scope?: string;
  now: number;
  session_context?: string;
  stream?: FixtureStreamContext;
}

interface FixtureStreamContext {
  stream_id: string; // base64-standard
  last_seen_seq: number;
}

interface FixtureExpected {
  delegation_sign_bytes_hex?: string[];
  challenge_sign_bytes_hex?: string;
  verify_options?: FixtureVerifyOpts;
  verify_result?: VerifyResult;
  expanded_scopes?: string[];
  revocation_sign_bytes_hex?: string;
  revocation_signature_ed25519_hex?: string;
  revocation_signature_ml_dsa_65_hex?: string;
  key_rotation_sign_bytes_hex?: string;
  key_rotation_verify_ok?: boolean;
  key_rotation_error_reason?: string;
  session_token_sign_bytes_hex?: string;
  session_token_mac_hex?: string;
  streamed_turn?: FixtureStreamedTurn;
  receipt_sign_bytes_hex?: string;
  receipt_valid?: boolean;
  receipt_error_reason?: string;
  revocation_push_sign_bytes_hex?: string;
  revocation_push_signature_ed25519_hex?: string;
  revocation_push_signature_ml_dsa_65_hex?: string;
  witness_entry_sign_bytes_hex?: string;
  witness_entry_signature_ed25519_hex?: string;
  witness_entry_signature_ml_dsa_65_hex?: string;
}

interface FixtureStreamedTurn {
  valid: boolean;
  identity_status: string;
  human_id?: string;
  agent_id?: string;
  granted_scope?: string[];
  error_reason?: string;
}

interface FixtureSessionToken {
  session_secret_hex: string;
  token: Record<string, unknown>;
  challenge: string;        // base64
  challenge_at: number;
  challenge_sig: JsonHybridSignature;
  verify_now: number;
}

interface FixtureVerifierContext {
  current_lat?: number;
  current_lon?: number;
  current_alt_m?: number;
  current_speed_mps?: number;
  requested_amount?: number;
  requested_currency?: string;
  invocations_in_window_count?: number;
}

interface FixtureFile {
  name: string;
  description: string;
  protocol_version: number;
  kind: "verify" | "scope" | "revocation" | "key_rotation" | "session_token" | "transaction_receipt" | "revocation_push" | "witness_entry";
  entities?: FixtureEntity[];
  timestamps?: Record<string, number>;
  challenge_hex?: string;
  cert_chain?: Array<Record<string, unknown>>;
  bundle?: Record<string, unknown>;
  key_rotation?: Record<string, unknown>;
  revocation_list?: Record<string, unknown>;
  revocation_push?: Record<string, unknown>;
  witness_entry?: Record<string, unknown>;
  session_token?: FixtureSessionToken;
  transaction_receipt?: Record<string, unknown>;
  scope_input?: string[];
  verifier_context?: FixtureVerifierContext;
  expected: FixtureExpected;
}

// ----- JSON -> typed struct with byte fields decoded -----

function decodeHybridPubKey(raw: JsonHybridPublicKey): HybridPublicKey {
  return {
    ed25519: base64StandardDecode(raw.ed25519),
    ml_dsa_65: base64StandardDecode(raw.ml_dsa_65),
  };
}

function decodeHybridSignature(raw: JsonHybridSignature): HybridSignature {
  return {
    ed25519: base64StandardDecode(raw.ed25519),
    ml_dsa_65: base64StandardDecode(raw.ml_dsa_65),
  };
}

function decodeCert(raw: Record<string, unknown>): DelegationCert {
  // Constraints round-trip as-is through JSON (they're already the right
  // shape for the Constraint type — numeric/string fields). Missing or null
  // becomes an empty array. Decoding them here — not discarding — is how
  // conformance actually tests the new v1 constraint surface end-to-end.
  const constraintsRaw = raw.constraints;
  const constraints = Array.isArray(constraintsRaw)
    ? (constraintsRaw as DelegationCert["constraints"])
    : [];
  return {
    cert_id: raw.cert_id as string,
    version: raw.version as number,
    issuer_id: raw.issuer_id as string,
    issuer_pub_key: decodeHybridPubKey(raw.issuer_pub_key as JsonHybridPublicKey),
    subject_id: raw.subject_id as string,
    subject_pub_key: decodeHybridPubKey(raw.subject_pub_key as JsonHybridPublicKey),
    scope: raw.scope as string[],
    constraints,
    issued_at: raw.issued_at as number,
    expires_at: raw.expires_at as number,
    signature: decodeHybridSignature(raw.signature as JsonHybridSignature),
  };
}

function decodeBundle(raw: Record<string, unknown>): ProofBundle {
  return {
    agent_id: raw.agent_id as string,
    agent_pub_key: decodeHybridPubKey(raw.agent_pub_key as JsonHybridPublicKey),
    delegations: (raw.delegations as Array<Record<string, unknown>>).map(decodeCert),
    challenge: base64StandardDecode(raw.challenge as string),
    challenge_at: raw.challenge_at as number,
    challenge_sig: decodeHybridSignature(raw.challenge_sig as JsonHybridSignature),
    session_context:
      typeof raw.session_context === "string"
        ? base64StandardDecode(raw.session_context)
        : undefined,
    stream_id:
      typeof raw.stream_id === "string"
        ? base64StandardDecode(raw.stream_id)
        : undefined,
    stream_seq: typeof raw.stream_seq === "number" ? raw.stream_seq : undefined,
  };
}

function decodeRevocationList(raw: Record<string, unknown>): RevocationList {
  return {
    issuer_id: raw.issuer_id as string,
    updated_at: raw.updated_at as number,
    revoked_certs: raw.revoked_certs as string[],
    signature: decodeHybridSignature(raw.signature as JsonHybridSignature),
  };
}

function decodeSessionToken(raw: Record<string, unknown>): SessionToken {
  return {
    version: raw.version as number,
    session_id: raw.session_id as string,
    agent_id: raw.agent_id as string,
    agent_pub_key: decodeHybridPubKey(raw.agent_pub_key as JsonHybridPublicKey),
    human_id: raw.human_id as string,
    granted_scope: raw.granted_scope as string[],
    issued_at: raw.issued_at as number,
    valid_until: raw.valid_until as number,
    chain_hash: base64StandardDecode(raw.chain_hash as string),
    mac: base64StandardDecode(raw.mac as string),
  };
}

function hexDecodeStandalone(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function decodeKeyRotation(raw: Record<string, unknown>): KeyRotationStatement {
  return {
    version: raw.version as number,
    old_id: raw.old_id as string,
    old_pub_key: decodeHybridPubKey(raw.old_pub_key as JsonHybridPublicKey),
    new_id: raw.new_id as string,
    new_pub_key: decodeHybridPubKey(raw.new_pub_key as JsonHybridPublicKey),
    rotated_at: raw.rotated_at as number,
    reason: raw.reason as KeyRotationStatement["reason"],
    signature_old: decodeHybridSignature(raw.signature_old as JsonHybridSignature),
    signature_new: decodeHybridSignature(raw.signature_new as JsonHybridSignature),
  };
}

// ----- Fixture loader -----

const fixtureFiles = readdirSync(FIXTURE_DIR)
  .filter((f) => f.endsWith(".json"))
  // cross_sdk_vectors.json has a different schema and is loaded by
  // cross_sdk.test.ts. Skipping here keeps the conformance loop on the 62
  // wire-format fixtures.
  .filter((f) => f !== "cross_sdk_vectors.json")
  .sort();

if (fixtureFiles.length === 0) {
  throw new Error(
    `No fixtures found in ${FIXTURE_DIR}. Run 'go run ./cmd/ratify-testvectors' first.`,
  );
}

// ----- Run every fixture through the TS implementation -----

for (const name of fixtureFiles) {
  test(`conformance: ${name}`, async () => {
    const raw = JSON.parse(readFileSync(join(FIXTURE_DIR, name), "utf8")) as FixtureFile;
    assert.equal(raw.protocol_version, 1, "protocol version mismatch");

    switch (raw.kind) {
      case "verify":
        await runVerifyFixture(raw);
        break;
      case "scope":
        runScopeFixture(raw);
        break;
      case "revocation":
        await runRevocationFixture(raw);
        break;
      case "key_rotation":
        await runKeyRotationFixture(raw);
        break;
      case "session_token":
        await runSessionTokenFixture(raw);
        break;
      case "transaction_receipt":
        await runTransactionReceiptFixture(raw);
        break;
      case "revocation_push":
        await runRevocationPushFixture(raw);
        break;
      case "witness_entry":
        await runWitnessEntryFixture(raw);
        break;
      default:
        throw new Error(`unknown fixture kind: ${raw.kind}`);
    }
  });
}

async function runVerifyFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.cert_chain, "verify fixture missing cert_chain");
  assert.ok(fx.expected.delegation_sign_bytes_hex, "missing expected sign bytes");
  assert.equal(
    fx.cert_chain.length,
    fx.expected.delegation_sign_bytes_hex.length,
    "cert chain length mismatches expected sign bytes count",
  );

  const chain = fx.cert_chain.map(decodeCert);

  // Cross-check canonical signing bytes for every cert.
  for (let i = 0; i < chain.length; i++) {
    const gotHex = hexEncode(delegationSignBytes(chain[i]!));
    const wantHex = fx.expected.delegation_sign_bytes_hex[i]!;
    assert.equal(
      gotHex,
      wantHex,
      `cert ${i} canonical sign bytes drift`,
    );
  }

  // Cross-check challenge signing bytes.
  if (fx.bundle && fx.expected.challenge_sign_bytes_hex) {
    const bundle = decodeBundle(fx.bundle);
    const gotHex = hexEncode(
      challengeSignBytes(
        bundle.challenge,
        bundle.challenge_at,
        bundle.session_context,
        bundle.stream_id,
        bundle.stream_seq,
      ),
    );
    assert.equal(
      gotHex,
      fx.expected.challenge_sign_bytes_hex,
      `challenge sign bytes drift`,
    );
  }

  // Run the verifier and compare to expected result.
  if (!fx.bundle || !fx.expected.verify_result || !fx.expected.verify_options) {
    return;
  }
  const bundle = decodeBundle(fx.bundle);
  const opts = fx.expected.verify_options;
  const sessionContext =
    typeof opts.session_context === "string"
      ? base64StandardDecode(opts.session_context)
      : undefined;
  const streamContext = opts.stream
    ? {
        stream_id: base64StandardDecode(opts.stream.stream_id),
        last_seen_seq: opts.stream.last_seen_seq,
      }
    : undefined;

  // revocation_middle_cert fixture uses an is_revoked callback; reconstruct
  // it from the expected result shape.
  const revokedStatus = fx.expected.verify_result.identity_status === "revoked";
  const isRevoked =
    revokedStatus && bundle.delegations.length > 1
      ? (certID: string) => certID === bundle.delegations[1]!.cert_id
      : undefined;

  // Thread the fixture's verifier_context into the verifier so constraint
  // fixtures (geo_circle, time_window, max_amount) exercise the real
  // constraint-evaluation path end-to-end.
  const vc = fx.verifier_context;
  const context = vc
    ? {
        current_lat: vc.current_lat,
        current_lon: vc.current_lon,
        current_alt_m: vc.current_alt_m,
        current_speed_mps: vc.current_speed_mps,
        requested_amount: vc.requested_amount,
        requested_currency: vc.requested_currency,
        invocations_in_window:
          typeof vc.invocations_in_window_count === "number"
            ? (() => {
                const n = vc.invocations_in_window_count!;
                return () => n;
              })()
            : undefined,
      }
    : undefined;

  const got = await verifyBundle(bundle, {
    required_scope: opts.required_scope,
    now: opts.now,
    session_context: sessionContext,
    stream: streamContext,
    is_revoked: isRevoked,
    context,
  });

  const want = fx.expected.verify_result;

  assert.equal(got.valid, want.valid, "Valid");
  assert.equal(got.identity_status, want.identity_status, "IdentityStatus");
  assert.equal(got.human_id ?? "", want.human_id ?? "", "HumanID");
  assert.equal(got.agent_id ?? "", want.agent_id ?? "", "AgentID");
  assert.equal(got.error_reason ?? "", want.error_reason ?? "", "ErrorReason");
  assert.deepEqual(
    [...(got.granted_scope ?? [])].sort(),
    [...(want.granted_scope ?? [])].sort(),
    "GrantedScope",
  );
}

function runScopeFixture(fx: FixtureFile): void {
  assert.ok(fx.scope_input, "scope fixture missing scope_input");
  assert.ok(fx.expected.expanded_scopes, "scope fixture missing expected.expanded_scopes");
  const got = expandScopes(fx.scope_input);
  const want = [...fx.expected.expanded_scopes].sort();
  assert.deepEqual(got, want, "ExpandScopes output mismatch");
}

async function runRevocationFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.revocation_list, "revocation fixture missing revocation_list");
  assert.ok(fx.entities && fx.entities.length > 0, "revocation fixture missing issuer entity");
  const list = decodeRevocationList(fx.revocation_list);

  const gotHex = hexEncode(revocationSignBytes(list));
  assert.equal(
    gotHex,
    fx.expected.revocation_sign_bytes_hex,
    "revocation sign bytes drift",
  );

  const issuerPub = decodeHybridPubKey(fx.entities[0]!.public_key);
  const valid = await verifyRevocationList(list, issuerPub);
  assert.equal(valid, true, "revocation list signature failed to verify");
}

async function runSessionTokenFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.session_token, "session_token fixture missing session_token block");
  const st = fx.session_token!;
  const token = decodeSessionToken(st.token);

  // Canonical MAC-input bytes must be byte-identical across SDKs.
  const gotSignHex = hexEncode(sessionTokenSignBytes(token));
  assert.equal(
    gotSignHex,
    fx.expected.session_token_sign_bytes_hex,
    "session_token sign bytes drift",
  );
  assert.equal(
    hexEncode(token.mac),
    fx.expected.session_token_mac_hex,
    "session_token MAC drift",
  );

  const secret = hexDecodeStandalone(st.session_secret_hex);
  const challenge = base64StandardDecode(st.challenge);
  const challengeSig = decodeHybridSignature(st.challenge_sig);
  const result = await verifyStreamedTurn(
    token,
    secret,
    challenge,
    st.challenge_at,
    challengeSig,
    undefined,
    undefined,
    undefined,
    st.verify_now,
  );
  const want = fx.expected.streamed_turn!;
  assert.equal(result.valid, want.valid, "streamed_turn.valid");
  assert.equal(
    result.identity_status,
    want.identity_status,
    "streamed_turn.identity_status",
  );
  assert.equal(result.human_id ?? "", want.human_id ?? "", "streamed_turn.human_id");
  assert.equal(result.agent_id ?? "", want.agent_id ?? "", "streamed_turn.agent_id");
  assert.equal(
    result.error_reason ?? "",
    want.error_reason ?? "",
    "streamed_turn.error_reason",
  );
  assert.deepEqual(
    [...(result.granted_scope ?? [])].sort(),
    [...(want.granted_scope ?? [])].sort(),
    "streamed_turn.granted_scope",
  );
}

async function runKeyRotationFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.key_rotation, "key_rotation fixture missing key_rotation");
  const stmt = decodeKeyRotation(fx.key_rotation);

  const gotHex = hexEncode(keyRotationSignBytes(stmt));
  assert.equal(
    gotHex,
    fx.expected.key_rotation_sign_bytes_hex,
    "key rotation sign bytes drift",
  );

  const err = await verifyKeyRotationStatementE(stmt);
  assert.equal(err === null, fx.expected.key_rotation_verify_ok);
  assert.equal(err ?? "", fx.expected.key_rotation_error_reason ?? "");
}

function decodeReceiptParty(raw: Record<string, unknown>): ReceiptParty {
  return {
    party_id: raw.party_id as string,
    role: raw.role as string,
    agent_id: raw.agent_id as string,
    agent_pub_key: decodeHybridPubKey(raw.agent_pub_key as JsonHybridPublicKey),
    proof_bundle: decodeBundle(raw.proof_bundle as Record<string, unknown>),
  };
}

function decodeReceiptPartySignature(raw: Record<string, unknown>): ReceiptPartySignature {
  return {
    party_id: raw.party_id as string,
    signature: decodeHybridSignature(raw.signature as JsonHybridSignature),
  };
}

function decodeTransactionReceipt(raw: Record<string, unknown>): TransactionReceipt {
  return {
    version: raw.version as number,
    transaction_id: raw.transaction_id as string,
    created_at: raw.created_at as number,
    terms_schema_uri: raw.terms_schema_uri as string,
    terms_canonical_json: base64StandardDecode(raw.terms_canonical_json as string),
    parties: (raw.parties as Array<Record<string, unknown>>).map(decodeReceiptParty),
    party_signatures: (raw.party_signatures as Array<Record<string, unknown>>).map(decodeReceiptPartySignature),
  };
}

async function runTransactionReceiptFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.transaction_receipt, "transaction_receipt fixture missing transaction_receipt");
  const receipt = decodeTransactionReceipt(fx.transaction_receipt);

  // Cross-check canonical signable bytes.
  if (fx.expected.receipt_sign_bytes_hex) {
    const gotHex = hexEncode(transactionReceiptSignBytes(receipt));
    assert.equal(
      gotHex,
      fx.expected.receipt_sign_bytes_hex,
      "receipt sign bytes drift",
    );
  }

  // Run verification and compare expected result.
  const now = fx.timestamps?.verifier_now ?? Math.floor(Date.now() / 1000);
  const result = await verifyTransactionReceipt(receipt, { now });
  assert.equal(result.valid, fx.expected.receipt_valid, "receipt_valid");
  assert.equal(
    result.error_reason ?? "",
    fx.expected.receipt_error_reason ?? "",
    "receipt_error_reason",
  );
}

function decodeRevocationPush(raw: Record<string, unknown>): RevocationPush {
  return {
    issuer_id: raw.issuer_id as string,
    seq_no: raw.seq_no as number,
    entries: (raw.entries as string[]) ?? [],
    pushed_at: raw.pushed_at as number,
    signature: decodeHybridSignature(raw.signature as JsonHybridSignature),
  };
}

async function runRevocationPushFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.revocation_push, "revocation_push fixture missing revocation_push");
  assert.ok(fx.entities && fx.entities.length > 0, "revocation_push fixture missing issuer entity");
  const push = decodeRevocationPush(fx.revocation_push);

  // Cross-check canonical signing bytes.
  const gotHex = hexEncode(revocationPushSignBytes(push));
  assert.equal(
    gotHex,
    fx.expected.revocation_push_sign_bytes_hex,
    "revocation push sign bytes drift",
  );

  // Cross-check signature component hex values.
  assert.equal(
    hexEncode(push.signature.ed25519),
    fx.expected.revocation_push_signature_ed25519_hex,
    "revocation push ed25519 signature drift",
  );
  assert.equal(
    hexEncode(push.signature.ml_dsa_65),
    fx.expected.revocation_push_signature_ml_dsa_65_hex,
    "revocation push ml_dsa_65 signature drift",
  );

  // Verify hybrid signature against issuer's public key.
  const issuerPub = decodeHybridPubKey(fx.entities[0]!.public_key);
  const valid = await verifyRevocationPush(push, issuerPub);
  assert.equal(valid, true, "revocation push signature failed to verify");
}

function decodeWitnessEntry(raw: Record<string, unknown>): WitnessEntry {
  return {
    prev_hash: base64StandardDecode(raw.prev_hash as string),
    entry_data: base64StandardDecode(raw.entry_data as string),
    timestamp: raw.timestamp as number,
    witness_id: raw.witness_id as string,
    signature: decodeHybridSignature(raw.signature as JsonHybridSignature),
  };
}

async function runWitnessEntryFixture(fx: FixtureFile): Promise<void> {
  assert.ok(fx.witness_entry, "witness_entry fixture missing witness_entry");
  assert.ok(fx.entities && fx.entities.length > 0, "witness_entry fixture missing witness entity");
  const entry = decodeWitnessEntry(fx.witness_entry);

  // Cross-check canonical signing bytes.
  const gotHex = hexEncode(witnessEntrySignBytes(entry));
  assert.equal(
    gotHex,
    fx.expected.witness_entry_sign_bytes_hex,
    "witness entry sign bytes drift",
  );

  // Cross-check signature component hex values.
  assert.equal(
    hexEncode(entry.signature.ed25519),
    fx.expected.witness_entry_signature_ed25519_hex,
    "witness entry ed25519 signature drift",
  );
  assert.equal(
    hexEncode(entry.signature.ml_dsa_65),
    fx.expected.witness_entry_signature_ml_dsa_65_hex,
    "witness entry ml_dsa_65 signature drift",
  );

  // Verify hybrid signature against witness's public key.
  const witnessPub = decodeHybridPubKey(fx.entities[0]!.public_key);
  const valid = await verifyWitnessEntry(entry, witnessPub);
  assert.equal(valid, true, "witness entry signature failed to verify");
}
