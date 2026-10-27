// Protocol v2 transaction receipt: canonical terms bound to one signed v2
// proof per party, with typed party statements (0x0007). Port of
// transaction_receipt_v2.go.

import { sha256, sha384 } from "@noble/hashes/sha2";

import { V2_OBJECT_TYPE, validateHybridKeyPairV2, type HybridKeyPairV2, type V2SignOptions } from "./crypto_v2.js";
import { validV2Timestamp } from "./clock_bounds_v2.js";
import { MAX_TRANSACTION_RECEIPT_BYTES_V2, checkV2WireSize } from "./limits_v2.js";
import { signV2StatementWithSigner, signerPublicKeyV2, withLocalSignerV2, type SignOptionsV2, type SignerV2 } from "./signer_v2.js";
import { classified, classifiedAsync, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  RawJSON,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  compareBytes,
  concatBytes,
  gBytes,
  gInt,
  gString,
  gStruct,
  isValidUTF8,
  isWellFormedString,
  parseJSONV2,
  rawSlice,
  rejectV2UnexpectedNull,
  requireV2Fields,
  uint64BE,
  utf8,
  type Fields,
  type JNode,
} from "./json_v2.js";
import { buildSessionContextV2 } from "./operation_context_v2.js";
import {
  bundleHashOfBytesV2,
  bundleHashV2,
  decodeHybridKey,
  decodeHybridSignature,
  decodeProofBundleV2,
  encodeProofBundleV2,
  equalHybridPublicKeys,
  keyIDV2,
  keyWire,
  validV2ID,
  verifyProofBundleV2Signatures,
  verifyV2Statement,
  type ProofBundleV2,
} from "./protocol_v2_wire.js";
import { validateRequiredScopeV2 } from "./scope_v2.js";
import { validPrefixedDigestV2 } from "./verification_receipt_v2.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

export const MAX_TRANSACTION_RECEIPT_BYTES = 5 << 20;
export const MAX_TRANSACTION_PARTIES = 32;
const MAX_SAFE = MAX_SAFE_INTEGER_V2;
const WORKSPACE_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface TransactionReceiptPartyV2 {
  party_id: string;
  role: string;
  agent_id: string;
  agent_pub_key: HybridPublicKey;
  verifier_id: string;
  workspace_id: string;
  session_id: string;
  invocation_id: string;
  required_scope: string;
  proof_bundle_hash: string;
  proof_bundle: ProofBundleV2 | null;
}

export interface TransactionReceiptSignatureV2 {
  party_id: string;
  signature: HybridSignature;
}

export interface TransactionReceiptV2 {
  version: number;
  transaction_id: string;
  created_at: number;
  terms_schema_uri: string;
  terms_canonical_json: Uint8Array;
  parties: TransactionReceiptPartyV2[];
  party_signatures: TransactionReceiptSignatureV2[];
}

const RECEIPT_FIELDS = ["version", "transaction_id", "created_at", "terms_schema_uri", "terms_canonical_json", "parties", "party_signatures"];
const PARTY_FIELDS = ["agent_id", "agent_pub_key", "invocation_id", "party_id", "proof_bundle", "proof_bundle_hash", "required_scope", "role", "session_id", "verifier_id", "workspace_id"];
const SIGNATURE_FIELDS = ["party_id", "signature"];

const lp = (value: Uint8Array) => concatBytes(uint64BE(value.length), value);
const byPartyID = (a: { party_id: string }, b: { party_id: string }) => compareBytes(utf8(a.party_id), utf8(b.party_id));

/** The exact 0x0007 signable bytes: proof bundles and signatures excluded, parties sorted. */
export function transactionReceiptV2SignBytes(r: TransactionReceiptV2): Uint8Array {
  return classified("malformed", () => {
    if (!r || !r.parties || r.parties.length === 0) throw new Error("v2 transaction receipt and parties are required");
    if (r.parties.length > MAX_TRANSACTION_PARTIES) {
      throw new Error(`v2 transaction receipt exceeds MAX_TRANSACTION_PARTIES (${MAX_TRANSACTION_PARTIES})`);
    }
    const parties = r.parties.map((p) => ({
      agent_id: p.agent_id, agent_pub_key: keyWire(p.agent_pub_key), invocation_id: p.invocation_id, party_id: p.party_id,
      proof_bundle_hash: p.proof_bundle_hash, required_scope: p.required_scope, role: p.role, session_id: p.session_id,
      verifier_id: p.verifier_id, workspace_id: p.workspace_id,
    })).sort(byPartyID);
    return canonicalJSONV2({
      created_at: r.created_at, parties, terms_canonical_json: r.terms_canonical_json,
      terms_schema_uri: r.terms_schema_uri, transaction_id: r.transaction_id, version: r.version,
    });
  });
}

export function transactionContextHashV2(r: TransactionReceiptV2): Uint8Array {
  return sha256(concatBytes(
    utf8("ratify/transaction-context/v2"), lp(utf8(r.transaction_id)), lp(utf8(r.terms_schema_uri)), sha384(r.terms_canonical_json),
  ));
}

export function transactionPartyRequestHashV2(transactionHash: Uint8Array, requiredScope: string): Uint8Array {
  return sha256(concatBytes(utf8("ratify/transaction-party-request/v2"), lp(transactionHash), lp(utf8(requiredScope))));
}

function termsCanonical(n: JNode): unknown {
  switch (n.k) {
    case "null": return null;
    case "bool": return n.v;
    case "str": return n.v;
    case "num": {
      if (n.raw === "-0" || /[.eE]/.test(n.raw)) throw new Error("non-integer JSON numbers are not permitted");
      const v = BigInt(n.raw);
      if (v > BigInt(MAX_SAFE) || v < -BigInt(MAX_SAFE)) throw new Error("JSON integer is outside the safe-integer range");
      return new RawJSON(utf8(n.raw));
    }
    case "arr": return n.a.map(termsCanonical);
    case "obj": {
      const out: Record<string, unknown> = {};
      for (const [k, v] of n.m) Object.defineProperty(out, k, { value: termsCanonical(v), enumerable: true, configurable: true, writable: true });
      return out;
    }
  }
}

/** Terms must be one canonical Ratify JSON object with integers only. */
export function validateCanonicalTransactionTermsV2(data: Uint8Array): void {
  if (!isValidUTF8(data)) throw new Error("terms are not valid UTF-8");
  const root = parseJSONV2(data, { rejectDuplicates: true, limitDepth: true });
  if (root.k !== "obj") throw new Error("terms must be a JSON object");
  const canonical = canonicalJSONV2(termsCanonical(root));
  if (!bytesEqual(canonical, data)) throw new Error("terms bytes differ from RatifyCanonicalJSON");
}

async function validateTransactionReceiptV2(r: TransactionReceiptV2, requireSignatures: boolean): Promise<void> {
  if (!r || r.version !== 2 || !r.transaction_id || !validV2Timestamp(r.created_at) ||
      !r.terms_schema_uri || !(r.terms_canonical_json instanceof Uint8Array) || r.terms_canonical_json.length === 0 ||
      !r.parties || r.parties.length === 0) {
    throw new Error("wire v2: transaction receipt header or terms are invalid");
  }
  if (r.parties.length > MAX_TRANSACTION_PARTIES) {
    throw new Error(`wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES (${MAX_TRANSACTION_PARTIES})`);
  }
  try {
    validateCanonicalTransactionTermsV2(r.terms_canonical_json);
  } catch (err) {
    throw wrapError("wire v2: transaction terms are not canonical Ratify JSON", err);
  }
  if (!isWellFormedString(r.transaction_id) || !isWellFormedString(r.terms_schema_uri)) {
    throw new Error("wire v2: transaction header is not valid UTF-8");
  }
  const seenParties = new Set<string>();
  const seenAgents = new Set<string>();
  const transactionHash = transactionContextHashV2(r);
  for (let i = 0; i < r.parties.length; i++) {
    const p = r.parties[i]!;
    for (const value of [p.party_id, p.role, p.session_id, p.invocation_id]) {
      if (!isWellFormedString(value)) throw new Error(`wire v2: transaction party ${i} text is not valid UTF-8`);
    }
    if (!p.party_id || !p.role || !p.session_id || !p.invocation_id || !validV2ID(p.verifier_id) ||
        !WORKSPACE_PATTERN.test(p.workspace_id) || !validV2ID(p.agent_id)) {
      throw new Error(`wire v2: transaction party ${i} has invalid identity or context fields`);
    }
    if (i > 0 && byPartyID(r.parties[i - 1]!, p) >= 0) throw new Error("wire v2: transaction parties must be sorted by unique party_id");
    if (seenParties.has(p.party_id)) throw new Error(`wire v2: duplicate transaction party ${JSON.stringify(p.party_id)}`);
    seenParties.add(p.party_id);
    if (seenAgents.has(p.agent_id)) throw new Error(`wire v2: agent ${JSON.stringify(p.agent_id)} cannot represent multiple transaction parties`);
    seenAgents.add(p.agent_id);
    const scopeErr = validateRequiredScopeV2(p.required_scope);
    if (scopeErr) throw new Error(`wire v2: party ${JSON.stringify(p.party_id)} required_scope: ${scopeErr}`);
    const bundle = p.proof_bundle;
    if (!bundle) throw new Error(`wire v2: party ${JSON.stringify(p.party_id)} proof_bundle is required`);
    let keyID = "";
    try {
      keyID = keyIDV2(p.agent_pub_key);
    } catch {
      keyID = "";
    }
    if (keyID === "" || keyID !== p.agent_id) {
      throw v2Errorf("key_id_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} agent ID does not match its complete public key`);
    }
    if (!validPrefixedDigestV2(p.proof_bundle_hash)) {
      throw v2Errorf("malformed", `wire v2: party ${JSON.stringify(p.party_id)} proof_bundle_hash is not sha384: followed by 96 lowercase hex characters`);
    }
    let bundleHash = "";
    try {
      bundleHash = bundleHashV2(bundle);
    } catch {
      bundleHash = "";
    }
    if (bundleHash === "" || bundleHash !== p.proof_bundle_hash) {
      throw v2Errorf("bundle_hash_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} proof_bundle_hash does not match its bundle`);
    }
    try {
      await verifyProofBundleV2Signatures(bundle);
    } catch (err) {
      throw wrapError(`wire v2: party ${JSON.stringify(p.party_id)} proof bundle signature`, err);
    }
    const certs = bundle.delegations ?? [];
    if (certs.length === 0) {
      // SPEC-v2 §5.7: a transaction party must present delegated authority.
      throw v2Errorf("transaction_party_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} proof bundle has no delegation certificates`);
    }
    if (bundle.agent_id !== p.agent_id || !equalHybridPublicKeys(bundle.agent_pub_key, p.agent_pub_key) ||
        bundle.verifier_id !== p.verifier_id || certs.length === 0 || certs[0]!.subject_id !== p.agent_id) {
      throw v2Errorf("transaction_party_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} proof bundle identity does not match its signed party`);
    }
    let expected: Uint8Array | null = null;
    try {
      expected = buildSessionContextV2({
        verifier_id: p.verifier_id, workspace_id: p.workspace_id, agent_id: p.agent_id, session_id: p.session_id,
        invocation_id: p.invocation_id, request_hash: transactionPartyRequestHashV2(transactionHash, p.required_scope),
      });
    } catch {
      expected = null;
    }
    if (expected === null || bundle.session_context === null || !bytesEqual(bundle.session_context, expected)) {
      throw v2Errorf("transaction_context_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} proof bundle session context does not bind this transaction and scope`);
    }
  }
  if (requireSignatures) {
    const sigs = r.party_signatures ?? [];
    if (sigs.length !== r.parties.length) {
      throw v2Errorf("transaction_signature_set_invalid", "wire v2: transaction receipt must have one signature per party");
    }
    const seen = new Set<string>();
    for (const item of sigs) {
      if (!seenParties.has(item.party_id) || seen.has(item.party_id)) {
        throw v2Errorf("transaction_signature_set_invalid", `wire v2: unknown or duplicate transaction party signature ${JSON.stringify(item.party_id)}`);
      }
      seen.add(item.party_id);
    }
  }
  transactionReceiptV2SignBytes(r);
}

/**
 * Checks typed party signatures, bundle hashes, party-key bindings and the
 * transaction-derived session context. Does not resolve trust or status.
 */
export async function verifyTransactionReceiptV2Signatures(r: TransactionReceiptV2): Promise<void> {
  return classifiedAsync("malformed", async () => {
    try {
      await validateTransactionReceiptV2(r, true);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    let signable: Uint8Array;
    try {
      signable = transactionReceiptV2SignBytes(r);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    const signatures = new Map<string, HybridSignature>();
    for (const item of r.party_signatures) {
      if (signatures.has(item.party_id)) {
        throw v2Errorf("transaction_signature_set_invalid", `v2 transaction receipt has duplicate signature for party ${JSON.stringify(item.party_id)}`);
      }
      signatures.set(item.party_id, item.signature);
    }
    if (signatures.size !== r.parties.length) {
      throw v2Errorf("transaction_signature_set_invalid", "v2 transaction receipt must contain exactly one signature per party");
    }
    for (const p of r.parties) {
      const sig = signatures.get(p.party_id);
      if (!sig) throw v2Errorf("transaction_signature_set_invalid", `v2 transaction receipt is missing signature for party ${JSON.stringify(p.party_id)}`);
      try {
        await verifyV2Statement(V2_OBJECT_TYPE.transactionPartyStatement, signable, sig, p.agent_pub_key);
      } catch (err) {
        throw wrapError(`v2 transaction receipt signature for party ${JSON.stringify(p.party_id)}`, err);
      }
    }
  });
}

/** Signs the shared transaction statement with one listed party's key. */
export async function signTransactionReceiptPartyV2(r: TransactionReceiptV2, partyID: string, key: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<TransactionReceiptSignatureV2> {
  return classifiedAsync("malformed", async () => {
    if (!r) throw new Error("transaction receipt is required");
    const party = r.parties.find((p) => p.party_id === partyID);
    if (!party) throw v2Errorf("transaction_party_mismatch", `party ${JSON.stringify(partyID)} is not listed in the transaction receipt`);
    await validateHybridKeyPairV2(key);
    return withLocalSignerV2(key, { deterministic: opts.deterministic }, (signer) => signTransactionReceiptPartyV2WithSigner(r, partyID, signer));
  });
}

/** signTransactionReceiptPartyV2 through a signer whose key must equal the party agent key. */
export async function signTransactionReceiptPartyV2WithSigner(r: TransactionReceiptV2, partyID: string, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<TransactionReceiptSignatureV2> {
  return classifiedAsync("malformed", async () => {
    if (!r) throw new Error("transaction receipt is required");
    const party = r.parties.find((p) => p.party_id === partyID);
    if (!party) throw v2Errorf("transaction_party_mismatch", `party ${JSON.stringify(partyID)} is not listed in the transaction receipt`);
    const partyPublic = await signerPublicKeyV2(signer);
    if (!equalHybridPublicKeys(partyPublic, party.agent_pub_key)) {
      throw v2Errorf("key_id_mismatch", `signing key does not match party ${JSON.stringify(partyID)} agent public key`);
    }
    try {
      await validateTransactionReceiptV2(r, false);
    } catch (err) {
      throw wrapError("cannot sign invalid transaction receipt", err);
    }
    const signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.transactionPartyStatement, transactionReceiptV2SignBytes(r), signer, partyPublic, opts);
    return { party_id: partyID, signature };
  });
}

function encodeTransactionReceiptV2Canonical(r: TransactionReceiptV2): Uint8Array {
  const parties = r.parties.map((p) => ({
    agent_id: p.agent_id, agent_pub_key: keyWire(p.agent_pub_key), invocation_id: p.invocation_id, party_id: p.party_id,
    proof_bundle: new RawJSON(encodeProofBundleV2(p.proof_bundle!)), proof_bundle_hash: p.proof_bundle_hash,
    required_scope: p.required_scope, role: p.role, session_id: p.session_id, verifier_id: p.verifier_id, workspace_id: p.workspace_id,
  }));
  const signatures = [...r.party_signatures].sort(byPartyID).map((s) => ({ party_id: s.party_id, signature: keyWire(s.signature) }));
  const encoded = canonicalJSONV2({
    created_at: r.created_at, parties, party_signatures: signatures, terms_canonical_json: r.terms_canonical_json,
    terms_schema_uri: r.terms_schema_uri, transaction_id: r.transaction_id, version: r.version,
  });
  if (encoded.length > MAX_TRANSACTION_RECEIPT_BYTES) {
    throw new Error(`wire v2: transaction receipt exceeds MAX_TRANSACTION_RECEIPT_BYTES (${MAX_TRANSACTION_RECEIPT_BYTES})`);
  }
  return encoded;
}

/** Canonical wire JSON after validating every party and embedded proof signature. */
export async function encodeTransactionReceiptV2(r: TransactionReceiptV2): Promise<Uint8Array> {
  return classifiedAsync("malformed", async () => {
    await verifyTransactionReceiptV2Signatures(r);
    return encodeTransactionReceiptV2Canonical(r);
  });
}

/**
 * Strict decode, including party signatures and embedded bundle identity and
 * context bindings. Trust, status, freshness and final scope authorization
 * are not inferred by this codec.
 */
// Every party and party-signature member is required: an object missing one
// does not spell the value it would decode to (SPEC-v2 §2.1).
function requireAllMembers(f: Fields, names: readonly string[], what: string): Fields {
  for (const name of names) if (!f.has(name)) throw new Error(`wire v2: ${what} member ${JSON.stringify(name)} is missing`);
  return f;
}

export async function decodeTransactionReceiptV2(data: Uint8Array): Promise<TransactionReceiptV2> {
  try {
    checkV2WireSize(data, "transaction receipt", "MAX_TRANSACTION_RECEIPT_BYTES_V2", MAX_TRANSACTION_RECEIPT_BYTES_V2);
    const root = checkWireJSONV2(data, ["terms_canonical_json"]);
    if (root.k !== "obj") throw new Error("wire v2: transaction receipt must be a JSON object");
    requireV2Fields(root, RECEIPT_FIELDS);
    const partiesNode = root.m.get("parties")!;
    if (partiesNode.k !== "arr") throw new Error("wire v2: transaction receipt parties must be an array");
    if (partiesNode.a.length > MAX_TRANSACTION_PARTIES) {
      throw new Error(`wire v2: transaction receipt exceeds MAX_TRANSACTION_PARTIES (${MAX_TRANSACTION_PARTIES})`);
    }
    const f = gStruct(root, RECEIPT_FIELDS, "transaction receipt");
    rejectV2UnexpectedNull(root);
    const partyStructs = partiesNode.a.map((n) => requireAllMembers(gStruct(n, PARTY_FIELDS, "transaction party"), PARTY_FIELDS, "transaction party"));
    const sigNode = f.get("party_signatures")!;
    if (sigNode.k !== "arr") throw new Error("wire v2: party_signatures must be an array");
    for (const n of sigNode.a) requireAllMembers(gStruct(n, SIGNATURE_FIELDS, "party signature"), SIGNATURE_FIELDS, "party signature");
    const receipt: TransactionReceiptV2 = {
      version: gInt(f.get("version"), "version"),
      transaction_id: gString(f.get("transaction_id"), "transaction_id"),
      created_at: gInt(f.get("created_at"), "created_at"),
      terms_schema_uri: gString(f.get("terms_schema_uri"), "terms_schema_uri"),
      terms_canonical_json: gBytes(f.get("terms_canonical_json"), "terms_canonical_json") ?? new Uint8Array(0),
      parties: [],
      party_signatures: sigNode.a.map((n) => {
        const s = gStruct(n, SIGNATURE_FIELDS, "party signature");
        return { party_id: gString(s.get("party_id"), "party_id"), signature: decodeHybridSignature(s.get("signature"), "signature") };
      }),
    };
    const typed = partyStructs.map((p) => ({
      party_id: gString(p.get("party_id"), "party_id"),
      role: gString(p.get("role"), "role"),
      agent_id: gString(p.get("agent_id"), "agent_id"),
      agent_pub_key: decodeHybridKey(p.get("agent_pub_key"), "agent_pub_key"),
      verifier_id: gString(p.get("verifier_id"), "verifier_id"),
      workspace_id: gString(p.get("workspace_id"), "workspace_id"),
      session_id: gString(p.get("session_id"), "session_id"),
      invocation_id: gString(p.get("invocation_id"), "invocation_id"),
      required_scope: gString(p.get("required_scope"), "required_scope"),
      proof_bundle_hash: gString(p.get("proof_bundle_hash"), "proof_bundle_hash"),
      raw: p.get("proof_bundle"),
    }));
    const bundleHashes: string[] = [];
    for (let i = 0; i < typed.length; i++) {
      const p = typed[i]!;
      if (p.raw === undefined || p.raw.k !== "obj") throw new Error(`wire v2: party ${i} proof_bundle must be a JSON object`);
      const raw = rawSlice(data, p.raw);
      // The nested bundle is decoded strictly, and must be in canonical form
      // like the whole receipt, before its hash is compared, so a malformed
      // bundle is malformed rather than bundle_hash_mismatch.
      let bundle: ProofBundleV2;
      try {
        bundle = decodeProofBundleV2(raw);
      } catch (err) {
        throw wrapError(`wire v2: party ${JSON.stringify(p.party_id)} proof bundle`, err);
      }
      let canonicalBundle: Uint8Array | null = null;
      try {
        canonicalBundle = encodeProofBundleV2(bundle);
      } catch {
        canonicalBundle = null;
      }
      if (canonicalBundle === null || !bytesEqual(canonicalBundle, raw)) {
        throw new Error(`wire v2: party ${JSON.stringify(p.party_id)} proof bundle is not canonical JSON`);
      }
      // The hash field's shape is checked before it is compared (SPEC-v2
      // §5.7, §2.7): a misshapen value is malformed, not a mismatch.
      if (!validPrefixedDigestV2(p.proof_bundle_hash)) {
        throw v2Errorf("malformed", `wire v2: party ${JSON.stringify(p.party_id)} proof_bundle_hash is not sha384: followed by 96 lowercase hex characters`);
      }
      bundleHashes.push(bundleHashOfBytesV2(raw));
      const { raw: _raw, ...rest } = p;
      void _raw;
      receipt.parties.push({ ...rest, proof_bundle: bundle });
    }
    // Canonical form is part of strict decode (SPEC-v2 §2.1), so it is
    // checked before any bundle hash, binding or signature: a non-canonical
    // receipt is malformed whatever else is wrong with it.
    const canonical = encodeTransactionReceiptV2Canonical(receipt);
    if (!bytesEqual(canonical, data)) throw new Error("wire v2: transaction receipt is not canonical JSON");
    receipt.parties.forEach((p, i) => {
      if (p.proof_bundle_hash !== bundleHashes[i]) {
        throw v2Errorf("bundle_hash_mismatch", `wire v2: party ${JSON.stringify(p.party_id)} proof_bundle_hash does not match its canonical bundle bytes`);
      }
    });
    await verifyTransactionReceiptV2Signatures(receipt);
    return receipt;
  } catch (err) {
    throw v2Classify("malformed", err);
  }
}

