// Ratify Protocol v1 — hybrid (Ed25519 + ML-DSA-65) crypto primitives.
//
// Uses:
//   @noble/ed25519       audited, universal (Node/browser/Deno)
//   @noble/post-quantum  audited, ML-DSA-65 per FIPS 204
//   @noble/hashes        SHA-256 for ID derivation
//
// Every sign produces BOTH component signatures. Every verify checks BOTH;
// either failure fails the whole signature.

import * as ed from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import { canonicalJSON, hexEncode } from "./canonical.js";
import type {
  AgentIdentity,
  Constraint,
  DelegationCert,
  HumanRoot,
  HybridPrivateKey,
  HybridPublicKey,
  HybridSignature,
  KeyRotationReason,
  KeyRotationStatement,
  ProofBundle,
  ReceiptPartySignature,
  RevocationList,
  RevocationPush,
  SessionToken,
  TransactionReceipt,
  VerifyResult,
  WitnessEntry,
} from "./types.js";

// ============================================================================
// ID derivation
// ============================================================================

/**
 * hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16]) — the canonical Ratify ID
 * for a HybridPublicKey. 128-bit collision space (2^64 birthday bound).
 */
export function deriveID(pub: HybridPublicKey): string {
  const buf = new Uint8Array(pub.ed25519.length + pub.ml_dsa_65.length);
  buf.set(pub.ed25519, 0);
  buf.set(pub.ml_dsa_65, pub.ed25519.length);
  const h = sha256(buf);
  return hexEncode(h.slice(0, 16));
}

// ============================================================================
// Keypair generation
// ============================================================================

/**
 * Generate a fresh hybrid keypair from OS randomness. Two independent
 * 32-byte seeds; knowledge of one component's secret reveals nothing about
 * the other's.
 */
export async function generateHybridKeypair(): Promise<{
  publicKey: HybridPublicKey;
  privateKey: HybridPrivateKey;
}> {
  // Ed25519: @noble's 32-byte "private key" is the seed; getPublicKey expands
  // via SHA-512 internally.
  const edSeed = ed.utils.randomPrivateKey();
  const edPub = await ed.getPublicKeyAsync(edSeed);

  // ML-DSA-65: keygen takes a 32-byte seed, returns {secretKey, publicKey}.
  const mlSeed = new Uint8Array(32);
  crypto.getRandomValues(mlSeed);
  const ml = ml_dsa65.keygen(mlSeed);

  return {
    publicKey: { ed25519: edPub, ml_dsa_65: ml.publicKey },
    privateKey: { ed25519: edSeed, ml_dsa_65: ml.secretKey },
  };
}

/**
 * Derive a deterministic hybrid keypair from two 32-byte seeds. Used for
 * test-vector regeneration and any application needing reproducible
 * keypairs. Production code SHOULD prefer generateHybridKeypair().
 */
export async function hybridKeypairFromSeeds(
  edSeed: Uint8Array,
  mlSeed: Uint8Array,
): Promise<{ publicKey: HybridPublicKey; privateKey: HybridPrivateKey }> {
  if (edSeed.length !== 32)
    throw new Error(`Ed25519 seed must be 32 bytes, got ${edSeed.length}`);
  if (mlSeed.length !== 32)
    throw new Error(`ML-DSA-65 seed must be 32 bytes, got ${mlSeed.length}`);

  const edPub = await ed.getPublicKeyAsync(edSeed);
  const ml = ml_dsa65.keygen(mlSeed);

  return {
    publicKey: { ed25519: edPub, ml_dsa_65: ml.publicKey },
    privateKey: { ed25519: edSeed, ml_dsa_65: ml.secretKey },
  };
}

/** Generate a new HumanRoot identity with a hybrid keypair. */
export async function generateHumanRoot(): Promise<{
  root: HumanRoot;
  privateKey: HybridPrivateKey;
}> {
  const { publicKey, privateKey } = await generateHybridKeypair();
  return {
    root: {
      id: deriveID(publicKey),
      public_key: publicKey,
      created_at: Math.floor(Date.now() / 1000),
    },
    privateKey,
  };
}

/** Generate a new AgentIdentity keypair. */
export async function generateAgent(
  name: string,
  agentType: string,
): Promise<{ agent: AgentIdentity; privateKey: HybridPrivateKey }> {
  const { publicKey, privateKey } = await generateHybridKeypair();
  return {
    agent: {
      id: deriveID(publicKey),
      public_key: publicKey,
      name,
      agent_type: agentType,
      created_at: Math.floor(Date.now() / 1000),
    },
    privateKey,
  };
}

// ============================================================================
// Canonical signing bytes — MUST match Go reference byte-for-byte.
// ============================================================================

/**
 * Canonical bytes signed to produce DelegationCert.signature (both algorithm
 * components sign the same bytes).
 */
export function delegationSignBytes(cert: DelegationCert): Uint8Array {
  // Signable subset = all cert fields except `signature`. canonicalJSON sorts
  // keys lex; we list them here for readability (alphabetical order).
  // `constraints` is ALWAYS serialized as an array — [] when absent — so
  // canonical bytes are deterministic across implementations.
  // Each Constraint is projected to its canonical per-kind shape so that
  // zero-valued kind-relevant fields (e.g. lat=0 on the equator) are
  // emitted explicitly, closing the zero-as-absence ambiguity.
  const signable = {
    cert_id: cert.cert_id,
    constraints: (cert.constraints ?? []).map(canonicalConstraintDict),
    expires_at: cert.expires_at,
    issued_at: cert.issued_at,
    issuer_id: cert.issuer_id,
    issuer_pub_key: cert.issuer_pub_key,
    scope: cert.scope,
    subject_id: cert.subject_id,
    subject_pub_key: cert.subject_pub_key,
    version: cert.version,
  };
  return canonicalJSON(signable);
}

// canonicalConstraintDict returns the object shape the canonical JSON
// encoder should emit for one Constraint, by kind. Kind-relevant fields
// are always included (zero values preserved); irrelevant fields are
// omitted entirely. Mirrors Go's Constraint.MarshalJSON.
function canonicalConstraintDict(c: Constraint): Record<string, unknown> {
  const out: Record<string, unknown> = { type: c.type };
  switch (c.type) {
    case "geo_circle":
      out.lat = c.lat ?? 0;
      out.lon = c.lon ?? 0;
      out.radius_m = c.radius_m ?? 0;
      break;
    case "geo_polygon":
      out.points = c.points ?? [];
      break;
    case "geo_bbox":
      out.max_lat = c.max_lat ?? 0;
      out.max_lon = c.max_lon ?? 0;
      out.min_lat = c.min_lat ?? 0;
      out.min_lon = c.min_lon ?? 0;
      if ((c.min_alt_m ?? 0) !== 0 || (c.max_alt_m ?? 0) !== 0) {
        out.max_alt_m = c.max_alt_m ?? 0;
        out.min_alt_m = c.min_alt_m ?? 0;
      }
      break;
    case "time_window":
      out.end = c.end ?? "";
      out.start = c.start ?? "";
      out.tz = c.tz ?? "";
      break;
    case "max_speed_mps":
      out.max_mps = c.max_mps ?? 0;
      break;
    case "max_amount":
      out.currency = c.currency ?? "";
      out.max_amount = c.max_amount ?? 0;
      break;
    case "max_rate":
      out.count = c.count ?? 0;
      out.window_s = c.window_s ?? 0;
      break;
    // Unknown kind — emit only the tag; verifier returns constraint_unknown.
  }
  return out;
}

/**
 * Canonical bytes signed to produce ProofBundle.challenge_sig. NOT JSON —
 * raw binary:
 *
 *     challenge || big-endian uint64(timestamp)
 *       || [optional 32-byte session_context]
 *       || [optional 32-byte stream_id || big-endian int64(stream_seq)]
 *
 * Order matters: session_context precedes the stream extension so the signable
 * bytes remain well-defined across the four allowed length combinations
 * (40 / 72 / 80 / 112 bytes for a 32-byte challenge).
 */
export function challengeSignBytes(
  challenge: Uint8Array,
  ts: number,
  sessionContext?: Uint8Array,
  streamID?: Uint8Array,
  streamSeq?: number,
): Uint8Array {
  const ctx = sessionContext ?? new Uint8Array(0);
  const stream = streamID ?? new Uint8Array(0);
  const hasStream = stream.length > 0;
  const streamBytes = hasStream ? stream.length + 8 : 0;
  const out = new Uint8Array(challenge.length + 8 + ctx.length + streamBytes);
  let off = 0;
  out.set(challenge, off);
  off += challenge.length;
  writeBigEndianUint64(out, off, ts);
  off += 8;
  out.set(ctx, off);
  off += ctx.length;
  if (hasStream) {
    out.set(stream, off);
    off += stream.length;
    writeBigEndianInt64(out, off, streamSeq ?? 0);
  }
  return out;
}

function writeBigEndianUint64(buf: Uint8Array, offset: number, value: number): void {
  const view = new DataView(buf.buffer, buf.byteOffset + offset, 8);
  const hi = Math.floor(value / 0x1_0000_0000);
  const lo = value >>> 0;
  view.setUint32(0, hi, false);
  view.setUint32(4, lo, false);
}

function writeBigEndianInt64(buf: Uint8Array, offset: number, value: number): void {
  // JS numbers are safe-int up to 2^53; sequence numbers stay well within that
  // bound. Reuse the uint64 writer — two's-complement reinterpretation is
  // fine because stream_seq is required to be ≥1.
  writeBigEndianUint64(buf, offset, value);
}

/** Canonical bytes signed to produce RevocationList.signature. */
export function revocationSignBytes(list: RevocationList): Uint8Array {
  const signable = {
    issuer_id: list.issuer_id,
    revoked_certs: list.revoked_certs,
    updated_at: list.updated_at,
  };
  return canonicalJSON(signable);
}

/** Canonical bytes signed by both old and new keys in KeyRotationStatement. */
export function keyRotationSignBytes(stmt: KeyRotationStatement): Uint8Array {
  const signable = {
    new_id: stmt.new_id,
    new_pub_key: stmt.new_pub_key,
    old_id: stmt.old_id,
    old_pub_key: stmt.old_pub_key,
    reason: stmt.reason,
    rotated_at: stmt.rotated_at,
    version: stmt.version,
  };
  return canonicalJSON(signable);
}

// ============================================================================
// Hybrid sign / verify
// ============================================================================

/**
 * Produce a hybrid signature over `msg` with both component private keys.
 * Both components sign identical bytes. ML-DSA-65 uses FIPS 204's canonical
 * (non-hedged) variant — matches the Go reference's SignTo(randomized=false).
 */
export async function signBoth(
  msg: Uint8Array,
  priv: HybridPrivateKey,
): Promise<HybridSignature> {
  const edSig = await ed.signAsync(msg, priv.ed25519);
  // @noble/post-quantum: sign(msg, secretKey, opts?) — message FIRST.
  // Default opts → deterministic signing (matches Go's SignTo(randomized=false)).
  const mlSig = ml_dsa65.sign(msg, priv.ml_dsa_65);
  return { ed25519: edSig, ml_dsa_65: mlSig };
}

/**
 * Verify a hybrid signature. Both component signatures must verify against
 * their respective public components. Returns null on success; a string
 * describing which check failed on failure. The string matches the Go
 * reference's error messages for cross-language fixture compatibility.
 */
export async function verifyBoth(
  msg: Uint8Array,
  sig: HybridSignature,
  pub: HybridPublicKey,
): Promise<string | null> {
  if (pub.ed25519.length !== 32)
    return `Ed25519 public key wrong length: ${pub.ed25519.length}`;
  if (pub.ml_dsa_65.length !== 1952)
    return `ML-DSA-65 public key wrong length: ${pub.ml_dsa_65.length}`;
  if (sig.ed25519.length !== 64)
    return `Ed25519 signature wrong length: ${sig.ed25519.length}`;
  if (sig.ml_dsa_65.length !== 3309)
    return `ML-DSA-65 signature wrong length: ${sig.ml_dsa_65.length}`;

  let edOk = false;
  try {
    edOk = await ed.verifyAsync(sig.ed25519, msg, pub.ed25519);
  } catch {
    edOk = false;
  }
  if (!edOk) return "Ed25519 signature invalid";

  // @noble/post-quantum: verify(sig, msg, pubKey) — signature FIRST.
  const mlOk = ml_dsa65.verify(sig.ml_dsa_65, msg, pub.ml_dsa_65);
  if (!mlOk) return "ML-DSA-65 signature invalid";
  return null;
}

// ============================================================================
// High-level sign/verify helpers
// ============================================================================

/** Sign a DelegationCert; populates cert.signature with a hybrid pair. */
export async function issueDelegation(
  cert: DelegationCert,
  issuerPrivateKey: HybridPrivateKey,
): Promise<void> {
  cert.signature = await signBoth(delegationSignBytes(cert), issuerPrivateKey);
}

/**
 * Verify a DelegationCert's hybrid signature. Returns null iff both
 * components verify; otherwise returns a diagnostic string matching the
 * Go reference (e.g. "Ed25519 signature invalid").
 */
export async function verifyDelegationSignatureE(
  cert: DelegationCert,
): Promise<string | null> {
  return verifyBoth(delegationSignBytes(cert), cert.signature, cert.issuer_pub_key);
}

/** Verify a DelegationCert's hybrid signature. True iff both components verify. */
export async function verifyDelegationSignature(
  cert: DelegationCert,
): Promise<boolean> {
  return (await verifyDelegationSignatureE(cert)) === null;
}

/** Produce a hybrid challenge signature (for ProofBundle.challenge_sig). */
export async function signChallenge(
  challenge: Uint8Array,
  ts: number,
  agentPrivateKey: HybridPrivateKey,
  sessionContext?: Uint8Array,
  streamID?: Uint8Array,
  streamSeq?: number,
): Promise<HybridSignature> {
  return signBoth(
    challengeSignBytes(challenge, ts, sessionContext, streamID, streamSeq),
    agentPrivateKey,
  );
}

/**
 * Verify a hybrid challenge signature. Returns null iff both components
 * verify; otherwise returns a Go-compatible diagnostic string.
 */
export async function verifyChallengeSignatureE(
  challenge: Uint8Array,
  ts: number,
  sig: HybridSignature,
  agentPublicKey: HybridPublicKey,
  sessionContext?: Uint8Array,
  streamID?: Uint8Array,
  streamSeq?: number,
): Promise<string | null> {
  return verifyBoth(
    challengeSignBytes(challenge, ts, sessionContext, streamID, streamSeq),
    sig,
    agentPublicKey,
  );
}

/** Verify a hybrid challenge signature. True iff both components verify. */
export async function verifyChallengeSignature(
  challenge: Uint8Array,
  ts: number,
  sig: HybridSignature,
  agentPublicKey: HybridPublicKey,
  sessionContext?: Uint8Array,
  streamID?: Uint8Array,
  streamSeq?: number,
): Promise<boolean> {
  return (
    (await verifyChallengeSignatureE(
      challenge,
      ts,
      sig,
      agentPublicKey,
      sessionContext,
      streamID,
      streamSeq,
    )) === null
  );
}

/** Sign a RevocationList with the issuer's hybrid private key. */
export async function issueRevocationList(
  list: RevocationList,
  issuerPrivateKey: HybridPrivateKey,
): Promise<void> {
  list.signature = await signBoth(revocationSignBytes(list), issuerPrivateKey);
}

/** Verify a RevocationList's hybrid signature. True iff both components verify. */
export async function verifyRevocationList(
  list: RevocationList,
  issuerPublicKey: HybridPublicKey,
): Promise<boolean> {
  return (
    (await verifyBoth(revocationSignBytes(list), list.signature, issuerPublicKey)) === null
  );
}

// ============================================================================
// v1.1 RevocationPush sign / verify
// ============================================================================

/** Canonical bytes signed to produce RevocationPush.signature. */
export function revocationPushSignBytes(push: RevocationPush): Uint8Array {
  const signable = {
    entries: push.entries ?? [],
    issuer_id: push.issuer_id,
    pushed_at: push.pushed_at,
    seq_no: push.seq_no,
  };
  return canonicalJSON(signable);
}

/** Sign a RevocationPush with the issuer's hybrid private key. */
export async function issueRevocationPush(
  push: RevocationPush,
  issuerPrivateKey: HybridPrivateKey,
): Promise<void> {
  push.signature = await signBoth(revocationPushSignBytes(push), issuerPrivateKey);
}

/** Verify a RevocationPush's hybrid signature. True iff both components verify. */
export async function verifyRevocationPush(
  push: RevocationPush,
  issuerPublicKey: HybridPublicKey,
): Promise<boolean> {
  return (
    (await verifyBoth(revocationPushSignBytes(push), push.signature, issuerPublicKey)) === null
  );
}

// ============================================================================
// v1.1 WitnessEntry sign / verify
// ============================================================================

/** Canonical bytes signed to produce WitnessEntry.signature. */
export function witnessEntrySignBytes(entry: WitnessEntry): Uint8Array {
  const signable = {
    entry_data: entry.entry_data,
    prev_hash: entry.prev_hash,
    timestamp: entry.timestamp,
    witness_id: entry.witness_id,
  };
  return canonicalJSON(signable);
}

/** Sign a WitnessEntry with the witness operator's hybrid private key. */
export async function issueWitnessEntry(
  entry: WitnessEntry,
  witnessPrivateKey: HybridPrivateKey,
): Promise<void> {
  entry.signature = await signBoth(witnessEntrySignBytes(entry), witnessPrivateKey);
}

/** Verify a WitnessEntry's hybrid signature. True iff both components verify. */
export async function verifyWitnessEntry(
  entry: WitnessEntry,
  witnessPublicKey: HybridPublicKey,
): Promise<boolean> {
  return (
    (await verifyBoth(witnessEntrySignBytes(entry), entry.signature, witnessPublicKey)) === null
  );
}

/** Sign a KeyRotationStatement with both old and new private keys. */
export async function issueKeyRotationStatement(
  stmt: KeyRotationStatement,
  oldPrivateKey: HybridPrivateKey,
  newPrivateKey: HybridPrivateKey,
): Promise<void> {
  const bytes = keyRotationSignBytes(stmt);
  stmt.signature_old = await signBoth(bytes, oldPrivateKey);
  stmt.signature_new = await signBoth(bytes, newPrivateKey);
}

/**
 * Verify key continuity, key possession, and ID/pubkey consistency for a
 * KeyRotationStatement. Returns null on success, diagnostic string on failure.
 */
export async function verifyKeyRotationStatementE(
  stmt: KeyRotationStatement,
): Promise<string | null> {
  if (stmt.version !== 1) return `version_mismatch: unsupported version ${stmt.version}`;
  if (stmt.old_id !== deriveID(stmt.old_pub_key)) return "old_id does not match old_pub_key";
  if (stmt.new_id !== deriveID(stmt.new_pub_key)) return "new_id does not match new_pub_key";
  if (stmt.old_id === stmt.new_id) return "old_id and new_id must differ";
  if (!isKeyRotationReasonKnown(stmt.reason)) {
    return `unknown key rotation reason: ${stmt.reason}`;
  }
  const bytes = keyRotationSignBytes(stmt);
  const oldErr = await verifyBoth(bytes, stmt.signature_old, stmt.old_pub_key);
  if (oldErr !== null) return `old signature invalid: ${oldErr}`;
  const newErr = await verifyBoth(bytes, stmt.signature_new, stmt.new_pub_key);
  if (newErr !== null) return `new signature invalid: ${newErr}`;
  return null;
}

/** Verify a KeyRotationStatement. True iff both signatures and IDs verify. */
export async function verifyKeyRotationStatement(
  stmt: KeyRotationStatement,
): Promise<boolean> {
  return (await verifyKeyRotationStatementE(stmt)) === null;
}

function isKeyRotationReasonKnown(reason: KeyRotationReason | string): boolean {
  return ["routine", "compromise_suspected", "device_lost", "recovery", "other"].includes(reason);
}

// ============================================================================
// v1.1 TransactionReceipt signable bytes (§6.4.7)
// ============================================================================

/**
 * Canonical bytes that every party in a TransactionReceipt signs. Parties
 * are sorted by party_id; only identifying fields (not proof_bundle) enter
 * the signable. Keys in lex order.
 */
export function transactionReceiptSignBytes(receipt: TransactionReceipt): Uint8Array {
  const parties = receipt.parties
    .map((p) => ({
      agent_id: p.agent_id,
      agent_pub_key: p.agent_pub_key,
      party_id: p.party_id,
      role: p.role,
    }))
    .sort((a, b) => (a.party_id < b.party_id ? -1 : a.party_id > b.party_id ? 1 : 0));
  const signable = {
    created_at: receipt.created_at,
    parties,
    terms_canonical_json: receipt.terms_canonical_json,
    terms_schema_uri: receipt.terms_schema_uri,
    transaction_id: receipt.transaction_id,
    version: receipt.version,
  };
  return canonicalJSON(signable);
}

/**
 * Produce a party's hybrid signature over the receipt's canonical signable.
 * Collect the resulting ReceiptPartySignature into receipt.party_signatures
 * before emitting the receipt.
 */
export async function signTransactionReceiptParty(
  receipt: TransactionReceipt,
  partyID: string,
  agentPriv: HybridPrivateKey,
): Promise<ReceiptPartySignature> {
  const data = transactionReceiptSignBytes(receipt);
  const sig = await signBoth(data, agentPriv);
  return { party_id: partyID, signature: sig };
}

// ============================================================================
// v1.1 session cert cache (ROADMAP 2.3)
// ============================================================================

/**
 * Canonical 32-byte SHA-256 hash of a delegation chain, defined as
 * SHA-256 of the concatenated delegationSignBytes of each cert in order.
 * Used as a stable chain identity inside SessionToken — a cert rotation
 * invalidates every token issued against the old chain.
 */
export function chainHash(chain: DelegationCert[]): Uint8Array {
  const parts: Uint8Array[] = chain.map(delegationSignBytes);
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return sha256(buf);
}

/**
 * Canonical MAC-input bytes for a SessionToken. The MAC itself is excluded
 * from the signable (a MAC cannot cover itself).
 */
export function sessionTokenSignBytes(token: SessionToken): Uint8Array {
  const scope = [...token.granted_scope].sort();
  const signable = {
    agent_id: token.agent_id,
    agent_pub_key: token.agent_pub_key,
    chain_hash: token.chain_hash,
    granted_scope: scope,
    human_id: token.human_id,
    issued_at: token.issued_at,
    session_id: token.session_id,
    valid_until: token.valid_until,
    version: token.version,
  };
  return canonicalJSON(signable);
}

/**
 * Issue a SessionToken from a previously verified bundle's result. Callers
 * MUST only invoke this after verifyBundle(bundle, opts) returned valid=true.
 * sessionSecret MUST be a cryptographically random secret known only to the
 * verifier.
 */
export function issueSessionToken(
  bundle: ProofBundle,
  result: VerifyResult,
  sessionID: string,
  issuedAt: number,
  validUntil: number,
  sessionSecret: Uint8Array,
): SessionToken {
  if (sessionSecret.length === 0) throw new Error("session_secret must not be empty");
  if (!sessionID) throw new Error("session_id must not be empty");
  if (validUntil <= issuedAt) throw new Error("valid_until must be strictly after issued_at");
  const scope = [...(result.granted_scope ?? [])].sort();
  const token: SessionToken = {
    version: 1,
    session_id: sessionID,
    agent_id: result.agent_id ?? "",
    agent_pub_key: bundle.agent_pub_key,
    human_id: result.human_id ?? "",
    granted_scope: scope,
    issued_at: issuedAt,
    valid_until: validUntil,
    chain_hash: chainHash(bundle.delegations),
    mac: new Uint8Array(0),
  };
  const signable = sessionTokenSignBytes(token);
  token.mac = hmac(sha256, sessionSecret, signable);
  return token;
}

/**
 * Check a SessionToken's HMAC against sessionSecret and its validity window
 * against `now` (unix seconds). Returns null on success; an error string on
 * failure.
 */
export function verifySessionTokenE(
  token: SessionToken,
  sessionSecret: Uint8Array,
  now: number,
): string | null {
  if (sessionSecret.length === 0) return "session_secret must not be empty";
  if (token.version !== 1) return `version_mismatch: unsupported version ${token.version}`;
  if (!token.chain_hash || token.chain_hash.length !== 32) {
    return `chain_hash must be 32 bytes, got ${token.chain_hash?.length ?? 0}`;
  }
  if (!token.mac || token.mac.length !== 32) {
    return `mac must be 32 bytes, got ${token.mac?.length ?? 0}`;
  }
  const want = hmac(sha256, sessionSecret, sessionTokenSignBytes(token));
  if (!constantTimeEqual(want, token.mac)) return "session_token MAC invalid";
  if (now < token.issued_at) return "session_token not yet valid";
  if (now > token.valid_until) return "session_token expired";
  return null;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Generate 32 cryptographically-random challenge bytes from WebCrypto. */
export function generateChallenge(): Uint8Array {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b;
}

export { hexEncode };
