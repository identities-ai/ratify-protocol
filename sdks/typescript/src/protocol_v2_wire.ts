// Protocol v2 wire objects: delegation certificate (0x0001), proof bundle /
// challenge presentation (0x0002), revocation list (0x0003) and revocation
// push (0x0005). Port of the Go reference protocol_v2_wire.go.

import { sha384 } from "@noble/hashes/sha2";

import { V2_MAX_DELEGATION_LIFETIME_SECONDS, validV2Timestamp } from "./clock_bounds_v2.js";
import {
  CONSTRAINT_RECEIVER_AUDIENCE_V2,
  CONSTRAINT_RESOURCE_PATH_V2,
  constraintWireObjectV2,
  decodeConstraintNodeV2,
  encodeConstraintV2,
  validateV2ConstraintFields,
  type ConstraintV2,
} from "./constraints_v2.js";
import { V2_OBJECT_TYPE, keyIDV2, verifyV2Statement, type HybridKeyPairV2, type V2SignOptions } from "./crypto_v2.js";
import { classified, classifiedAsync, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  concatBytes,
  gArray,
  gBytes,
  gInt,
  gString,
  gStringArray,
  gStruct,
  hexOf,
  rejectV2UnexpectedNull,
  requireV2Fields,
  uint16BE,
  utf8,
  utf8Len,
  type Fields,
  type JNode,
} from "./json_v2.js";
import {
  MAX_DELEGATION_CERT_BYTES_V2,
  MAX_PROOF_BUNDLE_BYTES_V2,
  MAX_REVOCATION_LIST_BYTES_V2,
  MAX_REVOCATION_LIST_REFS_V2,
  MAX_REVOCATION_PUSH_BYTES_V2,
  MAX_REVOCATION_PUSH_REFS_V2,
  checkV2WireSize,
} from "./limits_v2.js";
import { normalizeResourcePath, resourcePathsNested } from "./resource_path.js";
import { validateScopesV2 } from "./scope_v2.js";
import { newLocalSignerV2, signV2StatementWithSigner, signerPublicKeyV2, type SignOptionsV2, type SignerV2 } from "./signer_v2.js";
import {
  MAX_CONSTRAINTS_PER_CERT,
  MAX_DELEGATION_CHAIN_DEPTH,
  MAX_IDENTIFIER_LENGTH_BYTES,
  MAX_SCOPES_PER_CERT,
  MAX_SCOPE_LENGTH_BYTES,
  type HybridPublicKey,
  type HybridSignature,
} from "./types.js";

export { CONSTRAINT_RECEIVER_AUDIENCE_V2, keyIDV2, verifyV2Statement };


export interface DelegationCertV2 {
  version: number;
  cert_id: string;
  issuer_id: string;
  issuer_pub_key: HybridPublicKey;
  subject_id: string;
  subject_pub_key: HybridPublicKey;
  scope: string[] | null;
  constraints: ConstraintV2[] | null;
  issued_at: number;
  expires_at: number;
  signature: HybridSignature;
}

/** Proof bundle. Nullable members are the JSON null wire values. */
export interface ProofBundleV2 {
  version: number;
  verifier_id: string;
  agent_id: string;
  agent_pub_key: HybridPublicKey;
  delegations: DelegationCertV2[] | null;
  delegation_digest: Uint8Array;
  challenge: Uint8Array;
  challenge_at: number;
  challenge_sig: HybridSignature;
  session_context: Uint8Array | null;
  stream_id: Uint8Array | null;
  stream_seq: number | null;
}

/** Issuer-scoped: the containing signed status object carries the issuer ID. */
export interface RevokedCertV2 {
  cert_id: string;
}

export interface RevocationListV2 {
  version: number;
  issuer_id: string;
  updated_at: number;
  next_update: number;
  sequence: number;
  revoked: RevokedCertV2[] | null;
  signature: HybridSignature;
}

export interface RevocationPushV2 {
  version: number;
  issuer_id: string;
  sequence: number;
  pushed_at: number;
  revoked: RevokedCertV2[] | null;
  signature: HybridSignature;
}

// ---------------------------------------------------------------------------
// Shared helpers

export function validV2ID(id: unknown): id is string {
  return typeof id === "string" && /^[0-9a-f]{64}$/.test(id);
}

export function lowerHexString(value: string): boolean {
  return /^[0-9a-f]*$/.test(value);
}

export function equalHybridPublicKeys(a: HybridPublicKey | null | undefined, b: HybridPublicKey | null | undefined): boolean {
  return bytesEqual(a?.ed25519, b?.ed25519) && bytesEqual(a?.ml_dsa_65, b?.ml_dsa_65);
}

export function cloneHybridPublicKey(k: HybridPublicKey): HybridPublicKey {
  return { ed25519: Uint8Array.from(k.ed25519 ?? []), ml_dsa_65: Uint8Array.from(k.ml_dsa_65 ?? []) };
}

function cloneSig(s: HybridSignature): HybridSignature {
  return { ed25519: Uint8Array.from(s.ed25519 ?? []), ml_dsa_65: Uint8Array.from(s.ml_dsa_65 ?? []) };
}

export function placeholderV2Signature(): HybridSignature {
  return { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) };
}

export function validateHybridSignatureV2(sig: HybridSignature | null | undefined): void {
  if (!sig || !(sig.ed25519 instanceof Uint8Array) || !(sig.ml_dsa_65 instanceof Uint8Array) ||
      sig.ed25519.length !== 64 || sig.ml_dsa_65.length !== 3309) {
    throw new Error("wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components");
  }
}

export function keyWire(k: HybridPublicKey | HybridSignature): Record<string, unknown> {
  return { ed25519: k?.ed25519 ?? null, ml_dsa_65: k?.ml_dsa_65 ?? null };
}

export function isSafeInt(n: number): boolean {
  return Number.isInteger(n) && n >= -MAX_SAFE_INTEGER_V2 && n <= MAX_SAFE_INTEGER_V2;
}

// Go-typed sub-decoders ------------------------------------------------------

export function decodeHybridKey(n: JNode | undefined, what: string): HybridPublicKey {
  // A present key or signature carries both members: {} or a missing
  // component does not spell the structure it would decode to (SPEC-v2 §2.1).
  if (n !== undefined && n.k === "obj") {
    for (const member of ["ed25519", "ml_dsa_65"]) {
      if (!n.m.has(member)) throw new Error(`wire v2: ${what}.${member} is missing`);
    }
  }
  const f = gStruct(n, ["ed25519", "ml_dsa_65"], what);
  return {
    ed25519: gBytes(f.get("ed25519"), `${what}.ed25519`) ?? new Uint8Array(0),
    ml_dsa_65: gBytes(f.get("ml_dsa_65"), `${what}.ml_dsa_65`) ?? new Uint8Array(0),
  };
}

export const decodeHybridSignature = decodeHybridKey as (n: JNode | undefined, what: string) => HybridSignature;

/** Go CanonicalJSON(constraint): the exact canonical constraint bytes. */
export function constraintCanonicalJSONV2(c: ConstraintV2): Uint8Array {
  return canonicalJSONV2(constraintWireObjectV2(c));
}

/** Go validateV2ScopeArray: wire shape and resource bounds only. */
function validateV2ScopeArray(n: JNode | undefined): void {
  if (n === undefined || n.k !== "arr") throw new Error("wire v2: scope must be an array of strings");
  if (n.a.length > MAX_SCOPES_PER_CERT) throw new Error("wire v2: scope count exceeds protocol bound");
  n.a.forEach((raw, i) => {
    if ((raw.k !== "str" && raw.k !== "null") || (raw.k === "str" && utf8Len(raw.v) > MAX_SCOPE_LENGTH_BYTES)) {
      throw new Error(`wire v2: scope ${i} must be a bounded string`);
    }
  });
}

// ---------------------------------------------------------------------------
// Delegation certificate (0x0001)

const DELEGATION_V2_FIELDS = ["version", "cert_id", "issuer_id", "issuer_pub_key", "subject_id", "subject_pub_key", "scope", "constraints", "issued_at", "expires_at", "signature"];
const PROOF_BUNDLE_V2_FIELDS = ["version", "verifier_id", "agent_id", "agent_pub_key", "delegations", "delegation_digest", "challenge", "challenge_at", "challenge_sig", "session_context", "stream_id", "stream_seq"];

function checkRawCertificate(n: JNode, prefix: string): void {
  try {
    requireV2Fields(n, DELEGATION_V2_FIELDS);
    const fields = (n as Extract<JNode, { k: "obj" }>).m;
    const constraints = fields.get("constraints")!;
    if (constraints.k !== "arr") throw new Error("constraints must be an array");
    validateV2ScopeArray(fields.get("scope"));
    constraints.a.forEach((raw, j) => {
      try {
        validateV2ConstraintFields(raw);
      } catch (err) {
        throw wrapError(`constraint ${j}`, err);
      }
    });
  } catch (err) {
    throw wrapError(prefix, err);
  }
}

function decodeCertStruct(n: JNode | undefined, what: string): DelegationCertV2 {
  const f = gStruct(n, DELEGATION_V2_FIELDS, what);
  const rawConstraints = gArray(f.get("constraints"), `${what}.constraints`);
  return {
    version: gInt(f.get("version"), "version"),
    cert_id: gString(f.get("cert_id"), "cert_id"),
    issuer_id: gString(f.get("issuer_id"), "issuer_id"),
    issuer_pub_key: decodeHybridKey(f.get("issuer_pub_key"), "issuer_pub_key"),
    subject_id: gString(f.get("subject_id"), "subject_id"),
    subject_pub_key: decodeHybridKey(f.get("subject_pub_key"), "subject_pub_key"),
    scope: gStringArray(f.get("scope"), "scope"),
    constraints: rawConstraints === null ? null : rawConstraints.map((c) => decodeConstraintNodeV2(c)),
    issued_at: gInt(f.get("issued_at"), "issued_at"),
    expires_at: gInt(f.get("expires_at"), "expires_at"),
    signature: decodeHybridSignature(f.get("signature"), "signature"),
  };
}

export function validateDelegationCertV2(c: DelegationCertV2): void {
  if (c.version !== 2) throw new Error("version must be 2");
  if (!validV2Timestamp(c.issued_at) || !validV2Timestamp(c.expires_at)) throw new Error("issued_at and expires_at must be safe integers");
  if (typeof c.cert_id !== "string" || c.cert_id === "" || utf8Len(c.cert_id) > MAX_IDENTIFIER_LENGTH_BYTES) {
    throw new Error("cert_id must be non-empty and within the identifier byte limit");
  }
  if (!validV2ID(c.issuer_id) || !validV2ID(c.subject_id)) {
    throw new Error("issuer_id and subject_id must be 64 lowercase hexadecimal characters");
  }
  let issuer: string;
  let subject: string;
  try {
    issuer = keyIDV2(c.issuer_pub_key);
  } catch (err) {
    throw wrapError("issuer key", err);
  }
  try {
    subject = keyIDV2(c.subject_pub_key);
  } catch (err) {
    throw wrapError("subject key", err);
  }
  if (c.issuer_id !== issuer || c.subject_id !== subject) {
    throw v2Errorf("key_id_mismatch", "key ID does not match complete public key");
  }
  if (c.scope === null || !Array.isArray(c.scope)) throw new Error("scope must be an array");
  for (const s of c.scope) if (utf8Len(s) > MAX_SCOPE_LENGTH_BYTES) throw new Error("scope exceeds the protocol byte limit");
  if (c.constraints === null || !Array.isArray(c.constraints)) throw new Error("constraints must be an array");
  if (c.scope.length > MAX_SCOPES_PER_CERT || c.constraints.length > MAX_CONSTRAINTS_PER_CERT) {
    throw new Error("scope or constraint count exceeds protocol bound");
  }
  c.constraints.forEach((constraint, i) => {
    try {
      encodeConstraintV2(constraint);
    } catch (err) {
      throw wrapError(`constraint ${i}`, err);
    }
  });
}

function certSignableObject(c: DelegationCertV2): Record<string, unknown> {
  return {
    cert_id: c.cert_id,
    constraints: (c.constraints ?? []).map(constraintWireObjectV2),
    expires_at: c.expires_at,
    issued_at: c.issued_at,
    issuer_id: c.issuer_id,
    issuer_pub_key: keyWire(c.issuer_pub_key),
    scope: c.scope,
    subject_id: c.subject_id,
    subject_pub_key: keyWire(c.subject_pub_key),
    version: c.version,
  };
}

function certCanonicalObject(c: DelegationCertV2, nilConstraintsAsEmpty: boolean): Record<string, unknown> {
  const o = certSignableObject(c);
  if (!nilConstraintsAsEmpty && c.constraints === null) o.constraints = null;
  o.signature = keyWire(c.signature);
  return o;
}

export function delegationCertV2SignBytes(c: DelegationCertV2): Uint8Array {
  return canonicalJSONV2(certSignableObject(c));
}

export function decodeDelegationCertV2(data: Uint8Array): DelegationCertV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "certificate", "MAX_DELEGATION_CERT_BYTES_V2", MAX_DELEGATION_CERT_BYTES_V2);
    const root = checkWireJSONV2(data);
    checkRawCertificate(root, "wire v2");
    rejectV2UnexpectedNull(root);
    const cert = decodeCertStruct(root, "certificate");
    validateDelegationCertV2(cert);
    validateHybridSignatureV2(cert.signature);
    return cert;
  });
}

export function encodeDelegationCertV2(c: DelegationCertV2): Uint8Array {
  return classified("malformed", () => {
    if (!c) throw new Error("v2 delegation certificate is nil");
    validateDelegationCertV2(c);
    validateHybridSignatureV2(c.signature);
    const encoded = canonicalJSONV2(certCanonicalObject(c, false));
    try {
      decodeDelegationCertV2(encoded);
    } catch (err) {
      throw wrapError("invalid v2 delegation certificate", err);
    }
    return encoded;
  });
}

/**
 * Checks one certificate's structure, key-ID bindings and its issuer
 * signature under 0x0001 with the certificate's own issuer key. Does not
 * establish that the issuer is trusted.
 */
export async function verifyDelegationCertV2Signature(cert: DelegationCertV2): Promise<void> {
  return classifiedAsync("malformed", async () => {
    if (!cert) throw v2Errorf("malformed", "v2 delegation certificate is nil");
    let signable: Uint8Array;
    try {
      validateDelegationCertV2(cert);
      validateHybridSignatureV2(cert.signature);
      signable = delegationCertV2SignBytes(cert);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    await verifyV2Statement(V2_OBJECT_TYPE.delegationCertificate, signable, cert.signature, cert.issuer_pub_key);
  });
}

/**
 * Signs a v2 certificate with the issuer key pair. The certificate's issuer
 * ID and key must match the key. See signDelegationCertV2WithSigner.
 */
export async function signDelegationCertV2(cert: DelegationCertV2, issuer: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<DelegationCertV2> {
  return signDelegationCertV2WithSigner(cert, await newLocalSignerV2(issuer, { deterministic: opts.deterministic }));
}

/**
 * Signs a v2 certificate through a signer whose complete public key must
 * equal the certificate issuer key. The issuer duties of SPEC-v2 §5.1 and
 * §5.2 are checked before any signer method runs: the certificate must
 * validate, carry valid v2 scopes, have issued_at < expires_at and a
 * lifetime of at most 315360000 seconds, and carry a jointly satisfiable
 * set of resource_path constraints. A verifier still applies its own rules.
 */
export async function signDelegationCertV2WithSigner(cert: DelegationCertV2, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<DelegationCertV2> {
  return classifiedAsync("malformed", async () => {
    if (!cert) throw new Error("v2 delegation certificate is nil");
    validateDelegationCertV2(cert);
    const scopeErr = validateScopesV2(cert.scope);
    if (scopeErr) throw new Error(`v2 issuer scope: ${scopeErr}`);
    validateDelegationIssuanceV2(cert);
    const issuerPub = await signerPublicKeyV2(signer);
    const issuerID = keyIDV2(issuerPub);
    if (cert.issuer_id !== issuerID || !equalHybridPublicKeys(cert.issuer_pub_key, issuerPub)) {
      throw v2Errorf("key_id_mismatch", "v2 issuer key does not match certificate issuer");
    }
    const prepared = decodeDelegationCertV2(encodeDelegationCertV2({ ...cert, signature: placeholderV2Signature() }));
    const signable = delegationCertV2SignBytes(prepared);
    prepared.signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.delegationCertificate, signable, signer, issuerPub, opts);
    const signed = decodeDelegationCertV2(encodeDelegationCertV2(prepared));
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.delegationCertificate, signable, signed.signature, issuerPub);
    } catch (err) {
      throw wrapError("signed v2 delegation certificate failed verification", err);
    }
    return signed;
  });
}

/**
 * The issuer duties a decoder does not enforce (Go validateDelegationIssuanceV2):
 * issued_at < expires_at, a bounded lifetime, and a jointly satisfiable
 * resource_path set (one resource_id; every present prefix valid; every two
 * prefixes nested, an absent prefix ordering as "/").
 */
export function validateDelegationIssuanceV2(cert: DelegationCertV2): void {
  if (cert.issued_at >= cert.expires_at) throw new Error("v2 issuer duty: issued_at must be earlier than expires_at");
  if (cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS) {
    throw new Error(`v2 issuer duty: delegation lifetime exceeds ${V2_MAX_DELEGATION_LIFETIME_SECONDS} seconds`);
  }
  let resourceID = "";
  const prefixes: string[] = [];
  (cert.constraints ?? []).forEach((c, i) => {
    if (c.type !== CONSTRAINT_RESOURCE_PATH_V2) return;
    const prefix = c.path_prefix ?? "";
    if (prefix !== "") {
      try {
        normalizeResourcePath(prefix);
      } catch (err) {
        throw new Error(`v2 issuer duty: constraint ${i} path_prefix can never match: ${(err as Error).message}`);
      }
    }
    if (resourceID === "") resourceID = c.resource_id ?? "";
    else if (c.resource_id !== resourceID) {
      throw new Error(`v2 issuer duty: constraint ${i} names a different resource_id; the resource_path set is jointly unsatisfiable`);
    }
    for (const prior of prefixes) {
      if (!resourcePathsNested(prior, prefix)) {
        throw new Error(`v2 issuer duty: constraint ${i} path_prefix ${JSON.stringify(prefix)} does not nest with ${JSON.stringify(prior)}; the resource_path set is jointly unsatisfiable`);
      }
    }
    prefixes.push(prefix);
  });
}

// ---------------------------------------------------------------------------
// Proof bundle (0x0002)

function presentationSignableObject(b: ProofBundleV2): Record<string, unknown> {
  return {
    agent_id: b.agent_id,
    agent_pub_key: keyWire(b.agent_pub_key),
    challenge: b.challenge,
    challenge_at: b.challenge_at,
    delegation_digest: b.delegation_digest,
    session_context: b.session_context,
    stream_id: b.stream_id,
    stream_seq: b.stream_seq,
    verifier_id: b.verifier_id,
    version: b.version,
  };
}

export function presentationV2SignBytes(b: ProofBundleV2): Uint8Array {
  return canonicalJSONV2(presentationSignableObject(b));
}

export function delegationDigestV2(certs: readonly DelegationCertV2[]): Uint8Array {
  const canonical = canonicalJSONV2(certs.map((c) => certCanonicalObject(c, true)));
  return sha384(concatBytes(utf8("ratify-protocol-delegations-v2\0"), canonical));
}

export function encodeProofBundleV2(b: ProofBundleV2): Uint8Array {
  return classified("malformed", () => {
    if (!b) throw new Error("v2 proof bundle is nil");
    const wire = presentationSignableObject(b);
    wire.challenge_sig = keyWire(b.challenge_sig);
    wire.delegations = b.delegations === null ? null : b.delegations.map((c) => certCanonicalObject(c, false));
    const encoded = canonicalJSONV2(wire);
    try {
      decodeProofBundleV2(encoded);
    } catch (err) {
      throw wrapError("invalid v2 proof bundle", err);
    }
    return encoded;
  });
}

/** "sha384:" + hex(SHA-384("ratify-protocol-bundle-v2\0" || canonical signed bundle)). */
export function bundleHashV2(b: ProofBundleV2): string {
  return classified("malformed", () => {
    return bundleHashOfBytesV2(encodeProofBundleV2(b));
  });
}

export function bundleHashOfBytesV2(encoded: Uint8Array): string {
  return "sha384:" + hexOf(sha384(concatBytes(utf8("ratify-protocol-bundle-v2\0"), encoded)));
}

function optionalBytes(n: JNode | undefined, what: string): Uint8Array | null {
  // *[]byte: JSON null is a nil pointer; a string is a (possibly empty) slice.
  if (n === undefined || n.k === "null") return null;
  return gBytes(n, what) ?? new Uint8Array(0);
}

export function decodeProofBundleV2(data: Uint8Array): ProofBundleV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "proof bundle", "MAX_PROOF_BUNDLE_BYTES_V2", MAX_PROOF_BUNDLE_BYTES_V2);
    const root = checkWireJSONV2(data, ["delegation_digest"]);
    requireV2Fields(root, PROOF_BUNDLE_V2_FIELDS, ["session_context", "stream_id", "stream_seq"]);
    const top = (root as Extract<JNode, { k: "obj" }>).m;
    const rawDelegations = top.get("delegations")!;
    if (rawDelegations.k !== "arr") throw new Error("wire v2: delegations must be an array");
    rawDelegations.a.forEach((raw, i) => checkRawCertificate(raw, `wire v2 delegation ${i}`));
    rejectV2UnexpectedNull(root);
    const f: Fields = gStruct(root, PROOF_BUNDLE_V2_FIELDS, "proof bundle");
    const delegations = gArray(f.get("delegations"), "delegations");
    const stream = f.get("stream_seq");
    const bundle: ProofBundleV2 = {
      version: gInt(f.get("version"), "version"),
      verifier_id: gString(f.get("verifier_id"), "verifier_id"),
      agent_id: gString(f.get("agent_id"), "agent_id"),
      agent_pub_key: decodeHybridKey(f.get("agent_pub_key"), "agent_pub_key"),
      delegations: delegations === null ? null : delegations.map((c, i) => decodeCertStruct(c, `delegations[${i}]`)),
      delegation_digest: gBytes(f.get("delegation_digest"), "delegation_digest") ?? new Uint8Array(0),
      challenge: gBytes(f.get("challenge"), "challenge") ?? new Uint8Array(0),
      challenge_at: gInt(f.get("challenge_at"), "challenge_at"),
      challenge_sig: decodeHybridSignature(f.get("challenge_sig"), "challenge_sig"),
      session_context: optionalBytes(f.get("session_context"), "session_context"),
      stream_id: optionalBytes(f.get("stream_id"), "stream_id"),
      stream_seq: stream === undefined || stream.k === "null" ? null : gInt(stream, "stream_seq"),
    };
    if (bundle.version !== 2) throw new Error("wire v2: version must be 2");
    if (!validV2ID(bundle.verifier_id) || !validV2ID(bundle.agent_id)) {
      throw new Error("wire v2: verifier_id and agent_id must be 64 lowercase hexadecimal characters");
    }
    if (bundle.delegations === null) throw new Error("wire v2: delegations must be an array");
    if (bundle.delegations.length > MAX_DELEGATION_CHAIN_DEPTH) {
      throw new Error(`wire v2: delegation chain exceeds MAX_DELEGATION_CHAIN_DEPTH (${MAX_DELEGATION_CHAIN_DEPTH})`);
    }
    if (bundle.challenge.length !== 32) throw new Error("wire v2: challenge must be 32 bytes");
    if (!validV2Timestamp(bundle.challenge_at)) throw new Error("wire v2: challenge_at is outside 0..253402300799");
    if (bundle.delegation_digest.length !== 48) throw new Error("wire v2: delegation_digest must be 48 bytes");
    if (bundle.session_context !== null && bundle.session_context.length !== 32) {
      throw new Error("wire v2: session_context must be null or 32 bytes");
    }
    if ((bundle.stream_id === null) !== (bundle.stream_seq === null)) {
      throw new Error("wire v2: stream_id and stream_seq must both be null or both set");
    }
    if (bundle.stream_id !== null && (bundle.stream_id.length !== 32 || bundle.stream_seq! <= 0)) {
      throw new Error("wire v2: bound stream requires 32-byte stream_id and positive stream_seq");
    }
    if (bundle.stream_seq !== null && bundle.stream_seq > MAX_SAFE_INTEGER_V2) throw new Error("wire v2: stream_seq exceeds the safe integer range");
    validateHybridSignatureV2(bundle.challenge_sig);
    bundle.delegations.forEach((c, i) => {
      try {
        validateDelegationCertV2(c);
        validateHybridSignatureV2(c.signature);
      } catch (err) {
        throw wrapError(`wire v2 delegation ${i}`, err);
      }
    });
    return bundle;
  });
}

/** Recomputes every key ID and checks the delegation digest, duplicates and linkage. */
export function verifyProofBundleV2Structure(b: ProofBundleV2): void {
  if (!b) throw v2Errorf("malformed", "v2 proof bundle is nil");
  if (b.version !== 2) throw v2Errorf("malformed", "v2 proof bundle version must be 2");
  if (b.delegations === null || !Array.isArray(b.delegations)) {
    if (!(b.challenge?.length === 32 && b.delegation_digest?.length === 48)) {
      throw v2Errorf("malformed", "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length");
    }
    throw v2Errorf("malformed", "v2 delegations must be an array");
  }
  if (b.delegations.length > MAX_DELEGATION_CHAIN_DEPTH || b.challenge?.length !== 32 || b.delegation_digest?.length !== 48) {
    throw v2Errorf("malformed", "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length");
  }
  if (b.stream_seq !== null && b.stream_seq > MAX_SAFE_INTEGER_V2) throw v2Errorf("malformed", "v2 stream sequence exceeds the safe integer range");
  if (b.session_context !== null && b.session_context.length !== 32) throw v2Errorf("malformed", "v2 session_context must be null or 32 bytes");
  const streamNull = b.stream_id === null;
  if (streamNull !== (b.stream_seq === null) || (!streamNull && (b.stream_id!.length !== 32 || b.stream_seq! <= 0))) {
    throw v2Errorf("malformed", "v2 stream_id and stream_seq must both be null or a 32-byte ID and positive sequence");
  }
  if (!validV2ID(b.agent_id) || !validV2ID(b.verifier_id)) throw v2Errorf("malformed", "v2 verifier and agent IDs must be canonical");
  let agentID: string;
  try {
    agentID = keyIDV2(b.agent_pub_key);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  if (agentID !== b.agent_id) throw v2Errorf("key_id_mismatch", "agent_id does not match agent_pub_key");
  const certs = b.delegations;
  certs.forEach((c, i) => {
    try {
      validateDelegationCertV2(c);
    } catch (err) {
      throw v2Classify("malformed", wrapError(`delegation ${i}`, err));
    }
  });
  let digest: Uint8Array;
  try {
    digest = delegationDigestV2(certs);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  if (!bytesEqual(digest, b.delegation_digest)) throw v2Errorf("delegation_digest_mismatch", "delegation_digest mismatch");
  const seen = new Set<string>();
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i]!;
    const ref = c.issuer_id + "\0" + c.cert_id;
    if (seen.has(ref)) throw v2Errorf("duplicate_certificate_ref", "duplicate delegation reference");
    seen.add(ref);
    const parent = certs[i + 1];
    if (parent && (c.issuer_id !== parent.subject_id || !equalHybridPublicKeys(c.issuer_pub_key, parent.subject_pub_key))) {
      throw v2Errorf("chain_linkage_mismatch", `delegation chain link ${i} does not match parent subject`);
    }
  }
  const leaf = certs[0];
  if (leaf && (leaf.subject_id !== b.agent_id || !equalHybridPublicKeys(leaf.subject_pub_key, b.agent_pub_key))) {
    throw v2Errorf("chain_linkage_mismatch", "agent key does not match leaf delegation subject");
  }
}

async function verifyProofBundleV2SignaturesOnly(b: ProofBundleV2): Promise<void> {
  const certs = b.delegations ?? [];
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i]!;
    let signable: Uint8Array;
    try {
      signable = delegationCertV2SignBytes(c);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    try {
      await verifyV2Statement(V2_OBJECT_TYPE.delegationCertificate, signable, c.signature, c.issuer_pub_key);
    } catch (err) {
      throw wrapError(`delegation ${i} signature`, err);
    }
  }
  let signable: Uint8Array;
  try {
    signable = presentationV2SignBytes(b);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  await verifyV2Statement(V2_OBJECT_TYPE.challengePresentation, signable, b.challenge_sig, b.agent_pub_key);
}

/**
 * Checks local structure, chain linkage and every hybrid signature. Every
 * structural check completes before any signature is verified. Does not
 * resolve the root, consume a challenge, query status or decide.
 */
export async function verifyProofBundleV2Signatures(b: ProofBundleV2): Promise<void> {
  return classifiedAsync("malformed", async () => {
    verifyProofBundleV2Structure(b);
    await verifyProofBundleV2SignaturesOnly(b);
  });
}

/** Computes the delegation digest and signs the presentation with the agent key. */
export async function signProofBundleV2(bundle: ProofBundleV2, agent: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<ProofBundleV2> {
  return signProofBundleV2WithSigner(bundle, await newLocalSignerV2(agent, { deterministic: opts.deterministic }));
}

/** signProofBundleV2 through a signer whose key must equal the bundle agent key. */
export async function signProofBundleV2WithSigner(bundle: ProofBundleV2, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<ProofBundleV2> {
  return classifiedAsync("malformed", async () => {
    if (!bundle) throw new Error("v2 proof bundle is nil");
    const agentPub = await signerPublicKeyV2(signer);
    const agentID = keyIDV2(agentPub);
    if (bundle.agent_id !== agentID || !equalHybridPublicKeys(bundle.agent_pub_key, agentPub)) {
      throw v2Errorf("key_id_mismatch", "v2 agent key does not match proof bundle agent");
    }
    const prepared = decodeProofBundleV2(encodeProofBundleV2({
      ...bundle, challenge_sig: placeholderV2Signature(), delegation_digest: new Uint8Array(48),
    }));
    prepared.delegation_digest = delegationDigestV2(prepared.delegations ?? []);
    prepared.challenge_sig = await signV2StatementWithSigner(V2_OBJECT_TYPE.challengePresentation, presentationV2SignBytes(prepared), signer, agentPub, opts);
    const signed = decodeProofBundleV2(encodeProofBundleV2(prepared));
    try {
      await verifyProofBundleV2Signatures(signed);
    } catch (err) {
      throw wrapError("invalid signed v2 proof bundle", err);
    }
    return signed;
  });
}

// ---------------------------------------------------------------------------
// Revocation list (0x0003) and push (0x0005)

const REVOCATION_LIST_V2_FIELDS = ["version", "issuer_id", "updated_at", "next_update", "sequence", "revoked", "signature"];
const REVOCATION_PUSH_V2_FIELDS = ["version", "issuer_id", "sequence", "pushed_at", "revoked", "signature"];

function decodeRevoked(n: JNode | undefined): RevokedCertV2[] | null {
  const arr = gArray(n, "revoked");
  if (arr === null) return null;
  return arr.map((x) => ({ cert_id: gString(gStruct(x, ["cert_id"], "revoked entry").get("cert_id"), "cert_id") }));
}

function validateRevokedCertsV2(refs: RevokedCertV2[] | null): void {
  if (refs === null || !Array.isArray(refs)) throw new Error("v2 revoked must be an array");
  const seen = new Set<string>();
  for (const ref of refs) {
    if (!ref || ref.cert_id === "" || typeof ref.cert_id !== "string" || seen.has(ref.cert_id)) {
      throw new Error("v2 revoked cert IDs must be non-empty and unique");
    }
    seen.add(ref.cert_id);
  }
}

export function validateRevocationListV2(l: RevocationListV2): void {
  if (!l || l.version !== 2 || !validV2ID(l.issuer_id) || !(l.sequence > 0) || l.sequence > MAX_SAFE_INTEGER_V2 ||
      !validV2Timestamp(l.updated_at) || !validV2Timestamp(l.next_update) || l.next_update <= l.updated_at || !Number.isInteger(l.sequence)) {
    throw new Error("v2 revocation list has invalid version, issuer, sequence, or time bounds");
  }
  if (Array.isArray(l.revoked) && l.revoked.length > MAX_REVOCATION_LIST_REFS_V2) {
    throw new Error(`v2 revocation list exceeds MAX_REVOCATION_LIST_REFS_V2 (${MAX_REVOCATION_LIST_REFS_V2})`);
  }
  validateRevokedCertsV2(l.revoked);
}

export function validateRevocationPushV2(p: RevocationPushV2): void {
  if (!p || p.version !== 2 || !validV2ID(p.issuer_id) || !(p.sequence > 0) || p.sequence > MAX_SAFE_INTEGER_V2 ||
      !Number.isInteger(p.sequence) || !validV2Timestamp(p.pushed_at)) {
    throw new Error("v2 revocation push has invalid version, issuer, sequence, or timestamp");
  }
  if (Array.isArray(p.revoked) && p.revoked.length > MAX_REVOCATION_PUSH_REFS_V2) {
    throw new Error(`v2 revocation push exceeds MAX_REVOCATION_PUSH_REFS_V2 (${MAX_REVOCATION_PUSH_REFS_V2})`);
  }
  validateRevokedCertsV2(p.revoked);
}

const revokedWire = (r: RevokedCertV2[] | null) => (r === null ? null : r.map((x) => ({ cert_id: x.cert_id })));

export function revocationListV2SignBytes(l: RevocationListV2): Uint8Array {
  validateRevocationListV2(l);
  return canonicalJSONV2({
    issuer_id: l.issuer_id, next_update: l.next_update, revoked: revokedWire(l.revoked),
    sequence: l.sequence, updated_at: l.updated_at, version: l.version,
  });
}

export function revocationPushV2SignBytes(p: RevocationPushV2): Uint8Array {
  validateRevocationPushV2(p);
  return canonicalJSONV2({
    issuer_id: p.issuer_id, pushed_at: p.pushed_at, revoked: revokedWire(p.revoked), sequence: p.sequence, version: p.version,
  });
}

export function decodeRevocationListV2(data: Uint8Array): RevocationListV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "revocation list", "MAX_REVOCATION_LIST_BYTES_V2", MAX_REVOCATION_LIST_BYTES_V2);
    const root = checkWireJSONV2(data);
    requireV2Fields(root, REVOCATION_LIST_V2_FIELDS);
    rejectV2UnexpectedNull(root);
    const f = gStruct(root, REVOCATION_LIST_V2_FIELDS, "revocation list");
    const list: RevocationListV2 = {
      version: gInt(f.get("version"), "version"),
      issuer_id: gString(f.get("issuer_id"), "issuer_id"),
      updated_at: gInt(f.get("updated_at"), "updated_at"),
      next_update: gInt(f.get("next_update"), "next_update"),
      sequence: gInt(f.get("sequence"), "sequence"),
      revoked: decodeRevoked(f.get("revoked")),
      signature: decodeHybridSignature(f.get("signature"), "signature"),
    };
    validateRevocationListV2(list);
    validateHybridSignatureV2(list.signature);
    return list;
  });
}

export function decodeRevocationPushV2(data: Uint8Array): RevocationPushV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "revocation push", "MAX_REVOCATION_PUSH_BYTES_V2", MAX_REVOCATION_PUSH_BYTES_V2);
    const root = checkWireJSONV2(data);
    requireV2Fields(root, REVOCATION_PUSH_V2_FIELDS);
    rejectV2UnexpectedNull(root);
    const f = gStruct(root, REVOCATION_PUSH_V2_FIELDS, "revocation push");
    const push: RevocationPushV2 = {
      version: gInt(f.get("version"), "version"),
      issuer_id: gString(f.get("issuer_id"), "issuer_id"),
      sequence: gInt(f.get("sequence"), "sequence"),
      pushed_at: gInt(f.get("pushed_at"), "pushed_at"),
      revoked: decodeRevoked(f.get("revoked")),
      signature: decodeHybridSignature(f.get("signature"), "signature"),
    };
    validateRevocationPushV2(push);
    validateHybridSignatureV2(push.signature);
    return push;
  });
}

export function encodeRevocationListV2(l: RevocationListV2): Uint8Array {
  return classified("malformed", () => {
    validateRevocationListV2(l);
    validateHybridSignatureV2(l.signature);
    const encoded = canonicalJSONV2({
      issuer_id: l.issuer_id, next_update: l.next_update, revoked: revokedWire(l.revoked), sequence: l.sequence,
      signature: keyWire(l.signature), updated_at: l.updated_at, version: l.version,
    });
    decodeRevocationListV2(encoded);
    return encoded;
  });
}

export function encodeRevocationPushV2(p: RevocationPushV2): Uint8Array {
  return classified("malformed", () => {
    validateRevocationPushV2(p);
    validateHybridSignatureV2(p.signature);
    const encoded = canonicalJSONV2({
      issuer_id: p.issuer_id, pushed_at: p.pushed_at, revoked: revokedWire(p.revoked), sequence: p.sequence,
      signature: keyWire(p.signature), version: p.version,
    });
    decodeRevocationPushV2(encoded);
    return encoded;
  });
}

/** Status signatures are checked only against the caller-bound status key. */
export async function verifyRevocationListV2Signature(l: RevocationListV2, trustedIssuerID: string, statusKey: HybridPublicKey): Promise<void> {
  return classifiedAsync("malformed", async () => {
    try {
      validateRevocationListV2(l);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    if (trustedIssuerID !== l.issuer_id) {
      throw v2Errorf("status_key_binding_mismatch", "v2 revocation list issuer does not match authenticated status-key binding");
    }
    await verifyV2Statement(V2_OBJECT_TYPE.revocationList, revocationListV2SignBytes(l), l.signature, statusKey);
  });
}

export async function verifyRevocationPushV2Signature(p: RevocationPushV2, trustedIssuerID: string, statusKey: HybridPublicKey): Promise<void> {
  return classifiedAsync("malformed", async () => {
    try {
      validateRevocationPushV2(p);
    } catch (err) {
      throw v2Classify("malformed", err);
    }
    if (trustedIssuerID !== p.issuer_id) {
      throw v2Errorf("status_key_binding_mismatch", "v2 revocation push issuer does not match authenticated status-key binding");
    }
    await verifyV2Statement(V2_OBJECT_TYPE.revocationPush, revocationPushV2SignBytes(p), p.signature, statusKey);
  });
}

async function checkStatusSigner(issuerID: string, boundIssuerID: string, boundStatusKey: HybridPublicKey, signer: SignerV2, kind: string): Promise<HybridPublicKey> {
  if (boundIssuerID === "" || issuerID !== boundIssuerID) {
    throw v2Errorf("status_key_binding_mismatch", `${kind} issuer does not match caller-authenticated status-key binding`);
  }
  const derived = await signerPublicKeyV2(signer);
  if (!equalHybridPublicKeys(boundStatusKey, derived)) {
    throw v2Errorf("status_key_binding_mismatch", "status private key does not match caller-authenticated issuer status-key binding");
  }
  return derived;
}

/** Signs a list under the caller-authenticated status key bound to its issuer. */
export async function signRevocationListV2(l: RevocationListV2, boundIssuerID: string, boundStatusKey: HybridPublicKey, statusKey: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<RevocationListV2> {
  return signRevocationListV2WithSigner(l, boundIssuerID, boundStatusKey, await newLocalSignerV2(statusKey, { deterministic: opts.deterministic }));
}

/** signRevocationListV2 through a signer whose key must equal boundStatusKey. */
export async function signRevocationListV2WithSigner(l: RevocationListV2, boundIssuerID: string, boundStatusKey: HybridPublicKey, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<RevocationListV2> {
  return classifiedAsync("malformed", async () => {
    validateRevocationListV2(l);
    const derived = await checkStatusSigner(l.issuer_id, boundIssuerID, boundStatusKey, signer, "revocation-list");
    const prepared = decodeRevocationListV2(encodeRevocationListV2({ ...l, signature: placeholderV2Signature() }));
    prepared.signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.revocationList, revocationListV2SignBytes(prepared), signer, derived, opts);
    const signed = decodeRevocationListV2(encodeRevocationListV2(prepared));
    try {
      await verifyRevocationListV2Signature(signed, boundIssuerID, boundStatusKey);
    } catch (err) {
      throw wrapError("signed revocation list failed verification", err);
    }
    return signed;
  });
}

/** Signs a push under the caller-authenticated status key bound to its issuer. */
export async function signRevocationPushV2(p: RevocationPushV2, boundIssuerID: string, boundStatusKey: HybridPublicKey, statusKey: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<RevocationPushV2> {
  return signRevocationPushV2WithSigner(p, boundIssuerID, boundStatusKey, await newLocalSignerV2(statusKey, { deterministic: opts.deterministic }));
}

/** signRevocationPushV2 through a signer whose key must equal boundStatusKey. */
export async function signRevocationPushV2WithSigner(p: RevocationPushV2, boundIssuerID: string, boundStatusKey: HybridPublicKey, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<RevocationPushV2> {
  return classifiedAsync("malformed", async () => {
    validateRevocationPushV2(p);
    const derived = await checkStatusSigner(p.issuer_id, boundIssuerID, boundStatusKey, signer, "revocation-push");
    const prepared = decodeRevocationPushV2(encodeRevocationPushV2({ ...p, signature: placeholderV2Signature() }));
    prepared.signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.revocationPush, revocationPushV2SignBytes(prepared), signer, derived, opts);
    const signed = decodeRevocationPushV2(encodeRevocationPushV2(prepared));
    try {
      await verifyRevocationPushV2Signature(signed, boundIssuerID, boundStatusKey);
    } catch (err) {
      throw wrapError("signed revocation push failed verification", err);
    }
    return signed;
  });
}

/**
 * Binds an audit reference to the complete canonical signed status object.
 * It does not establish signature validity, freshness or policy.
 */
export function statusEvidenceDigestV2(objectType: number, object: RevocationListV2 | RevocationPushV2): Uint8Array {
  return classified("malformed", () => {
    let encoded: Uint8Array;
    if (objectType === V2_OBJECT_TYPE.revocationList) {
      if (!object || !("next_update" in object)) throw new Error("status evidence type 0x0003 requires RevocationListV2");
      encoded = encodeRevocationListV2(object);
    } else if (objectType === V2_OBJECT_TYPE.revocationPush) {
      if (!object || !("pushed_at" in object)) throw new Error("status evidence type 0x0005 requires RevocationPushV2");
      encoded = encodeRevocationPushV2(object);
    } else {
      throw v2Errorf("unsupported_object_type", `unsupported status evidence object type: ${objectType.toString(16).padStart(4, "0")}`);
    }
    return sha384(concatBytes(utf8("ratify-protocol-status-evidence-v2\0"), uint16BE(objectType), encoded));
  });
}

export function cloneRevocationListV2(l: RevocationListV2): RevocationListV2 {
  return decodeRevocationListV2(encodeRevocationListV2(l));
}

export { cloneSig as cloneHybridSignatureV2 };
