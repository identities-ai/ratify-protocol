// Wire codec for Ratify Protocol v1 signed structures.
//
// The wire JSON shape is normative (SPEC §5.7, §5.8, §6): object keys in
// lexicographic order, byte fields as base64-standard strings with padding,
// optional fields omitted when absent. Encoders emit canonical JSON text
// (via canonicalJSON), so encode output is exactly the canonical bytes.
//
// Decoders are strict and fail closed:
//   - byte input must be valid UTF-8 with no byte-order mark;
//   - malformed or non-canonical base64 is rejected;
//   - required fields and types are validated; integer fields must lie
//     within the IEEE-754 safe-integer range (SPEC §6.2);
//   - cryptographic byte lengths are validated against the protocol
//     constants (Ed25519 / ML-DSA-65 key and signature sizes);
//   - unknown fields in signed structures (DelegationCert, Constraint,
//     HybridPublicKey, HybridSignature, ProofBundle, SessionToken) are
//     rejected;
//   - duplicated JSON object keys are rejected at every nesting depth
//     (escape-decoded, so a Unicode-escaped spelling of a key collides
//     with its literal form);
//   - errors name the offending field and the reason.
//
// Round-trip guarantees for canonical inputs:
//   decodeProofBundle(encodeProofBundle(b)) deep-equals b, and
//   encodeProofBundle(decodeProofBundle(json)) is byte-identical to the
//   canonical JSON of the original document.

import {
  canonicalJSON,
  base64StandardEncode,
  base64StandardDecode,
} from "./canonical.js";
import { canonicalConstraintDict } from "./crypto.js";
import { utf8ByteLength, validateParamsValue } from "./resource_path.js";
import {
  ED25519_PUBLIC_KEY_SIZE,
  ED25519_SIGNATURE_SIZE,
  MAX_CONSTRAINTS_PER_CERT,
  MAX_IDENTIFIER_LENGTH_BYTES,
  MAX_JSON_NESTING_DEPTH,
  MAX_PROOF_BUNDLE_BYTES,
  MAX_SCOPES_PER_CERT,
  MAX_SCOPE_LENGTH_BYTES,
  MLDSA65_PUBLIC_KEY_SIZE,
  MLDSA65_SIGNATURE_SIZE,
  PROTOCOL_VERSION,
  type Constraint,
  type ConstraintType,
  type DelegationCert,
  type HybridPublicKey,
  type HybridSignature,
  type IdentityStatus,
  type ProofBundle,
  type SessionToken,
  type VerificationReceipt,
} from "./types.js";

// Fixed sizes for the 32-byte binding/digest fields on the wire
// (SPEC §5.8 session_context / stream_id, §6.4.1 challenge, §5 SessionToken
// chain_hash / mac).
const BINDING_SIZE = 32;

type JsonObj = Record<string, unknown>;

// ============================================================================
// Encoders
// ============================================================================

/** Encode a DelegationCert as canonical wire JSON (SPEC §5.7). */
export function encodeDelegationCert(cert: DelegationCert): string {
  return jsonText(certWireDict(cert, "DelegationCert"));
}

/** Encode a ProofBundle as canonical wire JSON (SPEC §5.8). */
export function encodeProofBundle(bundle: ProofBundle): string {
  const dict: JsonObj = {
    agent_id: bundle.agent_id,
    agent_pub_key: bundle.agent_pub_key,
    challenge: bundle.challenge,
    challenge_at: checkWireInt(bundle.challenge_at, "ProofBundle.challenge_at"),
    challenge_sig: bundle.challenge_sig,
    delegations: bundle.delegations.map((c, i) =>
      certWireDict(c, `ProofBundle.delegations[${i}]`),
    ),
  };
  // Optional v1.1 fields carry Go's omitempty semantics: absent or empty
  // values are omitted from the wire form.
  if (bundle.session_context !== undefined && bundle.session_context.length > 0) {
    dict.session_context = bundle.session_context;
  }
  if (bundle.stream_id !== undefined && bundle.stream_id.length > 0) {
    dict.stream_id = bundle.stream_id;
  }
  if (bundle.stream_seq !== undefined && bundle.stream_seq !== 0) {
    dict.stream_seq = checkWireInt(bundle.stream_seq, "ProofBundle.stream_seq");
  }
  return jsonText(dict);
}

/** Encode a SessionToken as canonical wire JSON (SPEC §16.3). */
export function encodeSessionToken(token: SessionToken): string {
  return jsonText({
    agent_id: token.agent_id,
    agent_pub_key: token.agent_pub_key,
    chain_hash: token.chain_hash,
    granted_scope: token.granted_scope,
    human_id: token.human_id,
    issued_at: checkWireInt(token.issued_at, "SessionToken.issued_at"),
    mac: token.mac,
    session_id: token.session_id,
    valid_until: checkWireInt(token.valid_until, "SessionToken.valid_until"),
    version: checkWireInt(token.version, "SessionToken.version"),
  });
}

function certWireDict(cert: DelegationCert, path: string): JsonObj {
  return {
    cert_id: cert.cert_id,
    constraints: (cert.constraints ?? []).map((c, i) =>
      checkedConstraintDict(c, `${path}.constraints[${i}]`),
    ),
    expires_at: checkWireInt(cert.expires_at, `${path}.expires_at`),
    issued_at: checkWireInt(cert.issued_at, `${path}.issued_at`),
    issuer_id: cert.issuer_id,
    issuer_pub_key: cert.issuer_pub_key,
    scope: cert.scope,
    signature: cert.signature,
    subject_id: cert.subject_id,
    subject_pub_key: cert.subject_pub_key,
    version: checkWireInt(cert.version, `${path}.version`),
  };
}

// The only integer-valued constraint fields are max_rate's count and
// window_s; the remaining constraint numerics are floats and are not
// subject to the integer domain.
function checkedConstraintDict(c: Constraint, path: string): Record<string, unknown> {
  const dict = canonicalConstraintDict(c);
  if ("count" in dict) checkWireInt(dict.count, `${path}.count`);
  if ("window_s" in dict) checkWireInt(dict.window_s, `${path}.window_s`);
  return dict;
}

// Encoders must never emit an integer their own decoder rejects: JSON
// integer wire fields are bounded by the IEEE-754 safe-integer range
// (SPEC §6.2). A bigint is rejected outright — canonicalJSON would happily
// serialize its digits, silently bypassing the domain check otherwise.
function checkWireInt(v: unknown, field: string): number {
  if (typeof v === "bigint") {
    throw new Error(
      `wire: ${field}: bigint is not a wire integer; use a number within the safe-integer range`,
    );
  }
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new Error(`wire: ${field}: expected integer`);
  }
  if (!Number.isSafeInteger(v)) {
    throw new Error(
      `wire: ${field}: integer outside the safe-integer range [-(2^53-1), 2^53-1]`,
    );
  }
  return v;
}

function jsonText(value: unknown): string {
  return new TextDecoder().decode(canonicalJSON(value));
}

// ============================================================================
// Decoders
// ============================================================================

/**
 * Decode a DelegationCert from wire JSON. Strict: rejects unknown fields,
 * malformed base64, and wrong cryptographic byte lengths.
 */
export function decodeDelegationCert(input: string | Uint8Array): DelegationCert {
  return decodeCertObj(asObject(parseInput(input), "DelegationCert"), "DelegationCert");
}

/**
 * Decode a ProofBundle from wire JSON. Strict: rejects unknown fields,
 * malformed base64, wrong cryptographic byte lengths, and unpaired v1.1
 * stream fields.
 */
export function decodeProofBundle(input: string | Uint8Array): ProofBundle {
  // Input bound (SPEC §5.1): an oversized payload is rejected BEFORE any
  // parsing — even garbage bytes of the right size never reach the parser.
  const nbytes = typeof input === "string" ? utf8ByteLength(input) : input.length;
  if (nbytes > MAX_PROOF_BUNDLE_BYTES) {
    throw new Error(
      `wire: proof bundle of ${nbytes} bytes exceeds MAX_PROOF_BUNDLE_BYTES (${MAX_PROOF_BUNDLE_BYTES})`,
    );
  }
  const obj = asObject(parseInput(input), "ProofBundle");
  const path = "ProofBundle";
  checkKeys(
    obj,
    [
      "agent_id",
      "agent_pub_key",
      "challenge",
      "challenge_at",
      "challenge_sig",
      "delegations",
      "session_context",
      "stream_id",
      "stream_seq",
    ],
    path,
  );
  const delegationsRaw = getArray(obj, "delegations", path);
  if (delegationsRaw.length === 0) {
    throw new Error(
      `wire: ${path}.delegations: must contain at least one certificate (SPEC §10)`,
    );
  }
  const bundle: ProofBundle = {
    agent_id: getString(obj, "agent_id", path),
    agent_pub_key: decodePubKeyObj(obj.agent_pub_key, `${path}.agent_pub_key`),
    delegations: delegationsRaw.map((c, i) =>
      decodeCertObj(asObject(c, `${path}.delegations[${i}]`), `${path}.delegations[${i}]`),
    ),
    challenge: getBytes(obj, "challenge", path, BINDING_SIZE),
    challenge_at: getInt(obj, "challenge_at", path),
    challenge_sig: decodeSignatureObj(obj.challenge_sig, `${path}.challenge_sig`),
  };
  if (obj.session_context !== undefined) {
    bundle.session_context = getBytes(obj, "session_context", path, BINDING_SIZE);
  }
  const hasStreamID = obj.stream_id !== undefined;
  const hasStreamSeq = obj.stream_seq !== undefined;
  if (hasStreamID !== hasStreamSeq) {
    throw new Error(
      `wire: ${path}: stream_id and stream_seq must be present together (SPEC §5.8)`,
    );
  }
  if (hasStreamID) {
    bundle.stream_id = getBytes(obj, "stream_id", path, BINDING_SIZE);
    const seq = getInt(obj, "stream_seq", path);
    if (seq < 1) {
      throw new Error(`wire: ${path}.stream_seq: must be >= 1, got ${seq}`);
    }
    bundle.stream_seq = seq;
  }
  return bundle;
}

/**
 * Decode a SessionToken from wire JSON. Strict: rejects unknown fields,
 * malformed base64, and wrong byte lengths.
 */
export function decodeSessionToken(input: string | Uint8Array): SessionToken {
  const obj = asObject(parseInput(input), "SessionToken");
  const path = "SessionToken";
  checkKeys(
    obj,
    [
      "agent_id",
      "agent_pub_key",
      "chain_hash",
      "granted_scope",
      "human_id",
      "issued_at",
      "mac",
      "session_id",
      "valid_until",
      "version",
    ],
    path,
  );
  return {
    version: getInt(obj, "version", path),
    session_id: getString(obj, "session_id", path),
    agent_id: getString(obj, "agent_id", path),
    agent_pub_key: decodePubKeyObj(obj.agent_pub_key, `${path}.agent_pub_key`),
    human_id: getString(obj, "human_id", path),
    granted_scope: getStringArray(obj, "granted_scope", path),
    issued_at: getInt(obj, "issued_at", path),
    valid_until: getInt(obj, "valid_until", path),
    chain_hash: getBytes(obj, "chain_hash", path, BINDING_SIZE),
    mac: getBytes(obj, "mac", path, BINDING_SIZE),
  };
}

// ============================================================================
// VerificationReceipt codec (SPEC §17.5)
// ============================================================================

// The closed identity_status vocabulary a receipt may attest (SPEC §5.9,
// §17.5). Receipts record verifier decisions; a string outside the enum is
// structurally invalid on both codec sides. "unauthorized" is reserved in the
// §5.9 enum (never emitted by the reference verifier) but enum-valid on wire.
const VALID_RECEIPT_DECISIONS: ReadonlySet<string> = new Set([
  "authorized_agent",
  "verified_human",
  "expired",
  "revoked",
  "scope_denied",
  "constraint_denied",
  "constraint_unverifiable",
  "constraint_unknown",
  "invalid_scope",
  "delegation_not_authorized",
  "invalid",
  "unauthorized",
]);

// Enforce the structural invariants of a wire VerificationReceipt
// (SPEC §17.5) — shared by encoder and decoder so the codec pair never emits
// a document its counterpart rejects.
function checkReceiptStructure(r: VerificationReceipt | null | undefined): void {
  if (r === null || r === undefined) {
    throw new Error("wire: nil verification receipt");
  }
  if (r.version !== PROTOCOL_VERSION) {
    throw new Error(`wire: receipt version ${r.version} is not PROTOCOL_VERSION (${PROTOCOL_VERSION})`);
  }
  if (!r.verifier_id) {
    throw new Error("wire: receipt verifier_id must be non-empty");
  }
  if (!VALID_RECEIPT_DECISIONS.has(r.decision)) {
    throw new Error(`wire: receipt decision "${r.decision}" is not a known identity_status`);
  }
  if (r.bundle_hash.length !== 32) {
    throw new Error(`wire: bundle_hash must be 32 bytes, got ${r.bundle_hash.length}`);
  }
  if (r.prev_hash.length !== 32) {
    throw new Error(`wire: prev_hash must be 32 bytes, got ${r.prev_hash.length}`);
  }
  if (r.verifier_pub.ed25519.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`wire: verifier_pub.ed25519 must be ${ED25519_PUBLIC_KEY_SIZE} bytes, got ${r.verifier_pub.ed25519.length}`);
  }
  if (r.verifier_pub.ml_dsa_65.length !== MLDSA65_PUBLIC_KEY_SIZE) {
    throw new Error(`wire: verifier_pub.ml_dsa_65 must be ${MLDSA65_PUBLIC_KEY_SIZE} bytes, got ${r.verifier_pub.ml_dsa_65.length}`);
  }
  if (r.signature.ed25519.length !== ED25519_SIGNATURE_SIZE) {
    throw new Error(`wire: signature.ed25519 must be ${ED25519_SIGNATURE_SIZE} bytes, got ${r.signature.ed25519.length}`);
  }
  if (r.signature.ml_dsa_65.length !== MLDSA65_SIGNATURE_SIZE) {
    throw new Error(`wire: signature.ml_dsa_65 must be ${MLDSA65_SIGNATURE_SIZE} bytes, got ${r.signature.ml_dsa_65.length}`);
  }
}

/**
 * Encode a VerificationReceipt into its canonical wire JSON (SPEC §17.5):
 * lex-sorted keys, byte fields as base64-standard strings, optional fields
 * omitted when empty. A structurally invalid receipt (wrong hash/key lengths,
 * unknown decision, wrong version) is an error, never emitted — the codec
 * pair never produces a document its own decoder rejects.
 */
export function encodeVerificationReceipt(r: VerificationReceipt): string {
  checkReceiptStructure(r);
  const dict: JsonObj = {
    bundle_hash: r.bundle_hash,
    decision: r.decision,
    prev_hash: r.prev_hash,
    signature: r.signature,
    verified_at: checkWireInt(r.verified_at, "VerificationReceipt.verified_at"),
    verifier_id: r.verifier_id,
    verifier_pub: r.verifier_pub,
    version: checkWireInt(r.version, "VerificationReceipt.version"),
  };
  // Optional fields carry Go's omitempty semantics.
  if (r.agent_id) dict.agent_id = r.agent_id;
  if (r.error_reason) dict.error_reason = r.error_reason;
  if (r.granted_scope !== undefined && r.granted_scope.length > 0) {
    dict.granted_scope = r.granted_scope;
  }
  if (r.human_id) dict.human_id = r.human_id;
  return jsonText(dict);
}

/**
 * Decode a VerificationReceipt from wire JSON under strict wire acceptance and
 * the same structural invariants the encoder enforces. Signature verification
 * is the caller's job via verifyVerificationReceipt.
 */
export function decodeVerificationReceipt(input: string | Uint8Array): VerificationReceipt {
  const obj = asObject(parseInput(input), "VerificationReceipt");
  const path = "VerificationReceipt";
  checkKeys(
    obj,
    [
      "agent_id",
      "bundle_hash",
      "decision",
      "error_reason",
      "granted_scope",
      "human_id",
      "prev_hash",
      "signature",
      "verified_at",
      "verifier_id",
      "verifier_pub",
      "version",
    ],
    path,
  );
  const r: VerificationReceipt = {
    version: getInt(obj, "version", path),
    verifier_id: getString(obj, "verifier_id", path),
    verifier_pub: decodePubKeyObj(obj.verifier_pub, `${path}.verifier_pub`),
    bundle_hash: getBytes(obj, "bundle_hash", path, BINDING_SIZE),
    decision: getString(obj, "decision", path) as IdentityStatus,
    verified_at: getInt(obj, "verified_at", path),
    prev_hash: getBytes(obj, "prev_hash", path, BINDING_SIZE),
    signature: decodeSignatureObj(obj.signature, `${path}.signature`),
  };
  if (obj.human_id !== undefined) r.human_id = getString(obj, "human_id", path);
  if (obj.agent_id !== undefined) r.agent_id = getString(obj, "agent_id", path);
  if (obj.granted_scope !== undefined) r.granted_scope = getStringArray(obj, "granted_scope", path);
  if (obj.error_reason !== undefined) r.error_reason = getString(obj, "error_reason", path);
  checkReceiptStructure(r);
  return r;
}

// ----- Nested structures -----

function decodeCertObj(obj: JsonObj, path: string): DelegationCert {
  checkKeys(
    obj,
    [
      "cert_id",
      "constraints",
      "expires_at",
      "issued_at",
      "issuer_id",
      "issuer_pub_key",
      "scope",
      "signature",
      "subject_id",
      "subject_pub_key",
      "version",
    ],
    path,
  );
  const constraintsRaw = getArray(obj, "constraints", path);
  const cert: DelegationCert = {
    cert_id: getString(obj, "cert_id", path),
    version: getInt(obj, "version", path),
    issuer_id: getString(obj, "issuer_id", path),
    issuer_pub_key: decodePubKeyObj(obj.issuer_pub_key, `${path}.issuer_pub_key`),
    subject_id: getString(obj, "subject_id", path),
    subject_pub_key: decodePubKeyObj(obj.subject_pub_key, `${path}.subject_pub_key`),
    scope: getStringArray(obj, "scope", path),
    constraints: constraintsRaw.map((c, i) =>
      decodeConstraintObj(
        asObject(c, `${path}.constraints[${i}]`),
        `${path}.constraints[${i}]`,
      ),
    ),
    issued_at: getInt(obj, "issued_at", path),
    expires_at: getInt(obj, "expires_at", path),
    signature: decodeSignatureObj(obj.signature, `${path}.signature`),
  };
  checkCertBounds(cert, path);
  return cert;
}

function decodePubKeyObj(raw: unknown, path: string): HybridPublicKey {
  const obj = asObject(raw, path);
  checkKeys(obj, ["ed25519", "ml_dsa_65"], path);
  return {
    ed25519: getBytes(obj, "ed25519", path, ED25519_PUBLIC_KEY_SIZE),
    ml_dsa_65: getBytes(obj, "ml_dsa_65", path, MLDSA65_PUBLIC_KEY_SIZE),
  };
}

function decodeSignatureObj(raw: unknown, path: string): HybridSignature {
  const obj = asObject(raw, path);
  checkKeys(obj, ["ed25519", "ml_dsa_65"], path);
  return {
    ed25519: getBytes(obj, "ed25519", path, ED25519_SIGNATURE_SIZE),
    ml_dsa_65: getBytes(obj, "ml_dsa_65", path, MLDSA65_SIGNATURE_SIZE),
  };
}

// Per-kind canonical field sets (SPEC §5.7.2; mirrors Go's
// Constraint.MarshalJSON): kind-relevant fields are always present, other
// fields never appear. Unknown constraint types carry only the tag — the
// verifier rejects them with constraint_unknown, but they must decode so
// they can reach the verifier.
function decodeConstraintObj(obj: JsonObj, path: string): Constraint {
  const type = getString(obj, "type", path);
  const c: Constraint = { type: type as ConstraintType };
  switch (type) {
    case "geo_circle":
      checkKeys(obj, ["lat", "lon", "radius_m", "type"], path);
      c.lat = getNumber(obj, "lat", path);
      c.lon = getNumber(obj, "lon", path);
      c.radius_m = getNumber(obj, "radius_m", path);
      break;
    case "geo_polygon":
      checkKeys(obj, ["points", "type"], path);
      c.points = getPoints(obj, "points", path);
      break;
    case "geo_bbox": {
      checkKeys(
        obj,
        ["max_alt_m", "max_lat", "max_lon", "min_alt_m", "min_lat", "min_lon", "type"],
        path,
      );
      c.max_lat = getNumber(obj, "max_lat", path);
      c.max_lon = getNumber(obj, "max_lon", path);
      c.min_lat = getNumber(obj, "min_lat", path);
      c.min_lon = getNumber(obj, "min_lon", path);
      const hasMinAlt = obj.min_alt_m !== undefined;
      const hasMaxAlt = obj.max_alt_m !== undefined;
      if (hasMinAlt !== hasMaxAlt) {
        throw new Error(
          `wire: ${path}: min_alt_m and max_alt_m must be present together`,
        );
      }
      if (hasMinAlt) {
        c.min_alt_m = getNumber(obj, "min_alt_m", path);
        c.max_alt_m = getNumber(obj, "max_alt_m", path);
      }
      break;
    }
    case "time_window":
      checkKeys(obj, ["end", "start", "tz", "type"], path);
      c.start = getString(obj, "start", path);
      c.end = getString(obj, "end", path);
      c.tz = getString(obj, "tz", path);
      break;
    case "max_speed_mps":
      checkKeys(obj, ["max_mps", "type"], path);
      c.max_mps = getNumber(obj, "max_mps", path);
      break;
    case "max_amount":
      checkKeys(obj, ["currency", "max_amount", "type"], path);
      c.currency = getString(obj, "currency", path);
      c.max_amount = getNumber(obj, "max_amount", path);
      break;
    case "max_rate":
      checkKeys(obj, ["count", "type", "window_s"], path);
      c.count = getInt(obj, "count", path);
      c.window_s = getInt(obj, "window_s", path);
      break;
    case "resource_path": {
      // path_prefix PRESENCE is load-bearing (SPEC §5.7.3): ABSENT means the
      // entire named resource; PRESENT as "" / null / non-string is REJECTED
      // — a malformed restriction must never silently widen into
      // whole-resource authority.
      if ("path_prefix" in obj) {
        const pp = obj.path_prefix;
        if (typeof pp !== "string" || pp === "") {
          throw new Error(
            `wire: ${path}.path_prefix: must be a non-empty string; omit the field to authorize the entire resource`,
          );
        }
      }
      checkKeys(obj, ["path_prefix", "resource_id", "type"], path);
      const resourceID = getString(obj, "resource_id", path);
      if (resourceID === "") {
        throw new Error(
          `wire: ${path}.resource_id: resource_path constraint requires a non-empty resource_id`,
        );
      }
      c.resource_id = resourceID;
      if ("path_prefix" in obj) c.path_prefix = obj.path_prefix as string;
      break;
    }
    default: {
      // Extension kind (SPEC §5.7.1): the canonical form carries the tag and
      // optionally a params object under the restricted value model.
      // Canonical types never reach this branch, so params here can never
      // widen a canonical type. The verifier rejects unknown types with
      // constraint_unknown, but they must decode so they reach the verifier.
      checkKeys(obj, ["params", "type"], path);
      if ("params" in obj) {
        const params = obj.params;
        if (params === null || typeof params !== "object" || Array.isArray(params)) {
          throw new Error(`wire: ${path}.params: expected object`);
        }
        try {
          validateParamsValue(params, 0);
        } catch (e) {
          throw new Error(`wire: ${path}.params: ${(e as Error).message}`);
        }
        c.params = params as Record<string, unknown>;
      }
      break;
    }
  }
  return c;
}

// Enforce the per-cert count and length limits of SPEC §5.1 during decode. It
// does NOT enforce issuance hygiene (validateResourceConstraints) — decoders
// accept what issuance rejects; verification fails unsatisfiable sets closed.
function checkCertBounds(cert: DelegationCert, path: string): void {
  if (cert.scope.length > MAX_SCOPES_PER_CERT) {
    throw new Error(
      `wire: ${path}: ${cert.scope.length} scopes exceeds MAX_SCOPES_PER_CERT (${MAX_SCOPES_PER_CERT})`,
    );
  }
  const constraints = cert.constraints ?? [];
  if (constraints.length > MAX_CONSTRAINTS_PER_CERT) {
    throw new Error(
      `wire: ${path}: ${constraints.length} constraints exceeds MAX_CONSTRAINTS_PER_CERT (${MAX_CONSTRAINTS_PER_CERT})`,
    );
  }
  for (const s of cert.scope) {
    const sLen = utf8ByteLength(s);
    if (sLen > MAX_SCOPE_LENGTH_BYTES) {
      throw new Error(
        `wire: ${path}: scope of ${sLen} bytes exceeds MAX_SCOPE_LENGTH_BYTES (${MAX_SCOPE_LENGTH_BYTES})`,
      );
    }
  }
  for (const c of constraints) {
    if (c.resource_id !== undefined) {
      const idLen = utf8ByteLength(c.resource_id);
      if (idLen > MAX_IDENTIFIER_LENGTH_BYTES) {
        throw new Error(
          `wire: ${path}: resource_id of ${idLen} bytes exceeds MAX_IDENTIFIER_LENGTH_BYTES (${MAX_IDENTIFIER_LENGTH_BYTES})`,
        );
      }
    }
  }
}

// ============================================================================
// Strict field accessors
// ============================================================================

// JSON.parse keeps the LAST occurrence of a duplicated object key, offers
// no hook to detect duplicates, and normalizes numeric lexemes ("1000.0"
// and "1e3" both become 1000) before any accessor can see the original
// form. After JSON.parse validates the syntax, scanWireText re-scans the
// text and (a) fails closed on any object that repeats a key — at every
// nesting depth, with string escapes decoded first, so "agent_id" and the
// same key written with a Unicode escape collide (matching the Python
// codec's object_pairs_hook behavior) — and (b) records the path of every
// numeric token written with a fraction or exponent, so integer field
// accessors can reject non-integer lexical forms the way Python, Go, and
// Rust parsers do. Float constraint fields are unaffected.
//
// The recorded paths of fraction/exponent numeric lexemes from the most
// recent parseInput call. Decoding is synchronous and non-reentrant, so a
// module-level slot is safe: it is replaced at the start of every decode
// before any accessor runs.
let floatLexemePaths: ReadonlySet<string> = new Set();

function parseInput(input: string | Uint8Array): unknown {
  let text: string;
  if (typeof input === "string") {
    text = input;
  } else {
    // Strict byte decoding, matching the Python codec: malformed UTF-8 is
    // rejected (the default TextDecoder would silently substitute U+FFFD),
    // and a leading BOM is NOT stripped — it reaches JSON.parse and is
    // rejected as invalid JSON there.
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch (e) {
      throw new Error(`wire: invalid UTF-8: ${(e as Error).message}`);
    }
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`wire: invalid JSON: ${(e as Error).message}`);
  }
  floatLexemePaths = scanWireText(text);
  return parsed;
}

// Single-pass scan over text already validated by JSON.parse. Tracks
// object/array nesting; inside an object, the string that opens a member is
// the key — collect it (escape-decoded) per object and error on a repeat
// (the same key text in different sibling objects is fine). Returns the
// set of root-relative paths (e.g. "delegations[0].issued_at") whose
// numeric token carries a fraction or exponent.
function scanWireText(text: string): Set<string> {
  const floatPaths = new Set<string>();
  interface Frame {
    keys: Set<string> | null; // object: seen keys; array: null
    pendingKey: string; // object: key of the member currently being read
    index: number; // array: index of the next value
    seg: string; // this container's path segment within its parent
  }
  const frames: Frame[] = [];
  let expectKey = false; // next string is a member key of the innermost object

  const leafSeg = (): string => {
    const top = frames[frames.length - 1];
    if (!top) return "";
    return top.keys ? top.pendingKey : `[${top.index}]`;
  };
  const joinSeg = (base: string, seg: string): string =>
    seg.startsWith("[") ? base + seg : base === "" ? seg : `${base}.${seg}`;
  const pathTo = (leaf: string): string => {
    let out = "";
    for (let i = 1; i < frames.length; i++) {
      out = joinSeg(out, frames[i]!.seg);
    }
    return joinSeg(out, leaf);
  };
  // A value just finished: an object expects the next member key; an array
  // advances to its next index.
  const valueDone = (): void => {
    const top = frames[frames.length - 1];
    if (!top) return;
    if (top.keys) {
      expectKey = true;
    } else {
      top.index++;
    }
  };

  const NUMBER_CHARS = "0123456789+-.eE";
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '"') {
      const [str, next] = scanJSONString(text, i);
      const keys = frames[frames.length - 1]?.keys;
      if (expectKey && keys) {
        if (keys.has(str)) {
          throw new Error(`wire: duplicate key "${str}" in JSON object`);
        }
        keys.add(str);
        frames[frames.length - 1]!.pendingKey = str;
        expectKey = false;
      } else {
        valueDone(); // string value
      }
      i = next;
      continue;
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      let isFloat = false;
      let j = i;
      while (j < text.length && NUMBER_CHARS.includes(text[j]!)) {
        if (text[j] === "." || text[j] === "e" || text[j] === "E") isFloat = true;
        j++;
      }
      if (isFloat) floatPaths.add(pathTo(leafSeg()));
      i = j;
      valueDone();
      continue;
    }
    switch (c) {
      case "{":
        // Input bound (SPEC §5.1): reject nesting beyond MAX_JSON_NESTING_DEPTH
        // during (not after) parse, matching Go's CheckWireJSON.
        if (frames.length >= MAX_JSON_NESTING_DEPTH) {
          throw new Error(
            `wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH (${MAX_JSON_NESTING_DEPTH})`,
          );
        }
        frames.push({ keys: new Set(), pendingKey: "", index: 0, seg: leafSeg() });
        expectKey = true;
        break;
      case "[":
        if (frames.length >= MAX_JSON_NESTING_DEPTH) {
          throw new Error(
            `wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH (${MAX_JSON_NESTING_DEPTH})`,
          );
        }
        frames.push({ keys: null, pendingKey: "", index: 0, seg: leafSeg() });
        expectKey = false;
        break;
      case "}":
      case "]":
        frames.pop();
        valueDone();
        break;
      case "t": // true
        i += 3;
        valueDone();
        break;
      case "f": // false
        i += 4;
        valueDone();
        break;
      case "n": // null
        i += 3;
        valueDone();
        break;
      default:
        break; // ':', ',', whitespace
    }
    i++;
  }
  return floatPaths;
}

// Scan one JSON string starting at its opening quote; return the
// escape-decoded value and the index just past the closing quote. The text
// is known-valid JSON (JSON.parse already accepted it), so escapes are
// well-formed and the string is terminated.
function scanJSONString(text: string, start: number): [string, number] {
  let out = "";
  let i = start + 1;
  for (;;) {
    const c = text[i]!;
    if (c === '"') return [out, i + 1];
    if (c === "\\") {
      const e = text[i + 1]!;
      if (e === "u") {
        out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
        i += 6;
        continue;
      }
      switch (e) {
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        default: out += e; break; // '"', '\\', '/'
      }
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
}

function asObject(v: unknown, path: string): JsonObj {
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    throw new Error(`wire: ${path}: expected JSON object`);
  }
  return v as JsonObj;
}

function checkKeys(obj: JsonObj, allowed: readonly string[], path: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) {
      throw new Error(`wire: ${path}: unknown field "${k}"`);
    }
  }
}

function getString(obj: JsonObj, key: string, path: string): string {
  const v = obj[key];
  if (typeof v !== "string") {
    throw new Error(`wire: ${path}.${key}: expected string`);
  }
  return v;
}

function getNumber(obj: JsonObj, key: string, path: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new Error(`wire: ${path}.${key}: expected number`);
  }
  return v;
}

function getInt(obj: JsonObj, key: string, path: string): number {
  const v = getNumber(obj, key, path);
  if (!Number.isInteger(v)) {
    throw new Error(`wire: ${path}.${key}: expected integer`);
  }
  // JSON.parse normalizes "1000.0" and "1e3" to 1000 before this accessor
  // runs; the pre-scan recorded which numeric tokens carried a fraction or
  // exponent, so non-integer lexical forms are rejected here the way the
  // Python, Go, and Rust parsers reject them natively.
  if (floatLexemePaths.has(rootRelativePath(path, key))) {
    throw new Error(
      `wire: ${path}.${key}: integer field must use plain decimal form (no fraction or exponent)`,
    );
  }
  // Interoperable integer domain for JSON wire fields (SPEC §6.2): the
  // IEEE-754 safe-integer range. Binary signable representations use
  // 64-bit fields, but a JSON integer outside this range does not survive
  // a double-precision JSON parser, so strict decoders reject it.
  if (!Number.isSafeInteger(v)) {
    throw new Error(
      `wire: ${path}.${key}: integer outside the safe-integer range [-(2^53-1), 2^53-1]`,
    );
  }
  return v;
}

// Accessor paths carry a root name ("ProofBundle.delegations[0]"); the
// pre-scan's paths are root-relative ("delegations[0].issued_at").
function rootRelativePath(path: string, key: string): string {
  const dot = path.indexOf(".");
  const rel = dot === -1 ? "" : path.slice(dot + 1);
  return rel === "" ? key : `${rel}.${key}`;
}

function getArray(obj: JsonObj, key: string, path: string): unknown[] {
  const v = obj[key];
  if (!Array.isArray(v)) {
    throw new Error(`wire: ${path}.${key}: expected array`);
  }
  return v;
}

function getStringArray(obj: JsonObj, key: string, path: string): string[] {
  const arr = getArray(obj, key, path);
  for (let i = 0; i < arr.length; i++) {
    if (typeof arr[i] !== "string") {
      throw new Error(`wire: ${path}.${key}[${i}]: expected string`);
    }
  }
  return arr as string[];
}

function getPoints(obj: JsonObj, key: string, path: string): [number, number][] {
  const arr = getArray(obj, key, path);
  return arr.map((p, i) => {
    if (
      !Array.isArray(p) ||
      p.length !== 2 ||
      typeof p[0] !== "number" ||
      typeof p[1] !== "number" ||
      !Number.isFinite(p[0]) ||
      !Number.isFinite(p[1])
    ) {
      throw new Error(`wire: ${path}.${key}[${i}]: expected [lat, lon] number pair`);
    }
    return [p[0], p[1]];
  });
}

function getBytes(obj: JsonObj, key: string, path: string, expectedLen: number): Uint8Array {
  const v = obj[key];
  if (typeof v !== "string") {
    throw new Error(`wire: ${path}.${key}: expected base64 string`);
  }
  return decodeBase64Strict(v, `${path}.${key}`, expectedLen);
}

// RFC 4648 §4 standard alphabet, padded. The regex rejects malformed input;
// the re-encode comparison rejects non-canonical encodings (nonzero trailing
// bits), so decode(encode(x)) is byte-exact.
const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

function decodeBase64Strict(s: string, path: string, expectedLen: number): Uint8Array {
  if (!B64_RE.test(s)) {
    throw new Error(`wire: ${path}: malformed base64`);
  }
  const out = base64StandardDecode(s);
  if (base64StandardEncode(out) !== s) {
    throw new Error(`wire: ${path}: non-canonical base64`);
  }
  if (out.length !== expectedLen) {
    throw new Error(`wire: ${path}: expected ${expectedLen} bytes, got ${out.length}`);
  }
  return out;
}
