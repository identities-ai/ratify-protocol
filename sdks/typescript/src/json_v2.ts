// Protocol v2 JSON layer. It reproduces the observable behavior of the Go
// reference's encoding/json usage for v2 objects:
//
//   - a strict RFC 8259 parser over UTF-8 bytes that keeps every number
//     lexeme and byte offsets (for RawMessage-style hashing);
//   - checkWireJSONV2: the Go CheckWireJSON pre-pass (invalid UTF-8,
//     duplicate keys after escape decoding, nesting depth, safe-integer
//     integer tokens, canonical base64 in protocol byte fields);
//   - Go-typed field extraction (null leaves the zero value, unknown fields
//     fail, integer fields reject fraction/exponent lexemes);
//   - the Go CanonicalJSON encoder, including HTML escaping inside subtrees
//     that Go marshals with json.Marshal (constraints, revoked-set digests).
//
// It is independent from the v1 codec in canonical.ts and wire.ts.

import { MAX_JSON_NESTING_DEPTH } from "./types.js";

export const MAX_SAFE_INTEGER_V2 = Number.MAX_SAFE_INTEGER;

export type JNode =
  | { k: "obj"; m: Map<string, JNode>; s: number; e: number }
  | { k: "arr"; a: JNode[]; s: number; e: number }
  | { k: "str"; v: string; s: number; e: number }
  | { k: "num"; raw: string; s: number; e: number }
  | { k: "bool"; v: boolean; s: number; e: number }
  | { k: "null"; s: number; e: number };

export interface ParseOptions {
  /** Reject a repeated (escape-decoded) key in any object. Go CheckWireJSON. */
  rejectDuplicates?: boolean;
  /** Reject container nesting deeper than MAX_JSON_NESTING_DEPTH. */
  limitDepth?: boolean;
  /** Reject integer-formed tokens outside +-(2^53-1). */
  safeIntegers?: boolean;
  /**
   * Protocol v2 strict rules (Go checkWireJSON strictV2): an unpaired UTF-16
   * surrogate escape and a number spelled with a negative zero integer part
   * (any spelling whose value is negative zero) are rejected instead of
   * silently decoded; ordinary negative floats such as -0.5 are accepted.
   */
  strictV2?: boolean;
}

const utf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const utf8Encoder = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return utf8Encoder.encode(s);
}

export function isValidUTF8(bytes: Uint8Array): boolean {
  try {
    utf8Strict.decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/** True when a JS string has no lone surrogate (Go utf8.ValidString analogue). */
export function isWellFormedString(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (n < 0xdc00 || n > 0xdfff) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/** Byte length of the UTF-8 encoding of s (Go len(string)). */
export function utf8Len(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n += 4;
        i++;
      } else n += 3;
    } else n += 3;
  }
  return n;
}

/** Go string comparison: byte-wise over UTF-8. */
export function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  const ab = utf8(a);
  const bb = utf8(b);
  return compareBytes(ab, bb);
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

export function bytesEqual(a: Uint8Array | null | undefined, b: Uint8Array | null | undefined): boolean {
  // Go bytes.Equal treats nil and empty as equal.
  const x = a ?? new Uint8Array(0);
  const y = b ?? new Uint8Array(0);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function hexOf(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Go hex.DecodeString: even length, either case accepted. */
export function hexDecodeGo(s: string): Uint8Array | null {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function uint64BE(value: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

export function uint16BE(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

// ---------------------------------------------------------------------------
// Parser

class JSONSyntaxError extends Error {}

export function parseJSONV2(bytes: Uint8Array, opts: ParseOptions = {}): JNode {
  if (!isValidUTF8(bytes)) throw new Error("wire: invalid UTF-8");
  const p = new Parser(bytes, opts);
  p.ws();
  const root = p.value(0);
  p.ws();
  if (p.i !== bytes.length) throw new Error("wire: trailing data after JSON document");
  return root;
}

class Parser {
  i = 0;
  constructor(readonly b: Uint8Array, readonly opts: ParseOptions) {}

  ws(): void {
    while (this.i < this.b.length) {
      const c = this.b[this.i]!;
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  fail(msg: string): never {
    throw new JSONSyntaxError(`wire: invalid JSON: ${msg} at offset ${this.i}`);
  }

  value(depth: number): JNode {
    if (this.i >= this.b.length) this.fail("unexpected end of input");
    const c = this.b[this.i]!;
    const s = this.i;
    switch (c) {
      case 0x7b: { // {
        if (this.opts.limitDepth && depth >= MAX_JSON_NESTING_DEPTH) {
          throw new Error(`wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH (${MAX_JSON_NESTING_DEPTH})`);
        }
        this.i++;
        const m = new Map<string, JNode>();
        this.ws();
        if (this.b[this.i] === 0x7d) {
          this.i++;
          return { k: "obj", m, s, e: this.i };
        }
        for (;;) {
          this.ws();
          if (this.b[this.i] !== 0x22) this.fail("expected object key");
          const key = this.string();
          if (m.has(key) && this.opts.rejectDuplicates) {
            throw new Error(`wire: duplicate key ${JSON.stringify(key)} in JSON object`);
          }
          this.ws();
          if (this.b[this.i] !== 0x3a) this.fail("expected ':'");
          this.i++;
          this.ws();
          const v = this.value(depth + 1);
          // Go keeps the last occurrence when duplicates are not rejected.
          m.delete(key);
          m.set(key, v);
          this.ws();
          const d = this.b[this.i];
          if (d === 0x2c) {
            this.i++;
            continue;
          }
          if (d === 0x7d) {
            this.i++;
            return { k: "obj", m, s, e: this.i };
          }
          this.fail("expected ',' or '}'");
        }
      }
      case 0x5b: { // [
        if (this.opts.limitDepth && depth >= MAX_JSON_NESTING_DEPTH) {
          throw new Error(`wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH (${MAX_JSON_NESTING_DEPTH})`);
        }
        this.i++;
        const a: JNode[] = [];
        this.ws();
        if (this.b[this.i] === 0x5d) {
          this.i++;
          return { k: "arr", a, s, e: this.i };
        }
        for (;;) {
          this.ws();
          a.push(this.value(depth + 1));
          this.ws();
          const d = this.b[this.i];
          if (d === 0x2c) {
            this.i++;
            continue;
          }
          if (d === 0x5d) {
            this.i++;
            return { k: "arr", a, s, e: this.i };
          }
          this.fail("expected ',' or ']'");
        }
      }
      case 0x22: {
        const v = this.string();
        return { k: "str", v, s, e: this.i };
      }
      case 0x74: // t
        this.literal("true");
        return { k: "bool", v: true, s, e: this.i };
      case 0x66: // f
        this.literal("false");
        return { k: "bool", v: false, s, e: this.i };
      case 0x6e: // n
        this.literal("null");
        return { k: "null", s, e: this.i };
      default:
        if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
        this.fail("unexpected character");
    }
  }

  literal(word: string): void {
    for (let j = 0; j < word.length; j++) {
      if (this.b[this.i + j] !== word.charCodeAt(j)) this.fail(`invalid literal`);
    }
    this.i += word.length;
  }

  number(): JNode {
    const s = this.i;
    const b = this.b;
    const digit = (x: number | undefined) => x !== undefined && x >= 0x30 && x <= 0x39;
    if (b[this.i] === 0x2d) this.i++;
    if (b[this.i] === 0x30) {
      this.i++;
    } else if (digit(b[this.i])) {
      while (digit(b[this.i])) this.i++;
    } else this.fail("invalid number");
    if (b[this.i] === 0x2e) {
      this.i++;
      if (!digit(b[this.i])) this.fail("invalid number fraction");
      while (digit(b[this.i])) this.i++;
    }
    if (b[this.i] === 0x65 || b[this.i] === 0x45) {
      this.i++;
      if (b[this.i] === 0x2b || b[this.i] === 0x2d) this.i++;
      if (!digit(b[this.i])) this.fail("invalid number exponent");
      while (digit(b[this.i])) this.i++;
    }
    const raw = String.fromCharCode(...b.subarray(s, this.i));
    // Only a value equal to negative zero is rejected; -0.5 is a valid float.
    if (this.opts.strictV2 && raw.startsWith("-") && Number(raw) === 0) {
      throw new Error("wire: negative zero is not a canonical number");
    }
    if (this.opts.safeIntegers && !/[.eE]/.test(raw)) {
      const n = BigInt(raw);
      if (n > BigInt(MAX_SAFE_INTEGER_V2) || n < -BigInt(MAX_SAFE_INTEGER_V2)) {
        throw new Error(`wire: integer ${raw} outside the safe-integer range [-(2^53-1), 2^53-1]`);
      }
    }
    return { k: "num", raw, s, e: this.i };
  }

  // Decodes a string the way Go's encoding/json does: a lone surrogate
  // escape becomes U+FFFD; raw control characters are rejected.
  string(): string {
    const b = this.b;
    this.i++; // opening quote
    let out = "";
    let runStart = this.i;
    const flush = (end: number) => {
      if (end > runStart) out += utf8Strict.decode(b.subarray(runStart, end));
    };
    for (;;) {
      if (this.i >= b.length) this.fail("unterminated string");
      const c = b[this.i]!;
      if (c === 0x22) {
        flush(this.i);
        this.i++;
        return out;
      }
      if (c < 0x20) this.fail("control character in string");
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      flush(this.i);
      const e = b[this.i + 1];
      switch (e) {
        case 0x22: out += '"'; this.i += 2; break;
        case 0x5c: out += "\\"; this.i += 2; break;
        case 0x2f: out += "/"; this.i += 2; break;
        case 0x62: out += "\b"; this.i += 2; break;
        case 0x66: out += "\f"; this.i += 2; break;
        case 0x6e: out += "\n"; this.i += 2; break;
        case 0x72: out += "\r"; this.i += 2; break;
        case 0x74: out += "\t"; this.i += 2; break;
        case 0x75: {
          const u = this.hex4(this.i + 2);
          this.i += 6;
          if (u >= 0xd800 && u <= 0xdbff) {
            if (b[this.i] === 0x5c && b[this.i + 1] === 0x75) {
              const v = this.hex4(this.i + 2);
              if (v >= 0xdc00 && v <= 0xdfff) {
                out += String.fromCharCode(u, v);
                this.i += 6;
                break;
              }
            }
            if (this.opts.strictV2) throw new Error("wire: unpaired UTF-16 surrogate escape");
            out += String.fromCharCode(0xfffd);
          } else if (u >= 0xdc00 && u <= 0xdfff) {
            if (this.opts.strictV2) throw new Error("wire: unpaired UTF-16 surrogate escape");
            out += String.fromCharCode(0xfffd);
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          this.fail("invalid escape");
      }
      runStart = this.i;
    }
  }

  hex4(at: number): number {
    let v = 0;
    for (let j = 0; j < 4; j++) {
      const c = this.b[at + j];
      let d: number;
      if (c === undefined) this.fail("truncated \\u escape");
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x57;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x37;
      else this.fail("invalid \\u escape");
      v = (v << 4) | d;
    }
    return v;
  }
}

// ---------------------------------------------------------------------------
// CheckWireJSON

/** Protocol byte-field member names checked for canonical base64 at any depth. */
const WIRE_BYTE_FIELDS = new Set([
  "bundle_hash", "chain_hash", "challenge", "context_hash", "ed25519", "entry_data",
  "mac", "ml_dsa_65", "prev_hash", "session_context", "stream_id", "terms_canonical_json",
]);

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function base64Encode(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64");
}

/** Canonical (Go StdEncoding.Strict + re-encode) base64 decode, or null. */
export function base64DecodeCanonical(s: string): Uint8Array | null {
  if (!B64_RE.test(s)) return null;
  const out = new Uint8Array(Buffer.from(s, "base64"));
  if (base64Encode(out) !== s) return null;
  return out;
}

/**
 * Go CheckWireJSON / checkWireJSONV2 / checkWireJSONV2WithTextTopLevel.
 * Returns the parsed tree for typed extraction.
 */
export function checkWireJSONV2(
  data: Uint8Array,
  topLevelByteFields: readonly string[] = [],
  topLevelTextFields: readonly string[] = [],
): JNode {
  const root = parseJSONV2(data, { rejectDuplicates: true, limitDepth: true, safeIntegers: true, strictV2: true });
  const topBytes = new Set(topLevelByteFields);
  const topText = new Set(topLevelTextFields);
  const walk = (n: JNode, depth: number): void => {
    if (n.k === "obj") {
      for (const [key, v] of n.m) {
        if (v.k === "str") {
          const isTop = depth === 1;
          if ((WIRE_BYTE_FIELDS.has(key) && !(isTop && topText.has(key))) || (isTop && topBytes.has(key))) {
            if (base64DecodeCanonical(v.v) === null) {
              throw new Error(`wire: field ${JSON.stringify(key)}: malformed or non-canonical base64`);
            }
          }
        } else {
          walk(v, depth + 1);
        }
      }
    } else if (n.k === "arr") {
      for (const v of n.a) walk(v, depth + 1);
    }
  };
  walk(root, 1);
  return root;
}

// ---------------------------------------------------------------------------
// Schema checks shared by v2 decoders (requireV2Fields, key case, nulls)

const V2_SCHEMA_FIELD_NAMES = (
  "version cert_id issuer_id issuer_pub_key subject_id subject_pub_key scope constraints signature ed25519 ml_dsa_65 issued_at expires_at verifier_id agent_id agent_pub_key delegations delegation_digest challenge challenge_at challenge_sig session_context stream_id stream_seq type params count currency end lat lon max_alt_m max_amount max_lat max_lon max_mps min_alt_m min_lat min_lon path_prefix points radius_m resource_id start tz window_s exact_receiver_ids trust_domain_ids max_membership_age_seconds next_update sequence pushed_at revoked authority_id recovery_epoch role previous_statement_hash old_key new_key old_key_id new_key_id not_before old_signature new_signature log_id bundle_hash issuer_ids decision decision_reason identity_status trust_assessment status_assessment challenge_assessment context_assessment context_policy_digest verified_at required_scope granted_scope status_evidence_digests previous_receipt_hash human_id status_key_id object_type_code digest transaction_id created_at terms_schema_uri terms_canonical_json parties party_id proof_bundle_hash proof_bundle party_signatures invocation_id workspace_id session_id"
).split(" ");

function equalFoldASCIIName(key: string, canonical: string): boolean {
  // canonical names are lowercase ASCII; Go strings.EqualFold also folds
  // U+017F (long s) to 's' and U+212A (Kelvin) to 'k'.
  if (key.length !== canonical.length) return false;
  for (let i = 0; i < key.length; i++) {
    let c = key[i]!;
    if (c === "ſ") c = "s";
    else if (c === "K") c = "k";
    else c = c.toLowerCase();
    if (c !== canonical[i]) return false;
  }
  return true;
}

export function checkV2SchemaKeyCase(root: JNode): void {
  const walk = (n: JNode): void => {
    if (n.k === "obj") {
      for (const [key, v] of n.m) {
        for (const canonical of V2_SCHEMA_FIELD_NAMES) {
          if (key !== canonical && equalFoldASCIIName(key, canonical)) {
            throw new Error(`wire v2: field ${JSON.stringify(key)} has incorrect case; use ${JSON.stringify(canonical)}`);
          }
        }
        if (key !== "params") walk(v);
      }
    } else if (n.k === "arr") {
      for (const v of n.a) walk(v);
    }
  };
  walk(root);
}

export function requireV2Fields(root: JNode, names: readonly string[], nullable: readonly string[] = []): void {
  if (root.k !== "obj") {
    if (root.k === "null") throw new Error(`wire v2: required field ${JSON.stringify(names[0] ?? "")} is missing`);
    throw new Error("wire v2: expected a JSON object");
  }
  for (const name of names) {
    const v = root.m.get(name);
    if (v === undefined) throw new Error(`wire v2: required field ${JSON.stringify(name)} is missing`);
    if (v.k === "null" && !nullable.includes(name)) {
      throw new Error(`wire v2: required field ${JSON.stringify(name)} must not be null`);
    }
  }
  checkV2SchemaKeyCase(root);
}

/** checkV2Nulls: no null anywhere except inside a params member value. */
export function checkV2Nulls(n: JNode): void {
  if (n.k === "null") throw new Error("null is not allowed in this v2 object");
  if (n.k === "obj") {
    for (const [key, v] of n.m) {
      if (key === "params") continue;
      checkV2Nulls(v);
    }
  } else if (n.k === "arr") {
    for (const v of n.a) checkV2Nulls(v);
  }
}

// ---------------------------------------------------------------------------
// Go-typed field extraction. `undefined` is an absent member.

export type Fields = Map<string, JNode>;

/** A struct-typed value: null/absent is the zero struct; unknown keys fail. */
export function gStruct(n: JNode | undefined, allowed: readonly string[], what: string): Fields {
  if (n === undefined || n.k === "null") return new Map();
  if (n.k !== "obj") throw new Error(`wire: cannot unmarshal into ${what}: expected object`);
  for (const key of n.m.keys()) {
    if (!allowed.includes(key)) throw new Error(`wire: json: unknown field ${JSON.stringify(key)}`);
  }
  return n.m;
}

export function gString(n: JNode | undefined, what: string): string {
  if (n === undefined || n.k === "null") return "";
  if (n.k !== "str") throw new Error(`wire: ${what} must be a string`);
  return n.v;
}

export function gBool(n: JNode | undefined, what: string): boolean {
  if (n === undefined || n.k === "null") return false;
  if (n.k !== "bool") throw new Error(`wire: ${what} must be a boolean`);
  return n.v;
}

/** int / int64 field: integer lexeme within int64; safe range enforced by caller checks. */
export function gInt(n: JNode | undefined, what: string): number {
  if (n === undefined || n.k === "null") return 0;
  if (n.k !== "num" || /[.eE]/.test(n.raw)) throw new Error(`wire: ${what} must be an integer`);
  const v = BigInt(n.raw);
  if (v > 0x7fffffffffffffffn || v < -0x8000000000000000n) throw new Error(`wire: ${what} overflows int64`);
  if (v > BigInt(MAX_SAFE_INTEGER_V2) || v < -BigInt(MAX_SAFE_INTEGER_V2)) {
    throw new Error(`wire: ${what} is outside the safe-integer range`);
  }
  return Number(v) + 0; // normalizes -0
}

export function gUint16(n: JNode | undefined, what: string): number {
  if (n === undefined || n.k === "null") return 0;
  if (n.k !== "num" || !/^(0|[1-9][0-9]*)$/.test(n.raw)) throw new Error(`wire: ${what} must be an unsigned integer`);
  const v = Number(n.raw);
  if (v > 0xffff) throw new Error(`wire: ${what} overflows uint16`);
  return v;
}

export function gFloat(n: JNode | undefined, what: string): number {
  if (n === undefined || n.k === "null") return 0;
  if (n.k !== "num") throw new Error(`wire: ${what} must be a number`);
  const v = Number(n.raw);
  if (!Number.isFinite(v)) throw new Error(`wire: ${what} is out of range`);
  return v;
}

/** []byte field: null/absent is nil (null); strings must be canonical base64. */
export function gBytes(n: JNode | undefined, what: string): Uint8Array | null {
  if (n === undefined || n.k === "null") return null;
  if (n.k !== "str") throw new Error(`wire: ${what} must be a base64 string`);
  const out = base64DecodeCanonical(n.v);
  if (out === null) throw new Error(`wire: ${what}: illegal or non-canonical base64 data`);
  return out;
}

/** []string field: null/absent is nil (null); a null element is "". */
export function gStringArray(n: JNode | undefined, what: string): string[] | null {
  if (n === undefined || n.k === "null") return null;
  if (n.k !== "arr") throw new Error(`wire: ${what} must be an array`);
  return n.a.map((x, i) => gString(x, `${what}[${i}]`));
}

export function gArray(n: JNode | undefined, what: string): JNode[] | null {
  if (n === undefined || n.k === "null") return null;
  if (n.k !== "arr") throw new Error(`wire: ${what} must be an array`);
  return n.a;
}

/** Generic Go `any` value: numbers decode to float64. */
export function gAny(n: JNode): unknown {
  switch (n.k) {
    case "null": return null;
    case "bool": return n.v;
    case "str": return n.v;
    case "num": {
      const v = Number(n.raw);
      if (!Number.isFinite(v)) throw new Error("wire: number out of range");
      return v;
    }
    case "arr": return n.a.map(gAny);
    case "obj": {
      const out: Record<string, unknown> = {};
      for (const [k, v] of n.m) {
        Object.defineProperty(out, k, { value: gAny(v), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
  }
}

export function rawSlice(bytes: Uint8Array, n: JNode): Uint8Array {
  return bytes.subarray(n.s, n.e);
}

// ---------------------------------------------------------------------------
// Canonical encoder (Go CanonicalJSON: encoding/json with SetEscapeHTML(false))

/** Encode the wrapped value with Go json.Marshal semantics (HTML escaping on). */
export class HTMLEscaped {
  constructor(readonly value: unknown) {}
}

/** Pre-encoded JSON bytes emitted verbatim (Go json.RawMessage). */
export class RawJSON {
  constructor(readonly bytes: Uint8Array) {}
}

/** A float64-typed value (Go formats it with strconv 'f'/'e' rules). */
export class Float64 {
  constructor(readonly value: number) {}
}

const HEX = "0123456789abcdef";

export function encodeGoString(s: string, escapeHTML: boolean): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) {
      if (c === 0x22) out += '\\"';
      else if (c === 0x5c) out += "\\\\";
      else if (c < 0x20) {
        if (c === 0x08) out += "\\b";
        else if (c === 0x0c) out += "\\f";
        else if (c === 0x0a) out += "\\n";
        else if (c === 0x0d) out += "\\r";
        else if (c === 0x09) out += "\\t";
        else out += "\\u00" + HEX[c >> 4] + HEX[c & 0xf];
      } else if (escapeHTML && (c === 0x3c || c === 0x3e || c === 0x26)) {
        out += "\\u00" + HEX[c >> 4] + HEX[c & 0xf];
      } else out += s[i];
      continue;
    }
    if (c === 0x2028 || c === 0x2029) {
      out += c === 0x2028 ? "\\u2028" : "\\u2029";
      continue;
    }
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s[i]! + s[i + 1]!;
        i++;
      } else out += "\\ufffd";
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
      out += "\\ufffd";
      continue;
    }
    out += s[i];
  }
  return out + '"';
}

function checkIntegerToken(token: string): void {
  if (/[.eE]/.test(token)) return;
  const v = BigInt(token);
  if (v > BigInt(MAX_SAFE_INTEGER_V2) || v < -BigInt(MAX_SAFE_INTEGER_V2)) {
    throw new Error(`canonical JSON: integer ${token} outside the safe-integer range [-(2^53-1), 2^53-1]`);
  }
}

/** Go encoding/json float64 formatting. */
export function formatGoFloat(n: number): string {
  if (!Number.isFinite(n)) throw new Error("json: unsupported value: non-finite float");
  if (Object.is(n, -0)) return "-0";
  // ECMAScript Number::toString uses the shortest round-trip digits and
  // switches to exponent form at the same thresholds as Go (<1e-6, >=1e21);
  // both write exponents without leading zeros.
  return n.toString();
}

function encodeInto(v: unknown, escapeHTML: boolean): string {
  if (v === null || v === undefined) return "null";
  if (v instanceof HTMLEscaped) return encodeInto(v.value, true);
  if (v instanceof RawJSON) return new TextDecoder().decode(v.bytes);
  if (v instanceof Float64) {
    const t = formatGoFloat(v.value);
    checkIntegerToken(t);
    return t;
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "bigint") {
    const t = v.toString(10);
    checkIntegerToken(t);
    return t;
  }
  if (typeof v === "number") {
    // Untyped numbers are float64 values (params) or integer fields.
    const t = formatGoFloat(v);
    checkIntegerToken(t);
    return t;
  }
  if (typeof v === "string") return encodeGoString(v, escapeHTML);
  if (v instanceof Uint8Array) return '"' + base64Encode(v) + '"';
  if (Array.isArray(v)) return "[" + v.map((x) => encodeInto(x, escapeHTML)).join(",") + "]";
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort(compareStrings);
    return "{" + keys.map((k) => encodeGoString(k, escapeHTML) + ":" + encodeInto(obj[k], escapeHTML)).join(",") + "}";
  }
  throw new Error(`canonical JSON: unsupported type ${typeof v}`);
}

/**
 * Go CanonicalJSON. Object keys are sorted by UTF-8 bytes (Go struct
 * declaration order is alphabetical for every v2 projection; Go map keys
 * are byte-sorted); undefined members are omitted (omitempty / absent).
 */
export function canonicalJSONV2(v: unknown): Uint8Array {
  return utf8(encodeInto(v, false));
}

/** Go json.Marshal (HTML escaping on). */
export function goMarshal(v: unknown): Uint8Array {
  return utf8(encodeInto(v, true));
}
