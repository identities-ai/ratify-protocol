// Canonical JSON serialization per Ratify Protocol §6.3.1.
//
// Rules (must match Go reference and all other implementations byte-for-byte):
//   1. Object keys in lexicographic byte order.
//   2. No whitespace between tokens. No trailing newline.
//   3. UTF-8.
//   4. Integers as base-10 with no leading zeros, no trailing zeros, no exponent.
//   5. Uint8Array values encode as base64-standard strings with padding.
//      (Project convention on top of RFC 8785.)
//   6. `<`, `>`, `&` pass through unmodified — NO HTML escaping.
//   7. U+2028 and U+2029 escape to \u2028 and \u2029 — matches Go's
//      encoding/json behavior (the one deviation from strict RFC 8785).
//   8. Other control chars below U+0020 escape as \u00XX.
//   9. Standard RFC 8259 string escapes: \" \\ \b \f \n \r \t.

const HEX = "0123456789abcdef";

/** Canonical JSON-encode a value. Returns UTF-8 bytes. */
export function canonicalJSON(value: unknown): Uint8Array {
  const text = encodeValue(value);
  return new TextEncoder().encode(text);
}

function encodeValue(v: unknown): string {
  if (v === null || v === undefined) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return encodeNumber(v);
  if (typeof v === "bigint") return v.toString(10);
  if (typeof v === "string") return encodeString(v);
  if (v instanceof Uint8Array) return encodeString(base64StandardEncode(v));
  if (Array.isArray(v)) return encodeArray(v);
  if (typeof v === "object") return encodeObject(v as Record<string, unknown>);
  throw new Error(`canonical JSON: unsupported type ${typeof v}`);
}

function encodeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error("canonical JSON: non-finite number");
  }
  // Integers in safe range: exact decimal representation.
  if (Number.isInteger(n) && Math.abs(n) <= Number.MAX_SAFE_INTEGER) {
    return n.toString(10);
  }
  // Non-integer path: v1 signable fields don't use floats, but support defensively.
  // ECMAScript ToString is the closest portable spec; other implementers SHOULD
  // avoid floats in signable fields.
  return n.toString();
}

function encodeArray(arr: unknown[]): string {
  const parts = arr.map(encodeValue);
  return "[" + parts.join(",") + "]";
}

function encodeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue; // omit undefined — matches Go's omitempty for optional fields
    parts.push(encodeString(k) + ":" + encodeValue(v));
  }
  return "{" + parts.join(",") + "}";
}

function encodeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    // Handle surrogate pairs transparently: TextEncoder will produce correct UTF-8
    // from the JS string as long as we emit the right escapes for code points we
    // need to escape. We only escape control chars + U+2028 + U+2029 + " + \.
    if (c === 0x22) { out += '\\"'; continue; }
    if (c === 0x5c) { out += "\\\\"; continue; }
    if (c === 0x08) { out += "\\b"; continue; }
    if (c === 0x09) { out += "\\t"; continue; }
    if (c === 0x0a) { out += "\\n"; continue; }
    if (c === 0x0c) { out += "\\f"; continue; }
    if (c === 0x0d) { out += "\\r"; continue; }
    if (c < 0x20) {
      // Other control chars: \u00XX
      out += "\\u00" + HEX[(c >> 4) & 0xf] + HEX[c & 0xf];
      continue;
    }
    // U+2028 / U+2029 — Go escapes these regardless; we must too.
    if (c === 0x2028) { out += "\\u2028"; continue; }
    if (c === 0x2029) { out += "\\u2029"; continue; }
    // Everything else passes through. Note: '<', '>', '&' are NOT escaped.
    out += s[i];
  }
  out += '"';
  return out;
}

/** Standard base64 encoding with padding. */
export function base64StandardEncode(bytes: Uint8Array): string {
  // Use Node's Buffer where available for speed; otherwise manual.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  const table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1]!;
    const c = bytes[i + 2]!;
    out += table[a >> 2]!;
    out += table[((a & 3) << 4) | (b >> 4)]!;
    out += table[((b & 0xf) << 2) | (c >> 6)]!;
    out += table[c & 0x3f]!;
  }
  if (i < bytes.length) {
    const a = bytes[i]!;
    out += table[a >> 2]!;
    if (i + 1 < bytes.length) {
      const b = bytes[i + 1]!;
      out += table[((a & 3) << 4) | (b >> 4)]!;
      out += table[(b & 0xf) << 2]!;
      out += "=";
    } else {
      out += table[(a & 3) << 4]!;
      out += "==";
    }
  }
  return out;
}

/** Decode standard base64 (with or without padding) into bytes. */
export function base64StandardDecode(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  // Fallback implementation.
  const table: Record<string, number> = {};
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    .split("")
    .forEach((c, i) => (table[c] = i));
  const clean = s.replace(/=+$/, "");
  const bytes: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const c of clean) {
    const v = table[c];
    if (v === undefined) throw new Error(`invalid base64 char: ${c}`);
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

/** Hex encoding (lowercase) — for IDs, keys, signatures in test vectors. */
export function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += HEX[(b >> 4) & 0xf]! + HEX[b & 0xf]!;
  }
  return out;
}

/** Hex decode — lower- or upper-case accepted. */
export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error("hex: odd length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = parseInt(s[i * 2]!, 16);
    const lo = parseInt(s[i * 2 + 1]!, 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) throw new Error("hex: bad char");
    out[i] = (hi << 4) | lo;
  }
  return out;
}
