// Canonical tool arguments of the Verify MCP signer (Preview).
//
// A strict JSON reader over UTF-8 bytes for the restricted value model:
// objects with unique keys, strings, integers in the safe range, booleans,
// and arrays, nested at most MAX_ARGUMENT_DEPTH deep. JSON.parse is not
// used: it cannot tell 1 from 1.0, keeps the last of duplicate keys, and
// accepts unpaired surrogate escapes.

import { compareBytes, isWellFormedString } from "../json_v2.js";
import { InvalidArgumentsError } from "./errors.js";

/**
 * The deepest nesting a value may have: the arguments object is depth 0 and
 * each enclosing object or array adds one. Preview.
 */
export const MAX_ARGUMENT_DEPTH = 4;

type ArgValue = ArgObject | ArgValue[] | Uint8Array | number | boolean;

interface ArgObject {
  kind: "object";
  entries: { key: Uint8Array; value: ArgValue }[];
}

/** One character per byte (ISO-8859-1), so equal strings mean equal bytes. */
function byteString(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("latin1");
}

function refuse(): never {
  throw new InvalidArgumentsError();
}

function isSpace(c: number | undefined): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0d || c === 0x0a;
}

function allowedCodePoint(r: number): boolean {
  return !(r < 0x20 || (r >= 0x7f && r <= 0x9f) || r === 0x2028 || r === 0x2029 || (r >= 0xd800 && r <= 0xdfff));
}

function appendCodePoint(out: number[], r: number): void {
  if (r < 0x80) {
    out.push(r);
  } else if (r < 0x800) {
    out.push(0xc0 | (r >> 6), 0x80 | (r & 0x3f));
  } else if (r < 0x10000) {
    out.push(0xe0 | (r >> 12), 0x80 | ((r >> 6) & 0x3f), 0x80 | (r & 0x3f));
  } else {
    out.push(0xf0 | (r >> 18), 0x80 | ((r >> 12) & 0x3f), 0x80 | ((r >> 6) & 0x3f), 0x80 | (r & 0x3f));
  }
}

/**
 * Decodes one well-formed UTF-8 sequence at pos (Unicode Table 3-7: no
 * overlong forms, no encoded surrogates, nothing above U+10FFFF). Returns
 * the code point and its length, or null.
 */
function decodeUTF8(b: Uint8Array, pos: number): [number, number] | null {
  const c0 = b[pos]!;
  if (c0 < 0x80) return [c0, 1];
  const cont = (i: number, lo = 0x80, hi = 0xbf): number | null => {
    const c = b[pos + i];
    return c !== undefined && c >= lo && c <= hi ? c & 0x3f : null;
  };
  if (c0 >= 0xc2 && c0 <= 0xdf) {
    const c1 = cont(1);
    return c1 === null ? null : [((c0 & 0x1f) << 6) | c1, 2];
  }
  if (c0 >= 0xe0 && c0 <= 0xef) {
    const lo = c0 === 0xe0 ? 0xa0 : 0x80;
    const hi = c0 === 0xed ? 0x9f : 0xbf;
    const c1 = cont(1, lo, hi);
    const c2 = c1 === null ? null : cont(2);
    return c1 === null || c2 === null ? null : [((c0 & 0x0f) << 12) | (c1 << 6) | c2, 3];
  }
  if (c0 >= 0xf0 && c0 <= 0xf4) {
    const lo = c0 === 0xf0 ? 0x90 : 0x80;
    const hi = c0 === 0xf4 ? 0x8f : 0xbf;
    const c1 = cont(1, lo, hi);
    const c2 = c1 === null ? null : cont(2);
    const c3 = c2 === null ? null : cont(3);
    return c1 === null || c2 === null || c3 === null ? null : [((c0 & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3, 4];
  }
  return null;
}

class ArgParser {
  pos = 0;
  constructor(readonly input: Uint8Array) {}

  space(): void {
    while (this.pos < this.input.length && isSpace(this.input[this.pos])) this.pos++;
  }

  literal(word: string): boolean {
    for (let i = 0; i < word.length; i++) {
      if (this.input[this.pos + i] !== word.charCodeAt(i)) return false;
    }
    this.pos += word.length;
    return true;
  }

  value(depth: number): ArgValue {
    if (depth > MAX_ARGUMENT_DEPTH) refuse();
    this.space();
    if (this.pos >= this.input.length) refuse();
    const c = this.input[this.pos]!;
    if (c === 0x7b /* { */) return this.object(depth);
    if (c === 0x5b /* [ */) return this.array(depth);
    if (c === 0x22 /* " */) return this.str();
    if (c === 0x74 /* t */ && this.literal("true")) return true;
    if (c === 0x66 /* f */ && this.literal("false")) return false;
    if (c === 0x2d /* - */ || (c >= 0x30 && c <= 0x39)) return this.number();
    return refuse();
  }

  object(depth: number): ArgObject {
    this.pos++;
    const obj: ArgObject = { kind: "object", entries: [] };
    const seen = new Set<string>();
    this.space();
    if (this.input[this.pos] === 0x7d /* } */) {
      this.pos++;
      return obj;
    }
    for (;;) {
      this.space();
      const key = this.str();
      // Keys are compared after unescaping.
      const seenKey = byteString(key);
      if (seen.has(seenKey)) refuse();
      seen.add(seenKey);
      this.space();
      if (this.input[this.pos] !== 0x3a /* : */) refuse();
      this.pos++;
      obj.entries.push({ key, value: this.value(depth + 1) });
      this.space();
      const next = this.input[this.pos];
      if (next === 0x2c /* , */) {
        this.pos++;
        continue;
      }
      if (next === 0x7d /* } */) {
        this.pos++;
        return obj;
      }
      refuse();
    }
  }

  array(depth: number): ArgValue[] {
    this.pos++;
    const list: ArgValue[] = [];
    this.space();
    if (this.input[this.pos] === 0x5d /* ] */) {
      this.pos++;
      return list;
    }
    for (;;) {
      list.push(this.value(depth + 1));
      this.space();
      const next = this.input[this.pos];
      if (next === 0x2c /* , */) {
        this.pos++;
        continue;
      }
      if (next === 0x5d /* ] */) {
        this.pos++;
        return list;
      }
      refuse();
    }
  }

  /** Only the JSON integer grammar: -?(0|[1-9][0-9]*), in the safe range. */
  number(): number {
    const start = this.pos;
    const isDigit = (c: number | undefined): boolean => c !== undefined && c >= 0x30 && c <= 0x39;
    if (this.input[this.pos] === 0x2d) this.pos++;
    const first = this.input[this.pos];
    if (first === 0x30) {
      this.pos++;
    } else if (first !== undefined && first >= 0x31 && first <= 0x39) {
      while (isDigit(this.input[this.pos])) this.pos++;
    } else {
      refuse();
    }
    const after = this.input[this.pos];
    if (after === 0x2e /* . */ || after === 0x65 /* e */ || after === 0x45 /* E */) refuse();
    const text = byteString(this.input.subarray(start, this.pos));
    if (text === "-0" || text.length > 17) refuse();
    const n = Number(text);
    if (!Number.isSafeInteger(n)) refuse();
    return n;
  }

  hex4(): number | null {
    if (this.pos + 4 > this.input.length) return null;
    let r = 0;
    for (let i = 0; i < 4; i++) {
      const c = this.input[this.pos + i]!;
      r <<= 4;
      if (c >= 0x30 && c <= 0x39) r |= c - 0x30;
      else if (c >= 0x61 && c <= 0x66) r |= c - 0x61 + 10;
      else if (c >= 0x41 && c <= 0x46) r |= c - 0x41 + 10;
      else return null;
    }
    this.pos += 4;
    return r;
  }

  /** A JSON string, returned as its unescaped UTF-8 bytes. */
  str(): Uint8Array {
    if (this.input[this.pos] !== 0x22) refuse();
    this.pos++;
    const out: number[] = [];
    for (;;) {
      if (this.pos >= this.input.length) refuse();
      const c = this.input[this.pos]!;
      if (c === 0x22) {
        this.pos++;
        return Uint8Array.from(out);
      }
      if (c === 0x5c /* \ */) {
        this.pos++;
        if (this.pos >= this.input.length) refuse();
        const e = this.input[this.pos]!;
        this.pos++;
        if (e === 0x22 || e === 0x5c || e === 0x2f) {
          out.push(e);
        } else if (e === 0x75 /* u */) {
          let r = this.hex4();
          if (r === null) refuse();
          if (r >= 0xd800 && r <= 0xdfff) {
            if (r >= 0xdc00 || !this.literal("\\u")) refuse();
            const low = this.hex4();
            if (low === null || low < 0xdc00 || low > 0xdfff) refuse();
            r = 0x10000 + ((r - 0xd800) << 10) + (low - 0xdc00);
          }
          if (!allowedCodePoint(r)) refuse();
          appendCodePoint(out, r);
        } else {
          // \b \f \n \r \t decode to control characters, which the model
          // refuses; any other escape is not JSON.
          refuse();
        }
        continue;
      }
      const decoded = decodeUTF8(this.input, this.pos);
      if (decoded === null || !allowedCodePoint(decoded[0])) refuse();
      for (let i = 0; i < decoded[1]; i++) out.push(this.input[this.pos + i]!);
      this.pos += decoded[1];
    }
  }
}

function writeString(out: number[], s: Uint8Array): void {
  out.push(0x22);
  for (const b of s) {
    if (b === 0x22 || b === 0x5c) out.push(0x5c);
    out.push(b);
  }
  out.push(0x22);
}

function writeValue(out: number[], v: ArgValue): void {
  if (v instanceof Uint8Array) {
    writeString(out, v);
  } else if (Array.isArray(v)) {
    out.push(0x5b);
    v.forEach((item, i) => {
      if (i > 0) out.push(0x2c);
      writeValue(out, item);
    });
    out.push(0x5d);
  } else if (typeof v === "object") {
    const entries = [...v.entries].sort((a, b) => compareBytes(a.key, b.key));
    out.push(0x7b);
    entries.forEach((entry, i) => {
      if (i > 0) out.push(0x2c);
      writeString(out, entry.key);
      out.push(0x3a);
      writeValue(out, entry.value);
    });
    out.push(0x7d);
  } else {
    for (const ch of String(v)) out.push(ch.charCodeAt(0));
  }
}

/**
 * Preview. Parses the JSON text of params.arguments under the restricted
 * value model and returns its canonical bytes. Strings and keys must be
 * valid UTF-8 without control characters (U+0000 to U+001F, U+007F to
 * U+009F), U+2028, U+2029, or unpaired surrogate escapes. Empty input, JSON
 * whitespace, and the literal null mean the empty object.
 *
 * Canonical form: object keys sorted by their UTF-8 bytes, no insignificant
 * whitespace, strings with only '"' and '\' escaped, integers in decimal.
 *
 * A string argument is encoded as UTF-8 first and must not hold an unpaired
 * surrogate. Throws InvalidArgumentsError.
 */
export function canonicalArguments(raw: Uint8Array | string): Uint8Array {
  let input: Uint8Array;
  if (typeof raw === "string") {
    if (!isWellFormedString(raw)) refuse();
    input = new TextEncoder().encode(raw);
  } else if (raw instanceof Uint8Array) {
    input = raw;
  } else {
    return refuse();
  }
  let start = 0;
  let end = input.length;
  while (start < end && isSpace(input[start])) start++;
  while (end > start && isSpace(input[end - 1])) end--;
  if (start === end || (end - start === 4 && byteString(input.subarray(start, end)) === "null")) {
    return new Uint8Array([0x7b, 0x7d]);
  }
  const p = new ArgParser(input);
  p.space();
  if (input[p.pos] !== 0x7b) refuse();
  const v = p.value(0);
  p.space();
  if (p.pos !== input.length) refuse();
  const out: number[] = [];
  writeValue(out, v);
  return Uint8Array.from(out);
}
