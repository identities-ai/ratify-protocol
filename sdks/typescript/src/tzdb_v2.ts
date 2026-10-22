// Pinned IANA time-zone database for Protocol v2 time_window evaluation
// (SPEC-v2 §5.2; Go internal/tzdbv2 and time.LoadLocationFromTZData).
//
// Zones load only from the embedded tzdata 2025c archive (tzdata_2025c.ts),
// never from the host's Intl data or zone files, so every verifier built from
// this package evaluates the same rules. The archive's SHA-256 is checked
// before first use. Lookup reproduces Go's time.Location semantics exactly,
// including the POSIX TZ footer rule used past the last transition and the
// period bounds Go reports for it, because the allow horizon depends on them.

import { sha256 } from "@noble/hashes/sha2";

import { TZDATA_2025C_ZIP_BASE64, TZDATA_2025C_ZIP_SHA256 } from "./tzdata_2025c.js";

/** The IANA tzdata release this SDK embeds and evaluates against. */
export const TZDB_VERSION_V2 = "2025c";

/** UTC offset in effect at an instant and the exclusive end of that period. */
export interface V2ZoneLookup {
  /** Seconds east of UTC. */
  offset: number;
  /** First UTC second of the next offset period, or null when none follows. */
  end: number | null;
}

/** One zone loaded from the pinned database. */
export interface V2TimeZone {
  readonly name: string;
  lookup(unixSeconds: number): V2ZoneLookup;
}

// Go's alpha/omega sentinels for unbounded period starts and ends.
const ALPHA = Number.NEGATIVE_INFINITY;
const OMEGA = Number.POSITIVE_INFINITY;
const SECONDS_PER_DAY = 86400;
const SECONDS_PER_HOUR = 3600;

interface Zone {
  offset: number;
  isDST: boolean;
}

interface Transition {
  when: number;
  index: number;
}

let archiveIndex: Map<string, Uint8Array> | null = null;
let archiveError: Error | null = null;
const cache = new Map<string, V2TimeZone>();

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function u16(b: Uint8Array, at: number): number {
  return b[at]! | (b[at + 1]! << 8);
}
function u32(b: Uint8Array, at: number): number {
  return (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0;
}

/** Indexes the stored (uncompressed) entries of the embedded zip archive. */
function loadArchive(): Map<string, Uint8Array> {
  if (archiveIndex) return archiveIndex;
  if (archiveError) throw archiveError;
  try {
    const zip = new Uint8Array(Buffer.from(TZDATA_2025C_ZIP_BASE64, "base64"));
    if (hex(sha256(zip)) !== TZDATA_2025C_ZIP_SHA256) throw new Error("embedded tzdata archive digest mismatch");
    let eocd = -1;
    for (let i = zip.length - 22; i >= Math.max(0, zip.length - 22 - 65535); i--) {
      if (u32(zip, i) === 0x06054b50) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) throw new Error("embedded tzdata archive has no end of central directory");
    const count = u16(zip, eocd + 10);
    let at = u32(zip, eocd + 16);
    const index = new Map<string, Uint8Array>();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    for (let n = 0; n < count; n++) {
      if (u32(zip, at) !== 0x02014b50) throw new Error("embedded tzdata archive central directory is corrupt");
      const method = u16(zip, at + 10);
      const compressed = u32(zip, at + 20);
      const size = u32(zip, at + 24);
      const nameLen = u16(zip, at + 28);
      const extraLen = u16(zip, at + 30);
      const commentLen = u16(zip, at + 32);
      const local = u32(zip, at + 42);
      const name = decoder.decode(zip.subarray(at + 46, at + 46 + nameLen));
      at += 46 + nameLen + extraLen + commentLen;
      if (name.endsWith("/")) continue;
      if (method !== 0 || compressed !== size) throw new Error(`embedded tzdata entry ${name} is not stored`);
      if (u32(zip, local) !== 0x04034b50) throw new Error("embedded tzdata archive local header is corrupt");
      const start = local + 30 + u16(zip, local + 26) + u16(zip, local + 28);
      index.set(name, zip.subarray(start, start + size));
    }
    archiveIndex = index;
    return index;
  } catch (err) {
    archiveError = new Error(`embedded tzdata archive is unreadable: ${(err as Error).message}`);
    throw archiveError;
  }
}

/** Parses TZif data like Go's LoadLocationFromTZData (64-bit data for v2+). */
function parseTZif(name: string, data: Uint8Array): { zones: Zone[]; tx: Transition[]; extend: string } {
  let p = 0;
  const fail = (): never => {
    throw new Error(`time zone "${name}" in IANA tzdata ${TZDB_VERSION_V2} is unreadable`);
  };
  const take = (n: number): Uint8Array => {
    if (p + n > data.length) fail();
    const out = data.subarray(p, p + n);
    p += n;
    return out;
  };
  const be32 = (b: Uint8Array, at: number): number => ((b[at]! << 24) | (b[at + 1]! << 16) | (b[at + 2]! << 8) | b[at + 3]!) >>> 0;
  const header = () => {
    const magic = take(4);
    if (magic[0] !== 0x54 || magic[1] !== 0x5a || magic[2] !== 0x69 || magic[3] !== 0x66) fail();
    const version = take(16)[0]!;
    const counts = take(24);
    const n = [0, 1, 2, 3, 4, 5].map((i) => be32(counts, i * 4));
    // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    return { version, isutc: n[0]!, isstd: n[1]!, leap: n[2]!, time: n[3]!, type: n[4]!, char: n[5]! };
  };
  let h = header();
  let timeSize = 4;
  if (h.version !== 0) {
    // Skip the version 1 data block and use the 64-bit block.
    take(h.time * 4 + h.time + h.type * 6 + h.char + h.leap * 8 + h.isstd + h.isutc);
    h = header();
    timeSize = 8;
  }
  if (h.type === 0) fail();
  const txTimes = take(h.time * timeSize);
  const txZones = take(h.time);
  const zoneData = take(h.type * 6);
  take(h.char);
  take(h.leap * (timeSize + 4));
  take(h.isstd);
  take(h.isutc);
  const zones: Zone[] = [];
  for (let i = 0; i < h.type; i++) {
    const b = zoneData.subarray(i * 6, i * 6 + 6);
    const offset = (b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!; // int32
    zones.push({ offset, isDST: b[4] !== 0 });
  }
  const tx: Transition[] = [];
  for (let i = 0; i < h.time; i++) {
    let when: number;
    if (timeSize === 8) {
      const hi = (txTimes[i * 8]! << 24) | (txTimes[i * 8 + 1]! << 16) | (txTimes[i * 8 + 2]! << 8) | txTimes[i * 8 + 3]!;
      when = hi * 4294967296 + be32(txTimes, i * 8 + 4);
    } else {
      when = (txTimes[i * 4]! << 24) | (txTimes[i * 4 + 1]! << 16) | (txTimes[i * 4 + 2]! << 8) | txTimes[i * 4 + 3]!;
    }
    const index = txZones[i]!;
    if (index >= zones.length) fail();
    tx.push({ when, index });
  }
  if (tx.length === 0) tx.push({ when: ALPHA, index: 0 });
  let extend = "";
  const rest = data.subarray(p);
  if (timeSize === 8 && rest.length > 2 && rest[0] === 0x0a && rest[rest.length - 1] === 0x0a) {
    extend = new TextDecoder().decode(rest.subarray(1, rest.length - 1));
  }
  return { zones, tx, extend };
}

class LoadedZone implements V2TimeZone {
  constructor(readonly name: string, private readonly zones: Zone[], private readonly tx: Transition[], private readonly extend: string) {}

  private lookupFirstZone(): number {
    if (!this.tx.some((t) => t.index === 0)) return 0;
    if (this.tx.length > 0 && this.zones[this.tx[0]!.index]!.isDST) {
      for (let zi = this.tx[0]!.index - 1; zi >= 0; zi--) if (!this.zones[zi]!.isDST) return zi;
    }
    for (let zi = 0; zi < this.zones.length; zi++) if (!this.zones[zi]!.isDST) return zi;
    return 0;
  }

  lookup(sec: number): V2ZoneLookup {
    const tx = this.tx;
    if (tx.length === 0 || sec < tx[0]!.when) {
      const zone = this.zones[this.lookupFirstZone()]!;
      return { offset: zone.offset, end: tx.length > 0 ? tx[0]!.when : null };
    }
    let end = OMEGA;
    let lo = 0;
    let hi = tx.length;
    while (hi - lo > 1) {
      const m = (lo + hi) >>> 1;
      const lim = tx[m]!.when;
      if (sec < lim) {
        end = lim;
        hi = m;
      } else lo = m;
    }
    const zone = this.zones[tx[lo]!.index]!;
    if (lo === tx.length - 1 && this.extend !== "") {
      const r = tzset(this.extend, tx[lo]!.when, sec);
      if (r) return { offset: r.offset, end: Number.isFinite(r.end) ? r.end : null };
    }
    return { offset: zone.offset, end: Number.isFinite(end) ? end : null };
  }
}

/**
 * Loads a zone from the embedded database after checking the configured
 * database version (Go loadV2TimeZone). "Local" and any name that is not a
 * zone file in the archive are errors; the host zone database is never used.
 */
export function loadV2TimeZone(configuredVersion: string, tz: string): V2TimeZone {
  if (configuredVersion === "") throw new Error("no tzdb_version is configured");
  if (configuredVersion !== TZDB_VERSION_V2) {
    throw new Error(`configured tzdb_version "${configuredVersion}" differs from the loaded IANA tzdata ${TZDB_VERSION_V2}`);
  }
  return loadTZDBZoneV2(tz);
}

/** Loads a zone from the embedded database (Go tzdbv2.Load). */
export function loadTZDBZoneV2(name: string): V2TimeZone {
  const cached = cache.get(name);
  if (cached) return cached;
  const index = loadArchive();
  const data = index.get(name);
  if (data === undefined || name === "" || name === "Local") {
    throw new Error(`time zone "${name}" is not in IANA tzdata ${TZDB_VERSION_V2}`);
  }
  const { zones, tx, extend } = parseTZif(name, data);
  const zone = new LoadedZone(name, zones, tx, extend);
  cache.set(name, zone);
  return zone;
}

/** Lowercase hex SHA-256 of the embedded archive. */
export const TZDB_ZIP_SHA256_V2 = TZDATA_2025C_ZIP_SHA256;

// ---------------------------------------------------------------------------
// POSIX TZ footer rules (Go time/zoneinfo.go tzset and helpers).

type Rule = { kind: "julian" | "doy" | "mwd"; day: number; week: number; mon: number; time: number };

function tzsetName(s: string): [string, string] | null {
  if (s.length === 0) return null;
  if (s[0] !== "<") {
    for (let i = 0; i < s.length; i++) {
      const c = s[i]!;
      if ((c >= "0" && c <= "9") || c === "," || c === "-" || c === "+") {
        if (i < 3) return null;
        return [s.slice(0, i), s.slice(i)];
      }
    }
    if (s.length < 3) return null;
    return [s, ""];
  }
  const close = s.indexOf(">");
  if (close < 0) return null;
  return [s.slice(1, close), s.slice(close + 1)];
}

function tzsetNum(s: string, min: number, max: number): [number, string] | null {
  if (s.length === 0) return null;
  let num = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) {
      if (i === 0 || num < min) return null;
      return [num, s.slice(i)];
    }
    num = num * 10 + (c - 0x30);
    if (num > max) return null;
  }
  if (num < min) return null;
  return [num, ""];
}

function tzsetOffset(s: string): [number, string] | null {
  if (s.length === 0) return null;
  let neg = false;
  if (s[0] === "+") s = s.slice(1);
  else if (s[0] === "-") {
    s = s.slice(1);
    neg = true;
  }
  const h = tzsetNum(s, 0, 24 * 7);
  if (!h) return null;
  let off = h[0] * SECONDS_PER_HOUR;
  s = h[1];
  if (s.length === 0 || s[0] !== ":") return [neg ? 0 - off : off, s];
  const m = tzsetNum(s.slice(1), 0, 59);
  if (!m) return null;
  off += m[0] * 60;
  s = m[1];
  if (s.length === 0 || s[0] !== ":") return [neg ? 0 - off : off, s];
  const sec = tzsetNum(s.slice(1), 0, 59);
  if (!sec) return null;
  off += sec[0];
  return [neg ? 0 - off : off, sec[1]];
}

function tzsetRule(s: string): [Rule, string] | null {
  if (s.length === 0) return null;
  const r: Rule = { kind: "doy", day: 0, week: 0, mon: 0, time: 0 };
  if (s[0] === "J") {
    const j = tzsetNum(s.slice(1), 1, 365);
    if (!j) return null;
    r.kind = "julian";
    r.day = j[0];
    s = j[1];
  } else if (s[0] === "M") {
    const mon = tzsetNum(s.slice(1), 1, 12);
    if (!mon || mon[1].length === 0 || mon[1][0] !== ".") return null;
    const week = tzsetNum(mon[1].slice(1), 1, 5);
    if (!week || week[1].length === 0 || week[1][0] !== ".") return null;
    const day = tzsetNum(week[1].slice(1), 0, 6);
    if (!day) return null;
    r.kind = "mwd";
    r.day = day[0];
    r.week = week[0];
    r.mon = mon[0];
    s = day[1];
  } else {
    const d = tzsetNum(s, 0, 365);
    if (!d) return null;
    r.kind = "doy";
    r.day = d[0];
    s = d[1];
  }
  if (s.length === 0 || s[0] !== "/") {
    r.time = 2 * SECONDS_PER_HOUR;
    return [r, s];
  }
  const off = tzsetOffset(s.slice(1));
  if (!off) return null;
  r.time = off[0];
  return [r, off[1]];
}

function isLeap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

const DAYS_BEFORE = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365];

function daysIn(month: number, year: number): number {
  if (month === 2 && isLeap(year)) return 29;
  return DAYS_BEFORE[month]! - DAYS_BEFORE[month - 1]!;
}

/** Go integer division truncating toward zero. */
const quo = (a: number, b: number): number => Math.trunc(a / b);
/** Go remainder with the sign of the dividend. */
const rem = (a: number, b: number): number => a - quo(a, b) * b;

function tzruleTime(year: number, r: Rule, off: number): number {
  let s: number;
  switch (r.kind) {
    case "julian":
      s = (r.day - 1) * SECONDS_PER_DAY;
      if (isLeap(year) && r.day >= 60) s += SECONDS_PER_DAY;
      break;
    case "doy":
      s = r.day * SECONDS_PER_DAY;
      break;
    case "mwd": {
      const m1 = rem(r.mon + 9, 12) + 1;
      let yy0 = year;
      if (r.mon <= 2) yy0--;
      const yy1 = quo(yy0, 100);
      const yy2 = rem(yy0, 100);
      let dow = rem(quo(26 * m1 - 2, 10) + 1 + yy2 + quo(yy2, 4) + quo(yy1, 4) - 2 * yy1, 7);
      if (dow < 0) dow += 7;
      let d = r.day - dow;
      if (d < 0) d += 7;
      for (let i = 1; i < r.week; i++) {
        if (d + 7 >= daysIn(r.mon, year)) break;
        d += 7;
      }
      d += DAYS_BEFORE[r.mon - 1]!;
      if (isLeap(year) && r.mon > 2) d++;
      s = d * SECONDS_PER_DAY;
      break;
    }
  }
  return s + r.time - off;
}

/** Proleptic Gregorian year and 1-based day of year of a UTC instant. */
function yearYday(sec: number): [number, number] {
  const days = Math.floor(sec / SECONDS_PER_DAY);
  // Civil-from-days (H. Hinnant), exact for the whole safe-integer range used here.
  const z = days + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  let year = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const month = mp < 10 ? mp + 3 : mp - 9;
  const day = doy - Math.floor((153 * mp + 2) / 5) + 1;
  if (month <= 2) year += 1;
  let yday = DAYS_BEFORE[month - 1]! + day;
  if (month > 2 && isLeap(year)) yday++;
  return [year, yday];
}

/** Go tzset: the offset and period of sec under a POSIX TZ rule string. */
function tzset(s: string, lastTxSec: number, sec: number): { offset: number; start: number; end: number } | null {
  const std = tzsetName(s);
  if (!std) return null;
  const stdOff = tzsetOffset(std[1]);
  if (!stdOff) return null;
  let stdOffset = 0 - stdOff[0];
  s = stdOff[1];
  if (s.length === 0 || s[0] === ",") return { offset: stdOffset, start: lastTxSec, end: OMEGA };
  const dst = tzsetName(s);
  if (!dst) return null;
  s = dst[1];
  let dstOffset: number;
  if (s.length === 0 || s[0] === ",") {
    dstOffset = stdOffset + SECONDS_PER_HOUR;
  } else {
    const o = tzsetOffset(s);
    if (!o) return null;
    dstOffset = 0 - o[0];
    s = o[1];
  }
  if (s.length === 0) s = ",M3.2.0,M11.1.0";
  if (s[0] !== "," && s[0] !== ";") return null;
  const start = tzsetRule(s.slice(1));
  if (!start || start[1].length === 0 || start[1][0] !== ",") return null;
  const end = tzsetRule(start[1].slice(1));
  if (!end || end[1].length > 0) return null;
  const [year, yday] = yearYday(sec);
  const ysec = (yday - 1) * SECONDS_PER_DAY + rem(sec, SECONDS_PER_DAY);
  const ystart = sec - ysec;
  let startSec = tzruleTime(year, start[0], stdOffset);
  let endSec = tzruleTime(year, end[0], dstOffset);
  if (endSec < startSec) {
    [startSec, endSec] = [endSec, startSec];
    [stdOffset, dstOffset] = [dstOffset, stdOffset];
  }
  if (ysec < startSec) return { offset: stdOffset, start: ystart, end: startSec + ystart };
  if (ysec >= endSec) return { offset: stdOffset, start: endSec + ystart, end: ystart + 365 * SECONDS_PER_DAY };
  return { offset: dstOffset, start: startSec + ystart, end: endSec + ystart };
}
