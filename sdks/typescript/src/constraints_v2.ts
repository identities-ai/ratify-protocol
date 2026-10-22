// Protocol v2 closed constraint registry (SPEC-v2 §5.2; Go constraints_v2.go).
//
// v2 defines its own constraint schemas and no v2 constraint member carries a
// floating-point number. Registered types and their exact wire members:
//
//   time_window              {"end","start","tz","type"}
//   max_amount               {"currency","max_amount_micros","type"}
//   max_rate                 {"count","type","window_s"}
//   resource_path            {"path_prefix"?,"resource_id","type"}
//   ratify.receiver_audience {"params","type"}
//
// Every other type (including the reserved geo_circle, geo_polygon, geo_bbox
// and max_speed_mps) is unregistered: it may carry only "type" and an
// optional "params" object, decodes, and evaluates as constraint_unknown.

import { V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS, V2_MAX_RATE_WINDOW_SECONDS } from "./clock_bounds_v2.js";
import { MAX_SAFE_INTEGER_V2, canonicalJSONV2, checkV2Nulls, gAny, parseJSONV2, utf8Len, type JNode } from "./json_v2.js";
import { normalizeResourcePath, resourcePathMatches, validateParamsValue } from "./resource_path.js";
import { loadV2TimeZone, type V2TimeZone } from "./tzdb_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES } from "./types.js";
import { classified } from "./errors_v2.js";

export const CONSTRAINT_TIME_WINDOW_V2 = "time_window";
export const CONSTRAINT_MAX_AMOUNT_V2 = "max_amount";
export const CONSTRAINT_MAX_RATE_V2 = "max_rate";
export const CONSTRAINT_RESOURCE_PATH_V2 = "resource_path";
export const CONSTRAINT_RECEIVER_AUDIENCE_V2 = "ratify.receiver_audience";

/** Bounds each receiver-audience ID array. */
export const MAX_AUDIENCE_IDS_V2 = 64;

/**
 * One entry of a v2 certificate's constraints array. Only the members of
 * the registered schema for `type` are encoded; absent members are the Go
 * zero values ("" and 0).
 */
export interface ConstraintV2 {
  type: string;
  // time_window
  start?: string;
  end?: string;
  tz?: string;
  // max_amount
  currency?: string;
  max_amount_micros?: number;
  // max_rate
  count?: number;
  window_s?: number;
  // resource_path
  resource_id?: string;
  path_prefix?: string;
  // ratify.receiver_audience and unregistered types
  params?: Record<string, unknown> | null;
}

/**
 * Verifier-authenticated action inputs for registered constraints. Amounts
 * use the same 10^-6 major-unit scale as max_amount_micros. Callers apply
 * every decoding and normalization step before building the context.
 */
export interface ConstraintContextV2 {
  requestedAmountMicros?: number;
  requestedCurrency?: string;
  hasAmount?: boolean;
  requestedResourceID?: string;
  requestedPath?: string;
  hasResource?: boolean;
  /** Named authenticated quantities for extension evaluator profiles. */
  extensionCounts?: ReadonlyMap<string, number> | null;
  /** Named authenticated exact values for extension evaluator profiles. */
  extensionValues?: ReadonlyMap<string, string> | null;
}

/** Thrown when a constraint cannot be evaluated from authenticated input. */
export class ConstraintUnverifiableError extends Error {
  constructor(reason: string) {
    super(`constraint_unverifiable: ${reason}`);
    this.name = "ConstraintUnverifiableError";
  }
}

/** Thrown for an unregistered constraint type (constraint_unknown). */
export class UnknownConstraintError extends Error {
  constructor(readonly kind: string) {
    super(`constraint_unknown: unknown constraint type "${kind}"`);
    this.name = "UnknownConstraintError";
  }
}

export function isRegisteredStructuredConstraintV2(t: string): boolean {
  return t === CONSTRAINT_TIME_WINDOW_V2 || t === CONSTRAINT_MAX_AMOUNT_V2 || t === CONSTRAINT_MAX_RATE_V2 || t === CONSTRAINT_RESOURCE_PATH_V2;
}

/** True when t is in the closed v2 registry. */
export function isRegisteredConstraintTypeV2(t: string): boolean {
  return isRegisteredStructuredConstraintV2(t) || t === CONSTRAINT_RECEIVER_AUDIENCE_V2;
}

const str = (v: string | undefined): string => (typeof v === "string" ? v : "");
const num = (v: number | undefined): number => (typeof v === "number" ? v : 0);

/**
 * The wire object of one constraint (Go ConstraintV2.MarshalJSON before its
 * validation step): exactly the registered members for its type.
 */
export function constraintWireObjectV2(c: ConstraintV2): Record<string, unknown> {
  const m: Record<string, unknown> = { type: str(c.type) };
  switch (c.type) {
    case CONSTRAINT_TIME_WINDOW_V2:
      m.start = str(c.start); m.end = str(c.end); m.tz = str(c.tz);
      break;
    case CONSTRAINT_MAX_AMOUNT_V2:
      m.currency = str(c.currency); m.max_amount_micros = num(c.max_amount_micros);
      break;
    case CONSTRAINT_MAX_RATE_V2:
      m.count = num(c.count); m.window_s = num(c.window_s);
      break;
    case CONSTRAINT_RESOURCE_PATH_V2:
      m.resource_id = str(c.resource_id);
      if (str(c.path_prefix) !== "") m.path_prefix = c.path_prefix;
      break;
    default:
      if (c.params !== undefined && c.params !== null) m.params = c.params;
  }
  if (c.params !== undefined && c.params !== null && isRegisteredStructuredConstraintV2(c.type)) {
    throw new Error(`v2 constraint type ${JSON.stringify(c.type)} must not carry params`);
  }
  return m;
}

/**
 * Go ConstraintV2.MarshalJSON: the canonical encoding of one constraint,
 * validated against the closed registry.
 */
export function encodeConstraintV2(c: ConstraintV2): Uint8Array {
  return classified("malformed", () => {
    const out = canonicalJSONV2(constraintWireObjectV2(c));
    validateV2ConstraintFields(parseJSONV2(out));
    return out;
  });
}

/** Go ConstraintV2.UnmarshalJSON: strict decode of one constraint node. */
export function decodeConstraintNodeV2(n: JNode): ConstraintV2 {
  validateV2ConstraintFields(n);
  const fields = (n as Extract<JNode, { k: "obj" }>).m;
  const type = (fields.get("type") as Extract<JNode, { k: "str" }>).v;
  const out: ConstraintV2 = { type };
  const s = (name: string): string => {
    const node = fields.get(name);
    return node !== undefined && node.k === "str" ? node.v : "";
  };
  const i = (name: string): number => {
    const node = fields.get(name);
    return node !== undefined && node.k === "num" ? Number(node.raw) + 0 : 0;
  };
  switch (type) {
    case CONSTRAINT_TIME_WINDOW_V2:
      out.start = s("start"); out.end = s("end"); out.tz = s("tz");
      break;
    case CONSTRAINT_MAX_AMOUNT_V2:
      out.currency = s("currency"); out.max_amount_micros = i("max_amount_micros");
      break;
    case CONSTRAINT_MAX_RATE_V2:
      out.count = i("count"); out.window_s = i("window_s");
      break;
    case CONSTRAINT_RESOURCE_PATH_V2:
      out.resource_id = s("resource_id");
      if (fields.has("path_prefix")) out.path_prefix = s("path_prefix");
      break;
    default: {
      const params = fields.get("params");
      if (params !== undefined) {
        out.params = params.k === "null" ? null : (gAny(params) as Record<string, unknown>);
      }
    }
  }
  return out;
}

/** Deep copy of a constraint (params are restricted-value-model JSON). */
export function cloneConstraintV2(c: ConstraintV2): ConstraintV2 {
  const out: ConstraintV2 = { ...c };
  if (c.params !== undefined && c.params !== null) out.params = structuredClone(c.params);
  return out;
}

/** Go validateV2ConstraintFields over one parsed constraint object. */
export function validateV2ConstraintFields(n: JNode): void {
  checkV2Nulls(n);
  if (n.k !== "obj") throw new Error("constraint must be an object");
  const fields = n.m;
  const typeNode = fields.get("type");
  if (typeNode === undefined || typeNode.k !== "str" || typeNode.v === "") {
    throw new Error("constraint type must be a non-empty string");
  }
  const kind = typeNode.v;
  const exact = (required: readonly string[], optional: readonly string[] = []): void => {
    for (const key of fields.keys()) {
      if (key !== "type" && !required.includes(key) && !optional.includes(key)) {
        throw new Error(`field ${JSON.stringify(key)} is not allowed for constraint type ${JSON.stringify(kind)}`);
      }
    }
    for (const name of required) {
      if (!fields.has(name)) throw new Error(`constraint type ${JSON.stringify(kind)} requires field ${JSON.stringify(name)}`);
    }
  };
  switch (kind) {
    case CONSTRAINT_TIME_WINDOW_V2: {
      exact(["start", "end", "tz"]);
      for (const name of ["start", "end"]) {
        const value = v2StringField(fields.get(name), `time_window ${name} must be a string`);
        parseHHMMV2(value);
      }
      const tz = fields.get("tz");
      if (tz === undefined || tz.k !== "str" || !validTimeZoneIDV2(tz.v)) {
        throw new Error("time_window tz must be 1 to 64 bytes of /-separated [A-Za-z0-9_+-] segments");
      }
      return;
    }
    case CONSTRAINT_MAX_AMOUNT_V2: {
      exact(["currency", "max_amount_micros"]);
      const currency = fields.get("currency");
      if (currency === undefined || currency.k !== "str" || !validISO4217AlphaV2(currency.v)) {
        throw new Error("max_amount currency must be an ISO-4217 alphabetic code");
      }
      const amount = v2IntegerFieldOrNull(fields.get("max_amount_micros"));
      if (amount === null || amount < 0) throw new Error("max_amount_micros must be a nonnegative safe integer");
      return;
    }
    case CONSTRAINT_MAX_RATE_V2: {
      exact(["count", "window_s"]);
      const count = v2IntegerFieldOrNull(fields.get("count"));
      if (count === null || count <= 0) throw new Error("max_rate count must be a positive safe integer");
      const window = v2IntegerFieldOrNull(fields.get("window_s"));
      if (window === null || window <= 0 || window > V2_MAX_RATE_WINDOW_SECONDS) {
        throw new Error(`max_rate window_s must be an integer in 1..${V2_MAX_RATE_WINDOW_SECONDS}`);
      }
      return;
    }
    case CONSTRAINT_RESOURCE_PATH_V2: {
      exact(["resource_id"], ["path_prefix"]);
      const id = fields.get("resource_id");
      if (id === undefined || id.k !== "str" || id.v === "" || utf8Len(id.v) > MAX_IDENTIFIER_LENGTH_BYTES) {
        throw new Error("resource_path resource_id must be a non-empty string within MAX_IDENTIFIER_LENGTH_BYTES");
      }
      const prefix = fields.get("path_prefix");
      if (prefix !== undefined && (prefix.k !== "str" || prefix.v === "")) {
        throw new Error("resource_path path_prefix must be a non-empty string when present");
      }
      return;
    }
    case CONSTRAINT_RECEIVER_AUDIENCE_V2:
      exact(["params"]);
      validateV2ReceiverAudience(fields.get("params")!);
      return;
    default: {
      if (utf8Len(kind) > MAX_IDENTIFIER_LENGTH_BYTES) {
        throw new Error("unregistered constraint type exceeds MAX_IDENTIFIER_LENGTH_BYTES");
      }
      exact([], ["params"]);
      const params = fields.get("params");
      if (params !== undefined) {
        if (params.k !== "obj") throw new Error("unregistered constraint params must be an object");
        validateParamsValue(gAny(params), 0);
      }
    }
  }
}

function strictStringArray(n: JNode | undefined): string[] | null {
  // Go json.Unmarshal into []string: an absent member fails, null yields nil
  // (rejected by the caller), and every element must be a string (a null
  // element unmarshals to "" and is then rejected as empty).
  if (n === undefined || n.k !== "arr") return null;
  const out: string[] = [];
  for (const item of n.a) {
    if (item.k === "str") out.push(item.v);
    else if (item.k === "null") out.push("");
    else return null;
  }
  return out;
}

function validateV2ReceiverAudience(raw: JNode): void {
  if (raw.k !== "obj") throw new Error("receiver audience requires params object");
  const params = raw.m;
  for (const key of params.keys()) {
    if (key !== "exact_receiver_ids" && key !== "trust_domain_ids" && key !== "max_membership_age_seconds") {
      throw new Error(`unknown receiver audience parameter ${JSON.stringify(key)}`);
    }
  }
  const exact = strictStringArray(params.get("exact_receiver_ids"));
  const domains = strictStringArray(params.get("trust_domain_ids"));
  if (exact === null || domains === null) {
    throw new Error("receiver audience requires exact_receiver_ids and trust_domain_ids arrays");
  }
  if (exact.length + domains.length === 0) throw new Error("receiver audience must name an exact receiver or trust domain");
  for (const values of [exact, domains]) {
    if (values.length > MAX_AUDIENCE_IDS_V2) throw new Error(`receiver audience arrays hold at most ${MAX_AUDIENCE_IDS_V2} IDs`);
    const seen = new Set<string>();
    for (const value of values) {
      if (value === "" || utf8Len(value) > MAX_IDENTIFIER_LENGTH_BYTES || seen.has(value)) {
        throw new Error(`receiver audience IDs must be unique and 1 to ${MAX_IDENTIFIER_LENGTH_BYTES} bytes`);
      }
      seen.add(value);
    }
  }
  const age = params.get("max_membership_age_seconds");
  if (domains.length > 0 && (age === undefined || age.k === "null")) {
    throw new Error("receiver audience trust domains require max_membership_age_seconds");
  }
  if (age !== undefined) {
    const seconds = v2IntegerFieldOrNull(age);
    if (seconds === null || seconds <= 0 || seconds > V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS) {
      throw new Error(`max_membership_age_seconds must be an integer in 1..${V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS}`);
    }
  }
  if (domains.length === 0 && age !== undefined) {
    throw new Error("receiver audience without trust domains must omit max_membership_age_seconds");
  }
}

/**
 * Go v2IntegerField: a JSON integer token in the safe-integer range. A
 * fraction or exponent spelling is rejected even when its value is integral.
 */
export function v2IntegerField(n: JNode | undefined): number {
  if (n === undefined || n.k !== "num") throw new Error("integer is required");
  const token = n.raw;
  const digits = token.startsWith("-") ? token.slice(1) : token;
  if (digits === "" || (digits.length > 1 && digits[0] === "0")) throw new Error(`integer ${JSON.stringify(token)} is not canonical`);
  if (!/^[0-9]+$/.test(digits)) throw new Error(`integer ${JSON.stringify(token)} is not a JSON integer`);
  if (token === "-0") throw new Error("negative zero is not a canonical integer");
  const v = BigInt(token);
  if (v > BigInt(MAX_SAFE_INTEGER_V2) || v < -BigInt(MAX_SAFE_INTEGER_V2)) {
    throw new Error(`integer ${JSON.stringify(token)} is outside the safe-integer range`);
  }
  return Number(v);
}

function v2IntegerFieldOrNull(n: JNode | undefined): number | null {
  try {
    return v2IntegerField(n);
  } catch {
    return null;
  }
}

function v2StringField(n: JNode | undefined, message: string): string {
  if (n === undefined || n.k !== "str") throw new Error(message);
  return n.v;
}

export function validISO4217AlphaV2(code: unknown): code is string {
  return typeof code === "string" && /^[A-Z]{3}$/.test(code);
}

/**
 * The SPEC-v2 §5.2 tz shape: 1 to 64 ASCII bytes of "/"-separated segments
 * of [A-Za-z0-9_+-], with no empty, "." or ".." segment.
 */
export function validTimeZoneIDV2(tz: string): boolean {
  if (tz.length === 0 || tz.length > 64) return false;
  for (const segment of tz.split("/")) {
    if (segment === "" || segment === "." || segment === "..") return false;
    if (!/^[A-Za-z0-9_+-]+$/.test(segment)) return false;
  }
  return true;
}

/** Exactly two-digit hours 00..23 and minutes 00..59; returns minute of day. */
export function parseHHMMV2(s: string): number {
  if (s.length !== 5 || s[2] !== ":" || !/^[0-9]{2}:[0-9]{2}$/.test(s)) throw new Error(`expected HH:MM, got ${JSON.stringify(s)}`);
  const h = Number(s.slice(0, 2));
  const m = Number(s.slice(3, 5));
  if (h > 23 || m > 59) throw new Error(`out-of-range HH:MM ${JSON.stringify(s)}`);
  return h * 60 + m;
}

/** Local wall-clock minute of day at unixSeconds in zone. */
export function localMinuteOfDayV2(zone: V2TimeZone, unixSeconds: number): number {
  const local = unixSeconds + zone.lookup(unixSeconds).offset;
  const secondOfDay = ((local % 86400) + 86400) % 86400;
  return Math.floor(secondOfDay / 60);
}

/**
 * Evaluates one locally decidable registered constraint (Go
 * evaluateConstraintV2). Returns normally on pass; throws
 * ConstraintUnverifiableError when authenticated input is unavailable,
 * UnknownConstraintError for an unregistered type, and any other error for
 * a denial. max_rate and ratify.receiver_audience never reach this
 * function.
 */
export function evaluateConstraintV2(c: ConstraintV2, ctx: ConstraintContextV2, tzdbVersion: string, now: number): void {
  switch (c.type) {
    case CONSTRAINT_RESOURCE_PATH_V2: {
      // SPEC-v2 §5.2 order: the signed path_prefix is checked before any
      // request input, because its validity does not depend on the request.
      const prefix = str(c.path_prefix);
      if (prefix !== "") {
        try {
          normalizeResourcePath(prefix);
        } catch (err) {
          throw new Error(`malformed path_prefix: ${(err as Error).message}`);
        }
      }
      const requestedID = str(ctx.requestedResourceID);
      if (!ctx.hasResource || requestedID === "") throw new ConstraintUnverifiableError("no requested resource in context");
      if (requestedID !== c.resource_id) throw new Error("requested resource does not match the authorized resource");
      if (prefix === "") return;
      const requestedPath = str(ctx.requestedPath);
      if (requestedPath === "") throw new ConstraintUnverifiableError("no requested path in context");
      try {
        normalizeResourcePath(requestedPath);
      } catch (err) {
        throw new Error(`invalid requested path: ${(err as Error).message}`);
      }
      if (!resourcePathMatches(prefix, requestedPath)) {
        throw new Error(`requested path "${requestedPath}" is outside the authorized prefix "${prefix}"`);
      }
      return;
    }
    case CONSTRAINT_TIME_WINDOW_V2: {
      let zone: V2TimeZone;
      try {
        zone = loadV2TimeZone(tzdbVersion, str(c.tz));
      } catch (err) {
        throw new ConstraintUnverifiableError(`time zone "${str(c.tz)}" cannot be evaluated: ${(err as Error).message}`);
      }
      const start = parseHHMMV2(str(c.start));
      const end = parseHHMMV2(str(c.end));
      const cur = localMinuteOfDayV2(zone, now);
      if ((start <= end && (cur < start || cur > end)) || (start > end && cur < start && cur > end)) {
        throw new Error(`current local minute ${cur} is outside [${c.start}, ${c.end}] ${c.tz}`);
      }
      return;
    }
    case CONSTRAINT_MAX_AMOUNT_V2: {
      if (!ctx.hasAmount) throw new ConstraintUnverifiableError("no requested amount in context");
      const amount = ctx.requestedAmountMicros;
      if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount < 0 || !validISO4217AlphaV2(ctx.requestedCurrency)) {
        throw new ConstraintUnverifiableError("requested amount is not a nonnegative safe integer in ISO-4217 micro-units");
      }
      if (ctx.requestedCurrency !== c.currency) {
        throw new Error(`currency mismatch: requested "${ctx.requestedCurrency}", constraint "${c.currency}"`);
      }
      if (amount > num(c.max_amount_micros)) {
        throw new Error(`amount ${amount} exceeds max ${num(c.max_amount_micros)} micro-units of ${c.currency}`);
      }
      return;
    }
    case CONSTRAINT_MAX_RATE_V2:
    case CONSTRAINT_RECEIVER_AUDIENCE_V2:
      throw new ConstraintUnverifiableError(`${c.type} requires its dedicated post-status stage`);
    default:
      throw new UnknownConstraintError(c.type);
  }
}
