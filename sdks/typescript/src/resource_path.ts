// Resource-bound authority — the resource_path constraint's path model,
// segment-boundary matching, and the extension-constraint params value model
// (SPEC §5.7.1, §5.7.3). Mirrors the Go reference resource_path.go exactly.
//
// Paths are absolute logical POSIX-style paths: they name a location inside
// the resource's own namespace, not filesystem paths on any machine. The
// verifier compares bytes exactly — no Unicode normalization, no percent
// decoding, no case folding. Issuers and adapters pre-normalize (NFC) and
// pre-decode BEFORE constructing constraints and verifier context; nothing
// transforms a path after verification.

import {
  MAX_IDENTIFIER_LENGTH_BYTES,
  MAX_JSON_NESTING_DEPTH,
  type Constraint,
  type ConstraintType,
} from "./types.js";

// 2^53 - 1: the largest integer JavaScript (and JSON's number domain)
// represents exactly. params integers beyond this travel as decimal strings.
const MAX_SAFE_INTEGER_VALUE = Number.MAX_SAFE_INTEGER;

const _utf8 = new TextEncoder();

/** UTF-8 byte length of a string — Go's len() over a string. */
export function utf8ByteLength(s: string): number {
  return _utf8.encode(s).length;
}

/**
 * Validate p against the logical path model (SPEC §5.7.3) and return its
 * comparison form: at most one trailing "/" trimmed, except for the root
 * path "/" itself. Throws when p is not a valid logical path:
 *
 *   - must begin with "/" ("/" is the only separator)
 *   - no NUL byte, no backslash (rejected, never translated)
 *   - no "." or ".." segment (rejected outright, never resolved)
 *   - no empty interior segment ("/a//b" is invalid; "/" is valid)
 *
 * "%" is an ordinary literal byte: the path model has no percent-encoding.
 */
export function normalizeResourcePath(p: string): string {
  if (p === "") throw new Error("path is empty");
  if (!p.startsWith("/")) throw new Error("path must begin with '/'");
  if (p.indexOf("\u0000") >= 0) throw new Error("path contains a NUL byte");
  if (p.indexOf("\\") >= 0) {
    throw new Error("path contains a backslash; '/' is the only separator");
  }
  if (p === "/") return "/";
  // Trim at most one trailing slash before segment validation: "/docs/" ≡
  // "/docs", while "/docs//" leaves an empty interior segment and is invalid.
  const trimmed = p.endsWith("/") ? p.slice(0, -1) : p;
  const segments = trimmed.slice(1).split("/");
  for (const seg of segments) {
    if (seg === "") throw new Error("path contains an empty segment");
    if (seg === "." || seg === "..") {
      throw new Error(
        "path contains a dot-segment; dot-segments are rejected, never resolved",
      );
    }
  }
  return trimmed;
}

/**
 * Reports whether requestedPath is at or below pathPrefix under
 * segment-boundary prefix matching (SPEC §5.7.3). NOT glob matching and NOT
 * plain string-prefix matching: "/src" matches "/src" and "/src/a.ts", never
 * "/src-old/a.ts" or "/srcx". Either input being invalid yields false.
 */
export function resourcePathMatches(
  pathPrefix: string,
  requestedPath: string,
): boolean {
  let prefix: string;
  let path: string;
  try {
    prefix = normalizeResourcePath(pathPrefix);
  } catch {
    return false;
  }
  try {
    path = normalizeResourcePath(requestedPath);
  } catch {
    return false;
  }
  if (prefix === "/") return true; // root prefix matches every valid path
  if (path === prefix) return true;
  return path.startsWith(prefix + "/");
}

// Reports whether two valid prefixes are comparable under the prefix relation
// (one at or below the other). An absent prefix ("") orders as "/".
function resourcePathsNested(a: string, b: string): boolean {
  const aa = a === "" ? "/" : a;
  const bb = b === "" ? "/" : b;
  return resourcePathMatches(aa, bb) || resourcePathMatches(bb, aa);
}

/**
 * Enforce the issuance rule of SPEC §5.7.3: a certificate's resource_path
 * constraints must be jointly satisfiable. Rejects constraint sets naming
 * different resource_ids, and same-resource sets whose prefixes do not form a
 * nested chain. Individual constraints are also validated (non-empty
 * resource_id within MAX_IDENTIFIER_LENGTH_BYTES; well-formed path_prefix).
 * Throws on violation.
 *
 * Decoders do NOT call this — wire compatibility is not conditioned on
 * issuance hygiene; verification denies unsatisfiable sets fail-closed.
 */
export function validateResourceConstraints(constraints: Constraint[]): void {
  let resourceID = "";
  const prefixes: string[] = [];
  for (let i = 0; i < constraints.length; i++) {
    const c = constraints[i]!;
    if (c.type !== "resource_path") continue;
    const rid = c.resource_id ?? "";
    if (rid === "") {
      throw new Error(`constraint[${i}]: resource_path requires a non-empty resource_id`);
    }
    const ridLen = utf8ByteLength(rid);
    if (ridLen > MAX_IDENTIFIER_LENGTH_BYTES) {
      throw new Error(
        `constraint[${i}]: resource_id is ${ridLen} bytes, exceeding MAX_IDENTIFIER_LENGTH_BYTES (${MAX_IDENTIFIER_LENGTH_BYTES})`,
      );
    }
    const pp = c.path_prefix ?? "";
    if (pp !== "") {
      try {
        normalizeResourcePath(pp);
      } catch (e) {
        throw new Error(`constraint[${i}]: invalid path_prefix: ${(e as Error).message}`);
      }
    }
    if (resourceID === "") {
      resourceID = rid;
    } else if (rid !== resourceID) {
      throw new Error(
        `constraint[${i}]: certificate carries resource_path constraints naming different resource_ids — jointly unsatisfiable (SPEC §5.7.3); issue separate certificates`,
      );
    }
    for (const prev of prefixes) {
      if (!resourcePathsNested(prev, pp)) {
        throw new Error(
          `constraint[${i}]: same-resource path_prefix values "${prev}" and "${pp}" do not nest — jointly unsatisfiable (SPEC §5.7.3); narrow to one prefix or issue separate certificates`,
        );
      }
    }
    prefixes.push(pp);
  }
}

/**
 * Enforce the extension-constraint params value model (SPEC §5.7.1): null,
 * booleans, strings, safe integers (|n| ≤ 2^53−1), and arrays/objects of
 * these. Floats and non-integer numbers are prohibited; integers beyond the
 * safe range travel as decimal strings. `depth` is the container nesting
 * already consumed; nesting beyond MAX_JSON_NESTING_DEPTH is rejected. Throws
 * on violation.
 */
export function validateParamsValue(v: unknown, depth: number): void {
  if (depth > MAX_JSON_NESTING_DEPTH) {
    throw new Error(`params nesting exceeds MAX_JSON_NESTING_DEPTH (${MAX_JSON_NESTING_DEPTH})`);
  }
  if (v === null || typeof v === "boolean" || typeof v === "string") return;
  if (typeof v === "number") {
    if (!Number.isFinite(v) || !Number.isInteger(v)) {
      throw new Error("params values must be safe integers, not floats (carry non-integers as strings)");
    }
    if (Math.abs(v) > MAX_SAFE_INTEGER_VALUE) {
      throw new Error("params integer exceeds the safe-integer range; carry it as a decimal string");
    }
    return;
  }
  if (typeof v === "bigint") {
    if (v > BigInt(MAX_SAFE_INTEGER_VALUE) || v < -BigInt(MAX_SAFE_INTEGER_VALUE)) {
      throw new Error("params integer exceeds the safe-integer range; carry it as a decimal string");
    }
    return;
  }
  // Raw bytes are outside the value model (carried as base64 strings if at all).
  if (v instanceof Uint8Array) {
    throw new Error("params value of type Uint8Array is outside the restricted value model");
  }
  if (Array.isArray(v)) {
    for (const item of v) validateParamsValue(item, depth + 1);
    return;
  }
  if (typeof v === "object") {
    for (const item of Object.values(v as Record<string, unknown>)) {
      validateParamsValue(item, depth + 1);
    }
    return;
  }
  throw new Error(`params value of type ${typeof v} is outside the restricted value model`);
}

// The canonical v1 constraint kinds (SPEC §5.7.2). params is permitted only
// on constraint types NOT in this set.
const CANONICAL_CONSTRAINT_TYPES: ReadonlySet<string> = new Set([
  "geo_circle",
  "geo_polygon",
  "geo_bbox",
  "time_window",
  "max_speed_mps",
  "max_amount",
  "max_rate",
  "resource_path",
]);

/** Reports whether t is one of the canonical v1 constraint kinds. */
export function isCanonicalConstraintType(t: ConstraintType | string): boolean {
  return CANONICAL_CONSTRAINT_TYPES.has(t);
}
