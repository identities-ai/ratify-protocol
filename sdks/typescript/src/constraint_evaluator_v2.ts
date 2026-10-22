// Protocol v2 extension constraint evaluator profiles (SPEC-v2 §5.2; Go
// constraint_evaluator_v2.go).
//
// A certificate may carry a constraint whose type is outside the closed v2
// registry. Without configuration it fails closed as constraint_unknown. A
// verifier may register, in caller-authenticated configuration, an evaluator
// profile for an exact extension type. The profile is identified by a digest
// over a canonical descriptor naming the type and a versioned profile
// identifier; the digest identifies the profile and proves nothing about an
// implementation. Neither the certificate nor the proof selects a profile.

import { sha384 } from "@noble/hashes/sha2";

import { V2_MAX_TIMESTAMP_SECONDS } from "./clock_bounds_v2.js";
import { ConstraintUnverifiableError, v2IntegerField, type ConstraintContextV2, type ConstraintV2 } from "./constraints_v2.js";
import { v2Classify, v2Errorf } from "./errors_v2.js";
import { MAX_SAFE_INTEGER_V2, canonicalJSONV2, compareStrings, concatBytes, hexOf, isValidUTF8, isWellFormedString, parseJSONV2, utf8, utf8Len, type JNode } from "./json_v2.js";
import type { ProofBundleV2 } from "./protocol_v2_wire.js";

export const CONSTRAINT_MAX_COUNT_V2 = "com.ratifyprotocol.max_count";
export const CONSTRAINT_ALLOWED_VALUES_V2 = "com.ratifyprotocol.allowed_values";
export const PROFILE_MAX_COUNT_V2 = "com.ratifyprotocol.max_count/v1";
export const PROFILE_ALLOWED_VALUES_V2 = "com.ratifyprotocol.allowed_values/v1";

export const MAX_CONSTRAINT_EVALUATORS_V2 = 32;
export const MAX_EXTENSION_TYPE_BYTES_V2 = 128;
export const MAX_PROFILE_ID_BYTES_V2 = 128;
export const MAX_EXTENSION_CONTEXT_ENTRIES_V2 = 64;
export const MAX_EXTENSION_CONTEXT_NAME_BYTES_V2 = 128;
export const MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 = 512;
export const MAX_ALLOWED_VALUES_V2 = 64;
/** Upper bound of the configured evaluation timeout, in milliseconds (10 s). */
export const MAX_CONSTRAINT_EVALUATOR_TIMEOUT_MS_V2 = 10_000;

const PROFILE_DIGEST_LABEL = "ratify-protocol-constraint-profile-v2";

/** The canonical object whose digest identifies an evaluator profile. */
export interface ConstraintProfileDescriptorV2 {
  profile: string;
  type: string;
}

/** One entry of a receipt's constraint_evaluators and of a sealed snapshot. */
export interface ConstraintEvaluatorRefV2 {
  profile_digest: string;
  type: string;
}

/** Everything an evaluator may read. A copy; evaluationTime is T_claim. */
export interface ConstraintEvaluationInputV2 {
  type: string;
  /** Canonical params object, or null when absent. */
  paramsJSON: Uint8Array | null;
  delegationIndex: number;
  constraintIndex: number;
  issuerID: string;
  certID: string;
  context: ConstraintContextV2;
  evaluationTime: number;
}

export type ConstraintOutcomeV2 = "pass" | "denied" | "unverifiable";

/** An evaluator's answer; validUntil is an optional exclusive pass horizon (0 = none). */
export interface ConstraintEvaluationResultV2 {
  outcome: ConstraintOutcomeV2;
  validUntil?: number;
  detail?: string;
}

/**
 * Evaluates one signed extension constraint. It must be a pure function of
 * its input: no I/O, clock, or randomness. A throw, rejection, timeout, or
 * invalid result is unverifiable. The signal aborts at the registry timeout.
 */
export type ConstraintEvaluatorFuncV2 = (
  input: ConstraintEvaluationInputV2,
  signal: AbortSignal,
) => ConstraintEvaluationResultV2 | Promise<ConstraintEvaluationResultV2>;

/** Binds one profile descriptor to its implementation. */
export interface ConstraintEvaluatorRegistrationV2 {
  descriptor: ConstraintProfileDescriptorV2;
  evaluate: ConstraintEvaluatorFuncV2;
}

/** A sealed registry entry. */
export interface RegisteredConstraintEvaluatorV2 {
  readonly ref: ConstraintEvaluatorRefV2;
  readonly evaluate: ConstraintEvaluatorFuncV2;
}

interface RegistryInternals {
  timeoutMs: number;
  entries: Map<string, RegisteredConstraintEvaluatorV2>;
}

const registries = new WeakMap<ConstraintEvaluatorRegistryV2, RegistryInternals>();

/**
 * Caller-authenticated verifier configuration, immutable once built. Only
 * newConstraintEvaluatorRegistryV2 builds a valid one.
 */
export class ConstraintEvaluatorRegistryV2 {
  private constructor() {}
  /** @internal */
  static create(internals: RegistryInternals): ConstraintEvaluatorRegistryV2 {
    const registry = new ConstraintEvaluatorRegistryV2();
    registries.set(registry, internals);
    Object.freeze(registry);
    return registry;
  }
  /** The registered {type, profile_digest} pairs sorted by type. */
  refs(): ConstraintEvaluatorRefV2[] {
    const internals = registries.get(this);
    if (!internals) return [];
    return [...internals.entries.values()].map((e) => ({ ...e.ref })).sort((a, b) => compareStrings(a.type, b.type));
  }
}

/**
 * Validates and freezes a registry (Go NewConstraintEvaluatorRegistryV2).
 * timeoutMs must be in (0, 10000]. Every type must be a registrable
 * extension type registered once. A violation is configuration_invalid.
 */
export function newConstraintEvaluatorRegistryV2(timeoutMs: number, ...registrations: ConstraintEvaluatorRegistrationV2[]): ConstraintEvaluatorRegistryV2 {
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_CONSTRAINT_EVALUATOR_TIMEOUT_MS_V2) {
    throw v2Errorf("configuration_invalid", `v2 constraint evaluator timeout must be in (0, ${MAX_CONSTRAINT_EVALUATOR_TIMEOUT_MS_V2}] ms`);
  }
  if (registrations.length > MAX_CONSTRAINT_EVALUATORS_V2) {
    throw v2Errorf("configuration_invalid", `v2 constraint evaluator registry holds at most ${MAX_CONSTRAINT_EVALUATORS_V2} profiles`);
  }
  const entries = new Map<string, RegisteredConstraintEvaluatorV2>();
  registrations.forEach((registration, i) => {
    if (!registration || typeof registration.evaluate !== "function") {
      throw v2Errorf("configuration_invalid", `v2 constraint evaluator ${i} has no implementation`);
    }
    let digest: string;
    try {
      digest = constraintProfileDigestV2(registration.descriptor);
    } catch (err) {
      throw v2Classify("configuration_invalid", err);
    }
    const type = registration.descriptor.type;
    if (entries.has(type)) throw v2Errorf("configuration_invalid", `v2 constraint type ${JSON.stringify(type)} is registered more than once`);
    entries.set(type, Object.freeze({ ref: Object.freeze({ type, profile_digest: digest }), evaluate: registration.evaluate }));
  });
  return ConstraintEvaluatorRegistryV2.create({ timeoutMs, entries });
}

/**
 * "sha384:" + lowercase hex SHA-384("ratify-protocol-constraint-profile-v2"
 * || 0x00 || RatifyCanonicalJSON({"profile":profile,"type":type})).
 */
export function constraintProfileDigestV2(d: ConstraintProfileDescriptorV2): string {
  if (!d || !validExtensionTypeV2(d.type)) throw new Error(`v2 constraint profile type ${JSON.stringify(d?.type)} is not a registrable extension type`);
  if (!validProfileIDV2(d.profile)) throw new Error(`v2 constraint profile identifier ${JSON.stringify(d.profile)} is invalid`);
  const body = canonicalJSONV2({ profile: d.profile, type: d.type });
  return "sha384:" + hexOf(sha384(concatBytes(utf8(PROFILE_DIGEST_LABEL), new Uint8Array([0]), body)));
}

const LABEL_RE = /^[a-z0-9_-]+$/;

/** 3 to 128 bytes of at least three "."-separated [a-z0-9_-] labels, not "ratify.". */
export function validExtensionTypeV2(t: unknown): t is string {
  if (typeof t !== "string" || t.length === 0 || t.length > MAX_EXTENSION_TYPE_BYTES_V2 || t.startsWith("ratify.")) return false;
  const labels = t.split(".");
  return labels.length >= 3 && labels.every((l) => LABEL_RE.test(l));
}

/** <name>/v<n>, at most 128 bytes; name is "."-separated labels, n positive without leading zeros. */
export function validProfileIDV2(id: unknown): id is string {
  if (typeof id !== "string" || id.length > MAX_PROFILE_ID_BYTES_V2) return false;
  const cut = id.indexOf("/v");
  if (cut < 0) return false;
  const name = id.slice(0, cut);
  const version = id.slice(cut + 2);
  if (name === "" || version === "" || version[0] === "0" || version.includes("/")) return false;
  if (!/^[0-9]+$/.test(version)) return false;
  return name.split(".").every((l) => LABEL_RE.test(l));
}

/** 1 to 128 bytes of [a-z0-9_.:-]. */
export function validExtensionContextNameV2(name: unknown): name is string {
  return typeof name === "string" && name.length > 0 && name.length <= MAX_EXTENSION_CONTEXT_NAME_BYTES_V2 && /^[a-z0-9_.:-]+$/.test(name);
}

/** Checks the extension request context before claim (configuration_invalid). */
export function validateV2ExtensionContext(c: ConstraintContextV2): void {
  const counts = c.extensionCounts ?? new Map<string, number>();
  const values = c.extensionValues ?? new Map<string, string>();
  if (counts.size > MAX_EXTENSION_CONTEXT_ENTRIES_V2 || values.size > MAX_EXTENSION_CONTEXT_ENTRIES_V2) {
    throw v2Errorf("configuration_invalid", `v2 extension request context holds at most ${MAX_EXTENSION_CONTEXT_ENTRIES_V2} counts and ${MAX_EXTENSION_CONTEXT_ENTRIES_V2} values`);
  }
  for (const [name, count] of counts) {
    if (!validExtensionContextNameV2(name) || typeof count !== "number" || !Number.isInteger(count) || count < 0 || count > MAX_SAFE_INTEGER_V2) {
      throw v2Errorf("configuration_invalid", `v2 extension count ${JSON.stringify(name)} must be named by 1 to ${MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-] and be 0..${MAX_SAFE_INTEGER_V2}`);
    }
  }
  for (const [name, value] of values) {
    if (!validExtensionContextNameV2(name) || typeof value !== "string" || !isWellFormedString(value) || utf8Len(value) > MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2) {
      throw v2Errorf("configuration_invalid", `v2 extension value ${JSON.stringify(name)} must be named by 1 to ${MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-] and be valid UTF-8 of at most ${MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2} bytes`);
    }
  }
}

/** A copy whose extension maps are independent of the caller's. */
export function cloneConstraintContextV2(c: ConstraintContextV2): ConstraintContextV2 {
  return {
    ...c,
    extensionCounts: c.extensionCounts ? new Map(c.extensionCounts) : c.extensionCounts,
    extensionValues: c.extensionValues ? new Map(c.extensionValues) : c.extensionValues,
  };
}

/** The sealed evaluator snapshot of one claim. */
export interface ConstraintEvaluatorSnapshotV2 {
  evaluators: ReadonlyMap<string, RegisteredConstraintEvaluatorV2>;
  refs: ConstraintEvaluatorRefV2[];
  timeoutMs: number;
}

/**
 * The registry entries for the extension types present in the chain, keyed
 * by type, with their refs sorted by type. Empty (no evaluators, no refs,
 * timeout 0) when no registry entry applies.
 */
export function snapshotConstraintEvaluatorsV2(registry: ConstraintEvaluatorRegistryV2 | null | undefined, bundle: ProofBundleV2 | null | undefined): ConstraintEvaluatorSnapshotV2 {
  const empty: ConstraintEvaluatorSnapshotV2 = { evaluators: new Map(), refs: [], timeoutMs: 0 };
  if (!registry || !bundle) return empty;
  const internals = registries.get(registry);
  if (!internals) return empty;
  const used = new Map<string, RegisteredConstraintEvaluatorV2>();
  for (const cert of bundle.delegations ?? []) {
    for (const constraint of cert.constraints ?? []) {
      const entry = internals.entries.get(constraint.type);
      if (entry) used.set(constraint.type, entry);
    }
  }
  if (used.size === 0) return empty;
  const refs = [...used.values()].map((e) => ({ ...e.ref })).sort((a, b) => compareStrings(a.type, b.type));
  return { evaluators: used, refs, timeoutMs: internals.timeoutMs };
}

function validPrefixedDigest(value: unknown): boolean {
  return typeof value === "string" && /^sha384:[0-9a-f]{96}$/.test(value);
}

/** Every entry has a registrable type and a sha384: digest, strictly sorted by type. */
export function validConstraintEvaluatorRefsV2(refs: readonly ConstraintEvaluatorRefV2[]): boolean {
  if (refs.length > MAX_CONSTRAINT_EVALUATORS_V2) return false;
  for (let i = 0; i < refs.length; i++) {
    const ref = refs[i]!;
    if (!validExtensionTypeV2(ref.type) || !validPrefixedDigest(ref.profile_digest)) return false;
    if (i > 0 && compareStrings(refs[i - 1]!.type, ref.type) >= 0) return false;
  }
  return true;
}

/** A copy of refs; empty when none (Go returns nil). */
export function cloneConstraintEvaluatorRefsV2(refs: readonly ConstraintEvaluatorRefV2[] | null | undefined): ConstraintEvaluatorRefV2[] {
  if (!refs || refs.length === 0) return [];
  return refs.map((r) => ({ profile_digest: r.profile_digest, type: r.type }));
}

/**
 * Invokes one sealed evaluator under its timeout and maps the answer: a
 * resolved horizon (0 = none) for a pass, a thrown Error for a denial, or a
 * thrown ConstraintUnverifiableError. Throws, rejections, timeouts, and
 * invalid outputs are unverifiable. A synchronous evaluator that never
 * returns cannot be interrupted in a single-threaded runtime; evaluators
 * must be pure and terminating.
 */
export async function runConstraintEvaluatorV2(entry: RegisteredConstraintEvaluatorV2, timeoutMs: number, input: ConstraintEvaluationInputV2): Promise<number> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  type Answer = { ok: true; result: ConstraintEvaluationResultV2 } | { ok: false; err: unknown } | { timeout: true };
  const timeout = new Promise<Answer>((resolve) => {
    timer = setTimeout(() => {
      controller.abort(new Error("evaluator timeout"));
      resolve({ timeout: true });
    }, timeoutMs);
  });
  const run = (async (): Promise<Answer> => {
    try {
      return { ok: true, result: await entry.evaluate(input, controller.signal) };
    } catch (err) {
      return { ok: false, err };
    }
  })();
  let got: Answer;
  try {
    got = await Promise.race([run, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  const type = input.type;
  if ("timeout" in got) throw new ConstraintUnverifiableError(`${type} evaluator did not answer within ${timeoutMs}ms`);
  if (!got.ok) throw new ConstraintUnverifiableError(`${type} evaluator failed: ${(got.err as Error)?.message ?? String(got.err)}`);
  const result = got.result;
  if (!result || typeof result !== "object") throw new ConstraintUnverifiableError(`${type} evaluator returned an invalid outcome`);
  const validUntil = result.validUntil ?? 0;
  if (typeof validUntil !== "number" || !Number.isSafeInteger(validUntil)) {
    throw new ConstraintUnverifiableError(`${type} evaluator returned an invalid horizon`);
  }
  switch (result.outcome) {
    case "pass":
      if (validUntil === 0) return 0;
      if (validUntil <= input.evaluationTime) throw new ConstraintUnverifiableError(`${type} evaluator returned a pass horizon not after the evaluation time`);
      return Math.min(validUntil, V2_MAX_TIMESTAMP_SECONDS);
    case "denied":
      if (validUntil !== 0) throw new ConstraintUnverifiableError(`${type} evaluator returned a horizon with a denial`);
      throw new Error(`${type} denied: ${result.detail ?? ""}`);
    case "unverifiable":
      if (validUntil !== 0) throw new ConstraintUnverifiableError(`${type} evaluator returned a horizon with an unverifiable result`);
      throw new ConstraintUnverifiableError(`${type} unverifiable: ${result.detail ?? ""}`);
    default:
      throw new ConstraintUnverifiableError(`${type} evaluator returned an invalid outcome`);
  }
}

// ---------------------------------------------------------------------------
// Standard profiles (SPEC-v2 §5.2).

/** com.ratifyprotocol.max_count/v1 for type com.ratifyprotocol.max_count. */
export function standardMaxCountEvaluatorV2(): ConstraintEvaluatorRegistrationV2 {
  return { descriptor: { profile: PROFILE_MAX_COUNT_V2, type: CONSTRAINT_MAX_COUNT_V2 }, evaluate: evaluateMaxCountV2 };
}

/** com.ratifyprotocol.allowed_values/v1 for type com.ratifyprotocol.allowed_values. */
export function standardAllowedValuesEvaluatorV2(): ConstraintEvaluatorRegistrationV2 {
  return { descriptor: { profile: PROFILE_ALLOWED_VALUES_V2, type: CONSTRAINT_ALLOWED_VALUES_V2 }, evaluate: evaluateAllowedValuesV2 };
}

function evaluateMaxCountV2(input: ConstraintEvaluationInputV2): ConstraintEvaluationResultV2 {
  let counter: string;
  let max: number;
  try {
    [counter, max] = decodeMaxCountParamsV2(input.paramsJSON);
  } catch (err) {
    return { outcome: "denied", detail: (err as Error).message };
  }
  const counts = input.context.extensionCounts;
  if (!counts || !counts.has(counter)) {
    return { outcome: "unverifiable", detail: `no authenticated count ${JSON.stringify(counter)} in the request context` };
  }
  const count = counts.get(counter)!;
  if (count > max) return { outcome: "denied", detail: `count ${JSON.stringify(counter)} is ${count}, above the signed maximum ${max}` };
  return { outcome: "pass" };
}

function evaluateAllowedValuesV2(input: ConstraintEvaluationInputV2): ConstraintEvaluationResultV2 {
  let field: string;
  let allowed: string[];
  try {
    [field, allowed] = decodeAllowedValuesParamsV2(input.paramsJSON);
  } catch (err) {
    return { outcome: "denied", detail: (err as Error).message };
  }
  const values = input.context.extensionValues;
  if (!values || !values.has(field)) {
    return { outcome: "unverifiable", detail: `no authenticated value ${JSON.stringify(field)} in the request context` };
  }
  if (!allowed.includes(values.get(field)!)) return { outcome: "denied", detail: `value of ${JSON.stringify(field)} is not an allowed value` };
  return { outcome: "pass" };
}

/** Strictly decodes a params object with exactly the named members. */
function decodeStandardParamsV2(data: Uint8Array | null, members: readonly string[]): Map<string, JNode> {
  if (data === null || data === undefined) throw new Error("params are required");
  if (!isValidUTF8(data)) throw new Error("params are not valid UTF-8");
  let root: JNode;
  try {
    root = parseJSONV2(data, { rejectDuplicates: true });
  } catch {
    throw new Error("params must be one JSON object without duplicate members");
  }
  if (root.k !== "obj") throw new Error("params must be one JSON object without duplicate members");
  if (root.m.size !== members.length || !members.every((m) => root.m.has(m))) {
    throw new Error(`params must have exactly the members ${members.join(" ")}`);
  }
  return root.m;
}

function decodeMaxCountParamsV2(data: Uint8Array | null): [string, number] {
  const fields = decodeStandardParamsV2(data, ["counter", "max"]);
  const counter = fields.get("counter")!;
  if (counter.k !== "str" || !validExtensionContextNameV2(counter.v)) {
    throw new Error(`counter must be 1 to ${MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-]`);
  }
  let max: number;
  try {
    max = v2IntegerField(fields.get("max"));
  } catch {
    throw new Error(`max must be an integer in 0..${MAX_SAFE_INTEGER_V2}`);
  }
  if (max < 0) throw new Error(`max must be an integer in 0..${MAX_SAFE_INTEGER_V2}`);
  return [counter.v, max];
}

function decodeAllowedValuesParamsV2(data: Uint8Array | null): [string, string[]] {
  const fields = decodeStandardParamsV2(data, ["allowed", "field"]);
  const field = fields.get("field")!;
  if (field.k !== "str" || !validExtensionContextNameV2(field.v)) {
    throw new Error(`field must be 1 to ${MAX_EXTENSION_CONTEXT_NAME_BYTES_V2} bytes of [a-z0-9_.:-]`);
  }
  const raw = fields.get("allowed")!;
  if (raw.k !== "arr") throw new Error("allowed must be an array of strings");
  if (raw.a.length === 0 || raw.a.length > MAX_ALLOWED_VALUES_V2) throw new Error(`allowed must hold 1 to ${MAX_ALLOWED_VALUES_V2} strings`);
  const allowed: string[] = [];
  for (const item of raw.a) {
    if (item.k !== "str" || item.v === "" || utf8Len(item.v) > MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2 || allowed.includes(item.v)) {
      throw new Error(`allowed values must be unique strings of 1 to ${MAX_EXTENSION_CONTEXT_VALUE_BYTES_V2} bytes`);
    }
    allowed.push(item.v);
  }
  return [field.v, allowed];
}

/** The canonical params object of an extension constraint, or null when it carries none. */
export function extensionParamsJSONV2(c: ConstraintV2): Uint8Array | null {
  if (c.params === undefined || c.params === null) return null;
  return canonicalJSONV2(c.params);
}

/** True only for a registry built by newConstraintEvaluatorRegistryV2. */
export function isConstraintEvaluatorRegistryV2(r: unknown): r is ConstraintEvaluatorRegistryV2 {
  return r instanceof ConstraintEvaluatorRegistryV2 && registries.has(r);
}
