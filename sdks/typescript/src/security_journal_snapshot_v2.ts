// SecurityJournalV2 logical snapshot (SPEC-v2 §6.6; Go
// security_journal_snapshot_v2.go): the canonical projection, its labelled
// digest, export/import, and migration of the version 1 alpha record.
//
//   SecurityJournalDigest = SHA-384("ratify-protocol-security-journal-v2" || 0x00 || snapshot)
//
// A valid digest chain is not rollback protection: the head must be anchored
// independently and advanced by atomic compare-and-swap (§7.10).

import { sha384 } from "@noble/hashes/sha2";

import { v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import {
  RawJSON,
  base64DecodeCanonical,
  base64Encode,
  canonicalJSONV2,
  compareBytes,
  compareStrings,
  concatBytes,
  encodeGoString,
  hexOf,
  isValidUTF8,
  parseJSONV2,
  utf8,
  type JNode,
} from "./json_v2.js";
import { decodeRevocationListV2, encodeRevocationListV2, type RevocationListV2 } from "./protocol_v2_wire.js";
import {
  SECURITY_JOURNAL_VERSION_V2,
  cloneSecurityJournalV2,
  sortKeyRoleHistoryV2,
  sortStatusKeyHistoryV2,
  validateSecurityJournalTransitionV2,
  validateSecurityJournalV2,
  type KeyRoleBindingV2,
  type SecurityJournalHeadV2,
  type SecurityJournalV2,
  type StatusKeyBindingV2,
} from "./security_journal_v2.js";
import {
  canonicalizeRevocationStatusStateV2,
  emptyRevocationStatusStateV2,
  sortedUniqueStringsV2,
  type RevocationObservationV2,
  type RevocationStatusStateV2,
} from "./status_state_v2.js";

/** Version 1: the alpha record with the unlabelled json.Marshal digest. */
export const SECURITY_JOURNAL_LEGACY_VERSION_V2 = 1;
/** Bounds an imported snapshot. */
export const MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES = 64 << 20;
const DIGEST_LABEL = utf8("ratify-protocol-security-journal-v2\0");
const GENESIS_PREVIOUS_DIGEST = "0".repeat(96);

/** The §6.6 compaction sort key. */
export function compareCompactionOrderV2(a: RevocationObservationV2, b: RevocationObservationV2): number {
  if (a.statusKeyEpoch !== b.statusKeyEpoch) return a.statusKeyEpoch < b.statusKeyEpoch ? -1 : 1;
  if (a.sequence !== b.sequence) return a.sequence < b.sequence ? -1 : 1;
  if (a.objectType !== b.objectType) return a.objectType < b.objectType ? -1 : 1;
  const c = compareBytes(a.revokedSetDigest, b.revokedSetDigest);
  if (c !== 0) return c;
  return compareBytes(a.bodyDigest, b.bodyDigest);
}

/** Puts every set and history of the record into snapshot order, in place. */
export function canonicalizeSecurityJournalV2(journal: SecurityJournalV2): void {
  journal.keyRoleHistory ??= [];
  journal.statusKeyHistory ??= [];
  journal.statusByIssuer ??= new Map();
  sortKeyRoleHistoryV2(journal.keyRoleHistory);
  sortStatusKeyHistoryV2(journal.statusKeyHistory);
  for (const [issuerID, state] of journal.statusByIssuer) {
    journal.statusByIssuer.set(issuerID, canonicalizeRevocationStatusStateV2(state));
  }
}

function snapshotObject(source: SecurityJournalV2): Record<string, unknown> {
  // Canonicalize a private copy; the caller's record is not mutated.
  const journal: SecurityJournalV2 = {
    ...source,
    keyRoleHistory: [...source.keyRoleHistory],
    statusKeyHistory: [...source.statusKeyHistory],
    statusByIssuer: new Map(source.statusByIssuer),
  };
  canonicalizeSecurityJournalV2(journal);
  if (journal.generation === 0 && journal.previousDigest !== "") throw new Error("security journal genesis has a predecessor");
  const issuers: Record<string, unknown>[] = [];
  for (const issuerID of [...journal.statusByIssuer.keys()].sort(compareStrings)) {
    const state = journal.statusByIssuer.get(issuerID)!;
    if (state.hasFloor !== (state.acceptedSnapshot !== null)) {
      throw new Error(`security journal issuer "${issuerID}" has an accepted snapshot inconsistent with its floor`);
    }
    let acceptedSnapshot: RawJSON | null = null;
    if (state.hasFloor) {
      try {
        acceptedSnapshot = new RawJSON(encodeRevocationListV2(state.acceptedSnapshot!));
      } catch (err) {
        throw wrapError(`encode accepted snapshot for issuer "${issuerID}"`, err);
      }
    }
    issuers.push({
      accepted_cert_ids: state.acceptedCertIDs,
      accepted_snapshot: acceptedSnapshot,
      deny_union_cert_ids: state.denyUnionCertIDs,
      floor: state.hasFloor ? state.floor : null,
      fork_sequence: state.forkSequence,
      future_dated_object_observed: state.futureDatedObjectObserved,
      issuer_id: state.issuerID,
      max_observed_sequence: state.maxObservedSequence,
      observations: state.observations.map((o) => ({
        accepted: o.accepted, body_digest: o.bodyDigest, evidence_digest: o.evidenceDigest, fork: o.fork,
        future_dated: o.futureDated, gap: o.gap, object_type_code: o.objectType,
        revoked_cert_ids: sortedUniqueStringsV2(o.revokedCertIDs), revoked_set_digest: o.revokedSetDigest,
        sequence: o.sequence, status_key_epoch: o.statusKeyEpoch, status_key_id: o.statusKeyID,
      })),
      preceding_checkpoint: state.hasPrecedingCheckpoint
        ? { accepted_cert_ids: state.precedingAcceptedCertIDs, floor: state.precedingFloor }
        : null,
      reconciliation_required: state.reconciliationRequired,
      retired_status_key_ids: state.retiredStatusKeyIDs,
      status_key_epoch: state.statusKeyEpoch,
      status_key_id: state.statusKeyID,
    });
  }
  return {
    generation: journal.generation,
    issuers,
    key_role_history: journal.keyRoleHistory.map((r) => ({
      ed25519_digest: r.ed25519Digest, key_id: r.keyID, ml_dsa_65_digest: r.mlDsa65Digest, role: r.role,
    })),
    previous_digest: journal.generation === 0 ? GENESIS_PREVIOUS_DIGEST : journal.previousDigest,
    status_key_history: journal.statusKeyHistory.map((b) => ({
      ed25519_digest: b.ed25519Digest, epoch: b.epoch, issuer_id: b.issuerID, ml_dsa_65_digest: b.mlDsa65Digest, status_key_id: b.statusKeyID,
    })),
    version: journal.version,
  };
}

/** Canonical snapshot bytes of a journal, without validation. */
export function securityJournalSnapshotBytesV2(journal: SecurityJournalV2): Uint8Array {
  return canonicalJSONV2(snapshotObject(journal));
}

/** The labelled SHA-384 of canonical snapshot bytes, as 96 lowercase hex characters. */
export function securityJournalSnapshotDigestV2(snapshot: Uint8Array): string {
  return hexOf(sha384(concatBytes(DIGEST_LABEL, snapshot)));
}

/** The record digest under its version's rule. */
export function securityJournalDigestV2(journal: SecurityJournalV2): string {
  if (journal.version === SECURITY_JOURNAL_VERSION_V2) return securityJournalSnapshotDigestV2(securityJournalSnapshotBytesV2(journal));
  if (journal.version === SECURITY_JOURNAL_LEGACY_VERSION_V2) return legacySecurityJournalDigestV1(journal);
  throw new Error(`security journal version ${journal.version} is unsupported`);
}

/** Validates a version 2 journal and returns its canonical snapshot bytes. */
export function exportSecurityJournalSnapshotV2(journal: SecurityJournalV2): Uint8Array {
  if (journal.version !== SECURITY_JOURNAL_VERSION_V2) {
    throw v2Errorf("configuration_invalid", `only version ${SECURITY_JOURNAL_VERSION_V2} security journals can be exported; migrate first`);
  }
  try {
    validateSecurityJournalV2(journal);
  } catch (err) {
    throw v2Classify("configuration_invalid", err);
  }
  return securityJournalSnapshotBytesV2(journal);
}

// --- import -----------------------------------------------------------------

type Obj = Map<string, JNode>;

function obj(n: JNode | undefined, allowed: readonly string[], what: string): Obj {
  if (n === undefined || n.k !== "obj") throw new Error(`${what} must be an object`);
  for (const k of n.m.keys()) if (!allowed.includes(k)) throw new Error(`json: unknown field "${k}"`);
  return n.m;
}
function str(n: JNode | undefined, what: string): string {
  if (n === undefined) return "";
  if (n.k !== "str") throw new Error(`${what} must be a string`);
  return n.v;
}
function bool(n: JNode | undefined, what: string): boolean {
  if (n === undefined) return false;
  if (n.k !== "bool") throw new Error(`${what} must be a boolean`);
  return n.v;
}
function int(n: JNode | undefined, what: string, unsigned: boolean): number {
  if (n === undefined) return 0;
  if (n.k !== "num" || !/^-?(0|[1-9][0-9]*)$/.test(n.raw)) throw new Error(`${what} must be an integer`);
  const v = Number(n.raw);
  if (!Number.isSafeInteger(v) || (unsigned && v < 0)) throw new Error(`${what} is out of range`);
  return v + 0;
}
function strings(n: JNode | undefined, what: string): string[] {
  if (n === undefined) return [];
  if (n.k !== "arr") throw new Error(`${what} must be an array`);
  return n.a.map((x) => str(x, what));
}
function bytes(n: JNode | undefined, what: string): Uint8Array {
  if (n === undefined) return new Uint8Array(0);
  if (n.k !== "str") throw new Error(`${what} must be base64`);
  const out = base64DecodeCanonical(n.v);
  if (out === null) throw new Error(`${what} is not canonical base64`);
  return out;
}
function arr(n: JNode | undefined, what: string): JNode[] {
  if (n === undefined) return [];
  if (n.k !== "arr") throw new Error(`${what} must be an array`);
  return n.a;
}

const SNAPSHOT_FIELDS = ["generation", "issuers", "key_role_history", "previous_digest", "status_key_history", "version"];
const ROLE_FIELDS = ["ed25519_digest", "key_id", "ml_dsa_65_digest", "role"];
const STATUS_KEY_FIELDS = ["ed25519_digest", "epoch", "issuer_id", "ml_dsa_65_digest", "status_key_id"];
const ISSUER_FIELDS = [
  "accepted_cert_ids", "accepted_snapshot", "deny_union_cert_ids", "floor", "fork_sequence", "future_dated_object_observed",
  "issuer_id", "max_observed_sequence", "observations", "preceding_checkpoint", "reconciliation_required",
  "retired_status_key_ids", "status_key_epoch", "status_key_id",
];
const OBSERVATION_FIELDS = [
  "accepted", "body_digest", "evidence_digest", "fork", "future_dated", "gap", "object_type_code", "revoked_cert_ids",
  "revoked_set_digest", "sequence", "status_key_epoch", "status_key_id",
];

/**
 * Decodes canonical snapshot bytes, requires them to be exactly canonical,
 * their digest and generation to equal the independently anchored head, and
 * the record to be valid. There is no partial import. A head mismatch is
 * log_state_mismatch; every other failure is malformed.
 */
export function importSecurityJournalSnapshotV2(snapshot: Uint8Array, head: SecurityJournalHeadV2): SecurityJournalV2 {
  try {
    return importSnapshot(snapshot, head);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
}

function importSnapshot(snapshot: Uint8Array, head: SecurityJournalHeadV2): SecurityJournalV2 {
  if (snapshot.length > MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES) {
    throw new Error(`security journal snapshot exceeds ${MAX_SECURITY_JOURNAL_SNAPSHOT_BYTES} bytes`);
  }
  if (!isValidUTF8(snapshot)) throw new Error("security journal snapshot is not UTF-8");
  let root: JNode;
  try {
    root = parseJSONV2(snapshot, { rejectDuplicates: true });
  } catch (err) {
    throw wrapError("security journal snapshot is not a single object with unique keys", err);
  }
  const f = obj(root, SNAPSHOT_FIELDS, "security journal snapshot");
  const version = int(f.get("version"), "version", true);
  if (version > 0xffff) throw new Error("version is out of range");
  if (version !== SECURITY_JOURNAL_VERSION_V2) throw new Error(`security journal snapshot version ${version} is unsupported`);
  const generation = int(f.get("generation"), "generation", true);
  let previous = str(f.get("previous_digest"), "previous_digest");
  if (generation === 0) {
    if (previous !== GENESIS_PREVIOUS_DIGEST) throw new Error("security journal genesis must have the all-zero predecessor");
    previous = "";
  }
  const journal: SecurityJournalV2 = {
    version, generation, previousDigest: previous, digest: "", statusByIssuer: new Map(), keyRoleHistory: [], statusKeyHistory: [],
  };
  for (const r of arr(f.get("key_role_history"), "key_role_history")) {
    const m = obj(r, ROLE_FIELDS, "key role");
    journal.keyRoleHistory.push({
      keyID: str(m.get("key_id"), "key_id"), ed25519Digest: str(m.get("ed25519_digest"), "ed25519_digest"),
      mlDsa65Digest: str(m.get("ml_dsa_65_digest"), "ml_dsa_65_digest"), role: str(m.get("role"), "role"),
    } satisfies KeyRoleBindingV2);
  }
  for (const b of arr(f.get("status_key_history"), "status_key_history")) {
    const m = obj(b, STATUS_KEY_FIELDS, "status key binding");
    journal.statusKeyHistory.push({
      issuerID: str(m.get("issuer_id"), "issuer_id"), epoch: int(m.get("epoch"), "epoch", true),
      statusKeyID: str(m.get("status_key_id"), "status_key_id"), ed25519Digest: str(m.get("ed25519_digest"), "ed25519_digest"),
      mlDsa65Digest: str(m.get("ml_dsa_65_digest"), "ml_dsa_65_digest"),
    } satisfies StatusKeyBindingV2);
  }
  for (const projectedNode of arr(f.get("issuers"), "issuers")) {
    const p = obj(projectedNode, ISSUER_FIELDS, "issuer state");
    const issuerID = str(p.get("issuer_id"), "issuer_id");
    if (journal.statusByIssuer.has(issuerID)) throw new Error(`security journal snapshot repeats issuer "${issuerID}"`);
    const state: RevocationStatusStateV2 = {
      ...emptyRevocationStatusStateV2(),
      issuerID, statusKeyEpoch: int(p.get("status_key_epoch"), "status_key_epoch", true), statusKeyID: str(p.get("status_key_id"), "status_key_id"),
      retiredStatusKeyIDs: strings(p.get("retired_status_key_ids"), "retired_status_key_ids"),
      acceptedCertIDs: strings(p.get("accepted_cert_ids"), "accepted_cert_ids"),
      denyUnionCertIDs: strings(p.get("deny_union_cert_ids"), "deny_union_cert_ids"),
      maxObservedSequence: int(p.get("max_observed_sequence"), "max_observed_sequence", false),
      forkSequence: int(p.get("fork_sequence"), "fork_sequence", false),
      reconciliationRequired: bool(p.get("reconciliation_required"), "reconciliation_required"),
      futureDatedObjectObserved: bool(p.get("future_dated_object_observed"), "future_dated_object_observed"),
    };
    const floor = p.get("floor");
    if (floor !== undefined && floor.k !== "null") {
      state.hasFloor = true;
      state.floor = int(floor, "floor", false);
    }
    const accepted = p.get("accepted_snapshot");
    if (accepted !== undefined && accepted.k !== "null") {
      if (accepted.k !== "obj") throw new Error("accepted_snapshot must be an object");
      try {
        state.acceptedSnapshot = decodeRevocationListV2(snapshot.subarray(accepted.s, accepted.e));
      } catch (err) {
        throw wrapError(`accepted snapshot for issuer "${issuerID}"`, err);
      }
    }
    const checkpoint = p.get("preceding_checkpoint");
    if (checkpoint !== undefined && checkpoint.k !== "null") {
      const c = obj(checkpoint, ["accepted_cert_ids", "floor"], "preceding_checkpoint");
      state.hasPrecedingCheckpoint = true;
      state.precedingFloor = int(c.get("floor"), "floor", false);
      state.precedingAcceptedCertIDs = strings(c.get("accepted_cert_ids"), "accepted_cert_ids");
    }
    for (const oNode of arr(p.get("observations"), "observations")) {
      const o = obj(oNode, OBSERVATION_FIELDS, "observation");
      const objectType = int(o.get("object_type_code"), "object_type_code", true);
      if (objectType > 0xffff) throw new Error("object_type_code is out of range");
      const observation: RevocationObservationV2 = {
        objectType, statusKeyEpoch: int(o.get("status_key_epoch"), "status_key_epoch", true),
        statusKeyID: str(o.get("status_key_id"), "status_key_id"), sequence: int(o.get("sequence"), "sequence", false),
        evidenceDigest: bytes(o.get("evidence_digest"), "evidence_digest"), bodyDigest: bytes(o.get("body_digest"), "body_digest"),
        revokedSetDigest: bytes(o.get("revoked_set_digest"), "revoked_set_digest"),
        revokedCertIDs: strings(o.get("revoked_cert_ids"), "revoked_cert_ids"),
        futureDated: bool(o.get("future_dated"), "future_dated"), fork: bool(o.get("fork"), "fork"),
        gap: bool(o.get("gap"), "gap"), accepted: bool(o.get("accepted"), "accepted"),
      };
      if (observation.evidenceDigest.length !== 48 || observation.bodyDigest.length !== 48 || observation.revokedSetDigest.length !== 48) {
        throw new Error(`observation digest for issuer "${issuerID}" is not 48 bytes`);
      }
      state.observations.push(observation);
    }
    for (let i = 1; i < state.observations.length; i++) {
      if (compareCompactionOrderV2(state.observations[i - 1]!, state.observations[i]!) > 0) {
        throw new Error(`observations for issuer "${issuerID}" are not in compaction order`);
      }
    }
    journal.statusByIssuer.set(issuerID, state);
  }
  const canonical = securityJournalSnapshotBytesV2(journal);
  if (compareBytes(canonical, snapshot) !== 0) throw new Error("security journal snapshot is not in canonical form");
  journal.digest = securityJournalSnapshotDigestV2(snapshot);
  if (!head || head.generation !== journal.generation || head.digest !== journal.digest) {
    throw v2Errorf("log_state_mismatch", "security journal snapshot does not match the anchored head");
  }
  validateSecurityJournalV2(journal);
  return journal;
}

// --- version 1 migration ------------------------------------------------------

/**
 * JSON paths whose Go slice was nil (encoded null) in a decoded version 1
 * record, so its legacy digest input can be reproduced exactly.
 */
const legacyNulls = new WeakMap<SecurityJournalV2, Set<string>>();

function goStrings(values: readonly string[] | null): string {
  if (values === null) return "null";
  return "[" + values.map((v) => encodeGoString(v, true)).join(",") + "]";
}
function goBytes(b: Uint8Array | null): string {
  return b === null ? "null" : `"${base64Encode(b)}"`;
}

function legacyListJSON(l: RevocationListV2 | null, nulls: Set<string>, path: string): string {
  if (l === null) return "null";
  const revoked = l.revoked === null || (l.revoked.length === 0 && nulls.has(`${path}.revoked`))
    ? "null"
    : "[" + l.revoked.map((r) => `{"cert_id":${encodeGoString(r.cert_id, true)}}`).join(",") + "]";
  const sig = `{"ed25519":${goBytes(l.signature?.ed25519 ?? null)},"ml_dsa_65":${goBytes(l.signature?.ml_dsa_65 ?? null)}}`;
  return `{"version":${l.version},"issuer_id":${encodeGoString(l.issuer_id, true)},"updated_at":${l.updated_at},` +
    `"next_update":${l.next_update},"sequence":${l.sequence},"revoked":${revoked},"signature":${sig}}`;
}

/**
 * The version 1 record's digest input: Go encoding/json of the record (struct
 * field order, HTML escaping, nil slices as null) with an empty digest.
 */
export function legacySecurityJournalDigestInputV1(journal: SecurityJournalV2): Uint8Array {
  const nulls = legacyNulls.get(journal) ?? new Set<string>();
  const slice = (values: readonly string[], path: string) => goStrings(values.length === 0 && nulls.has(path) ? null : values);
  const states = [...journal.statusByIssuer.keys()].sort(compareStrings).map((issuerID) => {
    const s = journal.statusByIssuer.get(issuerID)!;
    const p = `status_by_issuer.${issuerID}`;
    const observations = s.observations.length === 0 && nulls.has(`${p}.observations`)
      ? "null"
      : "[" + s.observations.map((o, i) => `{"object_type":${o.objectType},"status_key_epoch":${o.statusKeyEpoch},` +
        `"status_key_id":${encodeGoString(o.statusKeyID, true)},"sequence":${o.sequence},"evidence_digest":${goBytes(o.evidenceDigest)},` +
        `"body_digest":${goBytes(o.bodyDigest)},"revoked_set_digest":${goBytes(o.revokedSetDigest)},` +
        `"revoked_cert_ids":${slice(o.revokedCertIDs, `${p}.observations.${i}.revoked_cert_ids`)},"future_dated":${o.futureDated},` +
        `"fork":${o.fork},"gap":${o.gap},"accepted":${o.accepted}}`).join(",") + "]";
    return `${encodeGoString(issuerID, true)}:{"issuer_id":${encodeGoString(s.issuerID, true)},"status_key_epoch":${s.statusKeyEpoch},` +
      `"status_key_id":${encodeGoString(s.statusKeyID, true)},"retired_status_key_ids":${slice(s.retiredStatusKeyIDs, `${p}.retired_status_key_ids`)},` +
      `"has_floor":${s.hasFloor},"floor":${s.floor},"accepted_snapshot":${legacyListJSON(s.acceptedSnapshot, nulls, `${p}.accepted_snapshot`)},` +
      `"accepted_cert_ids":${slice(s.acceptedCertIDs, `${p}.accepted_cert_ids`)},"has_preceding_checkpoint":${s.hasPrecedingCheckpoint},` +
      `"preceding_floor":${s.precedingFloor},"preceding_accepted_cert_ids":${slice(s.precedingAcceptedCertIDs, `${p}.preceding_accepted_cert_ids`)},` +
      `"deny_union_cert_ids":${slice(s.denyUnionCertIDs, `${p}.deny_union_cert_ids`)},"observations":${observations},` +
      `"max_observed_sequence":${s.maxObservedSequence},"fork_sequence":${s.forkSequence},` +
      `"reconciliation_required":${s.reconciliationRequired},"future_dated_object_observed":${s.futureDatedObjectObserved}}`;
  });
  const roles = "[" + journal.keyRoleHistory.map((r) => `{"key_id":${encodeGoString(r.keyID, true)},"ed25519_digest":${encodeGoString(r.ed25519Digest, true)},` +
    `"ml_dsa_65_digest":${encodeGoString(r.mlDsa65Digest, true)},"role":${encodeGoString(r.role, true)}}`).join(",") + "]";
  const keys = "[" + journal.statusKeyHistory.map((b) => `{"issuer_id":${encodeGoString(b.issuerID, true)},"epoch":${b.epoch},` +
    `"status_key_id":${encodeGoString(b.statusKeyID, true)},"ed25519_digest":${encodeGoString(b.ed25519Digest, true)},` +
    `"ml_dsa_65_digest":${encodeGoString(b.mlDsa65Digest, true)}}`).join(",") + "]";
  return utf8(`{"version":${journal.version},"generation":${journal.generation},"previous_digest":${encodeGoString(journal.previousDigest, true)},` +
    `"digest":"","status_by_issuer":{${states.join(",")}},"key_role_history":${roles},"status_key_history":${keys}}`);
}

/** The pre-snapshot digest: unlabelled SHA-384 of the legacy digest input. */
export function legacySecurityJournalDigestV1(journal: SecurityJournalV2): string {
  return hexOf(sha384(legacySecurityJournalDigestInputV1(journal)));
}

function goField(m: Obj, name: string): JNode | undefined {
  // encoding/json: an exact match, otherwise a case-insensitive one.
  const exact = m.get(name);
  if (exact !== undefined) return exact;
  for (const [k, v] of m) if (k.toLowerCase() === name) return v;
  return undefined;
}

function legacyInt(n: JNode | undefined, what: string, unsigned: boolean): number {
  if (n === undefined || n.k === "null") return 0;
  return int(n, what, unsigned);
}
function legacyStr(n: JNode | undefined, what: string): string {
  return n === undefined || n.k === "null" ? "" : str(n, what);
}
function legacyBool(n: JNode | undefined, what: string): boolean {
  return n === undefined || n.k === "null" ? false : bool(n, what);
}
function legacyStrings(n: JNode | undefined, what: string, nulls: Set<string>, path: string): string[] {
  if (n === undefined || n.k === "null") {
    nulls.add(path);
    return [];
  }
  return strings(n, what).map((x) => x);
}
function legacyBytes(n: JNode | undefined, what: string): Uint8Array {
  if (n === undefined || n.k === "null") return new Uint8Array(0);
  return bytes(n, what);
}

/**
 * Decodes a version 1 alpha record (Go encoding/json semantics: unknown
 * members ignored, case-insensitive member names, null leaves the zero
 * value). It does not validate the record; migrateSecurityJournalV2 does.
 */
export function decodeLegacySecurityJournalV1(data: Uint8Array): SecurityJournalV2 {
  try {
    const root = parseJSONV2(data);
    if (root.k !== "obj") throw new Error("legacy security journal record must be an object");
    const nulls = new Set<string>();
    const m = root.m;
    const journal: SecurityJournalV2 = {
      version: legacyInt(goField(m, "version"), "version", true),
      generation: legacyInt(goField(m, "generation"), "generation", true),
      previousDigest: legacyStr(goField(m, "previous_digest"), "previous_digest"),
      digest: legacyStr(goField(m, "digest"), "digest"),
      statusByIssuer: new Map(), keyRoleHistory: [], statusKeyHistory: [],
    };
    const byIssuer = goField(m, "status_by_issuer");
    if (byIssuer === undefined || byIssuer.k === "null") throw new Error("legacy record has no status_by_issuer map");
    if (byIssuer.k !== "obj") throw new Error("status_by_issuer must be an object");
    for (const [issuerID, sNode] of byIssuer.m) {
      if (sNode.k !== "obj") throw new Error("issuer status state must be an object");
      const s = sNode.m;
      const p = `status_by_issuer.${issuerID}`;
      const state = emptyRevocationStatusStateV2();
      state.issuerID = legacyStr(goField(s, "issuer_id"), "issuer_id");
      state.statusKeyEpoch = legacyInt(goField(s, "status_key_epoch"), "status_key_epoch", true);
      state.statusKeyID = legacyStr(goField(s, "status_key_id"), "status_key_id");
      state.retiredStatusKeyIDs = legacyStrings(goField(s, "retired_status_key_ids"), "retired_status_key_ids", nulls, `${p}.retired_status_key_ids`);
      state.hasFloor = legacyBool(goField(s, "has_floor"), "has_floor");
      state.floor = legacyInt(goField(s, "floor"), "floor", false);
      const snapshotNode = goField(s, "accepted_snapshot");
      if (snapshotNode !== undefined && snapshotNode.k !== "null") {
        if (snapshotNode.k !== "obj") throw new Error("accepted_snapshot must be an object");
        const l = snapshotNode.m;
        const sig = goField(l, "signature");
        const sigMap = sig !== undefined && sig.k === "obj" ? sig.m : new Map<string, JNode>();
        const revokedNode = goField(l, "revoked");
        if (revokedNode === undefined || revokedNode.k === "null") nulls.add(`${p}.accepted_snapshot.revoked`);
        state.acceptedSnapshot = {
          version: legacyInt(goField(l, "version"), "version", false),
          issuer_id: legacyStr(goField(l, "issuer_id"), "issuer_id"),
          updated_at: legacyInt(goField(l, "updated_at"), "updated_at", false),
          next_update: legacyInt(goField(l, "next_update"), "next_update", false),
          sequence: legacyInt(goField(l, "sequence"), "sequence", false),
          revoked: revokedNode === undefined || revokedNode.k === "null" ? [] : arr(revokedNode, "revoked").map((r) => {
            if (r.k !== "obj") throw new Error("revoked entry must be an object");
            return { cert_id: legacyStr(goField(r.m, "cert_id"), "cert_id") };
          }),
          signature: { ed25519: legacyBytes(goField(sigMap, "ed25519"), "ed25519"), ml_dsa_65: legacyBytes(goField(sigMap, "ml_dsa_65"), "ml_dsa_65") },
        };
      }
      state.acceptedCertIDs = legacyStrings(goField(s, "accepted_cert_ids"), "accepted_cert_ids", nulls, `${p}.accepted_cert_ids`);
      state.hasPrecedingCheckpoint = legacyBool(goField(s, "has_preceding_checkpoint"), "has_preceding_checkpoint");
      state.precedingFloor = legacyInt(goField(s, "preceding_floor"), "preceding_floor", false);
      state.precedingAcceptedCertIDs = legacyStrings(goField(s, "preceding_accepted_cert_ids"), "preceding_accepted_cert_ids", nulls, `${p}.preceding_accepted_cert_ids`);
      state.denyUnionCertIDs = legacyStrings(goField(s, "deny_union_cert_ids"), "deny_union_cert_ids", nulls, `${p}.deny_union_cert_ids`);
      const obsNode = goField(s, "observations");
      if (obsNode === undefined || obsNode.k === "null") nulls.add(`${p}.observations`);
      state.observations = (obsNode === undefined || obsNode.k === "null" ? [] : arr(obsNode, "observations")).map((oNode, i) => {
        if (oNode.k !== "obj") throw new Error("observation must be an object");
        const o = oNode.m;
        return {
          objectType: legacyInt(goField(o, "object_type"), "object_type", true),
          statusKeyEpoch: legacyInt(goField(o, "status_key_epoch"), "status_key_epoch", true),
          statusKeyID: legacyStr(goField(o, "status_key_id"), "status_key_id"),
          sequence: legacyInt(goField(o, "sequence"), "sequence", false),
          evidenceDigest: legacyBytes(goField(o, "evidence_digest"), "evidence_digest"),
          bodyDigest: legacyBytes(goField(o, "body_digest"), "body_digest"),
          revokedSetDigest: legacyBytes(goField(o, "revoked_set_digest"), "revoked_set_digest"),
          revokedCertIDs: legacyStrings(goField(o, "revoked_cert_ids"), "revoked_cert_ids", nulls, `${p}.observations.${i}.revoked_cert_ids`),
          futureDated: legacyBool(goField(o, "future_dated"), "future_dated"),
          fork: legacyBool(goField(o, "fork"), "fork"),
          gap: legacyBool(goField(o, "gap"), "gap"),
          accepted: legacyBool(goField(o, "accepted"), "accepted"),
        } satisfies RevocationObservationV2;
      });
      state.maxObservedSequence = legacyInt(goField(s, "max_observed_sequence"), "max_observed_sequence", false);
      state.forkSequence = legacyInt(goField(s, "fork_sequence"), "fork_sequence", false);
      state.reconciliationRequired = legacyBool(goField(s, "reconciliation_required"), "reconciliation_required");
      state.futureDatedObjectObserved = legacyBool(goField(s, "future_dated_object_observed"), "future_dated_object_observed");
      journal.statusByIssuer.set(issuerID, state);
    }
    const rolesNode = goField(m, "key_role_history");
    const keysNode = goField(m, "status_key_history");
    if (rolesNode === undefined || rolesNode.k === "null" || keysNode === undefined || keysNode.k === "null") {
      throw new Error("legacy record has no key histories");
    }
    for (const r of arr(rolesNode, "key_role_history")) {
      if (r.k !== "obj") throw new Error("key role must be an object");
      journal.keyRoleHistory.push({
        keyID: legacyStr(goField(r.m, "key_id"), "key_id"), ed25519Digest: legacyStr(goField(r.m, "ed25519_digest"), "ed25519_digest"),
        mlDsa65Digest: legacyStr(goField(r.m, "ml_dsa_65_digest"), "ml_dsa_65_digest"), role: legacyStr(goField(r.m, "role"), "role"),
      });
    }
    for (const b of arr(keysNode, "status_key_history")) {
      if (b.k !== "obj") throw new Error("status key binding must be an object");
      journal.statusKeyHistory.push({
        issuerID: legacyStr(goField(b.m, "issuer_id"), "issuer_id"), epoch: legacyInt(goField(b.m, "epoch"), "epoch", true),
        statusKeyID: legacyStr(goField(b.m, "status_key_id"), "status_key_id"),
        ed25519Digest: legacyStr(goField(b.m, "ed25519_digest"), "ed25519_digest"),
        mlDsa65Digest: legacyStr(goField(b.m, "ml_dsa_65_digest"), "ml_dsa_65_digest"),
      });
    }
    legacyNulls.set(journal, nulls);
    return journal;
  } catch (err) {
    throw v2Classify("malformed", err);
  }
}

/**
 * Converts a valid version 1 record into its version 2 successor: the same
 * logical content at generation+1, previous_digest set to the legacy digest,
 * and the canonical snapshot digest. The caller commits it with the store's
 * anchored compare-and-swap from the legacy head.
 */
export function migrateSecurityJournalV2(legacy: SecurityJournalV2): SecurityJournalV2 {
  if (!legacy || legacy.version !== SECURITY_JOURNAL_LEGACY_VERSION_V2) {
    throw v2Errorf("configuration_invalid", `security journal migration requires a version ${SECURITY_JOURNAL_LEGACY_VERSION_V2} record`);
  }
  try {
    validateSecurityJournalV2(legacy);
  } catch (err) {
    throw v2Classify("configuration_invalid", err);
  }
  const next = cloneSecurityJournalV2(legacy);
  if (legacy.generation >= Number.MAX_SAFE_INTEGER) throw v2Errorf("configuration_invalid", "security journal generation exhausted");
  next.version = SECURITY_JOURNAL_VERSION_V2;
  next.generation = legacy.generation + 1;
  next.previousDigest = legacy.digest;
  canonicalizeSecurityJournalV2(next);
  next.digest = securityJournalDigestV2(next);
  try {
    validateSecurityJournalTransitionV2(legacy, next);
  } catch (err) {
    throw v2Classify("configuration_invalid", err);
  }
  return next;
}

/** Compares two journals' logical content, ignoring version, generation and digests. */
export function sameSecurityJournalContentV2(a: SecurityJournalV2, b: SecurityJournalV2): boolean {
  try {
    const left = securityJournalSnapshotBytesV2({ ...a, version: SECURITY_JOURNAL_VERSION_V2, generation: 1, previousDigest: "" });
    const right = securityJournalSnapshotBytesV2({ ...b, version: SECURITY_JOURNAL_VERSION_V2, generation: 1, previousDigest: "" });
    return compareBytes(left, right) === 0;
  } catch {
    return false;
  }
}
