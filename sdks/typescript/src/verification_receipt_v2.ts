// Protocol v2 verification receipt (0x0008): strict codec, terminal-tuple
// validation, receipt-log verification, bundle binding, and the prepared
// pre-signing outbox body. Port of verification_receipt_v2.go and
// verification_receipt_body_v2.go.

import { V2_OBJECT_TYPE, validateHybridKeyPairV2, type HybridKeyPairV2, type V2SignOptions } from "./crypto_v2.js";
import { validV2Timestamp } from "./clock_bounds_v2.js";
import { validConstraintEvaluatorRefsV2, type ConstraintEvaluatorRefV2 } from "./constraint_evaluator_v2.js";
import { MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2, MAX_VERIFICATION_RECEIPT_BYTES_V2, checkV2WireSize } from "./limits_v2.js";
import { newLocalSignerV2, signV2StatementWithSigner, signerPublicKeyV2, type SignOptionsV2, type SignerV2 } from "./signer_v2.js";
import { classified, v2Classify, v2Errorf } from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  bytesEqual,
  canonicalJSONV2,
  checkWireJSONV2,
  compareStrings,
  gArray,
  gBytes,
  gInt,
  gString,
  gStringArray,
  gStruct,
  gUint16,
  hexDecodeGo,
  isWellFormedString,
  requireV2Fields,
  type JNode,
} from "./json_v2.js";
import { type V2AppendResult, statementBodyDigestV2 } from "./key_rotation_v2.js";
import {
  bundleHashV2,
  decodeHybridSignature,
  encodeProofBundleV2,
  keyIDV2,
  keyWire,
  lowerHexString,
  validV2ID,
  validateHybridSignatureV2,
  verifyV2Statement,
  type ProofBundleV2,
} from "./protocol_v2_wire.js";
import { isWildcardScopeV2, validateRequiredScopeV2, validateScopesV2 } from "./scope_v2.js";
import { logPositionV2, validateLogHeadV2, type WitnessV2Head } from "./witness_v2.js";
import type { HybridPublicKey, HybridSignature } from "./types.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;
const ZERO48 = new Uint8Array(48);

/** One authenticated status evidence reference (receipt wire shape). */
export interface StatusEvidenceEntryV2 {
  issuer_id: string;
  status_key_id: string;
  sequence: number;
  object_type_code: number;
  digest: string;
}

/** A verifier-signed terminal assertion. agent_id / human_id "" are absent. */
export interface VerificationReceiptV2 {
  version: number;
  log_id: string;
  sequence: number;
  verifier_id: string;
  agent_id: string;
  human_id: string;
  bundle_hash: string;
  issuer_ids: string[] | null;
  decision: string;
  decision_reason: string;
  identity_status: string;
  trust_assessment: string;
  status_assessment: string;
  challenge_assessment: string;
  /**
   * Present exactly when the claim sealed at least one extension evaluator
   * profile (SPEC-v2 §5.2, §5.8); absent (undefined or null) otherwise.
   */
  constraint_evaluators?: ConstraintEvaluatorRefV2[] | null;
  context_assessment: string;
  context_policy_digest: string | null;
  verified_at: number;
  required_scope: string;
  granted_scope: string[] | null;
  status_evidence_digests: StatusEvidenceEntryV2[] | null;
  previous_receipt_hash: Uint8Array;
  signature: HybridSignature;
}

/** Caller-authenticated receipt-log state; verifierID is pinned for the log. */
export interface ReceiptV2Head extends WitnessV2Head {
  verifierID: string;
}

const RECEIPT_V2_FIELDS = [
  "version", "log_id", "sequence", "verifier_id", "bundle_hash", "issuer_ids", "decision", "decision_reason",
  "identity_status", "trust_assessment", "status_assessment", "challenge_assessment", "context_assessment",
  "context_policy_digest", "verified_at", "required_scope", "granted_scope", "status_evidence_digests",
  "previous_receipt_hash", "signature",
];
const RECEIPT_WIRE_FIELDS = [...RECEIPT_V2_FIELDS, "agent_id", "human_id", "constraint_evaluators"];
const RECEIPT_BODY_REQUIRED = [
  "version", "verifier_id", "bundle_hash", "issuer_ids", "decision", "decision_reason", "identity_status",
  "trust_assessment", "status_assessment", "challenge_assessment", "context_assessment", "context_policy_digest",
  "verified_at", "required_scope", "granted_scope", "status_evidence_digests",
];
const RECEIPT_BODY_FIELDS = [...RECEIPT_BODY_REQUIRED, "agent_id", "human_id", "constraint_evaluators"];
const EVIDENCE_FIELDS = ["digest", "issuer_id", "object_type_code", "sequence", "status_key_id"];

export function evidenceWireV2(values: readonly StatusEvidenceEntryV2[] | null): unknown {
  if (values === null) return null;
  return values.map((v) => ({
    digest: v.digest, issuer_id: v.issuer_id, object_type_code: v.object_type_code, sequence: v.sequence, status_key_id: v.status_key_id,
  }));
}

function bodyObject(r: VerificationReceiptV2): Record<string, unknown> {
  return {
    agent_id: r.agent_id === "" ? undefined : r.agent_id,
    bundle_hash: r.bundle_hash,
    challenge_assessment: r.challenge_assessment,
    constraint_evaluators: r.constraint_evaluators && r.constraint_evaluators.length > 0
      ? r.constraint_evaluators.map((e) => ({ profile_digest: e.profile_digest, type: e.type }))
      : undefined,
    context_assessment: r.context_assessment,
    context_policy_digest: r.context_policy_digest,
    decision: r.decision,
    decision_reason: r.decision_reason,
    granted_scope: r.granted_scope,
    human_id: r.human_id === "" ? undefined : r.human_id,
    identity_status: r.identity_status,
    issuer_ids: r.issuer_ids,
    required_scope: r.required_scope,
    status_assessment: r.status_assessment,
    status_evidence_digests: evidenceWireV2(r.status_evidence_digests),
    trust_assessment: r.trust_assessment,
    verified_at: r.verified_at,
    verifier_id: r.verifier_id,
    version: r.version,
  };
}

function signableObject(r: VerificationReceiptV2): Record<string, unknown> {
  const o = bodyObject(r);
  o.log_id = r.log_id;
  o.previous_receipt_hash = r.previous_receipt_hash;
  o.sequence = r.sequence;
  return o;
}

export function verificationReceiptV2SignBytes(r: VerificationReceiptV2): Uint8Array {
  return canonicalJSONV2(signableObject(r));
}

export function validPrefixedDigestV2(value: unknown): value is string {
  if (typeof value !== "string" || !value.startsWith("sha384:") || value.length !== 7 + 96) return false;
  const decoded = hexDecodeGo(value.slice(7));
  return decoded !== null && decoded.length === 48 && value.toLowerCase() === value;
}

function sortedUniqueV2IDs(values: readonly string[]): boolean {
  for (let i = 0; i < values.length; i++) {
    if (!validV2ID(values[i]) || (i > 0 && compareStrings(values[i - 1]!, values[i]!) >= 0)) return false;
  }
  return true;
}

function sortedGrantedScopesV2(values: readonly string[]): boolean {
  if (values.length === 0) return true;
  if (validateScopesV2(values) !== null) return false;
  for (let i = 0; i < values.length; i++) {
    if (isWildcardScopeV2(values[i]!) || (i > 0 && compareStrings(values[i - 1]!, values[i]!) >= 0)) return false;
  }
  return true;
}

export function hasAcceptedStatusHistoryPerIssuerV2(evidence: readonly StatusEvidenceEntryV2[], issuerIDs: readonly string[]): boolean {
  for (const issuerID of issuerIDs) {
    let baseSequence = 0;
    let statusKeyID = "";
    const pushes = new Set<number>();
    for (const entry of evidence) {
      if (entry.issuer_id !== issuerID) continue;
      if (statusKeyID === "") statusKeyID = entry.status_key_id;
      else if (statusKeyID !== entry.status_key_id) return false;
      if (entry.object_type_code === 3) {
        if (baseSequence !== 0) return false;
        baseSequence = entry.sequence;
      } else {
        if (pushes.has(entry.sequence)) return false;
        pushes.add(entry.sequence);
      }
    }
    if (baseSequence === 0) return false;
    for (const s of pushes) if (s <= baseSequence) return false;
    for (let s = baseSequence + 1; s <= baseSequence + pushes.size; s++) if (!pushes.has(s)) return false;
  }
  return issuerIDs.length > 0;
}

export function compareStatusEvidenceV2(a: StatusEvidenceEntryV2, b: StatusEvidenceEntryV2): number {
  const c1 = compareStrings(a.issuer_id, b.issuer_id);
  if (c1 !== 0) return c1;
  const c2 = compareStrings(a.status_key_id, b.status_key_id);
  if (c2 !== 0) return c2;
  if (a.sequence !== b.sequence) return a.sequence < b.sequence ? -1 : 1;
  if (a.object_type_code !== b.object_type_code) return a.object_type_code < b.object_type_code ? -1 : 1;
  return compareStrings(a.digest, b.digest);
}

function sortedEvidenceV2(values: readonly StatusEvidenceEntryV2[], issuerIDs: readonly string[], verifierID: string, agentID: string): boolean {
  const issuerSet = new Set(issuerIDs);
  const statusKeyIssuers = new Map<string, string>();
  for (let i = 0; i < values.length; i++) {
    const v = values[i]!;
    const prior = statusKeyIssuers.get(v.status_key_id);
    if (prior !== undefined && prior !== v.issuer_id) return false;
    statusKeyIssuers.set(v.status_key_id, v.issuer_id);
    if (!issuerSet.has(v.issuer_id) || !validV2ID(v.status_key_id) || issuerSet.has(v.status_key_id) ||
        v.status_key_id === verifierID || (agentID !== "" && v.status_key_id === agentID) ||
        !(v.sequence > 0) || v.sequence > MAX_SAFE || (v.object_type_code !== 3 && v.object_type_code !== 5) ||
        !validPrefixedDigestV2(v.digest)) {
      return false;
    }
    if (i > 0 && compareStatusEvidenceV2(values[i - 1]!, v) >= 0) return false;
  }
  return true;
}

function containsAll(have: readonly string[], want: readonly string[]): boolean {
  const set = new Set(have);
  return want.every((w) => set.has(w));
}

export function validateVerificationReceiptV2(r: VerificationReceiptV2, signature: boolean): void {
  if (!r || r.version !== 2 || typeof r.log_id !== "string" || r.log_id.length !== 32 || !lowerHexString(r.log_id) ||
      !(r.sequence > 0) || r.sequence > MAX_SAFE || !Number.isInteger(r.sequence) || !validV2Timestamp(r.verified_at)) {
    throw new Error("wire v2: receipt version, log ID, sequence, or verified_at is invalid");
  }
  if (!validV2ID(r.verifier_id) || (r.agent_id !== "" && !validV2ID(r.agent_id))) {
    throw new Error("wire v2: receipt verifier_id and optional agent_id must be v2 key IDs");
  }
  if (r.human_id !== "" && !isWellFormedString(r.human_id)) throw new Error("wire v2: human_id must be a valid UTF-8 string");
  if (!validPrefixedDigestV2(r.bundle_hash) || !(r.previous_receipt_hash instanceof Uint8Array) || r.previous_receipt_hash.length !== 48) {
    throw new Error("wire v2: receipt bundle hash or previous receipt hash is invalid");
  }
  if (r.issuer_ids === null || !sortedUniqueV2IDs(r.issuer_ids) || r.granted_scope === null || r.status_evidence_digests === null) {
    throw new Error("wire v2: receipt arrays must be present and canonical");
  }
  const issuers = r.issuer_ids;
  const evidence = r.status_evidence_digests;
  const granted = r.granted_scope;
  if (r.decision_reason !== "not_delegated" && r.decision_reason !== "evaluation_interrupted" && issuers.length === 0) {
    throw new Error("wire v2: a receipt for a delegated decision must identify its certificate issuers");
  }
  if (r.decision_reason === "evaluation_interrupted" && issuers.length === 0 &&
      (r.trust_assessment !== "not_evaluated" || r.status_assessment !== "not_evaluated" || r.context_assessment !== "not_evaluated" || evidence.length !== 0)) {
    throw new Error("wire v2: interrupted empty-chain receipt cannot claim completed trust, status, or context checks");
  }
  const scopeErr = validateRequiredScopeV2(r.required_scope);
  if (scopeErr) throw new Error(`wire v2: ${scopeErr}`);
  if ((r.sequence === 1 && !bytesEqual(r.previous_receipt_hash, ZERO48)) || (r.sequence > 1 && bytesEqual(r.previous_receipt_hash, ZERO48))) {
    throw new Error("wire v2: previous_receipt_hash is inconsistent with receipt sequence");
  }
  if (!sortedGrantedScopesV2(granted)) throw new Error("wire v2: granted_scope must be sorted, unique canonical scopes");
  for (const id of issuers) if (!validV2ID(id)) throw new Error("wire v2: issuer_ids contains an invalid v2 key ID");
  if (!sortedEvidenceV2(evidence, issuers, r.verifier_id, r.agent_id)) {
    throw new Error("wire v2: status evidence is invalid, duplicated, or not canonically sorted");
  }
  const sa = r.status_assessment;
  const ca = r.context_assessment;
  if ((sa === "current" || sa === "revoked" || sa === "stale") && evidence.length === 0) {
    throw new Error("wire v2: evaluated status requires authenticated evidence");
  }
  if (r.context_policy_digest !== null && !validPrefixedDigestV2(r.context_policy_digest)) {
    throw new Error("wire v2: context_policy_digest is invalid");
  }
  const evaluators = r.constraint_evaluators ?? [];
  if (!validConstraintEvaluatorRefsV2(evaluators) || (evaluators.length !== 0 && issuers.length === 0)) {
    throw new Error("wire v2: constraint_evaluators must be valid extension types with sha384 profile digests, sorted and unique by type, and only for a delegated chain");
  }
  if (((ca === "not_evaluated" || ca === "unbound") && r.context_policy_digest !== null) ||
      ((ca === "bound" || ca === "not_required" || ca === "mismatch") && r.context_policy_digest === null)) {
    throw new Error("wire v2: context_policy_digest does not match context_assessment");
  }
  if (sa === "not_evaluated" && evidence.length !== 0) throw new Error("wire v2: status evidence cannot be present when status was not evaluated");
  if ((sa === "current" || sa === "stale") && !hasAcceptedStatusHistoryPerIssuerV2(evidence, issuers)) {
    throw new Error("wire v2: current or stale status requires one accepted full-list base and contiguous pushes for every issuer");
  }
  if (r.challenge_assessment !== "current") throw new Error("wire v2: terminal receipt challenge_assessment must be current");
  validateReceiptDecisionV2(r);
  if (signature) validateHybridSignatureV2(r.signature);
}

const DECISION_REASONS = new Set([
  "authorized", "not_delegated", "delegation_not_authorized", "delegation_expired", "delegation_revoked", "scope_denied",
  "constraint_denied", "constraint_unverifiable", "constraint_unknown", "invalid_scope", "proof_invalid", "unauthorized",
  "status_stale", "status_unavailable", "action_context_unverified", "trust_unavailable", "evaluation_interrupted",
]);

const DENY_PAIRS: Record<string, string> = {
  not_delegated: "delegation_not_authorized", delegation_not_authorized: "delegation_not_authorized", delegation_expired: "expired",
  delegation_revoked: "revoked", scope_denied: "scope_denied", invalid_scope: "invalid_scope", constraint_denied: "constraint_denied",
  constraint_unverifiable: "constraint_unverifiable", constraint_unknown: "constraint_unknown", proof_invalid: "invalid",
  unauthorized: "unauthorized",
};

function validateReceiptDecisionV2(r: VerificationReceiptV2): void {
  const reason = r.decision_reason;
  const ta = r.trust_assessment;
  const sa = r.status_assessment;
  const ca = r.context_assessment;
  const evidence = r.status_evidence_digests ?? [];
  const granted = r.granted_scope ?? [];
  if (!DECISION_REASONS.has(reason)) throw new Error("wire v2: receipt decision_reason is invalid");
  if (!["trusted", "untrusted", "unavailable", "not_evaluated"].includes(ta)) throw new Error("wire v2: receipt trust_assessment is invalid");
  if (!["current", "revoked", "stale", "unavailable", "not_evaluated"].includes(sa)) throw new Error("wire v2: receipt status_assessment is invalid");
  if (!["bound", "not_required", "unbound", "unverified", "mismatch", "not_evaluated"].includes(ca)) {
    throw new Error("wire v2: receipt context_assessment is invalid");
  }
  const constraintReason = reason === "scope_denied" || reason === "constraint_denied" || reason === "constraint_unverifiable" || reason === "constraint_unknown";
  if (r.decision === "allow") {
    if (reason !== "authorized" || r.identity_status !== "authorized_agent" || ta !== "trusted" || sa !== "current" ||
        evidence.length === 0 || granted.length === 0 || !containsAll(granted, [r.required_scope]) ||
        (ca !== "bound" && ca !== "not_required") || r.context_policy_digest === null) {
      throw new Error("wire v2: allow receipt violates authorization, status, context, or scope requirements");
    }
    return;
  }
  if (r.decision === "deny") {
    if (granted.length !== 0 || !(Object.prototype.hasOwnProperty.call(DENY_PAIRS, reason) && DENY_PAIRS[reason] === r.identity_status)) {
      throw new Error("wire v2: deny receipt has an invalid reason/status pair or granted scope");
    }
    if (reason === "not_delegated" && (r.issuer_ids ?? []).length !== 0) {
      throw new Error("wire v2: not_delegated receipt cannot contain certificate issuers");
    }
    if (constraintReason && sa !== "current") throw new Error("wire v2: post-status local policy denial requires current status");
    if ((reason === "unauthorized" && ta !== "untrusted") || (reason === "not_delegated" && ta !== "not_evaluated") ||
        (reason !== "unauthorized" && reason !== "not_delegated" && ta !== "trusted")) {
      throw new Error("wire v2: deny receipt trust assessment is inconsistent");
    }
    if ((reason === "delegation_revoked" && sa !== "revoked") || (reason === "not_delegated" && sa !== "not_evaluated") ||
        (reason !== "delegation_revoked" && reason !== "not_delegated" && sa !== "not_evaluated" && !(sa === "current" && constraintReason))) {
      throw new Error("wire v2: deny receipt status assessment is inconsistent");
    }
    if ((reason === "not_delegated" && ca !== "not_evaluated") || (reason === "unauthorized" && ca !== "not_evaluated")) {
      throw new Error("wire v2: deny receipt context assessment is inconsistent");
    }
    if (reason === "delegation_revoked" && ca === "not_evaluated") {
      throw new Error("wire v2: delegation_revoked receipt must retain its completed context assessment");
    }
    if (reason !== "delegation_revoked" && !constraintReason && reason !== "not_delegated" && reason !== "unauthorized" && ca !== "not_evaluated") {
      throw new Error("wire v2: context assessment must be not_evaluated for this deny result");
    }
    if ((reason === "scope_denied" && ca === "not_evaluated") ||
        ((reason === "constraint_denied" || reason === "constraint_unverifiable" || reason === "constraint_unknown") &&
         ca !== "bound" && ca !== "not_required" && !(reason === "constraint_denied" && ca === "mismatch"))) {
      throw new Error("wire v2: constraint denial must retain its completed context assessment");
    }
    if ((reason === "not_delegated" || reason === "unauthorized") && evidence.length !== 0) {
      throw new Error("wire v2: status evidence is not evaluated for this deny result");
    }
    if (reason === "constraint_denied" && ca === "mismatch" && r.identity_status !== "constraint_denied") {
      throw new Error("wire v2: context mismatch must be a constraint denial");
    }
    return;
  }
  if (r.decision !== "indeterminate" || granted.length !== 0 || r.identity_status !== "authorization_unverified") {
    throw new Error("wire v2: receipt decision or indeterminate identity/scope is invalid");
  }
  switch (reason) {
    case "status_stale":
      if (ta !== "trusted" || sa !== "stale" || ca === "not_evaluated") throw new Error("wire v2: status_stale assessment tuple is invalid");
      return;
    case "status_unavailable":
      if (ta !== "trusted" || sa !== "unavailable" || ca === "not_evaluated") throw new Error("wire v2: status_unavailable assessment tuple is invalid");
      return;
    case "trust_unavailable":
      if (ta !== "unavailable" || sa !== "not_evaluated" || ca !== "not_evaluated" || evidence.length !== 0) {
        throw new Error("wire v2: trust_unavailable assessment tuple is invalid");
      }
      return;
    case "action_context_unverified":
      if (ta !== "trusted" || sa !== "current" || (ca !== "unbound" && ca !== "unverified")) {
        throw new Error("wire v2: action_context_unverified assessment tuple is invalid");
      }
      return;
    case "evaluation_interrupted":
      // Each dimension is independent (SPEC-v2 §6.7): trust keeps its last
      // state; status and context exist only under a trusted root; context is
      // recorded only when it completed as bound or not_required.
      if ((ca !== "not_evaluated" && ca !== "bound" && ca !== "not_required") ||
          (ta !== "trusted" && (sa !== "not_evaluated" || ca !== "not_evaluated"))) {
        throw new Error("wire v2: evaluation_interrupted assessment tuple is invalid");
      }
      return;
    default:
      throw new Error("wire v2: indeterminate reason is invalid");
  }
}

export function verificationReceiptV2Digest(r: VerificationReceiptV2): Uint8Array {
  validateVerificationReceiptV2(r, false);
  return statementBodyDigestV2(V2_OBJECT_TYPE.verificationReceipt, verificationReceiptV2SignBytes(r));
}

export function encodeVerificationReceiptV2(r: VerificationReceiptV2): Uint8Array {
  validateVerificationReceiptV2(r, true);
  const o = signableObject(r);
  o.signature = keyWire(r.signature);
  const data = canonicalJSONV2(o);
  checkV2WireSize(data, "verification receipt", "MAX_VERIFICATION_RECEIPT_BYTES_V2", MAX_VERIFICATION_RECEIPT_BYTES_V2);
  return data;
}

function decodeEvidence(n: JNode | undefined): StatusEvidenceEntryV2[] | null {
  const arr = gArray(n, "status_evidence_digests");
  if (arr === null) return null;
  return arr.map((x) => {
    const f = gStruct(x, EVIDENCE_FIELDS, "status evidence");
    return {
      digest: gString(f.get("digest"), "digest"),
      issuer_id: gString(f.get("issuer_id"), "issuer_id"),
      object_type_code: gUint16(f.get("object_type_code"), "object_type_code"),
      sequence: gInt(f.get("sequence"), "sequence"),
      status_key_id: gString(f.get("status_key_id"), "status_key_id"),
    };
  });
}

function decodeEvaluators(n: JNode | undefined): ConstraintEvaluatorRefV2[] | undefined {
  const arr = gArray(n, "constraint_evaluators");
  if (arr === null) return n === undefined ? undefined : [];
  return arr.map((x) => {
    const f = gStruct(x, ["profile_digest", "type"], "constraint evaluator");
    return { profile_digest: gString(f.get("profile_digest"), "profile_digest"), type: gString(f.get("type"), "type") };
  });
}

function decodeReceiptStruct(root: JNode, allowed: readonly string[]): VerificationReceiptV2 {
  const f = gStruct(root, allowed, "verification receipt");
  const cpd = f.get("context_policy_digest");
  const evaluators = decodeEvaluators(f.get("constraint_evaluators"));
  return {
    version: gInt(f.get("version"), "version"),
    log_id: gString(f.get("log_id"), "log_id"),
    sequence: gInt(f.get("sequence"), "sequence"),
    verifier_id: gString(f.get("verifier_id"), "verifier_id"),
    agent_id: gString(f.get("agent_id"), "agent_id"),
    human_id: gString(f.get("human_id"), "human_id"),
    bundle_hash: gString(f.get("bundle_hash"), "bundle_hash"),
    issuer_ids: gStringArray(f.get("issuer_ids"), "issuer_ids"),
    decision: gString(f.get("decision"), "decision"),
    decision_reason: gString(f.get("decision_reason"), "decision_reason"),
    identity_status: gString(f.get("identity_status"), "identity_status"),
    trust_assessment: gString(f.get("trust_assessment"), "trust_assessment"),
    status_assessment: gString(f.get("status_assessment"), "status_assessment"),
    challenge_assessment: gString(f.get("challenge_assessment"), "challenge_assessment"),
    ...(evaluators === undefined ? {} : { constraint_evaluators: evaluators }),
    context_assessment: gString(f.get("context_assessment"), "context_assessment"),
    context_policy_digest: cpd === undefined || cpd.k === "null" ? null : gString(cpd, "context_policy_digest"),
    verified_at: gInt(f.get("verified_at"), "verified_at"),
    required_scope: gString(f.get("required_scope"), "required_scope"),
    granted_scope: gStringArray(f.get("granted_scope"), "granted_scope"),
    status_evidence_digests: decodeEvidence(f.get("status_evidence_digests")),
    previous_receipt_hash: gBytes(f.get("previous_receipt_hash"), "previous_receipt_hash") ?? new Uint8Array(0),
    signature: decodeHybridSignature(f.get("signature"), "signature"),
  };
}

export function decodeVerificationReceiptV2(data: Uint8Array): VerificationReceiptV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "verification receipt", "MAX_VERIFICATION_RECEIPT_BYTES_V2", MAX_VERIFICATION_RECEIPT_BYTES_V2);
    const root = checkWireJSONV2(data, ["previous_receipt_hash"], ["bundle_hash"]);
    requireV2Fields(root, RECEIPT_V2_FIELDS, ["context_policy_digest"]);
    const r = decodeReceiptStruct(root, RECEIPT_WIRE_FIELDS);
    validateVerificationReceiptV2(r, true);
    let canonical: Uint8Array | null = null;
    try {
      canonical = encodeVerificationReceiptV2(r);
    } catch {
      canonical = null;
    }
    if (canonical === null || !bytesEqual(canonical, data)) throw new Error("wire v2: verification receipt is not canonical Ratify JSON");
    return r;
  });
}

/** Go validateVerificationReceiptSignableV2 (statement-body digest schema check). */
export function validateVerificationReceiptSignableV2(data: Uint8Array): void {
  const root = checkWireJSONV2(data, ["previous_receipt_hash"], ["bundle_hash"]);
  requireV2Fields(root, RECEIPT_V2_FIELDS.slice(0, -1), ["context_policy_digest"]);
  if (root.k === "obj" && root.m.has("signature")) throw new Error("signable body must exclude signature");
  const r = decodeReceiptStruct(root, RECEIPT_WIRE_FIELDS);
  validateVerificationReceiptV2(r, false);
  let canonical: Uint8Array | null = null;
  try {
    canonical = verificationReceiptV2SignBytes(r);
  } catch {
    canonical = null;
  }
  if (canonical === null || !bytesEqual(canonical, data)) throw new Error("signable body must use RatifyCanonicalJSON");
}

export async function signVerificationReceiptV2(r: VerificationReceiptV2, verifier: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<VerificationReceiptV2> {
  validateVerificationReceiptV2(r, false);
  await validateHybridKeyPairV2(verifier);
  return signVerificationReceiptV2WithSigner(r, await newLocalSignerV2(verifier, { deterministic: opts.deterministic }));
}

/** signVerificationReceiptV2 through a signer whose key ID must equal verifier_id. */
export async function signVerificationReceiptV2WithSigner(r: VerificationReceiptV2, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<VerificationReceiptV2> {
  validateVerificationReceiptV2(r, false);
  const verifierPublic = await signerPublicKeyV2(signer);
  if (keyIDV2(verifierPublic) !== r.verifier_id) throw new Error("receipt verifier_id does not match signing key");
  const signature = await signV2StatementWithSigner(V2_OBJECT_TYPE.verificationReceipt, verificationReceiptV2SignBytes(r), signer, verifierPublic, opts);
  const result = { ...r, signature };
  encodeVerificationReceiptV2(result);
  return result;
}

function validateReceiptV2Head(head: ReceiptV2Head): void {
  if (!head || !validV2ID(head.verifierID)) throw v2Errorf("configuration_invalid", "caller receipt head is invalid");
  validateLogHeadV2(head, "receipt");
}

/**
 * Verifies a receipt with a caller-supplied verifier key and authenticated
 * log head; the receipt never supplies trust in its own key.
 */
export async function verifyVerificationReceiptV2(r: VerificationReceiptV2, verifierPublic: HybridPublicKey, head: ReceiptV2Head): Promise<V2AppendResult> {
  try {
    validateVerificationReceiptV2(r, true);
    encodeVerificationReceiptV2(r);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  validateReceiptV2Head(head);
  if (r.log_id !== head.logID || r.verifier_id !== head.verifierID) {
    throw v2Errorf("log_state_mismatch", "receipt log ID or verifier identity does not match caller-authenticated state");
  }
  if (r.verifier_id !== keyIDV2(verifierPublic)) {
    throw v2Errorf("log_state_mismatch", "receipt verifier_id does not match caller-authenticated key");
  }
  await verifyV2Statement(V2_OBJECT_TYPE.verificationReceipt, verificationReceiptV2SignBytes(r), r.signature, verifierPublic);
  return logPositionV2(r.sequence, r.previous_receipt_hash, verificationReceiptV2Digest(r), head);
}

/**
 * Compares the fields available when a receipt and its proof bundle are both
 * present. It does not establish root trust or current status.
 */
export function checkVerificationReceiptV2BundleBinding(r: VerificationReceiptV2, bundle: ProofBundleV2): void {
  try {
    validateVerificationReceiptV2(r, false);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  try {
    encodeProofBundleV2(bundle);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  if (r.verifier_id !== bundle.verifier_id || (r.agent_id !== "" && r.agent_id !== bundle.agent_id)) {
    throw v2Errorf("receipt_bundle_mismatch", "receipt verifier or agent ID does not match the proof bundle");
  }
  const certs = bundle.delegations ?? [];
  const roleKeyIDs = new Set([bundle.verifier_id, bundle.agent_id]);
  for (const c of certs) {
    roleKeyIDs.add(c.issuer_id);
    roleKeyIDs.add(c.subject_id);
  }
  for (const e of r.status_evidence_digests ?? []) {
    if (roleKeyIDs.has(e.status_key_id)) {
      throw v2Errorf("receipt_bundle_mismatch", "receipt status key ID overlaps a proof or verifier key role");
    }
  }
  if (r.bundle_hash !== bundleHashV2(bundle)) throw v2Errorf("receipt_bundle_mismatch", "receipt bundle_hash does not match the proof bundle");
  const issuerIDs = [...new Set(certs.map((c) => c.issuer_id))].sort(compareStrings);
  const got = r.issuer_ids ?? [];
  if (issuerIDs.length !== got.length || issuerIDs.some((id, i) => id !== got[i])) {
    throw v2Errorf("receipt_bundle_mismatch", "receipt issuer_ids do not match the proof bundle chain");
  }
}

// ---------------------------------------------------------------------------
// Prepared body (verification_receipt_body_v2.go)

/**
 * The canonical content prepared before terminal commit. It excludes log
 * position, previous hash and signature; the caller binds it to its claim.
 */
export function verificationReceiptV2Body(r: VerificationReceiptV2): Uint8Array {
  if (!r) throw new Error("wire v2: receipt body is nil");
  const candidate: VerificationReceiptV2 = {
    ...r, log_id: "0123456789abcdef0123456789abcdef", sequence: 1, previous_receipt_hash: new Uint8Array(48),
    signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  validateVerificationReceiptV2(candidate, false);
  // Reserve the largest log envelope before commit.
  const prev = new Uint8Array(48);
  prev[0] = 1;
  encodeVerificationReceiptV2({
    ...candidate, sequence: MAX_SAFE, previous_receipt_hash: prev,
    signature: { ed25519: new Uint8Array(64), ml_dsa_65: new Uint8Array(3309) },
  });
  return canonicalJSONV2(bodyObject(r));
}

function emptyReceiptEnvelope(): Pick<VerificationReceiptV2, "log_id" | "sequence" | "previous_receipt_hash" | "signature"> {
  return { log_id: "", sequence: 0, previous_receipt_hash: new Uint8Array(0), signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) } };
}

/** Rejects a malformed or noncanonical pre-signing body. */
export function decodeVerificationReceiptBodyV2(data: Uint8Array): VerificationReceiptV2 {
  return classified("malformed", () => {
    checkV2WireSize(data, "verification receipt body", "MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2", MAX_VERIFICATION_RECEIPT_BODY_BYTES_V2);
    const root = checkWireJSONV2(data, [], ["bundle_hash"]);
    requireV2Fields(root, RECEIPT_BODY_REQUIRED, ["context_policy_digest"]);
    const decoded = decodeReceiptStruct(root, RECEIPT_BODY_FIELDS);
    const receipt: VerificationReceiptV2 = { ...decoded, ...emptyReceiptEnvelope() };
    let canonical: Uint8Array;
    try {
      canonical = verificationReceiptV2Body(receipt);
    } catch (err) {
      throw new Error(`wire v2: verification receipt body is invalid or noncanonical: ${(err as Error).message}`);
    }
    if (!bytesEqual(canonical, data)) throw new Error("wire v2: verification receipt body is noncanonical");
    return receipt;
  });
}

/** Assigns the next position in a caller-authenticated receipt log to a prepared body. */
export function bindVerificationReceiptBodyV2(data: Uint8Array, head: ReceiptV2Head): VerificationReceiptV2 {
  validateReceiptV2Head(head);
  if (head.frozen || head.sequence === MAX_SAFE) throw new Error("wire v2: receipt log cannot accept another entry");
  const receipt = decodeVerificationReceiptBodyV2(data);
  if (receipt.verifier_id !== head.verifierID) throw new Error("wire v2: prepared receipt verifier differs from authenticated log");
  receipt.log_id = head.logID;
  receipt.sequence = head.sequence + 1;
  receipt.previous_receipt_hash = Uint8Array.from(head.headHash);
  validateVerificationReceiptV2(receipt, false);
  return receipt;
}

/** Binds and signs an exact prepared body with a local verifier key. */
export async function signPreparedVerificationReceiptV2(data: Uint8Array, head: ReceiptV2Head, verifier: HybridKeyPairV2, opts: V2SignOptions = {}): Promise<VerificationReceiptV2> {
  await validateHybridKeyPairV2(verifier);
  return signPreparedVerificationReceiptV2WithSigner(data, head, await newLocalSignerV2(verifier, { deterministic: opts.deterministic }));
}

/** signPreparedVerificationReceiptV2 with an external verifier signer. */
export async function signPreparedVerificationReceiptV2WithSigner(data: Uint8Array, head: ReceiptV2Head, signer: SignerV2, opts: SignOptionsV2 = {}): Promise<VerificationReceiptV2> {
  const bound = bindVerificationReceiptBodyV2(data, head);
  const signed = await signVerificationReceiptV2WithSigner(bound, signer, opts);
  let body: Uint8Array | null = null;
  try {
    body = verificationReceiptV2Body(signed);
  } catch {
    body = null;
  }
  if (body === null || !bytesEqual(body, data)) throw new Error("wire v2: signed receipt differs from prepared body");
  return signed;
}
