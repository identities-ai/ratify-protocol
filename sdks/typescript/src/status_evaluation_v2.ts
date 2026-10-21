// Protocol v2 status aggregation across every CertificateRef of a verified
// chain (revoked > unavailable > stale, independent of chain order). Port of
// status_evaluation_v2.go.

import { MAX_SAFE_INTEGER_V2, hexDecodeGo } from "./json_v2.js";
import { validV2ID } from "./protocol_v2_wire.js";
import {
  sameStatusEvidenceV2,
  sortStatusEvidenceV2,
  sortedUniqueStringsV2,
  type RevocationStatusResultV2,
} from "./status_state_v2.js";
import { hasAcceptedStatusHistoryPerIssuerV2, type StatusEvidenceEntryV2 } from "./verification_receipt_v2.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;

export interface V2CertificateStatusCheck {
  delegationIndex: number;
  issuerID: string;
  subjectID: string;
  certID: string;
}

/** Deterministic aggregate; not a terminal decision. */
export interface V2StatusAssessment {
  assessment: string;
  reason: string;
  evidence: StatusEvidenceEntryV2[];
  freshUntil: number;
}

/**
 * Caller-authenticated status-key role bindings. reservedKeyIDs must include
 * every non-status role admitted by deployment trust history that is not in
 * the evaluated chain.
 */
export interface V2StatusRoleBindings {
  statusKeyIssuers: Map<string, string> | null;
  currentStatusKeyIDs: Map<string, string> | null;
  reservedKeyIDs: Set<string> | null;
}

function validV2StatusEvidenceDigest(value: string): boolean {
  if (typeof value !== "string" || !value.startsWith("sha384:")) return false;
  const encoded = value.slice(7);
  return encoded.length === 96 && encoded === encoded.toLowerCase() && hexDecodeGo(encoded) !== null;
}

function evidenceKey(e: StatusEvidenceEntryV2): string {
  return JSON.stringify([e.issuer_id, e.status_key_id, e.sequence, e.object_type_code, e.digest]);
}

function validateV2StatusRoleBindings(roles: V2StatusRoleBindings, checks: readonly V2CertificateStatusCheck[]): void {
  if (!roles || !roles.statusKeyIssuers || !roles.currentStatusKeyIDs || !roles.reservedKeyIDs) {
    throw new Error("v2 status aggregation requires authenticated status-key role bindings");
  }
  for (const [keyID, issuerID] of roles.statusKeyIssuers) {
    if (!validV2ID(keyID) || !validV2ID(issuerID)) throw new Error("authenticated status-key binding is malformed");
    if (roles.reservedKeyIDs.has(keyID)) throw new Error("status key collides with a reserved non-status key role");
  }
  for (const issuerID of new Set(checks.map((c) => c.issuerID))) {
    const keyID = roles.currentStatusKeyIDs.get(issuerID) ?? "";
    if ((roles.statusKeyIssuers.get(keyID) ?? "") !== issuerID) throw new Error("issuer lacks an authenticated current status-key binding");
  }
  for (const keyID of roles.reservedKeyIDs) if (!validV2ID(keyID)) throw new Error("reserved non-status key ID is malformed");
}

function addIssuerHistoryV2(histories: Map<string, StatusEvidenceEntryV2[]>, issuerID: string, evidence: readonly StatusEvidenceEntryV2[]): boolean {
  const canonical = sortStatusEvidenceV2([...evidence]);
  const prior = histories.get(issuerID);
  if (!prior) {
    histories.set(issuerID, canonical);
    return true;
  }
  return prior.length === canonical.length && prior.every((p, i) => sameStatusEvidenceV2(p, canonical[i]!));
}

function validCurrentStatusEvidenceV2(evidence: readonly StatusEvidenceEntryV2[], issuerID: string): boolean {
  if (evidence.length === 0) return false;
  let baseCount = 0;
  let base: StatusEvidenceEntryV2 | undefined;
  const pushes: StatusEvidenceEntryV2[] = [];
  for (const e of evidence) {
    if (e.issuer_id !== issuerID) return false;
    if (e.object_type_code === 3) {
      baseCount++;
      base = e;
    } else if (e.object_type_code === 5) {
      pushes.push(e);
    } else return false;
  }
  if (baseCount !== 1) return false;
  pushes.sort((a, b) => a.sequence - b.sequence);
  return pushes.every((p, i) => p.status_key_id === base!.status_key_id && p.sequence === base!.sequence + i + 1);
}

/**
 * Requires exactly one reducer result per requested CertificateRef, in order.
 * Authenticated evidence is deduplicated and sorted; malformed rows are
 * excluded and make their result unavailable.
 */
export function aggregateCertificateStatusV2(
  checks: readonly V2CertificateStatusCheck[],
  results: readonly RevocationStatusResultV2[],
  roles: V2StatusRoleBindings,
): V2StatusAssessment {
  if (checks.length === 0 || checks.length !== results.length) {
    throw new Error("v2 status aggregation requires one result for every non-empty certificate list");
  }
  validateV2StatusRoleBindings(roles, checks);
  const assessment: V2StatusAssessment = { assessment: "current", reason: "", evidence: [], freshUntil: 0 };
  const seen = new Set<string>();
  const digestBindings = new Map<string, StatusEvidenceEntryV2>();
  const invalidDigests = new Set<string>();
  const issuerIDs: string[] = [];
  const seenCertificates = new Set<string>();
  const issuerSet = new Set<string>();
  const subjectSet = new Set<string>();
  checks.forEach((check, i) => {
    if (check.delegationIndex !== i || !validV2ID(check.issuerID) || !validV2ID(check.subjectID) || check.certID === "") {
      throw new Error(`v2 status check ${i} has an invalid delegation index or CertificateRef`);
    }
    const ref = check.issuerID + "\0" + check.certID;
    if (seenCertificates.has(ref)) throw new Error("v2 status checks contain a duplicate CertificateRef");
    seenCertificates.add(ref);
    subjectSet.add(check.subjectID);
    if (!issuerSet.has(check.issuerID)) {
      issuerSet.add(check.issuerID);
      issuerIDs.push(check.issuerID);
    }
  });
  const statusKeyIssuers = roles.statusKeyIssuers!;
  const currentStatusKeyIDs = roles.currentStatusKeyIDs!;
  const reserved = roles.reservedKeyIDs!;
  let invalidResult = false;
  let anyRevoked = false;
  let anyUnavailable = false;
  let anyStale = false;
  const revokedCandidates: number[] = [];
  const issuerHistory = new Map<string, StatusEvidenceEntryV2[]>();
  checks.forEach((check, i) => {
    const result = results[i]!;
    const evidenceList = result.evidence ?? [];
    let resultValid = true;
    for (const e of evidenceList) {
      if (e.issuer_id !== check.issuerID || !validV2ID(e.status_key_id) || !(e.sequence > 0) || e.sequence > MAX_SAFE ||
          !validV2StatusEvidenceDigest(e.digest) || (e.object_type_code !== 3 && e.object_type_code !== 5)) {
        resultValid = false;
        continue;
      }
      if (issuerSet.has(e.status_key_id) || subjectSet.has(e.status_key_id)) {
        resultValid = false;
        continue;
      }
      if (reserved.has(e.status_key_id) || (statusKeyIssuers.get(e.status_key_id) ?? "") !== e.issuer_id ||
          (result.status !== "revoked" && (currentStatusKeyIDs.get(e.issuer_id) ?? "") !== e.status_key_id)) {
        resultValid = false;
        continue;
      }
      const prior = digestBindings.get(e.digest);
      if (prior && !sameStatusEvidenceV2(prior, e)) invalidDigests.add(e.digest);
      digestBindings.set(e.digest, e);
      const key = evidenceKey(e);
      if (!seen.has(key)) {
        seen.add(key);
        assessment.evidence.push({ ...e });
      }
    }
    switch (result.status) {
      case "not_revoked":
        resultValid = resultValid && (result.reason ?? "") === "" && result.freshUntil > 0 && result.freshUntil <= MAX_SAFE &&
          validCurrentStatusEvidenceV2(evidenceList, check.issuerID);
        if (resultValid) {
          if (assessment.freshUntil === 0 || result.freshUntil < assessment.freshUntil) assessment.freshUntil = result.freshUntil;
          resultValid = addIssuerHistoryV2(issuerHistory, check.issuerID, evidenceList);
        }
        break;
      case "revoked":
        resultValid = resultValid && (result.reason ?? "") === "" && evidenceList.length > 0;
        if (resultValid) revokedCandidates.push(i);
        break;
      case "indeterminate":
        if (result.reason === "unavailable") {
          anyUnavailable = true;
        } else if (result.reason === "stale") {
          resultValid = resultValid && validCurrentStatusEvidenceV2(evidenceList, check.issuerID);
          if (resultValid) resultValid = addIssuerHistoryV2(issuerHistory, check.issuerID, evidenceList);
          anyStale = true;
        } else {
          resultValid = false;
        }
        break;
      default:
        resultValid = false;
    }
    invalidResult = invalidResult || !resultValid;
  });
  if (invalidDigests.size !== 0) {
    assessment.evidence = assessment.evidence.filter((e) => !invalidDigests.has(e.digest));
    invalidResult = true;
  }
  for (const i of revokedCandidates) {
    const ev = results[i]!.evidence ?? [];
    anyRevoked = anyRevoked || (ev.length > 0 && !ev.some((e) => invalidDigests.has(e.digest)));
  }
  assessment.evidence = sortStatusEvidenceV2(assessment.evidence);
  if (anyRevoked) {
    assessment.assessment = "revoked";
    assessment.reason = "delegation_revoked";
  } else if (invalidResult || anyUnavailable) {
    assessment.assessment = "unavailable";
    assessment.reason = "status_unavailable";
  } else if (anyStale) {
    assessment.assessment = "stale";
    assessment.reason = "status_stale";
  } else if (!hasAcceptedStatusHistoryPerIssuerV2(assessment.evidence, sortedUniqueStringsV2(issuerIDs))) {
    assessment.assessment = "unavailable";
    assessment.reason = "status_unavailable";
  }
  if (assessment.assessment !== "current") assessment.freshUntil = 0;
  return assessment;
}
