// Protocol v2 receiver audience evaluation over caller-authenticated
// membership results, and the max_rate reservation batch. Port of
// audience_v2.go and rate_reservation_v2.go.

import { MAX_SAFE_INTEGER_V2, bytesEqual, compareStrings, gInt, gStringArray, parseJSONV2, type JNode } from "./json_v2.js";
import {
  V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS,
  V2_MAX_FUTURE_SKEW_SECONDS,
  V2_MAX_RATE_WINDOW_SECONDS,
  validV2Timestamp,
} from "./clock_bounds_v2.js";
import {
  CONSTRAINT_RECEIVER_AUDIENCE_V2,
  decodeConstraintNodeV2,
  validateV2ConstraintFields,
  type ConstraintV2,
} from "./constraints_v2.js";
import { constraintCanonicalJSONV2, validV2ID } from "./protocol_v2_wire.js";
import { validPrefixedDigestV2 } from "./verification_receipt_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES } from "./types.js";
import { utf8Len } from "./json_v2.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;

/** A constraint requiring the ordered status, membership or rate stage. */
export interface V2DeferredConstraint {
  delegationIndex: number;
  constraintIndex: number;
  issuerID: string;
  certID: string;
  type: string;
  canonicalJSON: Uint8Array;
}

/**
 * A caller-authenticated, complete membership result for one constrained
 * link. Protocol does not authenticate this input; absence is unavailable,
 * not proof of nonmembership.
 */
export interface V2AudienceMembership {
  delegationIndex: number;
  constraintIndex: number;
  receiverID: string;
  trustDomainIDs: string[];
  issuedAt: number;
  expiresAt: number;
  evidenceDigest: string;
}

export interface V2AudienceAssessment {
  status: string;
  evidenceDigests: string[];
  freshUntil: number;
}

/** Decodes and re-checks one sealed deferred constraint's canonical bytes. */
function sealedConstraint(item: V2DeferredConstraint): { constraint: ConstraintV2; node: JNode } {
  const node = parseJSONV2(item.canonicalJSON);
  validateV2ConstraintFields(node);
  const constraint = decodeConstraintNodeV2(node);
  if (!bytesEqual(constraintCanonicalJSONV2(constraint), item.canonicalJSON)) {
    throw new Error("v2 deferred constraint is not canonical");
  }
  return { constraint, node };
}

/**
 * Evaluates every deferred audience link. A valid nonmatching membership
 * takes precedence over unavailable membership in another link. Only the
 * verifier's authenticated expected receiver is used.
 */
export function evaluateReceiverAudienceV2(
  deferred: readonly V2DeferredConstraint[],
  receiverID: string,
  memberships: readonly V2AudienceMembership[] | null,
  now: number,
  futureSkew: number,
): V2AudienceAssessment {
  if (!receiverID || !validV2Timestamp(now) || !Number.isSafeInteger(futureSkew) || futureSkew < 0 || futureSkew > V2_MAX_FUTURE_SKEW_SECONDS) {
    throw new Error("v2 audience requires a sealed receiver and valid security time");
  }
  const links: { exact: string[]; domains: string[]; delegationIndex: number; constraintIndex: number }[] = [];
  const seenLinks = new Set<string>();
  let maxAge = MAX_SAFE;
  let freshUntil = MAX_SAFE;
  for (const item of deferred) {
    if (item.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2) continue;
    let node: JNode;
    try {
      node = parseJSONV2(item.canonicalJSON);
      validateV2ConstraintFields(node);
    } catch (err) {
      throw new Error(`v2 sealed audience constraint is invalid: ${(err as Error).message}`);
    }
    const key = `${item.delegationIndex}/${item.constraintIndex}`;
    if (item.delegationIndex < 0 || item.constraintIndex < 0 || seenLinks.has(key)) {
      throw new Error("v2 audience constraint has duplicate or invalid position");
    }
    seenLinks.add(key);
    sealedConstraint(item);
    const params = node.k === "obj" ? node.m.get("params") : undefined;
    const p = params && params.k === "obj" ? params.m : new Map<string, JNode>();
    const exact = gStringArray(p.get("exact_receiver_ids"), "exact_receiver_ids") ?? [];
    const domains = gStringArray(p.get("trust_domain_ids"), "trust_domain_ids") ?? [];
    const age = gInt(p.get("max_membership_age_seconds"), "max_membership_age_seconds");
    if (domains.length > 0 && (age <= 0 || age > V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS)) {
      throw new Error(`v2 audience membership age must be 1..${V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS} seconds`);
    }
    if (domains.length > 0 && age < maxAge) maxAge = age;
    links.push({ exact, domains, delegationIndex: item.delegationIndex, constraintIndex: item.constraintIndex });
  }
  if (links.length === 0) throw new Error("v2 audience stage has no audience constraints");
  let denied = false;
  let unavailable = false;
  const evidence: string[] = [];
  for (const link of links) {
    if (link.exact.includes(receiverID)) continue;
    if (link.domains.length === 0) throw new Error("v2 exact-only audience mismatch passed preflight");
    let membership: V2AudienceMembership | null = null;
    for (const candidate of memberships ?? []) {
      if (candidate.delegationIndex === link.delegationIndex && candidate.constraintIndex === link.constraintIndex) {
        if (membership !== null) {
          unavailable = true;
          membership = null;
          break;
        }
        membership = candidate;
      }
    }
    if (membership === null) {
      unavailable = true;
      continue;
    }
    const m = membership;
    if (m.receiverID !== receiverID || !validPrefixedDigestV2(m.evidenceDigest) || !validV2Timestamp(m.issuedAt) ||
        !validV2Timestamp(m.expiresAt) || m.issuedAt >= m.expiresAt || now >= m.expiresAt ||
        (m.issuedAt > now && m.issuedAt - now > futureSkew) || (now >= m.issuedAt && now - m.issuedAt >= maxAge)) {
      unavailable = true;
      continue;
    }
    const seen = new Set<string>();
    let match = false;
    let malformed = false;
    for (const domainID of m.trustDomainIDs ?? []) {
      if (domainID === "" || seen.has(domainID)) {
        malformed = true;
        break;
      }
      seen.add(domainID);
      match = match || link.domains.includes(domainID);
    }
    if (malformed) {
      unavailable = true;
      continue;
    }
    evidence.push(m.evidenceDigest);
    if (!match) {
      denied = true;
    } else {
      if (m.expiresAt < freshUntil) freshUntil = m.expiresAt;
      const ageUntil = m.issuedAt + maxAge;
      if (ageUntil < freshUntil) freshUntil = ageUntil;
    }
  }
  const digests = [...new Set(evidence)].sort(compareStrings);
  if (denied) return { status: "constraint_denied", evidenceDigests: digests, freshUntil: 0 };
  if (unavailable) return { status: "constraint_unverifiable", evidenceDigests: digests, freshUntil: 0 };
  return { status: "passed", evidenceDigests: digests, freshUntil };
}

// ---------------------------------------------------------------------------
// max_rate reservation batch

/** One issuer-scoped rolling-window counter; the smallest signed limit wins. */
export interface V2RateReservation {
  issuerID: string;
  certID: string;
  windowS: number;
  limit: number;
}

/** Derives the deterministic atomic reservation batch from signed max_rate constraints. */
export function buildV2RateReservationBatch(deferred: readonly V2DeferredConstraint[]): V2RateReservation[] {
  const counters = new Map<string, V2RateReservation>();
  const seenPositions = new Set<string>();
  for (const item of deferred) {
    const position = `${item.delegationIndex}/${item.constraintIndex}`;
    if (item.delegationIndex < 0 || item.constraintIndex < 0 || seenPositions.has(position) || !validV2ID(item.issuerID) ||
        item.certID === "" || utf8Len(item.certID) > MAX_IDENTIFIER_LENGTH_BYTES) {
      throw new Error("v2 rate constraint has invalid identity or duplicate position");
    }
    seenPositions.add(position);
    let constraint: ConstraintV2;
    try {
      const node = parseJSONV2(item.canonicalJSON);
      validateV2ConstraintFields(node);
      constraint = decodeConstraintNodeV2(node);
    } catch (err) {
      throw new Error(`v2 rate constraint is invalid: ${(err as Error).message}`);
    }
    if (constraint.type !== item.type) throw new Error("v2 rate constraint has wrong type");
    if (!bytesEqual(constraintCanonicalJSONV2(constraint), item.canonicalJSON)) throw new Error("v2 rate constraint has noncanonical fields");
    if (item.type !== "max_rate" && item.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2) {
      throw new Error("v2 rate batch contains an unexpected deferred constraint type");
    }
    if (item.type === CONSTRAINT_RECEIVER_AUDIENCE_V2) continue;
    const count = constraint.count ?? 0;
    const windowS = constraint.window_s ?? 0;
    if (count <= 0 || count > MAX_SAFE || windowS <= 0 || windowS > V2_MAX_RATE_WINDOW_SECONDS) {
      throw new Error("v2 rate constraint has noncanonical or invalid limits");
    }
    const key = JSON.stringify([item.issuerID, item.certID, windowS]);
    const previous = counters.get(key);
    if (!previous || count < previous.limit) counters.set(key, { issuerID: item.issuerID, certID: item.certID, windowS, limit: count });
  }
  return [...counters.values()].sort((a, b) => {
    if (a.issuerID !== b.issuerID) return compareStrings(a.issuerID, b.issuerID);
    if (a.certID !== b.certID) return compareStrings(a.certID, b.certID);
    return a.windowS - b.windowS;
  });
}
