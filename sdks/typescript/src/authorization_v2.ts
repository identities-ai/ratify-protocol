// Protocol v2 post-claim local authorization and the ordered status,
// audience and rate stages (SPEC-v2 §6.4, §6.7, §6.8; Go authorization_v2.go).

import {
  buildV2RateReservationBatch,
  evaluateReceiverAudienceV2,
  type V2AudienceMembership,
  type V2DeferredConstraint,
} from "./audience_v2.js";
import { challengeClaimDigestV2, protocolClaimIDV2 } from "./challenge_claim_v2.js";
import {
  isV2RateAtFinalizationStore,
  tokenStateV2,
  withTokenLockV2,
  type V2EvaluationToken,
  type V2EvaluationTokenState,
  type V2RateReservationStore,
} from "./claim_store_v2.js";
import { V2_MAX_DELEGATION_LIFETIME_SECONDS, V2_MAX_TIMESTAMP_SECONDS, checkedAddV2, validV2Timestamp } from "./clock_bounds_v2.js";
import {
  CONSTRAINT_MAX_RATE_V2,
  CONSTRAINT_RECEIVER_AUDIENCE_V2,
  CONSTRAINT_TIME_WINDOW_V2,
  ConstraintUnverifiableError,
  UnknownConstraintError,
  evaluateConstraintV2,
  isRegisteredConstraintTypeV2,
  parseHHMMV2,
  type ConstraintContextV2,
} from "./constraints_v2.js";
import { extensionParamsJSONV2, runConstraintEvaluatorV2 } from "./constraint_evaluator_v2.js";
import { evaluateProofBundleV2ContextPolicy, sameV2ContextPolicy, type V2ContextPolicy } from "./context_policy_v2.js";
import { ErrV2RateLimitExceeded, errorIs } from "./errors_v2.js";
import { bytesEqual, compareStrings } from "./json_v2.js";
import { bundleHashV2, constraintCanonicalJSONV2, equalHybridPublicKeys, verifyProofBundleV2Signatures, type ProofBundleV2 } from "./protocol_v2_wire.js";
import { SCOPE_IDENTITY_DELEGATE_V2, intersectScopesV2, validateRequiredScopeV2, validateScopesV2 } from "./scope_v2.js";
import type { V2CertificateStatusCheck, V2StatusAssessment } from "./status_evaluation_v2.js";
import type { HybridPublicKey } from "./types.js";
import { loadV2TimeZone, type V2TimeZone } from "./tzdb_v2.js";
import type { StatusEvidenceEntryV2 } from "./verification_receipt_v2.js";
import { matchesExpectedChallengeV2, type ExpectedChallengeStateV2, type ExpectedChallengeV2 } from "./verify_v2_preflight.js";

export type { V2CertificateStatusCheck, V2DeferredConstraint };

/**
 * Verifier-owned inputs for the deterministic checks that follow a
 * successful claim. There is no caller-supplied evaluation time: every
 * time-sensitive check uses the authoritative claim time sealed in the token.
 */
export interface V2LocalAuthorizationOptions {
  futureSkewSeconds: number;
  requiredScope: string;
  trustedRootID?: string;
  trustedRootKey?: HybridPublicKey | null;
  trustConfigured?: boolean;
  context?: ConstraintContextV2;
  /** The configured IANA tzdata release; must equal TZDB_VERSION_V2. */
  tzdbVersion?: string;
  contextPolicy?: V2ContextPolicy | null;
  expectedChallenge?: ExpectedChallengeV2 | null;
  claimToken: V2EvaluationToken | null;
}

/** A pure local verdict held until every status reference completes. */
export interface V2LocalPolicyFailure {
  status: string;
  reason: string;
  detail: string;
}

/** An intermediate, non-terminal assessment (Go V2LocalAuthorizationAssessment). */
export interface V2LocalAuthorizationAssessment {
  bundleHash: string;
  issuerIDs: string[];
  agentID: string;
  rootID: string;
  requiredScope: string;
  delegationDigest: Uint8Array;
  effectiveScope: string[];
  contextAssessment: string;
  contextPolicyDigest: string | null;
  statusAssessment: string;
  delegationValidUntil: number;
  localTimeValidUntil: number;
  extensionValidUntil: number;
  statusFreshUntil: number;
  audienceFreshUntil: number;
  statusEvidence: StatusEvidenceEntryV2[];
  audienceEvidenceDigests: string[];
  rateStoreUnavailable: boolean;
  rateAdmissionDeferred: boolean;
  statusChecks: V2CertificateStatusCheck[];
  deferred: V2DeferredConstraint[];
  localPolicyFailure: V2LocalPolicyFailure | null;
  status: string;
  reason: string;
  detail: string;
}

export function v2LocalAssessment(status: string, reason: string, scope: string[] | null, detail: string): V2LocalAuthorizationAssessment {
  return {
    bundleHash: "", issuerIDs: [], agentID: "", rootID: "", requiredScope: "", delegationDigest: new Uint8Array(0),
    effectiveScope: scope ?? [], contextAssessment: "not_evaluated", contextPolicyDigest: null, statusAssessment: "",
    delegationValidUntil: 0, localTimeValidUntil: 0, extensionValidUntil: 0, statusFreshUntil: 0, audienceFreshUntil: 0,
    statusEvidence: [], audienceEvidenceDigests: [], rateStoreUnavailable: false, rateAdmissionDeferred: false,
    statusChecks: [], deferred: [], localPolicyFailure: null, status, reason, detail,
  };
}

export const v2InterruptedAssessment = (detail: string) => v2LocalAssessment("authorization_unverified", "evaluation_interrupted", null, detail);

export function cloneV2LocalAuthorizationAssessment(a: V2LocalAuthorizationAssessment): V2LocalAuthorizationAssessment {
  return {
    ...a,
    issuerIDs: [...a.issuerIDs],
    delegationDigest: Uint8Array.from(a.delegationDigest),
    effectiveScope: [...a.effectiveScope],
    statusChecks: a.statusChecks.map((c) => ({ ...c })),
    statusEvidence: a.statusEvidence.map((e) => ({ ...e })),
    audienceEvidenceDigests: [...a.audienceEvidenceDigests],
    deferred: a.deferred.map((d) => ({ ...d, canonicalJSON: Uint8Array.from(d.canonicalJSON) })),
    localPolicyFailure: a.localPolicyFailure ? { ...a.localPolicyFailure } : null,
  };
}

export function constraintPrecedenceV2(status: string): number {
  switch (status) {
    case "constraint_denied": return 3;
    case "constraint_unknown": return 2;
    case "constraint_unverifiable": return 1;
    default: return 0;
  }
}

function combinableWithAudienceV2(failure: V2LocalPolicyFailure | null, deferred: readonly V2DeferredConstraint[]): boolean {
  if (!failure || (failure.status !== "constraint_unknown" && failure.status !== "constraint_unverifiable")) return false;
  return deferred.some((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2);
}

/** The earliest exclusive allow deadline, clamped to the timestamp domain (Go allowHorizonV2). */
export function allowHorizonV2(a: V2LocalAuthorizationAssessment): number {
  let horizon = Math.min(a.delegationValidUntil, a.statusFreshUntil);
  if (a.audienceFreshUntil > 0) horizon = Math.min(horizon, a.audienceFreshUntil);
  if (a.localTimeValidUntil > 0) horizon = Math.min(horizon, a.localTimeValidUntil);
  if (a.extensionValidUntil > 0) horizon = Math.min(horizon, a.extensionValidUntil);
  return Math.min(horizon, V2_MAX_TIMESTAMP_SECONDS);
}

// Days from civil (proleptic Gregorian), exact integer arithmetic.
function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0;
  const era = Math.floor(y / 400);
  const yoe = y - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

/**
 * Bounds an allow at the end of each currently accepted local minute or the
 * next offset transition, whichever is first (Go localTimeWindowValidUntilV2).
 * Returns 0 when no time_window constraint exists.
 */
export function localTimeWindowValidUntilV2(bundle: ProofBundleV2, tzdbVersion: string, now: number): number {
  let horizon = 0;
  for (const cert of bundle.delegations ?? []) {
    for (const c of cert.constraints ?? []) {
      if (c.type !== CONSTRAINT_TIME_WINDOW_V2) continue;
      const zone = loadV2TimeZone(tzdbVersion, c.tz ?? "");
      const start = parseHHMMV2(c.start ?? "");
      const end = parseHHMMV2(c.end ?? "");
      const { offset } = zone.lookup(now);
      const local = now + offset;
      const localDay = Math.floor(local / 86400);
      const minute = Math.floor((local - localDay * 86400) / 60);
      if ((start <= end && (minute < start || minute > end)) || (start > end && minute < start && minute > end)) {
        throw new Error("time window is no longer current");
      }
      const dayOffset = start > end && minute >= start ? 1 : 0;
      // Local midnight of the evaluation day plus (end + 1) minutes, as UTC
      // wall time, minus the current offset (Go time.Date normalization).
      let until = (localDay + dayOffset) * 86400 + (end + 1) * 60 - offset;
      const change = nextUTCOffsetChangeV2(zone, now);
      if (change !== null && change < until) until = change;
      if (!(until > now)) throw new Error("time window has no valid terminal horizon");
      const contribution = Math.min(until, V2_MAX_TIMESTAMP_SECONDS);
      if (horizon === 0 || contribution < horizon) horizon = contribution;
    }
  }
  return horizon;
}

/**
 * The first instant after now at which the UTC offset of zone differs from its
 * offset at now (SPEC-v2 §5.2; Go nextUTCOffsetChangeV2), or null when the
 * offset never changes again within the timestamp domain. A period bound that
 * keeps the offset (an abbreviation or DST-flag change, or the start of a
 * year plus 365 days reported past a year's last footer transition) is not
 * an offset change, so the search steps past it.
 */
function nextUTCOffsetChangeV2(zone: V2TimeZone, now: number): number | null {
  const { offset } = zone.lookup(now);
  let candidate = now;
  while (candidate <= V2_MAX_TIMESTAMP_SECONDS) {
    let end = zone.lookup(candidate).end;
    if (end === null) return null;
    if (!(end > candidate)) {
      // The leap-year bound can equal the instant it was computed from;
      // resume at the next UTC year, which has no footer transition before it.
      const next = new Date(0);
      next.setUTCFullYear(new Date(candidate * 1000).getUTCFullYear() + 1, 0, 1);
      end = next.getTime() / 1000;
    }
    if (zone.lookup(end).offset !== offset) return end;
    candidate = end;
  }
  return null;
}

function constraintStatusOf(err: unknown): string {
  if (err instanceof ConstraintUnverifiableError) return "constraint_unverifiable";
  if (err instanceof UnknownConstraintError) return "constraint_unknown";
  return "constraint_denied";
}

/** Go evaluateV2LocalConstraints. */
async function evaluateV2LocalConstraints(
  bundle: ProofBundleV2,
  opts: V2LocalAuthorizationOptions,
  sealed: ExpectedChallengeStateV2,
  nowUnix: number,
): Promise<{ deferred: V2DeferredConstraint[]; constraintStatus: string; failures: string[]; extensionHorizon: number }> {
  const deferred: V2DeferredConstraint[] = [];
  let constraintStatus = "";
  const failures: string[] = [];
  let extensionHorizon = 0;
  const certs = bundle.delegations ?? [];
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i]!;
    const constraints = cert.constraints ?? [];
    for (let j = 0; j < constraints.length; j++) {
      const c = constraints[j]!;
      if (c.type === CONSTRAINT_MAX_RATE_V2 || c.type === CONSTRAINT_RECEIVER_AUDIENCE_V2) {
        let encoded: Uint8Array;
        try {
          encoded = constraintCanonicalJSONV2(c);
        } catch (err) {
          if (constraintPrecedenceV2("constraint_unverifiable") > constraintPrecedenceV2(constraintStatus)) constraintStatus = "constraint_unverifiable";
          failures.push(`delegation ${i} constraint ${j} cannot be encoded: ${(err as Error).message}`);
          continue;
        }
        deferred.push({ delegationIndex: i, constraintIndex: j, issuerID: cert.issuer_id, certID: cert.cert_id, type: c.type, canonicalJSON: encoded });
        continue;
      }
      let failure: unknown = null;
      const entry = sealed.evaluators.get(c.type);
      if (entry !== undefined && !isRegisteredConstraintTypeV2(c.type)) {
        let params: Uint8Array | null = null;
        try {
          params = extensionParamsJSONV2(c);
        } catch (err) {
          failure = new ConstraintUnverifiableError(`${c.type} params cannot be encoded: ${(err as Error).message}`);
        }
        if (failure === null) {
          try {
            const horizon = await runConstraintEvaluatorV2(entry, sealed.evaluatorTimeoutMs, {
              type: c.type, paramsJSON: params, delegationIndex: i, constraintIndex: j,
              issuerID: cert.issuer_id, certID: cert.cert_id, context: cloneContext(opts.context ?? {}), evaluationTime: nowUnix,
            });
            if (horizon !== 0 && (extensionHorizon === 0 || horizon < extensionHorizon)) extensionHorizon = horizon;
          } catch (err) {
            failure = err;
          }
        }
      } else {
        try {
          evaluateConstraintV2(c, opts.context ?? {}, opts.tzdbVersion ?? "", nowUnix);
        } catch (err) {
          failure = err;
        }
      }
      if (failure !== null) {
        const status = constraintStatusOf(failure);
        if (constraintStatus === "" || constraintPrecedenceV2(status) > constraintPrecedenceV2(constraintStatus)) constraintStatus = status;
        failures.push(`delegation ${i} constraint ${j}: ${(failure as Error)?.message ?? String(failure)}`);
      }
    }
  }
  return { deferred, constraintStatus, failures, extensionHorizon };
}

function cloneContext(c: ConstraintContextV2): ConstraintContextV2 {
  return {
    ...c,
    extensionCounts: c.extensionCounts ? new Map(c.extensionCounts) : c.extensionCounts,
    extensionValues: c.extensionValues ? new Map(c.extensionValues) : c.extensionValues,
  };
}

function pendingV2LocalAssessment(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions, effective: string[], deferred: V2DeferredConstraint[], failure: V2LocalPolicyFailure | null): V2LocalAuthorizationAssessment {
  const a = v2LocalAssessment("pending_external_checks", "external_checks_required", effective, "local checks recorded; status and deferred authorization checks remain");
  a.agentID = bundle.agent_id;
  a.rootID = opts.trustedRootID ?? "";
  a.requiredScope = opts.requiredScope;
  a.delegationDigest = Uint8Array.from(bundle.delegation_digest);
  a.localPolicyFailure = failure;
  a.statusChecks = (bundle.delegations ?? []).map((cert, i) => ({ delegationIndex: i, issuerID: cert.issuer_id, subjectID: cert.subject_id, certID: cert.cert_id }));
  a.deferred = deferred;
  return a;
}

/**
 * Evaluates trust-root binding, delegation times, effective scope and
 * deterministic constraints (Go EvaluateProofBundleV2LocalAuthorization).
 * Call only after preflight and the atomic claim. No status lookup, rate
 * reservation, or other external call happens here.
 */
export async function evaluateProofBundleV2LocalAuthorization(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions): Promise<V2LocalAuthorizationAssessment> {
  const state = tokenStateV2(opts.claimToken);
  let evaluationStarted = false;
  let assessment: V2LocalAuthorizationAssessment;
  try {
    assessment = await evaluateLocal(bundle, opts, state, () => (evaluationStarted = true));
  } catch (err) {
    assessment = v2InterruptedAssessment(`local authorization failed: ${(err as Error)?.message ?? String(err)}`);
  }
  if (state) {
    assessment.bundleHash = state.expected.bundleHash;
    assessment.issuerIDs = [...state.expected.issuerIDs];
    if (evaluationStarted && assessment.status !== "") {
      await withTokenLockV2(state, () => {
        state.evaluationStatus = assessment.status;
        state.evaluationReason = assessment.reason;
        if (assessment.status === "pending_external_checks") state.pendingAssessment = cloneV2LocalAuthorizationAssessment(assessment);
        state.evaluationComplete = true;
      });
    }
  }
  return assessment;
}

async function evaluateLocal(
  bundle: ProofBundleV2,
  opts: V2LocalAuthorizationOptions,
  tokenState: V2EvaluationTokenState | null,
  markStarted: () => void,
): Promise<V2LocalAuthorizationAssessment> {
  if (!tokenState) {
    return v2LocalAssessment("preflight_binding_mismatch", "claim_required", null, "local authorization requires a successful atomic challenge claim");
  }
  let claimID = "";
  try {
    claimID = protocolClaimIDV2(tokenState.expected.verifierNamespace, tokenState.expected.replayEpoch, tokenState.expected.value);
  } catch {
    claimID = "";
  }
  if (claimID === "" || tokenState.claimID !== claimID || tokenState.proofDigest !== tokenState.expected.bundleHash || tokenState.ownerToken.length !== 32) {
    return v2InterruptedAssessment("local authorization state differs from successful preflight or atomic claim");
  }
  if (tokenState.used) {
    return v2LocalAssessment("evaluation_in_progress", "claim_in_progress", null, "the claim's single evaluation token has already been used");
  }
  tokenState.used = true;
  markStarted();
  if (!tokenState.claimTimeValid) {
    return v2InterruptedAssessment("claim store returned an authoritative claim time outside the authenticated freshness bounds");
  }
  if (opts.expectedChallenge && !matchesExpectedChallengeV2(opts.expectedChallenge, tokenState.expected)) {
    return v2InterruptedAssessment("local authorization challenge state differs from successful preflight or atomic claim");
  }
  const nowUnix = tokenState.claimedAt;
  await withTokenLockV2(tokenState, () => {
    tokenState.evaluatedAt = nowUnix;
  });
  if (opts.requiredScope !== tokenState.requiredScope || opts.futureSkewSeconds !== tokenState.futureSkew) {
    return v2InterruptedAssessment("local authorization state differs from successful preflight or atomic claim");
  }
  if (opts.requiredScope !== tokenState.expected.requiredScope) {
    return v2InterruptedAssessment("required scope differs from the scope validated during preflight");
  }
  let bundleHash = "";
  try {
    bundleHash = bundleHashV2(bundle);
  } catch {
    bundleHash = "";
  }
  if (bundleHash === "" || bundleHash !== tokenState.proofDigest) {
    return v2InterruptedAssessment("proof bundle differs from the bundle validated during preflight");
  }
  if (!bundle || !bytesEqual(bundle.challenge, tokenState.expected.value) || bundle.challenge_at !== tokenState.expected.issuedAt ||
      bundle.verifier_id !== tokenState.expected.verifierID) {
    return v2InterruptedAssessment("proof challenge differs from the challenge validated during preflight");
  }
  const scopeErr = validateRequiredScopeV2(opts.requiredScope);
  if (scopeErr) return v2InterruptedAssessment("required scope changed after successful preflight: " + scopeErr);
  try {
    await verifyProofBundleV2Signatures(bundle);
  } catch {
    return v2InterruptedAssessment("proof signature changed after successful preflight");
  }
  const certs = bundle.delegations ?? [];
  if (certs.length === 0) return v2LocalAssessment("delegation_not_authorized", "not_delegated", null, "proof has no delegation certificates");
  if (!opts.trustConfigured) {
    return v2LocalAssessment("authorization_unverified", "trust_unavailable", null, "caller-authenticated trust configuration is unavailable");
  }
  const root = certs[certs.length - 1]!;
  if ((opts.trustedRootID ?? "") !== root.issuer_id || !equalHybridPublicKeys(opts.trustedRootKey ?? null, root.issuer_pub_key)) {
    return v2LocalAssessment("unauthorized", "unauthorized", null, "delegation chain does not terminate at the configured trust root");
  }
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i]!;
    const latestIssue = checkedAddV2(nowUnix, tokenState.futureSkew);
    if (!validV2Timestamp(cert.issued_at) || !validV2Timestamp(cert.expires_at) || cert.issued_at >= cert.expires_at ||
        cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS || latestIssue === null || cert.issued_at > latestIssue) {
      return v2LocalAssessment("invalid", "proof_invalid", null, `delegation ${i} has invalid time bounds`);
    }
  }
  for (let i = 0; i < certs.length; i++) {
    if (nowUnix >= certs[i]!.expires_at) return v2LocalAssessment("expired", "delegation_expired", null, `delegation ${i} has expired`);
  }
  for (let i = 0; i < certs.length; i++) {
    const err = validateScopesV2(certs[i]!.scope);
    if (err) return v2LocalAssessment("invalid_scope", "invalid_scope", null, `delegation ${i}: ${err}`);
  }
  for (let i = 0; i + 1 < certs.length; i++) {
    if (!(certs[i + 1]!.scope ?? []).includes(SCOPE_IDENTITY_DELEGATE_V2)) {
      return v2LocalAssessment("delegation_not_authorized", "delegation_not_authorized", null, `parent delegation ${i + 1} does not grant "${SCOPE_IDENTITY_DELEGATE_V2}"`);
    }
  }
  const effective = intersectScopesV2(certs.map((c) => c.scope ?? []));
  let localPolicyFailure: V2LocalPolicyFailure | null = null;
  if (!effective.includes(opts.requiredScope)) {
    localPolicyFailure = { status: "scope_denied", reason: "scope_denied", detail: `required scope "${opts.requiredScope}" is not in the effective delegation scope` };
  }
  if (opts.contextPolicy && !sameV2ContextPolicy(opts.contextPolicy, tokenState.expected.contextPolicy)) {
    return v2InterruptedAssessment("context policy differs from the policy sealed during successful preflight");
  }
  const contextAssessment = evaluateProofBundleV2ContextPolicy(bundle, tokenState.expected.contextPolicy);
  if (contextAssessment.status !== "passed" && localPolicyFailure === null) {
    localPolicyFailure = { status: contextAssessment.status, reason: contextAssessment.reason, detail: contextAssessment.detail };
  }
  const local = await evaluateV2LocalConstraints(bundle, opts, tokenState.expected, nowUnix);
  if (local.constraintStatus !== "" && localPolicyFailure === null) {
    localPolicyFailure = { status: local.constraintStatus, reason: local.constraintStatus, detail: [...local.failures].sort(compareStrings).join("; ") };
  }
  const assessment = pendingV2LocalAssessment(bundle, opts, effective, local.deferred, localPolicyFailure);
  assessment.extensionValidUntil = local.extensionHorizon;
  assessment.delegationValidUntil = Math.min(...certs.map((c) => c.expires_at));
  if (localPolicyFailure === null) {
    try {
      assessment.localTimeValidUntil = localTimeWindowValidUntilV2(bundle, opts.tzdbVersion ?? "", nowUnix);
    } catch (err) {
      assessment.localPolicyFailure = { status: "constraint_unverifiable", reason: "constraint_unverifiable", detail: (err as Error).message };
    }
  }
  assessment.contextAssessment = contextAssessment.assessment;
  assessment.contextPolicyDigest = contextAssessment.policyDigest;
  return assessment;
}

/**
 * @internal Completes the ordered post-claim status stage from an
 * authenticated aggregate (Go resolveClaimProofBundleV2AfterStatus). Status
 * reaches a claim only through the evidence path of SPEC-v2 §6.5.
 */
export async function resolveClaimProofBundleV2AfterStatus(
  token: V2EvaluationToken,
  aggregate: (checks: V2CertificateStatusCheck[]) => V2StatusAssessment | Promise<V2StatusAssessment>,
): Promise<V2LocalAuthorizationAssessment> {
  const state = tokenStateV2(token);
  if (!state) throw new Error("v2 claim evaluator capability is required");
  return withTokenLockV2(state, async () => {
    if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || state.pendingAssessment === null) {
      throw new Error("v2 claim does not have a pending status assessment");
    }
    const a = cloneV2LocalAuthorizationAssessment(state.pendingAssessment);
    if (a.bundleHash !== state.expected.bundleHash || a.requiredScope !== state.expected.requiredScope) {
      throw new Error("pending status assessment differs from its claimed proof");
    }
    const aggregated = await aggregate(a.statusChecks);
    a.statusAssessment = aggregated.assessment;
    a.statusFreshUntil = aggregated.freshUntil;
    a.statusEvidence = aggregated.evidence.map((e) => ({ ...e }));
    switch (aggregated.assessment) {
      case "revoked":
        a.status = "revoked"; a.reason = "delegation_revoked"; a.detail = "at least one delegation certificate is revoked";
        break;
      case "unavailable":
        a.status = "authorization_unverified"; a.reason = "status_unavailable"; a.detail = "one or more delegation certificate statuses are unavailable";
        break;
      case "stale":
        a.status = "authorization_unverified"; a.reason = "status_stale"; a.detail = "one or more delegation certificate statuses are stale";
        break;
      case "current":
        if (a.localPolicyFailure !== null && combinableWithAudienceV2(a.localPolicyFailure, a.deferred)) {
          a.deferred = a.deferred.filter((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2);
          a.status = "pending_external_checks"; a.reason = "deferred_policy_checks_required";
          a.detail = "status is current; audience must be aggregated with a pending local constraint result";
          state.pendingAssessment = cloneV2LocalAuthorizationAssessment(a);
          state.evaluationStatus = a.status; state.evaluationReason = a.reason;
          return a;
        } else if (a.localPolicyFailure !== null) {
          a.status = a.localPolicyFailure.status; a.reason = a.localPolicyFailure.reason; a.detail = a.localPolicyFailure.detail;
        } else if (a.deferred.length !== 0) {
          a.status = "pending_external_checks"; a.reason = "deferred_policy_checks_required";
          a.detail = "status is current; deferred audience or rate checks remain";
          state.pendingAssessment = cloneV2LocalAuthorizationAssessment(a);
          state.evaluationStatus = a.status; state.evaluationReason = a.reason;
          return a;
        } else {
          a.status = "authorized_agent"; a.reason = "authorized"; a.detail = "proof, status, and local authorization checks passed";
          state.allowValidUntil = allowHorizonV2(a);
        }
        break;
      default:
        throw new Error("v2 status aggregator returned an unknown assessment");
    }
    state.evaluationStatus = a.status;
    state.evaluationReason = a.reason;
    state.pendingAssessment = null;
    return a;
  });
}

/**
 * Consumes caller-authenticated, complete membership results after every
 * status is current (Go ResolveClaimProofBundleV2AfterAudience). Freshness
 * uses the authoritative claim time sealed in the token.
 */
export async function resolveClaimProofBundleV2AfterAudience(token: V2EvaluationToken, memberships: readonly V2AudienceMembership[] | null): Promise<V2LocalAuthorizationAssessment> {
  const state = tokenStateV2(token);
  if (!state) throw new Error("v2 claim evaluator capability is required");
  return withTokenLockV2(state, () => {
    const pending = state.pendingAssessment;
    if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || pending === null || pending.statusAssessment !== "current" ||
        (pending.localPolicyFailure !== null && !combinableWithAudienceV2(pending.localPolicyFailure, pending.deferred))) {
      throw new Error("v2 claim does not have current status and pending audience checks");
    }
    const a = cloneV2LocalAuthorizationAssessment(pending);
    if (a.bundleHash !== state.expected.bundleHash || a.requiredScope !== state.expected.requiredScope) {
      state.evaluationStatus = "authorization_unverified"; state.evaluationReason = "evaluation_interrupted"; state.pendingAssessment = null;
      throw new Error("pending audience assessment differs from its claimed proof");
    }
    let r;
    try {
      r = evaluateReceiverAudienceV2(a.deferred, state.expected.expectedReceiverID, memberships, state.evaluatedAt, state.futureSkew);
    } catch (err) {
      state.evaluationStatus = "authorization_unverified"; state.evaluationReason = "evaluation_interrupted"; state.pendingAssessment = null;
      throw err;
    }
    a.audienceEvidenceDigests = [...r.evidenceDigests];
    a.audienceFreshUntil = r.freshUntil;
    const local = a.localPolicyFailure;
    if (local !== null) {
      if (r.status === "passed" || constraintPrecedenceV2(local.status) > constraintPrecedenceV2(r.status)) {
        a.status = local.status; a.reason = local.reason; a.detail = local.detail;
      } else {
        a.status = r.status; a.reason = r.status; a.detail = "receiver audience did not authorize this receiver";
      }
      a.deferred = [];
      state.pendingAssessment = null;
    } else if (r.status !== "passed") {
      a.status = r.status; a.reason = r.status; a.detail = "receiver audience did not authorize this receiver";
      state.pendingAssessment = null;
    } else {
      a.deferred = a.deferred.filter((d) => d.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2);
      if (a.deferred.length === 0) {
        a.status = "authorized_agent"; a.reason = "authorized"; a.detail = "proof, status, audience, and local authorization checks passed";
        state.allowValidUntil = allowHorizonV2(a);
        state.pendingAssessment = null;
      } else {
        a.status = "pending_external_checks"; a.reason = "rate_reservation_required"; a.detail = "audience passed; rate reservation remains";
        state.pendingAssessment = cloneV2LocalAuthorizationAssessment(a);
      }
    }
    state.evaluationStatus = a.status;
    state.evaluationReason = a.reason;
    return a;
  });
}

function sameBatch(a: readonly { issuerID: string; certID: string; windowS: number; limit: number }[], b: typeof a): boolean {
  return a.length === b.length && a.every((x, i) => x.issuerID === b[i]!.issuerID && x.certID === b[i]!.certID && x.windowS === b[i]!.windowS && x.limit === b[i]!.limit);
}

/**
 * The final external Protocol constraint stage (Go
 * ResolveClaimProofBundleV2AfterRate). An ambiguous store error never
 * authorizes; claim recovery releases any provisional rows.
 */
export async function resolveClaimProofBundleV2AfterRate(store: V2RateReservationStore | null | undefined, token: V2EvaluationToken, signal?: AbortSignal): Promise<V2LocalAuthorizationAssessment> {
  const state = tokenStateV2(token);
  if (!state) throw new Error("v2 rate evaluation requires context and claim capability");
  if (signal?.aborted) throw signal.reason ?? new Error("cancelled");
  return withTokenLockV2(state, async () => {
    const pending = state.pendingAssessment;
    if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || pending === null || pending.statusAssessment !== "current" || pending.localPolicyFailure !== null) {
      throw new Error("v2 claim does not have current status and pending rate checks");
    }
    const a = cloneV2LocalAuthorizationAssessment(pending);
    if (a.bundleHash !== state.expected.bundleHash || a.requiredScope !== state.expected.requiredScope || state.rateBatch.length === 0) {
      state.evaluationStatus = "authorization_unverified"; state.evaluationReason = "evaluation_interrupted"; state.pendingAssessment = null;
      throw new Error("pending rate assessment differs from its claimed proof");
    }
    if (a.deferred.some((d) => d.type !== CONSTRAINT_MAX_RATE_V2)) throw new Error("audience or unknown checks remain before rate reservation");
    let batch;
    try {
      batch = buildV2RateReservationBatch(a.deferred);
    } catch {
      batch = null;
    }
    if (batch === null || !sameBatch(batch, state.rateBatch)) {
      state.evaluationStatus = "authorization_unverified"; state.evaluationReason = "evaluation_interrupted"; state.pendingAssessment = null;
      throw new Error("pending rate checks differ from sealed signed batch");
    }
    let err: unknown = null;
    if (!store) err = new Error("v2 rate reservation store is unavailable");
    else if (isV2RateAtFinalizationStore(store)) {
      state.rateAtFinalization = true;
      a.rateAdmissionDeferred = true;
    } else {
      try {
        await store.reserveV2RateBatch(state.claimID, Uint8Array.from(state.ownerToken), a.bundleHash, batch.map((r) => ({ ...r })), signal);
      } catch (e) {
        err = e ?? new Error("rate store failed");
      }
    }
    if (err === null) {
      a.status = "authorized_agent"; a.reason = "authorized";
      a.detail = state.rateAtFinalization
        ? "proof, status, and audience passed; rate admission is deferred to durable finalization"
        : "proof, status, audience, and rate checks passed";
      state.allowValidUntil = allowHorizonV2(a);
    } else if (errorIs(err, ErrV2RateLimitExceeded)) {
      a.status = "constraint_denied"; a.reason = "constraint_denied"; a.detail = "signed rate limit has no remaining capacity";
    } else {
      a.status = "constraint_unverifiable"; a.reason = "constraint_unverifiable"; a.detail = "rate reservation could not be verified";
      a.rateStoreUnavailable = true;
    }
    a.deferred = [];
    state.pendingAssessment = null;
    state.evaluationStatus = a.status;
    state.evaluationReason = a.reason;
    return a;
  });
}

/** @internal Turns the claim's evaluation into indeterminate/evaluation_interrupted (Go interruptV2Evaluation). */
export async function interruptV2Evaluation(token: V2EvaluationToken | null): Promise<void> {
  const state = tokenStateV2(token);
  if (!state) return;
  await withTokenLockV2(state, () => {
    state.evaluationStatus = "authorization_unverified";
    state.evaluationReason = "evaluation_interrupted";
    state.allowValidUntil = 0;
    state.rateAtFinalization = false;
    state.pendingAssessment = null;
    state.evaluationComplete = true;
  });
}

/** @internal The exclusive allow deadline sealed for this claim (0 unless allow). */
export async function tokenAllowHorizonV2(token: V2EvaluationToken): Promise<number> {
  const state = tokenStateV2(token);
  if (!state) return 0;
  return withTokenLockV2(state, () => state.allowValidUntil);
}

export { challengeClaimDigestV2 };
