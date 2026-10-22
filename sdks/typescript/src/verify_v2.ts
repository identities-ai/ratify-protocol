// Protocol v2 live verifier (SPEC-v2 §6; Go verify_v2.go): ordered pre-claim
// preflight, the atomic challenge claim, trust, local authorization,
// authenticated status for every CertificateRef, receiver audience,
// max_rate reservation, and terminal finalization. A committed outcome is
// never an authorization; only releaseV2Decision produces one.

import type { V2AudienceMembership, V2DeferredConstraint } from "./audience_v2.js";
import {
  evaluateProofBundleV2LocalAuthorization,
  interruptV2Evaluation,
  resolveClaimProofBundleV2AfterAudience,
  resolveClaimProofBundleV2AfterRate,
  resolveClaimProofBundleV2AfterStatus,
  tokenAllowHorizonV2,
  v2InterruptedAssessment,
  type V2LocalAuthorizationAssessment,
  type V2LocalAuthorizationOptions,
} from "./authorization_v2.js";
import {
  claimProofBundleV2,
  finalizeClaimProofBundleV2,
  isV2RateAtFinalizationStore,
  terminalDecisionForV2Evaluation,
  tokenStateV2,
  type ClaimStoreV2,
  type V2ChallengeClaim,
  type V2ClaimDisposition,
  type V2RateReservationStore,
} from "./claim_store_v2.js";
import { V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_STATUS_LIFETIME_SECONDS, validateV2FreshnessConfiguration } from "./clock_bounds_v2.js";
import { CONSTRAINT_RECEIVER_AUDIENCE_V2, validISO4217AlphaV2, type ConstraintContextV2 } from "./constraints_v2.js";
import {
  cloneConstraintEvaluatorRefsV2,
  isConstraintEvaluatorRegistryV2,
  validateV2ExtensionContext,
  type ConstraintEvaluatorRegistryV2,
} from "./constraint_evaluator_v2.js";
import type { V2ContextPolicy } from "./context_policy_v2.js";
import { ErrV2RateLimitExceeded, errorIs, v2Classify, v2ErrorClassOf, v2Errorf, wrapError, type V2ErrorClass } from "./errors_v2.js";
import { cloneV2EvaluationProgress, initialV2EvaluationProgress, recordV2ProgressSafely, type V2EvaluationProgress } from "./evaluation_progress_v2.js";
import { MAX_SAFE_INTEGER_V2, canonicalJSONV2, compareStrings, isWellFormedString, utf8Len } from "./json_v2.js";
import { decodeProofBundleV2, equalHybridPublicKeys, keyIDV2, validV2ID, type DelegationCertV2, type ProofBundleV2 } from "./protocol_v2_wire.js";
import { newCommittedV2Outcome, type CommittedV2Outcome } from "./release_v2.js";
import type { SecurityJournalStoreV2 } from "./security_journal_v2.js";
import type { RevocationStatusPolicyV2 } from "./status_state_v2.js";
import { runV2StatusStage, type V2StatusEvidenceBatch, type V2StatusEvidenceRequest, type V2StatusKeyConfig } from "./status_provenance_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES, type HybridPublicKey } from "./types.js";
import { verificationReceiptV2Body, type StatusEvidenceEntryV2, type VerificationReceiptV2 } from "./verification_receipt_v2.js";
import { preflightProofBundleV2Internal, type ExpectedChallengeV2, type V2ReceiverBindingHook } from "./verify_v2_preflight.js";

/** A trust provider's answer for one verified chain (SPEC-v2 §6.1). */
export type V2TrustOutcome = "trusted" | "untrusted" | "unavailable" | "ambiguous";

/**
 * The caller-authenticated trust provider result. rootKey is the complete
 * root key for "trusted"; the verifier recomputes its ID and requires it
 * and the key to equal the chain's terminal issuer, treating a mismatch as
 * ambiguous. Anything other than a matching trusted root or "untrusted" is
 * trust_unavailable.
 */
export interface V2TrustResolution {
  outcome: V2TrustOutcome;
  rootKey?: HybridPublicKey | null;
}

/**
 * The verifier-owned dependencies of the live decision path. claimStore is
 * required. Every callback is selected by authenticated configuration; a
 * callback that throws or rejects is handled fail-closed.
 */
export interface V2VerifyCallbacks {
  /** Pure pre-consumption hook; runs after every built-in pre-claim check. Throw to reject. */
  receiverBinding?: V2ReceiverBindingHook | null;
  claimStore: ClaimStoreV2;
  trust?: ((chain: DelegationCertV2[], signal?: AbortSignal) => Promise<V2TrustResolution> | V2TrustResolution) | null;
  /** Returns a bounded batch of signed status objects for one issuer; never a status result. */
  statusEvidence?: ((req: V2StatusEvidenceRequest, signal?: AbortSignal) => Promise<V2StatusEvidenceBatch>) | null;
  /** The rollback-protected, anchored security journal. Without it every status is unavailable. */
  statusJournal?: SecurityJournalStoreV2 | null;
  audience?: ((deferred: V2DeferredConstraint[], receiverID: string, signal?: AbortSignal) => Promise<V2AudienceMembership[] | null> | V2AudienceMembership[] | null) | null;
  rate?: V2RateReservationStore | null;
}

/**
 * One live verification. contextPolicy null means the verifier explicitly
 * configured no context policy; the result can then never be allow. now is
 * used only for the pre-claim freshness check.
 */
export interface V2VerifyRequest {
  bundle: Uint8Array;
  expected: ExpectedChallengeV2 | null;
  contextPolicy: V2ContextPolicy | null;
  requiredScope: string;
  verifierNamespace: string;
  replayEpoch: number;
  now: number;
  maxChallengeAgeSeconds: number;
  futureSkewSeconds: number;
  context?: ConstraintContextV2;
  /** The configured IANA tzdata release for time_window; must equal TZDB_VERSION_V2. */
  tzdbVersion?: string;
  statusKeys?: ReadonlyMap<string, V2StatusKeyConfig> | null;
  statusPolicy: RevocationStatusPolicyV2;
  /** Caller-authenticated extension evaluator registry; null registers none. */
  constraintEvaluators?: ConstraintEvaluatorRegistryV2 | null;
}

/** Where a verification stopped. */
export type V2VerifyStage = "preflight" | "replay" | "evaluating" | "committed";

/**
 * The result of verifyProofBundleV2. It has no decision field: for
 * "committed", committed is the opaque handoff to releaseV2Decision.
 */
export interface V2VerifyOutcome {
  stage: V2VerifyStage;
  error: Error | null;
  errorClass: V2ErrorClass | "";
  disposition: V2ClaimDisposition | "";
  claim: V2ChallengeClaim | null;
  committed: CommittedV2Outcome | null;
}

/** Options for one verification call. */
export interface V2VerifyOptions {
  /** Cancellation: before the claim nothing is consumed; after it, nothing is committed. */
  signal?: AbortSignal;
}

interface Progress {
  persisted: V2EvaluationProgress;
  trustCompleted: boolean;
}

const aborted = (signal?: AbortSignal): Error | null =>
  signal?.aborted ? (signal.reason instanceof Error ? signal.reason : new Error("v2 verification cancelled")) : null;

/**
 * Runs the live Protocol v2 decision path in the SPEC-v2 §6 order (Go
 * VerifyProofBundleV2). A pre-claim failure returns stage "preflight" with a
 * classified error and invokes no claim, trust, status, audience or rate
 * callback. A committed outcome is never an authorization.
 */
export async function verifyProofBundleV2(req: V2VerifyRequest, cb: V2VerifyCallbacks, opts: V2VerifyOptions = {}): Promise<V2VerifyOutcome> {
  const signal = opts.signal;
  const preflightFailure = (err: unknown): V2VerifyOutcome => {
    const e = v2Classify("configuration_invalid", err instanceof Error ? err : new Error(String(err)));
    return { stage: "preflight", error: e, errorClass: v2ErrorClassOf(e), disposition: "", claim: null, committed: null };
  };
  if (!cb?.claimStore) return preflightFailure(v2Errorf("configuration_invalid", "v2 verification requires a context and claim store"));
  let bundle: ProofBundleV2;
  try {
    bundle = decodeProofBundleV2(req.bundle);
  } catch (err) {
    return preflightFailure(err);
  }
  let preflight;
  try {
    validateV2VerifyConfiguration(req);
    preflight = await preflightProofBundleV2Internal(bundle, req.expected, req.contextPolicy, true, cb.receiverBinding ?? null,
      req.constraintEvaluators ?? null, req.requiredScope, req.verifierNamespace, req.replayEpoch, req.now,
      req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  } catch (err) {
    return preflightFailure(err);
  }
  let claimed;
  try {
    claimed = await claimProofBundleV2(cb.claimStore, bundle, preflight, req.verifierNamespace, req.replayEpoch, req.now, signal);
  } catch (err) {
    return preflightFailure(v2ErrorClassOf(err) === "unclassified" ? v2Classify("claim_store_unavailable", err) : err);
  }
  const { claim, disposition, token } = claimed;
  if (disposition !== "created" || token === null) {
    return { stage: "replay", error: null, errorClass: "", disposition, claim, committed: null };
  }
  // Every evaluating error reaching here is a claim-store, progress-write,
  // or finalization failure unless it already carries a class.
  const evaluating = (err: unknown): V2VerifyOutcome => {
    const e = v2Classify("claim_store_unavailable", err instanceof Error ? err : new Error(String(err)));
    return { stage: "evaluating", error: e, errorClass: v2ErrorClassOf(e), disposition, claim, committed: null };
  };
  const cancelled = (err: Error) => evaluating(v2Classify("evaluation_cancelled", wrapError("v2 evaluation cancelled before commit", err)));
  const state = tokenStateV2(token)!;

  const progress: Progress = { persisted: initialV2EvaluationProgress(), trustCompleted: false };
  const record = async (): Promise<Error | null> => {
    try {
      await recordV2ProgressSafely(cb.claimStore, token, progress.persisted, signal);
      return null;
    } catch (err) {
      const stop = aborted(signal);
      if (stop) return v2Classify("evaluation_cancelled", wrapError("v2 evaluation cancelled before commit", stop));
      return err as Error;
    }
  };
  const authOpts: V2LocalAuthorizationOptions = {
    futureSkewSeconds: req.futureSkewSeconds, requiredScope: req.requiredScope, context: req.context ?? {}, tzdbVersion: req.tzdbVersion ?? "",
    contextPolicy: req.contextPolicy, expectedChallenge: req.expected, claimToken: token,
  };
  const certs = bundle.delegations ?? [];
  if (state.claimTimeValid && certs.length > 0) {
    progress.persisted.trustAssessment = "unavailable"; // resolution started
    const failed = await record();
    if (failed) return evaluating(failed);
    let resolution: V2TrustResolution | null = null;
    let trustErr: unknown = null;
    if (cb.trust) {
      try {
        resolution = await cb.trust(certs.map((c) => c), signal);
      } catch (err) {
        trustErr = err ?? new Error("trust resolver failed");
      }
    }
    if (trustErr !== null) {
      const stop = aborted(signal);
      if (stop) return cancelled(stop);
    }
    const root = certs[certs.length - 1]!;
    let trust = "unavailable";
    if (trustErr === null && resolution) {
      if (resolution.outcome === "trusted" && resolution.rootKey) {
        let rootID = "";
        try {
          rootID = keyIDV2(resolution.rootKey);
        } catch {
          rootID = "";
        }
        if (rootID !== "" && rootID === root.issuer_id && equalHybridPublicKeys(resolution.rootKey, root.issuer_pub_key)) {
          trust = "trusted";
          authOpts.trustedRootID = rootID;
          authOpts.trustedRootKey = resolution.rootKey;
        }
      } else if (resolution.outcome === "untrusted") {
        trust = "untrusted";
      }
    }
    authOpts.trustConfigured = trust !== "unavailable";
    progress.trustCompleted = true;
    progress.persisted.trustAssessment = trust;
  }
  let assessment = await evaluateProofBundleV2LocalAuthorization(bundle, authOpts);
  const claimedAt = state.claimedAt;
  if (progress.trustCompleted) {
    if (progress.persisted.trustAssessment === "trusted" && (assessment.contextAssessment === "bound" || assessment.contextAssessment === "not_required") &&
        assessment.contextPolicyDigest !== null) {
      progress.persisted.contextAssessment = assessment.contextAssessment;
      progress.persisted.contextPolicyDigest = assessment.contextPolicyDigest;
    }
    if (assessment.status === "pending_external_checks") progress.persisted.statusAssessment = "unavailable"; // status started
    const failed = await record();
    if (failed) return evaluating(failed);
  }

  if (assessment.status === "pending_external_checks") {
    const stage = await runV2StatusStage(signal, bundle, assessment.statusChecks, {
      statusKeys: req.statusKeys ?? null, statusPolicy: req.statusPolicy, statusJournal: cb.statusJournal ?? null, statusEvidence: cb.statusEvidence ?? null,
    }, claimedAt);
    if (stage.cancelled !== null && stage.cancelled !== undefined) {
      return cancelled(stage.cancelled instanceof Error ? stage.cancelled : new Error(String(stage.cancelled)));
    }
    progress.persisted.statusAssessment = stage.assessment.assessment;
    progress.persisted.statusEvidence = stage.assessment.evidence.map((e) => ({ ...e }));
    const failed = await record();
    if (failed) return evaluating(failed);
    try {
      assessment = await resolveClaimProofBundleV2AfterStatus(token, () => stage.assessment);
    } catch {
      await interruptV2Evaluation(token);
      assessment = v2InterruptedAssessment("evaluation interrupted after status");
    }
  }
  if (assessment.status === "pending_external_checks" && assessment.deferred.some((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2)) {
    const audienceDeferred = assessment.deferred.filter((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2).map((d) => ({ ...d, canonicalJSON: Uint8Array.from(d.canonicalJSON) }));
    let memberships: V2AudienceMembership[] | null = null;
    if (cb.audience) {
      try {
        memberships = (await cb.audience(audienceDeferred, req.expected?.expectedReceiverID ?? "", signal)) ?? null;
      } catch {
        const stop = aborted(signal);
        if (stop) return cancelled(stop);
        memberships = null;
      }
    }
    try {
      assessment = await resolveClaimProofBundleV2AfterAudience(token, memberships);
    } catch {
      await interruptV2Evaluation(token);
      assessment = v2InterruptedAssessment("evaluation interrupted after audience");
    }
  }
  if (assessment.status === "pending_external_checks") {
    const stop = aborted(signal);
    if (stop) return cancelled(stop);
    try {
      assessment = await resolveClaimProofBundleV2AfterRate(safeV2RateStore(cb.rate ?? null), token, signal);
    } catch {
      const stop2 = aborted(signal);
      if (stop2) return cancelled(stop2);
      await interruptV2Evaluation(token);
      assessment = v2InterruptedAssessment("evaluation interrupted after rate");
    }
  }

  // The store reads T_final inside the finalization compare-and-set and
  // rejects a regressed clock or an allow at or beyond its horizon or the
  // challenge expiry; nothing is then committed (SPEC-v2 §7.2, §7.5).
  for (let attempt = 0; attempt < 2; attempt++) {
    let built;
    try {
      built = buildV2TerminalResult(bundle, assessment, progress, claim, claimedAt);
    } catch (err) {
      return evaluating(err);
    }
    let finalizeErr: unknown = null;
    try {
      await finalizeClaimProofBundleV2(cb.claimStore, token, built.terminal, built.body, signal);
    } catch (err) {
      finalizeErr = err ?? new Error("claim store finalization failed");
    }
    if (finalizeErr === null) {
      const horizon = built.decision === "allow" ? await tokenAllowHorizonV2(token) : 0;
      return { stage: "committed", error: null, errorClass: "", disposition, claim, committed: newCommittedV2Outcome(claim, built.body, horizon) };
    }
    const stop = aborted(signal);
    if (stop) return cancelled(stop);
    if (!errorIs(finalizeErr, ErrV2RateLimitExceeded) || attempt > 0) {
      return evaluating(v2ErrorClassOf(finalizeErr) === "unclassified" ? v2Classify("claim_store_unavailable", finalizeErr) : finalizeErr);
    }
    // A barrier store proved definitive capacity exhaustion and rolled back;
    // the same claim finalizes once as constraint_denied.
    assessment.status = "constraint_denied";
    assessment.reason = "constraint_denied";
    assessment.detail = "signed rate limit has no remaining capacity";
  }
  return evaluating(new Error("v2 terminal finalization did not complete"));
}

/** Out-of-bounds configuration and invalid request context (Go validateV2VerifyConfiguration). */
export function validateV2VerifyConfiguration(req: V2VerifyRequest): void {
  validateV2FreshnessConfiguration(req.now, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  validateV2RequestContext(req.context ?? {});
  if (req.constraintEvaluators !== undefined && req.constraintEvaluators !== null && !isConstraintEvaluatorRegistryV2(req.constraintEvaluators)) {
    throw v2Errorf("configuration_invalid", "v2 constraint evaluator registry was not built by newConstraintEvaluatorRegistryV2");
  }
  validateV2StatusConfiguration(req.statusKeys ?? null, req.statusPolicy);
}

/**
 * The authenticated request context of SPEC-v2 §5.2, checked before claim
 * (Go validateV2RequestContext). Any violation is configuration_invalid.
 */
export function validateV2RequestContext(c: ConstraintContextV2): void {
  const amount = c.requestedAmountMicros ?? 0;
  const currency = c.requestedCurrency ?? "";
  if (c.hasAmount) {
    if (!Number.isSafeInteger(amount) || amount < 0 || amount > MAX_SAFE_INTEGER_V2 || !validISO4217AlphaV2(currency)) {
      throw v2Errorf("configuration_invalid", `v2 request amount must be 0..${MAX_SAFE_INTEGER_V2} micro-units with a three-letter A-Z currency`);
    }
  } else if (amount !== 0 || currency !== "") {
    throw v2Errorf("configuration_invalid", "v2 request amount and currency must be supplied together with has_amount");
  }
  const resourceID = c.requestedResourceID ?? "";
  const path = c.requestedPath ?? "";
  if (c.hasResource) {
    if (!isWellFormedString(resourceID) || !isWellFormedString(path) || utf8Len(resourceID) > MAX_IDENTIFIER_LENGTH_BYTES) {
      throw v2Errorf("configuration_invalid", `v2 requested resource ID and path must be valid UTF-8 and the resource ID at most ${MAX_IDENTIFIER_LENGTH_BYTES} bytes`);
    }
  } else if (resourceID !== "" || path !== "") {
    throw v2Errorf("configuration_invalid", "v2 requested resource ID and path must be supplied with has_resource");
  }
  validateV2ExtensionContext(c);
}

/** Status policy bounds and status-key configuration (Go validateV2StatusConfiguration). */
export function validateV2StatusConfiguration(keys: ReadonlyMap<string, V2StatusKeyConfig> | null, policy: RevocationStatusPolicyV2): void {
  const inRange = (n: number, lo: number, hi: number) => Number.isSafeInteger(n) && n >= lo && n <= hi;
  if (!policy || !inRange(policy.maxListLifetimeSeconds, 1, V2_MAX_STATUS_LIFETIME_SECONDS) ||
      !inRange(policy.maxStatusAgeSeconds, 1, V2_MAX_STATUS_LIFETIME_SECONDS) || !inRange(policy.clockSkewSeconds, 0, V2_MAX_FUTURE_SKEW_SECONDS)) {
    throw v2Errorf("configuration_invalid", `v2 status policy must bound list lifetime and status age to 1..${V2_MAX_STATUS_LIFETIME_SECONDS} seconds and skew to 0..${V2_MAX_FUTURE_SKEW_SECONDS}`);
  }
  for (const [issuerID, config] of keys ?? []) {
    if (!validV2ID(issuerID) || !Number.isSafeInteger(config?.epoch) || config.epoch < 1) {
      throw v2Errorf("configuration_invalid", "v2 status-key configuration has an invalid issuer or epoch");
    }
    try {
      keyIDV2(config.key);
    } catch (err) {
      throw v2Errorf("configuration_invalid", `v2 status-key configuration has an invalid key: ${(err as Error).message}`);
    }
  }
}

/**
 * Maps a terminal assessment to the receipt tuple of SPEC-v2 §5.8 and the
 * §6.7 table and prepares the exact receipt outbox body (Go
 * buildV2TerminalResult). verifiedAt is T_claim.
 */
function buildV2TerminalResult(bundle: ProofBundleV2, a: V2LocalAuthorizationAssessment, progress: Progress, claim: V2ChallengeClaim, verifiedAt: number): { decision: string; terminal: Uint8Array; body: Uint8Array } {
  const decision = terminalDecisionForV2Evaluation(a.status, a.reason);
  if (decision === null) throw new Error(`v2 evaluation did not reach a terminal result: ${a.status}/${a.reason}`);
  let trust = progress.persisted.trustAssessment;
  let statusAssessment = a.statusAssessment === "" ? "not_evaluated" : a.statusAssessment;
  let contextAssessment = a.contextAssessment === "" ? "not_evaluated" : a.contextAssessment;
  let evidence: StatusEvidenceEntryV2[] = a.statusEvidence.map((e) => ({ ...e }));
  if (a.reason === "not_delegated") trust = "not_evaluated";
  if (statusAssessment === "not_evaluated") evidence = [];
  let policyDigest: string | null = null;
  if (contextAssessment !== "not_evaluated" && contextAssessment !== "unbound" && a.contextPolicyDigest !== null) policyDigest = a.contextPolicyDigest;
  if (a.reason === "evaluation_interrupted") {
    const p = cloneV2EvaluationProgress(progress.persisted);
    trust = p.trustAssessment; statusAssessment = p.statusAssessment; contextAssessment = p.contextAssessment;
    policyDigest = p.contextPolicyDigest; evidence = p.statusEvidence;
  }
  const granted = decision === "allow" ? [...new Set(a.effectiveScope)].sort(compareStrings) : [];
  const receipt = {
    version: 2, log_id: "", sequence: 0, verifier_id: bundle.verifier_id, agent_id: bundle.agent_id, human_id: "",
    bundle_hash: claim.bundleHash, issuer_ids: [...claim.issuerIDs], decision, decision_reason: a.reason, identity_status: a.status,
    trust_assessment: trust, status_assessment: statusAssessment, challenge_assessment: "current", context_assessment: contextAssessment,
    context_policy_digest: policyDigest, verified_at: verifiedAt, required_scope: claim.requiredScope, granted_scope: granted,
    status_evidence_digests: evidence, previous_receipt_hash: new Uint8Array(0), signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
    constraint_evaluators: claim.constraintEvaluators.length === 0 ? undefined : cloneConstraintEvaluatorRefsV2(claim.constraintEvaluators),
  } as VerificationReceiptV2;
  let body: Uint8Array;
  try {
    body = verificationReceiptV2Body(receipt);
  } catch (err) {
    throw wrapError("v2 terminal receipt body is inconsistent with the evaluated result", err);
  }
  const terminal = canonicalJSONV2({ decision, decision_reason: a.reason, identity_status: a.status });
  return { decision, terminal, body };
}

function safeV2RateStore(store: V2RateReservationStore | null): V2RateReservationStore | null {
  if (!store || isV2RateAtFinalizationStore(store)) return store;
  return {
    async reserveV2RateBatch(claimID, owner, bundleHash, batch, signal) {
      try {
        await store.reserveV2RateBatch(claimID, owner, bundleHash, batch, signal);
      } catch (err) {
        if (errorIs(err, ErrV2RateLimitExceeded)) throw err;
        throw err ?? new Error("rate store failed");
      }
    },
  };
}
