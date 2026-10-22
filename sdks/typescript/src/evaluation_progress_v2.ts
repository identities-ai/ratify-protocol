// Protocol v2 evaluation progress and lease-expiry recovery (SPEC-v2 §6.7,
// §7.5; Go evaluation_progress_v2.go).

import { validV2Timestamp } from "./clock_bounds_v2.js";
import { cloneConstraintEvaluatorRefsV2 } from "./constraint_evaluator_v2.js";
import { v2Classify, v2ErrorClassOf, v2Errorf } from "./errors_v2.js";
import { canonicalJSONV2, compareStrings } from "./json_v2.js";
import { newCommittedV2Outcome, type CommittedV2Outcome } from "./release_v2.js";
import { tokenStateV2, type ClaimStoreV2, type V2ChallengeClaim, type V2EvaluationToken } from "./claim_store_v2.js";
import { validPrefixedDigestV2, verificationReceiptV2Body, type StatusEvidenceEntryV2, type VerificationReceiptV2 } from "./verification_receipt_v2.js";

/**
 * Per-dimension progress of one claimed evaluation. Its canonical JSON form
 * is {"context_assessment","context_policy_digest","status_assessment",
 * "status_evidence_digests","trust_assessment"}.
 */
export interface V2EvaluationProgress {
  trustAssessment: string;
  statusAssessment: string;
  contextAssessment: string;
  contextPolicyDigest: string | null;
  statusEvidence: StatusEvidenceEntryV2[];
}

/** What a claim store returns to lease-expiry recovery. */
export interface V2InterruptedClaim {
  claim: V2ChallengeClaim;
  claimedAt: number;
  progress: V2EvaluationProgress;
}

/** The progress of a claim on which no post-claim check has started. */
export function initialV2EvaluationProgress(): V2EvaluationProgress {
  return { trustAssessment: "not_evaluated", statusAssessment: "not_evaluated", contextAssessment: "not_evaluated", contextPolicyDigest: null, statusEvidence: [] };
}

export function cloneV2EvaluationProgress(p: V2EvaluationProgress): V2EvaluationProgress {
  return { ...p, statusEvidence: (p.statusEvidence ?? []).map((e) => ({ ...e })) };
}

/** The canonical JSON form of a progress record. */
export function encodeV2EvaluationProgress(p: V2EvaluationProgress): Uint8Array {
  validateV2EvaluationProgress(p);
  return canonicalJSONV2({
    context_assessment: p.contextAssessment, context_policy_digest: p.contextPolicyDigest,
    status_assessment: p.statusAssessment,
    status_evidence_digests: p.statusEvidence.map((e) => ({ digest: e.digest, issuer_id: e.issuer_id, object_type_code: e.object_type_code, sequence: e.sequence, status_key_id: e.status_key_id })),
    trust_assessment: p.trustAssessment,
  });
}

/** Go ValidateV2EvaluationProgress. Throws on a record that violates §7.5. */
export function validateV2EvaluationProgress(p: V2EvaluationProgress): void {
  if (!p || !["not_evaluated", "unavailable", "trusted", "untrusted"].includes(p.trustAssessment)) {
    throw new Error("v2 evaluation progress trust_assessment is invalid");
  }
  if (!["not_evaluated", "unavailable", "current", "revoked", "stale"].includes(p.statusAssessment)) {
    throw new Error("v2 evaluation progress status_assessment is invalid");
  }
  if (!["not_evaluated", "bound", "not_required"].includes(p.contextAssessment)) {
    throw new Error("v2 evaluation progress context_assessment is invalid");
  }
  const digest = p.contextPolicyDigest ?? null;
  if ((p.contextAssessment === "not_evaluated") !== (digest === null) || (digest !== null && !validPrefixedDigestV2(digest))) {
    throw new Error("v2 evaluation progress context_policy_digest does not match context_assessment");
  }
  if (p.trustAssessment !== "trusted" && (p.statusAssessment !== "not_evaluated" || p.contextAssessment !== "not_evaluated")) {
    throw new Error("v2 evaluation progress records status or context without a trusted root");
  }
  if (!Array.isArray(p.statusEvidence) || (p.statusAssessment === "not_evaluated" && p.statusEvidence.length !== 0)) {
    throw new Error("v2 evaluation progress status evidence is inconsistent with status_assessment");
  }
}

const TERMINAL_INTERRUPTED = { decision: "indeterminate", decision_reason: "evaluation_interrupted", identity_status: "authorization_unverified" };

/**
 * Builds the canonical terminal result and receipt outbox body for
 * indeterminate/evaluation_interrupted from the claim's sealed values and
 * progress (Go V2EvaluationInterruptedResult). verifiedAt is T_claim.
 */
export function v2EvaluationInterruptedResult(claim: V2ChallengeClaim, verifiedAt: number, progress: V2EvaluationProgress): { terminalResult: Uint8Array; receiptBody: Uint8Array } {
  if (!validV2Timestamp(verifiedAt)) throw v2Errorf("configuration_invalid", "v2 recovery time is outside the timestamp domain");
  try {
    validateV2EvaluationProgress(progress);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  const p = cloneV2EvaluationProgress(progress);
  const issuers = [...new Set(claim.issuerIDs)].sort(compareStrings);
  const receipt: VerificationReceiptV2 = {
    version: 2, log_id: "", sequence: 0, verifier_id: claim.verifierID, agent_id: claim.agentID, human_id: "",
    bundle_hash: claim.bundleHash, issuer_ids: issuers, decision: "indeterminate", decision_reason: "evaluation_interrupted",
    identity_status: "authorization_unverified", trust_assessment: p.trustAssessment, status_assessment: p.statusAssessment,
    challenge_assessment: "current", context_assessment: p.contextAssessment, context_policy_digest: p.contextPolicyDigest,
    verified_at: verifiedAt, required_scope: claim.requiredScope, granted_scope: [], status_evidence_digests: p.statusEvidence,
    previous_receipt_hash: new Uint8Array(0), signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
    constraint_evaluators: claim.constraintEvaluators.length === 0 ? undefined : cloneConstraintEvaluatorRefsV2(claim.constraintEvaluators),
  } as VerificationReceiptV2;
  let receiptBody: Uint8Array;
  try {
    receiptBody = verificationReceiptV2Body(receipt);
  } catch (err) {
    throw v2Classify("malformed", err);
  }
  return { terminalResult: canonicalJSONV2(TERMINAL_INTERRUPTED), receiptBody };
}

const classifyStore = (err: unknown): Error =>
  v2ErrorClassOf(err) === "unclassified" ? v2Classify("claim_store_unavailable", err) : (err as Error);

/**
 * Lease-expiry recovery (Go RecoverInterruptedClaimV2): loads the sealed
 * claim, T_claim and progress (the store refuses while the lease is live),
 * commits evaluation_interrupted, and returns the committed, non-actionable
 * outcome. An identical repeat returns the same outcome.
 */
export async function recoverInterruptedClaimV2(store: ClaimStoreV2, claimID: string, signal?: AbortSignal): Promise<CommittedV2Outcome> {
  if (!store || !claimID) throw v2Errorf("configuration_invalid", "v2 recovery requires a context, claim store and claim ID");
  let interrupted;
  try {
    interrupted = await store.loadV2InterruptedClaim(claimID, signal);
  } catch (err) {
    throw classifyStore(err);
  }
  if (!interrupted || interrupted.claim?.claimID !== claimID) {
    throw v2Errorf("claim_store_unavailable", "v2 claim store returned a different claim for recovery");
  }
  const { terminalResult, receiptBody } = v2EvaluationInterruptedResult(interrupted.claim, interrupted.claimedAt, interrupted.progress);
  try {
    await store.recoverInterruptedV2Claim(claimID, terminalResult, receiptBody, signal);
  } catch (err) {
    throw classifyStore(err);
  }
  return newCommittedV2Outcome(interrupted.claim, receiptBody, 0);
}

/** @internal Persists progress under the evaluator capability (Go recordV2ProgressSafely). */
export async function recordV2ProgressSafely(store: ClaimStoreV2, token: V2EvaluationToken, progress: V2EvaluationProgress, signal?: AbortSignal): Promise<void> {
  const state = tokenStateV2(token);
  if (!state) throw v2Errorf("claim_store_unavailable", "v2 evaluator capability is unavailable");
  validateV2EvaluationProgress(progress);
  try {
    await store.recordV2EvaluationProgress(state.claimID, Uint8Array.from(state.ownerToken), cloneV2EvaluationProgress(progress), signal);
  } catch (err) {
    throw classifyStore(err);
  }
}
