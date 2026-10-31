// Protocol v2 evaluation progress and lease-expiry recovery (SPEC-v2 §6.7,
// §7.5; Go evaluation_progress_v2.go).

import { validV2Timestamp } from "./clock_bounds_v2.js";
import { claimIDMatchesKeyV2 } from "./challenge_claim_v2.js";
import { cloneConstraintEvaluatorRefsV2 } from "./constraint_evaluator_v2.js";
import { classified, classifiedAsync, v2Classify, v2ErrorClassOf, v2Errorf } from "./errors_v2.js";
import { canonicalJSONV2, compareStrings } from "./json_v2.js";
import { newCommittedV2Outcome, type CommittedV2Outcome } from "./release_v2.js";
import { tokenStateV2, validateV2FinalizationPayload, type ClaimStoreV2, type V2ChallengeClaim, type V2EvaluationToken } from "./claim_store_v2.js";
import { decodeVerificationReceiptBodyV2, validPrefixedDigestV2, verificationReceiptV2Body, type StatusEvidenceEntryV2, type VerificationReceiptV2 } from "./verification_receipt_v2.js";

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
  return classified("malformed", () => {
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
  });
}

const TERMINAL_INTERRUPTED = { decision: "indeterminate", decision_reason: "evaluation_interrupted", identity_status: "authorization_unverified" };

/**
 * Builds the canonical terminal result and receipt outbox body for
 * indeterminate/evaluation_interrupted from the claim's sealed values and
 * progress (Go V2EvaluationInterruptedResult). verifiedAt is T_claim.
 */
export function v2EvaluationInterruptedResult(claim: V2ChallengeClaim, verifiedAt: number, progress: V2EvaluationProgress): { terminalResult: Uint8Array; receiptBody: Uint8Array } {
  return classified("malformed", () => {
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
  });
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
  return classifiedAsync("claim_store_unavailable", async () => {
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
  });
}

/**
 * A terminal claim as the claim store's terminal compare-and-set persisted
 * it: the sealed claim values, the terminal result, the sealed receipt outbox
 * body, and the allow horizon (0 unless the result is an allow).
 */
export interface V2CommittedClaim {
  claim: V2ChallengeClaim;
  terminalResult: Uint8Array;
  receiptBody: Uint8Array;
  allowHorizon: number;
}

/**
 * Loads a terminal claim's persisted record for resumption (SPEC-v2 §7.11).
 * loadV2CommittedClaim answers claim_not_found for a claim the store does not
 * hold, claim_lease_live for a claim still evaluating under a live lease, and
 * claim_lease_lost for a claim still evaluating after its lease expired
 * (lease-expiry recovery runs first).
 */
export interface V2CommittedClaimStore {
  loadV2CommittedClaim(claimID: string, signal?: AbortSignal): Promise<V2CommittedClaim>;
}

/**
 * Returns the handoff of a claim's committed result from the claim store's
 * persisted record (SPEC-v2 §7.11; Go ResumeCommittedClaimV2), for a service
 * whose handoff was lost after the terminal commit, for example by a crash
 * before the verifier returned. It checks the record as the terminal
 * compare-and-set does and never builds or replaces a result; a record that
 * fails a check is claim_store_unavailable. Publication, checkpoint
 * submission and release then proceed as for a returned handoff.
 */
export async function resumeCommittedClaimV2(store: V2CommittedClaimStore, claimID: string, signal?: AbortSignal): Promise<CommittedV2Outcome> {
  return classifiedAsync("claim_store_unavailable", async () => {
    if (!store || !claimID) throw v2Errorf("configuration_invalid", "v2 resumption requires a context, claim store and claim ID");
    let committed: V2CommittedClaim;
    try {
      committed = await store.loadV2CommittedClaim(claimID, signal);
    } catch (err) {
      throw classifyStore(err);
    }
    try {
      validateV2CommittedClaim(committed, claimID);
    } catch (err) {
      throw v2Errorf("claim_store_unavailable", `v2 claim store returned a committed record that fails its checks: ${err instanceof Error ? err.message : String(err)}`);
    }
    return newCommittedV2Outcome(committed.claim, committed.receiptBody, committed.allowHorizon);
  });
}

/**
 * Applies the terminal compare-and-set's checks to a persisted record: the
 * claim ID (§7.3), the finalization payload (§7.5), and the allow horizon
 * (§6.8).
 */
function validateV2CommittedClaim(committed: V2CommittedClaim, claimID: string): void {
  const claim = committed?.claim;
  if (!claim || claim.claimID !== claimID) throw new Error("the record is for a different claim");
  if (!claimIDMatchesKeyV2(claim)) throw new Error("the claim ID does not derive from the claim's replay key");
  validateV2FinalizationPayload(claim, committed.terminalResult, committed.receiptBody);
  const body = decodeVerificationReceiptBodyV2(committed.receiptBody);
  if (body.decision === "allow") {
    if (!validV2Timestamp(committed.allowHorizon) || committed.allowHorizon <= 0) {
      throw new Error("an allow has no allow horizon in the timestamp domain");
    }
  } else if (committed.allowHorizon !== 0) {
    throw new Error("a result that is not an allow has an allow horizon");
  }
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
