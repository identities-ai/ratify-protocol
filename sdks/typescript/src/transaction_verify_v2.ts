// Composed transaction-receipt verification (SPEC-v2 §5.7; Go
// transaction_verify_v2.go). The result is evidence about signed authority,
// never an authorization decision: actionable is always false.

import { FRESHNESS_UNVERIFIED_V2 } from "./archival_v2.js";
import { V2_MAX_DELEGATION_LIFETIME_SECONDS, V2_MAX_FUTURE_SKEW_SECONDS, V2_MAX_TIMESTAMP_SECONDS, checkedAddV2, validV2Timestamp } from "./clock_bounds_v2.js";
import { keyIDV2 } from "./crypto_v2.js";
import { v2Errorf } from "./errors_v2.js";
import { equalHybridPublicKeys, type DelegationCertV2 } from "./protocol_v2_wire.js";
import { SCOPE_IDENTITY_DELEGATE_V2, intersectScopesV2, validateScopesV2 } from "./scope_v2.js";
import type { SecurityJournalStoreV2 } from "./security_journal_v2.js";
import type { V2CertificateStatusCheck } from "./status_evaluation_v2.js";
import { runV2StatusStage, type V2StatusEvidenceBatch, type V2StatusEvidenceRequest, type V2StatusKeyConfig } from "./status_provenance_v2.js";
import type { RevocationStatusPolicyV2 } from "./status_state_v2.js";
import { decodeTransactionReceiptV2, type TransactionReceiptPartyV2 } from "./transaction_receipt_v2.js";
import type { StatusEvidenceEntryV2 } from "./verification_receipt_v2.js";
import { validateV2StatusConfiguration, type V2TrustResolution } from "./verify_v2.js";

/**
 * Caller-authenticated trust and status sources, with the same shapes as the
 * live verifier's. A missing trust provider means trust is unavailable; a
 * missing status source makes that issuer's status unavailable.
 */
export interface TransactionVerifySourcesV2 {
  trust?: ((chain: DelegationCertV2[], signal?: AbortSignal) => Promise<V2TrustResolution> | V2TrustResolution) | null;
  statusEvidence?: ((req: V2StatusEvidenceRequest, signal?: AbortSignal) => Promise<V2StatusEvidenceBatch>) | null;
  statusJournal?: SecurityJournalStoreV2 | null;
  statusKeys?: ReadonlyMap<string, V2StatusKeyConfig> | null;
  statusPolicy: RevocationStatusPolicyV2;
}

/** One composed check: now is the authoritative evaluation time. */
export interface TransactionVerifyRequestV2 {
  receipt: Uint8Array;
  now: number;
  futureSkewSeconds: number;
}

/** The per-party evidence of SPEC-v2 §5.7 (wire member names). */
export interface TransactionPartyVerificationV2 {
  party_id: string;
  agent_id: string;
  required_scope: string;
  trust_assessment: "trusted" | "untrusted" | "unavailable";
  delegation_assessment: "current" | "expired" | "invalid" | "not_evaluated";
  delegation_expires_at: number | null;
  status_assessment: string;
  scope_assessment: "covered" | "not_covered" | "invalid_scope" | "delegation_not_authorized" | "not_evaluated";
  freshness: typeof FRESHNESS_UNVERIFIED_V2;
  status_evidence_digests: StatusEvidenceEntryV2[];
}

/** Never an authorization decision: actionable is always false. */
export interface TransactionReceiptVerificationV2 {
  transaction_id: string;
  actionable: false;
  parties: TransactionPartyVerificationV2[];
}

/**
 * Verifies the complete receipt (structure, every party signature, bundle
 * hash and signature, party binding, transaction context), then evaluates
 * each party in party_id order: trust, delegation validity at now, status
 * of every chain CertificateRef through the evidence path, and effective
 * scope (Go VerifyTransactionReceiptV2). It never claims a challenge.
 */
export async function verifyTransactionReceiptV2(req: TransactionVerifyRequestV2, sources: TransactionVerifySourcesV2, signal?: AbortSignal): Promise<TransactionReceiptVerificationV2> {
  if (!validV2Timestamp(req.now)) throw v2Errorf("configuration_invalid", `transaction verification time is outside 0..${V2_MAX_TIMESTAMP_SECONDS}`);
  if (!Number.isSafeInteger(req.futureSkewSeconds) || req.futureSkewSeconds < 0 || req.futureSkewSeconds > V2_MAX_FUTURE_SKEW_SECONDS) {
    throw v2Errorf("configuration_invalid", `transaction verification future skew must be 0..${V2_MAX_FUTURE_SKEW_SECONDS} seconds`);
  }
  validateV2StatusConfiguration(sources.statusKeys ?? null, sources.statusPolicy);
  const receipt = await decodeTransactionReceiptV2(req.receipt);
  const result: TransactionReceiptVerificationV2 = { transaction_id: receipt.transaction_id, actionable: false, parties: [] };
  for (const party of receipt.parties) {
    if (signal?.aborted) throw signal.reason ?? new Error("cancelled");
    result.parties.push(await verifyTransactionPartyV2(party, req, sources, signal));
  }
  return result;
}

async function verifyTransactionPartyV2(party: TransactionReceiptPartyV2, req: TransactionVerifyRequestV2, sources: TransactionVerifySourcesV2, signal?: AbortSignal): Promise<TransactionPartyVerificationV2> {
  const out: TransactionPartyVerificationV2 = {
    party_id: party.party_id, agent_id: party.agent_id, required_scope: party.required_scope,
    trust_assessment: "unavailable", delegation_assessment: "not_evaluated", delegation_expires_at: null,
    status_assessment: "not_evaluated", scope_assessment: "not_evaluated", freshness: FRESHNESS_UNVERIFIED_V2, status_evidence_digests: [],
  };
  const bundle = party.proof_bundle!;
  const chain = bundle.delegations ?? [];
  const root = chain[chain.length - 1]!; // decoding rejects an empty chain
  if (sources.trust) {
    let resolution: V2TrustResolution | null = null;
    try {
      resolution = await sources.trust([...chain], signal);
    } catch (err) {
      if (signal?.aborted) throw signal.reason ?? err;
      resolution = null;
    }
    if (resolution?.outcome === "trusted" && resolution.rootKey) {
      let rootID = "";
      try {
        rootID = keyIDV2(resolution.rootKey);
      } catch {
        rootID = "";
      }
      if (rootID !== "" && rootID === root.issuer_id && equalHybridPublicKeys(resolution.rootKey, root.issuer_pub_key)) out.trust_assessment = "trusted";
    } else if (resolution?.outcome === "untrusted") {
      out.trust_assessment = "untrusted";
    }
  }
  if (out.trust_assessment !== "trusted") return out;

  out.delegation_assessment = "current";
  let earliest = chain[0]!.expires_at;
  for (const cert of chain) {
    earliest = Math.min(earliest, cert.expires_at);
    const latestIssue = checkedAddV2(req.now, req.futureSkewSeconds);
    if (latestIssue === null || cert.issued_at >= cert.expires_at || cert.expires_at - cert.issued_at > V2_MAX_DELEGATION_LIFETIME_SECONDS || cert.issued_at > latestIssue) {
      out.delegation_assessment = "invalid";
    } else if (req.now >= cert.expires_at && out.delegation_assessment === "current") {
      out.delegation_assessment = "expired";
    }
  }
  out.delegation_expires_at = earliest;

  const checks: V2CertificateStatusCheck[] = chain.map((cert, i) => ({ delegationIndex: i, issuerID: cert.issuer_id, subjectID: cert.subject_id, certID: cert.cert_id }));
  const stage = await runV2StatusStage(signal, bundle, checks, {
    statusKeys: sources.statusKeys ?? null, statusPolicy: sources.statusPolicy, statusJournal: sources.statusJournal ?? null, statusEvidence: sources.statusEvidence ?? null,
  }, req.now);
  if (stage.cancelled !== null && stage.cancelled !== undefined) throw stage.cancelled;
  out.status_assessment = stage.assessment.assessment;
  out.status_evidence_digests = stage.assessment.evidence.map((e) => ({ ...e }));

  out.scope_assessment = "covered";
  for (const cert of chain) {
    if (validateScopesV2(cert.scope) !== null) {
      out.scope_assessment = "invalid_scope";
      return out;
    }
  }
  for (let i = 0; i + 1 < chain.length; i++) {
    if (!(chain[i + 1]!.scope ?? []).includes(SCOPE_IDENTITY_DELEGATE_V2)) {
      out.scope_assessment = "delegation_not_authorized";
      return out;
    }
  }
  if (!intersectScopesV2(chain.map((c) => c.scope ?? [])).includes(party.required_scope)) out.scope_assessment = "not_covered";
  return out;
}
