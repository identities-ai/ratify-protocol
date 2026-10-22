// Shared request/callback builder for the verifier-ordering, lifecycle and
// transaction runners (Go v2BuildVerifyRequest and friends).

import type { V2AudienceMembership } from "../../src/audience_v2.js";
import type { ClaimStoreV2, V2ChallengeClaim, V2ClaimResult, V2RateReservationStore } from "../../src/claim_store_v2.js";
import {
  newConstraintEvaluatorRegistryV2,
  standardAllowedValuesEvaluatorV2,
  standardMaxCountEvaluatorV2,
  type ConstraintEvaluatorFuncV2,
  type ConstraintEvaluatorRegistrationV2,
} from "../../src/constraint_evaluator_v2.js";
import { newV2ContextPolicy } from "../../src/context_policy_v2.js";
import { ErrV2ClaimProofConflict, ErrV2RateLimitExceeded, V2Error } from "../../src/errors_v2.js";
import type { V2EvaluationProgress, V2InterruptedClaim } from "../../src/evaluation_progress_v2.js";
import { decodeRevocationListV2, decodeRevocationPushV2 } from "../../src/protocol_v2_wire.js";
import {
  ErrSecurityJournalConflictV2,
  applyRevocationListToJournalV2,
  applyRevocationPushToJournalV2,
  configureStatusKeyEpochV2,
  type SecurityJournalHeadV2,
  type SecurityJournalStoreV2,
  type SecurityJournalV2,
} from "../../src/security_journal_v2.js";
import type { RevocationStatusPolicyV2 } from "../../src/status_state_v2.js";
import type { V2StatusKeyConfig } from "../../src/status_provenance_v2.js";
import type { HybridPublicKey } from "../../src/types.js";
import { newJournalStoreTestOnly, type JournalStoreTestOnly } from "../../src/v2reference/journal.js";
import { TrustRegistryTestOnly } from "../../src/v2reference/trust_registry.js";
import type { V2RateReservation } from "../../src/audience_v2.js";
import type { V2VerifyCallbacks, V2VerifyRequest, V2TrustResolution } from "../../src/verify_v2.js";
import type { ExpectedChallengeV2 } from "../../src/verify_v2_preflight.js";
import { compareStrings } from "../../src/json_v2.js";
import { type Any, pubOf, unb64 } from "./helpers.js";

export interface Counts {
  receiver_binding: number;
  claim: number;
  trust: number;
  status: number;
  audience: number;
  rate: number;
  finalize: number;
  progress: number;
  evaluator: number;
}

export const zeroCounts = (): Counts => ({ receiver_binding: 0, claim: 0, trust: 0, status: 0, audience: 0, rate: 0, finalize: 0, progress: 0, evaluator: 0 });

export const statusPolicyOf = (p: Any): RevocationStatusPolicyV2 => ({
  maxListLifetimeSeconds: p?.max_list_lifetime_seconds ?? 0,
  maxStatusAgeSeconds: p?.max_status_age_seconds ?? 0,
  clockSkewSeconds: p?.clock_skew_seconds ?? 0,
});

const keyOf = (k: Any): HybridPublicKey => pubOf(k);

/** A single-claim scripted claim store (Go v2ScriptedClaimStore). */
export class ScriptedClaimStore implements ClaimStoreV2 {
  finalBody: Uint8Array | null = null;
  expiresAt = 0;
  progress: V2EvaluationProgress | null = null;
  constructor(readonly mode: string, readonly claimedAt: number, readonly finalizationAt: number, readonly counts: Counts) {}
  async authoritativeTimeV2(): Promise<number> {
    return this.finalizationAt;
  }
  async claimV2(claim: V2ChallengeClaim): Promise<V2ClaimResult> {
    this.counts.claim++;
    this.expiresAt = claim.expiresAt;
    switch (this.mode) {
      case "create":
        return { disposition: "created", claimedAt: this.claimedAt, ownerToken: new Uint8Array(32).fill(7) };
      case "proof_conflict":
        throw ErrV2ClaimProofConflict;
      case "in_progress":
        return { disposition: "in_progress", claimedAt: this.claimedAt, ownerToken: null };
      case "terminal_replay":
        return { disposition: "terminal_replay", claimedAt: this.claimedAt, ownerToken: null };
    }
    throw new Error("scripted claim store unavailable");
  }
  async finalizeV2Claim(_id: string, _owner: Uint8Array, _terminal: Uint8Array, receiptBody: Uint8Array, allowValidUntil: number): Promise<boolean> {
    this.counts.finalize++;
    if (this.finalizationAt < this.claimedAt) throw new V2Error("clock_regressed", "scripted finalization clock regressed");
    if (allowValidUntil > 0 && (this.finalizationAt >= allowValidUntil || this.finalizationAt >= this.expiresAt)) {
      throw new V2Error("allow_horizon_passed", "scripted allow at or beyond its deadline");
    }
    this.finalBody = Uint8Array.from(receiptBody);
    return true;
  }
  async recordV2EvaluationProgress(_id: string, _owner: Uint8Array, progress: V2EvaluationProgress): Promise<void> {
    this.counts.progress++;
    this.progress = progress;
  }
  async loadV2InterruptedClaim(): Promise<V2InterruptedClaim> {
    throw new Error("not used by ordering vectors");
  }
  async recoverInterruptedV2Claim(): Promise<boolean> {
    throw new Error("not used by ordering vectors");
  }
}

/** Go v2ScriptedRateStore. */
export class ScriptedRateStore implements V2RateReservationStore {
  batch: V2RateReservation[] = [];
  constructor(readonly mode: string, readonly counts: Counts) {}
  async reserveV2RateBatch(_claimID: string, _owner: Uint8Array, _bundleHash: string, batch: V2RateReservation[]): Promise<void> {
    this.counts.rate++;
    this.batch = batch.map((r) => ({ ...r }));
    switch (this.mode) {
      case "reserve":
        return;
      case "exceeded":
        throw ErrV2RateLimitExceeded;
      case "panic":
        throw new Error("scripted rate store panic");
    }
    throw new Error("scripted rate store unavailable");
  }
}

/** Go v2ModalJournalStore: the reference journal with scripted failure modes. */
export class ModalJournalStore implements SecurityJournalStoreV2 {
  casCalls = 0;
  constructor(readonly inner: SecurityJournalStoreV2, readonly mode: string) {}
  async load(signal?: AbortSignal): Promise<{ journal: SecurityJournalV2; head: SecurityJournalHeadV2 }> {
    if (this.mode === "load_error") throw new Error("scripted journal load failure");
    const loaded = await this.inner.load(signal);
    if (this.mode === "unanchored") return { journal: loaded.journal, head: { ...loaded.head, digest: "e".repeat(96) } };
    return loaded;
  }
  async compareAndSwap(head: SecurityJournalHeadV2, next: SecurityJournalV2, signal?: AbortSignal): Promise<void> {
    this.casCalls++;
    if (this.mode === "cas_conflict" || (this.mode === "cas_conflict_once" && this.casCalls % 2 === 1)) throw ErrSecurityJournalConflictV2;
    return this.inner.compareAndSwap(head, next, signal);
  }
}

/** Go v2PopulateStatusJournal: status keys in ascending issuer order, then preload. */
export async function populateStatusJournal(store: SecurityJournalStoreV2, inputs: Any): Promise<void> {
  const keys = inputs.status_keys ?? {};
  for (const issuer of Object.keys(keys).sort(compareStrings)) {
    await configureStatusKeyEpochV2(store, issuer, keys[issuer].epoch, keyOf(keys[issuer].public_key));
  }
  const policy = statusPolicyOf(inputs.status_policy);
  for (const p of inputs.journal?.preload ?? []) {
    const key = keys[p.issuer_id];
    const wire = unb64(p.wire_b64);
    if (p.object_type_code === 3) {
      await applyRevocationListToJournalV2(store, decodeRevocationListV2(wire), p.issuer_id, key.epoch, keyOf(key.public_key), policy, p.now);
    } else {
      await applyRevocationPushToJournalV2(store, decodeRevocationPushV2(wire), p.issuer_id, key.epoch, keyOf(key.public_key), policy, p.now);
    }
  }
}

export async function buildStatusJournal(inputs: Any): Promise<JournalStoreTestOnly> {
  const store = await newJournalStoreTestOnly();
  await populateStatusJournal(store, inputs);
  return store;
}

export function expectedChallengeOf(e: Any): ExpectedChallengeV2 | null {
  if (!e) return null;
  const exp: ExpectedChallengeV2 = {
    value: unb64(e.value_b64), issuedAt: e.issued_at, expiresAt: e.expires_at, verifierNamespace: e.verifier_namespace,
    replayEpoch: e.replay_epoch, verifierID: e.verifier_id,
  };
  if (e.expected_agent_id !== null && e.expected_agent_id !== undefined) {
    exp.expectedAgentID = e.expected_agent_id;
    exp.expectedAgentPublicKey = e.expected_agent_public_key ? keyOf(e.expected_agent_public_key) : null;
  }
  if (e.expected_receiver_id !== null && e.expected_receiver_id !== undefined) exp.expectedReceiverID = e.expected_receiver_id;
  if (e.expected_session_context_b64 !== null && e.expected_session_context_b64 !== undefined) exp.expectedSessionContext = unb64(e.expected_session_context_b64);
  return exp;
}

function evaluatorRegistry(inputs: Any, counts: Counts) {
  const standard: Record<string, ConstraintEvaluatorFuncV2> = {
    "com.ratifyprotocol.max_count/v1": standardMaxCountEvaluatorV2().evaluate,
    "com.ratifyprotocol.allowed_values/v1": standardAllowedValuesEvaluatorV2().evaluate,
  };
  const registrations: ConstraintEvaluatorRegistrationV2[] = [];
  for (const e of inputs.constraint_evaluators) {
    let impl: ConstraintEvaluatorFuncV2;
    switch (e.implementation) {
      case "fault:error":
        impl = () => {
          throw new Error("scripted evaluator failure");
        };
        break;
      case "fault:panic":
        impl = () => {
          throw new TypeError("scripted evaluator panic");
        };
        break;
      case "fault:timeout":
        impl = (_input, signal) => new Promise((resolve) => signal.addEventListener("abort", () => resolve({ outcome: "pass" }), { once: true }));
        break;
      case "fault:invalid_outcome":
        impl = () => ({ outcome: "maybe" as never });
        break;
      case "fault:pass_until":
        impl = () => ({ outcome: "pass", validUntil: e.valid_until });
        break;
      default: {
        const s = standard[e.implementation];
        if (!s) throw new Error(`unknown evaluator implementation ${e.implementation}`);
        impl = s;
      }
    }
    const inner = impl;
    registrations.push({
      descriptor: { profile: e.profile, type: e.type },
      evaluate: (input, signal) => {
        counts.evaluator++;
        return inner(input, signal);
      },
    });
  }
  return newConstraintEvaluatorRegistryV2(1000, ...registrations);
}

/** Go v2BuildVerifyRequest. The claim store is supplied by the caller. */
export async function buildVerifyRequest(inputs: Any, bundle: Uint8Array, counts: Counts): Promise<{ req: V2VerifyRequest; cb: Omit<V2VerifyCallbacks, "claimStore">; rate: ScriptedRateStore | null }> {
  const statusKeys = new Map<string, V2StatusKeyConfig>();
  for (const [issuer, key] of Object.entries<Any>(inputs.status_keys ?? {})) statusKeys.set(issuer, { epoch: key.epoch, key: keyOf(key.public_key) });
  let contextPolicy = null;
  if (inputs.context_policy) {
    const p = inputs.context_policy;
    contextPolicy = newV2ContextPolicy(p.profile, p.require_bound, p.required_fields, p.expected_session_context_b64 ? unb64(p.expected_session_context_b64) : null);
  }
  const req: V2VerifyRequest = {
    bundle, expected: expectedChallengeOf(inputs.expected_challenge), contextPolicy, requiredScope: inputs.required_scope,
    verifierNamespace: inputs.configured_namespace, replayEpoch: inputs.configured_replay_epoch, now: inputs.now,
    maxChallengeAgeSeconds: inputs.max_challenge_age_seconds, futureSkewSeconds: inputs.future_skew_seconds,
    statusPolicy: statusPolicyOf(inputs.status_policy), statusKeys, tzdbVersion: inputs.tzdb_version ?? "",
  };
  const c = inputs.request_context;
  if (c) {
    req.context = {
      hasResource: c.has_resource ?? false, requestedResourceID: c.requested_resource_id ?? "", requestedPath: c.requested_path ?? "",
      hasAmount: c.has_amount ?? false, requestedAmountMicros: c.requested_amount_micros ?? 0, requestedCurrency: c.requested_currency ?? "",
      extensionCounts: c.extension_counts ? new Map(Object.entries<number>(c.extension_counts)) : null,
      extensionValues: c.extension_values ? new Map(Object.entries<string>(c.extension_values)) : null,
    };
  }
  if ((inputs.constraint_evaluators ?? []).length !== 0) req.constraintEvaluators = evaluatorRegistry(inputs, counts);
  const registry = inputs.trust?.mode === "registry" ? new TrustRegistryTestOnly((inputs.trust.registry ?? []).map(keyOf)) : null;
  const cb: Omit<V2VerifyCallbacks, "claimStore"> = {
    trust: async (chain): Promise<V2TrustResolution> => {
      counts.trust++;
      if (!inputs.trust) return { outcome: "unavailable" };
      if (registry) return registry.resolve(chain);
      if (inputs.trust.mode === "error") throw new Error("scripted trust provider failure");
      if (inputs.trust.mode === "panic") throw new TypeError("scripted trust provider panic");
      return { outcome: inputs.trust.outcome, rootKey: inputs.trust.root_public_key ? keyOf(inputs.trust.root_public_key) : null };
    },
    statusEvidence: async (r) => {
      counts.status++;
      const script = (inputs.status_evidence ?? {})[r.issuerID];
      if (!script) return { objects: [] };
      if (script.mode === "error") throw new Error("scripted status provider failure");
      if (script.mode === "panic") throw new TypeError("scripted status provider panic");
      return { objects: (script.objects ?? []).map((o: Any) => ({ objectType: o.object_type_code, wire: unb64(o.wire_b64) })) };
    },
    audience: async (): Promise<V2AudienceMembership[]> => {
      counts.audience++;
      if (inputs.audience_mode === "error") throw new Error("scripted audience provider failure");
      if (inputs.audience_mode === "panic") throw new TypeError("scripted audience provider panic");
      return (inputs.audience_memberships ?? []).map((m: Any) => ({
        delegationIndex: m.delegation_index, constraintIndex: m.constraint_index, receiverID: m.receiver_id, trustDomainIDs: m.trust_domain_ids ?? [],
        issuedAt: m.issued_at, expiresAt: m.expires_at, evidenceDigest: m.evidence_digest,
      }));
    },
  };
  if (inputs.journal?.mode !== "absent") cb.statusJournal = new ModalJournalStore(await buildStatusJournal(inputs), inputs.journal?.mode ?? "anchored");
  if (inputs.receiver_binding_hook === "accept" || inputs.receiver_binding_hook === "reject") {
    cb.receiverBinding = () => {
      counts.receiver_binding++;
      if (inputs.receiver_binding_hook === "reject") throw new Error("application receiver binding rejected");
    };
  }
  let rate: ScriptedRateStore | null = null;
  if (inputs.rate && inputs.rate !== "absent") {
    rate = new ScriptedRateStore(inputs.rate, counts);
    cb.rate = rate;
  }
  return { req, cb, rate };
}
