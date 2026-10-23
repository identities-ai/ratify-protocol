// Protocol v2 ordered pre-claim checks (SPEC-v2 §6.2; Go verify_v2_preflight.go).

import { V2_MAX_TIMESTAMP_SECONDS, v2ChallengeTimeCurrent, validV2Timestamp, validateV2FreshnessConfiguration } from "./clock_bounds_v2.js";
import { CONSTRAINT_RECEIVER_AUDIENCE_V2 } from "./constraints_v2.js";
import {
  cloneConstraintEvaluatorRefsV2,
  snapshotConstraintEvaluatorsV2,
  type ConstraintEvaluatorRefV2,
  type ConstraintEvaluatorRegistryV2,
  type RegisteredConstraintEvaluatorV2,
} from "./constraint_evaluator_v2.js";
import { isValidV2ContextPolicy, sameV2ContextPolicy, type V2ContextPolicy } from "./context_policy_v2.js";
import { classifiedAsync, v2Classify, v2Errorf, wrapError } from "./errors_v2.js";
import { MAX_SAFE_INTEGER_V2, bytesEqual, compareStrings } from "./json_v2.js";
import { bundleHashV2, equalHybridPublicKeys, keyIDV2, validV2ID, verifyProofBundleV2Signatures, type ProofBundleV2 } from "./protocol_v2_wire.js";
import { validateRequiredScopeV2 } from "./scope_v2.js";
import type { HybridPublicKey } from "./types.js";
import { validPrefixedDigestV2 } from "./verification_receipt_v2.js";

/**
 * Verifier-authenticated issuance state for one challenge. Values come from
 * the local issuer or an independently authenticated issuer, never from the
 * proof.
 */
export interface ExpectedChallengeV2 {
  value: Uint8Array;
  issuedAt: number;
  expiresAt: number;
  verifierNamespace: string;
  replayEpoch: number;
  verifierID: string;
  /** "" or absent when not configured; configure with expectedAgentPublicKey. */
  expectedAgentID?: string;
  expectedAgentPublicKey?: HybridPublicKey | null;
  /** "" or absent when not configured. */
  expectedReceiverID?: string;
  /** null/absent when not configured. */
  expectedSessionContext?: Uint8Array | null;
  contextPolicy?: V2ContextPolicy | null;
}

/** @internal The sealed preflight state (Go expectedChallengeStateV2). */
export interface ExpectedChallengeStateV2 {
  value: Uint8Array;
  issuedAt: number;
  expiresAt: number;
  verifierNamespace: string;
  replayEpoch: number;
  verifierID: string;
  expectedAgentID: string;
  expectedAgentPublicKey: HybridPublicKey | null;
  expectedReceiverID: string;
  expectedSessionContext: Uint8Array | null;
  requiredScope: string;
  bundleHash: string;
  issuerIDs: string[];
  futureSkew: number;
  maxAge: number;
  contextPolicyDigest: string;
  contextPolicy: V2ContextPolicy | null;
  noContextPolicy: boolean;
  evaluatorRefs: ConstraintEvaluatorRefV2[];
  evaluators: ReadonlyMap<string, RegisteredConstraintEvaluatorV2>;
  evaluatorTimeoutMs: number;
}

const preflightStates = new WeakMap<V2PreflightResult, ExpectedChallengeStateV2>();

/**
 * Seals the authenticated issuance, policy and proof identity for one
 * request. Its state is never exposed or mutated after construction.
 */
export class V2PreflightResult {
  private constructor() {}
  /** @internal */
  static seal(state: ExpectedChallengeStateV2): V2PreflightResult {
    const r = new V2PreflightResult();
    preflightStates.set(r, state);
    return r;
  }
}

/** @internal */
export function preflightStateV2(result: V2PreflightResult | null | undefined): ExpectedChallengeStateV2 | null {
  return result ? (preflightStates.get(result) ?? null) : null;
}

function cloneKey(k: HybridPublicKey): HybridPublicKey {
  return { ed25519: Uint8Array.from(k.ed25519), ml_dsa_65: Uint8Array.from(k.ml_dsa_65) };
}

/** Deep copy of an expected challenge (the policy object is immutable and shared). */
export function cloneExpectedChallengeV2(e: ExpectedChallengeV2): ExpectedChallengeV2 {
  return {
    ...e,
    value: Uint8Array.from(e.value ?? []),
    expectedSessionContext: e.expectedSessionContext ? Uint8Array.from(e.expectedSessionContext) : (e.expectedSessionContext ?? null),
    expectedAgentPublicKey: e.expectedAgentPublicKey ? cloneKey(e.expectedAgentPublicKey) : (e.expectedAgentPublicKey ?? null),
  };
}

/** @internal */
export function cloneExpectedChallengeStateV2(s: ExpectedChallengeStateV2): ExpectedChallengeStateV2 {
  return {
    ...s,
    value: Uint8Array.from(s.value),
    expectedSessionContext: s.expectedSessionContext === null ? null : Uint8Array.from(s.expectedSessionContext),
    expectedAgentPublicKey: s.expectedAgentPublicKey === null ? null : cloneKey(s.expectedAgentPublicKey),
    issuerIDs: [...s.issuerIDs],
    evaluatorRefs: cloneConstraintEvaluatorRefsV2(s.evaluatorRefs),
    evaluators: new Map(s.evaluators),
  };
}

const agentID = (e: ExpectedChallengeV2) => e.expectedAgentID ?? "";
const agentKey = (e: ExpectedChallengeV2) => e.expectedAgentPublicKey ?? null;
const receiverID = (e: ExpectedChallengeV2) => e.expectedReceiverID ?? "";
const sessionCtx = (e: ExpectedChallengeV2) => e.expectedSessionContext ?? null;

/** @internal Go matchesExpectedChallengeV2. */
export function matchesExpectedChallengeV2(expected: ExpectedChallengeV2 | null | undefined, s: ExpectedChallengeStateV2 | null): boolean {
  if (!expected || !s || !bytesEqual(expected.value, s.value) || expected.issuedAt !== s.issuedAt || expected.expiresAt !== s.expiresAt ||
      expected.verifierNamespace !== s.verifierNamespace || expected.replayEpoch !== s.replayEpoch || expected.verifierID !== s.verifierID ||
      agentID(expected) !== s.expectedAgentID || receiverID(expected) !== s.expectedReceiverID ||
      !bytesEqual(sessionCtx(expected), s.expectedSessionContext) ||
      (expected.contextPolicy && !sameV2ContextPolicy(expected.contextPolicy, s.contextPolicy))) {
    return false;
  }
  const k = agentKey(expected);
  if ((k === null) !== (s.expectedAgentPublicKey === null)) return false;
  return k === null || equalHybridPublicKeys(k, s.expectedAgentPublicKey);
}

/** Go checkExactReceiverAudienceV2: exact-only audiences reject before claim. */
export function checkExactReceiverAudienceV2(bundle: ProofBundleV2, receiver: string): void {
  (bundle.delegations ?? []).forEach((cert, i) => {
    for (const c of cert.constraints ?? []) {
      if (c.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2) continue;
      if (receiver === "") throw v2Errorf("receiver_audience_required", "v2 receiver audience requires an authenticated expected receiver ID");
      const params = (c.params ?? {}) as Record<string, unknown>;
      const exact = Array.isArray(params.exact_receiver_ids) ? params.exact_receiver_ids : [];
      const domains = Array.isArray(params.trust_domain_ids) ? params.trust_domain_ids : [];
      const matches = exact.some((v) => typeof v === "string" && v === receiver);
      if (domains.length === 0 && !matches) {
        throw v2Errorf("receiver_audience_mismatch", `v2 receiver does not match exact-only audience at delegation ${i}`);
      }
    }
  });
}

/**
 * Pure pre-claim checks before a caller may consume challenge or stream
 * state (Go ValidateProofBundleV2Preflight): required scope, proof
 * structure and signatures, then challenge bindings and freshness, agent
 * and session binding, and exact-only receiver audience. No external call
 * and no decision.
 */
export async function validateProofBundleV2Preflight(
  bundle: ProofBundleV2,
  expected: ExpectedChallengeV2,
  requiredScope: string,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
  maxAgeSeconds: number,
  futureSkewSeconds: number,
): Promise<void> {
  return classifiedAsync("configuration_invalid", async () => {
    if (!Number.isSafeInteger(configuredReplayEpoch) || configuredReplayEpoch < 0 || configuredReplayEpoch > MAX_SAFE_INTEGER_V2) {
      throw v2Errorf("configuration_invalid", `v2 configured replay epoch must be 0..${MAX_SAFE_INTEGER_V2}`);
    }
    const policy = expected.contextPolicy ?? null;
    const expectedSession = sessionCtx(expected);
    if (expectedSession !== null && expectedSession.length !== 32) {
      throw v2Errorf("configuration_invalid", "v2 expected session context must be absent or exactly 32 bytes");
    }
    if (policy !== null) {
      if (!isValidV2ContextPolicy(policy) || !validPrefixedDigestV2(policy.digest)) {
        throw v2Errorf("configuration_invalid", "v2 expected context policy is invalid");
      }
      if (policy.requireBound && expectedSession !== null && !bytesEqual(expectedSession, policy.expectedSessionContext)) {
        throw v2Errorf("configuration_invalid", "v2 expected context does not match its policy");
      }
      if (!policy.requireBound && expectedSession !== null) {
        throw v2Errorf("configuration_invalid", "unbound v2 context policy cannot have an expected session context");
      }
    }
    const scopeErr = validateRequiredScopeV2(requiredScope);
    if (scopeErr) throw v2Errorf("invalid_required_scope", `v2 request scope: ${scopeErr}`);
    try {
      await verifyProofBundleV2Signatures(bundle);
    } catch (err) {
      throw wrapError("v2 cryptographic preflight", err);
    }
    if (configuredNamespace === "" || expected.verifierNamespace !== configuredNamespace) {
      throw v2Errorf("namespace_mismatch", "v2 challenge verifier namespace mismatch");
    }
    const epochOK = (n: number) => Number.isSafeInteger(n) && n >= 0 && n <= MAX_SAFE_INTEGER_V2;
    if (!epochOK(configuredReplayEpoch) || !epochOK(expected.replayEpoch) || expected.replayEpoch !== configuredReplayEpoch) {
      throw v2Errorf("stale_replay_epoch", "v2 challenge replay epoch is stale");
    }
    if (!expected.verifierID || expected.verifierID !== bundle.verifier_id || !validV2ID(expected.verifierID)) {
      throw v2Errorf("verifier_id_mismatch", "v2 challenge verifier ID mismatch");
    }
    if (expected.value?.length !== 32 || !bytesEqual(bundle.challenge, expected.value) || bundle.challenge_at !== expected.issuedAt) {
      throw v2Errorf("challenge_mismatch", "v2 proof does not match authenticated challenge issuance");
    }
    if (!validV2Timestamp(expected.issuedAt) || !validV2Timestamp(expected.expiresAt) || expected.expiresAt <= expected.issuedAt) {
      throw v2Errorf("configuration_invalid", `v2 authenticated challenge time bounds are invalid (0..${V2_MAX_TIMESTAMP_SECONDS})`);
    }
    validateV2FreshnessConfiguration(nowUnix, maxAgeSeconds, futureSkewSeconds);
    if (!v2ChallengeTimeCurrent(nowUnix, expected.issuedAt, expected.expiresAt, maxAgeSeconds, futureSkewSeconds)) {
      throw v2Errorf("challenge_not_fresh", "v2 challenge is not fresh (future-dated, expired, or beyond maximum age)");
    }
    const key = agentKey(expected);
    if ((agentID(expected) === "") !== (key === null)) {
      throw v2Errorf("configuration_invalid", "v2 expected agent ID and public key must be configured together");
    }
    if (key !== null) {
      let id: string;
      try {
        id = keyIDV2(key);
      } catch (err) {
        throw v2Errorf("configuration_invalid", `v2 expected agent key: ${(err as Error).message}`, err);
      }
      if (id !== agentID(expected) || bundle.agent_id !== id || !equalHybridPublicKeys(bundle.agent_pub_key, key)) {
        throw v2Errorf("expected_agent_mismatch", "v2 presentation does not match authenticated expected agent");
      }
    }
    if (expectedSession !== null) {
      if (bundle.session_context === null || !bytesEqual(bundle.session_context, expectedSession)) {
        throw v2Errorf("session_context_mismatch", "v2 presentation does not match expected session context");
      }
    }
    checkExactReceiverAudienceV2(bundle, receiverID(expected));
  });
}

/** The application's pure pre-consumption receiver-binding hook. Throw to reject. */
export type V2ReceiverBindingHook = (bundle: ProofBundleV2, expected: ExpectedChallengeV2) => void;

/** @internal Go preflightProofBundleV2: the ordered pre-claim pipeline. */
export async function preflightProofBundleV2Internal(
  bundle: ProofBundleV2,
  expected: ExpectedChallengeV2 | null | undefined,
  policy: V2ContextPolicy | null | undefined,
  allowNoPolicy: boolean,
  hook: V2ReceiverBindingHook | null | undefined,
  evaluators: ConstraintEvaluatorRegistryV2 | null | undefined,
  requiredScope: string,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
  maxAgeSeconds: number,
  futureSkewSeconds: number,
): Promise<V2PreflightResult> {
  if (!expected) throw v2Errorf("expected_challenge_unavailable", "v2 expected challenge is unavailable");
  const pol = policy ?? null;
  if ((pol === null && !allowNoPolicy) || (pol !== null && (!isValidV2ContextPolicy(pol) || !validPrefixedDigestV2(pol.digest)))) {
    throw v2Errorf("configuration_invalid", "v2 context policy is missing or invalid");
  }
  const issued = expected.contextPolicy ?? null;
  if (pol === null && issued !== null) {
    throw v2Errorf("configuration_invalid", "v2 challenge context policy does not match the issued policy");
  }
  const expectedSession = sessionCtx(expected);
  if (pol !== null) {
    if (issued !== null && !sameV2ContextPolicy(issued, pol)) {
      throw v2Errorf("configuration_invalid", "v2 challenge context policy does not match the issued policy");
    }
    if (pol.requireBound) {
      // SPEC-v2 §6.7: an ExpectedChallenge without an expected session
      // context is accepted; the policy's own expected context is compared
      // after claim and a mismatch is a post-claim deny.
      if (expectedSession !== null && !bytesEqual(expectedSession, pol.expectedSessionContext)) {
        throw v2Errorf("configuration_invalid", "v2 challenge context does not match the configured context policy");
      }
    } else if (expectedSession !== null) {
      throw v2Errorf("configuration_invalid", "unbound v2 context policy cannot have an expected session context");
    }
  }
  const checked: ExpectedChallengeV2 = { ...expected, contextPolicy: pol };
  await validateProofBundleV2Preflight(bundle, checked, requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds);
  if (hook) {
    try {
      hook(bundle, cloneExpectedChallengeV2(checked));
    } catch (err) {
      throw v2Errorf("receiver_binding_rejected", `v2 receiver-binding hook rejected the presentation: ${(err as Error)?.message ?? String(err)}`, err);
    }
  }
  let bundleHash: string;
  try {
    bundleHash = bundleHashV2(bundle);
  } catch (err) {
    throw v2Classify("malformed", wrapError("v2 validated bundle hash", err));
  }
  const issuerIDs = [...new Set((bundle.delegations ?? []).map((c) => c.issuer_id))].sort(compareStrings);
  const snapshot = snapshotConstraintEvaluatorsV2(evaluators ?? null, bundle);
  const key = agentKey(expected);
  return V2PreflightResult.seal({
    value: Uint8Array.from(expected.value), issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
    verifierNamespace: expected.verifierNamespace, replayEpoch: expected.replayEpoch, verifierID: expected.verifierID,
    expectedAgentID: agentID(expected), expectedAgentPublicKey: key === null ? null : cloneKey(key),
    expectedReceiverID: receiverID(expected),
    expectedSessionContext: expectedSession === null ? null : Uint8Array.from(expectedSession),
    requiredScope, bundleHash, issuerIDs, maxAge: maxAgeSeconds, futureSkew: futureSkewSeconds,
    contextPolicy: pol, contextPolicyDigest: pol?.digest ?? "", noContextPolicy: pol === null,
    evaluatorRefs: snapshot.refs, evaluators: snapshot.evaluators, evaluatorTimeoutMs: snapshot.timeoutMs,
  });
}

/**
 * Binds the challenge's expected context to the immutable policy used by
 * terminal evaluation (Go PreflightProofBundleV2). It seals no extension
 * evaluator profile; only verifyProofBundleV2 accepts a registry.
 */
export function preflightProofBundleV2(
  bundle: ProofBundleV2,
  expected: ExpectedChallengeV2 | null,
  policy: V2ContextPolicy | null,
  requiredScope: string,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
  maxAgeSeconds: number,
  futureSkewSeconds: number,
): Promise<V2PreflightResult> {
  return classifiedAsync("configuration_invalid", () => preflightProofBundleV2Internal(bundle, expected, policy, false, null, null,
    requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds));
}
