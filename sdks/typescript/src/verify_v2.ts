// Protocol v2 live verifier: ordered pre-claim preflight, the atomic
// challenge claim, post-claim local authorization, status, receiver
// audience and max_rate stages, and terminal finalization (SPEC-v2 §6).
// Port of verify_v2_preflight.go, claim_store_v2.go, authorization_v2.go and
// verify_v2.go.

import { sha256 } from "@noble/hashes/sha2";

import { evaluateConstraints } from "./constraints.js";
import {
  CONSTRAINT_RECEIVER_AUDIENCE_V2,
  bundleHashV2,
  constraintCanonicalJSONV2,
  decodeProofBundleV2,
  equalHybridPublicKeys,
  keyIDV2,
  validV2ID,
  verifyProofBundleV2Signatures,
  type DelegationCertV2,
  type ProofBundleV2,
} from "./protocol_v2_wire.js";
import {
  ErrV2RateLimitExceeded,
  errorIs,
  v2Classify,
  v2ErrorClassOf,
  v2Errorf,
  wrapError,
  type V2ErrorClass,
} from "./errors_v2.js";
import {
  MAX_SAFE_INTEGER_V2,
  bytesEqual,
  canonicalJSONV2,
  compareStrings,
  concatBytes,
  hexOf,
  isValidUTF8,
  parseJSONV2,
  uint64BE,
  utf8,
} from "./json_v2.js";
import { challengeClaimDigestV2, protocolClaimIDV2 } from "./challenge_claim_v2.js";
import { evaluateProofBundleV2ContextPolicy, isValidV2ContextPolicy, sameV2ContextPolicy, type V2ContextPolicy } from "./context_policy_v2.js";
import { buildV2RateReservationBatch, evaluateReceiverAudienceV2, type V2AudienceMembership, type V2DeferredConstraint, type V2RateReservation } from "./audience_v2.js";
import { aggregateCertificateStatusV2, type V2CertificateStatusCheck, type V2StatusRoleBindings } from "./status_evaluation_v2.js";
import type { RevocationStatusResultV2 } from "./status_state_v2.js";
import { intersectScopesV2, validateRequiredScopeV2, validateScopesV2, SCOPE_IDENTITY_DELEGATE_V2 } from "./scope_v2.js";
import { verificationReceiptV2Body, type StatusEvidenceEntryV2, type VerificationReceiptV2 } from "./verification_receipt_v2.js";
import type { HybridPublicKey, VerifierContext } from "./types.js";

const MAX_SAFE = MAX_SAFE_INTEGER_V2;

// ---------------------------------------------------------------------------
// Expected challenge and preflight

/** Verifier-authenticated issuance state for one challenge. */
export interface ExpectedChallengeV2 {
  value: Uint8Array;
  issuedAt: number;
  expiresAt: number;
  verifierNamespace: string;
  replayEpoch: number;
  verifierID: string;
  /** "" when not configured. Configure together with expectedAgentPublicKey. */
  expectedAgentID?: string;
  expectedAgentPublicKey?: HybridPublicKey | null;
  /** "" when not configured. */
  expectedReceiverID?: string;
  /** null/undefined when not configured. */
  expectedSessionContext?: Uint8Array | null;
  contextPolicy?: V2ContextPolicy | null;
}

interface SealedExpectedChallenge {
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
}

const preflightStates = new WeakMap<V2PreflightResult, SealedExpectedChallenge>();

/** Seals authenticated issuance, policy and proof identity for one request. */
export class V2PreflightResult {
  private constructor() {}
  /** @internal */
  static seal(state: SealedExpectedChallenge): V2PreflightResult {
    const r = new V2PreflightResult();
    preflightStates.set(r, state);
    return r;
  }
}

function normalizeExpected(e: ExpectedChallengeV2) {
  return {
    expectedAgentID: e.expectedAgentID ?? "",
    expectedAgentPublicKey: e.expectedAgentPublicKey ?? null,
    expectedReceiverID: e.expectedReceiverID ?? "",
    expectedSessionContext: e.expectedSessionContext ?? null,
    contextPolicy: e.contextPolicy ?? null,
  };
}

function cloneSealed(s: SealedExpectedChallenge): SealedExpectedChallenge {
  // The frozen policy object is immutable and branded; it is shared, not cloned.
  return { ...structuredClone({ ...s, contextPolicy: null }), contextPolicy: s.contextPolicy };
}

function matchesExpectedChallengeV2(expected: ExpectedChallengeV2, s: SealedExpectedChallenge): boolean {
  const e = normalizeExpected(expected);
  if (!bytesEqual(expected.value, s.value) || expected.issuedAt !== s.issuedAt || expected.expiresAt !== s.expiresAt ||
      expected.verifierNamespace !== s.verifierNamespace || expected.replayEpoch !== s.replayEpoch || expected.verifierID !== s.verifierID ||
      e.expectedAgentID !== s.expectedAgentID || e.expectedReceiverID !== s.expectedReceiverID ||
      !bytesEqual(e.expectedSessionContext, s.expectedSessionContext) ||
      (e.contextPolicy !== null && !sameV2ContextPolicy(e.contextPolicy, s.contextPolicy))) {
    return false;
  }
  if ((e.expectedAgentPublicKey === null) !== (s.expectedAgentPublicKey === null)) return false;
  return e.expectedAgentPublicKey === null || equalHybridPublicKeys(e.expectedAgentPublicKey, s.expectedAgentPublicKey);
}

function checkExactReceiverAudienceV2(bundle: ProofBundleV2, receiverID: string): void {
  (bundle.delegations ?? []).forEach((cert, i) => {
    for (const c of cert.constraints ?? []) {
      if (c.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2) continue;
      if (receiverID === "") throw v2Errorf("receiver_audience_required", "v2 receiver audience requires an authenticated expected receiver ID");
      const params = (c.params ?? {}) as Record<string, unknown>;
      const exact = Array.isArray(params.exact_receiver_ids) ? params.exact_receiver_ids : [];
      const domains = Array.isArray(params.trust_domain_ids) ? params.trust_domain_ids : [];
      const matches = exact.some((v) => typeof v === "string" && v === receiverID);
      if (domains.length === 0 && !matches) {
        throw v2Errorf("receiver_audience_mismatch", `v2 receiver does not match exact-only audience at delegation ${i}`);
      }
    }
  });
}

/**
 * Pure pre-claim checks before a caller may consume challenge or stream
 * state: required scope, proof structure and signatures, then challenge
 * bindings and freshness. No external call; no decision.
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
  const e = normalizeExpected(expected);
  if (e.contextPolicy !== null) {
    if (!isValidV2ContextPolicy(e.contextPolicy)) throw v2Errorf("configuration_invalid", "v2 expected context policy is invalid");
    if (e.contextPolicy.requireBound && (!bytesEqual(e.expectedSessionContext, e.contextPolicy.expectedSessionContext) || e.expectedSessionContext?.length !== 32)) {
      throw v2Errorf("configuration_invalid", "v2 expected context does not match its policy");
    }
    if (!e.contextPolicy.requireBound && e.expectedSessionContext !== null) {
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
  if (!(configuredReplayEpoch >= 0) || configuredReplayEpoch > MAX_SAFE || !(expected.replayEpoch >= 0) || expected.replayEpoch > MAX_SAFE ||
      expected.replayEpoch !== configuredReplayEpoch) {
    throw v2Errorf("stale_replay_epoch", "v2 challenge replay epoch is stale");
  }
  if (expected.verifierID === "" || expected.verifierID !== bundle.verifier_id || !validV2ID(expected.verifierID)) {
    throw v2Errorf("verifier_id_mismatch", "v2 challenge verifier ID mismatch");
  }
  if (expected.value?.length !== 32 || !bytesEqual(bundle.challenge, expected.value) || bundle.challenge_at !== expected.issuedAt) {
    throw v2Errorf("challenge_mismatch", "v2 proof does not match authenticated challenge issuance");
  }
  if (expected.issuedAt < -MAX_SAFE || expected.issuedAt > MAX_SAFE || expected.expiresAt < -MAX_SAFE || expected.expiresAt > MAX_SAFE ||
      expected.expiresAt <= expected.issuedAt) {
    throw v2Errorf("configuration_invalid", "v2 authenticated challenge time bounds are invalid");
  }
  if (nowUnix < -MAX_SAFE || nowUnix > MAX_SAFE || !(maxAgeSeconds > 0) || maxAgeSeconds > MAX_SAFE || !(futureSkewSeconds >= 0) || futureSkewSeconds > MAX_SAFE) {
    throw v2Errorf("configuration_invalid", "v2 freshness policy is invalid");
  }
  if (expected.issuedAt > nowUnix && expected.issuedAt - nowUnix > futureSkewSeconds) {
    throw v2Errorf("challenge_not_fresh", "v2 challenge issuance is too far in the future");
  }
  if (nowUnix >= expected.expiresAt) throw v2Errorf("challenge_not_fresh", "v2 challenge is expired");
  if (nowUnix - expected.issuedAt > maxAgeSeconds) throw v2Errorf("challenge_not_fresh", "v2 challenge exceeds maximum age");
  if ((e.expectedAgentID === "") !== (e.expectedAgentPublicKey === null)) {
    throw v2Errorf("configuration_invalid", "v2 expected agent ID and public key must be configured together");
  }
  if (e.expectedAgentPublicKey !== null) {
    let id: string;
    try {
      id = keyIDV2(e.expectedAgentPublicKey);
    } catch (err) {
      throw v2Errorf("configuration_invalid", `v2 expected agent key: ${(err as Error).message}`, err);
    }
    if (id !== e.expectedAgentID || bundle.agent_id !== id || !equalHybridPublicKeys(bundle.agent_pub_key, e.expectedAgentPublicKey)) {
      throw v2Errorf("expected_agent_mismatch", "v2 presentation does not match authenticated expected agent");
    }
  }
  if (e.expectedSessionContext !== null) {
    if (e.expectedSessionContext.length !== 32 || bundle.session_context === null || !bytesEqual(bundle.session_context, e.expectedSessionContext)) {
      throw v2Errorf("session_context_mismatch", "v2 presentation does not match expected session context");
    }
  }
  checkExactReceiverAudienceV2(bundle, e.expectedReceiverID);
}

export type V2ReceiverBindingHook = (bundle: ProofBundleV2, expected: ExpectedChallengeV2) => void;

async function preflightProofBundleV2Internal(
  bundle: ProofBundleV2,
  expected: ExpectedChallengeV2 | null | undefined,
  policy: V2ContextPolicy | null | undefined,
  allowNoPolicy: boolean,
  hook: V2ReceiverBindingHook | undefined,
  requiredScope: string,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
  maxAgeSeconds: number,
  futureSkewSeconds: number,
): Promise<V2PreflightResult> {
  if (!expected) throw v2Errorf("expected_challenge_unavailable", "v2 expected challenge is unavailable");
  const pol = policy ?? null;
  if ((pol === null && !allowNoPolicy) || (pol !== null && !isValidV2ContextPolicy(pol))) {
    throw v2Errorf("configuration_invalid", "v2 context policy is missing or invalid");
  }
  const e = normalizeExpected(expected);
  if (pol === null && e.contextPolicy !== null) {
    throw v2Errorf("configuration_invalid", "v2 challenge context policy does not match the issued policy");
  }
  if (pol !== null) {
    if (e.contextPolicy !== null && !sameV2ContextPolicy(e.contextPolicy, pol)) {
      throw v2Errorf("configuration_invalid", "v2 challenge context policy does not match the issued policy");
    }
    if (pol.requireBound) {
      if (!bytesEqual(e.expectedSessionContext, pol.expectedSessionContext) || e.expectedSessionContext?.length !== 32) {
        throw v2Errorf("configuration_invalid", "v2 challenge context does not match the configured context policy");
      }
    } else if (e.expectedSessionContext !== null) {
      throw v2Errorf("configuration_invalid", "unbound v2 context policy cannot have an expected session context");
    }
  }
  const checked: ExpectedChallengeV2 = { ...expected, contextPolicy: pol };
  await validateProofBundleV2Preflight(bundle, checked, requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds);
  if (hook) {
    try {
      hook(bundle, checked);
    } catch (err) {
      throw v2Errorf("receiver_binding_rejected", `v2 receiver-binding hook rejected the presentation: ${(err as Error)?.message ?? err}`, err);
    }
  }
  let bundleHash: string;
  try {
    bundleHash = bundleHashV2(bundle);
  } catch (err) {
    throw v2Classify("malformed", wrapError("v2 validated bundle hash", err));
  }
  const issuerIDs = [...new Set((bundle.delegations ?? []).map((c) => c.issuer_id))].sort(compareStrings);
  return V2PreflightResult.seal({
    value: Uint8Array.from(expected.value), issuedAt: expected.issuedAt, expiresAt: expected.expiresAt,
    verifierNamespace: expected.verifierNamespace, replayEpoch: expected.replayEpoch, verifierID: expected.verifierID,
    expectedAgentID: e.expectedAgentID,
    expectedAgentPublicKey: e.expectedAgentPublicKey === null ? null : structuredClone(e.expectedAgentPublicKey),
    expectedReceiverID: e.expectedReceiverID,
    expectedSessionContext: e.expectedSessionContext === null ? null : Uint8Array.from(e.expectedSessionContext),
    requiredScope, bundleHash, issuerIDs, maxAge: maxAgeSeconds, futureSkew: futureSkewSeconds,
    contextPolicy: pol, contextPolicyDigest: pol?.digest ?? "", noContextPolicy: pol === null,
  });
}

/**
 * Binds the challenge's expected context to the same immutable policy used
 * by terminal evaluation. A missing or divergent policy cannot consume the
 * challenge before context validation.
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
  return preflightProofBundleV2Internal(bundle, expected, policy, false, undefined, requiredScope, configuredNamespace,
    configuredReplayEpoch, nowUnix, maxAgeSeconds, futureSkewSeconds);
}

// ---------------------------------------------------------------------------
// Claim store boundary

export interface V2ChallengeClaim {
  claimID: string;
  namespace: string;
  replayEpoch: number;
  challengeDigest: string;
  proofDigest: string;
  bundleHash: string;
  issuerIDs: string[];
  requiredScope: string;
  contextPolicyDigest: string;
  verifierID: string;
  agentID: string;
  requiresRate: boolean;
  rateBatch: V2RateReservation[];
  issuedAt: number;
  expiresAt: number;
  maxAgeSeconds: number;
  clockSkewSeconds: number;
  streamID: Uint8Array | null;
  streamSeq: number | null;
}

export type V2ClaimDisposition = "created" | "in_progress" | "terminal_replay";

export interface V2ClaimResult {
  disposition: V2ClaimDisposition;
  /** The store's authoritative claim timestamp. */
  claimedAt: number;
  /** 32 random bytes, returned only to the creating process. */
  ownerToken?: Uint8Array | null;
}

/**
 * Storage boundary for challenge consumption (see Go ClaimStoreV2 for the
 * full atomicity, durability and owner-token contract). A rejected
 * different proof for the same replay key throws ErrV2ClaimProofConflict.
 */
export interface ClaimStoreV2 {
  claimV2(claim: V2ChallengeClaim): Promise<V2ClaimResult>;
  finalizeV2Claim(claimID: string, ownerToken: Uint8Array, terminalResult: Uint8Array, receiptBody: Uint8Array, allowValidUntil: number): Promise<boolean>;
  recoverInterruptedV2Claim(claimID: string, terminalResult: Uint8Array, receiptBody: Uint8Array): Promise<boolean>;
}

/** Atomically reserves the complete claim-sealed rate batch. */
export interface V2RateReservationStore {
  reserveV2RateBatch(claimID: string, ownerToken: Uint8Array, bundleHash: string, batch: V2RateReservation[]): Promise<void>;
}

/**
 * A claim store that admits the sealed rate batch during finalization. Its
 * finalizeV2Claim may throw ErrV2RateLimitExceeded only after definitive
 * rollback.
 */
export interface V2RateAtFinalizationStore extends ClaimStoreV2, V2RateReservationStore {
  admitsV2RateAtFinalization(): void;
}

function isRateAtFinalizationStore(store: unknown): store is V2RateAtFinalizationStore {
  return !!store && typeof (store as V2RateAtFinalizationStore).admitsV2RateAtFinalization === "function" &&
    typeof (store as V2RateAtFinalizationStore).finalizeV2Claim === "function" &&
    typeof (store as V2RateAtFinalizationStore).reserveV2RateBatch === "function";
}

interface TokenState {
  claimID: string;
  proofDigest: string;
  requiredScope: string;
  futureSkew: number;
  expected: SealedExpectedChallenge;
  used: boolean;
  evaluationComplete: boolean;
  finalizationDigest: Uint8Array | null;
  finalizationStarted: boolean;
  claimTimeValid: boolean;
  claimedAt: number;
  evaluatedAt: number;
  rateBatch: V2RateReservation[];
  rateAtFinalization: boolean;
  allowValidUntil: number;
  ownerToken: Uint8Array;
  evaluationStatus: string;
  evaluationReason: string;
  pendingAssessment: V2LocalAuthorizationAssessment | null;
}

const tokenStates = new WeakMap<V2EvaluationToken, TokenState>();

/** Single-use capability for one local evaluation of a newly created claim. */
export class V2EvaluationToken {
  private constructor() {}
  /** @internal */
  static create(state: TokenState): V2EvaluationToken {
    const t = new V2EvaluationToken();
    tokenStates.set(t, state);
    return t;
  }
  /** The allow freshness horizon recorded at a terminal allow, else 0. */
  get allowValidUntil(): number {
    return tokenStates.get(this)?.allowValidUntil ?? 0;
  }
}

function signedV2RateReservationBatch(bundle: ProofBundleV2): V2RateReservation[] {
  const deferred: V2DeferredConstraint[] = [];
  (bundle.delegations ?? []).forEach((cert, i) => {
    (cert.constraints ?? []).forEach((c, j) => {
      if (c.type !== "max_rate") return;
      deferred.push({ delegationIndex: i, constraintIndex: j, issuerID: cert.issuer_id, certID: cert.cert_id, type: "max_rate", canonicalJSON: constraintCanonicalJSONV2(c) });
    });
  });
  return buildV2RateReservationBatch(deferred);
}

export interface V2ClaimOutcome {
  claim: V2ChallengeClaim;
  disposition: V2ClaimDisposition;
  token: V2EvaluationToken | null;
}

/**
 * Repeats the freshness and binding checks immediately before invoking the
 * atomic claim store. No trust, status or policy callback runs before this.
 */
export async function claimProofBundleV2(
  store: ClaimStoreV2,
  bundle: ProofBundleV2,
  preflight: V2PreflightResult,
  configuredNamespace: string,
  configuredReplayEpoch: number,
  nowUnix: number,
): Promise<V2ClaimOutcome> {
  if (!store) throw new Error("v2 claim store and context are required");
  const state = preflight ? preflightStates.get(preflight) : undefined;
  if (!state || (state.contextPolicy === null && !state.noContextPolicy)) {
    throw new Error("v2 successful preflight state is required before claim");
  }
  const sealed = cloneSealed(state);
  let bundleHash = "";
  try {
    bundleHash = bundleHashV2(bundle);
  } catch {
    bundleHash = "";
  }
  if (bundleHash === "" || bundleHash !== sealed.bundleHash) throw new Error("v2 proof bundle differs from successful preflight");
  const expected: ExpectedChallengeV2 = {
    value: sealed.value, issuedAt: sealed.issuedAt, expiresAt: sealed.expiresAt, verifierNamespace: sealed.verifierNamespace,
    replayEpoch: sealed.replayEpoch, verifierID: sealed.verifierID, expectedAgentID: sealed.expectedAgentID,
    expectedAgentPublicKey: sealed.expectedAgentPublicKey, expectedReceiverID: sealed.expectedReceiverID,
    expectedSessionContext: sealed.expectedSessionContext, contextPolicy: sealed.contextPolicy,
  };
  try {
    await validateProofBundleV2Preflight(bundle, expected, sealed.requiredScope, configuredNamespace, configuredReplayEpoch, nowUnix, sealed.maxAge, sealed.futureSkew);
  } catch (err) {
    throw wrapError("v2 claim-time preflight", err);
  }
  const challengeDigest = challengeClaimDigestV2(sealed.value);
  const claimID = protocolClaimIDV2(sealed.verifierNamespace, sealed.replayEpoch, sealed.value);
  let rateBatch: V2RateReservation[];
  try {
    rateBatch = signedV2RateReservationBatch(bundle);
  } catch (err) {
    throw wrapError("v2 signed rate batch", err);
  }
  const claim: V2ChallengeClaim = {
    claimID, namespace: sealed.verifierNamespace, replayEpoch: sealed.replayEpoch,
    challengeDigest: "sha384:" + hexOf(challengeDigest), proofDigest: bundleHash, bundleHash: sealed.bundleHash,
    issuerIDs: [...sealed.issuerIDs], requiredScope: sealed.requiredScope, contextPolicyDigest: sealed.contextPolicyDigest,
    verifierID: sealed.verifierID, agentID: bundle.agent_id, requiresRate: rateBatch.length !== 0, rateBatch,
    issuedAt: sealed.issuedAt, expiresAt: sealed.expiresAt, maxAgeSeconds: sealed.maxAge, clockSkewSeconds: sealed.futureSkew,
    streamID: bundle.stream_id === null ? null : Uint8Array.from(bundle.stream_id), streamSeq: bundle.stream_seq,
  };
  const result = await store.claimV2(structuredClone(claim));
  switch (result?.disposition) {
    case "created": {
      const owner = result.ownerToken;
      if (!(owner instanceof Uint8Array) || owner.length !== 32) throw new Error("v2 claim store returned an invalid evaluator owner token");
      const at = result.claimedAt;
      const claimTimeValid = Number.isInteger(at) && at >= -MAX_SAFE && at <= MAX_SAFE &&
        !(at < sealed.issuedAt && sealed.issuedAt - at > sealed.futureSkew) && at < sealed.expiresAt &&
        !(at > sealed.issuedAt && at - sealed.issuedAt > sealed.maxAge);
      const token = V2EvaluationToken.create({
        claimID, proofDigest: claim.proofDigest, requiredScope: sealed.requiredScope, futureSkew: sealed.futureSkew, expected: sealed,
        used: false, evaluationComplete: false, finalizationDigest: null, finalizationStarted: false, claimTimeValid,
        claimedAt: at, evaluatedAt: 0, rateBatch: [...rateBatch], rateAtFinalization: false, allowValidUntil: 0,
        ownerToken: Uint8Array.from(owner), evaluationStatus: "", evaluationReason: "", pendingAssessment: null,
      });
      return { claim, disposition: "created", token };
    }
    case "in_progress":
    case "terminal_replay":
      if (result.ownerToken && result.ownerToken.length !== 0) throw new Error("v2 exact retry must not receive evaluator ownership");
      return { claim, disposition: result.disposition, token: null };
    default:
      throw new Error("v2 claim store returned an invalid disposition");
  }
}

// ---------------------------------------------------------------------------
// Post-claim local authorization

export interface V2TrustResolution {
  available: boolean;
  rootID: string;
  rootKey: HybridPublicKey | null;
}

export interface V2LocalAuthorizationOptions {
  /** Unix seconds. */
  now?: number;
  futureSkewSeconds: number;
  requiredScope: string;
  trustedRootID: string;
  trustedRootKey: HybridPublicKey | null;
  trustConfigured: boolean;
  context: VerifierContext;
  contextPolicy: V2ContextPolicy | null;
  expectedChallenge: ExpectedChallengeV2 | null;
  claimToken: V2EvaluationToken | null;
}

export interface V2LocalPolicyFailure {
  status: string;
  reason: string;
  detail: string;
}

/** An intermediate result, not a terminal decision. */
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

function localAssessment(status: string, reason: string, scope: string[] | null, detail: string): V2LocalAuthorizationAssessment {
  return {
    bundleHash: "", issuerIDs: [], agentID: "", rootID: "", requiredScope: "", delegationDigest: new Uint8Array(0),
    effectiveScope: scope ?? [], contextAssessment: "not_evaluated", contextPolicyDigest: null, statusAssessment: "",
    delegationValidUntil: 0, localTimeValidUntil: 0, statusFreshUntil: 0, audienceFreshUntil: 0, statusEvidence: [],
    audienceEvidenceDigests: [], rateStoreUnavailable: false, rateAdmissionDeferred: false, statusChecks: [], deferred: [],
    localPolicyFailure: null, status, reason, detail,
  };
}

const interrupted = (detail: string) => localAssessment("authorization_unverified", "evaluation_interrupted", null, detail);

function constraintPrecedenceV2(status: string): number {
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

async function evaluateV2LocalConstraints(bundle: ProofBundleV2, ctx: VerifierContext, now: number) {
  const deferred: V2DeferredConstraint[] = [];
  let constraintStatus = "";
  const failures: string[] = [];
  const certs = bundle.delegations ?? [];
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i]!;
    const constraints = cert.constraints ?? [];
    for (let j = 0; j < constraints.length; j++) {
      const c = constraints[j]!;
      if (c.type === "max_rate" || c.type === CONSTRAINT_RECEIVER_AUDIENCE_V2) {
        try {
          deferred.push({ delegationIndex: i, constraintIndex: j, issuerID: cert.issuer_id, certID: cert.cert_id, type: c.type, canonicalJSON: constraintCanonicalJSONV2(c) });
        } catch (err) {
          if (constraintPrecedenceV2("constraint_unverifiable") > constraintPrecedenceV2(constraintStatus)) constraintStatus = "constraint_unverifiable";
          failures.push(`delegation ${i} constraint ${j} cannot be encoded: ${(err as Error).message}`);
        }
        continue;
      }
      // The v1 evaluator implements every canonical constraint kind; unknown
      // kinds report constraint_unknown and missing context unverifiable.
      const single = { cert_id: cert.cert_id, constraints: [c] } as unknown as Parameters<typeof evaluateConstraints>[0];
      const err = await evaluateConstraints(single, ctx ?? {}, now);
      if (err !== null) {
        const detail = err.replace(/^constraint\[0\] \([^)]*\): /, "");
        let status = "constraint_denied";
        if (detail.startsWith("constraint_unverifiable")) status = "constraint_unverifiable";
        else if (detail.startsWith("constraint_unknown:")) status = "constraint_unknown";
        if (constraintStatus === "" || constraintPrecedenceV2(status) > constraintPrecedenceV2(constraintStatus)) constraintStatus = status;
        failures.push(`delegation ${i} constraint ${j}: ${detail}`);
      }
    }
  }
  return { deferred, constraintStatus, failures };
}

function parseHHMMGo(s: string): number | null {
  const b = utf8(s);
  if (b.length !== 5 || b[2] !== 0x3a) return null;
  const h = (b[0]! - 0x30) * 10 + (b[1]! - 0x30);
  const m = (b[3]! - 0x30) * 10 + (b[4]! - 0x30);
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return h * 60 + m;
}

interface ZoneInfo {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  offset: number;
}

function zoneInfo(tz: string, unix: number): ZoneInfo {
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  const parts = Object.fromEntries(fmt.formatToParts(new Date(unix * 1000)).map((p) => [p.type, p.value]));
  const year = Number(parts.year);
  const month = Number(parts.month);
  const day = Number(parts.day);
  const hour = Number(parts.hour) % 24;
  const minute = Number(parts.minute);
  const second = Number(parts.second);
  const local = Date.UTC(year, month - 1, day, hour, minute, second) / 1000;
  return { year, month, day, hour, minute, offset: local - unix };
}

/** Next instant after `from` whose UTC offset differs, if it is at or before `limit`. */
function nextZoneTransition(tz: string, from: number, limit: number): number | null {
  const base = zoneInfo(tz, from).offset;
  let lo = from;
  for (let t = from + 900; ; t += 900) {
    const probe = Math.min(t, limit);
    if (zoneInfo(tz, probe).offset !== base) {
      let hi = probe;
      while (hi - lo > 1) {
        const mid = Math.floor((lo + hi) / 2);
        if (zoneInfo(tz, mid).offset !== base) hi = mid;
        else lo = mid;
      }
      return hi;
    }
    lo = probe;
    if (probe >= limit) return null;
  }
}

/** Bounds an allow at the end of each accepted local minute window or the next zone transition. */
function localTimeWindowValidUntilV2(bundle: ProofBundleV2, now: number): number {
  let horizon = 0;
  for (const cert of bundle.delegations ?? []) {
    for (const c of cert.constraints ?? []) {
      if (c.type !== "time_window") continue;
      let local: ZoneInfo;
      try {
        local = zoneInfo(c.tz ?? "", now);
      } catch {
        throw new Error(`unknown time zone ${c.tz}`);
      }
      const start = parseHHMMGo(c.start ?? "");
      const end = parseHHMMGo(c.end ?? "");
      if (start === null || end === null) throw new Error("expected HH:MM");
      const minute = local.hour * 60 + local.minute;
      if ((start <= end && (minute < start || minute > end)) || (start > end && minute < start && minute > end)) {
        throw new Error("time window is no longer current");
      }
      const dayOffset = start > end && minute >= start ? 1 : 0;
      let until = Date.UTC(local.year, local.month - 1, local.day + dayOffset, 0, end + 1, 0) / 1000 - local.offset;
      const zoneEnd = nextZoneTransition(c.tz!, now, until);
      if (zoneEnd !== null && zoneEnd < until) until = zoneEnd;
      if (!(until > now) || until <= 0 || until > MAX_SAFE) throw new Error("time window has no valid terminal horizon");
      if (horizon === 0 || until < horizon) horizon = until;
    }
  }
  return horizon;
}

function allowHorizonV2(a: V2LocalAuthorizationAssessment): number {
  let horizon = Math.min(a.delegationValidUntil, a.statusFreshUntil);
  if (a.audienceFreshUntil > 0) horizon = Math.min(horizon, a.audienceFreshUntil);
  if (a.localTimeValidUntil > 0) horizon = Math.min(horizon, a.localTimeValidUntil);
  return horizon;
}

const cloneAssessment = (a: V2LocalAuthorizationAssessment): V2LocalAuthorizationAssessment => structuredClone(a);

/**
 * Evaluates trust-root binding, delegation times, effective scope, context
 * policy and deterministic constraints after preflight and atomic claim. It
 * performs no status lookup, rate reservation or other external call.
 */
export async function evaluateProofBundleV2LocalAuthorization(bundle: ProofBundleV2, opts: V2LocalAuthorizationOptions): Promise<V2LocalAuthorizationAssessment> {
  const tokenState = opts.claimToken ? tokenStates.get(opts.claimToken) : undefined;
  let evaluationStarted = false;
  const finish = (assessment: V2LocalAuthorizationAssessment): V2LocalAuthorizationAssessment => {
    if (tokenState?.expected) {
      assessment.bundleHash = tokenState.expected.bundleHash;
      assessment.issuerIDs = [...tokenState.expected.issuerIDs];
    }
    if (evaluationStarted && assessment.status !== "" && tokenState) {
      tokenState.evaluationStatus = assessment.status;
      tokenState.evaluationReason = assessment.reason;
      if (assessment.status === "pending_external_checks") tokenState.pendingAssessment = cloneAssessment(assessment);
      tokenState.evaluationComplete = true;
    }
    return assessment;
  };
  if (!tokenState || !tokenState.expected) {
    return finish(localAssessment("preflight_binding_mismatch", "claim_required", null, "local authorization requires a successful atomic challenge claim"));
  }
  let claimID = "";
  try {
    claimID = protocolClaimIDV2(tokenState.expected.verifierNamespace, tokenState.expected.replayEpoch, tokenState.expected.value);
  } catch {
    claimID = "";
  }
  if (claimID === "" || tokenState.claimID !== claimID || tokenState.proofDigest !== tokenState.expected.bundleHash || tokenState.ownerToken.length !== 32) {
    return finish(interrupted("local authorization state differs from successful preflight or atomic claim"));
  }
  if (tokenState.used) return finish(localAssessment("evaluation_in_progress", "claim_in_progress", null, "the claim's single evaluation token has already been used"));
  tokenState.used = true;
  evaluationStarted = true;
  if (!tokenState.claimTimeValid) {
    return finish(interrupted("claim store returned an authoritative claim time outside the authenticated freshness bounds"));
  }
  if (opts.expectedChallenge && !matchesExpectedChallengeV2(opts.expectedChallenge, tokenState.expected)) {
    return finish(interrupted("local authorization challenge state differs from successful preflight or atomic claim"));
  }
  let now = opts.now ?? Math.floor(Date.now() / 1000);
  if (now < tokenState.claimedAt) now = tokenState.claimedAt;
  tokenState.evaluatedAt = now;
  if (opts.requiredScope !== tokenState.requiredScope || !(opts.futureSkewSeconds >= 0) || !Number.isInteger(opts.futureSkewSeconds) ||
      opts.futureSkewSeconds !== tokenState.futureSkew) {
    return finish(interrupted("local authorization state differs from successful preflight or atomic claim"));
  }
  if (opts.requiredScope !== tokenState.expected.requiredScope) {
    return finish(interrupted("required scope differs from the scope validated during preflight"));
  }
  let bundleHash = "";
  try {
    bundleHash = bundleHashV2(bundle);
  } catch {
    bundleHash = "";
  }
  if (bundleHash === "" || bundleHash !== tokenState.proofDigest) return finish(interrupted("proof bundle differs from the bundle validated during preflight"));
  if (!bundle || !bytesEqual(bundle.challenge, tokenState.expected.value) || bundle.challenge_at !== tokenState.expected.issuedAt ||
      bundle.verifier_id !== tokenState.expected.verifierID) {
    return finish(interrupted("proof challenge differs from the challenge validated during preflight"));
  }
  const scopeErr = validateRequiredScopeV2(opts.requiredScope);
  if (scopeErr) return finish(interrupted("required scope changed after successful preflight: " + scopeErr));
  try {
    await verifyProofBundleV2Signatures(bundle);
  } catch {
    return finish(interrupted("proof signature changed after successful preflight"));
  }
  const certs = bundle.delegations ?? [];
  if (certs.length === 0) return finish(localAssessment("delegation_not_authorized", "not_delegated", null, "proof has no delegation certificates"));
  if (!opts.trustConfigured) {
    return finish(localAssessment("authorization_unverified", "trust_unavailable", null, "caller-authenticated trust configuration is unavailable"));
  }
  const root = certs[certs.length - 1]!;
  if (opts.trustedRootID !== root.issuer_id || !equalHybridPublicKeys(opts.trustedRootKey, root.issuer_pub_key)) {
    return finish(localAssessment("unauthorized", "unauthorized", null, "delegation chain does not terminate at the configured trust root"));
  }
  const skew = opts.futureSkewSeconds;
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i]!;
    if (c.issued_at >= c.expires_at || c.issued_at > now + skew) {
      return finish(localAssessment("invalid", "proof_invalid", null, `delegation ${i} has invalid time bounds`));
    }
  }
  for (let i = 0; i < certs.length; i++) {
    if (!(now < certs[i]!.expires_at)) return finish(localAssessment("expired", "delegation_expired", null, `delegation ${i} has expired`));
  }
  for (let i = 0; i < certs.length; i++) {
    const err = validateScopesV2(certs[i]!.scope);
    if (err) return finish(localAssessment("invalid_scope", "invalid_scope", null, `delegation ${i}: ${err}`));
  }
  for (let i = 0; i + 1 < certs.length; i++) {
    if (!(certs[i + 1]!.scope ?? []).includes(SCOPE_IDENTITY_DELEGATE_V2)) {
      return finish(localAssessment("delegation_not_authorized", "delegation_not_authorized", null, `parent delegation ${i + 1} does not grant "identity:delegate"`));
    }
  }
  const effective = intersectScopesV2(certs.map((c) => c.scope ?? []));
  let localPolicyFailure: V2LocalPolicyFailure | null = null;
  if (!effective.includes(opts.requiredScope)) {
    localPolicyFailure = { status: "scope_denied", reason: "scope_denied", detail: `required scope ${JSON.stringify(opts.requiredScope)} is not in the effective delegation scope` };
  }
  if (opts.contextPolicy && !sameV2ContextPolicy(opts.contextPolicy, tokenState.expected.contextPolicy)) {
    return finish(interrupted("context policy differs from the policy sealed during successful preflight"));
  }
  const contextAssessment = evaluateProofBundleV2ContextPolicy(bundle, tokenState.expected.contextPolicy);
  if (contextAssessment.status !== "passed" && localPolicyFailure === null) {
    localPolicyFailure = { status: contextAssessment.status, reason: contextAssessment.reason, detail: contextAssessment.detail };
  }
  const { deferred, constraintStatus, failures } = await evaluateV2LocalConstraints(bundle, opts.context, now);
  if (constraintStatus !== "" && localPolicyFailure === null) {
    localPolicyFailure = { status: constraintStatus, reason: constraintStatus, detail: [...failures].sort(compareStrings).join("; ") };
  }
  const assessment = localAssessment("pending_external_checks", "external_checks_required", effective, "local checks recorded; status and deferred authorization checks remain");
  assessment.agentID = bundle.agent_id;
  assessment.rootID = opts.trustedRootID;
  assessment.requiredScope = opts.requiredScope;
  assessment.delegationDigest = Uint8Array.from(bundle.delegation_digest);
  assessment.localPolicyFailure = localPolicyFailure;
  assessment.statusChecks = certs.map((c, i) => ({ delegationIndex: i, issuerID: c.issuer_id, subjectID: c.subject_id, certID: c.cert_id }));
  assessment.deferred = deferred;
  assessment.delegationValidUntil = Math.min(...certs.map((c) => c.expires_at));
  if (localPolicyFailure === null) {
    try {
      assessment.localTimeValidUntil = localTimeWindowValidUntilV2(bundle, now);
    } catch (err) {
      assessment.localPolicyFailure = { status: "constraint_unverifiable", reason: "constraint_unverifiable", detail: (err as Error).message };
    }
  }
  assessment.contextAssessment = contextAssessment.assessment;
  assessment.contextPolicyDigest = contextAssessment.policyDigest;
  return finish(assessment);
}

function requireState(token: V2EvaluationToken | null): TokenState {
  const state = token ? tokenStates.get(token) : undefined;
  if (!state) throw new Error("v2 claim evaluator capability is required");
  return state;
}

/**
 * Completes the ordered status stage for the sealed assessment: exactly one
 * authenticated result per CertificateRef; local denials apply only when
 * every status is current.
 */
export function resolveClaimProofBundleV2AfterStatus(token: V2EvaluationToken, results: readonly RevocationStatusResultV2[], roles: V2StatusRoleBindings): V2LocalAuthorizationAssessment {
  const state = requireState(token);
  if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || state.pendingAssessment === null) {
    throw new Error("v2 claim does not have a pending status assessment");
  }
  const assessment = cloneAssessment(state.pendingAssessment);
  if (assessment.bundleHash !== state.expected.bundleHash || assessment.requiredScope !== state.expected.requiredScope) {
    throw new Error("pending status assessment differs from its claimed proof");
  }
  const aggregated = aggregateCertificateStatusV2(assessment.statusChecks, results, roles);
  assessment.statusAssessment = aggregated.assessment;
  assessment.statusFreshUntil = aggregated.freshUntil;
  assessment.statusEvidence = aggregated.evidence.map((e) => ({ ...e }));
  switch (aggregated.assessment) {
    case "revoked":
      Object.assign(assessment, { status: "revoked", reason: "delegation_revoked", detail: "at least one delegation certificate is revoked" });
      break;
    case "unavailable":
      Object.assign(assessment, { status: "authorization_unverified", reason: "status_unavailable", detail: "one or more delegation certificate statuses are unavailable" });
      break;
    case "stale":
      Object.assign(assessment, { status: "authorization_unverified", reason: "status_stale", detail: "one or more delegation certificate statuses are stale" });
      break;
    case "current":
      if (assessment.localPolicyFailure !== null && combinableWithAudienceV2(assessment.localPolicyFailure, assessment.deferred)) {
        assessment.deferred = assessment.deferred.filter((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2);
        Object.assign(assessment, { status: "pending_external_checks", reason: "deferred_policy_checks_required", detail: "status is current; audience must be aggregated with a pending local constraint result" });
        state.pendingAssessment = cloneAssessment(assessment);
        state.evaluationStatus = assessment.status;
        state.evaluationReason = assessment.reason;
        return assessment;
      } else if (assessment.localPolicyFailure !== null) {
        assessment.status = assessment.localPolicyFailure.status;
        assessment.reason = assessment.localPolicyFailure.reason;
        assessment.detail = assessment.localPolicyFailure.detail;
      } else if (assessment.deferred.length !== 0) {
        Object.assign(assessment, { status: "pending_external_checks", reason: "deferred_policy_checks_required", detail: "status is current; deferred audience or rate checks remain" });
        state.pendingAssessment = cloneAssessment(assessment);
        state.evaluationStatus = assessment.status;
        state.evaluationReason = assessment.reason;
        return assessment;
      } else {
        Object.assign(assessment, { status: "authorized_agent", reason: "authorized", detail: "proof, status, and local authorization checks passed" });
        state.allowValidUntil = allowHorizonV2(assessment);
      }
      break;
    default:
      throw new Error("v2 status aggregator returned an unknown assessment");
  }
  state.evaluationStatus = assessment.status;
  state.evaluationReason = assessment.reason;
  state.pendingAssessment = null;
  return assessment;
}

/** Consumes caller-authenticated complete membership results after current status. */
export function resolveClaimProofBundleV2AfterAudience(token: V2EvaluationToken, memberships: readonly V2AudienceMembership[] | null, now: number): V2LocalAuthorizationAssessment {
  const state = requireState(token);
  const pending = state.pendingAssessment;
  if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || pending === null || pending.statusAssessment !== "current" ||
      (pending.localPolicyFailure !== null && !combinableWithAudienceV2(pending.localPolicyFailure, pending.deferred))) {
    throw new Error("v2 claim does not have current status and pending audience checks");
  }
  const assessment = cloneAssessment(pending);
  const abort = (message: string): never => {
    state.evaluationStatus = "authorization_unverified";
    state.evaluationReason = "evaluation_interrupted";
    state.pendingAssessment = null;
    throw new Error(message);
  };
  if (assessment.bundleHash !== state.expected.bundleHash || assessment.requiredScope !== state.expected.requiredScope) {
    abort("pending audience assessment differs from its claimed proof");
  }
  if (now < state.evaluatedAt) now = state.evaluatedAt;
  let result;
  try {
    result = evaluateReceiverAudienceV2(assessment.deferred, state.expected.expectedReceiverID, memberships, now, state.futureSkew);
  } catch (err) {
    return abort((err as Error).message);
  }
  assessment.audienceEvidenceDigests = [...result.evidenceDigests];
  assessment.audienceFreshUntil = result.freshUntil;
  const local = assessment.localPolicyFailure;
  if (local !== null) {
    if (result.status === "passed" || constraintPrecedenceV2(local.status) > constraintPrecedenceV2(result.status)) {
      Object.assign(assessment, { status: local.status, reason: local.reason, detail: local.detail });
    } else {
      Object.assign(assessment, { status: result.status, reason: result.status, detail: "receiver audience did not authorize this receiver" });
    }
    assessment.deferred = [];
    state.pendingAssessment = null;
  } else if (result.status !== "passed") {
    Object.assign(assessment, { status: result.status, reason: result.status, detail: "receiver audience did not authorize this receiver" });
    state.pendingAssessment = null;
  } else {
    assessment.deferred = assessment.deferred.filter((d) => d.type !== CONSTRAINT_RECEIVER_AUDIENCE_V2);
    if (assessment.deferred.length === 0) {
      Object.assign(assessment, { status: "authorized_agent", reason: "authorized", detail: "proof, status, audience, and local authorization checks passed" });
      state.allowValidUntil = allowHorizonV2(assessment);
      state.pendingAssessment = null;
    } else {
      Object.assign(assessment, { status: "pending_external_checks", reason: "rate_reservation_required", detail: "audience passed; rate reservation remains" });
      state.pendingAssessment = cloneAssessment(assessment);
    }
  }
  state.evaluationStatus = assessment.status;
  state.evaluationReason = assessment.reason;
  return assessment;
}

/** The final external constraint stage: atomic reservation of the sealed batch. */
export async function resolveClaimProofBundleV2AfterRate(store: V2RateReservationStore | null | undefined, token: V2EvaluationToken): Promise<V2LocalAuthorizationAssessment> {
  const state = requireState(token);
  const pending = state.pendingAssessment;
  if (!state.evaluationComplete || state.evaluationStatus !== "pending_external_checks" || pending === null || pending.statusAssessment !== "current" ||
      pending.localPolicyFailure !== null) {
    throw new Error("v2 claim does not have current status and pending rate checks");
  }
  const assessment = cloneAssessment(pending);
  const abort = (message: string): never => {
    state.evaluationStatus = "authorization_unverified";
    state.evaluationReason = "evaluation_interrupted";
    state.pendingAssessment = null;
    throw new Error(message);
  };
  if (assessment.bundleHash !== state.expected.bundleHash || assessment.requiredScope !== state.expected.requiredScope || state.rateBatch.length === 0) {
    abort("pending rate assessment differs from its claimed proof");
  }
  if (assessment.deferred.some((d) => d.type !== "max_rate")) throw new Error("audience or unknown checks remain before rate reservation");
  let batch: V2RateReservation[] = [];
  let batchOK = true;
  try {
    batch = buildV2RateReservationBatch(assessment.deferred);
  } catch {
    batchOK = false;
  }
  const sameBatch = batchOK && batch.length === state.rateBatch.length && batch.every((b, i) => {
    const s = state.rateBatch[i]!;
    return b.issuerID === s.issuerID && b.certID === s.certID && b.windowS === s.windowS && b.limit === s.limit;
  });
  if (!sameBatch) abort("pending rate checks differ from sealed signed batch");
  let err: unknown = null;
  if (!store) {
    err = new Error("v2 rate reservation store is unavailable");
  } else if (isRateAtFinalizationStore(store)) {
    state.rateAtFinalization = true;
    assessment.rateAdmissionDeferred = true;
  } else {
    try {
      await store.reserveV2RateBatch(state.claimID, Uint8Array.from(state.ownerToken), assessment.bundleHash, batch.map((b) => ({ ...b })));
    } catch (e) {
      err = e ?? new Error("rate store failed");
    }
  }
  if (err === null) {
    Object.assign(assessment, {
      status: "authorized_agent", reason: "authorized",
      detail: state.rateAtFinalization ? "proof, status, and audience passed; rate admission is deferred to durable finalization" : "proof, status, audience, and rate checks passed",
    });
    state.allowValidUntil = allowHorizonV2(assessment);
  } else if (errorIs(err, ErrV2RateLimitExceeded)) {
    Object.assign(assessment, { status: "constraint_denied", reason: "constraint_denied", detail: "signed rate limit has no remaining capacity" });
  } else {
    Object.assign(assessment, { status: "constraint_unverifiable", reason: "constraint_unverifiable", detail: "rate reservation could not be verified", rateStoreUnavailable: true });
  }
  assessment.deferred = [];
  state.pendingAssessment = null;
  state.evaluationStatus = assessment.status;
  state.evaluationReason = assessment.reason;
  return assessment;
}

// ---------------------------------------------------------------------------
// Terminal finalization

export function terminalDecisionForV2Evaluation(status: string, reason: string): string | null {
  if (reason === "evaluation_interrupted") return status === "authorization_unverified" ? "indeterminate" : null;
  switch (status) {
    case "authorization_unverified":
      return ["trust_unavailable", "action_context_unverified", "status_unavailable", "status_stale"].includes(reason) ? "indeterminate" : null;
    case "authorized_agent":
      return reason === "authorized" ? "allow" : null;
    case "constraint_denied": case "constraint_unverifiable": case "constraint_unknown": case "unauthorized": case "invalid_scope": case "scope_denied":
      return reason === status ? "deny" : null;
    case "revoked":
      return reason === "delegation_revoked" ? "deny" : null;
    case "invalid":
      return reason === "proof_invalid" ? "deny" : null;
    case "delegation_not_authorized":
      return reason === "not_delegated" || reason === "delegation_not_authorized" ? "deny" : null;
    case "expired":
      return reason === "delegation_expired" ? "deny" : null;
    default:
      return null;
  }
}

function readTerminalPayload(value: Uint8Array): [string, string] | null {
  if (!isValidUTF8(value)) return null;
  try {
    const root = parseJSONV2(value, { rejectDuplicates: true });
    if (root.k !== "obj") return null;
    const d = root.m.get("decision");
    const r = root.m.get("decision_reason");
    const text = (n: typeof d): string | null => (n === undefined ? null : n.k === "null" ? "" : n.k === "str" ? n.v : null);
    const decision = text(d);
    const reason = text(r);
    return decision === null || reason === null ? null : [decision, reason];
  } catch {
    return null;
  }
}

function finalizationDigest(terminalResult: Uint8Array, receiptBody: Uint8Array): Uint8Array {
  return sha256(concatBytes(uint64BE(terminalResult.length), terminalResult, uint64BE(receiptBody.length), receiptBody));
}

/**
 * Commits a terminal local evaluation through the capability that won the
 * atomic claim. Retries are allowed only with identical result and body.
 */
export async function finalizeClaimProofBundleV2(store: ClaimStoreV2, token: V2EvaluationToken, terminalResult: Uint8Array, receiptBody: Uint8Array): Promise<boolean> {
  const state = token ? tokenStates.get(token) : undefined;
  if (!store || !state || state.ownerToken.length !== 32 || state.claimID === "") {
    throw new Error("v2 claim store and valid evaluator capability are required");
  }
  const result = Uint8Array.from(terminalResult);
  const body = Uint8Array.from(receiptBody);
  if (!state.evaluationComplete) throw new Error("v2 proof evaluation has not completed");
  const decision = terminalDecisionForV2Evaluation(state.evaluationStatus, state.evaluationReason);
  if (decision === null) throw new Error("v2 proof evaluation has not reached a terminal local result");
  const r = readTerminalPayload(result);
  const b = readTerminalPayload(body);
  if (!r || !b || r[0] !== decision || b[0] !== decision || r[1] !== state.evaluationReason || b[1] !== state.evaluationReason) {
    throw new Error("v2 terminal result does not match the completed local evaluation");
  }
  if ((decision === "allow" && state.allowValidUntil <= 0) || (decision !== "allow" && state.allowValidUntil !== 0)) {
    throw new Error("v2 terminal result lacks a valid allow freshness horizon");
  }
  if (state.rateAtFinalization && !isRateAtFinalizationStore(store)) throw new Error("v2 rate-at-finalization requires an atomic rate store");
  const digest = finalizationDigest(result, body);
  if (state.finalizationStarted && !bytesEqual(state.finalizationDigest, digest)) {
    throw new Error("v2 evaluator capability cannot change its terminal result or receipt body");
  }
  state.finalizationStarted = true;
  state.finalizationDigest = digest;
  try {
    return await store.finalizeV2Claim(state.claimID, Uint8Array.from(state.ownerToken), result, body, state.allowValidUntil);
  } catch (err) {
    if (state.rateAtFinalization && decision === "allow" && err === ErrV2RateLimitExceeded && isRateAtFinalizationStore(store)) {
      state.evaluationStatus = "constraint_denied";
      state.evaluationReason = "constraint_denied";
      state.allowValidUntil = 0;
      state.rateAtFinalization = false;
      state.finalizationStarted = false;
      state.finalizationDigest = null;
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// End-to-end live verifier

export interface V2VerifyCallbacks {
  /** Pure pre-consumption application hook; throw to reject. No I/O. */
  receiverBinding?: V2ReceiverBindingHook;
  claimStore: ClaimStoreV2;
  trust?: (chain: DelegationCertV2[]) => Promise<V2TrustResolution> | V2TrustResolution;
  status?: (ref: { issuerID: string; certID: string }) => Promise<RevocationStatusResultV2> | RevocationStatusResultV2;
  audience?: (deferred: V2DeferredConstraint[], receiverID: string) => Promise<V2AudienceMembership[]> | V2AudienceMembership[];
  rate?: V2RateReservationStore | null;
}

/**
 * One live verification. contextPolicy null means the verifier explicitly
 * configured no context policy (the result can then never be allow).
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
  context?: VerifierContext;
  statusRoles: V2StatusRoleBindings;
}

export type V2VerifyStage = "preflight" | "replay" | "evaluating" | "terminal";

export interface V2VerifyOutcome {
  stage: V2VerifyStage;
  /** The classified pre-claim error (stage preflight). */
  error: Error | null;
  errorClass: V2ErrorClass | "";
  /**
   * Set when a claimed evaluation could not reach a terminal commit (stage
   * evaluating; Go returns this as the error result). The claim stays in
   * progress for lease-expiry recovery.
   */
  evaluationError: Error | null;
  disposition: V2ClaimDisposition | "";
  claim: V2ChallengeClaim | null;
  decision: string;
  reason: string;
  identityStatus: string;
  receipt: VerificationReceiptV2 | null;
  receiptBody: Uint8Array | null;
  allowValidUntil: number;
}

function emptyOutcome(stage: V2VerifyStage): V2VerifyOutcome {
  return {
    stage, error: null, errorClass: "", evaluationError: null, disposition: "", claim: null, decision: "", reason: "",
    identityStatus: "", receipt: null, receiptBody: null, allowValidUntil: 0,
  };
}

function terminalV2Outcome(bundle: ProofBundleV2, a: V2LocalAuthorizationAssessment, trustIn: string, req: V2VerifyRequest, claim: V2ChallengeClaim): V2VerifyOutcome {
  const decision = terminalDecisionForV2Evaluation(a.status, a.reason);
  if (decision === null) throw new Error(`v2 evaluation did not reach a terminal result: ${a.status}/${a.reason}`);
  let trust = trustIn;
  let statusAssessment = a.statusAssessment || "not_evaluated";
  let contextAssessment = a.contextAssessment || "not_evaluated";
  if (a.reason === "not_delegated") {
    trust = "not_evaluated";
  } else if (a.reason === "evaluation_interrupted") {
    if (trust !== "trusted") {
      trust = "not_evaluated";
      statusAssessment = "not_evaluated";
    }
    if (contextAssessment !== "bound" && contextAssessment !== "not_required") contextAssessment = "not_evaluated";
    if (contextAssessment === "not_evaluated") statusAssessment = "not_evaluated";
  }
  const policyDigest = contextAssessment !== "not_evaluated" && contextAssessment !== "unbound" && a.contextPolicyDigest !== null ? a.contextPolicyDigest : null;
  const evidence = statusAssessment === "not_evaluated" ? [] : a.statusEvidence.map((e) => ({ ...e }));
  const granted = decision === "allow" ? [...new Set(a.effectiveScope)].sort(compareStrings) : [];
  const receipt: VerificationReceiptV2 = {
    version: 2, log_id: "", sequence: 0, verifier_id: bundle.verifier_id, agent_id: bundle.agent_id, human_id: "",
    bundle_hash: claim.bundleHash, issuer_ids: [...claim.issuerIDs], decision, decision_reason: a.reason, identity_status: a.status,
    trust_assessment: trust, status_assessment: statusAssessment, challenge_assessment: "current", context_assessment: contextAssessment,
    context_policy_digest: policyDigest, verified_at: req.now, required_scope: claim.requiredScope, granted_scope: granted,
    status_evidence_digests: evidence, previous_receipt_hash: new Uint8Array(0), signature: { ed25519: new Uint8Array(0), ml_dsa_65: new Uint8Array(0) },
  };
  let body: Uint8Array;
  try {
    body = verificationReceiptV2Body(receipt);
  } catch (err) {
    throw wrapError("v2 terminal receipt body is inconsistent with the evaluated result", err);
  }
  const outcome = emptyOutcome("terminal");
  return { ...outcome, claim, decision, reason: a.reason, identityStatus: a.status, receipt, receiptBody: body };
}

/**
 * Runs the complete live Protocol v2 decision path in the SPEC-v2 §6 order:
 * strict decode and structure, required scope, key IDs, digest, linkage and
 * duplicates, every signature, authenticated ExpectedChallenge and
 * freshness, the pure receiver-binding hook, the atomic claim, and only then
 * trust, local authorization, status for every CertificateRef, receiver
 * audience and max_rate reservation, then terminal finalization.
 *
 * A pre-claim failure returns stage "preflight" with a classified error and
 * invokes no claim, trust, status, audience or rate callback.
 */
export async function verifyProofBundleV2(req: V2VerifyRequest, cb: V2VerifyCallbacks): Promise<V2VerifyOutcome> {
  const preflightFailure = (err: unknown): V2VerifyOutcome => {
    const error = err instanceof Error ? err : new Error(String(err));
    return { ...emptyOutcome("preflight"), error, errorClass: v2ErrorClassOf(error) };
  };
  if (!cb || !cb.claimStore) return preflightFailure(v2Errorf("configuration_invalid", "v2 verification requires a context and claim store"));
  let bundle: ProofBundleV2;
  try {
    bundle = decodeProofBundleV2(req.bundle);
  } catch (err) {
    return preflightFailure(err);
  }
  let preflight: V2PreflightResult;
  try {
    preflight = await preflightProofBundleV2Internal(bundle, req.expected, req.contextPolicy, true, cb.receiverBinding, req.requiredScope,
      req.verifierNamespace, req.replayEpoch, req.now, req.maxChallengeAgeSeconds, req.futureSkewSeconds);
  } catch (err) {
    return preflightFailure(err);
  }
  let claimed: V2ClaimOutcome;
  try {
    claimed = await claimProofBundleV2(cb.claimStore, bundle, preflight, req.verifierNamespace, req.replayEpoch, req.now);
  } catch (err) {
    let e = err;
    if (v2ErrorClassOf(e) === "unclassified") e = v2Classify("claim_store_unavailable", e);
    return preflightFailure(e);
  }
  const { claim, disposition, token } = claimed;
  if (disposition !== "created" || token === null) return { ...emptyOutcome("replay"), disposition, claim };
  const evaluating = (err: unknown): V2VerifyOutcome => ({
    ...emptyOutcome("evaluating"), claim, disposition, evaluationError: err instanceof Error ? err : new Error(String(err)),
  });

  let trust = "not_evaluated";
  const opts: V2LocalAuthorizationOptions = {
    now: req.now, futureSkewSeconds: req.futureSkewSeconds, requiredScope: req.requiredScope, context: req.context ?? {},
    contextPolicy: req.contextPolicy, expectedChallenge: req.expected, claimToken: token, trustConfigured: false,
    trustedRootID: "", trustedRootKey: null,
  };
  const certs = bundle.delegations ?? [];
  if (certs.length > 0) {
    let resolution: V2TrustResolution = { available: false, rootID: "", rootKey: null };
    if (cb.trust) {
      try {
        resolution = await cb.trust(structuredClone(certs));
      } catch {
        resolution = { available: false, rootID: "", rootKey: null };
      }
    }
    opts.trustConfigured = !!resolution.available;
    opts.trustedRootID = resolution.rootID ?? "";
    opts.trustedRootKey = resolution.rootKey ?? null;
    const root = certs[certs.length - 1]!;
    if (!resolution.available) trust = "unavailable";
    else if (resolution.rootID !== root.issuer_id || !equalHybridPublicKeys(resolution.rootKey, root.issuer_pub_key)) trust = "untrusted";
    else trust = "trusted";
  }
  let assessment = await evaluateProofBundleV2LocalAuthorization(bundle, opts);
  try {
    if (assessment.status === "pending_external_checks") {
      const results: RevocationStatusResultV2[] = [];
      for (const check of assessment.statusChecks) {
        if (!cb.status) {
          results.push({ status: "indeterminate", reason: "unavailable", evidence: [], freshUntil: 0 });
          continue;
        }
        results.push(await cb.status({ issuerID: check.issuerID, certID: check.certID }));
      }
      try {
        assessment = resolveClaimProofBundleV2AfterStatus(token, results, req.statusRoles);
      } catch (err) {
        return evaluating(v2Classify("configuration_invalid", err));
      }
    }
    if (assessment.status === "pending_external_checks" && assessment.deferred.some((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2)) {
      let memberships: V2AudienceMembership[] | null = null;
      if (cb.audience) {
        const audienceDeferred = assessment.deferred.filter((d) => d.type === CONSTRAINT_RECEIVER_AUDIENCE_V2).map((d) => structuredClone(d));
        try {
          memberships = await cb.audience(audienceDeferred, req.expected?.expectedReceiverID ?? "");
        } catch {
          memberships = null;
        }
      }
      try {
        assessment = resolveClaimProofBundleV2AfterAudience(token, memberships, req.now);
      } catch (err) {
        return evaluating(v2Classify("configuration_invalid", err));
      }
    }
    if (assessment.status === "pending_external_checks") {
      try {
        assessment = await resolveClaimProofBundleV2AfterRate(cb.rate, token);
      } catch (err) {
        return evaluating(v2Classify("configuration_invalid", err));
      }
    }
  } catch (err) {
    return evaluating(err);
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    let outcome: V2VerifyOutcome;
    let terminal: Uint8Array;
    try {
      outcome = terminalV2Outcome(bundle, assessment, trust, req, claim);
      terminal = canonicalJSONV2({ decision: outcome.decision, decision_reason: outcome.reason, identity_status: outcome.identityStatus });
    } catch (err) {
      return evaluating(err);
    }
    try {
      await finalizeClaimProofBundleV2(cb.claimStore, token, terminal, outcome.receiptBody!);
      return { ...outcome, disposition, allowValidUntil: token.allowValidUntil };
    } catch (err) {
      if (!errorIs(err, ErrV2RateLimitExceeded) || attempt > 0) return evaluating(err);
      Object.assign(assessment, { status: "constraint_denied", reason: "constraint_denied", detail: "signed rate limit has no remaining capacity" });
    }
  }
  return evaluating(new Error("v2 terminal finalization did not complete"));
}
