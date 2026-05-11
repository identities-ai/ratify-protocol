// Receipts & verdicts — SPEC §17.5–§17.8.
//
// Three additive primitives sit on top of the verifier:
//
//   - VerificationReceipt — hybrid-signed attestation that a bundle was
//     verified with a specific decision at a specific time. Receipts chain
//     by prev_hash so the chain is tamper-evident (Lever 1).
//   - PolicyVerdict — HMAC-bound cached policy decision; lets a commercial
//     policy backend skip live evaluation on subsequent calls (Lever 2).
//   - VerifierContextHash — canonical SHA-256 of the policy-relevant subset
//     of a VerifierContext; used as the context binding on a PolicyVerdict.
//
// Wire format unchanged: these are SDK-side primitives that wrap output of
// the verifier, not new fields on existing signed objects.

import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";

import { canonicalJSON } from "./canonical.js";
import { signBoth, verifyBoth } from "./crypto.js";
import type {
  HybridPrivateKey,
  HybridPublicKey,
  HybridSignature,
  PolicyVerdict,
  ProofBundle,
  VerificationReceipt,
  VerifierContext,
  VerifyResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Lever 1: VerificationReceipt — SPEC §17.5
// ---------------------------------------------------------------------------

/**
 * BundleHash returns the canonical SHA-256 digest of a ProofBundle's full
 * wire form. The stable identifier of "what was verified" inside a
 * VerificationReceipt. Cross-implementation deterministic via RFC 8785.
 */
export function bundleHash(bundle: ProofBundle): Uint8Array {
  return sha256(canonicalJSON(bundle));
}

function verificationReceiptSignBytes(r: VerificationReceipt): Uint8Array {
  const scope = r.granted_scope ? [...r.granted_scope].sort() : undefined;
  const signable: Record<string, unknown> = {
    bundle_hash: r.bundle_hash,
    decision: r.decision,
    prev_hash: r.prev_hash,
    verified_at: r.verified_at,
    verifier_id: r.verifier_id,
    verifier_pub: r.verifier_pub,
    version: r.version,
  };
  if (r.agent_id) signable.agent_id = r.agent_id;
  if (r.error_reason) signable.error_reason = r.error_reason;
  if (scope && scope.length > 0) signable.granted_scope = scope;
  if (r.human_id) signable.human_id = r.human_id;
  return canonicalJSON(signable);
}

export function verificationReceiptSignBytesBuf(
  r: VerificationReceipt,
): Uint8Array {
  return verificationReceiptSignBytes(r);
}

/**
 * Issue a verifier-signed VerificationReceipt over a (bundle, result, prev)
 * triple. `prev_hash` is 32 zero bytes for genesis.
 */
export async function issueVerificationReceipt(
  bundle: ProofBundle,
  result: VerifyResult,
  verifierID: string,
  verifierPub: HybridPublicKey,
  verifierPriv: HybridPrivateKey,
  prevHash: Uint8Array | null,
  verifiedAt: number,
): Promise<VerificationReceipt> {
  const prev = prevHash ?? new Uint8Array(32);
  if (prev.length !== 32) {
    throw new Error(`prev_hash must be 32 bytes, got ${prev.length}`);
  }
  const r: VerificationReceipt = {
    version: 1,
    verifier_id: verifierID,
    verifier_pub: verifierPub,
    bundle_hash: bundleHash(bundle),
    decision: result.identity_status,
    human_id: result.human_id,
    agent_id: result.agent_id,
    granted_scope: result.granted_scope,
    error_reason: result.error_reason,
    verified_at: verifiedAt,
    prev_hash: prev,
    signature: {
      ed25519: new Uint8Array(0),
      ml_dsa_65: new Uint8Array(0),
    } as HybridSignature,
  };
  r.signature = await signBoth(verificationReceiptSignBytes(r), verifierPriv);
  return r;
}

/**
 * Verify the hybrid signature on a VerificationReceipt against the
 * receipt's declared verifier_pub. Returns null iff both component sigs
 * verify; otherwise an error string.
 */
export async function verifyVerificationReceipt(
  r: VerificationReceipt,
): Promise<string | null> {
  if (r.version !== 1) return `unsupported version ${r.version}`;
  if (r.bundle_hash.length !== 32) {
    return `bundle_hash must be 32 bytes, got ${r.bundle_hash.length}`;
  }
  if (r.prev_hash.length !== 32) {
    return `prev_hash must be 32 bytes, got ${r.prev_hash.length}`;
  }
  return verifyBoth(
    verificationReceiptSignBytes(r),
    r.signature,
    r.verifier_pub,
  );
}

/** SHA-256 of a receipt's signable bytes — use as `prev_hash` for the next. */
export function receiptHash(r: VerificationReceipt): Uint8Array {
  return sha256(verificationReceiptSignBytes(r));
}

// ---------------------------------------------------------------------------
// Lever 2: PolicyVerdict — SPEC §17.6
// ---------------------------------------------------------------------------

/**
 * Canonical SHA-256 of the policy-relevant subset of a VerifierContext.
 * Used as `context_hash` on a PolicyVerdict so a verdict cached for one
 * context never accidentally applies to another.
 */
export function verifierContextHash(ctx: VerifierContext): Uint8Array {
  // has_* booleans derived from field presence so the canonical hash matches
  // the Go reference, which carries explicit Has* fields. invocations_in_window
  // (a closure) is excluded — closures don't serialize.
  const signable = {
    current_alt_m: ctx.current_alt_m ?? 0,
    current_lat: ctx.current_lat ?? 0,
    current_lon: ctx.current_lon ?? 0,
    current_speed_mps: ctx.current_speed_mps ?? 0,
    has_amount: ctx.requested_amount !== undefined,
    has_location:
      ctx.current_lat !== undefined && ctx.current_lon !== undefined,
    has_speed: ctx.current_speed_mps !== undefined,
    requested_amount: ctx.requested_amount ?? 0,
    requested_currency: ctx.requested_currency ?? "",
  };
  return sha256(canonicalJSON(signable));
}

function policyVerdictSignBytes(v: PolicyVerdict): Uint8Array {
  const signable = {
    agent_id: v.agent_id,
    allow: v.allow,
    context_hash: v.context_hash,
    issued_at: v.issued_at,
    scope: v.scope,
    valid_until: v.valid_until,
    verdict_id: v.verdict_id,
    version: v.version,
  };
  return canonicalJSON(signable);
}

export function policyVerdictSignBytesBuf(v: PolicyVerdict): Uint8Array {
  return policyVerdictSignBytes(v);
}

/**
 * Issue an HMAC-bound PolicyVerdict. Typically called by a commercial
 * policy backend; `policySecret` MUST be cryptographically random and
 * private to the issuing service.
 */
export function issuePolicyVerdict(
  verdictID: string,
  agentID: string,
  scope: string,
  allow: boolean,
  contextHash: Uint8Array,
  issuedAt: number,
  validUntil: number,
  policySecret: Uint8Array,
): PolicyVerdict {
  if (policySecret.length === 0) throw new Error("policy_secret must not be empty");
  if (!verdictID) throw new Error("verdict_id must not be empty");
  if (!agentID) throw new Error("agent_id must not be empty");
  if (!scope) throw new Error("scope must not be empty");
  if (contextHash.length !== 32) {
    throw new Error(`context_hash must be 32 bytes, got ${contextHash.length}`);
  }
  if (validUntil <= issuedAt) throw new Error("valid_until must be strictly after issued_at");
  const v: PolicyVerdict = {
    version: 1,
    verdict_id: verdictID,
    agent_id: agentID,
    scope,
    allow,
    context_hash: contextHash,
    issued_at: issuedAt,
    valid_until: validUntil,
    mac: new Uint8Array(0),
  };
  v.mac = hmac(sha256, policySecret, policyVerdictSignBytes(v));
  return v;
}

/**
 * Check a PolicyVerdict's HMAC and validity. Returns null iff:
 *   - MAC matches `policySecret`
 *   - within [issued_at, valid_until] at `now`
 *   - agent_id / scope / context_hash match the caller's expectation
 *   - allow == true
 *
 * Returns `"policy_verdict_denied: ..."` when the MAC is valid but
 * `allow == false` (explicit cached deny).
 */
export function verifyPolicyVerdict(
  v: PolicyVerdict,
  policySecret: Uint8Array,
  expectedAgentID: string,
  expectedScope: string,
  expectedContextHash: Uint8Array,
  now: number,
): string | null {
  if (policySecret.length === 0) return "policy_secret must not be empty";
  if (v.version !== 1) return `unsupported version ${v.version}`;
  if (v.context_hash.length !== 32) {
    return `context_hash must be 32 bytes, got ${v.context_hash.length}`;
  }
  if (v.mac.length !== 32) {
    return `mac must be 32 bytes, got ${v.mac.length}`;
  }
  const want = hmac(sha256, policySecret, policyVerdictSignBytes(v));
  if (!constantTimeEqual(want, v.mac)) return "policy_verdict MAC invalid";
  if (now < v.issued_at) return "policy_verdict not yet valid";
  if (now > v.valid_until) return "policy_verdict expired";
  if (v.agent_id !== expectedAgentID) return "policy_verdict agent_id mismatch";
  if (v.scope !== expectedScope) return "policy_verdict scope mismatch";
  if (!constantTimeEqual(v.context_hash, expectedContextHash)) {
    return "policy_verdict context_hash mismatch";
  }
  if (!v.allow) {
    return `policy_verdict_denied: cached deny for scope "${v.scope}"`;
  }
  return null;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
