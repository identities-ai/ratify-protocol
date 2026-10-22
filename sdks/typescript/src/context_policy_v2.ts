// Protocol v2 verifier-owned context policy and its post-claim assessment.
// Port of context_policy_v2.go.

import { sha384 } from "@noble/hashes/sha2";

import { bytesEqual, canonicalJSONV2, hexOf, isWellFormedString } from "./json_v2.js";
import type { ProofBundleV2 } from "./protocol_v2_wire.js";
import { validPrefixedDigestV2 } from "./verification_receipt_v2.js";
import { classified } from "./errors_v2.js";

const VERIFY_SESSION_CONTEXT_PROFILE_V2 = "ratify.verify.session-context/v1";
const VERIFY_SESSION_CONTEXT_FIELDS_V2 = ["verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"];

const policyBrand = Symbol("V2ContextPolicy");

/**
 * A validated, fingerprinted verifier context policy. The receipt digest is
 * derived from the canonical policy fields, never supplied by callers.
 * Construct with newV2ContextPolicy only.
 */
export interface V2ContextPolicy {
  readonly [policyBrand]: true;
  readonly profile: string;
  readonly requireBound: boolean;
  readonly requiredFields: readonly string[];
  /** Per-invocation authenticated context; excluded from the digest. */
  readonly expectedSessionContext: Uint8Array | null;
  readonly digest: string;
}

export interface V2ContextPolicyAssessment {
  assessment: string;
  policyDigest: string | null;
  status: string;
  reason: string;
  detail: string;
}

export function newV2ContextPolicy(
  profile: string,
  requireBound: boolean,
  requiredFields: readonly string[] | null,
  expectedSessionContext: Uint8Array | null,
): V2ContextPolicy {
  return classified("configuration_invalid", () => {
    if (typeof profile !== "string" || profile === "" || !isWellFormedString(profile)) {
      throw new Error("v2 context policy profile must be non-empty valid UTF-8");
    }
    const fields = [...(requiredFields ?? [])];
    const seen = new Set<string>();
    fields.forEach((field, i) => {
      if (typeof field !== "string" || field === "" || !isWellFormedString(field)) {
        throw new Error(`v2 context policy field ${i} is empty or invalid UTF-8`);
      }
      if (seen.has(field)) throw new Error(`v2 context policy has duplicate field ${JSON.stringify(field)}`);
      seen.add(field);
    });
    const expectedLength = expectedSessionContext?.length ?? 0;
    if (requireBound && (fields.length === 0 || expectedLength !== 32)) {
      throw new Error("bound v2 context policy requires fields and a 32-byte authenticated context");
    }
    if (!requireBound && expectedLength !== 0) throw new Error("unbound v2 context policy cannot carry an expected context");
    if (profile === VERIFY_SESSION_CONTEXT_PROFILE_V2 &&
        (!requireBound || fields.length !== VERIFY_SESSION_CONTEXT_FIELDS_V2.length || fields.some((f, i) => f !== VERIFY_SESSION_CONTEXT_FIELDS_V2[i]))) {
      throw new Error("Ratify Verify session-context policy must require the canonical field set");
    }
    const encoded = canonicalJSONV2({ profile, require_bound: requireBound, required_fields: fields, version: 1 });
    return Object.freeze({
      [policyBrand]: true as const,
      profile,
      requireBound,
      requiredFields: Object.freeze(fields),
      expectedSessionContext: expectedSessionContext === null || expectedSessionContext === undefined ? null : Uint8Array.from(expectedSessionContext),
      digest: "sha384:" + hexOf(sha384(encoded)),
    });
  });
}

export function isValidV2ContextPolicy(p: V2ContextPolicy | null | undefined): p is V2ContextPolicy {
  return !!p && p[policyBrand] === true && typeof p.digest === "string" && p.digest !== "" && validPrefixedDigestV2(p.digest);
}

export function sameV2ContextPolicy(a: V2ContextPolicy | null | undefined, b: V2ContextPolicy | null | undefined): boolean {
  return isValidV2ContextPolicy(a) && isValidV2ContextPolicy(b) && a.profile === b.profile && a.requireBound === b.requireBound &&
    a.digest === b.digest && a.requiredFields.length === b.requiredFields.length &&
    a.requiredFields.every((f, i) => f === b.requiredFields[i]) && bytesEqual(a.expectedSessionContext, b.expectedSessionContext);
}

function failure(assessment: string, status: string, reason: string, detail: string): V2ContextPolicyAssessment {
  return { assessment, policyDigest: null, status, reason, detail };
}

/** Applies a validated verifier context policy after preflight and claim. */
export function evaluateProofBundleV2ContextPolicy(bundle: ProofBundleV2 | null, policy: V2ContextPolicy | null): V2ContextPolicyAssessment {
  if (!bundle) return failure("unverified", "authorization_unverified", "action_context_unverified", "proof bundle is unavailable");
  const bound = bundle.session_context !== null;
  if (!policy) {
    return failure(bound ? "unverified" : "unbound", "authorization_unverified", "action_context_unverified", "no caller-authenticated context policy is configured");
  }
  if (!isValidV2ContextPolicy(policy)) {
    return failure(bound ? "unverified" : "unbound", "authorization_unverified", "action_context_unverified", "no valid caller-authenticated context policy is configured");
  }
  const digest = policy.digest;
  if (!policy.requireBound) return { assessment: "not_required", policyDigest: digest, status: "passed", reason: "", detail: "" };
  if (!bound) {
    return { assessment: "unverified", policyDigest: digest, status: "authorization_unverified", reason: "action_context_unverified", detail: "required session context is absent" };
  }
  if (!bytesEqual(bundle.session_context, policy.expectedSessionContext)) {
    return { assessment: "mismatch", policyDigest: digest, status: "constraint_denied", reason: "constraint_denied", detail: "proof session context does not match the verifier's authenticated context" };
  }
  return { assessment: "bound", policyDigest: digest, status: "passed", reason: "", detail: "" };
}
