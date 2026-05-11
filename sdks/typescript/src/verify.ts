// Verify — the core verifier. Mirrors the Go reference verify.go exactly.
// v1 uses hybrid signatures (Ed25519 + ML-DSA-65); both component signatures
// must verify for any signature check to pass.

import {
  CHALLENGE_WINDOW_SECONDS,
  ED25519_PUBLIC_KEY_SIZE,
  MAX_DELEGATION_CHAIN_DEPTH,
  MLDSA65_PUBLIC_KEY_SIZE,
  PROTOCOL_VERSION,
  type DelegationCert,
  type HybridPublicKey,
  type HybridSignature,
  type IdentityStatus,
  type ProofBundle,
  type SessionToken,
  type TransactionReceipt,
  type TransactionReceiptResult,
  type VerifyOptions,
  type VerifyReceiptOptions,
  type VerifyResult,
} from "./types.js";
import {
  verifyDelegationSignatureE,
  verifyChallengeSignatureE,
  verifySessionTokenE,
  transactionReceiptSignBytes,
  verifyBoth,
} from "./crypto.js";
import { intersectScopes, SCOPE_IDENTITY_DELEGATE } from "./scope.js";
import { evaluateConstraints } from "./constraints.js";
import { verifierContextHash, verifyPolicyVerdict } from "./receipts.js";

/**
 * Validate a ProofBundle against the Ratify Protocol.
 *
 * Checks in order:
 *   1. Structural: non-empty chain, chain depth ≤ MAX_DELEGATION_CHAIN_DEPTH,
 *      challenge present, agent hybrid pubkey component sizes correct.
 *   2. Agent binding: bundle.agent_pub_key / agent_id match the leaf cert's
 *      subject_pub_key / subject_id.
 *   3. For each cert in chain:
 *      a. version == PROTOCOL_VERSION
 *      b. now ∈ [issued_at, expires_at]
 *      c. not revoked (per opts.is_revoked)
 *      d. hybrid signature valid — BOTH Ed25519 and ML-DSA-65 components
 *         verify against declared issuer_pub_key
 *      e. chain linkage: cert[i].issuer_{id,pub_key} == cert[i+1].subject_{id,pub_key}
 *   4. Challenge freshness: challenge age ∈ [0, CHALLENGE_WINDOW_SECONDS].
 *   5. Challenge signature: hybrid signature valid against agent_pub_key.
 *   6. Effective scope: required_scope ∈ intersectScopes(all cert scopes).
 *
 * Single-component failure fails the whole signature (fail-closed).
 */
export async function verifyBundle(
  bundle: ProofBundle,
  opts: VerifyOptions = {},
): Promise<VerifyResult> {
  const res = await _verifyBundle(bundle, opts);
  if (opts.audit) {
    try {
      await opts.audit.logVerification(res, bundle);
    } catch (e) {
      // Ignored per reference implementation.
    }
  }
  return res;
}

async function _verifyBundle(
  bundle: ProofBundle,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  // --- Basic structure ---
  if (!bundle.delegations || bundle.delegations.length === 0) {
    return invalid("no_delegations", "proof bundle contains no delegation certificates");
  }
  if (bundle.delegations.length > MAX_DELEGATION_CHAIN_DEPTH) {
    return invalid("chain_too_deep", "delegation chain exceeds maximum depth");
  }
  if (!bundle.challenge || bundle.challenge.length === 0) {
    return invalid("no_challenge", "proof bundle contains no challenge");
  }
  if (bundle.session_context && bundle.session_context.length !== 32) {
    return invalid(
      "invalid_session_context",
      `session_context must be 32 bytes, got ${bundle.session_context.length}`,
    );
  }
  if (opts.session_context && opts.session_context.length !== 32) {
    return invalid(
      "invalid_session_context",
      `verify option session_context must be 32 bytes, got ${opts.session_context.length}`,
    );
  }
  if (opts.session_context) {
    if (!bundle.session_context) {
      return invalid(
        "missing_session_context",
        "verifier requires a session-bound challenge but bundle has no session_context",
      );
    }
    if (!bytesEqual(bundle.session_context, opts.session_context)) {
      return invalid(
        "session_context_mismatch",
        "bundle session_context does not match verifier context",
      );
    }
  } else if (bundle.session_context) {
    return invalid(
      "session_context_unverifiable",
      "bundle has session_context but verifier did not provide one",
    );
  }

  // --- v1.1 stream binding checks (SPEC §5.8, §6.4.2) ---
  const bundleStreamID = bundle.stream_id ?? new Uint8Array(0);
  const bundleStreamSeq = bundle.stream_seq ?? 0;
  if (bundleStreamID.length !== 0 && bundleStreamID.length !== 32) {
    return invalid(
      "invalid_stream_id",
      `stream_id must be 32 bytes, got ${bundleStreamID.length}`,
    );
  }
  if (bundleStreamID.length === 0 && bundleStreamSeq !== 0) {
    return invalid("invalid_stream_seq", "stream_seq set without stream_id");
  }
  if (bundleStreamID.length !== 0 && bundleStreamSeq < 1) {
    return invalid(
      "invalid_stream_seq",
      `stream_seq must be >=1, got ${bundleStreamSeq}`,
    );
  }
  if (opts.stream) {
    if (!opts.stream.stream_id || opts.stream.stream_id.length !== 32) {
      return invalid(
        "invalid_stream_id",
        `verify option stream_id must be 32 bytes, got ${opts.stream.stream_id?.length ?? 0}`,
      );
    }
    if (bundleStreamID.length === 0) {
      return invalid(
        "missing_stream_context",
        "verifier requires a stream-bound challenge but bundle has no stream_id",
      );
    }
    if (!bytesEqual(bundleStreamID, opts.stream.stream_id)) {
      return invalid(
        "stream_id_mismatch",
        "bundle stream_id does not match verifier stream context",
      );
    }
    const expected = opts.stream.last_seen_seq + 1;
    if (bundleStreamSeq <= opts.stream.last_seen_seq) {
      return invalid(
        "stream_seq_replay",
        `stream_seq ${bundleStreamSeq} already seen (last=${opts.stream.last_seen_seq})`,
      );
    }
    if (bundleStreamSeq !== expected) {
      return invalid(
        "stream_seq_skip",
        `stream_seq ${bundleStreamSeq} skips expected ${expected}`,
      );
    }
  } else if (bundleStreamID.length !== 0) {
    return invalid(
      "stream_context_unverifiable",
      "bundle has stream_id but verifier did not provide a stream context",
    );
  }
  const agentKeyErr = validateHybridPubKeyLens(bundle.agent_pub_key, "agent");
  if (agentKeyErr) return invalid("invalid_agent_key", agentKeyErr);

  const firstCert = bundle.delegations[0]!;
  // The human root — issuer of the last cert in the chain. Consistent across
  // success and failure paths so audit logs always report the principal.
  const humanID = bundle.delegations[bundle.delegations.length - 1]!.issuer_id;

  if (!hybridPubKeyEqual(bundle.agent_pub_key, firstCert.subject_pub_key)) {
    return invalid("key_mismatch", "agent public key does not match delegation subject");
  }
  if (bundle.agent_id !== firstCert.subject_id) {
    return invalid("id_mismatch", "agent ID does not match delegation subject ID");
  }

  if (opts.force_revocation_check && !opts.is_revoked && !opts.revocation) {
    return invalid(
      "force_revocation_no_callback",
      "force_revocation_check is true but neither is_revoked nor revocation provider is set",
    );
  }

  // --- Per-cert checks ---
  for (let i = 0; i < bundle.delegations.length; i++) {
    const cert: DelegationCert = bundle.delegations[i]!;

    if (cert.version !== PROTOCOL_VERSION) {
      return invalid("version_mismatch", `cert ${i} has unsupported version ${cert.version}`);
    }
    if (now > cert.expires_at) {
      return expired(humanID, bundle.agent_id);
    }
    if (now < cert.issued_at) {
      return invalid("not_yet_valid", `cert ${i} is not yet valid`);
    }
    // Revocation: provider (SPEC §17.1) takes precedence over legacy closure.
    if (opts.revocation) {
      const [rev, revErr] = await opts.revocation.isRevoked(cert.cert_id);
      if (revErr) {
        return invalid(
          "revocation_error",
          `cert ${i}: revocation lookup failed: ${revErr.message ?? revErr}`,
        );
      }
      if (rev) {
        return revoked(humanID, bundle.agent_id);
      }
    } else if (opts.is_revoked && opts.is_revoked(cert.cert_id)) {
      return revoked(humanID, bundle.agent_id);
    }
    const sigErr = await verifyDelegationSignatureE(cert);
    if (sigErr !== null) {
      return invalid("bad_signature", `cert ${i}: ${sigErr}`);
    }

    // Constraint evaluation — each cert's first-class constraints must all
    // pass against the caller-supplied VerifierContext. Fail-closed.
    // Route to the specific identity_status via sentinel prefix in the
    // returned error. Matches Go/Python/Rust — see SPEC §5.9 enum table.
    const constraintErr = await evaluateConstraints(
      cert,
      opts.context ?? {},
      now,
      opts.constraint_evaluators,
    );
    if (constraintErr !== null) {
      let status: IdentityStatus = "constraint_denied";
      if (constraintErr.includes("constraint_unverifiable")) {
        status = "constraint_unverifiable";
      } else if (constraintErr.includes("constraint_unknown")) {
        status = "constraint_unknown";
      }
      return failWithStatus(status, `cert ${i}: ${constraintErr}`);
    }

    // Chain linkage: each cert's subject must match the next cert's issuer
    if (i + 1 < bundle.delegations.length) {
      const next = bundle.delegations[i + 1]!;
      if (cert.issuer_id !== next.subject_id) {
        return invalid("broken_chain", `cert ${i} issuer does not match cert ${i + 1} subject`);
      }
      if (!hybridPubKeyEqual(cert.issuer_pub_key, next.subject_pub_key)) {
        return invalid(
          "broken_chain_keys",
          `cert ${i} issuer key does not match cert ${i + 1} subject key`,
        );
      }
      // Sub-delegation gate: parent cert must have explicitly granted
      // identity:delegate — sensitive, never introduced by wildcard expansion.
      if (!next.scope.includes(SCOPE_IDENTITY_DELEGATE)) {
        return failWithStatus(
          "delegation_not_authorized",
          `cert ${i} issued by a subject whose parent cert ${i + 1} did not grant "${SCOPE_IDENTITY_DELEGATE}"`,
        );
      }
    }
  }

  // --- Liveness (challenge freshness + hybrid signature) ---
  const challengeAge = now - bundle.challenge_at;
  if (challengeAge < 0 || challengeAge > CHALLENGE_WINDOW_SECONDS) {
    return invalid(
      "stale_challenge",
      `challenge is ${challengeAge} seconds old (max ${CHALLENGE_WINDOW_SECONDS})`,
    );
  }
  const challengeSigErr = await verifyChallengeSignatureE(
    bundle.challenge,
    bundle.challenge_at,
    bundle.challenge_sig,
    bundle.agent_pub_key,
    bundle.session_context,
    bundle.stream_id,
    bundle.stream_seq,
  );
  if (challengeSigErr !== null) {
    return invalid(
      "bad_challenge_sig",
      `challenge signature verification failed: ${challengeSigErr}`,
    );
  }

  // --- Effective scope (intersection across chain) ---
  const scopeLists = bundle.delegations.map((c) => c.scope);
  const effective = intersectScopes(...scopeLists);

  if (opts.required_scope) {
    if (!effective.includes(opts.required_scope)) {
      return failWithStatus(
        "scope_denied",
        `required scope "${opts.required_scope}" not in effective delegation scope`,
      );
    }
  }

  const res: VerifyResult = {
    valid: true,
    human_id: humanID,
    agent_id: bundle.agent_id,
    granted_scope: effective,
    identity_status: "authorized_agent",
  };

  // --- Anchor resolution (SPEC §17.8) ---
  // Best-effort: populate anchor on the success result so downstream
  // AuditProviders observe an identity-bound receipt. Resolver errors are
  // non-fatal — the bundle still verifies.
  if (opts.anchor_resolver) {
    try {
      const anchor = await opts.anchor_resolver.resolveAnchor(humanID);
      if (anchor) res.anchor = anchor;
    } catch {
      // intentional swallow
    }
  }

  // --- Advanced Policy Gating (SPEC §17.2 / §17.6) ---
  //
  // Fast path: if a PolicyVerdict is supplied AND verifies cleanly, skip the
  // live Policy provider entirely. Stale/mismatched verdicts fall back to
  // live policy.
  if (opts.policy_verdict && opts.required_scope && opts.policy_secret) {
    const ctxHash = verifierContextHash(opts.context ?? {});
    const verdictErr = verifyPolicyVerdict(
      opts.policy_verdict,
      opts.policy_secret,
      bundle.agent_id,
      opts.required_scope,
      ctxHash,
      now,
    );
    if (verdictErr === null) {
      // Cached allow — skip live policy.
      return res;
    }
    if (verdictErr.startsWith("policy_verdict_denied")) {
      return failWithStatus("scope_denied", "policy verdict (cached) denied access");
    }
    // else: fall through to live policy.
  }

  if (opts.policy) {
    try {
      const ok = await opts.policy.evaluatePolicy(bundle, opts.context ?? {});
      if (!ok) {
        return failWithStatus("scope_denied", "advanced policy evaluation denied access");
      }
    } catch (err: any) {
      return invalid("policy_error", `advanced policy evaluation failed: ${err}`);
    }
  }

  return res;
}

// ============================================================================
// Hybrid public key helpers
// ============================================================================

function hybridPubKeyEqual(a: HybridPublicKey, b: HybridPublicKey): boolean {
  return bytesEqual(a.ed25519, b.ed25519) && bytesEqual(a.ml_dsa_65, b.ml_dsa_65);
}

function validateHybridPubKeyLens(
  pub: HybridPublicKey,
  label: string,
): string | null {
  if (pub.ed25519.length !== ED25519_PUBLIC_KEY_SIZE) {
    return `${label} Ed25519 public key has wrong length: ${pub.ed25519.length}`;
  }
  if (pub.ml_dsa_65.length !== MLDSA65_PUBLIC_KEY_SIZE) {
    return `${label} ML-DSA-65 public key has wrong length: ${pub.ml_dsa_65.length}`;
  }
  return null;
}

// ============================================================================
// Result constructors
// ============================================================================

function invalid(reason: string, msg: string): VerifyResult {
  return {
    valid: false,
    identity_status: "invalid",
    error_reason: `${reason}: ${msg}`,
  };
}

// failWithStatus is used when the failure type maps to its own identity_status.
// Mirrors Go's failWithStatus helper — prefix of error_reason is the status.
function failWithStatus(status: IdentityStatus, msg: string): VerifyResult {
  return {
    valid: false,
    identity_status: status,
    error_reason: `${status}: ${msg}`,
  };
}

function expired(humanID: string, agentID: string): VerifyResult {
  return {
    valid: false,
    human_id: humanID,
    agent_id: agentID,
    identity_status: "expired",
    error_reason: "delegation certificate has expired",
  };
}

function revoked(humanID: string, agentID: string): VerifyResult {
  return {
    valid: false,
    human_id: humanID,
    agent_id: agentID,
    identity_status: "revoked",
    error_reason: "delegation certificate has been revoked",
  };
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ============================================================================
// v1.1 session cert cache (ROADMAP 2.3) streamed-turn verification
// ============================================================================

/**
 * Fast-path verifier for streamed turns that present a SessionToken in place
 * of the full cert chain. Checks the HMAC, token validity window, challenge
 * freshness, and hybrid challenge signature against the token's agent pubkey.
 * The chain is NOT re-verified — that's the point of the token.
 */
export async function verifyStreamedTurn(
  token: SessionToken,
  sessionSecret: Uint8Array,
  challenge: Uint8Array,
  challengeAt: number,
  challengeSig: HybridSignature,
  sessionContext: Uint8Array | undefined,
  streamID: Uint8Array | undefined,
  streamSeq: number | undefined,
  now: number,
): Promise<VerifyResult> {
  if (!token) return invalid("nil_session_token", "session_token must not be nil");
  const mac = verifySessionTokenE(token, sessionSecret, now);
  if (mac !== null) return invalid("session_token_invalid", mac);
  if (!challenge || challenge.length === 0) {
    return invalid("no_challenge", "streamed turn contains no challenge");
  }
  if (sessionContext && sessionContext.length !== 0 && sessionContext.length !== 32) {
    return invalid(
      "invalid_session_context",
      `session_context must be 32 bytes, got ${sessionContext.length}`,
    );
  }
  if (streamID && streamID.length !== 0 && streamID.length !== 32) {
    return invalid(
      "invalid_stream_id",
      `stream_id must be 32 bytes, got ${streamID.length}`,
    );
  }
  if (streamID && streamID.length !== 0 && (streamSeq ?? 0) < 1) {
    return invalid(
      "invalid_stream_seq",
      `stream_seq must be >=1, got ${streamSeq ?? 0}`,
    );
  }
  const challengeAge = now - challengeAt;
  if (challengeAge < 0 || challengeAge > CHALLENGE_WINDOW_SECONDS) {
    return invalid(
      "stale_challenge",
      `challenge is ${challengeAge} seconds old (max ${CHALLENGE_WINDOW_SECONDS})`,
    );
  }
  const sigErr = await verifyChallengeSignatureE(
    challenge,
    challengeAt,
    challengeSig,
    token.agent_pub_key,
    sessionContext,
    streamID,
    streamSeq,
  );
  if (sigErr !== null) {
    return invalid(
      "bad_challenge_sig",
      `challenge signature verification failed: ${sigErr}`,
    );
  }
  return {
    valid: true,
    human_id: token.human_id,
    agent_id: token.agent_id,
    granted_scope: [...token.granted_scope],
    identity_status: "authorized_agent",
  };
}

// ============================================================================
// v1.1 TransactionReceipt verification (SPEC §5.14)
// ============================================================================

/**
 * Verify a TransactionReceipt's envelope: version, structural checks,
 * party uniqueness, signature coverage, per-party ProofBundle verification,
 * agent_id/pubkey consistency, and party signature verification over the
 * canonical signable. Atomic: any single failure fails the whole receipt.
 */
export async function verifyTransactionReceipt(
  receipt: TransactionReceipt,
  opts: VerifyReceiptOptions = {},
): Promise<TransactionReceiptResult> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  // --- Structural checks ---
  if (receipt.version !== PROTOCOL_VERSION) {
    return { valid: false, error_reason: `version_mismatch: unsupported version ${receipt.version}` };
  }
  if (!receipt.transaction_id) {
    return { valid: false, error_reason: "missing_transaction_id: transaction_id must not be empty" };
  }
  if (!receipt.terms_schema_uri) {
    return { valid: false, error_reason: "missing_terms_schema_uri: terms_schema_uri must not be empty" };
  }
  if (!receipt.terms_canonical_json || receipt.terms_canonical_json.length === 0) {
    return { valid: false, error_reason: "missing_terms_canonical_json: terms_canonical_json must not be empty" };
  }
  if (!receipt.parties || receipt.parties.length === 0) {
    return { valid: false, error_reason: "no_parties: receipt must list at least one party" };
  }

  // Party IDs must be unique.
  const partyIdx = new Map<string, number>();
  for (let i = 0; i < receipt.parties.length; i++) {
    const p = receipt.parties[i]!;
    if (!p.party_id) {
      return { valid: false, error_reason: `empty_party_id: party ${i} has no party_id` };
    }
    if (partyIdx.has(p.party_id)) {
      return { valid: false, error_reason: `duplicate_party_id: "${p.party_id}" listed more than once` };
    }
    partyIdx.set(p.party_id, i);
  }

  // Each party must have exactly one signature; no extras.
  const sigByParty = new Map<string, number>();
  for (let i = 0; i < receipt.party_signatures.length; i++) {
    const s = receipt.party_signatures[i]!;
    if (!partyIdx.has(s.party_id)) {
      return { valid: false, error_reason: `unknown_party_signature: signature ${i} references unknown party_id "${s.party_id}"` };
    }
    if (sigByParty.has(s.party_id)) {
      return { valid: false, error_reason: `duplicate_party_signature: party "${s.party_id}" has multiple signatures` };
    }
    sigByParty.set(s.party_id, i);
  }
  for (const p of receipt.parties) {
    if (!sigByParty.has(p.party_id)) {
      return { valid: false, error_reason: `missing_party_signature: party "${p.party_id}" has no signature` };
    }
  }

  // Canonical signable bytes.
  const signable = transactionReceiptSignBytes(receipt);

  const partyResults: VerifyResult[] = new Array(receipt.parties.length);
  for (let i = 0; i < receipt.parties.length; i++) {
    const p = receipt.parties[i]!;

    // agent_id / agent_pub_key consistency with proof_bundle.
    if (p.proof_bundle.agent_id !== p.agent_id) {
      return {
        valid: false,
        error_reason: `party_agent_id_mismatch: party "${p.party_id}" proof_bundle.agent_id="${p.proof_bundle.agent_id}" != party.agent_id="${p.agent_id}"`,
      };
    }
    if (!hybridPubKeyEqual(p.proof_bundle.agent_pub_key, p.agent_pub_key)) {
      return {
        valid: false,
        error_reason: `party_agent_key_mismatch: party "${p.party_id}" proof_bundle.agent_pub_key != party.agent_pub_key`,
      };
    }

    // Verify the party's ProofBundle.
    let bundleOpts: VerifyOptions = {};
    if (opts.party_verify_options) {
      bundleOpts = opts.party_verify_options(p.role);
    }
    bundleOpts.now = now;
    const r = await verifyBundle(p.proof_bundle, bundleOpts);
    partyResults[i] = r;
    if (!r.valid) {
      return {
        valid: false,
        error_reason: `party_bundle_invalid: party "${p.party_id}" status=${r.identity_status} reason=${r.error_reason}`,
        party_results: partyResults,
      };
    }

    // Verify party signature over canonical signable.
    const sigIdx = sigByParty.get(p.party_id)!;
    const sig = receipt.party_signatures[sigIdx]!.signature;
    const sigErr = await verifyBoth(signable, sig, p.agent_pub_key);
    if (sigErr !== null) {
      return {
        valid: false,
        error_reason: `party_signature_invalid: party "${p.party_id}": ${sigErr}`,
        party_results: partyResults,
      };
    }
  }

  return { valid: true, party_results: partyResults };
}
