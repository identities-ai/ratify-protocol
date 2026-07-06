// Ratify Protocol v1 — TypeScript type definitions.
//
// Mirrors the Go reference types at module root of github.com/identities-ai/ratify-protocol.
// v1 uses hybrid cryptography: every signed object carries a HybridSignature
// composed of one Ed25519 and one ML-DSA-65 (FIPS 204) component. Both must
// verify for the signature to be accepted.
//
// Field names use snake_case to match the canonical JSON wire format directly.

export const PROTOCOL_VERSION = 1;

/**
 * NO_EXPIRY_SENTINEL is the `expires_at` value that means "no expiry (until
 * revoked)": 4070908799 = 2099-12-31 23:59:59 UTC. DelegationCert.expires_at
 * is a required integer with no null representation, so open-ended
 * delegations carry this sentinel in the signed bytes. Conformant
 * implementations MUST treat a cert with expires_at === NO_EXPIRY_SENTINEL
 * as "no expiry (until revoked)" in display and policy evaluation — NOT as a
 * literal 2099 expiry. Verification is unchanged: the sentinel is a future
 * timestamp, so the temporal check passes; revocation is the sole
 * termination mechanism for such certs. See SPEC §5.7.
 */
export const NO_EXPIRY_SENTINEL = 4070908799;

export const MAX_DELEGATION_CHAIN_DEPTH = 3;
export const CHALLENGE_WINDOW_SECONDS = 300;

// Algorithm component byte sizes.
export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_SIGNATURE_SIZE = 64;
export const MLDSA65_PUBLIC_KEY_SIZE = 1952;
export const MLDSA65_SIGNATURE_SIZE = 3309;

/**
 * HybridPublicKey pairs an Ed25519 public key with an ML-DSA-65 public key.
 * Canonical JSON form (keys in lex order):
 *
 *     {"ed25519":"<base64-32-bytes>","ml_dsa_65":"<base64-1952-bytes>"}
 */
export interface HybridPublicKey {
  ed25519: Uint8Array;    // 32 bytes
  ml_dsa_65: Uint8Array;  // 1952 bytes (FIPS 204 ML-DSA-65)
}

/**
 * HybridSignature is an Ed25519 signature paired with an ML-DSA-65 signature
 * over the same canonical bytes. Both MUST verify for the signature to be
 * considered valid.
 */
export interface HybridSignature {
  ed25519: Uint8Array;    // 64 bytes
  ml_dsa_65: Uint8Array;  // 3309 bytes
}

/**
 * HybridPrivateKey holds both component private keys. Never serialized to
 * the wire. Kept on the principal's device or inside the agent's process.
 */
export interface HybridPrivateKey {
  ed25519: Uint8Array;    // 32-byte seed (Ed25519 derives 64-byte expanded key on demand)
  ml_dsa_65: Uint8Array;  // ML-DSA-65 secret key bytes (@noble/post-quantum representation)
}

/** An optional external binding that raises the assurance level of a HumanRoot. */
export interface Anchor {
  type: string;
  provider: string;
  reference: string;      // opaque, not PII
  verified_at: number;    // unix seconds
}

/** The master identity for a human (or tenant admin). */
export interface HumanRoot {
  id: string;             // hex(SHA-256(ed25519_pub || ml_dsa_65_pub)[:16])
  public_key: HybridPublicKey;
  created_at: number;
  anchors?: Anchor[];
}

/** An AI agent's identity. Agents generate their own hybrid keypairs. */
export interface AgentIdentity {
  id: string;
  public_key: HybridPublicKey;
  name: string;
  agent_type: string;
  created_at: number;
}

/**
 * A signed delegation from a principal (human or another agent) to an agent.
 * The signature is hybrid; both components must verify against the issuer's
 * HybridPublicKey for the cert to be accepted.
 *
 * `scope` answers *what* the agent may do. `constraints` answer *where /
 * when / how much* — first-class bounds evaluated at verify time against a
 * caller-supplied VerifierContext.
 */
export interface DelegationCert {
  cert_id: string;
  version: number;
  issuer_id: string;
  issuer_pub_key: HybridPublicKey;
  subject_id: string;
  subject_pub_key: HybridPublicKey;
  scope: string[];
  /** Empty array if none; always present in canonical JSON (never absent). */
  constraints: Constraint[];
  issued_at: number;
  expires_at: number;
  signature: HybridSignature;
}

/**
 * Reports whether the cert carries NO_EXPIRY_SENTINEL, meaning "no expiry
 * (until revoked)". Callers rendering expiry to users or applying lifetime
 * policy caps MUST branch on this rather than treating the sentinel as a
 * real 2099 timestamp.
 */
export function isNoExpiry(cert: DelegationCert): boolean {
  return cert.expires_at === NO_EXPIRY_SENTINEL;
}

/**
 * A first-class bound on when / where / how much an agent may exercise its
 * scopes. Verifier evaluates each constraint against a caller-supplied
 * VerifierContext; missing context for a required field fails closed.
 *
 * Wire format is a tagged JSON object. Unknown `type` values MUST be rejected.
 */
export interface Constraint {
  type: ConstraintType;

  // Geo parameters.
  lat?: number;
  lon?: number;
  radius_m?: number;
  points?: [number, number][]; // geo_polygon: [[lat, lon], ...]
  min_lat?: number;
  min_lon?: number;
  max_lat?: number;
  max_lon?: number;
  min_alt_m?: number;
  max_alt_m?: number;

  // Time window.
  start?: string; // "HH:MM" 24-hour
  end?: string;
  tz?: string; // IANA zone name

  // Magnitude.
  max_mps?: number;
  max_amount?: number;
  currency?: string; // ISO 4217

  // Rate.
  count?: number;
  window_s?: number;
}

export type ConstraintType =
  | "geo_circle"
  | "geo_polygon"
  | "geo_bbox"
  | "time_window"
  | "max_speed_mps"
  | "max_amount"
  | "max_rate";

/**
 * Application-supplied inputs needed to evaluate first-class constraints.
 * Fields are optional; a cert bearing a constraint whose required context is
 * absent will fail closed with `constraint_unverifiable`.
 */
export interface VerifierContext {
  // Agent position — required by geo_circle, geo_polygon, geo_bbox.
  current_lat?: number;
  current_lon?: number;
  current_alt_m?: number;

  // Agent velocity — required by max_speed_mps.
  current_speed_mps?: number;

  // Transaction — required by max_amount.
  requested_amount?: number;
  requested_currency?: string;

  // Rate — required by max_rate.
  invocations_in_window?: (certID: string, windowS: number) => number;
}

/**
 * A bundle presented by an agent to a verifier. Used symmetrically in
 * human-agent and agent-agent flows.
 *
 * v1.1 optional stream binding: when `stream_id` and `stream_seq` are both
 * set, the bundle is "stream-bound" — it belongs to an ordered sequence of
 * interactions sharing a stream_id. Both are signed into the challenge bytes
 * (SPEC §6.4.2) so replay, reorder, or omission within the stream invalidate
 * the signature.
 */
export interface ProofBundle {
  agent_id: string;
  agent_pub_key: HybridPublicKey;
  delegations: DelegationCert[]; // [leaf, ..., root], depth 1..MAX_DELEGATION_CHAIN_DEPTH
  challenge: Uint8Array;
  challenge_at: number;
  challenge_sig: HybridSignature;
  /** Optional 32-byte v1.1 verifier/session/request binding. */
  session_context?: Uint8Array;
  /** Optional 32-byte v1.1 opaque stream identifier. Paired with stream_seq. */
  stream_id?: Uint8Array;
  /** Optional v1.1 monotonic sequence number (≥1 when stream_id is set). */
  stream_seq?: number;
}

/** A signed list of revoked cert IDs, served by the issuer. */
export interface RevocationList {
  issuer_id: string;
  updated_at: number;
  revoked_certs: string[];
  signature: HybridSignature;
}

/**
 * v1.1 revocation push: issuer sends a signed delta of newly revoked cert IDs.
 * The signature is hybrid; both components must verify against the issuer's
 * HybridPublicKey.
 */
export interface RevocationPush {
  issuer_id: string;
  seq_no: number;
  entries: string[];
  pushed_at: number;
  signature: HybridSignature;
}

/**
 * v1.1 witness append-only log entry (ROADMAP 3.2). A witness operator signs
 * an entry linking prev_hash -> entry_data -> timestamp.
 */
export interface WitnessEntry {
  prev_hash: Uint8Array;    // 32 bytes, zeros for genesis
  entry_data: Uint8Array;
  timestamp: number;
  witness_id: string;
  signature: HybridSignature;
}

/**
 * v1.1 verifier-issued credential that caches a verified chain for the
 * lifetime of a session. After a full Verify succeeds, the verifier MAY issue
 * a SessionToken binding the verified chain to its session. Subsequent turns
 * present the token plus a fresh challenge signature; the verifier checks the
 * HMAC and the challenge sig without re-verifying the chain.
 *
 * MAC = HMAC-SHA256(session_secret, sessionTokenSignBytes(token)). The
 * session_secret is private to the verifier and never leaves its trust
 * boundary.
 */
export interface SessionToken {
  version: number; // = PROTOCOL_VERSION
  session_id: string;
  agent_id: string;
  agent_pub_key: HybridPublicKey;
  human_id: string;
  granted_scope: string[]; // lex-sorted
  issued_at: number;
  valid_until: number;
  chain_hash: Uint8Array; // 32-byte SHA-256 of concatenated delegation sign bytes
  mac: Uint8Array;        // 32-byte HMAC-SHA256
}

/** Signed continuity statement from an old root key to a new root key. */
export interface KeyRotationStatement {
  version: number;
  old_id: string;
  old_pub_key: HybridPublicKey;
  new_id: string;
  new_pub_key: HybridPublicKey;
  rotated_at: number;
  reason: KeyRotationReason;
  signature_old: HybridSignature;
  signature_new: HybridSignature;
}

export type KeyRotationReason =
  | "routine"
  | "compromise_suspected"
  | "device_lost"
  | "recovery"
  | "other";

/** The deterministic result of verifyBundle(). Always check `valid` first. */
export interface VerifyResult {
  valid: boolean;
  human_id?: string;
  agent_id?: string;
  agent_name?: string;
  agent_type?: string;
  granted_scope?: string[];
  identity_status: IdentityStatus;
  error_reason?: string;
  /**
   * Resolved external-identity binding for the human_id (SPEC §17.8).
   * Populated only when the caller supplies an AnchorResolver and the bundle
   * verifies. Lets downstream AuditProviders record an unforgeable chain from
   * verification → identity attestation.
   */
  anchor?: Anchor;
}

export type IdentityStatus =
  | "verified_human"
  | "authorized_agent"
  | "expired"
  | "revoked"
  | "scope_denied"
  | "constraint_denied"
  | "constraint_unverifiable"
  | "constraint_unknown"
  | "delegation_not_authorized"
  | "invalid"
  | "unauthorized";

/**
 * v1.1 multi-party, atomic transaction receipt. Every listed party signs the
 * same canonical signable so altering or omitting any party invalidates every
 * other party's signature. Ratify verifies the envelope atomicity and party
 * signatures; application-level terms are opaque.
 */
export interface TransactionReceipt {
  version: number;
  transaction_id: string;
  created_at: number;
  terms_schema_uri: string;
  terms_canonical_json: Uint8Array;
  parties: ReceiptParty[];
  party_signatures: ReceiptPartySignature[];
}

/** One party to a TransactionReceipt. */
export interface ReceiptParty {
  party_id: string;
  role: string;
  agent_id: string;
  agent_pub_key: HybridPublicKey;
  proof_bundle: ProofBundle;
}

/** Hybrid signature by a party's agent key over the canonical signable. */
export interface ReceiptPartySignature {
  party_id: string;
  signature: HybridSignature;
}

/** Result of verifyTransactionReceipt(). */
export interface TransactionReceiptResult {
  valid: boolean;
  error_reason?: string;
  party_results?: VerifyResult[];
}

/** Options controlling per-party verification inside verifyTransactionReceipt. */
export interface VerifyReceiptOptions {
  /** Override "now" for testing. Unix seconds. Default: current time. */
  now?: number;
  /** Returns VerifyOptions for each party's ProofBundle, keyed by role. */
  party_verify_options?: (role: string) => VerifyOptions;
}

/**
 * RevocationProvider determines if a `cert_id` is currently revoked.
 * (SPEC §17.1)
 *
 * Implementations return `[isRevoked, errorOrNull]`. A non-null error fails
 * the bundle as `revocation_error` — SDKs MUST NOT treat a lookup failure
 * as "not revoked." On the verifier's hot path; implementations should be
 * O(1) at call time.
 */
export interface RevocationProvider {
  isRevoked(certID: string): Promise<[boolean, Error | null]>;
}

/**
 * PolicyProvider evaluates application-level policy that exceeds the
 * deterministic constraint logic defined in SPEC §5.7.2. (SPEC §17.2)
 *
 * Evaluated AFTER all cryptographic, temporal, revocation, constraint, and
 * scope-intersection checks pass. Resolving to `false` denies with
 * `scope_denied`; throwing fails closed as `policy_error`.
 */
export interface PolicyProvider {
  evaluatePolicy(bundle: ProofBundle, context: VerifierContext): Promise<boolean>;
}

/**
 * AuditProvider handles the persistence of verification receipts for
 * compliance and forensic analysis. (SPEC §17.3)
 *
 * Invoked on every `verify_bundle` call (success AND failure). Errors are
 * swallowed by the verifier — auditing MUST NOT alter the verdict.
 */
export interface AuditProvider {
  logVerification(result: VerifyResult, bundle: ProofBundle): Promise<void>;
}

/**
 * ConstraintEvaluator is a pluggable evaluator for extension constraint
 * types (SPEC §17.7). Built-in types (geo_circle, geo_polygon, geo_bbox,
 * time_window, max_speed_mps, max_amount, max_rate) are evaluated by the
 * SDK directly; an evaluator is consulted only for types the SDK does not
 * natively understand. Resolve to `true` to allow; resolve to `false` to
 * deny with `constraint_denied`; resolve to "unverifiable" string to route
 * to `constraint_unverifiable`; throw to deny with the thrown message.
 */
export interface ConstraintEvaluator {
  evaluate(
    c: Constraint,
    cert_id: string,
    context: VerifierContext,
    now_unix: number,
  ): Promise<true | false | "unverifiable">;
}

/**
 * AnchorResolver resolves a verified `human_id` to its external-identity
 * binding (SPEC §17.8). Implementations typically read from a verifier-local
 * identity directory.
 *
 * Errors and rejections are non-fatal: the verifier MUST NOT fail the bundle
 * because the resolver errored. The verifier silently leaves
 * `VerifyResult.anchor` undefined and continues.
 */
export interface AnchorResolver {
  resolveAnchor(human_id: string): Promise<Anchor | null>;
}

/**
 * PolicyVerdict is a v1.1 verifier-cached policy decision: a short-lived
 * HMAC-bound attestation that a given (agent_id, scope, context_hash) tuple
 * passed advanced policy evaluation at a specific moment (SPEC §17.6).
 *
 * Issued by a commercial policy backend with a private `policy_secret`,
 * checked locally by the verifier — letting subsequent calls within
 * `valid_until` accept the cached allow/deny without re-calling the backend.
 */
export interface PolicyVerdict {
  version: number;
  verdict_id: string;
  agent_id: string;
  scope: string;
  allow: boolean;
  context_hash: Uint8Array; // 32 bytes — SHA-256 of canonical VerifierContext
  issued_at: number;
  valid_until: number;
  mac: Uint8Array; // 32 bytes — HMAC-SHA256 over canonical signable bytes
}

/**
 * VerificationReceipt is a verifier-signed attestation that a specific
 * ProofBundle was verified at a specific moment with a specific outcome
 * (SPEC §17.5). It is the cryptographic complement of `AuditProvider`:
 * AuditProvider chooses what to do with verification events; a chain of
 * VerificationReceipts makes the event itself unforgeable.
 *
 * Receipts chain by `prev_hash` (SHA-256 of previous receipt's canonical
 * signable bytes) so a missing or backdated receipt is detectable. Genesis
 * uses 32 zero bytes.
 */
export interface VerificationReceipt {
  version: number;
  verifier_id: string;
  verifier_pub: HybridPublicKey;
  bundle_hash: Uint8Array;       // 32 bytes — SHA-256 of canonical bundle
  decision: IdentityStatus;
  human_id?: string;
  agent_id?: string;
  granted_scope?: string[];
  error_reason?: string;
  verified_at: number;            // unix seconds
  prev_hash: Uint8Array;          // 32 bytes; zeros for genesis
  signature: HybridSignature;
}

export interface VerifyOptions {
  /** The scope the verifier requires. Empty skips the scope check. */
  required_scope?: string;
  /**
   * Legacy v1 revocation closure.
   * @deprecated Use `revocation` (SPEC §17.1) instead. The closure has no
   * way to surface lookup failures; `revocation` returns `(bool, error)` and
   * fails closed on error. Slated for removal in v1.0.0-beta.1.
   */
  is_revoked?: (certID: string) => boolean;
  /**
   * Pluggable revocation provider (SPEC §17.1). Takes precedence over
   * `is_revoked`. A provider error fails the bundle as `revocation_error`.
   */
  revocation?: RevocationProvider;
  /** Advanced policy evaluator hook (SPEC §17.2). */
  policy?: PolicyProvider;
  /** Verification audit logging hook (SPEC §17.3). */
  audit?: AuditProvider;
  /**
   * Force a fresh revocation check for high-stakes endpoints. The SDK cannot
   * fetch revocation state itself; callers must provide is_revoked or a
   * revocation provider when this is true.
   */
  force_revocation_check?: boolean;
  /** Override "now" for testing. Unix seconds. Default: current time. */
  now?: number;
  /**
   * Verifier-reconstructed 32-byte v1.1 session context. If set, the bundle
   * must carry the same session_context and the challenge signature is checked
   * over challenge || challenge_at || session_context.
   */
  session_context?: Uint8Array;
  /**
   * Verifier-tracked stream binding for v1.1 stream-bound bundles. If set,
   * the bundle must carry stream_id equal to stream.stream_id and stream_seq
   * equal to stream.last_seen_seq+1. If absent, bundles carrying stream fields
   * are rejected as stream_context_unverifiable.
   */
  stream?: StreamContext;
  /**
   * Application inputs for evaluating first-class constraints (geo, time,
   * speed, amount, rate). Zero value is fine for certs that declare no
   * constraints; constraint-bearing certs fail closed if required context is
   * missing.
   */
  context?: VerifierContext;
  /**
   * Per-Verify registry of extension constraint evaluators (SPEC §17.7).
   * Keys are constraint type strings outside the built-in set; built-in
   * types are evaluated by the SDK directly. Types without a registered
   * evaluator still fail closed with `constraint_unknown`.
   */
  constraint_evaluators?: Record<string, ConstraintEvaluator>;
  /**
   * Fast-path cached policy decision (SPEC §17.6). When present and valid
   * (MAC matches `policy_secret`, within window, agent/scope/context match),
   * the verifier skips the live `policy` hook. Stale or invalid verdicts
   * fall back to live policy.
   */
  policy_verdict?: PolicyVerdict;
  /** HMAC secret used to verify `policy_verdict.mac`. */
  policy_secret?: Uint8Array;
  /**
   * Anchor resolver (SPEC §17.8). When set on a Valid=true verification,
   * the verifier looks up the human_id's external-identity binding and
   * populates `VerifyResult.anchor`. Resolver errors are non-fatal.
   */
  anchor_resolver?: AnchorResolver;
}

/**
 * Verifier state tracked per stream_id for v1.1 stream-bound bundles.
 * last_seen_seq is the highest sequence number the verifier has already
 * accepted for stream_id; zero means no turns accepted yet, so the first
 * valid bundle must carry stream_seq == 1.
 */
export interface StreamContext {
  stream_id: Uint8Array;
  last_seen_seq: number;
}
