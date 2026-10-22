// Protocol v2 language-neutral failure classes (Go errors_v2.go). Messages
// are diagnostic only; conformance compares classes.

export type V2ErrorClass =
  | "unclassified"
  | "malformed"
  | "unsupported_object_type"
  | "key_id_mismatch"
  | "delegation_digest_mismatch"
  | "chain_linkage_mismatch"
  | "duplicate_certificate_ref"
  | "invalid_signature"
  | "invalid_required_scope"
  | "configuration_invalid"
  | "expected_challenge_unavailable"
  | "namespace_mismatch"
  | "stale_replay_epoch"
  | "verifier_id_mismatch"
  | "challenge_mismatch"
  | "challenge_not_fresh"
  | "expected_agent_mismatch"
  | "session_context_mismatch"
  | "receiver_audience_required"
  | "receiver_audience_mismatch"
  | "receiver_binding_rejected"
  | "claim_replay"
  | "claim_store_unavailable"
  | "status_key_binding_mismatch"
  | "receipt_bundle_mismatch"
  | "bundle_hash_mismatch"
  | "transaction_party_mismatch"
  | "transaction_context_mismatch"
  | "transaction_signature_set_invalid"
  | "rotation_state_mismatch"
  | "rotation_key_reused"
  | "rotation_future_dated"
  | "rotation_fork"
  | "rotation_frozen"
  | "rotation_recovery_invalid"
  | "log_state_mismatch"
  | "log_gap"
  | "log_orphan"
  | "log_fork"
  | "log_frozen"
  | "status_object_rejected"
  | "stream_sequence_mismatch"
  | "clock_regressed"
  | "evaluation_cancelled"
  | "claim_lease_live"
  | "claim_lease_lost"
  | "claim_already_terminal"
  | "claim_not_found"
  | "receipt_abandoned"
  | "allow_horizon_passed";

/**
 * The closed SPEC-v2 §2.7 error-class list (49 classes). "unclassified" is
 * not a class: it marks an error this package did not classify.
 */
export const V2_ERROR_CLASSES: readonly Exclude<V2ErrorClass, "unclassified">[] = Object.freeze([
  "malformed", "unsupported_object_type", "key_id_mismatch", "delegation_digest_mismatch",
  "chain_linkage_mismatch", "duplicate_certificate_ref", "invalid_signature", "invalid_required_scope",
  "configuration_invalid", "expected_challenge_unavailable", "namespace_mismatch", "stale_replay_epoch",
  "verifier_id_mismatch", "challenge_mismatch", "challenge_not_fresh", "expected_agent_mismatch",
  "session_context_mismatch", "receiver_audience_required", "receiver_audience_mismatch",
  "receiver_binding_rejected", "claim_replay", "stream_sequence_mismatch", "claim_store_unavailable",
  "receipt_abandoned", "evaluation_cancelled", "clock_regressed", "allow_horizon_passed",
  "claim_lease_live", "claim_lease_lost", "claim_already_terminal", "claim_not_found",
  "status_key_binding_mismatch", "status_object_rejected", "receipt_bundle_mismatch",
  "bundle_hash_mismatch", "transaction_party_mismatch", "transaction_context_mismatch",
  "transaction_signature_set_invalid", "rotation_state_mismatch", "rotation_key_reused",
  "rotation_future_dated", "rotation_fork", "rotation_frozen", "rotation_recovery_invalid",
  "log_state_mismatch", "log_gap", "log_orphan", "log_fork", "log_frozen",
]);

/** An error carrying a conformance class. The wrapped cause stays reachable. */
export class V2Error extends Error {
  readonly v2Class: V2ErrorClass;
  constructor(v2Class: V2ErrorClass, message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "V2Error";
    this.v2Class = v2Class;
  }
}

/** A sentinel error (Go errors.New), matched by identity through the cause chain. */
export class V2SentinelError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "V2SentinelError";
  }
}

export const ErrWitnessLogFork = new V2SentinelError("witness log fork");
export const ErrWitnessLogGap = new V2SentinelError("witness log sequence gap");
export const ErrWitnessLogOrphan = new V2SentinelError("orphaned witness entry");
export const ErrWitnessLogFrozen = new V2SentinelError("witness log is frozen");
export const ErrV2ClaimProofConflict = new V2SentinelError("v2 challenge was already claimed by a different proof");
export const ErrKeyRotationForkV2 = new V2SentinelError("key rotation fork");
export const ErrKeyRotationFrozenV2 = new V2SentinelError("key rotation authority is frozen");
export const ErrV2RateLimitExceeded = new V2SentinelError("v2 signed rate limit has no remaining capacity");

/** fmt.Errorf("...: %w", cause) */
export function wrapError(message: string, cause: unknown): Error {
  const detail = cause instanceof Error ? cause.message : String(cause);
  return new Error(`${message}: ${detail}`, { cause });
}

function* chain(err: unknown): Generator<unknown> {
  let current: unknown = err;
  for (let depth = 0; current !== undefined && current !== null && depth < 64; depth++) {
    yield current;
    current = current instanceof Error ? (current as { cause?: unknown }).cause : undefined;
  }
}

/** errors.Is for sentinel identity through the cause chain. */
export function errorIs(err: unknown, target: Error): boolean {
  for (const e of chain(err)) if (e === target) return true;
  return false;
}

function findV2Error(err: unknown): V2Error | undefined {
  for (const e of chain(err)) if (e instanceof V2Error) return e;
  return undefined;
}

export function v2Errorf(v2Class: V2ErrorClass, message: string, cause?: unknown): V2Error {
  return new V2Error(v2Class, message, cause);
}

/** Go v2Classify: keep an existing class, otherwise attach this one. */
export function v2Classify(v2Class: V2ErrorClass, err: unknown): Error {
  if (findV2Error(err)) return err as Error;
  const message = err instanceof Error ? err.message : String(err);
  return new V2Error(v2Class, message, err);
}

/** Go V2ErrorClassOf. Returns "" for no error, "unclassified" when unknown. */
export function v2ErrorClassOf(err: unknown): V2ErrorClass | "" {
  if (err === undefined || err === null) return "";
  const classified = findV2Error(err);
  if (classified) return classified.v2Class;
  if (errorIs(err, ErrWitnessLogFork)) return "log_fork";
  if (errorIs(err, ErrWitnessLogGap)) return "log_gap";
  if (errorIs(err, ErrWitnessLogOrphan)) return "log_orphan";
  if (errorIs(err, ErrWitnessLogFrozen)) return "log_frozen";
  if (errorIs(err, ErrV2ClaimProofConflict)) return "claim_replay";
  if (errorIs(err, ErrKeyRotationForkV2)) return "rotation_fork";
  if (errorIs(err, ErrKeyRotationFrozenV2)) return "rotation_frozen";
  return "unclassified";
}

/** Runs fn and classifies any thrown error with v2Class (Go `defer v2Classify`). */
export function classified<T>(v2Class: V2ErrorClass, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    throw v2Classify(v2Class, err);
  }
}
