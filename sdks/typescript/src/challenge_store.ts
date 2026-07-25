// ChallengeStore — single-use tracking for verifier-issued challenges
// (SPEC §10). verifyBundle consumes a challenge through this interface at
// the locked point in the algorithm: after the structural, chain, and
// challenge-signature checks pass, and before authorization evaluation —
// so a forged presentation cannot burn a legitimate challenge, and a
// cryptographically valid presentation spends its challenge even when
// authorization is subsequently denied.

import { base64StandardEncode } from "./canonical.js";
import { generateChallenge } from "./crypto.js";

/**
 * The uniform rejection detail for a challenge that cannot be consumed:
 * never issued, expired, already consumed, or issued under a different
 * session binding. Deliberately identical across those cases so a
 * rejection's public detail does not distinguish them. verifyBundle
 * normalizes EVERY store failure — custom-store error strings and thrown
 * exceptions included — to this text in the public result, so
 * implementations cannot leak record state even accidentally.
 */
export const UNKNOWN_CHALLENGE =
  "challenge was not issued by this verifier or has already been used";

/**
 * Tracks verifier-issued challenges so each is accepted at most once
 * within its freshness window (SPEC §10).
 *
 * The bundled implementation is in-memory (MemoryChallengeStore).
 * Deployments that need issuance state to survive restarts or span
 * verifier replicas implement this interface over shared storage; consume
 * MUST remain atomic (compare-and-set) so two concurrent presentations of
 * one challenge cannot both succeed.
 */
export interface ChallengeStore {
  /**
   * Generate a fresh challenge bound to sessionContext (which must be
   * empty/undefined or exactly 32 bytes; absent = unbound), valid for
   * ttlSeconds (which must be positive). Returns the challenge and its
   * expiry (unix seconds).
   */
  issue(
    sessionContext: Uint8Array | undefined,
    ttlSeconds: number,
  ): Promise<{ challenge: Uint8Array; expires_at: number }>;

  /**
   * Report whether challenge could be consumed right now — issued,
   * unexpired, unconsumed, and bound to sessionContext — WITHOUT
   * consuming it. Returns null when consumable, or a rejection reason.
   * verifyBundle calls this before any signature work.
   */
  validate(
    challenge: Uint8Array,
    sessionContext: Uint8Array | undefined,
    now: number,
  ): Promise<string | null>;

  /**
   * Atomically remove the challenge's issuance record. Exactly one
   * consume of a given challenge may ever succeed; all later calls (and
   * calls with a mismatched sessionContext, which do NOT remove the
   * record) return a rejection reason. Returns null on success. Removing
   * the record keeps the store's capacity a count of PENDING challenges —
   * a consumed challenge frees its slot immediately.
   */
  consume(
    challenge: Uint8Array,
    sessionContext: Uint8Array | undefined,
    now: number,
  ): Promise<string | null>;
}

interface ChallengeRecord {
  sessionContext: Uint8Array;
  expiresAt: number;
}

/**
 * In-memory ChallengeStore: map keyed by the challenge with lazy expiry
 * and a capacity cap. Single-process only — state does not survive
 * restarts (an unconsumed challenge dies with the process, which fails
 * closed), and replicas sharing verification traffic would each accept
 * the same challenge once. Deployments spanning processes or hosts need
 * a ChallengeStore over shared storage whose consume is atomic (e.g. a
 * single-row DELETE ... RETURNING).
 */
export class MemoryChallengeStore implements ChallengeStore {
  private readonly records = new Map<string, ChallengeRecord>();

  constructor(private readonly maxSize: number = 10_000) {
    if (!Number.isInteger(maxSize) || maxSize < 1) {
      throw new Error(`MemoryChallengeStore maxSize must be a positive integer, got ${maxSize}`);
    }
  }

  async issue(
    sessionContext: Uint8Array | undefined,
    ttlSeconds: number,
  ): Promise<{ challenge: Uint8Array; expires_at: number }> {
    if (sessionContext && sessionContext.length !== 0 && sessionContext.length !== 32) {
      throw new Error(`session context must be empty or 32 bytes, got ${sessionContext.length}`);
    }
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0) {
      throw new Error(`challenge ttl must be a positive integer of seconds, got ${ttlSeconds}`);
    }
    const now = Math.floor(Date.now() / 1000);
    this.expire(now);
    if (this.records.size >= this.maxSize) {
      throw new Error("challenge store full — too many pending challenges");
    }
    const challenge = generateChallenge();
    const expiresAt = now + ttlSeconds;
    this.records.set(base64StandardEncode(challenge), {
      sessionContext: sessionContext ? sessionContext.slice() : new Uint8Array(0),
      expiresAt,
    });
    return { challenge, expires_at: expiresAt };
  }

  async validate(
    challenge: Uint8Array,
    sessionContext: Uint8Array | undefined,
    now: number,
  ): Promise<string | null> {
    return this.lookup(challenge, sessionContext, now) === null
      ? UNKNOWN_CHALLENGE
      : null;
  }

  async consume(
    challenge: Uint8Array,
    sessionContext: Uint8Array | undefined,
    now: number,
  ): Promise<string | null> {
    // Check-and-delete happens synchronously between awaits, so no other
    // consume of the same challenge can interleave. Removal frees the
    // record's capacity slot immediately; a session-context mismatch
    // leaves the record in place.
    const key = this.lookup(challenge, sessionContext, now);
    if (key === null) {
      return UNKNOWN_CHALLENGE;
    }
    this.records.delete(key);
    return null;
  }

  // Resolve a presentable record's key, or null. A session-context
  // mismatch fails WITHOUT touching the record, so a presentation under
  // the wrong binding cannot burn the legitimate one.
  private lookup(
    challenge: Uint8Array,
    sessionContext: Uint8Array | undefined,
    now: number,
  ): string | null {
    this.expire(now);
    const key = base64StandardEncode(challenge);
    const record = this.records.get(key);
    if (!record) {
      return null;
    }
    const presented = sessionContext ?? new Uint8Array(0);
    if (!bytesEqual(record.sessionContext, presented)) {
      return null;
    }
    return key;
  }

  private expire(now: number): void {
    for (const [key, record] of this.records) {
      if (record.expiresAt < now) {
        this.records.delete(key);
      }
    }
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
