// Challenge issuance helper (SPEC-v2 Part B §7.3; Go challenge_issuance_v2.go).
//
// The issuer reads the authoritative clock, draws 32 unpredictable bytes,
// and durably persists the complete issuance record BEFORE it returns the
// challenge. A failure at any step returns no challenge; a record persisted
// without being returned is never presented and simply expires.


import { challengeClaimDigestV2 } from "./challenge_claim_v2.js";
import { V2_MAX_CHALLENGE_AGE_SECONDS, checkedAddV2, validV2Timestamp } from "./clock_bounds_v2.js";
import type { V2AuthoritativeClock } from "./claim_store_v2.js";
import { keyIDV2 } from "./crypto_v2.js";
import { classifiedAsync, errorIs, v2Classify, v2Errorf, V2SentinelError, wrapError } from "./errors_v2.js";
import { MAX_SAFE_INTEGER_V2, bytesEqual, isWellFormedString, utf8Len } from "./json_v2.js";
import { validV2ID } from "./protocol_v2_wire.js";
import { readV2AuthoritativeTime } from "./release_v2.js";
import { MAX_IDENTIFIER_LENGTH_BYTES, type HybridPublicKey } from "./types.js";
import { cloneExpectedChallengeV2, type ExpectedChallengeV2 } from "./verify_v2_preflight.js";

/** A record already exists for the key; the store never overwrites it. */
export const ErrV2ChallengeIssuanceConflict = new V2SentinelError("v2 challenge issuance record already exists");
/** No record exists, including after its retention ended. */
export const ErrV2ChallengeIssuanceNotFound = new V2SentinelError("v2 challenge issuance record not found");

/**
 * The durable issuance record store, keyed by (namespace, replay_epoch,
 * ChallengeClaimDigest(challenge)). persistV2Challenge resolves only after
 * the record is durable and throws ErrV2ChallengeIssuanceConflict for an
 * existing key; loadV2Challenge returns a copy, throws
 * ErrV2ChallengeIssuanceNotFound, or throws for unavailability.
 */
export interface V2ChallengeIssuanceStore {
  persistV2Challenge(record: ExpectedChallengeV2, signal?: AbortSignal): Promise<void>;
  loadV2Challenge(namespace: string, replayEpoch: number, claimDigest: Uint8Array, signal?: AbortSignal): Promise<ExpectedChallengeV2>;
}

/** The authenticated issuance context; bindings never come from the presenter. */
export interface V2ChallengeIssueRequest {
  verifierNamespace: string;
  replayEpoch: number;
  verifierID: string;
  /** expires_at = issued_at + lifetimeSeconds; 1..300. */
  lifetimeSeconds: number;
  expectedAgentID?: string;
  expectedAgentPublicKey?: HybridPublicKey | null;
  expectedReceiverID?: string;
  expectedSessionContext?: Uint8Array | null;
}

/** A source of random bytes (tests may script it). */
export type V2RandomSource = (n: number) => Uint8Array | Promise<Uint8Array>;

/** Issues challenges. clock and store are required; random defaults to node:crypto. */
export interface V2ChallengeIssuer {
  clock: V2AuthoritativeClock;
  store: V2ChallengeIssuanceStore;
  random?: V2RandomSource;
}

/** A conflict on 32 random bytes indicates a broken random source. */
const MAX_V2_ISSUANCE_ATTEMPTS = 3;

/**
 * Generates and durably persists one challenge record and returns it (Go
 * IssueChallengeV2): validate (configuration_invalid), read the clock, draw
 * 32 bytes, persist, and only then return. A key conflict draws fresh bytes
 * (at most three attempts) and never overwrites.
 */
export async function issueChallengeV2(issuer: V2ChallengeIssuer, req: V2ChallengeIssueRequest, signal?: AbortSignal): Promise<ExpectedChallengeV2> {
  return classifiedAsync("claim_store_unavailable", async () => {
    if (!issuer?.clock || !issuer.store) {
      throw v2Errorf("configuration_invalid", "v2 challenge issuer requires a context, authoritative clock and issuance store");
    }
    validateV2ChallengeIssueRequest(req);
    const random: V2RandomSource = issuer.random ?? ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
    let issuedAt: number;
    try {
      issuedAt = await readV2AuthoritativeTime(issuer.clock, signal);
    } catch (err) {
      throw wrapError("v2 challenge issuance: authoritative clock", err);
    }
    const expiresAt = checkedAddV2(issuedAt, req.lifetimeSeconds);
    if (expiresAt === null || !validV2Timestamp(expiresAt)) {
      throw v2Errorf("configuration_invalid", "v2 challenge expiry leaves the timestamp domain");
    }
    for (let attempt = 0; attempt < MAX_V2_ISSUANCE_ATTEMPTS; attempt++) {
      let value: Uint8Array;
      try {
        value = Uint8Array.from(await random(32));
      } catch (err) {
        throw v2Classify("configuration_invalid", wrapError("v2 challenge issuance: random source", err));
      }
      if (value.length !== 32) throw v2Errorf("configuration_invalid", "v2 challenge issuance: random source: short read");
      const record: ExpectedChallengeV2 = {
        value, issuedAt, expiresAt, verifierNamespace: req.verifierNamespace, replayEpoch: req.replayEpoch, verifierID: req.verifierID,
        expectedAgentID: req.expectedAgentID ?? "", expectedAgentPublicKey: req.expectedAgentPublicKey ?? null,
        expectedReceiverID: req.expectedReceiverID ?? "", expectedSessionContext: req.expectedSessionContext ?? null,
      };
      try {
        await issuer.store.persistV2Challenge(cloneExpectedChallengeV2(record), signal);
      } catch (err) {
        if (errorIs(err, ErrV2ChallengeIssuanceConflict)) continue;
        throw wrapError("v2 challenge issuance: the record was not durably persisted, so the challenge is not exposed", err);
      }
      return cloneExpectedChallengeV2(record);
    }
    throw v2Errorf("configuration_invalid", `v2 challenge issuance: ${MAX_V2_ISSUANCE_ATTEMPTS} consecutive key conflicts; the random source is not trustworthy`);
  });
}

/**
 * Retrieves the issuance record for presented challenge bytes (Go
 * LoadExpectedChallengeV2). A missing record is
 * expected_challenge_unavailable; the caller still runs the complete
 * pre-claim checks against the returned record.
 */
export async function loadExpectedChallengeV2(store: V2ChallengeIssuanceStore, namespace: string, replayEpoch: number, challenge: Uint8Array, signal?: AbortSignal): Promise<ExpectedChallengeV2> {
  return classifiedAsync("expected_challenge_unavailable", async () => {
    if (!store) throw v2Errorf("configuration_invalid", "v2 challenge lookup requires a context and issuance store");
    let digest: Uint8Array;
    try {
      digest = challengeClaimDigestV2(challenge);
    } catch {
      throw v2Errorf("expected_challenge_unavailable", "v2 presented challenge is not 32 bytes");
    }
    let record: ExpectedChallengeV2;
    try {
      record = await store.loadV2Challenge(namespace, replayEpoch, Uint8Array.from(digest), signal);
    } catch (err) {
      throw v2Classify("expected_challenge_unavailable", err);
    }
    if (!record || !bytesEqual(record.value, challenge) || record.verifierNamespace !== namespace || record.replayEpoch !== replayEpoch) {
      throw v2Errorf("expected_challenge_unavailable", "v2 issuance store returned a record for another challenge");
    }
    return cloneExpectedChallengeV2(record);
  });
}

/** Go validateV2ChallengeIssueRequest. */
export function validateV2ChallengeIssueRequest(req: V2ChallengeIssueRequest): void {
  const invalid = (msg: string) => v2Errorf("configuration_invalid", msg);
  if (!req || typeof req.verifierNamespace !== "string" || req.verifierNamespace === "" || !isWellFormedString(req.verifierNamespace)) {
    throw invalid("v2 challenge issuance requires a non-empty UTF-8 verifier namespace");
  }
  if (!Number.isSafeInteger(req.replayEpoch) || req.replayEpoch < 0 || req.replayEpoch > MAX_SAFE_INTEGER_V2) {
    throw invalid(`v2 challenge replay epoch must be 0..${MAX_SAFE_INTEGER_V2}`);
  }
  if (!validV2ID(req.verifierID)) throw invalid("v2 challenge verifier_id must be a v2 key ID");
  if (!Number.isSafeInteger(req.lifetimeSeconds) || req.lifetimeSeconds < 1 || req.lifetimeSeconds > V2_MAX_CHALLENGE_AGE_SECONDS) {
    throw invalid(`v2 challenge lifetime must be 1..${V2_MAX_CHALLENGE_AGE_SECONDS} seconds`);
  }
  const agentID = req.expectedAgentID ?? "";
  const agentKey = req.expectedAgentPublicKey ?? null;
  if ((agentID === "") !== (agentKey === null)) throw invalid("v2 expected agent ID and public key must be supplied together");
  if (agentKey !== null) {
    let id = "";
    try {
      id = keyIDV2(agentKey);
    } catch {
      id = "";
    }
    if (id === "" || id !== agentID) throw invalid("v2 expected agent ID does not match its complete public key");
  }
  const receiver = req.expectedReceiverID ?? "";
  if (receiver !== "" && (!isWellFormedString(receiver) || utf8Len(receiver) > MAX_IDENTIFIER_LENGTH_BYTES)) {
    throw invalid(`v2 expected receiver ID must be valid UTF-8 of at most ${MAX_IDENTIFIER_LENGTH_BYTES} bytes`);
  }
  const session = req.expectedSessionContext ?? null;
  if (session !== null && session.length !== 32) throw invalid("v2 expected session context must be absent or exactly 32 bytes");
}
