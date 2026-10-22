// Protocol v2 configuration and clock bounds (SPEC-v2 §2.5; Go
// clock_bounds_v2.go). Every time value is an integer number of seconds
// since the Unix epoch. Every deadline is exclusive.

import { v2Errorf } from "./errors_v2.js";

/** 9999-12-31T23:59:59Z. Timestamps are 0..this. */
export const V2_MAX_TIMESTAMP_SECONDS = 253402300799;
export const V2_MAX_FUTURE_SKEW_SECONDS = 300;
export const V2_MAX_CHALLENGE_AGE_SECONDS = 300;
export const V2_MAX_STATUS_LIFETIME_SECONDS = 86400;
export const V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS = 86400;
export const V2_MAX_RATE_WINDOW_SECONDS = 86400;
/** Ten 365-day years. */
export const V2_MAX_DELEGATION_LIFETIME_SECONDS = 315360000;

/** True when t is an integer inside the v2 timestamp domain. */
export function validV2Timestamp(t: number): boolean {
  return Number.isSafeInteger(t) && t >= 0 && t <= V2_MAX_TIMESTAMP_SECONDS;
}

/** Adds two second counts; null when either operand leaves the timestamp domain. */
export function checkedAddV2(a: number, b: number): number | null {
  if (!Number.isSafeInteger(a) || !Number.isSafeInteger(b) || a < 0 || b < 0 ||
      a > V2_MAX_TIMESTAMP_SECONDS || b > V2_MAX_TIMESTAMP_SECONDS) {
    return null;
  }
  return a + b;
}

/** Exclusive challenge deadlines (Go v2ChallengeTimeCurrent). */
export function v2ChallengeTimeCurrent(now: number, issuedAt: number, expiresAt: number, maxAge: number, futureSkew: number): boolean {
  if (!validV2Timestamp(now) || !validV2Timestamp(issuedAt) || !validV2Timestamp(expiresAt)) return false;
  if (issuedAt > now && issuedAt - now > futureSkew) return false;
  const ageDeadline = checkedAddV2(issuedAt, maxAge);
  return ageDeadline !== null && now < expiresAt && now < ageDeadline;
}

/** Request-level clock bounds (Go validateV2FreshnessConfiguration). */
export function validateV2FreshnessConfiguration(now: number, maxAgeSeconds: number, futureSkewSeconds: number): void {
  if (!validV2Timestamp(now)) {
    throw v2Errorf("configuration_invalid", `v2 verifier time is outside 0..${V2_MAX_TIMESTAMP_SECONDS}`);
  }
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 1 || maxAgeSeconds > V2_MAX_CHALLENGE_AGE_SECONDS) {
    throw v2Errorf("configuration_invalid", `v2 challenge maximum age must be 1..${V2_MAX_CHALLENGE_AGE_SECONDS} seconds`);
  }
  if (!Number.isSafeInteger(futureSkewSeconds) || futureSkewSeconds < 0 || futureSkewSeconds > V2_MAX_FUTURE_SKEW_SECONDS) {
    throw v2Errorf("configuration_invalid", `v2 future skew must be 0..${V2_MAX_FUTURE_SKEW_SECONDS} seconds`);
  }
}
