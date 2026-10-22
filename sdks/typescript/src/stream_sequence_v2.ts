// Stream sequence (SPEC-v2 §7.4; Go stream_sequence_v2.go). Every rejection
// has the class stream_sequence_mismatch; messages distinguish gap,
// duplicate and reorder for diagnostics only. The advance is part of the
// same atomic transaction as the challenge claim.

import { v2Errorf } from "./errors_v2.js";
import { MAX_SAFE_INTEGER_V2 } from "./json_v2.js";

/**
 * Applies the normative stream-sequence rule. hasLast reports whether the
 * key (namespace, agent_id, stream_id) already has accepted state. Returning
 * normally means the store must record seq as the new last value.
 */
export function checkV2StreamSequence(hasLast: boolean, last: number, seq: number): void {
  const inRange = (n: number) => Number.isSafeInteger(n) && n >= 1 && n <= MAX_SAFE_INTEGER_V2;
  if (!inRange(seq) || (hasLast && !inRange(last))) throw v2Errorf("malformed", "v2 stream sequence is outside 1..2^53-1");
  let expected = 1;
  if (hasLast) {
    if (last === MAX_SAFE_INTEGER_V2) throw v2Errorf("stream_sequence_mismatch", "v2 stream sequence is exhausted");
    expected = last + 1;
  }
  if (seq === expected) return;
  if (seq > expected) throw v2Errorf("stream_sequence_mismatch", `v2 stream sequence ${seq} skips expected ${expected}`);
  if (seq === last) throw v2Errorf("stream_sequence_mismatch", `v2 stream sequence ${seq} was already accepted`);
  throw v2Errorf("stream_sequence_mismatch", `v2 stream sequence ${seq} precedes accepted ${last}`);
}
