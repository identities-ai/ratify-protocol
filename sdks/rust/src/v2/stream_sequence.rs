//! Stream sequence (SPEC-v2 §7.4). Mirrors Go `stream_sequence_v2.go`.
//!
//! Every rejection has the class `stream_sequence_mismatch`; the message
//! distinguishes gap, duplicate and reorder for diagnostics only. A
//! presentation that carries `stream_id` and `stream_seq` advances the state
//! of the key (verifier_namespace, agent_id, stream_id) in the same atomic
//! transaction as the challenge claim.

use super::errors::{err, V2ErrorClass, V2Result};
use super::wire::MAX_SAFE;

/// Go `CheckV2StreamSequence`: the normative stream-sequence rule. `has_last`
/// reports whether the stream key already has accepted state. `Ok` means the
/// store must record `seq` as the new last value in the claim transaction.
pub fn check_v2_stream_sequence(has_last: bool, last: i64, seq: i64) -> V2Result<()> {
    if !(1..=MAX_SAFE).contains(&seq) || has_last && !(1..=MAX_SAFE).contains(&last) {
        return err(V2ErrorClass::Malformed, "v2 stream sequence is outside 1..2^53-1");
    }
    let mut expected = 1i64;
    if has_last {
        if last == MAX_SAFE {
            return err(V2ErrorClass::StreamSequenceMismatch, "v2 stream sequence is exhausted");
        }
        expected = last + 1;
    }
    if seq == expected {
        Ok(())
    } else if seq > expected {
        err(
            V2ErrorClass::StreamSequenceMismatch,
            format!("v2 stream sequence {seq} skips expected {expected}"),
        )
    } else if seq == last {
        err(
            V2ErrorClass::StreamSequenceMismatch,
            format!("v2 stream sequence {seq} was already accepted"),
        )
    } else {
        err(
            V2ErrorClass::StreamSequenceMismatch,
            format!("v2 stream sequence {seq} precedes accepted {last}"),
        )
    }
}
