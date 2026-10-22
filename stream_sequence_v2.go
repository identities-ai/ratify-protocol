package ratify

// Stream sequence (SPEC-v2 §7.4). Every rejection
// has the class stream_sequence_mismatch; the message distinguishes gap,
// duplicate and reorder for diagnostics only.
//
// A presentation that carries stream_id and stream_seq advances the state of
// the key (verifier_namespace, agent_id, stream_id). The advance is part of
// the same atomic transaction as the challenge claim: either both commit or
// neither does. The rule, applied by CheckV2StreamSequence, is:
//
//   - no state for the key: only stream_seq 1 is accepted (anything larger is
//     a gap);
//   - state last: only last+1 is accepted;
//   - stream_seq == last is a duplicate; stream_seq < last is a reorder;
//     stream_seq > last+1 is a gap.
//
// An exact retry of an already-claimed presentation is resolved by the claim
// key before this rule runs, so it returns in_progress or terminal_replay and
// never advances the stream twice. Two different presentations that carry the
// same stream_seq race on the store's lock: exactly one advances the stream
// and the other is a duplicate. A rejected advance consumes nothing.

// CheckV2StreamSequence applies the normative stream-sequence rule. hasLast
// reports whether the stream key already has accepted state. A nil error means
// the store must record seq as the new last value in the claim transaction.
func CheckV2StreamSequence(hasLast bool, last, seq int64) error {
	if seq < 1 || seq > maxSafeInteger || hasLast && (last < 1 || last > maxSafeInteger) {
		return v2Errorf(V2ErrMalformed, "v2 stream sequence is outside 1..2^53-1")
	}
	expected := int64(1)
	if hasLast {
		if last == maxSafeInteger {
			return v2Errorf(V2ErrStreamSequenceMismatch, "v2 stream sequence is exhausted")
		}
		expected = last + 1
	}
	switch {
	case seq == expected:
		return nil
	case seq > expected:
		return v2Errorf(V2ErrStreamSequenceMismatch, "v2 stream sequence %d skips expected %d", seq, expected)
	case seq == last:
		return v2Errorf(V2ErrStreamSequenceMismatch, "v2 stream sequence %d was already accepted", seq)
	default:
		return v2Errorf(V2ErrStreamSequenceMismatch, "v2 stream sequence %d precedes accepted %d", seq, last)
	}
}
