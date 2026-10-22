"""Stream sequence (SPEC-v2 §7.4), mirroring Go stream_sequence_v2.go.

A presentation that carries ``stream_id`` and ``stream_seq`` advances the state
of the key (verifier_namespace, agent_id, stream_id) in the same atomic
transaction as the challenge claim. With no state only ``stream_seq`` 1 is
accepted; with state ``last`` only ``last + 1``. ``stream_seq == last`` is a
duplicate, ``< last`` a reorder, and ``> last + 1`` a gap; every rejection has
the class ``stream_sequence_mismatch`` and consumes nothing.
"""
from __future__ import annotations

from .errors_v2 import V2Error, V2ErrorClass
from .types_v2 import MAX_SAFE_INTEGER, is_int


def check_v2_stream_sequence(has_last: bool, last: int, seq: int) -> None:
    """Apply the normative stream-sequence rule. Returning normally means the
    store must record ``seq`` as the new last value in the claim
    transaction."""
    if not isinstance(has_last, bool) or not is_int(last) or not is_int(seq):
        raise V2Error(V2ErrorClass.MALFORMED, "v2 stream sequence inputs must be a bool and integers")
    if seq < 1 or seq > MAX_SAFE_INTEGER or (has_last and (last < 1 or last > MAX_SAFE_INTEGER)):
        raise V2Error(V2ErrorClass.MALFORMED, "v2 stream sequence is outside 1..2^53-1")
    expected = 1
    if has_last:
        if last == MAX_SAFE_INTEGER:
            raise V2Error(V2ErrorClass.STREAM_SEQUENCE_MISMATCH, "v2 stream sequence is exhausted")
        expected = last + 1
    if seq == expected:
        return
    if seq > expected:
        raise V2Error(V2ErrorClass.STREAM_SEQUENCE_MISMATCH, f"v2 stream sequence {seq} skips expected {expected}")
    if seq == last:
        raise V2Error(V2ErrorClass.STREAM_SEQUENCE_MISMATCH, f"v2 stream sequence {seq} was already accepted")
    raise V2Error(V2ErrorClass.STREAM_SEQUENCE_MISMATCH, f"v2 stream sequence {seq} precedes accepted {last}")
