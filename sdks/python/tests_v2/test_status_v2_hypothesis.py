"""Property tests for the decoders this package owns in the status layer.

``import_security_journal_snapshot_v2`` and the version 1 record decoder take
untrusted bytes. For any input they either return a valid record or raise a
classified error; they never raise an unclassified exception, and a snapshot
is accepted only in its exact canonical form at its anchored head.
"""
from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from corpus import b64, load
from ratify_protocol.v2 import security_journal_snapshot_v2 as snap
from ratify_protocol.v2 import security_journal_v2 as sj
from ratify_protocol.v2.errors_v2 import ALL_ERROR_CLASSES, V2Error

VECTORS = load("security-journal.json")
SNAPSHOTS = [
    (b64(step["expect_snapshot_b64"]), sj.SecurityJournalHeadV2(**step["expect_head"]))
    for scenario in VECTORS["scenarios"] for step in scenario["steps"]
]
LEGACY = b64(VECTORS["migration"]["legacy_record_b64"])

json_values = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-(2**60), max_value=2**60) | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4),
    max_leaves=20,
)


def _classified_or_ok(fn, *args):
    try:
        return fn(*args)
    except V2Error as exc:
        assert exc.error_class in ALL_ERROR_CLASSES
        return None


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=512))
def test_import_arbitrary_bytes(data):
    head = sj.SecurityJournalHeadV2(generation=0, digest=VECTORS["genesis_digest"])
    _classified_or_ok(snap.import_security_journal_snapshot_v2, data, head)


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(range(len(SNAPSHOTS))), st.integers(min_value=0), st.integers(min_value=0, max_value=255))
def test_import_single_byte_mutation(index, position, value):
    data, head = SNAPSHOTS[index]
    position %= len(data)
    mutated = data[:position] + bytes([value]) + data[position + 1:]
    result = _classified_or_ok(snap.import_security_journal_snapshot_v2, mutated, head)
    if result is not None:
        # Only the identity mutation can import at the same anchored head.
        assert mutated == data


@settings(max_examples=200)
@given(json_values)
def test_import_arbitrary_json(value):
    import json

    data = json.dumps(value, separators=(",", ":")).encode()
    head = sj.SecurityJournalHeadV2(generation=0, digest=VECTORS["genesis_digest"])
    _classified_or_ok(snap.import_security_journal_snapshot_v2, data, head)


@settings(max_examples=100, deadline=None)
@given(st.sampled_from(range(len(SNAPSHOTS))))
def test_import_export_round_trip(index):
    data, head = SNAPSHOTS[index]
    journal = snap.import_security_journal_snapshot_v2(data, head)
    assert snap.export_security_journal_snapshot_v2(journal) == data
    assert journal.digest == head.digest


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=256) | st.integers(min_value=0).map(lambda p: LEGACY[: p % len(LEGACY)]))
def test_legacy_decoder_is_classified(data):
    _classified_or_ok(sj.decode_legacy_security_journal_v1, data)
