"""SecurityJournalV2 snapshot known answers (testvectors/v2/security-journal.json).

Every step runs against the reference anchored store and must reproduce the
exact anchored head and canonical snapshot bytes; the version 1 record must
validate under its legacy digest and migrate to the exact version 2
successor; every import negative must be refused with its class; and every
transition negative (two snapshots that each import) must fail transition
validation with its class.
"""
from __future__ import annotations

import pytest

from corpus import b64, load, pubkey
from ratify_protocol.v2 import context_v2
from ratify_protocol.v2 import security_journal_snapshot_v2 as snap
from ratify_protocol.v2 import security_journal_v2 as sj
from ratify_protocol.v2.errors_v2 import V2Error, error_class_of
from ratify_protocol.v2.protocol_v2 import decode_revocation_list_v2, decode_revocation_push_v2
from ratify_protocol.v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol.v2.v2reference.journal import JournalStore

VECTORS = load("security-journal.json")
CTX = context_v2.background()


def _policy(p: dict) -> RevocationStatusPolicyV2:
    return RevocationStatusPolicyV2(p["max_list_lifetime_seconds"], p["max_status_age_seconds"], p["clock_skew_seconds"])


def test_genesis_snapshot_and_digest():
    genesis = sj.empty_security_journal_v2()
    exported = snap.export_security_journal_snapshot_v2(genesis)
    assert exported == VECTORS["genesis_snapshot"].encode()
    assert genesis.digest == VECTORS["genesis_digest"]
    assert snap.security_journal_snapshot_digest_v2(exported) == VECTORS["genesis_digest"]


def _run_step(store: JournalStore, step: dict):
    op = step["op"]
    key = pubkey(step["key"]["public_key"])
    if op == "record_key_role":
        return sj.record_security_key_role_v2(CTX, store, step["role"], key)
    if op == "configure_status_key_epoch":
        return sj.configure_status_key_epoch_v2(CTX, store, step["issuer_id"], step["epoch"], key)
    if op == "apply_revocation_list":
        lst = decode_revocation_list_v2(b64(step["wire_b64"]))
        return sj.apply_revocation_list_to_journal_v2(
            CTX, store, lst, step["issuer_id"], step["epoch"], key, _policy(step["policy"]), step["now"])
    if op == "apply_revocation_push":
        push = decode_revocation_push_v2(b64(step["wire_b64"]))
        return sj.apply_revocation_push_to_journal_v2(
            CTX, store, push, step["issuer_id"], step["epoch"], key, _policy(step["policy"]), step["now"])
    raise AssertionError(f"unknown op {op}")


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda s: s["name"])
def test_transition_scenario(scenario):
    store = JournalStore()
    assert scenario["steps"], "empty scenario"
    for i, step in enumerate(scenario["steps"]):
        before = store.head()
        if step.get("expect_rejected"):
            with pytest.raises(Exception):
                _run_step(store, step)
        else:
            _run_step(store, step)
        head = store.head()
        assert (head != before) == step["expect_changed"], f"step {i} {step['op']} changed"
        want = step["expect_head"]
        assert (head.generation, head.digest) == (want["generation"], want["digest"]), f"step {i} head"
        journal, _ = store.load(CTX)
        exported = snap.export_security_journal_snapshot_v2(journal)
        assert exported == b64(step["expect_snapshot_b64"]), f"step {i} snapshot bytes"
        assert snap.security_journal_snapshot_digest_v2(exported) == want["digest"]


def test_version_1_migration():
    m = VECTORS["migration"]
    legacy = sj.decode_legacy_security_journal_v1(b64(m["legacy_record_b64"]))
    assert sj.security_journal_v2_go_json(type(legacy)(**{**legacy.__dict__, "digest": ""})) == b64(m["legacy_digest_input_b64"])
    assert sj.legacy_security_journal_digest_v1(legacy) == m["legacy_digest"]
    sj.validate_security_journal_v2(legacy)
    migrated = snap.migrate_security_journal_v2(legacy)
    want = m["expect_head"]
    assert (migrated.generation, migrated.digest) == (want["generation"], want["digest"])
    assert migrated.previous_digest == m["expect_previous_digest"]
    assert snap.export_security_journal_snapshot_v2(migrated) == b64(m["expect_snapshot_b64"])
    tampered = sj.decode_legacy_security_journal_v1(b64(m["tampered_legacy_record_b64"]))
    with pytest.raises(V2Error) as excinfo:
        snap.migrate_security_journal_v2(tampered)
    # The record's own digest check fails, so the reference reports the
    # malformed class of ValidateSecurityJournalV2 rather than the
    # configuration_invalid default of the migration.
    assert error_class_of(excinfo.value) == "malformed"
    # A loaded version 1 record is never used directly: it requires migration.
    assert legacy.version == 1


def test_journal_corpus_shape():
    assert len(VECTORS["scenarios"]) == 2
    assert len(VECTORS["import_negatives"]) == 20
    assert sum(n["name"].startswith("invariant_") for n in VECTORS["import_negatives"]) == 9
    assert len(VECTORS["transition_negatives"]) == 6


def _head(h: dict) -> sj.SecurityJournalHeadV2:
    return sj.SecurityJournalHeadV2(generation=h["generation"], digest=h["digest"])


@pytest.mark.parametrize("case", VECTORS["transition_negatives"], ids=lambda c: c["name"])
def test_transition_negative(case):
    current = snap.import_security_journal_snapshot_v2(b64(case["current_snapshot_b64"]), _head(case["current_head"]))
    nxt = snap.import_security_journal_snapshot_v2(b64(case["next_snapshot_b64"]), _head(case["next_head"]))
    with pytest.raises(V2Error) as excinfo:
        sj.validate_security_journal_transition_v2(current, nxt)
    assert error_class_of(excinfo.value) == case["expect_error_class"]


@pytest.mark.parametrize("case", VECTORS["import_negatives"], ids=lambda c: c["name"])
def test_import_negative(case):
    head = sj.SecurityJournalHeadV2(generation=case["head"]["generation"], digest=case["head"]["digest"])
    with pytest.raises(V2Error) as excinfo:
        snap.import_security_journal_snapshot_v2(b64(case["snapshot_b64"]), head)
    assert error_class_of(excinfo.value) == case["expect_error_class"]


def test_import_round_trip_of_every_scenario_snapshot():
    """Every committed snapshot re-imports at its own head."""
    for scenario in VECTORS["scenarios"]:
        for step in scenario["steps"]:
            data = b64(step["expect_snapshot_b64"])
            head = sj.SecurityJournalHeadV2(**step["expect_head"])
            journal = snap.import_security_journal_snapshot_v2(data, head)
            assert snap.export_security_journal_snapshot_v2(journal) == data
