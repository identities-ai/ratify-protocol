"""Issuer status reducer sequences (testvectors/v2/status-sequences.json).

Each scenario starts from empty state; a rejected step leaves state
unchanged; every query must return the exact status, reason, and ordered
evidence, including the exclusive next_update and status-age deadlines.
Every apply step that records an observation names its unlabelled body
digest (SPEC-v2 §6.6), which the state must hold.
"""
from __future__ import annotations

import pytest

from corpus import b64, load, pubkey
from ratify_protocol_v2 import status_state_v2 as ss
from ratify_protocol_v2.errors_v2 import error_class_of
from ratify_protocol_v2.protocol_v2 import decode_revocation_list_v2, decode_revocation_push_v2
from ratify_protocol_v2.types_v2 import StatusEvidenceEntryV2

VECTORS = load("status-sequences.json")
PUB = {k["name"]: pubkey(k["public_key"]) for k in load("keys.json")["keys"]}


def _policy(p: dict) -> ss.RevocationStatusPolicyV2:
    return ss.RevocationStatusPolicyV2(p["max_list_lifetime_seconds"], p["max_status_age_seconds"], p["clock_skew_seconds"])


def _evidence(e: dict) -> StatusEvidenceEntryV2:
    return StatusEvidenceEntryV2(
        issuer_id=e["issuer_id"], status_key_id=e["status_key_id"], sequence=e["sequence"],
        object_type=e["object_type_code"], digest=e["digest"],
    )


def _check_state(where: str, s: ss.RevocationStatusStateV2, want: dict) -> None:
    got = {
        "has_floor": s.has_floor, "floor": s.floor, "max_observed_sequence": s.max_observed_sequence,
        "fork_sequence": s.fork_sequence, "reconciliation_required": s.reconciliation_required,
        "future_dated_object_observed": s.future_dated_object_observed,
        "accepted_set": list(s.accepted_cert_ids), "deny_union": list(s.deny_union_cert_ids),
    }
    for name, value in want.items():
        assert got[name] == value, f"{where}: {name} = {got[name]!r}, want {value!r}"


def _has_body_digest(s: ss.RevocationStatusStateV2, epoch: int, op: str, want: str) -> bool:
    code = 5 if op == "apply_push" else 3
    return any(o.status_key_epoch == epoch and o.object_type == code and "sha384:" + bytes(o.body_digest).hex() == want
               for o in s.observations)


def test_scenario_and_step_counts():
    assert len(VECTORS["scenarios"]) == 22
    assert sum(len(s["steps"]) for s in VECTORS["scenarios"]) == 112
    assert sum(1 for s in VECTORS["scenarios"] for step in s["steps"] if step.get("expect_body_digest")) == 63


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda s: s["name"])
def test_status_sequence(scenario):
    state = ss.RevocationStatusStateV2()
    for i, step in enumerate(scenario["steps"]):
        key = PUB.get(step.get("status_key", ""))
        policy = _policy(step.get("policy") or scenario["policy"])
        op = step["op"]
        where = f"step {i} {op} {step.get('label', '')}"
        if op == "query":
            r = ss.revocation_status_for_cert_v2(
                state, scenario["issuer_id"], step["cert_id"], step["status_key_epoch"], key, policy, step["now"])
            want = step["expect_result"]
            assert (r.status, r.reason) == (want["status"], want.get("reason", "")), where
            assert r.evidence == [_evidence(e) for e in want["evidence"]], where
            continue
        nxt = None
        err = None
        try:
            if op == "apply_list":
                lst = decode_revocation_list_v2(b64(step["wire_b64"]))
                nxt = ss.apply_revocation_list_v2(state, lst, scenario["issuer_id"], step["status_key_epoch"], key, policy, step["now"])
            elif op == "apply_push":
                push = decode_revocation_push_v2(b64(step["wire_b64"]))
                nxt = ss.apply_revocation_push_v2(state, push, scenario["issuer_id"], step["status_key_epoch"], key, policy, step["now"])
            elif op == "transition_epoch":
                nxt = ss.transition_revocation_status_epoch_v2(state, scenario["issuer_id"], step["status_key_epoch"], key)
            else:
                raise AssertionError(f"unknown op {op}")
        except Exception as exc:  # noqa: BLE001 - compared by class below
            err = exc
        if "expect_error_class" in step:
            assert err is not None, f"{where}: expected {step['expect_error_class']}"
            assert error_class_of(err) == step["expect_error_class"], f"{where}: {err!r}"
            continue
        assert err is None, f"{where}: {err!r}"
        state = nxt
        if "expect_state" in step:
            _check_state(where, state, step["expect_state"])
        if step.get("expect_body_digest"):
            assert _has_body_digest(state, step["status_key_epoch"], op, step["expect_body_digest"]), \
                f"{where}: no observation with body_digest {step['expect_body_digest']} (SPEC-v2 §6.6)"


def test_reducer_never_mutates_its_input():
    scenario = VECTORS["scenarios"][0]
    policy = _policy(scenario["policy"])
    step = scenario["steps"][0]
    lst = decode_revocation_list_v2(b64(step["wire_b64"]))
    state = ss.RevocationStatusStateV2()
    first = ss.apply_revocation_list_v2(state, lst, scenario["issuer_id"], step["status_key_epoch"], PUB[step["status_key"]], policy, step["now"])
    assert state == ss.RevocationStatusStateV2()
    snapshot_before = (list(first.deny_union_cert_ids), len(first.observations))
    ss.apply_revocation_list_v2(first, lst, scenario["issuer_id"], step["status_key_epoch"], PUB[step["status_key"]], policy, step["now"])
    assert (list(first.deny_union_cert_ids), len(first.observations)) == snapshot_before


@pytest.mark.parametrize("bad", [True, -1, 2**53, "1", None])
def test_reducer_rejects_out_of_range_epochs(bad):
    scenario = VECTORS["scenarios"][0]
    step = scenario["steps"][0]
    lst = decode_revocation_list_v2(b64(step["wire_b64"]))
    with pytest.raises(Exception) as excinfo:
        ss.apply_revocation_list_v2(ss.RevocationStatusStateV2(), lst, scenario["issuer_id"], bad,
                                    PUB[step["status_key"]], _policy(scenario["policy"]), step["now"])
    assert error_class_of(excinfo.value) == "status_object_rejected"
