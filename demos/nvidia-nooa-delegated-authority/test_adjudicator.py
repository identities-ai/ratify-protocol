# SPDX-License-Identifier: Apache-2.0
"""Tests for the OpenShell profile's adjudicator.

The adjudicator decides whether a live OpenShell run passed. If it can be
fooled, every artifact it produces is worthless, so it gets tested like any
other security-relevant code.

This exists because an earlier version appended ``{"result": "PASS"}`` for
every parser case it found, unconditionally. It could not fail. Each test below
feeds evidence of one specific violation and asserts the adjudicator says FAIL,
so the regression that would have caught that defect is now permanent.

Every test states WHY the property matters, not just what the code does. A test
that would still pass if the security property were removed is not a test of
the security property.
"""

from __future__ import annotations

import pytest

from openshell_cases import (
    GROUPS,
    REQUIRED_CASES,
    Expect,
    adjudicate_group,
    carriage_refusal_expect,
    denial_expect,
    judge,
    missing_expectations,
    openshell_denial_expect,
    prepare_expect,
    refusal_expect,
)

EXECUTE = "refund.execute"
PREPARE = "refund.prepare"


def snap(seq=0, ingress=0, dispatch=(), prepare=0, execute=0, refunded=0.0,
         receipts=0, all_verify=True, refusals=0, internal_errors=0,
         proof_sha=(), proof_len=()):
    return {
        "seq": seq,
        "counters": {
            "http_ingress": ingress,
            "tool_dispatch": list(dispatch),
            "prepare": prepare,
            "execute": execute,
            "refunded_total": refunded,
            "receipts": receipts,
            "receipts_all_verify": all_verify,
            "receipt_ids": [f"refund-service:{i + 1}" for i in range(receipts)],
            "refusals": refusals,
            "internal_errors": internal_errors,
            "inbound_proof_sha": list(proof_sha),
            "inbound_proof_len": list(proof_len),
        },
        "events": [],
    }


def ok_case(**over):
    # ``outcome`` is only consulted by the outcomes that produce no HTTP status,
    # but it is present here so a sweep across every declared case exercises the
    # check under test rather than tripping the completeness guard first.
    base = {"http_status": 200, "policy_denied": False, "transport_error": False,
            "is_error": False, "decision": "authorized", "status_code": "authorized_agent",
            "reason": "", "receipt_id": "refund-service:1", "refunded": 75.0,
            "outcome": "returned"}
    base.update(over)
    return base


SENT = {"sha256": "a" * 64, "len": 1234}


def authorized_pair():
    """A clean before/after pair for one authorized refund of 75.00."""
    before = snap(seq=10, ingress=5, dispatch=[PREPARE], prepare=1)
    # ingress + dispatch + execute + its decision + proof_observed = 5 events.
    after = snap(seq=15, ingress=6, dispatch=[PREPARE, EXECUTE], prepare=1, execute=1,
                 refunded=75.0, receipts=1, proof_sha=[SENT["sha256"]],
                 proof_len=[SENT["len"]])
    return before, after


AUTHORIZE = GROUPS["positive_and_replay"]["execute_valid"]


# -- baselines -------------------------------------------------------------

def test_a_clean_authorized_run_passes():
    """WHY: the baseline. If a correct run cannot pass, every failure below
    proves nothing, because a uniformly-failing adjudicator is as useless as a
    uniformly-passing one."""
    before, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "PASS", v.detail


def test_a_clean_openshell_denial_passes():
    """WHY: the other baseline. A policy refusal that the receiver genuinely
    never saw is the intended behaviour, not a failure."""
    s = snap(seq=3, ingress=2)
    v = judge("denied", openshell_denial_expect(),
              {"http_status": 403, "policy_denied": True}, s, s)
    assert v.result == "PASS", v.detail


# -- 1-4: evidence that is absent, incomplete, or inconsistent -------------

def test_a_missing_case_fails():
    """WHY: absence of evidence is not evidence of safety. A case that did not
    execute must fail loudly rather than vanish from the artifact, or a run
    that skipped half the matrix would report clean."""
    before, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, None, before, after, SENT)
    assert v.result == "FAIL"
    assert "did not execute" in v.detail


def test_a_missing_before_snapshot_fails():
    """WHY: without a before snapshot the case's effects cannot be separated
    from every other case's, so no delta claim about it is honest."""
    _, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, ok_case(), None, after, SENT)
    assert v.result == "FAIL"
    assert "before snapshot" in v.detail


def test_a_missing_after_snapshot_fails():
    """WHY: the same, from the other end. An unbounded case could have moved
    money after the last observation and nothing would show it."""
    before, _ = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, None, SENT)
    assert v.result == "FAIL"
    assert "after snapshot" in v.detail


def test_a_stale_sequence_fails():
    """WHY: a monotonic sequence is the only thing that proves the 'after'
    snapshot was taken after the case ran. An after that precedes its before is
    a stale read, and stale reads are exactly what the polled state file used
    to hand the adjudicator."""
    before, after = authorized_pair()
    after["seq"] = before["seq"] - 1
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "stale" in v.detail


def test_a_snapshot_without_a_sequence_number_fails():
    """WHY: a snapshot with no sequence cannot be ordered against any other, so
    it cannot support a delta claim at all."""
    before, after = authorized_pair()
    del after["seq"]
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "sequence number" in v.detail


# -- 5-6: the two layers disagreeing with their declared expectation -------

def test_an_expected_openshell_denial_that_was_admitted_fails():
    """WHY: a policy layer that admits what it must refuse is precisely the
    finding this profile exists to surface. Tolerating it would make the
    profile a rubber stamp."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=13, ingress=6, dispatch=[EXECUTE], execute=1, receipts=1)
    v = judge("unlisted", openshell_denial_expect(),
              ok_case(decision="denied", status_code="invalid"), before, after)
    assert v.result == "FAIL"
    assert "expected refusal before MCP ingress" in v.detail


def test_an_expected_admission_that_was_denied_fails():
    """WHY: the adjudicator must distinguish 'a denial is acceptable here' from
    'a denial means something broke'. Cases without or_deny are the ones whose
    admission is itself the property under test."""
    s = snap(seq=10, ingress=5)
    v = judge("prepare_valid", prepare_expect(),
              {"http_status": 403, "policy_denied": True}, s, s)
    assert v.result == "FAIL"
    assert "unexpectedly denied" in v.detail


def test_a_permitted_denial_passes_only_when_the_receiver_saw_nothing():
    """WHY: or_deny means the policy layer may be stricter than the server. It
    does not mean a request reported as denied may still have been served: that
    combination is the smuggling outcome, dressed as a denial."""
    parser = GROUPS["parser_differentials"]["dup_name_allowed_then_denied"]
    clean = snap(seq=10, ingress=5)
    v = judge("dup", parser, {"http_status": 403, "policy_denied": True}, clean, clean)
    assert v.result == "PASS", v.detail

    after = snap(seq=13, ingress=6, dispatch=[EXECUTE], execute=1, receipts=1)
    v = judge("dup", parser, {"http_status": 403, "policy_denied": True}, clean, after)
    # A 4xx that still produced ingress is not a policy denial at all, so the
    # case is judged as an admission and fails on the non-200 status.
    assert v.result == "FAIL"
    assert "not an authorization outcome" in v.detail


# -- 7-8: dispatch identity ------------------------------------------------

def test_the_wrong_tool_dispatched_fails():
    """WHY: the core invariant of the whole parser matrix. Admitted as one
    identity and dispatched as another is a confused-deputy bug even when both
    tools are individually allowed."""
    before = snap(seq=10, ingress=5)
    # Everything the authorized case expects, except that the server dispatched
    # the other tool.
    after = snap(seq=15, ingress=6, dispatch=[PREPARE], execute=1, refunded=75.0,
                 receipts=1, proof_sha=[SENT["sha256"]], proof_len=[SENT["len"]])
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "dispatched ['refund.prepare']" in v.detail


def test_an_admin_tool_dispatched_fails_every_case():
    """WHY: this is the smuggling outcome the matrix exists to detect. If an
    unlisted tool ran, no case may report success, whatever its own HTTP status
    looked like and whatever else it expected."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=6, dispatch=["admin.wipe"], execute=1)
    for group, cases in GROUPS.items():
        for name, expect in cases.items():
            v = judge(name, expect, ok_case(), before, after, SENT)
            assert v.result == "FAIL", f"{group}::{name} passed with an admin dispatch"
            assert "unlisted tool was dispatched" in v.detail


# -- 9-10: MCP ingress -----------------------------------------------------

def test_unexpected_mcp_ingress_fails():
    """WHY: 'RefundService was not reached' does not prove 'the request never
    arrived'. Ingress is counted separately precisely so a denial that leaked a
    request to the ASGI app cannot be reported as a clean refusal."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=11, ingress=6)
    v = judge("denied", openshell_denial_expect(),
              {"http_status": 403, "policy_denied": True}, before, after)
    assert v.result == "FAIL"
    assert "ingress" in v.detail


def test_missing_expected_mcp_ingress_fails():
    """WHY: a case that reports HTTP 200 but produced no ingress was answered by
    something other than the receiver. Believing the status code over the
    receiver's own counter is how a harness ends up testing a proxy."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=13, ingress=5, dispatch=[EXECUTE], execute=1, refunded=75.0,
                 receipts=1, proof_sha=[SENT["sha256"]], proof_len=[SENT["len"]])
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "http_ingress delta 0" in v.detail


# -- 11-12: RefundService entry -------------------------------------------

def test_an_unexpected_refundservice_entry_fails():
    """WHY: a case refused at the MCP boundary must never reach the receiver. If
    execute() ran anyway, the boundary check is decorative."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=6, dispatch=[EXECUTE], execute=1, refusals=1,
                 proof_sha=["x" * 64], proof_len=[10])
    v = judge("malformed_proof", carriage_refusal_expect(),
              ok_case(is_error=True, error_text="invalid base64", decision=None,
                      status_code=None, receipt_id=None, refunded=None),
              before, after)
    assert v.result == "FAIL"
    assert "execute delta 1" in v.detail


def test_a_missing_refundservice_entry_fails():
    """WHY: a denial that never reached the receiver is not a Ratify denial. It
    would let a transport failure be recorded as a semantic authorization
    result, which is the single most misleading thing this artifact could
    claim."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=12, ingress=6, dispatch=[EXECUTE], receipts=1,
                 proof_sha=["x" * 64], proof_len=[10])
    v = judge("expired_delegation", denial_expect("expired"),
              ok_case(decision="denied", status_code="expired", refunded=0.0),
              before, after)
    assert v.result == "FAIL"
    assert "execute delta 0" in v.detail


# -- 13-16: money and receipts --------------------------------------------

def test_an_unexpected_refund_fails():
    """WHY: the one thing a denial must never do is move money. A denial that
    refunded is the worst possible outcome and must never read as a pass."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=6, dispatch=[EXECUTE], execute=1, refunded=75.0,
                 receipts=1, proof_sha=["x" * 64], proof_len=[10])
    v = judge("expired_delegation", denial_expect("expired"),
              ok_case(decision="denied", status_code="expired", refunded=0.0),
              before, after)
    assert v.result == "FAIL"
    assert "refund delta 75.0" in v.detail


def test_an_unexpected_receipt_fails():
    """WHY: a receipt is an attestation that a holder of the agent key presented
    a proof and the verifier ruled on it. Minting one for traffic that never
    authenticated gives an unauthenticated caller a write primitive into the
    audit trail."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=6, dispatch=[EXECUTE], execute=1, refusals=1,
                 receipts=1, proof_sha=["x" * 64], proof_len=[10])
    v = judge("execute_replay", refusal_expect(),
              ok_case(decision="denied", status_code="invalid", refunded=0.0,
                      receipt_id=""),
              before, after)
    assert v.result == "FAIL"
    assert "receipt delta 1" in v.detail


def test_a_missing_receipt_fails():
    """WHY: an authorized action with no attestation is an unauditable one. The
    receipt is the deliverable, not a side effect."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=6, dispatch=[EXECUTE], execute=1, refunded=75.0,
                 receipts=0, proof_sha=[SENT["sha256"]], proof_len=[SENT["len"]])
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "receipt delta 0" in v.detail


def test_receipt_verification_failure_fails():
    """WHY: counting receipts is not verifying them. A receipt that does not
    verify is worse than no receipt, because it looks like evidence."""
    before, after = authorized_pair()
    after["counters"]["receipts_all_verify"] = False
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "receipt verification failed" in v.detail


def test_an_empty_receipt_set_is_not_treated_as_verified():
    """WHY: ``all()`` over an empty sequence is True. A receiver that issued
    nothing would otherwise report 'every receipt verified' and the artifact
    would carry vacuous truth as positive verification evidence."""
    before = snap(seq=10, ingress=5, receipts=0)
    after = snap(seq=14, ingress=6, dispatch=[EXECUTE], execute=1, refunded=75.0,
                 receipts=0, all_verify=True,
                 proof_sha=[SENT["sha256"]], proof_len=[SENT["len"]])
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    # It is caught as a receipt-count failure, and must never surface as a pass.
    assert "receipt" in v.detail


# -- 17: carriage fidelity -------------------------------------------------

def test_a_proof_hash_mismatch_fails():
    """WHY: the whole claim is that the proof crosses the policy boundary
    unaltered. If the bytes the receiver measured are not the bytes the runner
    signed, something in the path rewrote authorization material and every
    downstream verdict is suspect."""
    before, after = authorized_pair()
    after["counters"]["inbound_proof_sha"] = ["b" * 64]
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "changed in transit" in v.detail


def test_a_proof_length_mismatch_fails():
    """WHY: same property, and the length is checked as well as the hash so a
    truncation that happened to be recorded with a stale hash still fails."""
    before, after = authorized_pair()
    after["counters"]["inbound_proof_len"] = [SENT["len"] - 1]
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "changed in transit" in v.detail


def test_fidelity_without_a_sent_measurement_fails():
    """WHY: comparing against nothing is not a comparison. A missing sent-proof
    record must fail rather than skip the check."""
    before, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, None)
    assert v.result == "FAIL"
    assert "no sent-proof measurement" in v.detail


# -- 18-20: transport and log integrity ------------------------------------

def test_a_5xx_response_is_not_an_authorization_outcome():
    """WHY: an infrastructure failure must never masquerade as a security
    result. A 500 means the run is broken, not that the system denied
    something."""
    before, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, ok_case(http_status=500), before, after, SENT)
    assert v.result == "FAIL"
    assert "500" in v.detail


def test_a_partial_downloaded_result_fails():
    """WHY: a truncated or half-written result file is not evidence. Reading a
    missing field as absent-and-therefore-fine is how a failed download becomes
    a green artifact."""
    before, after = authorized_pair()
    v = judge("execute_valid", AUTHORIZE, {"policy_denied": False}, before, after, SENT)
    assert v.result == "FAIL"
    assert "partial result" in v.detail


def test_an_extra_unexplained_event_fails():
    """WHY: the sequence must advance by exactly what the deltas account for. A
    larger jump means the receiver recorded activity this case did not cause,
    so the snapshots do not bound the case and none of its deltas are
    attributable to it."""
    before, after = authorized_pair()
    after["seq"] += 3
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "unexplained events" in v.detail


def test_a_rewritten_dispatch_log_fails():
    """WHY: the dispatch log is append-only. If its prefix changed between two
    snapshots, the two are not from the same run, or something rewrote the
    record the adjudicator depends on."""
    before = snap(seq=10, ingress=5, dispatch=[PREPARE])
    after = snap(seq=14, ingress=6, dispatch=["something.else", EXECUTE], execute=1)
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "append-only" in v.detail


def test_an_internal_error_fails():
    """WHY: an internal error during a case means the receiver hit a path it did
    not expect. That is never an acceptable component of a passing security
    result."""
    before, after = authorized_pair()
    after["counters"]["internal_errors"] = 1
    v = judge("execute_valid", AUTHORIZE, ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "internal_errors" in v.detail


def test_a_transport_error_is_not_a_pass_where_admission_was_required():
    """WHY: a blocked socket and an admitted request are opposite outcomes. A
    case that had to be admitted cannot pass because the connection failed."""
    s = snap(seq=10, ingress=5)
    v = judge("prepare_valid", prepare_expect(),
              {"http_status": None, "policy_denied": False, "transport_error": True}, s, s)
    assert v.result == "FAIL"


# -- structural guarantees -------------------------------------------------

def test_every_declared_case_is_adjudicated_even_with_no_evidence():
    """WHY: a case that produced no evidence must still appear in the report as
    a failure. Dropping it would shrink the denominator and make a partial run
    look complete."""
    for group in GROUPS:
        verdicts = adjudicate_group(group, {})
        assert len(verdicts) == len(GROUPS[group])
        assert all(v.result == "FAIL" for v in verdicts)


def test_no_case_the_driver_runs_is_left_without_an_expectation():
    """WHY: a case constructed but not adjudicated cannot fail, which is the
    exact defect this file was written for. Any probe added to a group must also
    declare what it expects."""
    assert missing_expectations("positive_and_replay", ["prepare_valid"]) == []
    assert missing_expectations("positive_and_replay", ["invented"]) == ["invented"]


def test_required_cases_are_enumerated_and_non_empty():
    """WHY: the artifact's not_executed list is meaningless without a fixed
    denominator of what was required in the first place."""
    assert len(REQUIRED_CASES) >= 40
    assert all("::" in name for name in REQUIRED_CASES)
    assert len(set(REQUIRED_CASES)) == len(REQUIRED_CASES)


def test_every_expectation_declares_a_known_outcome():
    """WHY: an unknown outcome string would fall through to a default. There is
    no safe default for 'what should this security case have done'."""
    known = {"authorize", "deny_at_ratify", "deny_at_openshell", "admit_as",
             "inert", "tool_denied_at_openshell"}
    for group, cases in GROUPS.items():
        for name, expect in cases.items():
            assert expect.outcome in known, f"{group}::{name} has outcome {expect.outcome!r}"


def test_an_unknown_outcome_fails_closed():
    """WHY: if an outcome string is ever mistyped, the adjudicator must refuse
    to judge rather than silently pass the case."""
    before, after = authorized_pair()
    v = judge("weird", Expect(outcome="probably_fine", ingress=1, dispatch=(EXECUTE,),
                              execute=1, refund=75.0, receipts=1, proof_observed=1),
              ok_case(), before, after, SENT)
    assert v.result == "FAIL"
    assert "unknown expected outcome" in v.detail


def test_an_inert_case_with_no_recorded_outcome_fails():
    """WHY: the completeness check has to follow the shape each outcome actually
    produces. An inert case yields no HTTP status by construction, so its
    evidence of having run is the outcome field, and a report missing that is
    just as incomplete as a truncated HTTP result."""
    s = snap(seq=10, ingress=5)
    v = judge("inert", GROUPS["nooa_full_path"]["nooa_capability_inert_without_the_adapter"],
              {"policy_denied": False}, s, s)
    assert v.result == "FAIL"
    assert "no outcome recorded" in v.detail


def test_an_inert_capability_that_actually_sent_traffic_fails():
    """WHY: "removing the adapter leaves the capability inert" is only a claim
    about the composition if traffic reaching the receiver falsifies it. An
    inert case that produced ingress means the capability found another way to
    act, which is the opposite of the property."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=11, ingress=6)
    v = judge("inert", GROUPS["nooa_full_path"]["nooa_capability_inert_without_the_adapter"],
              {"http_status": None, "outcome": "capability_inert"}, before, after)
    assert v.result == "FAIL"
    assert "inert capability" in v.detail


def test_an_inert_capability_that_returned_a_decision_fails():
    """WHY: the capability must refuse to run, not run and be denied. A
    returned decision means the adapter was not actually absent."""
    s = snap(seq=10, ingress=5)
    v = judge("inert", GROUPS["nooa_full_path"]["nooa_capability_inert_without_the_adapter"],
              {"http_status": 200, "outcome": "returned"}, s, s)
    assert v.result == "FAIL"
    assert "refuse to run" in v.detail


def test_an_openshell_tool_refusal_that_dispatched_fails():
    """WHY: the handshake being admitted must not license a tool call. If the
    tool dispatched anyway, the policy did not hold, whatever the client saw."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=14, ingress=7, dispatch=[EXECUTE], execute=1)
    v = judge("tool", GROUPS["nooa_full_path"]["nooa_unlisted_tool_denied_by_openshell"],
              {"http_status": None, "outcome": "mcp_transport_error"}, before, after)
    assert v.result == "FAIL"
    assert "dispatched despite the refusal" in v.detail


def test_an_openshell_tool_refusal_with_the_wrong_handshake_count_fails():
    """WHY: the ingress budget for this case is exactly the handshake. More than
    that means the refused tool call still reached the receiver."""
    before = snap(seq=10, ingress=5)
    after = snap(seq=13, ingress=8)
    v = judge("tool", GROUPS["nooa_full_path"]["nooa_unlisted_tool_denied_by_openshell"],
              {"http_status": None, "outcome": "mcp_transport_error"}, before, after)
    assert v.result == "FAIL"
    assert "handshake only" in v.detail


@pytest.mark.parametrize("status", [200, 403])
def test_judgement_never_depends_on_the_case_merely_existing(status):
    """WHY: the exact defect this file was written for. The presence of a result
    record must not, by itself, produce a pass."""
    clean = snap(seq=10, ingress=5)
    v = judge("unlisted", openshell_denial_expect(),
              {"http_status": status, "policy_denied": status == 403}, clean, clean)
    assert (v.result == "PASS") == (status == 403)


# -- the unified suite's event windows --------------------------------------
#
# One sandbox execution produces one interleaved event stream for every unified
# subcase, so the per-subcase snapshot pair is *derived* rather than measured.
# That derivation is the only thing standing between "each subcase was judged on
# its own effects" and "the subcases were judged on each other's". It had no
# tests; these are them.

TENANT_A = "tenant/acme/orders/canary-s1"
TENANT_B = "tenant/acme/orders/canary-s2"


def ev(seq, kind, **extra):
    return {"seq": seq, "event_type": kind, **extra}


def business_events(first_seq, resource, authorized):
    """The ten events one adapter-installed subcase produces, in receiver order.

    Two handshake requests, then prepare (dispatch precedes the prepare it
    causes, which is why segmentation splits on ingress and not on prepare),
    then execute, its proof measurement, and the decision.
    """
    s = first_seq
    return [
        ev(s, "http_ingress"), ev(s + 1, "http_ingress"),
        ev(s + 2, "http_ingress"),
        ev(s + 3, "tool_dispatch", tool_name=PREPARE),
        ev(s + 4, "prepare", resource_id=resource),
        ev(s + 5, "http_ingress"),
        ev(s + 6, "tool_dispatch", tool_name=EXECUTE),
        ev(s + 7, "proof_observed", proof_sha256="b" * 64, proof_len=900),
        ev(s + 8, "execute"),
        ev(s + 9, "decision",
           decision="authorized" if authorized else "denied",
           receipt_id="refund-service:1"),
    ]


def suite_stream(resource_a=TENANT_A, resource_b=TENANT_B, trailing=(), leading=()):
    """The recorded shape of a real unified suite: 22 events, four subcases.

    inert makes no request at all; two subcases run the full path; the last one
    is refused by the policy after its handshake, so it owns two events and no
    prepare.
    """
    events = list(leading)
    offset = len(events)
    events += business_events(offset + 1, resource_a, authorized=True)
    events += business_events(offset + 11, resource_b, authorized=False)
    events += [ev(offset + 21, "http_ingress"), ev(offset + 22, "http_ingress")]
    events += list(trailing)
    for index, event in enumerate(events):
        event["seq"] = index + 1
    return events


SUBCASES = [
    {"name": "nooa_capability_inert_without_the_adapter", "install_adapter": False},
    {"name": "nooa_authorized_refund", "install_adapter": True},
    {"name": "nooa_over_limit_denied_by_ratify", "install_adapter": True},
    {"name": "nooa_unlisted_tool_denied_by_openshell", "install_adapter": True},
]

RESOURCES = {
    "nooa_capability_inert_without_the_adapter": "tenant/acme/orders/canary-s0",
    "nooa_authorized_refund": TENANT_A,
    "nooa_over_limit_denied_by_ratify": TENANT_B,
    "nooa_unlisted_tool_denied_by_openshell": "tenant/acme/orders/canary-s3",
}


def segment(events, resources=None):
    from openshell_driver import Runner

    before = snap(seq=0)
    after = snap(seq=len(events), ingress=8, dispatch=[PREPARE, EXECUTE] * 2,
                 prepare=2, execute=2, refunded=75.0, receipts=2,
                 proof_sha=["b" * 64] * 2, proof_len=[900] * 2)
    after["events"] = events
    windows = Runner._segment_suite(before, after, SUBCASES,
                                    {"nooa_resources": resources or RESOURCES})
    reconciliation = Runner._reconcile_suite(before, after, windows, SUBCASES)
    return windows, reconciliation


UNIFIED = GROUPS["nooa_full_path"]


def test_the_unified_windows_partition_the_event_log_and_every_subcase_passes():
    """WHY: the baseline for attribution. Each subcase must be judged PASS on
    the events its own window contains, and the windows together must account
    for every event the receiver recorded. If the parts do not sum to the whole,
    some subcase was credited with another's effects and every unified verdict
    is unsound."""
    windows, reconciliation = segment(suite_stream())
    assert reconciliation == {"reconciled": True, "events_in_suite": 22,
                              "events_attributed": 22}

    cases = {
        "nooa_capability_inert_without_the_adapter": {"outcome": "capability_inert"},
        "nooa_authorized_refund": ok_case(),
        "nooa_over_limit_denied_by_ratify": ok_case(
            decision="denied", status_code="constraint_denied", receipt_id=None,
            refunded=None),
        "nooa_unlisted_tool_denied_by_openshell": {"outcome": "mcp_transport_error"},
    }
    for name, case in cases.items():
        before, after = windows[name]
        v = judge(name, UNIFIED[name], case, before, after)
        assert v.result == "PASS", f"{name}: {v.detail}"


def test_the_inert_subcase_never_claims_an_anonymous_window():
    """WHY: the unlisted-tool subcase produces a handshake and no prepare, so
    its window cannot be identified by resource. Letting any unmatched subcase
    take it handed the inert subcase two ingress events it did not cause, and
    reported both subcases wrongly. A subcase with no adapter installs no client
    and can never own a segment."""
    windows, _ = segment(suite_stream())
    before, after = windows["nooa_capability_inert_without_the_adapter"]
    assert before["seq"] == after["seq"] == 0
    tool_before, tool_after = windows["nooa_unlisted_tool_denied_by_openshell"]
    assert tool_after["seq"] - tool_before["seq"] == 2


def test_a_trailing_event_no_subcase_explains_fails_the_last_subcase():
    """WHY: the final subcase's window runs to the end of the stream, so an
    unexplained trailing event is absorbed into it rather than left over, and
    reconciliation alone cannot see it. The outcome's own event budget is the
    only thing that catches it: a policy refusal accounts for its handshake
    requests and nothing else."""
    events = suite_stream(trailing=[ev(0, "proof_observed", proof_sha256="c" * 64,
                                       proof_len=10)])
    windows, reconciliation = segment(events)
    assert reconciliation["reconciled"] is True  # absorbed, not left over
    before, after = windows["nooa_unlisted_tool_denied_by_openshell"]
    v = judge("tool", UNIFIED["nooa_unlisted_tool_denied_by_openshell"],
              {"outcome": "mcp_transport_error"}, before, after)
    assert v.result == "FAIL"
    assert "inbound proof" in v.detail


def test_an_event_before_the_first_window_is_left_unattributed():
    """WHY: a segment begins at an ingress that opens a fresh MCP session, so
    anything the receiver recorded before the first one belongs to no subcase.
    It must show up as a shortfall rather than being folded into whichever
    subcase happened to start next."""
    _, reconciliation = segment(suite_stream(leading=[ev(0, "execute")]))
    assert reconciliation["reconciled"] is False
    assert reconciliation["events_attributed"] < reconciliation["events_in_suite"]


def test_two_subcases_that_derived_the_same_resource_are_not_both_credited():
    """WHY: per-subcase attribution rests on each subcase having its own order,
    so the receiver derives a distinct canonical resource for each. If two ever
    collided, one window would be claimed twice and the other lost; the sum must
    refuse to reconcile rather than quietly reporting both as judged."""
    _, reconciliation = segment(suite_stream(resource_a=TENANT_A, resource_b=TENANT_A))
    assert reconciliation["reconciled"] is False
    assert reconciliation["events_attributed"] == 12


def test_reconciliation_of_a_suite_with_no_snapshots_fails_closed():
    """WHY: absence of evidence is not evidence of attribution. A suite whose
    snapshots are missing has not been bounded at all."""
    from openshell_driver import Runner

    assert Runner._reconcile_suite(None, snap(seq=1), {}, SUBCASES)["reconciled"] is False
    assert Runner._segment_suite(None, snap(seq=1), SUBCASES, {}) == {}


# -- parser coverage --------------------------------------------------------
#
# The safety invariant and the coverage gate are complementary. Safety is
# "admitted as X, never dispatched as Y", which a policy that denies everything
# satisfies vacuously; removing the refund.execute allow rule left all fifteen
# parser verdicts PASS on a real run. These tests are why that can no longer be
# reported as a working parser matrix.

from openshell_cases import (  # noqa: E402
    PARSER_EXPECTED_BRANCH,
    parser_branch,
    parser_coverage,
)


def branch_deltas(branch_of):
    """Per-case deltas that produce the requested branch for each parser probe."""
    out = {}
    for name, branch in branch_of.items():
        if branch == "admitted":
            out[name] = {"http_ingress": 1, "tool_dispatch": [EXECUTE]}
        elif branch == "denied":
            out[name] = {"http_ingress": 0, "tool_dispatch": []}
        else:
            out[name] = {"http_ingress": 1, "tool_dispatch": []}
    return out


def test_the_expected_branch_table_covers_exactly_the_parser_group():
    """WHY: a coverage table that omitted a probe would let that probe take
    either branch unnoticed, which is the hole this gate exists to close."""
    assert set(PARSER_EXPECTED_BRANCH) == set(GROUPS["parser_differentials"])


def test_the_normal_parser_matrix_passes_coverage():
    """WHY: the baseline. Measured against v0.0.102 the matrix admits ten probes
    and denies five; if that cannot pass, every failure below proves nothing."""
    c = parser_coverage(branch_deltas(PARSER_EXPECTED_BRANCH))
    assert c["result"] == "PASS"
    assert (c["admitted"], c["denied"]) == (10, 5)


def test_a_deny_all_policy_fails_coverage():
    """WHY: the exact situation observed when the refund.execute allow rule was
    removed. Every parser verdict passed, because a blanket refusal never
    laundered one tool into another. Coverage is what must fail there."""
    c = parser_coverage(branch_deltas({n: "denied" for n in PARSER_EXPECTED_BRANCH}))
    assert c["result"] == "FAIL"
    assert c["admitted"] == 0
    assert len(c["mismatched"]) == 10


def test_an_allow_all_policy_fails_coverage():
    """WHY: the mirror image. If the policy stopped refusing the malformations it
    is supposed to refuse, the matrix would still show no smuggling, and the
    denial branch would silently disappear."""
    c = parser_coverage(branch_deltas({n: "admitted" for n in PARSER_EXPECTED_BRANCH}))
    assert c["result"] == "FAIL"
    assert c["denied"] == 0


def test_two_probes_swapping_branches_fails_even_though_the_totals_match():
    """WHY: aggregate counts would call this correct. The branch each probe takes
    is a property of that probe, so it is compared per case."""
    swapped = dict(PARSER_EXPECTED_BRANCH)
    swapped["dup_hdr_method"] = "denied"        # was admitted
    swapped["dup_params_container"] = "admitted"  # was denied
    c = parser_coverage(branch_deltas(swapped))
    assert c["result"] == "FAIL"
    assert (c["admitted"], c["denied"]) == (10, 5)  # totals unchanged
    assert len(c["mismatched"]) == 2


def test_a_probe_that_reached_ingress_without_dispatching_is_not_coverage():
    """WHY: admission means the request crossed the boundary *and* dispatched the
    effective tool. Counting a request that arrived and did nothing would report
    a half-executed probe as evidence that the branch works."""
    deltas = branch_deltas(PARSER_EXPECTED_BRANCH)
    deltas["dup_hdr_method"] = {"http_ingress": 1, "tool_dispatch": []}
    c = parser_coverage(deltas)
    assert c["result"] == "FAIL"
    assert c["unaccounted"] == ["dup_hdr_method"]


def test_a_probe_that_dispatched_the_wrong_tool_is_not_coverage():
    """WHY: dispatching something other than the effective tool is the smuggling
    the safety invariant forbids; coverage must not launder it into a pass."""
    deltas = branch_deltas(PARSER_EXPECTED_BRANCH)
    deltas["dup_hdr_name"] = {"http_ingress": 1, "tool_dispatch": [PREPARE]}
    assert parser_branch(deltas["dup_hdr_name"]) == "unaccounted"
    assert parser_coverage(deltas)["result"] == "FAIL"


def test_a_parser_probe_with_no_evidence_fails_coverage():
    """WHY: absence of evidence is not coverage. A probe that produced no deltas
    at all has demonstrated neither branch."""
    deltas = branch_deltas(PARSER_EXPECTED_BRANCH)
    del deltas["hdr_method_missing"]
    c = parser_coverage(deltas)
    assert c["result"] == "FAIL"
    assert c["unaccounted"] == ["hdr_method_missing"]


# -- driver-level failure accounting ----------------------------------------
#
# Case verdicts and driver errors are complementary. A run in which the entire
# unified group vanished failed its four case gates and still reported
# driver_errors: [], so driver_reported_no_errors was a weaker claim than its
# name. These tests fix the semantics in place.

import json as _json  # noqa: E402
import shutil  # noqa: E402
import types  # noqa: E402

# Resolved rather than hardcoded: `true` and `false` live in /usr/bin on macOS and
# /bin on most Linuxes, and a wrong path tests "binary missing" instead of "binary
# exited non-zero", which is a different branch of the accounting.
TRUE = shutil.which("true")
FALSE = shutil.which("false")


def driver(tmp_path, openshell=None):
    from openshell_driver import Runner

    return Runner(types.SimpleNamespace(
        work=str(tmp_path), openshell=openshell or TRUE, gateway_endpoint="http://127.0.0.1:1",
        sandbox="sb", sandbox_dir="/sandbox/x", mcp_host="127.0.0.1", mcp_port=1,
        ctrl_port=2, run_id="test", gateway_dir=str(tmp_path), artifact=str(tmp_path / "a"),
    ))


def kinds(runner):
    return sorted(e["kind"] for e in runner.errors)


SUITE_PLAN = [{"name": n} for n in (
    "nooa_capability_inert_without_the_adapter", "nooa_authorized_refund",
    "nooa_over_limit_denied_by_ratify", "nooa_unlisted_tool_denied_by_openshell")]


def complete_suite():
    return {"step": "suite", "nooa_imports": 1, "nooa_imports_measured": True,
            "subcases": [{"subcase": s["name"], "outcome": "returned"} for s in SUITE_PLAN]}


def test_a_complete_suite_records_no_driver_error(tmp_path):
    """WHY: the baseline that stops this accounting from crying wolf. If a healthy
    suite produced driver errors, the gate would be useless in the other
    direction and would be ignored."""
    r = driver(tmp_path)
    r._check_suite_report(complete_suite(), SUITE_PLAN, "nooa_full_path")
    assert r.errors == []


def test_a_vanished_unified_suite_records_a_driver_error(tmp_path):
    """WHY: the defect this exists for. A suite that produced no parseable report
    at all failed its case gates but left driver_errors empty, so the artifact
    said nothing had gone wrong with the harness while a whole group was
    missing."""
    r = driver(tmp_path)
    r._check_suite_report(None, SUITE_PLAN, "nooa_full_path")
    assert kinds(r) == ["missing_result"]


def test_a_partial_unified_suite_records_a_driver_error(tmp_path):
    """WHY: fewer records than subcases is a harness failure, not a set of
    individually failing cases. Both must be reported."""
    report = complete_suite()
    report["subcases"] = report["subcases"][:2]
    r = driver(tmp_path)
    r._check_suite_report(report, SUITE_PLAN, "nooa_full_path")
    assert "partial_suite" in kinds(r)
    assert kinds(r).count("missing_subcase") == 2


def test_a_suite_report_from_another_step_is_misattributed(tmp_path):
    """WHY: the isolated per-subcase `run` mode writes a report of the same shape.
    Adjudicating one of those as though it were the suite would attribute one
    subcase's evidence to four."""
    report = complete_suite()
    report["step"] = "run"
    r = driver(tmp_path)
    r._check_suite_report(report, SUITE_PLAN, "nooa_full_path")
    assert "misattributed_result" in kinds(r)


def test_a_suite_record_without_an_outcome_is_incomplete(tmp_path):
    """WHY: a record with no outcome cannot be judged, and a truncated record
    must not be mistaken for a subcase that ran."""
    report = complete_suite()
    del report["subcases"][1]["outcome"]
    r = driver(tmp_path)
    r._check_suite_report(report, SUITE_PLAN, "nooa_full_path")
    assert "incomplete_result" in kinds(r)


def test_an_unplanned_subcase_in_the_report_is_misattributed(tmp_path):
    """WHY: a report naming a subcase the driver never launched is evidence the
    report belongs to another run."""
    report = complete_suite()
    report["subcases"].append({"subcase": "invented", "outcome": "returned"})
    r = driver(tmp_path)
    r._check_suite_report(report, SUITE_PLAN, "nooa_full_path")
    assert "misattributed_result" in kinds(r)


def test_a_result_belonging_to_another_group_records_a_driver_error(tmp_path):
    """WHY: the client stamps every report with its group, step and case. Judging
    another group's result as this case's evidence would attribute effects to a
    case that never produced them."""
    r = driver(tmp_path)
    payload = {"group": "size_boundaries", "step": 3, "case": "invalid_base64",
               "result": {"http_status": 200}}
    r.download = lambda remote, local: local.write_text(_json.dumps(payload))
    r._result_of({}, "excessive_amount", 3, "ratify_semantic_denials")
    assert "misattributed_result" in kinds(r)


def test_a_result_for_another_case_records_a_driver_error(tmp_path):
    """WHY: same group, wrong case. The step index alone would not catch a stale
    file left by an earlier case."""
    r = driver(tmp_path)
    payload = {"group": "ratify_semantic_denials", "step": 3, "case": "expired_delegation",
               "result": {"http_status": 200}}
    r.download = lambda remote, local: local.write_text(_json.dumps(payload))
    r._result_of({}, "excessive_amount", 3, "ratify_semantic_denials")
    assert "misattributed_result" in kinds(r)


def test_a_result_that_does_not_parse_records_a_driver_error(tmp_path):
    """WHY: an unparseable download is a harness failure. Silently falling back to
    stdout and then to None is how a whole group disappeared quietly."""
    r = driver(tmp_path)
    r.download = lambda remote, local: local.write_text("{not json")
    assert r._result_of({}, "excessive_amount", 3, "ratify_semantic_denials") is None
    assert kinds(r) == ["malformed_result", "missing_result"]


def test_a_missing_result_records_a_driver_error(tmp_path):
    """WHY: no file and no parseable stdout means no evidence, which must be
    stated rather than returned as None for a case gate to interpret."""
    r = driver(tmp_path)
    r.download = lambda remote, local: None
    assert r._result_of({"stdout": ""}, "excessive_amount", 3, "ratify_semantic_denials") is None
    assert kinds(r) == ["missing_result"]


def test_a_result_without_a_result_member_is_incomplete(tmp_path):
    """WHY: the schema matters, not just the parse. A payload that parsed but
    carries no result member has told the driver nothing about the case."""
    r = driver(tmp_path)
    r.download = lambda remote, local: local.write_text(
        _json.dumps({"group": "ratify_semantic_denials", "step": 3}))
    r._result_of({}, "excessive_amount", 3, "ratify_semantic_denials")
    assert "incomplete_result" in kinds(r)


def test_driver_errors_never_carry_the_subprocess_payload(tmp_path):
    """WHY: driver errors land in the artifact, and the artifact is evidence that
    gets shared. A message that quoted the client's report would carry proof
    material, challenges and delegation bodies out with it."""
    r = driver(tmp_path)
    secret = "eyJhbGciOiJIUzI1NiJ9.SECRETPROOFMATERIAL"
    r.download = lambda remote, local: local.write_text(
        _json.dumps({"group": "other", "step": 3, "case": "x",
                     "result": {"proof": secret}}))
    r._result_of({}, "excessive_amount", 3, "ratify_semantic_denials")
    assert r.errors
    assert all(secret not in _json.dumps(e) for e in r.errors)


def test_a_stale_snapshot_pair_records_a_driver_error(tmp_path):
    """WHY: a sequence that moved backwards means the snapshots are not from one
    run. The adjudicator fails the case; the driver has to say the harness is at
    fault, because no case caused this."""
    r = driver(tmp_path)
    r._check_window(snap(seq=10), snap(seq=4), "positive_and_replay", "execute_valid")
    assert kinds(r) == ["stale_snapshot"]


def test_a_snapshot_without_a_sequence_number_records_a_driver_error(tmp_path):
    """WHY: an unsequenced snapshot cannot bound a case at all."""
    r = driver(tmp_path)
    bad = snap(seq=1); bad["seq"] = None
    r._check_window(snap(seq=1), bad, "positive_and_replay", "execute_valid")
    assert kinds(r) == ["stale_snapshot"]


def test_a_missing_snapshot_records_a_driver_error(tmp_path):
    """WHY: a case that ran without a before/after pair was not measured."""
    r = driver(tmp_path)
    r._check_window(snap(seq=1), None, "positive_and_replay", "execute_valid")
    assert kinds(r) == ["snapshot_unavailable"]


def test_a_healthy_window_records_nothing(tmp_path):
    """WHY: the negative control for the two tests above."""
    r = driver(tmp_path)
    r._check_window(snap(seq=1), snap(seq=11), "positive_and_replay", "execute_valid")
    assert r.errors == []


def test_a_nonzero_openshell_operation_is_recorded(tmp_path):
    """WHY: a refusal under test is carried in the client's result, never in the
    CLI's exit status. Five passing runs recorded 242 operations each with zero
    non-zero exits, so a non-zero exit is an anomaly and must be named."""
    r = driver(tmp_path, openshell=FALSE)
    r.exec("anything")
    assert kinds(r) == ["operation_failed"]


def test_a_successful_openshell_operation_records_nothing(tmp_path):
    """WHY: the negative control. Accounting that fires on success would make the
    gate meaningless."""
    r = driver(tmp_path, openshell=TRUE)
    r.exec("anything")
    assert r.errors == []


def test_an_operation_that_cannot_be_launched_is_recorded(tmp_path):
    """WHY: a missing binary produces no exit status at all, and must not be
    indistinguishable from success."""
    r = driver(tmp_path, openshell=str(tmp_path / "does-not-exist"))
    r.exec("anything")
    assert kinds(r) == ["operation_not_launched"]


def test_an_unknown_group_is_recorded_rather_than_raising(tmp_path):
    """WHY: a declared group with no builder would raise a KeyError and take the
    profile down before it could write an artifact, so there would be no evidence
    of why it died."""
    r = driver(tmp_path)
    r.run_group("group_that_does_not_exist", {})
    assert kinds(r) == ["unknown_group"]


# -- clock-skew preflight ---------------------------------------------------
#
# The in-sandbox presenter backdates its challenge_at by a safety margin. The
# preflight is the diagnostic that says when that margin is no longer enough,
# so a run fails with a clock-discipline error up front instead of a confusing
# stale_challenge somewhere in the middle of the matrix.

from openshell_driver import (  # noqa: E402
    CHALLENGE_CLOCK_SAFETY_MARGIN_SECONDS as MARGIN,
    clock_skew_verdict,
)


def test_measured_platform_skew_passes_the_preflight():
    """WHY: the baseline, using the figures actually measured on the executed
    platform: the sandbox container's clock led the host's by +0.018 to +0.228s
    across six brackets. A preflight that failed on that would block every run."""
    v = clock_skew_verdict([(0.018, 0.228), (0.021, 0.194), (0.019, 0.201)], MARGIN)
    assert v["result"] == "PASS"
    assert v["sandbox_lead_at_least_seconds"] == 0.021


def test_a_lead_beyond_the_margin_fails_with_a_clock_discipline_message():
    """WHY: past the margin, backdating can no longer guarantee a non-negative
    challenge age, so the run would fail somewhere in the matrix for a reason
    that looks like a protocol refusal. It has to be named as what it is."""
    v = clock_skew_verdict([(0.1, 0.4), (MARGIN + 0.5, MARGIN + 0.9)], MARGIN)
    assert v["result"] == "FAIL"
    assert "clock discipline" in v["detail"]


def test_the_verdict_rests_on_the_certain_lead_not_the_optimistic_one():
    """WHY: each sample is a bracket, because the sandbox read its clock somewhere
    between two host readings. Only the largest lower bound is a lead the host can
    be certain of; deciding on the upper bound would fail runs for latency."""
    v = clock_skew_verdict([(0.05, MARGIN + 5.0)], MARGIN)
    assert v["result"] == "PASS"
    assert v["sandbox_lead_at_least_seconds"] == 0.05


def test_no_clock_samples_fails_closed():
    """WHY: absence of evidence is not evidence of a synchronised clock."""
    assert clock_skew_verdict([], MARGIN)["result"] == "FAIL"


# -- bounded download retry --------------------------------------------------
#
# Two concurrent-profile runs each hit one `sandbox download` that exited 1 and
# succeeded on an immediate second attempt, distinct from every exec and upload,
# which never did across the whole engagement. A download only re-reads a file
# the sandbox already finished writing, so retrying it cannot touch anything a
# case gate judges. exec and upload are never retried, because they can reach the
# presentation boundary.

def fake_op(sequence):
    """A stand-in Op whose .run() returns each dict in `sequence` in order,
    ignoring retries/kind/argv, so the retry policy can be tested without a real
    subprocess or a real flake to reproduce."""
    calls = []

    class FakeOp:
        def run(self, kind, argv, stdin_devnull=True, retries=0, retry_delay=0.0):
            calls.append({"kind": kind, "retries": retries})
            attempt = 0
            for record in sequence:
                attempt += 1
                if record.get("returncode") == 0 or attempt > retries:
                    return {**record, "attempts": attempt}
            return {**sequence[-1], "attempts": attempt}

    return FakeOp(), calls


def test_a_download_that_fails_once_then_succeeds_is_not_a_driver_error(tmp_path):
    """WHY: the exact shape observed twice under concurrency. A transient exit-1
    that self-heals on retry must not be reported as a harness failure, because no
    case's evidence was ever unattributed."""
    r = driver(tmp_path)
    r.op, _ = fake_op([{"returncode": 1}, {"returncode": 0}])
    r.download("remote", tmp_path / "local")
    assert r.errors == []
    assert r.retried_operations == [{"stage": "download", "attempts": 2}]


def test_a_download_that_never_recovers_still_records_a_driver_error(tmp_path):
    """WHY: the retry is bounded and must not become a way to hide a genuine
    failure. Exhausting both retries has to reach driver_errors exactly as an
    unretried failure would."""
    r = driver(tmp_path)
    r.op, _ = fake_op([{"returncode": 1}, {"returncode": 1}, {"returncode": 1}])
    r.download("remote", tmp_path / "local")
    assert kinds(r) == ["operation_failed"]
    assert r.retried_operations == []


def test_exec_and_upload_are_never_retried(tmp_path):
    """WHY: exec drives the client that presents to the receiver, and upload
    places the job it reads. Retrying either could re-attempt something
    security-relevant; only download, which reads back a file that already
    exists, is ever given retries."""
    r = driver(tmp_path)
    r.op, calls = fake_op([{"returncode": 1}, {"returncode": 0}])
    r.exec("anything")
    r.op, calls2 = fake_op([{"returncode": 1}, {"returncode": 0}])
    r.upload(tmp_path / "local", "remote")
    assert calls[0]["retries"] == 0
    assert calls2[0]["retries"] == 0
    # Both fail, since the fake only returns success on a retried second call and
    # neither operation is given one.
    assert {e["kind"] for e in r.errors} == {"operation_failed"}


def test_a_download_that_succeeds_first_try_is_not_recorded_as_retried(tmp_path):
    """WHY: the negative control. Every ordinary download must not show up in
    retried_operations, or the field stops meaning anything."""
    r = driver(tmp_path)
    r.op, _ = fake_op([{"returncode": 0}])
    r.download("remote", tmp_path / "local")
    assert r.errors == []
    assert r.retried_operations == []
