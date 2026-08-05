# SPDX-License-Identifier: Apache-2.0
"""Case expectations and per-case adjudication for the OpenShell profile.

Pure functions over recorded evidence. Nothing here talks to Docker, the
OpenShell CLI, or the network, which is what makes the adjudicator testable:
:mod:`test_adjudicator` feeds it evidence of violations and asserts it says
FAIL. That test file exists because an earlier version of this module appended
``{"result": "PASS"}`` for every parser case it found, unconditionally. It
could not fail, so every artifact it produced was worthless.

Two rules the whole design follows:

1. **Every required case declares what it expects.** A case with no declared
   expectation is a case that cannot fail, so :func:`missing_expectations`
   makes that a startup error rather than a silent gap.
2. **Absence of evidence is failure, never success.** A missing case, a
   missing snapshot, a stale sequence number, or a partial result is a FAIL.
   There is no code path that reaches PASS without a complete before/after
   pair and a recorded response.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Where the proof travels. Mirrors mcp_server.PROOF_META_KEY, restated here
#: so this module stays importable without the MCP SDK installed.
PROOF_KEY = "ai.identities.ratify/proof"

#: The refund amount the positive path uses, and the amount a denial must not
#: move. Named once so a gate cannot drift from the case that produced it.
UNDER_LIMIT = 75.0
#: Above the delegation's own cap, and above the capped parent in the
#: amplification chains.
OVER_LIMIT = 500.0

REFUND_PREPARE = "refund.prepare"
REFUND_EXECUTE = "refund.execute"


@dataclass(frozen=True)
class Expect:
    """What a case must do, at every boundary, for it to pass.

    ``outcome`` is the headline:

        ``deny_at_openshell``  refused by the policy layer; the receiver must
                               observe nothing at all
        ``admit_as``           the policy layer admitted it and the server must
                               have dispatched exactly ``tool``
        ``deny_at_ratify``     admitted, dispatched, and refused by the
                               receiver with ``status``
        ``authorize``          admitted, dispatched, verified, and acted on

    Every other field is a required delta between the before and after
    snapshots. They are stated rather than derived because deriving them from
    the outcome is how a harness ends up asserting only what it already
    believes.
    """

    outcome: str
    tool: str | None = None
    status: str | None = None
    ingress: int = 0
    dispatch: tuple[str, ...] = ()
    prepare: int = 0
    execute: int = 0
    refund: float = 0.0
    receipts: int = 0
    refusals: int = 0
    internal_errors: int = 0
    proof_observed: int = 0
    #: Transport-level refusal by the receiver before verification, e.g. a
    #: malformed proof. The tool dispatches, nothing else moves.
    receiver_refused: bool = False
    #: A policy layer is allowed to be stricter than the server. Where that is
    #: acceptable, a denial is not a failure; where it is not, it is.
    or_deny: bool = False
    #: The proof the runner sent must arrive byte-identical.
    proof_fidelity: bool = False
    notes: str = ""


def prepare_expect(**overrides) -> Expect:
    base = dict(
        outcome="admit_as", tool=REFUND_PREPARE, ingress=1,
        dispatch=(REFUND_PREPARE,), prepare=1,
    )
    base.update(overrides)
    return Expect(**base)


def denial_expect(status: str, **overrides) -> Expect:
    """A denial the receiver reached *after* authenticating the presenter.

    Proof of possession succeeded, so the presenter's failed claim of
    authority is a real authorization decision and is attested: one receipt,
    no refusal, no money moved.
    """
    base = dict(
        outcome="deny_at_ratify", status=status, tool=REFUND_EXECUTE, ingress=1,
        dispatch=(REFUND_EXECUTE,), execute=1, receipts=1, proof_observed=1,
    )
    base.update(overrides)
    return Expect(**base)


def refusal_expect(**overrides) -> Expect:
    """A refusal of traffic that never authenticated.

    Recording these as signed receipts would let an unauthenticated caller
    append to the verifier's audit trail at will, so the receipt count must not
    move and the refusal count must.
    """
    base = dict(
        outcome="deny_at_ratify", status="invalid", tool=REFUND_EXECUTE, ingress=1,
        dispatch=(REFUND_EXECUTE,), execute=1, refusals=1, proof_observed=1,
    )
    base.update(overrides)
    return Expect(**base)


def carriage_refusal_expect(**overrides) -> Expect:
    """Refused by the MCP boundary before the receiver was consulted.

    The tool dispatches and the proof is measured, but ``RefundService`` is
    never called, so the execute counter must not move either.
    """
    base = dict(
        outcome="deny_at_ratify", tool=REFUND_EXECUTE, ingress=1,
        dispatch=(REFUND_EXECUTE,), receiver_refused=True, proof_observed=1,
    )
    base.update(overrides)
    return Expect(**base)


def openshell_denial_expect(**overrides) -> Expect:
    """Refused before MCP ingress. Nothing may move anywhere."""
    base = dict(outcome="deny_at_openshell")
    base.update(overrides)
    return Expect(**base)


# --------------------------------------------------------------------------
# Group A: the full positive path, then a replay of the same presentation.
# --------------------------------------------------------------------------
GROUP_A: dict[str, Expect] = {
    "prepare_valid": prepare_expect(notes="receiver issues its own challenge"),
    "execute_valid": Expect(
        outcome="authorize", tool=REFUND_EXECUTE, status="authorized_agent",
        ingress=1, dispatch=(REFUND_EXECUTE,), execute=1, refund=UNDER_LIMIT,
        receipts=1, proof_observed=1, proof_fidelity=True,
        notes="the only case in the whole profile that may move money",
    ),
    "execute_replay": refusal_expect(
        notes="same presentation, second time: the challenge is already spent, "
              "and a spent challenge must not mint a second receipt",
    ),
    "openshell_denies_unlisted_tool": openshell_denial_expect(
        notes="admin.delete_everything is not in the policy",
    ),
}

# --------------------------------------------------------------------------
# Group B: semantic denials. OpenShell admits every one of these; the policy
# layer cannot see an amount, a tenant, an expiry, or a delegation chain, and
# is not asked to. Ratify decides all of them.
# --------------------------------------------------------------------------
GROUP_B: dict[str, Expect] = {
    "excessive_amount": denial_expect("constraint_denied"),
    "wrong_resource_path": denial_expect("constraint_denied"),
    "same_order_other_tenant": denial_expect(
        "constraint_denied",
        notes="alpha.16: resource identity is the tenant-qualified path, so the "
              "same local order id under another tenant is a different resource",
    ),
    "expired_delegation": denial_expect("expired"),
    "revoked_delegation": denial_expect("revoked"),
    "revocation_provider_failure": denial_expect(
        "invalid", notes="a revocation lookup error is not 'not revoked'; it fails closed",
    ),
    "wrong_agent_key": refusal_expect(
        notes="the presented key is not the agent the challenge was issued to, "
              "so this never authenticates and must not be attested",
    ),
    "untrusted_root": denial_expect("unauthorized"),
    "scope_amplification": denial_expect("scope_denied"),
    "constraint_amplification": denial_expect(
        "constraint_denied",
        notes="the child raises the cap the parent set; the parent's cap must bind",
    ),
    "cross_request_proof_movement": refusal_expect(
        notes="a presentation for one challenge, submitted under another",
    ),
    "invalid_challenge": refusal_expect(
        notes="well-formed 32 bytes that this receiver never issued",
    ),
    "malformed_proof": carriage_refusal_expect(
        notes="invalid base64 in the proof member",
    ),
    "observer_failure_after_decision": Expect(
        outcome="authorize", tool=REFUND_EXECUTE, status="authorized_agent",
        ingress=1, dispatch=(REFUND_EXECUTE,), execute=1, refund=UNDER_LIMIT,
        receipts=1, proof_observed=1,
        notes="observability failing after the fact must not turn an executed "
              "refund into an error, and must not change the decision",
    ),
    "no_resource_constraint": Expect(
        outcome="authorize", tool=REFUND_EXECUTE, status="authorized_agent",
        ingress=1, dispatch=(REFUND_EXECUTE,), execute=1, refund=UNDER_LIMIT,
        receipts=1, proof_observed=1,
        notes="a delegation that names no resource is not resource-bound; this "
              "is the control that shows resource_path denials are the "
              "constraint firing rather than a blanket refusal",
    ),
}

# --------------------------------------------------------------------------
# Group C: an alpha.16 maximum-depth chain, carried inline through _meta.
# --------------------------------------------------------------------------
GROUP_C: dict[str, Expect] = {
    "prepare_max_depth": prepare_expect(),
    "execute_max_depth": Expect(
        outcome="authorize", tool=REFUND_EXECUTE, status="authorized_agent",
        ingress=1, dispatch=(REFUND_EXECUTE,), execute=1, refund=UNDER_LIMIT,
        receipts=1, proof_observed=1, proof_fidelity=True,
        notes="depth 8, the protocol maximum, inline in _meta and under the "
              "262,144-byte envelope limit",
    ),
}

# --------------------------------------------------------------------------
# Group D: three independent limits, each enforced by a different component
# against a different quantity.
# --------------------------------------------------------------------------
GROUP_D: dict[str, Expect] = {
    "under_openshell_limit_reaches_mcp": Expect(
        outcome="admit_as", tool=REFUND_EXECUTE, ingress=1,
        dispatch=(REFUND_EXECUTE,), receiver_refused=True, proof_observed=1,
        notes="a valid-sized envelope crosses the policy and is refused by the "
              "receiver on its own terms, which proves it arrived",
    ),
    "over_openshell_limit_denied_before_mcp": openshell_denial_expect(
        notes="above 262,144: OpenShell refuses it before MCP ingress",
    ),
    "over_receiver_limit_admitted_then_refused": carriage_refusal_expect(
        notes="the case that proves the receiver's decoded-proof bound is a "
              "real independent limit and not shadowed by the envelope bound",
    ),
    "invalid_base64": carriage_refusal_expect(),
    "malformed_proof_encoding": carriage_refusal_expect(),
    "chain_above_protocol_maximum": denial_expect(
        "invalid", notes="depth 9; the verifier refuses it as chain_too_deep",
    ),
}

# --------------------------------------------------------------------------
# Group E: parser differentials. The invariant is narrow and absolute: a
# request admitted by OpenShell as method/tool X must never be dispatched by
# the MCP server as Y. Both layers are allowed to deny; only disagreement is a
# finding.
# --------------------------------------------------------------------------
_PARSER = dict(outcome="admit_as", tool=REFUND_EXECUTE, or_deny=True, ingress=1,
               dispatch=(REFUND_EXECUTE,))

GROUP_E: dict[str, Expect] = {
    "dup_method_allowed_then_denied": Expect(**_PARSER),
    "dup_method_denied_then_allowed": Expect(**_PARSER),
    "dup_name_allowed_then_denied": Expect(**_PARSER),
    "dup_name_denied_then_allowed": Expect(**_PARSER),
    "dup_params_container": Expect(**_PARSER),
    # These two are the only parser probes that actually carry a proof member,
    # so the receiver measures one inbound proof for each. The duplicate is
    # resolved last-wins by the JSON parser, which is what the case is probing.
    "dup_meta_container": Expect(**{**_PARSER, "proof_observed": 1}),
    "dup_proof_member": Expect(**{**_PARSER, "proof_observed": 1}),
    "hdr_method_allowed_body_denied": openshell_denial_expect(
        notes="the body names a tool the policy does not allow; a header must "
              "not be able to launder it",
    ),
    "hdr_method_denied_body_allowed": Expect(**_PARSER),
    "hdr_name_allowed_body_denied": openshell_denial_expect(),
    "hdr_name_denied_body_allowed": Expect(**_PARSER),
    "hdr_method_missing": Expect(**_PARSER),
    "hdr_name_missing": Expect(**_PARSER),
    "dup_hdr_method": Expect(**_PARSER),
    "dup_hdr_name": Expect(**_PARSER),
}

#: Which branch each parser probe must actually exercise under the ordinary
#: policy, measured against OpenShell v0.0.96.
#:
#: This exists because ``or_deny=True`` is the right setting for the safety
#: invariant and the wrong one for coverage. Safety here is "admitted as X, never
#: dispatched as Y", and a policy that denies every request satisfies it
#: vacuously: the whole parser matrix passes while nothing was parsed. That is
#: exactly what happened when the ``refund.execute`` allow rule was removed —
#: all fifteen probes passed. So the branch each probe takes is stated per case
#: rather than in aggregate, which also catches two probes swapping branches
#: while the totals stay the same.
#:
#: A probe moving from ``denied`` to ``admitted`` is not necessarily a defect; it
#: is a change in how the policy layer resolves that malformation, and the point
#: of the gate is that it cannot pass unnoticed.
PARSER_EXPECTED_BRANCH: dict[str, str] = {
    "dup_method_allowed_then_denied": "denied",
    "dup_method_denied_then_allowed": "admitted",
    "dup_name_allowed_then_denied": "denied",
    "dup_name_denied_then_allowed": "admitted",
    "dup_params_container": "denied",
    "dup_meta_container": "admitted",
    "dup_proof_member": "admitted",
    "hdr_method_allowed_body_denied": "denied",
    "hdr_method_denied_body_allowed": "admitted",
    "hdr_name_allowed_body_denied": "denied",
    "hdr_name_denied_body_allowed": "admitted",
    "hdr_method_missing": "admitted",
    "hdr_name_missing": "admitted",
    "dup_hdr_method": "admitted",
    "dup_hdr_name": "admitted",
}


def parser_branch(delta: dict | None) -> str:
    """Which branch one parser probe took, from the receiver's own counters.

    ``admitted`` means the request reached MCP ingress and dispatched exactly the
    effective allowed tool. ``denied`` means the receiver observed nothing at all.
    Anything else is ``unaccounted``: a probe that reached ingress without
    dispatching, or dispatched something other than the effective tool, has not
    demonstrated either branch and must never be counted as coverage.
    """
    if not delta:
        return "unaccounted"
    ingress = delta.get("http_ingress") or 0
    dispatch = list(delta.get("tool_dispatch") or [])
    if ingress == 1 and dispatch == [REFUND_EXECUTE]:
        return "admitted"
    if ingress == 0 and not dispatch:
        return "denied"
    return "unaccounted"


def parser_coverage(deltas: dict[str, dict]) -> dict:
    """Did the parser matrix exercise admission as well as denial?

    Complementary to the safety invariant, never a replacement for it: safety
    says a request must not be laundered into a different tool, and coverage says
    the matrix actually tested that on requests which were let through. Both are
    required for the parser group to mean anything.
    """
    observed = {name: parser_branch(deltas.get(name))
                for name in PARSER_EXPECTED_BRANCH}
    mismatched = sorted(
        f"{name}: expected {want}, observed {observed[name]}"
        for name, want in PARSER_EXPECTED_BRANCH.items() if observed[name] != want
    )
    admitted = sorted(n for n, b in observed.items() if b == "admitted")
    denied = sorted(n for n, b in observed.items() if b == "denied")
    unaccounted = sorted(n for n, b in observed.items() if b == "unaccounted")
    expected_admitted = sum(1 for b in PARSER_EXPECTED_BRANCH.values() if b == "admitted")
    expected_denied = sum(1 for b in PARSER_EXPECTED_BRANCH.values() if b == "denied")
    ok = (
        not mismatched
        and not unaccounted
        # Stated separately from the per-case comparison so the gate cannot pass
        # on an empty or half-declared expectation table.
        and len(admitted) == expected_admitted
        and len(denied) == expected_denied
        and admitted
        and denied
    )
    return {
        "result": "PASS" if ok else "FAIL",
        "admitted": len(admitted),
        "denied": len(denied),
        "expected_admitted": expected_admitted,
        "expected_denied": expected_denied,
        "unaccounted": unaccounted,
        "mismatched": mismatched,
    }


# --------------------------------------------------------------------------
# Group F: destination, path, and port. All refused before MCP ingress.
# --------------------------------------------------------------------------
GROUP_F: dict[str, Expect] = {
    "unauthorized_destination": openshell_denial_expect(),
    "wrong_port": openshell_denial_expect(),
    "wrong_path": openshell_denial_expect(),
    "unlisted_mcp_tool": openshell_denial_expect(),
    "disallowed_mcp_method": openshell_denial_expect(),
    "control_plane_unreachable": openshell_denial_expect(
        notes="the host-only snapshot endpoint is not in the policy, so the "
              "sandbox cannot reach the thing that records its behaviour",
    ),
}

# --------------------------------------------------------------------------
# Group H: the unified path. One execution in which NOOA, MCP, OpenShell, the
# receiver, and Ratify are all present. Running NOOA in one suite and MCP
# through OpenShell in another proves two seams; it does not prove the
# composition, which is what this group exists to make executable.
#
# Ingress counts include the MCP handshake, because the NOOA capability drives
# a real client that must connect before it can call a tool: initialize and
# notifications/initialized are two requests before either refund tool.
# --------------------------------------------------------------------------
HANDSHAKE_INGRESS = 2

GROUP_H: dict[str, Expect] = {
    "nooa_authorized_refund": Expect(
        outcome="authorize", tool=REFUND_EXECUTE, status="authorized_agent",
        ingress=HANDSHAKE_INGRESS + 2, dispatch=(REFUND_PREPARE, REFUND_EXECUTE),
        prepare=1, execute=1, refund=UNDER_LIMIT, receipts=1, proof_observed=1,
        notes="one NOOA capability call, carried over MCP through an OpenShell "
              "policy to an independent receiver, authorized by Ratify, with the "
              "receipt id returned back up through MCP and the adapter",
    ),
    "nooa_over_limit_denied_by_ratify": Expect(
        outcome="deny_at_ratify", status="constraint_denied", tool=REFUND_EXECUTE,
        ingress=HANDSHAKE_INGRESS + 2, dispatch=(REFUND_PREPARE, REFUND_EXECUTE),
        prepare=1, execute=1, receipts=1, proof_observed=1,
        notes="OpenShell admits it, because v0.0.96 cannot see an amount; "
              "Ratify denies it on the principal's ceiling",
    ),
    "nooa_unlisted_tool_denied_by_openshell": Expect(
        outcome="tool_denied_at_openshell", ingress=HANDSHAKE_INGRESS,
        notes="the capability is pointed at a tool the policy does not name; the "
              "handshake is admitted and the tool call is refused before dispatch",
    ),
    "nooa_capability_inert_without_the_adapter": Expect(
        outcome="inert",
        notes="removing the presentation adapter leaves the capability unable to "
              "prove anything, so it cannot be exercised at all",
    ),
}

#: Group G re-exercises cases from the groups above purely so the log audit has
#: each shape of traffic to search against. It declares no expectations of its
#: own; the canary search is the gate.
GROUP_G_SHAPES = (
    "authorized_request",
    "openshell_policy_denial",
    "ratify_semantic_denial",
    "malformed_proof",
    "oversized_envelope",
)

GROUPS: dict[str, dict[str, Expect]] = {
    "positive_and_replay": GROUP_A,
    "ratify_semantic_denials": GROUP_B,
    "maximum_depth": GROUP_C,
    "size_boundaries": GROUP_D,
    "parser_differentials": GROUP_E,
    "destination_path_port": GROUP_F,
    "nooa_full_path": GROUP_H,
}

#: Every case the complete profile is required to execute. A required case that
#: does not run is a FAIL, never a SKIP, and never silently absent.
REQUIRED_CASES: tuple[str, ...] = tuple(
    f"{group}::{name}" for group, cases in GROUPS.items() for name in cases
)


def missing_expectations(group: str, case_names) -> list[str]:
    """Case names the driver intends to run that nothing will adjudicate."""
    declared = GROUPS.get(group, {})
    return [name for name in case_names if name not in declared]


# --------------------------------------------------------------------------
# Adjudication
# --------------------------------------------------------------------------

#: Counter names compared as scalar deltas.
_SCALARS = ("http_ingress", "prepare", "execute", "refusals", "internal_errors")


def _delta(before: dict, after: dict, key: str):
    return (after["counters"].get(key) or 0) - (before["counters"].get(key) or 0)


def _dispatch_delta(before: dict, after: dict) -> list[str]:
    prior = before["counters"].get("tool_dispatch") or []
    now = after["counters"].get("tool_dispatch") or []
    if now[: len(prior)] != prior:
        # The dispatch log is append-only. A prefix that changed means the
        # snapshots are not from the same run or the log was rewritten.
        return ["<DISPATCH-LOG-REWRITTEN>"]
    return list(now[len(prior):])


def _proof_delta(before: dict, after: dict) -> list[tuple[str, int]]:
    prior = len(before["counters"].get("inbound_proof_sha") or [])
    shas = (after["counters"].get("inbound_proof_sha") or [])[prior:]
    lens = (after["counters"].get("inbound_proof_len") or [])[prior:]
    return list(zip(shas, lens))


@dataclass
class Verdict:
    name: str
    result: str
    detail: str
    deltas: dict = field(default_factory=dict)


def judge(
    name: str,
    expect: Expect,
    case: dict | None,
    before: dict | None,
    after: dict | None,
    sent_proof: dict | None = None,
) -> Verdict:
    """PASS or FAIL for one case, from recorded evidence only.

    ``case`` is what the client reported. ``before`` and ``after`` are control-
    plane snapshots taken immediately either side of this case's exec. Any of
    them being absent, stale, or incomplete is a failure: a case whose effects
    cannot be bounded has not been tested, whatever its HTTP status looked
    like.
    """
    if case is None:
        return Verdict(name, "FAIL", "case did not execute; no result recorded")
    if before is None:
        return Verdict(name, "FAIL", "no before snapshot; effects cannot be attributed")
    if after is None:
        return Verdict(name, "FAIL", "no after snapshot; effects cannot be attributed")
    if not isinstance(before.get("seq"), int) or not isinstance(after.get("seq"), int):
        return Verdict(name, "FAIL", "snapshot is missing its sequence number")
    if after["seq"] < before["seq"]:
        return Verdict(
            name, "FAIL",
            f"stale snapshot: after seq {after['seq']} precedes before seq {before['seq']}",
        )
    # Completeness, checked against the shape this outcome actually produces.
    # Two outcomes never yield an HTTP status by construction: a capability that
    # refused to run made no request, and a tool refused by the policy layer got
    # no response to read a status from. Demanding http_status of them would fail
    # them for being correct, and demanding nothing of the rest would let a
    # truncated result pass.
    _NO_HTTP = ("inert", "tool_denied_at_openshell")
    if expect.outcome in _NO_HTTP:
        if "outcome" not in case:
            return Verdict(name, "FAIL", "partial result: no outcome recorded")
    elif "http_status" not in case:
        return Verdict(name, "FAIL", "partial result: no http_status recorded")

    deltas = {k: _delta(before, after, k) for k in _SCALARS}
    dispatched = _dispatch_delta(before, after)
    deltas["tool_dispatch"] = dispatched
    deltas["refund"] = round(
        (after["counters"].get("refunded_total") or 0.0)
        - (before["counters"].get("refunded_total") or 0.0),
        6,
    )
    deltas["receipts"] = (after["counters"].get("receipts") or 0) - (
        before["counters"].get("receipts") or 0
    )
    proofs = _proof_delta(before, after)
    deltas["proof_observed"] = len(proofs)
    deltas["seq"] = after["seq"] - before["seq"]

    if dispatched == ["<DISPATCH-LOG-REWRITTEN>"]:
        return Verdict(name, "FAIL", "the append-only dispatch log was rewritten", deltas)

    # Absolute, and checked before anything else: nothing the profile does may
    # ever dispatch a tool the policy does not name.
    if any("admin" in tool for tool in dispatched):
        return Verdict(name, "FAIL", f"an unlisted tool was dispatched: {dispatched}", deltas)

    if deltas["internal_errors"] != expect.internal_errors:
        return Verdict(
            name, "FAIL",
            f"internal_errors delta {deltas['internal_errors']}, expected "
            f"{expect.internal_errors}", deltas,
        )

    status = case.get("http_status")
    # Whether the policy layer refused is decided by the receiver's own ingress
    # counter, not by pattern-matching the response body. OpenShell signals its
    # refusals in more than one shape: an unlisted tool comes back as a
    # policy_denied body, while an envelope over the inspection limit comes back
    # as HTTP 400 with "rejected before policy evaluation". Sniffing for one
    # marker missed the other and reported a correct refusal as an admission.
    # The authoritative question is simply whether the request ever reached the
    # receiver.
    blocked = case.get("transport_error") is True or (
        status is not None and 400 <= status < 500 and deltas["http_ingress"] == 0
    )

    if expect.outcome == "inert":
        # Nothing may cross any boundary. The capability had no way to prove
        # authority, so it must not have been exercised at all.
        if deltas["seq"] != 0 or deltas["http_ingress"] != 0 or dispatched:
            return Verdict(
                name, "FAIL",
                f"expected an inert capability, but the receiver observed "
                f"ingress={deltas['http_ingress']} dispatch={dispatched} "
                f"events={deltas['seq']}", deltas,
            )
        if case.get("outcome") != "capability_inert":
            return Verdict(
                name, "FAIL",
                f"expected the capability to refuse to run, got "
                f"outcome={case.get('outcome')!r}", deltas,
            )
        return Verdict(name, "PASS", "capability inert without the adapter", deltas)

    if expect.outcome == "tool_denied_at_openshell":
        # The handshake is admitted; the tool call is not. The receiver must
        # have observed the handshake and nothing else.
        if deltas["http_ingress"] != expect.ingress:
            return Verdict(
                name, "FAIL",
                f"http_ingress delta {deltas['http_ingress']}, expected "
                f"{expect.ingress} (handshake only)", deltas,
            )
        if dispatched:
            return Verdict(
                name, "FAIL", f"a tool was dispatched despite the refusal: {dispatched}",
                deltas,
            )
        if deltas["refund"] or deltas["receipts"] or deltas["execute"] or deltas["prepare"]:
            return Verdict(name, "FAIL", "the refusal did not hold; receiver state moved",
                           deltas)
        if deltas["proof_observed"]:
            return Verdict(
                name, "FAIL",
                f"the tool call was refused, yet the receiver measured "
                f"{deltas['proof_observed']} inbound proof(s)", deltas,
            )
        if case.get("outcome") != "mcp_transport_error":
            return Verdict(
                name, "FAIL",
                f"expected the tool call to be refused before a decision, got "
                f"outcome={case.get('outcome')!r}", deltas,
            )
        # This subcase owns the tail of the suite's event stream, so anything the
        # receiver recorded after it lands in this window. Without this check an
        # unexplained trailing event of a type the checks above do not count
        # would pass: the handshake requests are the only events this outcome can
        # account for.
        if deltas["seq"] != expect.ingress:
            return Verdict(
                name, "FAIL",
                f"event log advanced by {deltas['seq']} but only the "
                f"{expect.ingress} handshake request(s) are accounted for; "
                "unexplained events occurred between the snapshots", deltas,
            )
        return Verdict(name, "PASS", "handshake admitted, unlisted tool refused", deltas)

    if expect.outcome == "deny_at_openshell":
        if not blocked:
            return Verdict(
                name, "FAIL",
                f"expected refusal before MCP ingress, was admitted (http={status})", deltas,
            )
        # A denial is only a denial if the receiver saw nothing.
        if deltas["http_ingress"] != 0:
            return Verdict(
                name, "FAIL",
                f"reported as denied but {deltas['http_ingress']} request(s) reached "
                "MCP ingress", deltas,
            )
        if dispatched:
            return Verdict(name, "FAIL", f"denied but a tool dispatched: {dispatched}", deltas)
        if deltas["refund"] or deltas["receipts"]:
            return Verdict(name, "FAIL", "denied but receiver state moved", deltas)
        if deltas["seq"] != 0:
            return Verdict(
                name, "FAIL",
                f"denied before ingress, yet the receiver recorded {deltas['seq']} "
                "event(s); the refusal did not hold", deltas,
            )
        return Verdict(name, "PASS", f"refused before MCP ingress (http={status})", deltas)

    if blocked:
        if expect.or_deny:
            if deltas["http_ingress"] != 0 or dispatched:
                return Verdict(
                    name, "FAIL",
                    "reported as policy-denied but the receiver still observed the "
                    f"request (ingress={deltas['http_ingress']}, dispatch={dispatched})",
                    deltas,
                )
            if deltas["seq"] != 0:
                return Verdict(
                    name, "FAIL",
                    f"denied by policy, yet the receiver recorded {deltas['seq']} event(s)",
                    deltas,
                )
            return Verdict(
                name, "PASS",
                f"denied by policy, which is permitted for this case (http={status})", deltas,
            )
        return Verdict(name, "FAIL", f"unexpectedly denied (http={status})", deltas)

    # Admitted. Everything from here is about what the receiver actually did.
    if status != 200:
        return Verdict(
            name, "FAIL", f"admitted but http={status}, which is not an authorization outcome",
            deltas,
        )

    # Dispatch identity first. "Admitted as X, dispatched as Y" is the headline
    # invariant of the whole matrix, so it is reported as itself rather than as
    # whichever counter happened to move differently as a consequence.
    if tuple(dispatched) != expect.dispatch:
        return Verdict(
            name, "FAIL",
            f"dispatched {dispatched}, expected {list(expect.dispatch)}", deltas,
        )

    for key, want in (
        ("http_ingress", expect.ingress),
        ("prepare", expect.prepare),
        ("execute", expect.execute),
        ("refusals", expect.refusals),
        ("proof_observed", expect.proof_observed),
    ):
        if deltas[key] != want:
            return Verdict(name, "FAIL", f"{key} delta {deltas[key]}, expected {want}", deltas)
    if deltas["receipts"] != expect.receipts:
        return Verdict(
            name, "FAIL", f"receipt delta {deltas['receipts']}, expected {expect.receipts}",
            deltas,
        )
    if abs(deltas["refund"] - expect.refund) > 1e-9:
        return Verdict(
            name, "FAIL", f"refund delta {deltas['refund']}, expected {expect.refund}", deltas,
        )
    if expect.receipts > 0:
        # ``all()`` over an empty sequence is True, so a receipt set that is
        # empty would otherwise read as "every receipt verified". Requiring the
        # set to be non-empty first is what stops vacuous truth from being
        # reported as positive verification evidence.
        if (after["counters"].get("receipts") or 0) <= 0:
            return Verdict(
                name, "FAIL",
                "a receipt was expected but the receipt set is empty; an empty set "
                "must not be reported as verified", deltas,
            )
        if after["counters"].get("receipts_all_verify") is not True:
            return Verdict(name, "FAIL", "a receipt exists but receipt verification failed", deltas)

    # Event-log integrity. Every counter movement appends exactly one event, so
    # the sequence must advance by exactly the number of events this case's
    # deltas account for. A larger jump means the receiver recorded something
    # this case did not explain, which is evidence the snapshots do not bound
    # the case and the deltas above are not attributable to it.
    accounted = (
        deltas["http_ingress"]
        + len(dispatched)
        + deltas["prepare"]
        + deltas["execute"] * 2  # execute, then its decision
        + deltas["proof_observed"]
    )
    if deltas["seq"] != accounted:
        return Verdict(
            name, "FAIL",
            f"event log advanced by {deltas['seq']} but the observed deltas account "
            f"for {accounted}; unexplained events occurred between the snapshots",
            deltas,
        )

    if expect.receiver_refused:
        if case.get("is_error") is not True:
            return Verdict(
                name, "FAIL",
                "expected the receiver to refuse this before verification, but it "
                f"returned a normal result (decision={case.get('decision')})", deltas,
            )
        return Verdict(
            name, "PASS", f"refused by the receiver: {(case.get('error_text') or '')[:80]}", deltas,
        )

    if expect.outcome == "admit_as":
        return Verdict(
            name, "PASS", f"admitted and dispatched as {expect.tool}", deltas,
        )

    decision = case.get("decision")
    if expect.outcome == "authorize":
        if decision != "authorized":
            return Verdict(
                name, "FAIL",
                f"expected authorization, got decision={decision} "
                f"status={case.get('status_code')} reason={(case.get('reason') or '')[:70]}",
                deltas,
            )
        if not case.get("receipt_id"):
            return Verdict(name, "FAIL", "authorized but no receipt_id returned", deltas)
        if expect.proof_fidelity:
            if not sent_proof:
                return Verdict(name, "FAIL", "no sent-proof measurement to compare against", deltas)
            if len(proofs) != 1:
                return Verdict(
                    name, "FAIL", f"expected exactly one inbound proof, saw {len(proofs)}", deltas,
                )
            got_sha, got_len = proofs[0]
            if got_sha != sent_proof["sha256"] or got_len != sent_proof["len"]:
                return Verdict(
                    name, "FAIL",
                    f"proof changed in transit: sent {sent_proof['len']}B/"
                    f"{sent_proof['sha256'][:12]}, received {got_len}B/{str(got_sha)[:12]}",
                    deltas,
                )
        return Verdict(
            name, "PASS",
            f"authorized, refunded {deltas['refund']}, receipt {case.get('receipt_id')}", deltas,
        )

    if expect.outcome == "deny_at_ratify":
        if decision != "denied":
            return Verdict(
                name, "FAIL", f"expected a denial, got decision={decision}", deltas,
            )
        if expect.status and case.get("status_code") != expect.status:
            return Verdict(
                name, "FAIL",
                f"denied as {case.get('status_code')}, expected {expect.status}", deltas,
            )
        return Verdict(
            name, "PASS",
            f"denied by Ratify as {case.get('status_code')}: {(case.get('reason') or '')[:70]}",
            deltas,
        )

    return Verdict(name, "FAIL", f"unknown expected outcome {expect.outcome!r}", deltas)


def adjudicate_group(group: str, evidence: dict) -> list[Verdict]:
    """Judge every declared case in a group.

    ``evidence`` maps case name to ``{"case", "before", "after", "sent_proof"}``.
    A declared case with no evidence at all is judged, and fails, rather than
    being dropped from the report.
    """
    verdicts = []
    for name, expect in GROUPS[group].items():
        found = evidence.get(name) or {}
        verdicts.append(
            judge(
                f"{group}::{name}",
                expect,
                found.get("case"),
                found.get("before"),
                found.get("after"),
                found.get("sent_proof"),
            )
        )
    return verdicts
