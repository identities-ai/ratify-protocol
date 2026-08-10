# SPDX-License-Identifier: Apache-2.0
"""Orchestration for the OpenShell profile: runs the groups, gathers evidence.

Invoked by run-openshell-profile.sh once the gateway, the receiver, and the
sandbox are up. Everything that needs a bound, a retry decision, or a
structured result lives here rather than in the shell, for three reasons:

* ``subprocess.run(timeout=...)`` is portable and actually kills the child.
  GNU ``timeout`` is not present on a stock macOS, and ``openshell sandbox
  exec --timeout`` bounds the remote command but not the CLI: with stdin
  inherited and not at EOF the CLI blocks indefinitely before the remote
  timeout is ever armed. A run of this profile hung for twenty minutes that
  way. Every exec here passes ``--no-tty`` and closes stdin, *and* is wrapped
  in an external bound.
* Per-case evidence needs a snapshot taken immediately before and immediately
  after each case, which is a loop with state, not a pipeline.
* The adjudicator has to be handed structured evidence. Reconstructing that
  from shell variables is how the previous version ended up with gates that
  could not fail.

The sandbox never decides anything. It receives one case at a time, reports
what happened, and the runner attributes the effects using snapshots the
sandbox cannot reach or influence.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).parent))

from mcp_refund_client import (  # noqa: E402
    CHALLENGE_CLOCK_SAFETY_MARGIN_SECONDS,
)
from openshell_cases import (  # noqa: E402
    GROUPS,
    GROUP_G_SHAPES,
    OVER_LIMIT,
    PROOF_KEY,
    REQUIRED_CASES,
    UNDER_LIMIT,
    adjudicate_group,
    missing_expectations,
    parser_coverage,
)

ENV = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}
ENVS_JSON = (
    '"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
    '"io.modelcontextprotocol/clientCapabilities":{}'
)

#: Bounds for every external operation, in seconds. Chosen well above the
#: measured latency of each (create ~15s, everything else under 1s) so a
#: timeout means something is actually wrong rather than merely slow.
TIMEOUTS = {
    "create": 180,
    "upload": 90,
    "exec": 120,
    "download": 90,
    "delete": 90,
    "gateway": 60,
    "docker": 120,
    "control": 60,
}

#: The interpreter, by the absolute path the policy's binaries list names. A
#: bare ``python3`` resolves through PATH, and the sandbox image sets
#: VIRTUAL_ENV=/sandbox/.venv, so it can land on an interpreter the policy does
#: not permit; the supervisor then refuses to exec it and the case produces no
#: output at all.
SANDBOX_PYTHON = "/usr/bin/python3"

#: Above the 262,144-byte envelope ceiling the policy proposes.
OVERSIZED_PROOF_BYTES = 400_000
#: Decodes above the receiver's 131,072-byte bound while the resulting
#: envelope stays under the 262,144-byte policy bound: the only window in
#: which the receiver's own limit is independently observable.
OVER_RECEIVER_PROOF_BYTES = 150_000


def clock_skew_verdict(brackets: list[tuple[float, float]], margin: int) -> dict:
    """Does the sandbox's clock lead this host's by more than the safety margin?

    Each bracket is ``(lower, upper)`` for one sample: the sandbox read its clock
    somewhere between two host readings, so the offset is bounded rather than
    known. ``lead_at_least`` is the largest lower bound observed, which is the
    only figure a fail-fast decision may rest on: it is the amount by which the
    sandbox certainly leads.

    The margin is diagnostic, never a substitute for backdating the presenter's
    timestamp. If the sandbox leads by more than the margin, backdating can no
    longer guarantee a non-negative challenge age and the run would fail
    somewhere in the matrix with a confusing stale_challenge; this says so up
    front instead.
    """
    if not brackets:
        return {"result": "FAIL", "detail": "no clock samples were taken",
                "samples": 0, "margin_seconds": margin}
    lead_at_least = max(lower for lower, _ in brackets)
    lead_at_most = min(upper for _, upper in brackets)
    ok = lead_at_least <= margin
    return {
        "result": "PASS" if ok else "FAIL",
        "samples": len(brackets),
        "margin_seconds": margin,
        "sandbox_lead_at_least_seconds": round(lead_at_least, 4),
        "sandbox_lead_at_most_seconds": round(lead_at_most, 4),
        "detail": (
            f"sandbox clock leads the host by at least {lead_at_least:+.3f}s, which "
            f"exceeds the {margin}s presenter safety margin; fix clock discipline "
            "on the container runtime (SPEC 15.6)"
        ) if not ok else (
            f"sandbox clock offset within [{lead_at_least:+.3f}, {lead_at_most:+.3f}]s "
            f"against a {margin}s presenter safety margin"
        ),
    }


class Timeout(Exception):
    """An external operation exceeded its bound. Recorded, never swallowed."""


class Op:
    """Bounded external command execution, with every outcome recorded.

    Nothing here raises on a non-zero exit: a refusal is frequently the result
    under test. A timeout is different, and is reported as a distinct outcome
    so a hung stage can never be mistaken for a clean denial.
    """

    def __init__(self, log_path: pathlib.Path) -> None:
        self.log_path = log_path
        self.records: list[dict] = []

    def run(self, kind: str, argv: list[str], stdin_devnull: bool = True,
            retries: int = 0, retry_delay: float = 0.5) -> dict:
        """One attempt, or several for a caller-declared-safe operation.

        ``retries`` is 0 for every operation except ``download``, and it stays
        that way deliberately: a download only re-reads a file the sandbox
        already finished writing, so retrying it cannot touch the presentation
        or authorization boundary. Retrying an ``exec`` or ``upload`` could
        re-attempt something security-relevant and is never done here. Every
        attempt is recorded, not just the last, so a self-healed retry is
        visible in operations.jsonl rather than disappearing into a single
        clean-looking record.
        """
        attempt = 0
        while True:
            attempt += 1
            started = time.monotonic()
            record = {"kind": kind, "argv_len": sum(len(a) for a in argv),
                      "argc": len(argv), "attempt": attempt}
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUTS.get(kind, 120),
                    stdin=subprocess.DEVNULL if stdin_devnull else None,
                    check=False,
                )
                record.update(
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    timed_out=False,
                )
            except subprocess.TimeoutExpired as exc:
                record.update(
                    returncode=None,
                    stdout=(exc.stdout or b"").decode(errors="replace")
                    if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                    stderr=(exc.stderr or b"").decode(errors="replace")
                    if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                    timed_out=True,
                    stage=kind,
                )
            except OSError as exc:
                record.update(returncode=None, stdout="", stderr=f"{type(exc).__name__}: {exc}",
                              timed_out=False)
            record["seconds"] = round(time.monotonic() - started, 3)
            self.records.append(record)
            with self.log_path.open("a") as fh:
                fh.write(json.dumps({k: v for k, v in record.items()
                                     if k not in ("stdout", "stderr")}) + "\n")
            ok = record.get("returncode") == 0 and not record.get("timed_out")
            if ok or attempt > retries:
                record["attempts"] = attempt
                return record
            time.sleep(retry_delay)


class Control:
    """The receiver's loopback control plane. Not reachable from the sandbox."""

    def __init__(self, port: int) -> None:
        self.base = f"http://127.0.0.1:{port}"

    def _call(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method="POST" if data is not None else "GET",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=TIMEOUTS["control"]) as response:
            return json.loads(response.read())

    def public(self) -> dict:
        return self._call("/public")

    def snapshot(self) -> dict:
        return self._call("/snapshot")

    def sign(self, variant: str, challenge: str, session_context: str) -> dict:
        return self._call("/sign", {"variant": variant, "challenge": challenge,
                                    "session_context": session_context})

    def revoke(self, variant: str) -> dict:
        return self._call("/revoke", {"variant": variant})

    def break_revocation(self) -> dict:
        return self._call("/break-revocation", {})

    def fix_revocation(self) -> dict:
        return self._call("/fix-revocation", {})

    def break_observer(self) -> dict:
        return self._call("/break-observer", {})

    def fix_observer(self) -> dict:
        return self._call("/fix-observer", {})


# --------------------------------------------------------------------------
# Case construction
# --------------------------------------------------------------------------

def prepare_body(idx: int, ctx: dict, amount: float = UNDER_LIMIT, order: str | None = None,
                 tenant: str | None = None, agent_id: str | None = None) -> dict:
    return {
        "jsonrpc": "2.0", "id": idx, "method": "tools/call",
        "params": {
            "name": "refund.prepare", "_meta": ENV,
            "arguments": {
                "order_id": order or ctx["canaries"]["order"],
                "amount": amount,
                "agent_id": agent_id or ctx["agent_id"],
                "currency": "USD",
                "tenant": tenant or ctx["canaries"]["tenant"],
            },
        },
    }


def execute_body(idx: int, ctx: dict, challenge: str, proof: str) -> dict:
    return {
        "jsonrpc": "2.0", "id": idx, "method": "tools/call",
        "params": {
            "name": "refund.execute",
            "arguments": {"challenge": challenge},
            "_meta": {
                **ENV,
                PROOF_KEY: proof,
                "traceparent": ctx["canaries"]["traceparent"],
                "baggage": ctx["canaries"]["baggage"],
            },
        },
    }


def prepare_case(name: str, ctx: dict, **kw) -> dict:
    return {"name": name, "body": prepare_body(10, ctx, **kw),
            "hdr_method": "tools/call", "hdr_name": "refund.prepare"}


def execute_case(name: str, ctx: dict, challenge: str, proof: str) -> dict:
    return {"name": name, "body": execute_body(100, ctx, challenge, proof),
            "hdr_method": "tools/call", "hdr_name": "refund.execute"}


def unlisted_tool_case(name: str = "openshell_denies_unlisted_tool") -> dict:
    return {
        "name": name,
        "body": {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                 "params": {"name": "admin.delete_everything", "arguments": {}, "_meta": ENV}},
        "hdr_method": "tools/call", "hdr_name": "admin.delete_everything",
    }


def zero_challenge() -> str:
    return base64.b64encode(b"\x00" * 32).decode()


# --------------------------------------------------------------------------
# Group definitions. Each entry is (case_name, builder). A builder receives
# (ctx, prior) where ``prior`` maps already-run case names to their results,
# so a case that needs a live challenge can be materialized at the moment it
# runs rather than guessed in advance.
# --------------------------------------------------------------------------

def _signed_execute(ctx, prior, prepare_name, variant, case_name):
    """Build an execute case from a prepare that already ran."""
    prepared = (prior.get(prepare_name) or {}).get("prepared")
    if not prepared:
        raise RuntimeError(f"{prepare_name} produced no challenge; cannot build {case_name}")
    signed = ctx["control"].sign(variant, prepared["challenge"], prepared["session_context"])
    ctx["sent_proofs"][case_name] = {"sha256": signed["sha256"], "len": signed["len"]}
    if case_name == "execute_valid":
        # The log audit has to search for literal fragments of a proof that
        # actually crossed the wire; searching a synthetic string would prove
        # nothing. Three 32-character slices are written, never the whole
        # proof, into the 0700 work directory that teardown removes.
        proof = signed["proof"]
        ctx["fragment_file"].write_text(
            json.dumps({"proof_prefix": proof[:32],
                        "proof_middle": proof[len(proof) // 2:][:32],
                        "proof_suffix": proof[-32:]})
        )
        ctx["fragment_file"].chmod(0o600)
    return execute_case(case_name, ctx, prepared["challenge"], signed["proof"])


def group_positive_and_replay(ctx):
    yield "prepare_valid", lambda c, p: prepare_case("prepare_valid", c)
    yield "execute_valid", lambda c, p: _signed_execute(
        c, p, "prepare_valid", "valid", "execute_valid")
    # The identical presentation, sent a second time.
    yield "execute_replay", lambda c, p: {
        **_replay_of(c, p, "execute_valid"), "name": "execute_replay"}
    yield "openshell_denies_unlisted_tool", lambda c, p: unlisted_tool_case()


def _replay_of(ctx, prior, name):
    body = ctx["bodies"].get(name)
    if body is None:
        raise RuntimeError(f"no recorded body for {name}; cannot replay it")
    return {"name": name, "body": body, "hdr_method": "tools/call",
            "hdr_name": "refund.execute"}


def _denial_pair(case_name, variant, *, amount=UNDER_LIMIT, tenant=None, order=None,
                 before=None, after=None):
    """A prepare/execute pair whose execute is expected to be denied by Ratify.

    The prepare half is an internal step: it is not adjudicated as a case of
    its own, because Group B is about what the receiver does with a
    presentation, not about issuing challenges. Its effects are still bounded
    by their own snapshots so they cannot contaminate the execute delta.
    """
    prep_name = f"__prepare__{case_name}"

    def build_prepare(ctx, prior):
        if before:
            before(ctx)
        return prepare_case(prep_name, ctx, amount=amount, tenant=tenant, order=order)

    def build_execute(ctx, prior):
        case = _signed_execute(ctx, prior, prep_name, variant, case_name)
        return case

    return (prep_name, build_prepare), (case_name, build_execute), after


def group_ratify_semantic_denials(ctx):
    specs = [
        _denial_pair("excessive_amount", "valid", amount=OVER_LIMIT),
        _denial_pair("wrong_resource_path", "wrong_order"),
        _denial_pair("same_order_other_tenant", "other_tenant"),
        _denial_pair("expired_delegation", "expired"),
        _denial_pair("revoked_delegation", "revoked",
                     before=lambda c: c["control"].revoke("revoked")),
        _denial_pair("revocation_provider_failure", "valid",
                     before=lambda c: c["control"].break_revocation(),
                     after=lambda c: c["control"].fix_revocation()),
        _denial_pair("wrong_agent_key", "wrong_agent"),
        _denial_pair("untrusted_root", "untrusted_root"),
        _denial_pair("scope_amplification", "scope_amplification"),
        # The child raises the parent's cap; the request sits above the
        # parent's limit and below the child's, so authorizing it would mean
        # amplification succeeded.
        _denial_pair("constraint_amplification", "constraint_amplification",
                     amount=OVER_LIMIT),
        _denial_pair("no_resource_constraint", "no_resource"),
        _denial_pair("observer_failure_after_decision", "valid",
                     before=lambda c: c["control"].break_observer(),
                     after=lambda c: c["control"].fix_observer()),
    ]
    for (prep, execute, after) in specs:
        yield prep
        yield execute
        if after:
            yield ("__hook__" + execute[0], after)

    # Cross-request proof movement: two challenges, a proof for the first,
    # submitted under the second.
    yield "__prepare__cross_a", lambda c, p: prepare_case("__prepare__cross_a", c)
    yield "__prepare__cross_b", lambda c, p: prepare_case("__prepare__cross_b", c)

    def cross(ctx, prior):
        first = prior["__prepare__cross_a"]["prepared"]
        second = prior["__prepare__cross_b"]["prepared"]
        signed = ctx["control"].sign("valid", first["challenge"], first["session_context"])
        ctx["sent_proofs"]["cross_request_proof_movement"] = {
            "sha256": signed["sha256"], "len": signed["len"]}
        return execute_case("cross_request_proof_movement", ctx,
                            second["challenge"], signed["proof"])

    yield "cross_request_proof_movement", cross

    # A well-formed 32-byte challenge this receiver never issued.
    yield "__prepare__invalid_challenge", lambda c, p: prepare_case(
        "__prepare__invalid_challenge", c)

    def invalid_challenge(ctx, prior):
        prepared = prior["__prepare__invalid_challenge"]["prepared"]
        signed = ctx["control"].sign("valid", prepared["challenge"],
                                     prepared["session_context"])
        never_issued = base64.b64encode(b"\x11" * 32).decode()
        return execute_case("invalid_challenge", ctx, never_issued, signed["proof"])

    yield "invalid_challenge", invalid_challenge

    yield "__prepare__malformed", lambda c, p: prepare_case("__prepare__malformed", c)
    yield "malformed_proof", lambda c, p: execute_case(
        "malformed_proof", c, p["__prepare__malformed"]["prepared"]["challenge"],
        "!!!" + c["canaries"]["malformed_marker"] + "!!!")


def group_maximum_depth(ctx):
    yield "prepare_max_depth", lambda c, p: prepare_case("prepare_max_depth", c)
    yield "execute_max_depth", lambda c, p: _signed_execute(
        c, p, "prepare_max_depth", "max_depth", "execute_max_depth")


def group_size_boundaries(ctx):
    # 1. A valid-sized envelope crosses the policy. It carries a proof the
    #    receiver will refuse on its own terms, which is what proves it
    #    arrived rather than merely being sent.
    yield "__prepare__under", lambda c, p: prepare_case("__prepare__under", c)
    yield "under_openshell_limit_reaches_mcp", lambda c, p: execute_case(
        "under_openshell_limit_reaches_mcp", c,
        p["__prepare__under"]["prepared"]["challenge"],
        base64.b64encode(b"U" * 1024).decode())

    # 2. Above the policy's envelope ceiling: refused before MCP ingress.
    yield "over_openshell_limit_denied_before_mcp", lambda c, p: {
        "name": "over_openshell_limit_denied_before_mcp",
        "body": {"jsonrpc": "2.0", "id": 400, "method": "tools/call",
                 "params": {"name": "refund.execute",
                            "arguments": {"challenge": zero_challenge()},
                            "_meta": {**ENV, PROOF_KEY: base64.b64encode(
                                b"A" * OVERSIZED_PROOF_BYTES).decode()}}},
        "hdr_method": "tools/call", "hdr_name": "refund.execute"}

    # 3. Admitted by the policy, refused by the receiver's own decoded-proof
    #    bound. Only reachable because the two limits are separated.
    yield "__prepare__over_recv", lambda c, p: prepare_case("__prepare__over_recv", c)
    yield "over_receiver_limit_admitted_then_refused", lambda c, p: execute_case(
        "over_receiver_limit_admitted_then_refused", c,
        p["__prepare__over_recv"]["prepared"]["challenge"],
        base64.b64encode(b"R" * OVER_RECEIVER_PROOF_BYTES).decode())

    yield "__prepare__b64", lambda c, p: prepare_case("__prepare__b64", c)
    yield "invalid_base64", lambda c, p: execute_case(
        "invalid_base64", c, p["__prepare__b64"]["prepared"]["challenge"],
        "not*valid*base64===")

    yield "__prepare__enc", lambda c, p: prepare_case("__prepare__enc", c)
    yield "malformed_proof_encoding", lambda c, p: execute_case(
        "malformed_proof_encoding", c, p["__prepare__enc"]["prepared"]["challenge"],
        base64.b64encode(b"{ this is not a proof bundle }").decode())

    yield "__prepare__deep", lambda c, p: prepare_case("__prepare__deep", c)
    yield "chain_above_protocol_maximum", lambda c, p: _signed_execute(
        c, p, "__prepare__deep", "over_depth", "chain_above_protocol_maximum")


def _raw(idx, name, params_json, meta_extra=""):
    return (f'{{"jsonrpc":"2.0","id":{idx},"method":"tools/call",'
            f'"params":{params_json}}}')


def group_parser_differentials(ctx):
    ch = zero_challenge()
    args = f'"arguments":{{"challenge":"{ch}"}}'
    meta = f'"_meta":{{{ENVS_JSON}}}'

    raws = {
        "dup_method_allowed_then_denied":
            f'{{"jsonrpc":"2.0","id":200,"method":"tools/call","method":"admin/nope",'
            f'"params":{{"name":"refund.execute",{args},{meta}}}}}',
        "dup_method_denied_then_allowed":
            f'{{"jsonrpc":"2.0","id":201,"method":"admin/nope","method":"tools/call",'
            f'"params":{{"name":"refund.execute",{args},{meta}}}}}',
        "dup_name_allowed_then_denied":
            f'{{"jsonrpc":"2.0","id":202,"method":"tools/call",'
            f'"params":{{"name":"refund.execute","name":"admin.wipe",{args},{meta}}}}}',
        "dup_name_denied_then_allowed":
            f'{{"jsonrpc":"2.0","id":203,"method":"tools/call",'
            f'"params":{{"name":"admin.wipe","name":"refund.execute",{args},{meta}}}}}',
        "dup_params_container":
            f'{{"jsonrpc":"2.0","id":204,"method":"tools/call",'
            f'"params":{{"name":"refund.execute",{args},{meta}}},'
            f'"params":{{"name":"admin.wipe","arguments":{{}},{meta}}}}}',
        "dup_meta_container":
            f'{{"jsonrpc":"2.0","id":205,"method":"tools/call",'
            f'"params":{{"name":"refund.execute",{args},{meta},'
            f'"_meta":{{{ENVS_JSON},"{PROOF_KEY}":"GARBAGE"}}}}}}',
        "dup_proof_member":
            f'{{"jsonrpc":"2.0","id":206,"method":"tools/call",'
            f'"params":{{"name":"refund.execute",{args},'
            f'"_meta":{{{ENVS_JSON},"{PROOF_KEY}":"FIRST","{PROOF_KEY}":"SECOND"}}}}}}',
    }
    for name, raw in raws.items():
        yield name, (lambda n, r: (lambda c, p: {
            "name": n, "raw": r, "hdr_method": "tools/call",
            "hdr_name": "refund.execute"}))(name, raw)

    allowed_body = (f'{{"jsonrpc":"2.0","id":300,"method":"tools/call",'
                    f'"params":{{"name":"refund.execute",{args},{meta}}}}}')
    denied_body = (f'{{"jsonrpc":"2.0","id":301,"method":"tools/call",'
                   f'"params":{{"name":"admin.wipe","arguments":{{}},{meta}}}}}')

    header_cases = {
        "hdr_method_allowed_body_denied": ({"hdr_method": "tools/call",
                                            "hdr_name": "refund.execute"}, denied_body),
        "hdr_method_denied_body_allowed": ({"hdr_method": "admin/nope",
                                            "hdr_name": "refund.execute"}, allowed_body),
        "hdr_name_allowed_body_denied": ({"hdr_method": "tools/call",
                                          "hdr_name": "refund.execute"}, denied_body),
        "hdr_name_denied_body_allowed": ({"hdr_method": "tools/call",
                                          "hdr_name": "admin.wipe"}, allowed_body),
        "hdr_method_missing": ({"hdr_name": "refund.execute"}, allowed_body),
        "hdr_name_missing": ({"hdr_method": "tools/call"}, allowed_body),
    }
    for name, (headers, body) in header_cases.items():
        yield name, (lambda n, h, b: (lambda c, p: {"name": n, "raw": b, **h}))(
            name, headers, body)

    # Duplicate headers, where the client permits them. urllib collapses
    # repeated header names, so these are sent as a single folded value, which
    # is the only duplication this client can express. Recorded as such rather
    # than claimed as a true duplicate-header test.
    yield "dup_hdr_method", lambda c, p: {
        "name": "dup_hdr_method", "raw": allowed_body,
        "hdr_method": "tools/call, admin/nope", "hdr_name": "refund.execute"}
    yield "dup_hdr_name", lambda c, p: {
        "name": "dup_hdr_name", "raw": allowed_body,
        "hdr_method": "tools/call", "hdr_name": "refund.execute, admin.wipe"}


def group_destination_path_port(ctx):
    base = ctx["mcp_url"]
    host, port = ctx["mcp_host"], ctx["mcp_port"]
    body = {"jsonrpc": "2.0", "id": 500, "method": "tools/call",
            "params": {"name": "refund.execute",
                       "arguments": {"challenge": zero_challenge()}, "_meta": ENV}}

    def at(url, name):
        return {"name": name, "body": body, "url": url,
                "hdr_method": "tools/call", "hdr_name": "refund.execute"}

    yield "unauthorized_destination", lambda c, p: at(
        "http://example.com/mcp", "unauthorized_destination")
    yield "wrong_port", lambda c, p: at(
        f"http://{host}:{port + 1}/mcp", "wrong_port")
    yield "wrong_path", lambda c, p: at(
        f"http://{host}:{port}/not-mcp", "wrong_path")
    yield "unlisted_mcp_tool", lambda c, p: unlisted_tool_case("unlisted_mcp_tool")
    yield "disallowed_mcp_method", lambda c, p: {
        "name": "disallowed_mcp_method",
        "body": {"jsonrpc": "2.0", "id": 501, "method": "resources/list", "params": {}},
        "hdr_method": "resources/list"}
    # The snapshot endpoint the runner uses to judge this very run. If the
    # sandbox could reach it, the evidence would be attacker-influenced.
    yield "control_plane_unreachable", lambda c, p: at(
        f"http://{host}:{c['ctrl_port']}/snapshot", "control_plane_unreachable")


GROUP_BUILDERS = {
    "positive_and_replay": group_positive_and_replay,
    "ratify_semantic_denials": group_ratify_semantic_denials,
    "maximum_depth": group_maximum_depth,
    "size_boundaries": group_size_boundaries,
    "parser_differentials": group_parser_differentials,
    "destination_path_port": group_destination_path_port,
}


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

class Runner:
    def __init__(self, args) -> None:
        self.args = args
        self.work = pathlib.Path(args.work)
        self.op = Op(self.work / "operations.jsonl")
        self.control = Control(args.ctrl_port)
        self.sandbox = args.sandbox
        self.sb_dir = args.sandbox_dir
        self.osbin = args.openshell
        self.gateway = args.gateway_endpoint
        self.evidence: dict[str, dict] = {}
        self.timeouts: list[dict] = []
        self.errors: list[dict] = []
        #: Operations that failed at least once but succeeded on retry. Disclosed
        #: in the artifact rather than folded into driver_errors, because a
        #: self-healed download did not leave any case unattributed.
        self.retried_operations: list[dict] = []

    def error(self, kind: str, detail: str, **context) -> None:
        """Record a driver-level failure, structured so the artifact says what broke.

        Driver errors and case verdicts are complementary rather than
        alternatives. A group that vanishes must fail its cases *and* record that
        the driver could not run them: an earlier version did only the former, so
        ``driver_reported_no_errors`` passed on a run in which the entire unified
        group produced nothing, which is a weaker claim than the gate's name.

        Detail text is written here and never carries a subprocess's captured
        output, proof material, keys, or delegation bodies.
        """
        self.errors.append({"kind": kind, "detail": detail, **context})

    # -- sandbox operations ------------------------------------------------

    def _os(self, kind: str, *argv: str, retries: int = 0) -> dict:
        record = self.op.run(kind, [self.osbin, "--gateway-endpoint", self.gateway, *argv],
                             retries=retries)
        # Every OpenShell operation this profile issues is expected to succeed: a
        # refusal under test is carried in the client's *result*, not in the CLI's
        # exit status. Five consecutive passing runs recorded 242 operations each
        # with zero non-zero exits, so a non-zero exit is an anomaly and is
        # recorded as one rather than being left for a case gate to imply.
        #
        # A download that needed a retry is the one exception. Under concurrent
        # profiles, `sandbox download` was twice observed to exit 1 once and
        # succeed on an immediate second attempt, distinct from every exec and
        # upload, which never did. It re-reads a file the sandbox already
        # finished writing, so a retry cannot touch anything the case gates
        # judge; the attempt count is still carried into the artifact so it is
        # visible rather than silently smoothed over.
        if record["attempts"] > 1 and record.get("returncode") == 0:
            self.retried_operations.append({"stage": kind, "attempts": record["attempts"]})
        elif record.get("timed_out"):
            self.timeouts.append({"stage": kind, "argv": list(argv)[:3],
                                  "stderr": (record.get("stderr") or "")[:200]})
            self.error("operation_timeout",
                       f"{kind} exceeded its {TIMEOUTS.get(kind, 120)}s bound "
                       f"after {record['attempts']} attempt(s)", stage=kind)
        elif record.get("returncode") is None:
            self.error("operation_not_launched",
                       f"{kind} could not be launched after {record['attempts']} attempt(s)",
                       stage=kind)
        elif record["returncode"] != 0:
            self.error("operation_failed",
                       f"{kind} exited {record['returncode']} after "
                       f"{record['attempts']} attempt(s)", stage=kind)
        return record

    def upload(self, local: pathlib.Path, remote: str) -> dict:
        # The destination must be a full file path. Passing a directory
        # replaces that directory with the uploaded file, which silently
        # destroyed the working directory in an earlier version of this
        # profile and made every later exec fail with a missing client.
        return self._os("upload", "sandbox", "upload", self.sandbox, str(local), remote)

    def exec(self, *argv: str) -> dict:
        return self._os("exec", "sandbox", "exec", "--no-tty", "-n", self.sandbox, "--", *argv)

    def download(self, remote: str, local: pathlib.Path) -> dict:
        return self._os("download", "sandbox", "download", self.sandbox, remote, str(local),
                        retries=2)

    # -- evidence ----------------------------------------------------------

    def snapshot(self) -> dict | None:
        try:
            return self.control.snapshot()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.error("snapshot_unavailable",
                       f"the control plane snapshot failed: {type(exc).__name__}")
            return None

    def measure_clock_skew(self, samples: int = 3) -> dict:
        """Bracket the sandbox clock against this host's, before the matrix runs.

        Read through ``SANDBOX_PYTHON``, the same interpreter and the same
        ``time.time()`` the unified client uses to stamp ``challenge_at``, so the
        number measured is the number that matters.
        """
        brackets: list[tuple[float, float]] = []
        for _ in range(samples):
            before = time.time()
            record = self._os("exec", "sandbox", "exec", "--no-tty", "-n", self.sandbox,
                              "--", SANDBOX_PYTHON, "-c",
                              "import time;print(f'{time.time():.6f}')")
            after = time.time()
            for line in (record.get("stdout") or "").splitlines():
                try:
                    sandbox_now = float(line.strip())
                except ValueError:
                    continue
                brackets.append((sandbox_now - after, sandbox_now - before))
                break
        verdict = clock_skew_verdict(brackets, CHALLENGE_CLOCK_SAFETY_MARGIN_SECONDS)
        if verdict["result"] != "PASS":
            self.error("clock_discipline", verdict["detail"])
        return verdict

    def _check_window(self, before, after, group: str, case: str | None = None) -> None:
        """A case's before/after pair must exist and must not run backwards.

        The adjudicator fails such a case on its own, but a snapshot that could
        not be taken, or a sequence that moved backwards, is a fault in the
        harness rather than a property of the case, and the artifact has to say
        so in its own voice.
        """
        if before is None or after is None:
            self.error("snapshot_unavailable",
                       "a case ran without a complete before/after snapshot pair",
                       group=group, case=case)
            return
        if isinstance(before.get("seq"), int) and isinstance(after.get("seq"), int):
            if after["seq"] < before["seq"]:
                self.error("stale_snapshot",
                           f"the event sequence moved backwards ({before['seq']} -> "
                           f"{after['seq']})", group=group, case=case)
        else:
            self.error("stale_snapshot", "a snapshot is missing its sequence number",
                       group=group, case=case)

    def _result_of(self, record: dict, name: str, index, group: str | None = None) -> dict | None:
        """The client's report, preferring the downloaded file over stdout.

        stdout is the fallback rather than the primary because a truncated
        stream and a complete one are hard to tell apart; a file that fails to
        parse is unambiguous.

        The payload is checked against the case that asked for it. The client
        stamps every report with its group, step, and case name, so a report that
        belongs to another group or another case is detectable rather than being
        adjudicated as though it were this case's evidence.
        """
        remote = f"{self.sb_dir}/result-{index}.json"
        local = self.work / "downloads" / f"{name}-{index}.json"
        local.parent.mkdir(parents=True, exist_ok=True)
        self.download(remote, local)
        payload = None
        if local.exists():
            try:
                payload = json.loads(local.read_text())
            except json.JSONDecodeError:
                self.error("malformed_result", "the downloaded result did not parse",
                           group=group, case=name)
        if payload is None:
            for line in reversed((record.get("stdout") or "").splitlines()):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        payload = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
        if payload is None:
            self.error("missing_result", "no result was recorded for this case",
                       group=group, case=name)
            return None
        if not isinstance(payload, dict) or "result" not in payload:
            self.error("incomplete_result", "the result payload has no result member",
                       group=group, case=name)
            return payload if isinstance(payload, dict) else None
        if group is not None and payload.get("group") != group:
            self.error("misattributed_result",
                       f"the result reports group {payload.get('group')!r}",
                       group=group, case=name)
        if payload.get("case") is not None and payload.get("case") != name:
            self.error("misattributed_result",
                       f"the result reports case {payload.get('case')!r}",
                       group=group, case=name)
        if payload.get("step") not in (index, str(index)):
            self.error("misattributed_result",
                       f"the result reports step {payload.get('step')!r}, expected {index!r}",
                       group=group, case=name)
        return payload

    # -- the group loop ----------------------------------------------------

    def run_group(self, group: str, ctx: dict) -> None:
        if group not in GROUP_BUILDERS:
            # A declared group with no builder would otherwise raise a KeyError
            # and take the whole profile down without an artifact.
            self.error("unknown_group", "the group has no builder", group=group)
            return
        builder = GROUP_BUILDERS[group]
        steps = list(builder(ctx))
        # The local basename must match the remote one; see the note in
        # run-openshell-profile.sh about how `sandbox upload` resolves its
        # destination. One stable local path, rewritten per group.
        upload_dir = self.work / "upload"
        upload_dir.mkdir(parents=True, exist_ok=True)
        job_path = upload_dir / "job.json"
        remote_job = f"{self.sb_dir}/job.json"
        session_file = f"{self.sb_dir}/session-{group}.txt"

        declared = [n for n, _ in steps
                    if not n.startswith("__prepare__") and not n.startswith("__hook__")]
        gaps = missing_expectations(group, declared)
        if gaps:
            self.error("undeclared_case", f"cases with no declared expectation: {gaps}",
                       group=group)

        cases: list[dict] = []
        prior: dict[str, dict] = {}

        def push_job() -> None:
            job_path.write_text(json.dumps(
                {"group": group, "url": ctx["mcp_url"], "session_file": session_file,
                 "cases": cases}))
            self.upload(job_path, remote_job)

        # A fresh MCP session per group.
        cases.append({"name": "__handshake__", "body": {}})
        push_job()
        record = self.exec(SANDBOX_PYTHON, f"{self.sb_dir}/client.py", remote_job,
                           f"{self.sb_dir}/result-handshake.json", "handshake")
        handshake = self._result_of(record, "handshake", "handshake", group)
        ctx["handshakes"][group] = (handshake or {}).get("result")

        for index, (name, build) in enumerate(steps):
            if name.startswith("__hook__"):
                # An operator control that must run between cases, e.g.
                # restoring the revocation provider. Not a case.
                try:
                    build(ctx)
                except Exception as exc:  # noqa: BLE001
                    self.error("hook_failed", f"{name} raised {type(exc).__name__}",
                               group=group)
                continue
            try:
                case = build(ctx, prior)
            except Exception as exc:  # noqa: BLE001 - a build failure is evidence
                self.error("case_build_failed",
                           f"could not build the case: {type(exc).__name__}",
                           group=group, case=name)
                continue
            if case.get("body") is not None:
                ctx["bodies"][name] = case["body"]

            while len(cases) <= index + 1:
                cases.append({"name": "__placeholder__", "body": {}})
            cases[index + 1] = case
            push_job()

            before = self.snapshot()
            record = self.exec(SANDBOX_PYTHON, f"{self.sb_dir}/client.py", remote_job,
                               f"{self.sb_dir}/result-{index + 1}.json", str(index + 1))
            after = self.snapshot()
            self._check_window(before, after, group, name)
            report = self._result_of(record, name, index + 1, group)
            result = (report or {}).get("result")
            if record.get("timed_out"):
                self.error("case_exec_timeout", "the case exec timed out",
                           group=group, case=name)
            prior[name] = result or {}
            if not name.startswith("__prepare__"):
                self.evidence.setdefault(group, {})[name] = {
                    "case": result, "before": before, "after": after,
                    "sent_proof": ctx["sent_proofs"].get(name),
                }

        # Uploaded jobs carry signed presentations. Nothing is left behind.
        self.exec("/bin/sh", "-c",
                  f"rm -f {self.sb_dir}/job.json {self.sb_dir}/result-*.json "
                  f"{self.sb_dir}/session-{group}.txt")

    def collect_logs(self) -> dict:
        """Capture each log source separately, before anything is torn down.

        "The logs" is not one thing. A canary search over a concatenation
        cannot say which component leaked, so each source is written to its own
        file and searched on its own.
        """
        logs = self.work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        collected = {}

        def capture(name: str, kind: str, argv: list[str]) -> None:
            record = self.op.run(kind, argv)
            text = (record.get("stdout") or "") + (record.get("stderr") or "")
            (logs / name).write_text(text)
            collected[name] = {"bytes": len(text), "timed_out": bool(record.get("timed_out"))}

        capture("openshell-audit.log", "gateway",
                [self.osbin, "--gateway-endpoint", self.gateway, "logs", self.sandbox])
        capture("gateway-container.log", "docker",
                ["docker", "logs", f"{self.args.run_id}-gateway"])
        capture("gateway-compose.log", "docker",
                ["docker", "compose", "-p", self.args.run_id, "--project-directory",
                 self.args.gateway_dir, "logs", "gateway"])

        # Every sandbox container this run's gateway created. The supervisor is
        # the process inside it, so its container log is the supervisor log.
        listing = self.op.run("docker", ["docker", "ps", "-a", "--format", "{{.Names}}"])
        names = [n for n in (listing.get("stdout") or "").splitlines()
                 if f"--{self.sandbox}-" in n]
        supervisor = []
        for name in names:
            record = self.op.run("docker", ["docker", "logs", name])
            supervisor.append((record.get("stdout") or "") + (record.get("stderr") or ""))
        (logs / "supervisor.log").write_text("\n".join(supervisor))
        collected["supervisor.log"] = {"containers": len(names)}

        # The sandbox's own stdout, as this run observed it across every exec.
        (logs / "sandbox-stdout.log").write_text(
            "\n".join((r.get("stdout") or "") + (r.get("stderr") or "")
                       for r in self.op.records if r["kind"] == "exec")
        )
        return collected

    def run_nooa_group(self, ctx: dict) -> None:
        """Group H: the unified path, executed as one call per case.

        The other groups drive ``openshell_client.py``, a stdlib client that
        proves the MCP-through-OpenShell seam. This group drives NOOA itself,
        inside the same policy-governed sandbox, so a single execution contains
        every layer the architecture claims.

        Authority flows the way the protocol intends. The agent generates its
        own keypair inside the sandbox and emits only the public half; the host
        principal issues a delegation to that key. No private key is ever
        carried into the sandbox, and the subject identifier the principal signs
        is derived from the key rather than trusted from the sandbox's report.
        """
        group = "nooa_full_path"
        state = f"{self.sb_dir}/nooa-state"
        python = SANDBOX_PYTHON
        client = f"{self.sb_dir}/nooa_openshell_client.py"
        # LITELLM_LOCAL_MODEL_COST_MAP is not a convenience. litellm, which nooa
        # imports transitively, fetches a model-cost map from raw.githubusercontent
        # at import time. Under a deny-all egress policy every NOOA invocation
        # therefore makes a request OpenShell refuses, and repeated refusals were
        # observed to collapse the v0.0.102 exec relay: the sandbox dropped back to
        # Provisioning partway through this group and later cases produced no
        # result at all. Telling litellm to use its bundled copy removes the
        # denied request, and with it the instability. Recorded as a finding: an
        # agent framework that fetches on import will hammer a restrictive egress
        # policy, and the failure is cumulative rather than immediate.
        env = ("--env", f"PYTHONPATH={self.sb_dir}/site:{self.sb_dir}",
               "--env", "LITELLM_LOCAL_MODEL_COST_MAP=True")

        def nooa_exec(*argv: str) -> dict:
            # `sandbox exec --env` rather than a shell wrapper, so the policy's
            # binaries list is exercised on the interpreter itself and no shell
            # sits between the runner and the code under test.
            #
            # The client's own audit hook can only count loads inside one
            # process, so the runner counts the processes that reach a mode which
            # imports nooa at all. `keygen` deliberately does not. Together the
            # two numbers are what make "imported once per profile" a
            # measurement rather than a description.
            if argv[1:2] and argv[1] in ("suite", "run"):
                ctx["nooa_processes"] = ctx.get("nooa_processes", 0) + 1
            return self._os("exec", "sandbox", "exec", "--no-tty", "-n", self.sandbox,
                            *env, "--", python, *argv)

        # 1. The agent generates its own key and reports the public half.
        out = f"{state}/keygen.json"
        record = nooa_exec(client, "keygen", state, out)
        keygen = self._json_from(record, "keygen", f"{state}/keygen.json", "nooa-keygen")
        if not keygen or not keygen.get("agent_pub"):
            self.error("missing_result", "keygen produced no public key", group=group)
            for name in GROUPS[group]:
                self.evidence.setdefault(group, {})[name] = {}
            return
        if keygen.get("derived_id_matches") is not True:
            self.error("identity_not_derived",
                       "the sandbox's agent id is not derived from its key", group=group)

        # 2. The principal issues authority to that key. Two grants: one bound
        #    to the canary order at the $100 ceiling, and nothing else.
        try:
            grant = self.control._call("/delegate", {"agent_pub": keygen["agent_pub"]})
        except Exception as exc:  # noqa: BLE001
            self.error("delegation_failed", f"delegation failed: {type(exc).__name__}",
                       group=group)
            return
        if grant["subject_id"] != keygen["agent_id"]:
            self.errors.append(
                f"{group}: principal derived {grant['subject_id']} from the key but the "
                f"sandbox claimed {keygen['agent_id']}"
            )

        canaries = ctx["canaries"]
        trace_context = {"traceparent": canaries["traceparent"],
                         "baggage": canaries["baggage"]}

        # One order per subcase, so the receiver derives a distinct canonical
        # resource for each and the runner can attribute server-side events
        # without believing the sandbox's account of which request was which.
        # Each order gets its own delegation, bound to that resource.
        plan = [
            ("nooa_capability_inert_without_the_adapter", UNDER_LIMIT, False, None),
            ("nooa_authorized_refund", UNDER_LIMIT, True, None),
            ("nooa_over_limit_denied_by_ratify", OVER_LIMIT, True, None),
            ("nooa_unlisted_tool_denied_by_openshell", UNDER_LIMIT, True,
             "admin.delete_everything"),
        ]
        subcases = []
        for index, (name, amount, install, prepare_tool) in enumerate(plan):
            order = f"{canaries['order']}-s{index}"
            try:
                grant = self.control._call(
                    "/delegate", {"agent_pub": keygen["agent_pub"], "order": order}
                )
            except Exception as exc:  # noqa: BLE001
                self.error("delegation_failed",
                           f"delegation failed: {type(exc).__name__}",
                           group=group, case=name)
                return
            spec = {
                "name": name,
                "url": ctx["mcp_url"],
                "tenant": canaries["tenant"],
                "order_id": order,
                "amount": amount,
                "install_adapter": install,
                "delegations": [grant["delegation"]],
                "trace_context": trace_context,
            }
            if prepare_tool:
                spec["prepare_tool"] = prepare_tool
            subcases.append(spec)
            ctx.setdefault("nooa_resources", {})[name] = (
                f"tenant/{canaries['tenant']}/orders/{order}"
            )

        upload_dir = self.work / "upload"
        upload_dir.mkdir(parents=True, exist_ok=True)
        job_local = upload_dir / "nooa-job.json"
        job_local.write_text(json.dumps({"url": ctx["mcp_url"], "subcases": subcases}))
        job_remote = f"{self.sb_dir}/nooa-job.json"
        self.upload(job_local, job_remote)

        # One exec, one process, one nooa import. Four separate execs imported
        # nooa four times and the sandbox did not survive it.
        out = f"{state}/suite.json"
        before = self.snapshot()
        record = nooa_exec(client, "suite", state, job_remote, out)
        after = self.snapshot()
        report = self._json_from(record, "nooa-suite", out, "nooa-suite")
        if record.get("timed_out"):
            self.error("case_exec_timeout", "the unified suite exec timed out",
                       group=group)

        self._check_window(before, after, group)
        self._check_suite_report(report, subcases, group)
        reported = {r["subcase"]: r for r in (report or {}).get("subcases", [])
                    if isinstance(r, dict) and r.get("subcase")}
        windows = self._segment_suite(before, after, subcases, ctx)
        for spec in subcases:
            name = spec["name"]
            self.evidence.setdefault(group, {})[name] = {
                "case": self._nooa_case(reported.get(name)),
                "before": windows.get(name, (None, None))[0],
                "after": windows.get(name, (None, None))[1],
                "sent_proof": None,
            }
        ctx["nooa_suite"] = report
        ctx["nooa_reports"] = reported
        ctx["nooa_reconciliation"] = self._reconcile_suite(before, after, windows, subcases)

        # The agent's own secret was generated in the sandbox and stays there.
        # It is removed with the group, along with the uploaded delegation.
        self.exec("/bin/sh", "-c", f"rm -rf {state} {job_remote}")

    def _check_suite_report(self, report, subcases, group: str) -> None:
        """Is the unified suite's report complete, and is it this suite's report?

        The four subcase gates already fail when a subcase produces nothing, but
        a suite that returned no report at all, returned another step's report, or
        returned fewer records than it was asked for is a harness failure and is
        recorded as one. This is the specific hole that let
        ``driver_reported_no_errors`` pass while the whole group vanished.
        """
        if report is None:
            self.error("missing_result", "the unified suite produced no parseable report",
                       group=group)
            return
        if report.get("step") != "suite":
            self.error("misattributed_result",
                       f"the report reports step {report.get('step')!r}, expected 'suite'",
                       group=group)
        records = report.get("subcases")
        if not isinstance(records, list):
            self.error("incomplete_result", "the report carries no subcase list", group=group)
            return
        if len(records) != len(subcases):
            self.error("partial_suite",
                       f"the suite reported {len(records)} of {len(subcases)} subcases",
                       group=group)
        reported = {r.get("subcase") for r in records if isinstance(r, dict)}
        for spec in subcases:
            if spec["name"] not in reported:
                self.error("missing_subcase", "the suite reported no record for this subcase",
                           group=group, case=spec["name"])
        planned = {spec["name"] for spec in subcases}
        for name in sorted(reported - planned):
            self.error("misattributed_result", "the suite reported an unplanned subcase",
                       group=group, case=str(name))
        for record in records:
            if not isinstance(record, dict) or "outcome" not in record:
                self.error("incomplete_result",
                           "a subcase record carries no outcome", group=group,
                           case=str((record or {}).get("subcase")) if isinstance(record, dict)
                           else None)

    @staticmethod
    def _segment_suite(before, after, subcases, ctx) -> dict:
        """Split one suite execution into per-subcase snapshot pairs.

        Built from the receiver's own append-only event log, not from the
        sandbox's report. Each subcase owns a contiguous run of events beginning
        at the ``prepare`` event whose ``resource_id`` matches the resource that
        subcase was delegated, and ending where the next subcase's run begins.
        Attribution is sound because the suite is strictly sequential in one
        process and the log's monotonic sequence corroborates that ordering; the
        reconciliation check below is what would catch it if it were not.

        A subcase that makes no request at all, the inert one, owns an empty
        window, which is exactly the evidence its expectation requires.
        """
        if before is None or after is None:
            return {}
        events = [e for e in after.get("events", []) if e["seq"] > before["seq"]]
        resources = ctx.get("nooa_resources", {})
        # Segment boundaries come from the shape of the log, not from counting
        # prepares. Each subcase opens a fresh MCP session, so its run begins at
        # an ingress that directly follows the previous subcase's decision, or at
        # the very start. Splitting on prepare events instead put each subcase's
        # tool_dispatch in its predecessor's window, because the receiver records
        # the dispatch before the prepare it causes.
        starts = [
            index
            for index, event in enumerate(events)
            if event["event_type"] == "http_ingress"
            and (index == 0 or events[index - 1]["event_type"] == "decision")
        ]
        segments = [
            (begin, starts[position + 1] if position + 1 < len(starts) else len(events))
            for position, begin in enumerate(starts)
        ]

        # Identify each segment by the receiver's own canonical resource id where
        # it issued a challenge. A segment with no prepare made no business
        # request, so it is matched positionally against the remaining subcases.
        by_resource = {}
        anonymous = []
        for begin, finish in segments:
            prepare = next(
                (e for e in events[begin:finish] if e["event_type"] == "prepare"), None
            )
            if prepare and prepare.get("resource_id"):
                by_resource[prepare["resource_id"]] = (begin, finish)
            else:
                anonymous.append((begin, finish))

        windows = {}
        for spec in subcases:
            name = spec["name"]
            segment = by_resource.pop(resources.get(name), None)
            # A subcase with no presentation adapter installs no client and makes
            # no MCP call, so it can never own a segment. Letting it claim an
            # anonymous one handed it the handshake of the subcase whose tool the
            # policy refused, and reported both incorrectly.
            if segment is None and anonymous and spec.get("install_adapter", True):
                segment = anonymous.pop(0)
            if segment is None:
                # Nothing reached the receiver for this subcase. An empty
                # window, which is precisely what an inert capability must show.
                windows[name] = (before, before)
                continue
            begin, finish = segment
            windows[name] = (
                Runner._synthesize(before, events[:begin]),
                Runner._synthesize(before, events[:finish], final=after),
            )
        return windows

    @staticmethod
    def _synthesize(base: dict, events: list, final: dict | None = None) -> dict:
        """A snapshot as of a point in the event stream.

        Replays the log forward from ``base``, which is the only way to state a
        per-subcase delta when several subcases share one execution. Counter
        values that the log does not carry, the refund ledger and the receipt
        set, are taken from the decision events themselves.
        """
        counters = dict(base["counters"])
        counters["tool_dispatch"] = list(counters.get("tool_dispatch") or [])
        counters["inbound_proof_sha"] = list(counters.get("inbound_proof_sha") or [])
        counters["inbound_proof_len"] = list(counters.get("inbound_proof_len") or [])
        seq = base["seq"]
        for event in events:
            seq = event["seq"]
            kind = event["event_type"]
            if kind == "http_ingress":
                counters["http_ingress"] += 1
            elif kind == "tool_dispatch":
                counters["tool_dispatch"].append(event.get("tool_name"))
            elif kind == "prepare":
                counters["prepare"] += 1
            elif kind == "execute":
                counters["execute"] += 1
            elif kind == "proof_observed":
                counters["inbound_proof_sha"].append(event.get("proof_sha256"))
                counters["inbound_proof_len"].append(event.get("proof_len"))
            elif kind == "decision":
                if event.get("receipt_id"):
                    counters["receipts"] += 1
                else:
                    counters["refusals"] += 1
                if event.get("decision") == "authorized":
                    counters["refunded_total"] += UNDER_LIMIT
        if final is not None:
            # Verification of the receipt set is a property of the whole set and
            # cannot be replayed, so it is carried from the real final snapshot.
            counters["receipts_all_verify"] = final["counters"].get("receipts_all_verify")
        return {"seq": seq, "counters": counters, "events": []}

    @staticmethod
    def _reconcile_suite(before, after, windows, subcases) -> dict:
        """Do the per-subcase windows account for everything the receiver saw?

        If a subcase's activity were misattributed, or if anything happened that
        no subcase explains, the parts would not sum to the whole. This is the
        check that makes segmentation trustworthy rather than merely plausible.
        """
        if before is None or after is None:
            return {"reconciled": False, "reason": "missing suite snapshots"}
        total = (after["seq"] or 0) - (before["seq"] or 0)
        covered = 0
        for spec in subcases:
            window = windows.get(spec["name"])
            if not window or window[0] is None or window[1] is None:
                continue
            covered += (window[1]["seq"] or 0) - (window[0]["seq"] or 0)
        return {
            "reconciled": covered == total,
            "events_in_suite": total,
            "events_attributed": covered,
        }

    @staticmethod
    def _nooa_case(report: dict | None) -> dict | None:
        """Translate a NOOA run report into the shape the adjudicator judges.

        The adjudicator is deliberately transport-agnostic: it judges HTTP
        status, decision, and boundary deltas. This maps one vocabulary onto the
        other without inventing anything. A report that produced no decision
        keeps ``http_status`` absent, which the adjudicator treats as a partial
        result and fails.
        """
        if report is None:
            return None
        decision = report.get("decision") or {}
        case = {
            "outcome": report.get("outcome"),
            "policy_denied": False,
            "transport_error": report.get("outcome") == "mcp_transport_error",
            "is_error": False,
            "llm_calls": report.get("llm_calls"),
            "presented": report.get("presented"),
            "mcp_trace": report.get("mcp_trace"),
        }
        if report.get("outcome") == "returned":
            case["http_status"] = 200
            case["decision"] = decision.get("decision")
            case["status_code"] = decision.get("status")
            case["reason"] = decision.get("reason") or ""
            case["receipt_id"] = decision.get("receipt_id")
            case["refunded"] = decision.get("refunded")
        return case

    def _json_from(self, record: dict, label: str, remote: str, stem: str) -> dict | None:
        """The client's report, preferring the downloaded file over stdout."""
        local = self.work / "downloads" / f"{stem}.json"
        local.parent.mkdir(parents=True, exist_ok=True)
        self.download(remote, local)
        if local.exists():
            try:
                return json.loads(local.read_text())
            except json.JSONDecodeError:
                self.error("malformed_result", f"the {label} result did not parse")
        for line in reversed((record.get("stdout") or "").splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        self.error("missing_result", f"no parseable {label} result was recorded")
        return None

    def run_log_canaries(self, ctx: dict) -> dict:
        """Group G: exercise each shape of traffic so the log audit has
        something of every kind to search against.

        These reuse cases the other groups already adjudicate, so the gate here
        is the canary search rather than a per-case verdict.
        """
        return {"shapes_exercised": list(GROUP_G_SHAPES),
                "note": "each shape is produced by the groups above; the gate is the "
                        "canary search across log sources"}


# --------------------------------------------------------------------------
# Log audit
# --------------------------------------------------------------------------

def audit_logs(work: pathlib.Path, canaries: dict[str, str],
               extra: dict[str, str]) -> dict:
    """Search each log source separately for this run's canaries.

    Only labels and counts are recorded. The searched values include literal
    fragments of a proof that went over the wire, and writing those into the
    artifact would defeat the point of measuring carriage by hash.
    """
    needles = {k: v for k, v in {**canaries, **extra}.items() if v}
    # Component output is what the components under test wrote. Harness output
    # is what this profile wrote about itself: the client's own report of the
    # request it just sent necessarily contains the values it sent, and
    # counting that as a leak would make the gate meaningless. Both are
    # searched and both are recorded; only component sources gate the run.
    sources = {
        "gateway_compose": ("component", work / "logs" / "gateway-compose.log"),
        "gateway_container": ("component", work / "logs" / "gateway-container.log"),
        "supervisor": ("component", work / "logs" / "supervisor.log"),
        "openshell_audit": ("component", work / "logs" / "openshell-audit.log"),
        "mcp_receiver": ("component", work / "logs" / "receiver.log"),
        "harness_sandbox_stdout": ("harness", work / "logs" / "sandbox-stdout.log"),
        "harness_runner": ("harness", work / "operations.jsonl"),
    }
    report = {}
    for label, (owner, path) in sources.items():
        if not path.exists():
            report[label] = {"owner": owner, "present": False, "hits": {}}
            continue
        text = path.read_text(errors="replace")
        report[label] = {
            "owner": owner,
            "present": True,
            "lines": text.count("\n"),
            "hits": {name: text.count(value) for name, value in needles.items()},
        }
    return report


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", required=True)
    parser.add_argument("--openshell", required=True)
    parser.add_argument("--gateway-endpoint", required=True)
    parser.add_argument("--sandbox", required=True)
    parser.add_argument("--sandbox-dir", required=True)
    parser.add_argument("--mcp-host", required=True)
    parser.add_argument("--mcp-port", type=int, required=True)
    parser.add_argument("--ctrl-port", type=int, required=True)
    parser.add_argument("--env-json", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--gateway-dir", required=True)
    parser.add_argument("--artifact", required=True)
    args = parser.parse_args()

    work = pathlib.Path(args.work)
    runner = Runner(args)
    public = runner.control.public()

    ctx = {
        "control": runner.control,
        "canaries": public["canaries"],
        "agent_id": public["agent_id"],
        "resource_id": public["resource_id"],
        "mcp_host": args.mcp_host,
        "mcp_port": args.mcp_port,
        "ctrl_port": args.ctrl_port,
        "mcp_url": f"http://{args.mcp_host}:{args.mcp_port}/mcp",
        "sent_proofs": {},
        "bodies": {},
        "handshakes": {},
        "fragment_file": work / "proof_fragment.json",
    }

    # Before anything is judged: the in-sandbox presenter stamps challenge_at from
    # the container's clock, and the receiver verifies against this host's.
    ctx["clock_skew"] = runner.measure_clock_skew()

    fragment_file = ctx["fragment_file"]
    for group in GROUPS:
        if group == "nooa_full_path":
            continue
        runner.run_group(group, ctx)
    runner.run_nooa_group(ctx)
    group_g = runner.run_log_canaries(ctx)
    group_g["log_capture"] = runner.collect_logs()

    verdicts = []
    for group in GROUPS:
        verdicts.extend(adjudicate_group(group, runner.evidence.get(group, {})))

    # A required case counts as executed only if a result was actually recorded
    # for it. Deriving this from the verdict list instead was vacuous: the
    # adjudicator emits a verdict for every declared case by design, so the list
    # was always empty and the gate below could not fail. The failing case still
    # fails on its own verdict; this is the separate claim that the profile ran
    # everything it requires.
    not_executed = []
    for required in REQUIRED_CASES:
        group, _, case = required.partition("::")
        found = (runner.evidence.get(group) or {}).get(case)
        if not found or found.get("case") is None:
            not_executed.append(required)

    # Literal proof fragments, from a proof that actually crossed the wire.
    proof_fragments = {}
    if fragment_file.exists():
        try:
            proof_fragments = json.loads(fragment_file.read_text())
        except json.JSONDecodeError:
            runner.error("malformed_result", "the proof fragment file did not parse")
    canary_report = audit_logs(work, ctx["canaries"], proof_fragments)

    # Only component sources gate the run; see audit_logs for why.
    leaked = [f"{source}:{label}"
              for source, info in canary_report.items()
              if info.get("owner") == "component"
              for label, count in (info.get("hits") or {}).items() if count]

    environment = json.loads(pathlib.Path(args.env_json).read_text())
    handshake_ok = all(
        (h or {}).get("initialize", {}).get("http_status") == 200
        for h in ctx["handshakes"].values()
    )
    tools_seen = sorted({
        tool
        for h in ctx["handshakes"].values()
        for tool in ((h or {}).get("tools_list", {}) or {}).get("tools", []) or []
    })

    gates = [{"name": v.name, "result": v.result, "detail": v.detail, "deltas": v.deltas}
             for v in verdicts]
    gates.append({
        "name": "mcp_handshake_through_openshell_every_group",
        "result": "PASS" if handshake_ok else "FAIL",
        "detail": f"{len(ctx['handshakes'])} groups", "deltas": {},
    })
    gates.append({
        "name": "tools_list_exposes_exactly_the_two_refund_tools",
        "result": "PASS" if tools_seen == ["refund.execute", "refund.prepare"] else "FAIL",
        "detail": str(tools_seen), "deltas": {},
    })
    # Parser coverage, alongside the safety invariant rather than instead of it.
    # The fifteen parser verdicts can all pass under a policy that denies
    # everything, because a blanket refusal never laundered a method into another
    # tool. This gate is what fails in that situation.
    coverage = parser_coverage({
        v.name.split("::", 1)[1]: v.deltas
        for v in verdicts if v.name.startswith("parser_differentials::")
    })
    gates.append({
        "name": "parser_matrix_exercised_both_admission_and_denial",
        "result": coverage["result"],
        "detail": (f"{coverage['admitted']}/{coverage['expected_admitted']} admitted, "
                   f"{coverage['denied']}/{coverage['expected_denied']} denied"
                   + (f"; mismatched: {coverage['mismatched']}" if coverage["mismatched"] else "")
                   + (f"; unaccounted: {coverage['unaccounted']}"
                      if coverage["unaccounted"] else ""))[:300],
        "deltas": {},
    })

    nooa_reports = ctx.get("nooa_reports", {})
    llm_calls = [n for n, r in nooa_reports.items() if (r or {}).get("llm_calls")]
    reconciliation = ctx.get("nooa_reconciliation") or {}
    gates.append({
        "name": "unified_suite_events_fully_attributed_to_subcases",
        "result": "PASS" if reconciliation.get("reconciled") else "FAIL",
        "detail": json.dumps(reconciliation),
        "deltas": {},
    })
    suite_report = ctx.get("nooa_suite") or {}
    # Two independent measurements, both required, neither sufficient alone: the
    # name `nooa` was loaded exactly once inside the suite process (counted by an
    # `import` audit hook, which fires only on a sys.modules miss), and exactly
    # one process in the whole profile reached a mode that imports nooa at all.
    # The first is blind to other processes; the second is blind to what happens
    # inside one. The `measured` flag is not decoration: without it an older
    # client reporting a hardcoded 1 would still pass this gate.
    module_loads = suite_report.get("nooa_imports")
    nooa_processes = ctx.get("nooa_processes")
    imported_once = (
        suite_report.get("nooa_imports_measured") is True
        and module_loads == 1
        and nooa_processes == 1
    )
    gates.append({
        "name": "unified_suite_imported_nooa_once",
        "result": "PASS" if imported_once else "FAIL",
        "detail": f"measured={suite_report.get('nooa_imports_measured')} "
                  f"module_loads={module_loads} nooa_processes={nooa_processes}",
        "deltas": {},
    })
    gates.append({
        "name": "unified_path_never_called_an_llm",
        "result": "PASS" if (nooa_reports and not llm_calls) else "FAIL",
        "detail": f"llm calls in {llm_calls}" if llm_calls else
                  f"{len(nooa_reports)} NOOA runs, zero LLM calls",
        "deltas": {},
    })
    authorized = (nooa_reports.get("nooa_authorized_refund") or {})
    presented = authorized.get("presented") or []
    trace = authorized.get("mcp_trace") or []
    tools_over_mcp = [e.get("tool") for e in trace]
    composed = (
        len(presented) == 1
        and presented[0][0] == "issue_refund"
        and "initialize" in tools_over_mcp
        and "refund.prepare" in tools_over_mcp
        and "refund.execute" in tools_over_mcp
        and (authorized.get("decision") or {}).get("receipt_id")
    )
    gates.append({
        "name": "one_execution_traversed_nooa_mcp_openshell_receiver_ratify",
        "result": "PASS" if composed else "FAIL",
        "detail": f"capability={[p[0] for p in presented]} mcp={tools_over_mcp} "
                  f"receipt={(authorized.get('decision') or {}).get('receipt_id')}",
        "deltas": {},
    })
    skew = ctx.get("clock_skew") or {}
    gates.append({
        "name": "sandbox_clock_within_presenter_safety_margin",
        "result": skew.get("result", "FAIL"),
        "detail": str(skew.get("detail", "no clock measurement"))[:200],
        "deltas": {},
    })
    gates.append({
        "name": "no_tested_canaries_in_inspected_logs",
        "result": "PASS" if not leaked else "FAIL",
        "detail": ", ".join(leaked) if leaked else
                  f"{sum(1 for s in canary_report.values() if s.get('present') and s.get('owner') == 'component')} "
                  "component sources searched, none hit",
        "deltas": {},
    })
    gates.append({
        "name": "no_external_operation_timed_out",
        "result": "PASS" if not runner.timeouts else "FAIL",
        "detail": json.dumps(runner.timeouts)[:300] if runner.timeouts else "none",
        "deltas": {},
    })
    gates.append({
        "name": "every_required_case_executed",
        "result": "PASS" if not not_executed else "FAIL",
        "detail": ", ".join(not_executed) if not_executed else
                  f"{len(REQUIRED_CASES)} required cases",
        "deltas": {},
    })
    gates.append({
        "name": "driver_reported_no_errors",
        "result": "PASS" if not runner.errors else "FAIL",
        "detail": "; ".join(
            f"{e['kind']}[{e.get('group', '-')}::{e.get('case', '-')}] {e['detail']}"
            for e in runner.errors)[:400] if runner.errors else "none",
        "deltas": {},
    })

    passed = sum(1 for g in gates if g["result"] == "PASS")
    failed = sum(1 for g in gates if g["result"] == "FAIL")
    skipped = sum(1 for g in gates if g["result"] == "SKIP")

    artifact = {
        "run_id": environment.get("run_id"),
        # Carried through from the environment: whether this run was built from the
        # published Ratify package or from the checkout. An artifact that does not
        # say which one it is can be mistaken for final evidence.
        "evidence_status": environment.get("evidence_status"),
        "components": environment.get("components", {}),
        "platform": environment.get("platform", {}),
        "ports": environment.get("ports", {}),
        "hashes": environment.get("hashes", {}),
        "network": environment.get("network", {}),
        "concurrency": environment.get("concurrency", {}),
        "executed_cases": [v.name for v in verdicts],
        "not_executed": not_executed,
        # Things this profile deliberately does not claim to have executed.
        # Separate from not_executed, which is required cases that failed to
        # run and always fails the profile. These are scope boundaries, stated
        # so the documentation cannot overclaim past them.
        "known_limitations": [
            {"item": "linux/amd64 execution",
             "why": "only the recorded host architecture was executed; other "
                    "platforms are compatibility targets, not results"},
            {"item": "Podman as the container runtime",
             "why": "only Docker was executed"},
            {"item": "verifier-side missing resource context (has_resource=False)",
             "why": "unreachable through the MCP path by construction, because the "
                    "receiver always supplies its own phase-1 resource id; covered "
                    "hermetically in test_verification.py instead"},
            {"item": "genuinely duplicated HTTP header fields",
             "why": "urllib collapses repeated header names, so the duplicate-header "
                    "probes send one folded value; recorded as folded rather than "
                    "claimed as true duplication"},
            {"item": "concurrent OpenShell gateway bootstrap",
             "why": "OpenShell v0.0.102 uses a fixed supervisor-extraction container "
                    "name, so concurrent bootstrap collides upstream; the profile "
                    "serializes bootstrap only and records this as a finding"},
            {"item": "TLS, OIDC, or mTLS in front of the gateway",
             "why": "the profile runs a local single-player gateway on loopback with "
                    "plaintext and unauthenticated access, as its config states"},
        ],
        "case_deltas": {v.name: v.deltas for v in verdicts},
        "proof_sizes": ctx["sent_proofs"],
        "log_sources_inspected": canary_report,
        "group_g": group_g,
        "parser_coverage": coverage,
        "clock_skew": skew,
        "unified_execution_model": {
            "nooa_module_loads_in_suite_process": module_loads,
            "nooa_module_loads_measured": suite_report.get("nooa_imports_measured"),
            "processes_that_import_nooa": nooa_processes,
            "why": "four separate execs imported nooa four times and the sandbox "
                   "did not survive it; the exec relay closed and the sandbox fell "
                   "back to Provisioning",
            "reconciliation": reconciliation,
        },
        "unified_path": {
            name: {
                "outcome": (r or {}).get("outcome"),
                "llm_calls": (r or {}).get("llm_calls"),
                "capability_calls": [p[0] for p in ((r or {}).get("presented") or [])],
                "mcp_tools": [e.get("tool") for e in ((r or {}).get("mcp_trace") or [])],
                "decision": ((r or {}).get("decision") or {}).get("decision"),
                "status": ((r or {}).get("decision") or {}).get("status"),
                "receipt_id": ((r or {}).get("decision") or {}).get("receipt_id"),
            }
            for name, r in nooa_reports.items()
        },
        "operations": {
            "count": len(runner.op.records),
            "timeouts": runner.timeouts,
            "slowest_seconds": max((r["seconds"] for r in runner.op.records), default=0),
            "max_argv_bytes": max((r["argv_len"] for r in runner.op.records), default=0),
            # Downloads only: an attempt count above 1 with a final success. Never
            # exec or upload, and never masked into driver_errors.
            "retried_operations": runner.retried_operations,
        },
        "driver_errors": runner.errors,
        "gates": gates,
        "summary": {"passed": passed, "failed": failed, "skipped": skipped,
                    "required_cases": len(REQUIRED_CASES)},
    }

    # Atomic: a reader never sees a half-written artifact, and a crash mid-write
    # leaves the previous run's file rather than a corrupt one.
    target = pathlib.Path(args.artifact)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(artifact, indent=2, default=str))
    os.replace(tmp, target)

    for gate in gates:
        print(f"    {gate['result']:<5} {gate['name']:<62} {str(gate['detail'])[:70]}")
    print(f"\n  gates: {passed} passed, {failed} failed, {skipped} skipped")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
