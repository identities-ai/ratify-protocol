# SPDX-License-Identifier: Apache-2.0
"""The authorization artifact crossing a real MCP Streamable HTTP boundary.

Every test here drives an actual MCP client against an actual server over
Streamable HTTP: initialize, notifications/initialized, tools/list, tools/call.
Nothing calls a decorated Python function directly, because doing so would
prove the receiver works and say nothing about whether the proof survives the
transport, which is the entire question.

Hermetic. No LLM, no API key, no Docker, no GPU, no network beyond loopback.

Pinned: mcp==2.0.0, protocol 2026-07-28.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import threading
import time

import pytest

# Skipping is right for the general SDK suite: most environments have no reason
# to install the MCP SDK. It is wrong for the reference gate. An ordinary pytest
# run on Python 3.11 reported "91 passed, 1 skipped" and exited 0 while this
# entire module, a third of the hermetic suite, had not run. A gate that turns a
# missing dependency into a green tick is worse than no gate, so
# RATIFY_REQUIRE_MCP=1 makes the absence a hard failure instead of a skip.
# scripts/nvidia-reference-check.sh sets it.
if os.environ.get("RATIFY_REQUIRE_MCP") == "1":
    import mcp  # noqa: F401, must import, or this check has failed
else:
    pytest.importorskip(
        "mcp",
        reason="MCP transport tests require `pip install mcp==2.0.0`; "
        "set RATIFY_REQUIRE_MCP=1 to make this a failure instead",
    )

import uvicorn  # noqa: E402
from mcp import Client  # noqa: E402
from ratify_protocol import (  # noqa: E402
    Constraint,
    SCOPE_PAYMENTS_SEND,
    verify_verification_receipt,
)
from ratify_protocol.wire import encode_proof_bundle  # noqa: E402

from mcp_server import (  # noqa: E402
    MAX_PROOF_BYTES,
    PROOF_META_KEY,
    PROPOSED_OPENSHELL_MAX_BODY_BYTES,
    build_server,
)
from principal import new_agent, new_principal, sign_cert  # noqa: E402
from refund_service import RefundService, canonical_resource_id  # noqa: E402
from test_verification import build_bundle  # noqa: E402

LIMIT = 100.0
UNDER = 75.0
OVER = 150.0
DAY = 24 * 3600


def _free_port() -> int:
    with contextlib.closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _World:
    def __init__(self, principal, principal_priv, agent, agent_priv, cert, service, url):
        self.principal = principal
        self.principal_priv = principal_priv
        self.agent = agent
        self.agent_priv = agent_priv
        self.cert = cert
        self.service = service
        self.url = url


@pytest.fixture
def mcp_world():
    """A refund service behind a live MCP Streamable HTTP endpoint."""
    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("mcp-refund-agent")
    now = int(time.time())
    cert = sign_cert(
        issuer_id=principal.id,
        issuer_pub=principal.public_key,
        issuer_priv=principal_priv,
        subject_id=agent.id,
        subject_pub=agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[
            Constraint(type="max_amount", max_amount=LIMIT, currency="USD"),
            Constraint(type="resource_path", resource_id=canonical_resource_id("acme", "ord-1")),
        ],
        issued_at=now - 60,
        expires_at=now + DAY,
    )

    service = RefundService(trust_root=principal.public_key)
    observed: list[tuple[str, dict]] = []
    port = _free_port()
    app = build_server(service, observe=lambda t, tc: observed.append((t, tc))).streamable_http_app(
        json_response=True
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("MCP server did not start")

    try:
        world = _World(
            principal,
            principal_priv,
            agent,
            agent_priv,
            cert,
            service,
            f"http://127.0.0.1:{port}/mcp",
        )
        world.observed = observed
        yield world
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@contextlib.asynccontextmanager
async def _session(url):
    """A real MCP client over Streamable HTTP.

    Entering the client performs initialize and notifications/initialized;
    every call below therefore crosses the wire as JSON-RPC.
    """
    async with Client(url) as session:
        yield session


def _proof_meta(bundle) -> dict:
    return {PROOF_META_KEY: base64.b64encode(encode_proof_bundle(bundle).encode()).decode()}


async def _prepare(session, order_id, amount, agent_id, currency="USD", tenant="acme"):
    result = await session.call_tool(
        "refund.prepare",
        {
            "order_id": order_id,
            "amount": amount,
            "agent_id": agent_id,
            "currency": currency,
            "tenant": tenant,
        },
    )
    return result.structured_content


async def _execute(session, challenge_b64, bundle, extra_meta=None, arguments=None):
    meta = _proof_meta(bundle) if bundle is not None else {}
    if extra_meta:
        meta.update(extra_meta)
    args = {"challenge": challenge_b64}
    if arguments:
        args.update(arguments)
    result = await session.call_tool("refund.execute", args, meta=meta or None)
    return result


async def _full_refund(world, session, order_id, amount, cert=None, agent=None, priv=None):
    """prepare, sign the receiver's challenge, execute."""
    agent = agent or world.agent
    priv = priv or world.agent_priv
    prepared = await _prepare(session, order_id, amount, agent.id)
    bundle = build_bundle(
        agent.id,
        agent.public_key,
        priv,
        [cert or world.cert],
        base64.b64decode(prepared["challenge"]),
        base64.b64decode(prepared["session_context"]),
    )
    result = await _execute(session, prepared["challenge"], bundle)
    return result.structured_content


# ---------------------------------------------------------------------------
# Protocol surface
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_initialize_and_tool_discovery(mcp_world):
    """WHY: the boundary has to be a real MCP endpoint, not an HTTP service
    wearing the name. Initialization and discovery are what any MCP client,
    gateway, or policy layer will do first, and they are what makes the
    contribution portable rather than bespoke."""
    async with _session(mcp_world.url) as session:
        listed = await session.list_tools()

    names = {t.name for t in listed.tools}
    assert names == {"refund.prepare", "refund.execute"}


@pytest.mark.anyio
async def test_proof_is_not_a_business_argument_in_the_tool_schema(mcp_world):
    """WHY: authorization material must not appear in the tool schema. If it
    did, it would be a field a model can see, reason about, and hallucinate,
    and it would surface anywhere tool arguments are logged. The proof belongs
    to transport metadata; the schema should describe the business action."""
    async with _session(mcp_world.url) as session:
        listed = await session.list_tools()

    execute = next(t for t in listed.tools if t.name == "refund.execute")
    properties = set(execute.input_schema.get("properties", {}))
    assert properties == {"challenge"}
    schema_text = str(execute.input_schema).lower()
    assert "proof" not in schema_text
    assert "ratify" not in schema_text


# ---------------------------------------------------------------------------
# The authorization artifact survives the boundary
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_bounded_refund_executes_across_the_mcp_boundary(mcp_world):
    """WHY: the whole contribution in one test. A principal-signed delegation
    crosses a standard tool boundary, and an independent receiver verifies it
    before acting. If this does not work, nothing else matters."""
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-1", UNDER)

    assert out["decision"] == "authorized"
    assert out["status"] == "authorized_agent"
    assert out["receipt_id"]
    assert mcp_world.service.refunded_total == UNDER


@pytest.mark.anyio
async def test_over_limit_is_denied_after_transport(mcp_world):
    """WHY: MCP moved the bytes; it did not grant anything. The principal's
    $100 ceiling still binds on the far side of a tool boundary the principal
    never saw."""
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-1", OVER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert mcp_world.service.refunded_total == 0.0


@pytest.mark.anyio
async def test_wrong_resource_is_denied_after_transport(mcp_world):
    """WHY: resource-bound authority has to survive the transport too. The
    delegation names tenant/acme/orders/ord-1, and the receiver canonicalizes
    its own parse of whatever the tool call asked for."""
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-99", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"
    assert "resource" in out["reason"]


@pytest.mark.anyio
async def test_wrong_tenant_is_denied_after_transport(mcp_world):
    """WHY: the cross-tenant case is the one that looks correct in every log.
    Same local order number, different tenant, and the canonical identifiers
    differ by exact byte comparison."""
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id, tenant="globex")
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        result = await _execute(session, prepared["challenge"], bundle)

    out = result.structured_content
    assert out["decision"] == "denied"
    assert out["status"] == "constraint_denied"


@pytest.mark.anyio
async def test_replay_across_the_boundary_is_denied(mcp_world):
    """WHY: a tool boundary is a place presentations can be captured. Single
    use is enforced by the receiver, not by the transport, so it has to hold
    when the same call is repeated through MCP."""
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        first = await _execute(session, prepared["challenge"], bundle)
        second = await _execute(session, prepared["challenge"], bundle)

    assert first.structured_content["decision"] == "authorized"
    assert second.structured_content["decision"] == "denied"
    assert mcp_world.service.refunded_total == UNDER


@pytest.mark.anyio
async def test_a_proof_cannot_be_moved_to_another_pending_request(mcp_world):
    """WHY: two prepared refunds exist at once. A proof answering one must not
    satisfy the other, or an agent could prepare a small refund and a large
    one and present the cheap proof against the expensive record."""
    async with _session(mcp_world.url) as session:
        small = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        large = await _prepare(session, "ord-1", OVER, mcp_world.agent.id)
        bundle_for_small = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(small["challenge"]),
            base64.b64decode(small["session_context"]),
        )
        # Present the small refund's proof against the large refund's record.
        result = await _execute(session, large["challenge"], bundle_for_small)

    out = result.structured_content
    assert out["decision"] == "denied"
    assert out["receipt_id"] == ""  # refused before authentication
    assert mcp_world.service.refunded_total == 0.0


@pytest.mark.anyio
async def test_expired_delegation_is_denied_after_transport(mcp_world):
    """WHY: expiry is evaluated at the receiver, and the transport has no
    opinion about time."""
    now = int(time.time())
    expired = sign_cert(
        issuer_id=mcp_world.principal.id,
        issuer_pub=mcp_world.principal.public_key,
        issuer_priv=mcp_world.principal_priv,
        subject_id=mcp_world.agent.id,
        subject_pub=mcp_world.agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[],
        issued_at=now - 7200,
        expires_at=now - 3600,
    )
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-1", UNDER, cert=expired)

    assert out["decision"] == "denied"
    assert out["status"] == "expired"


@pytest.mark.anyio
async def test_revoked_delegation_is_denied_after_transport(mcp_world):
    """WHY: revocation must reach the decision even when the request arrived
    over a tool protocol that knows nothing about it."""
    async with _session(mcp_world.url) as session:
        assert (await _full_refund(mcp_world, session, "ord-1", UNDER))["decision"] == "authorized"
        mcp_world.service.revoke(mcp_world.cert.cert_id)
        out = await _full_refund(mcp_world, session, "ord-1", UNDER)

    assert out["decision"] == "denied"
    assert out["status"] == "revoked"


# ---------------------------------------------------------------------------
# Proof carriage is a contract, and it is enforced
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_there_is_exactly_one_authoritative_proof_location(mcp_world):
    """WHY: if authorization material could arrive in either _meta or the tool
    arguments, some precedence rule would decide which wins, and a precedence
    rule is a thing an attacker aims at.

    Two observed behaviours together give one location. An undeclared
    argument is dropped by MCP schema validation before the handler runs, so
    it cannot influence anything: the call below succeeds on the strength of
    its _meta proof alone, and the bogus argument is inert. A proof supplied
    only as an argument is refused outright, because the handler reads _meta
    and nothing else."""
    async with _session(mcp_world.url) as session:
        # (a) A bogus proof argument alongside a real _meta proof is inert.
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        with_extra = await _execute(
            session,
            prepared["challenge"],
            bundle,
            arguments={"authorization_proof": "attacker-supplied"},
        )
        assert with_extra.structured_content["decision"] == "authorized"

        # (b) The same proof, offered only as an argument, authorizes nothing.
        second = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        args_only = await session.call_tool(
            "refund.execute",
            {
                "challenge": second["challenge"],
                "authorization_proof": _proof_meta(bundle)[PROOF_META_KEY],
            },
        )

    assert args_only.is_error
    assert mcp_world.service.refunded_total == UNDER  # only (a) moved money


@pytest.mark.anyio
@pytest.mark.parametrize(
    "meta,label",
    [
        ({}, "absent"),
        ({PROOF_META_KEY: 12345}, "not_a_string"),
        ({PROOF_META_KEY: "!!!not base64!!!"}, "invalid_base64"),
        ({PROOF_META_KEY: base64.b64encode(b"{not a bundle").decode()}, "malformed_bundle"),
        ({PROOF_META_KEY: base64.b64encode(b"x" * 300_000).decode()}, "oversized"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
async def test_unusable_proof_metadata_is_refused_before_verification(mcp_world, meta, label):
    """WHY: every one of these has to be a clean refusal, with no receipt, no
    consumed challenge, and no exception escaping the tool. A transport that
    answers malformed authorization metadata with a stack trace has not failed
    closed, it has just failed."""
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        result = await session.call_tool(
            "refund.execute",
            {"challenge": prepared["challenge"]},
            meta=meta or None,
        )

    assert result.is_error
    assert mcp_world.service.receipts == []
    assert mcp_world.service.refunded_total == 0.0


@pytest.mark.anyio
async def test_a_refused_presentation_leaves_the_challenge_usable(mcp_world):
    """WHY: refusing bad metadata must not burn the pending record. Otherwise
    anyone who can reach the endpoint can grief a legitimate agent by firing
    garbage at a challenge it is about to use."""
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        bad = await session.call_tool(
            "refund.execute",
            {"challenge": prepared["challenge"]},
            meta={PROOF_META_KEY: "!!!"},
        )
        assert bad.is_error

        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        good = await _execute(session, prepared["challenge"], bundle)

    assert good.structured_content["decision"] == "authorized"


# ---------------------------------------------------------------------------
# Correlation is not authority
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_trace_context_propagates_to_the_receiving_boundary(mcp_world):
    """WHY: W3C trace context and the authorization proof share the _meta
    envelope and must never share meaning. This asserts the narrow, true
    property: trace context reaches the receiving boundary, separately from
    authorization metadata, and the adapter observes it for instrumentation.

    It deliberately does NOT claim trace correlation. Nothing here joins a
    NOOA span to an OpenShell audit event to a Ratify receipt; establishing
    that needs a real exporter and is pending the observability work.

    Note also what is absent from the result: the response carries no
    traceparent and no baggage. Echoing caller-supplied strings back inside an
    authorization response would prove nothing an observability backend needs
    and would normalize putting attacker-controlled data there."""
    traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        result = await _execute(
            session,
            prepared["challenge"],
            bundle,
            extra_meta={"traceparent": traceparent, "baggage": "tenant=acme"},
        )

    out = result.structured_content
    assert out["decision"] == "authorized"

    # Propagated to the boundary and observed by the adapter.
    tool, trace = mcp_world.observed[-1]
    assert tool == "refund.execute"
    assert trace["traceparent"] == traceparent
    assert trace["baggage"] == "tenant=acme"

    # And absent from the authorization result.
    assert set(out) == {"decision", "status", "reason", "refunded", "receipt_id"}


@pytest.mark.anyio
async def test_trace_context_cannot_influence_a_decision(mcp_world):
    """WHY: trace context is attacker-controlled. If any of it were consulted
    during authorization, baggage would become a policy input, which is
    exactly the confusion the separation exists to prevent."""
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-99", UNDER, mcp_world.agent.id)
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        result = await _execute(
            session,
            prepared["challenge"],
            bundle,
            # Baggage asserting whatever an attacker would like it to.
            extra_meta={"baggage": "tenant=acme,authorized=true,amount=1000000"},
        )

    out = result.structured_content
    assert out["decision"] == "denied"  # wrong resource, and baggage changes nothing
    assert out["status"] == "constraint_denied"


@pytest.mark.anyio
async def test_the_result_returns_a_receipt_id_and_no_proof_material(mcp_world):
    """WHY: the caller learns the outcome and a handle to the audit record.
    Echoing the receipt or any proof material back through the transport would
    put authorization-sensitive bytes somewhere they do not need to be."""
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-1", UNDER)

    assert out["receipt_id"] == mcp_world.service.receipt_ids[0]
    assert set(out) == {"decision", "status", "reason", "refunded", "receipt_id"}
    body = str(out).lower()
    for leak in ("signature", "ml_dsa", "ed25519", "private", "cert_id", "bundle"):
        assert leak not in body


# ---------------------------------------------------------------------------
# Unknown tools
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_unknown_tool_is_refused_at_the_server(mcp_world):
    """WHY: the server default-denies unknown tools on its own. OpenShell
    denying them at the runtime boundary is a second, independent control, and
    the reference should not depend on either one alone."""
    async with _session(mcp_world.url) as session:
        result = await session.call_tool("refund.approve_anything", {})

    assert result.is_error
    assert mcp_world.service.refunded_total == 0.0


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---------------------------------------------------------------------------
# Envelope sizing: post-quantum proofs are large, and that is an integration
# consideration rather than a footnote
# ---------------------------------------------------------------------------


def _chain(world, depth):
    """A delegation chain of `depth` certificates, [leaf, ..., root]."""
    now = int(time.time())
    chain = [world.cert]
    issuer, issuer_priv = world.agent, world.agent_priv
    for i in range(depth - 1):
        sub, sub_priv = new_agent(f"sub-{i}")
        chain.insert(
            0,
            sign_cert(
                issuer_id=issuer.id,
                issuer_pub=issuer.public_key,
                issuer_priv=issuer_priv,
                subject_id=sub.id,
                subject_pub=sub.public_key,
                scope=[SCOPE_PAYMENTS_SEND],
                constraints=[],
                issued_at=now - 30,
                expires_at=now + DAY,
            ),
        )
        issuer, issuer_priv = sub, sub_priv
    return chain, issuer, issuer_priv


@pytest.mark.anyio
@pytest.mark.parametrize("depth", [1, 2, 4, 8], ids=lambda d: f"depth{d}")
async def test_envelope_size_is_measured_and_bounded(mcp_world, depth, capsys):
    """WHY: hybrid post-quantum signatures make authorization envelopes large
    enough that transport limits become a real integration constraint rather
    than a footnote. ML-DSA-65 contributes roughly 3.3KB per signature and 2KB
    per public key, so an alpha.16 maximum-depth chain is an order of
    magnitude bigger than a bearer token.

    This records the actual numbers at each depth so the OpenShell body limit
    is chosen from measurement, not from a guess, and asserts the maximum
    depth still fits the receiver's own ceiling."""
    import json as _json

    chain, leaf, leaf_priv = _chain(mcp_world, depth)
    raw = encode_proof_bundle(
        build_bundle(
            leaf.id,
            leaf.public_key,
            leaf_priv,
            chain,
            b"\x00" * 32,
            b"\x00" * 32,
        )
    )
    encoded = base64.b64encode(raw.encode()).decode()
    envelope = _json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "refund.execute",
                "arguments": {"challenge": base64.b64encode(b"\x00" * 32).decode()},
                "_meta": {
                    PROOF_META_KEY: encoded,
                    "traceparent": "00-" + "0" * 32 + "-" + "0" * 16 + "-01",
                },
            },
        }
    )

    # Two different bounds guarding two different quantities. The receiver
    # limit applies to the decoded proof; the OpenShell limit applies to the
    # whole MCP envelope. Comparing one against the other is a category error.
    receiver_margin = MAX_PROOF_BYTES - len(raw)
    openshell_margin = PROPOSED_OPENSHELL_MAX_BODY_BYTES - len(envelope)
    with capsys.disabled():
        print(
            f"\n  depth {depth}: raw proof {len(raw):,} -> b64 {len(encoded):,} "
            f"-> MCP envelope {len(envelope):,}"
            f"\n            receiver margin (decoded proof vs {MAX_PROOF_BYTES:,}): "
            f"{receiver_margin:,}"
            f"\n            OpenShell margin (envelope vs "
            f"{PROPOSED_OPENSHELL_MAX_BODY_BYTES:,}): {openshell_margin:,}"
        )

    assert receiver_margin >= 0, "maximum-depth decoded proof must fit the receiver ceiling"
    assert openshell_margin >= 0, "maximum-depth envelope must fit the proposed OpenShell limit"


@pytest.mark.anyio
async def test_a_proof_over_the_receiver_limit_is_refused(mcp_world):
    """WHY: OpenShell's transport bound protects OpenShell and the SDK's bound
    protects the HTTP layer. Neither is this service's resource-exhaustion
    protection, so it enforces its own, and refuses before any cryptographic
    work is attempted."""
    oversized = base64.b64encode(b"A" * (MAX_PROOF_BYTES + 1)).decode()
    async with _session(mcp_world.url) as session:
        prepared = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        result = await session.call_tool(
            "refund.execute",
            {"challenge": prepared["challenge"]},
            meta={PROOF_META_KEY: oversized},
        )

    assert result.is_error
    assert mcp_world.service.receipts == []
    assert mcp_world.service.refunded_total == 0.0


@pytest.mark.anyio
async def test_duplicate_meta_members_resolve_last_wins_and_still_verify(mcp_world):
    """WHY: documents inherited parser behaviour rather than claiming a
    property the reference does not have.

    A Python dict cannot express duplicate JSON members, so this sends raw
    JSON with the proof key present twice. The pinned MCP SDK parses with
    Python's json module, which is last-wins, so the second value is used and
    the first is discarded. Duplicates are NOT rejected. The reference emits
    canonical unique-key JSON; this test exists so that a future SDK change to
    first-wins or to outright rejection is noticed rather than assumed.

    A duplicate proof member is not itself a policy bypass. A runtime policy
    layer does not authorize proof semantics: it decides destination, method,
    and tool name, and the receiver verifies whichever proof reaches it
    against its own challenge, session context, operation context, trust root,
    and constraints. Showing the policy layer proof A while the server uses
    proof B changes nothing the policy layer was deciding.

    The dangerous cross-parser surface is the fields a policy layer *does*
    use: the JSON-RPC method, params.name, and the mcp-method / mcp-name
    headers. If a request could be admitted under one tool identity and
    dispatched under another, the policy decision would be about a different
    call than the one that runs. Header/body agreement is pinned in a separate
    test; the duplicate-member variants of those fields belong to the
    OpenShell matrix and are explicitly not settled here."""
    import httpx2 as httpx

    envelope_meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }

    def _decode(response):
        body = response.text
        return json.loads(body.split("data: ", 1)[1] if "data: " in body else body)

    with httpx.Client() as client:
        init = client.post(
            mcp_world.url,
            headers={**headers, "mcp-method": "initialize"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "dup-probe", "version": "1"},
                },
            },
        )
        session_headers = dict(headers)
        if init.headers.get("mcp-session-id"):
            session_headers["mcp-session-id"] = init.headers["mcp-session-id"]
        client.post(
            mcp_world.url,
            headers={**session_headers, "mcp-method": "notifications/initialized"},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        prepared_raw = client.post(
            mcp_world.url,
            headers={
                **session_headers,
                "mcp-method": "tools/call",
                "mcp-name": "refund.prepare",
            },
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "refund.prepare",
                    "arguments": {
                        "order_id": "ord-1",
                        "amount": UNDER,
                        "agent_id": mcp_world.agent.id,
                    },
                    "_meta": envelope_meta,
                },
            },
        )
        prepared = json.loads(_decode(prepared_raw)["result"]["content"][0]["text"])

        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(prepared["challenge"]),
            base64.b64decode(prepared["session_context"]),
        )
        good = _proof_meta(bundle)[PROOF_META_KEY]

        # The same key twice: garbage first, the real proof second.
        raw = (
            '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
            '{"name":"refund.execute","arguments":{"challenge":"%s"},'
            '"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
            '"io.modelcontextprotocol/clientCapabilities":{},'
            '"%s":"GARBAGE","%s":"%s"}}}'
            % (prepared["challenge"], PROOF_META_KEY, PROOF_META_KEY, good)
        )
        executed = client.post(
            mcp_world.url,
            headers={
                **session_headers,
                "mcp-method": "tools/call",
                "mcp-name": "refund.execute",
            },
            content=raw.encode(),
        )

    result = _decode(executed)["result"]
    assert result.get("isError") is not True, "last-wins: the second (valid) proof was used"
    assert json.loads(result["content"][0]["text"])["decision"] == "authorized"

    # A parser probe must not be able to conceal duplicate execution.
    assert mcp_world.service.refunded_total == UNDER  # exactly one refund
    assert len(mcp_world.service.receipts) == 1  # exactly one receipt
    assert verify_verification_receipt(mcp_world.service.receipts[0]) is None
    assert mcp_world.service.internal_errors == 0


# ---------------------------------------------------------------------------
# Observability must never be able to change what the caller sees
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_a_failing_observer_cannot_undo_or_obscure_an_executed_refund(mcp_world):
    """WHY: this is a post-action correctness property, and it was a real bug.

    The observability callback runs after the receiver has already verified,
    decided, moved money, and signed a receipt. An unisolated observer that
    raised turned that executed refund into an MCP error, and leaked its own
    exception text to the caller. A caller seeing an error after the action
    succeeded may reasonably retry, and pay twice.

    Observability is allowed to fail. It is not allowed to manufacture that
    ambiguity, and it is not allowed to speak to the caller."""
    secret = "OBSERVER_INTERNAL_DETAIL_9f3a"

    def exploding_observer(tool, trace):
        raise RuntimeError(secret)

    principal, principal_priv = new_principal()
    agent, agent_priv = new_agent("obs-agent")
    now = int(time.time())
    cert = sign_cert(
        issuer_id=principal.id,
        issuer_pub=principal.public_key,
        issuer_priv=principal_priv,
        subject_id=agent.id,
        subject_pub=agent.public_key,
        scope=[SCOPE_PAYMENTS_SEND],
        constraints=[Constraint(type="max_amount", max_amount=LIMIT, currency="USD")],
        issued_at=now - 60,
        expires_at=now + DAY,
    )
    service = RefundService(trust_root=principal.public_key)
    port = _free_port()
    app = build_server(service, observe=exploding_observer).streamable_http_app(
        json_response=True
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    try:
        url = f"http://127.0.0.1:{port}/mcp"
        async with _session(url) as session:
            prepared = await _prepare(session, "ord-1", UNDER, agent.id)
            bundle = build_bundle(
                agent.id,
                agent.public_key,
                agent_priv,
                [cert],
                base64.b64decode(prepared["challenge"]),
                base64.b64decode(prepared["session_context"]),
            )
            result = await _execute(session, prepared["challenge"], bundle)
            # And the same challenge again, to be sure the failure did not
            # leave the pending record in a state that permits a second refund.
            replay = await _execute(session, prepared["challenge"], bundle)
    finally:
        server.should_exit = True
        thread.join(timeout=10)

    out = result.structured_content
    assert result.is_error is not True
    assert out["decision"] == "authorized"
    assert out["receipt_id"] == service.receipt_ids[0]
    assert secret not in str(out)
    assert secret not in str(result.content)

    assert service.refunded_total == UNDER  # exactly one refund
    assert len(service.receipts) == 1  # exactly one receipt
    assert service.observation_failures == 2  # both observations lost, and counted
    assert replay.structured_content["decision"] == "denied"


# ---------------------------------------------------------------------------
# The challenge is structurally validated before it is used to look anything up
# ---------------------------------------------------------------------------


@pytest.mark.anyio
@pytest.mark.parametrize(
    "raw,label",
    [
        (b"", "empty"),
        (b"\x00" * 31, "31_bytes"),
        (b"\x00" * 33, "33_bytes"),
        (b"\x00" * 4096, "large_valid_base64"),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
async def test_wrong_length_challenges_are_refused(mcp_world, raw, label):
    """WHY: a well-formed base64 string of the wrong length is not a challenge.
    The transport bound stops unbounded allocation, but structural validation
    is what stops a wrong-shaped value from reaching the receiver's lookup at
    all. None of these may create a receipt or disturb a legitimate pending
    request."""
    async with _session(mcp_world.url) as session:
        legitimate = await _prepare(session, "ord-1", UNDER, mcp_world.agent.id)
        bundle = build_bundle(
            mcp_world.agent.id,
            mcp_world.agent.public_key,
            mcp_world.agent_priv,
            [mcp_world.cert],
            base64.b64decode(legitimate["challenge"]),
            base64.b64decode(legitimate["session_context"]),
        )
        bad = await session.call_tool(
            "refund.execute",
            {"challenge": base64.b64encode(raw).decode()},
            meta=_proof_meta(bundle),
        )
        assert bad.is_error
        assert mcp_world.service.receipts == []

        # The legitimate holder is unaffected.
        good = await _execute(session, legitimate["challenge"], bundle)

    assert good.structured_content["decision"] == "authorized"


@pytest.mark.anyio
async def test_a_correct_length_challenge_is_accepted(mcp_world):
    """WHY: the counterpart. Length validation must not reject the real thing."""
    async with _session(mcp_world.url) as session:
        out = await _full_refund(mcp_world, session, "ord-1", UNDER)

    assert out["decision"] == "authorized"


# ---------------------------------------------------------------------------
# Header/body agreement, which the SDK enforces and a policy layer will rely on
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_header_and_body_must_name_the_same_method_and_tool(mcp_world):
    """WHY: a policy layer in front of this server may read the mcp-method and
    mcp-name headers rather than parse the body. If a request could be admitted
    under one identity and dispatched under another, that is request smuggling,
    and the policy layer's decision would be about a different call than the
    one that runs.

    The pinned SDK rejects header/body disagreement itself. This pins that
    behaviour so a regression is visible here rather than discovered at a
    policy boundary. It does not prove anything about OpenShell, which is
    tested separately."""
    import httpx2 as httpx

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
    }
    envelope = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    }

    def _decode(response):
        body = response.text
        return json.loads(body.split("data: ", 1)[1] if "data: " in body else body)

    with httpx.Client() as client:
        init = client.post(
            mcp_world.url,
            headers={**headers, "mcp-method": "initialize"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "hdr-probe", "version": "1"},
                },
            },
        )
        session_headers = dict(headers)
        if init.headers.get("mcp-session-id"):
            session_headers["mcp-session-id"] = init.headers["mcp-session-id"]
        client.post(
            mcp_world.url,
            headers={**session_headers, "mcp-method": "notifications/initialized"},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )

        # Header names one tool, body names another.
        mismatched = client.post(
            mcp_world.url,
            headers={
                **session_headers,
                "mcp-method": "tools/call",
                "mcp-name": "refund.prepare",
            },
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "refund.execute",
                    "arguments": {"challenge": base64.b64encode(b"\x00" * 32).decode()},
                    "_meta": envelope,
                },
            },
        )

    payload = _decode(mismatched)
    assert "error" in payload, "header/body disagreement must not be dispatched"
    assert mcp_world.service.receipts == []
    assert mcp_world.service.refunded_total == 0.0
