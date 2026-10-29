# SPDX-License-Identifier: Apache-2.0
"""MCP Streamable HTTP boundary in front of the refund receiver.

The point of this file is that it contains no authorization logic. It decodes
transport, enforces a size bound, adapts MCP to the existing receiver, and
returns whatever the receiver decided. :class:`RefundService` remains the sole
authorization decision point, unchanged.

Two tools, because the flow is two-phase and OpenShell cannot inspect tool
arguments. Explicit tool names are what make a runtime policy expressible:

    refund.prepare   the receiver parses and canonicalizes the business
                     request, records what it believes the operation is, and
                     returns its own challenge and session binding
    refund.execute   the agent proves possession; the proof travels in MCP
                     ``_meta``, and the only business field is the challenge
                     that identifies the receiver's pending record

``refund.execute`` deliberately does not re-accept the amount, tenant, order,
or currency. The pending record already holds the receiver's authoritative
values, so there is nothing for the agent to restate and therefore nothing to
substitute.

Proof carriage: ``_meta`` under ``com.ratifyprotocol/proof``.
``RequestParamsMeta`` is an open map (``extra_items=Any``) in mcp==2.0.0, and
the server reads it through the public ``Context.request_context.meta``
accessor. Trace context
travels in the same ``_meta`` under the reserved W3C keys and is kept strictly
separate from authorization: correlation is not authority.

The proof is attacker-controlled transport input, exactly like a request body.
It means nothing until the receiver checks it against a challenge the receiver
issued, a session context the receiver derived, and a trust root the receiver
configured.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Callable
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from pydantic import StrictInt
from ratify_protocol.v2.limits_v2 import MAX_PROOF_BUNDLE_BYTES_V2
from ratify_protocol.v2.protocol_v2 import decode_proof_bundle_v2

from refund_service import BadRequest, DEFAULT_TENANT, RefundService

#: Where the proof travels. Reverse-DNS, so it cannot collide with the
#: reserved ``io.modelcontextprotocol/*`` keys.
PROOF_META_KEY = "com.ratifyprotocol/proof"

#: Challenge length. v2 challenges are exactly 32 random bytes (SPEC-v2); the
#: SDK exports no constant for it, so it is named once here rather than written
#: as a literal at the point of use.
CHALLENGE_BYTES = 32

#: W3C trace context, reserved by the MCP spec (SEP-414). Propagated opaquely:
#: the adapter carries these fields to the receiving boundary without parsing
#: or validating their syntax. Nothing here is ever authorization input.
TRACEPARENT_KEY = "traceparent"
TRACESTATE_KEY = "tracestate"
BAGGAGE_KEY = "baggage"

#: Receiver-side ceiling on the **decoded proof**, which is not the same
#: quantity as any transport bound. Three independent limits apply to a call,
#: each enforced by a different component against a different thing:
#:
#:   1. MCP/HTTP request body   the SDK's ``max_request_body_size``. This
#:                              reference does not configure it, so whatever
#:                              the pinned SDK defaults to applies (4 MiB in
#:                              mcp==2.0.0). It is a library default inherited
#:                              here, not a bound this reference enforces.
#:   2. MCP envelope buffered   enforced by OpenShell
#:      for inspection          (``mcp.max_body_bytes``, default 64 KiB;
#:                              this reference proposes 256 KiB)
#:   3. Decoded proof bytes     enforced here
#:
#: The first two bound the wire envelope; this one bounds what the receiver
#: will decode and hand to a verifier. Comparing an envelope size against this
#: number is a category error, so the size tests report the two margins
#: separately.
#:
#: Protocol v2 fixes this bound in the protocol itself:
#: ``MAX_PROOF_BUNDLE_BYTES_V2`` is 128 KiB (131,072 bytes) and the maximum
#: chain depth is 8. The receiver uses exactly that value, so it refuses
#: nothing the protocol allows and admits nothing the protocol forbids. The
#: reason it is 128 KiB and not larger still holds: a base64 string is 4/3 the
#: size of its payload, so the encoded ceiling is 174,764 bytes, comfortably
#: inside the 262,144-byte envelope limit the policy proposes, and the two
#: bounds stay independently observable. The size of a maximum-depth v2 chain
#: is measured by the transport tests rather than written down here.
MAX_PROOF_BYTES = MAX_PROOF_BUNDLE_BYTES_V2

#: The envelope limit this reference proposes for an OpenShell MCP endpoint.
#: Recorded here so the size tests can report margin against the number the
#: policy will actually carry, rather than against a decoded-proof bound.
PROPOSED_OPENSHELL_MAX_BODY_BYTES = 262_144


class ProofCarriageError(BadRequest):
    """The proof metadata is unusable. Maps to a transport-level rejection.

    Subclasses BadRequest so the MCP layer and the HTTP layer classify a
    malformed presentation the same way: refused before verification, with no
    receipt and no challenge consumed.
    """


def _meta_of(ctx: Context):
    """The inbound request's ``_meta``, through the SDK's public accessor.

    ``Context.request_context.meta`` is where mcp==2.0.0 exposes it. Reading it
    through one helper keeps the SDK surface this file depends on to a single
    line, which is the line to revisit if a future release moves it.
    """
    try:
        return ctx.request_context.meta
    except (AttributeError, ValueError):
        return None


def extract_proof(ctx: Context, arguments: dict[str, Any] | None = None) -> bytes:
    """Pull the proof bundle's exact v2 wire bytes out of ``_meta``, or refuse.

    One authoritative carriage location, and only one.

    The argument scan below is defense in depth for direct invocation. Over
    MCP it is unreachable: the SDK validates tool arguments against the
    declared schema and drops anything undeclared before the handler runs, so
    an argument-borne proof is inert on the wire and a proof supplied *only*
    as an argument fails here as missing. Both paths converge on the same
    property, which is what the transport tests assert.
    """
    if arguments:
        for key in arguments:
            if "proof" in key.lower() or "ratify" in key.lower():
                raise ProofCarriageError(
                    "authorization material must travel in _meta under "
                    f"{PROOF_META_KEY}, not in tool arguments"
                )

    meta = _meta_of(ctx)
    if not meta:
        raise ProofCarriageError(f"missing {PROOF_META_KEY} in _meta")
    raw = meta.get(PROOF_META_KEY)
    if raw is None:
        raise ProofCarriageError(f"missing {PROOF_META_KEY} in _meta")
    if not isinstance(raw, str):
        raise ProofCarriageError(f"{PROOF_META_KEY} must be a base64 string")

    # Bound before decoding. A base64 string is 4/3 the size of its payload,
    # so checking the encoded length first refuses an oversized proof without
    # allocating it.
    if len(raw) > (MAX_PROOF_BYTES * 4 // 3) + 4:
        raise ProofCarriageError("authorization proof exceeds the receiver limit")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProofCarriageError(f"invalid base64 in {PROOF_META_KEY}: {exc}") from exc
    if len(decoded) > MAX_PROOF_BYTES:
        raise ProofCarriageError("authorization proof exceeds the receiver limit")

    # A strict v2 decode here classifies a malformed proof at the transport
    # boundary. The receiver decodes it again inside the verifier; the bytes,
    # not this object, are what it verifies.
    try:
        decode_proof_bundle_v2(decoded)
    except Exception as exc:  # noqa: BLE001 - every decode failure is malformed
        raise ProofCarriageError(f"malformed proof bundle: {exc}") from exc
    return decoded


def trace_context(ctx: Context) -> dict[str, str]:
    """The W3C trace keys carried on this request, for instrumentation only.

    Never consulted when deciding anything, and never returned to the caller.
    Echoing caller-supplied trace context back in a business response would
    add nothing an observability backend needs and would normalize putting
    attacker-controlled strings in an authorization result.
    """
    meta = _meta_of(ctx) or {}
    return {
        k: meta[k]
        for k in (TRACEPARENT_KEY, TRACESTATE_KEY, BAGGAGE_KEY)
        if isinstance(meta.get(k), str)
    }


def _quietly(fn, *args) -> None:
    """Call a harness hook so that nothing it does can matter."""
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 - harness hooks are never load-bearing
        pass


def _measure(fn, ctx: Context) -> None:
    """Hash the inbound proof string for a harness, without exposing it."""
    meta = _meta_of(ctx) or {}
    raw = meta.get(PROOF_META_KEY)
    if isinstance(raw, str):
        _quietly(fn, hashlib.sha256(raw.encode()).hexdigest(), len(raw))


def _observe_quietly(
    observe: Callable[[str, dict[str, str]], None] | None,
    tool: str,
    ctx: Context,
    service: RefundService,
) -> None:
    """Run the observability callback so that nothing it does can matter.

    Best effort by construction. Called only after the receiver has decided
    and acted, never while holding a receiver lock, never retried, and its
    exception text never reaches the caller. A failure here is counted on the
    service so the demo can show that observation was lost, which is the only
    thing a lost observation should cost.
    """
    if observe is None:
        return
    try:
        observe(tool, trace_context(ctx))
    except Exception:  # noqa: BLE001 - see docstring
        service.observation_failures += 1


def build_server(
    service: RefundService,
    name: str = "ratify-refund",
    observe: Callable[[str, dict[str, str]], None] | None = None,
    dispatched: Callable[[str], None] | None = None,
    measure_proof: Callable[[str, int], None] | None = None,
) -> MCPServer:
    """An MCP server whose tools delegate every decision to ``service``.

    ``dispatched`` and ``measure_proof`` are optional harness hooks. The first
    records which tool the server actually dispatched, so an external policy
    layer's decision can be compared against what ran. The second receives the
    SHA-256 and length of the inbound proof string, never the proof, so a
    harness can prove carriage fidelity byte-for-byte without writing
    authorization material anywhere. Both are best effort and are called
    outside any receiver lock.

    ``observe`` is an optional observability callback the adapter calls with ``(tool_name,
    trace_context)`` once per invocation. It exists so propagation can be
    asserted without exposing trace data in the tool result, and so a real
    exporter can be attached later. It receives no authorization material and
    cannot influence a decision.
    """
    server = MCPServer(
        name=name,
        instructions=(
            "Refunds require a principal-issued Ratify delegation. Call "
            "refund.prepare to obtain a challenge, then refund.execute with "
            f"the proof in _meta under {PROOF_META_KEY}."
        ),
    )

    @server.tool(
        name="refund.prepare",
        description=(
            "Describe an intended refund. Returns the challenge and session "
            "binding this service derived from its own parse of the request."
        ),
    )
    async def refund_prepare(
        order_id: str,
        # StrictInt: v2 amounts are integer micro-units, and a float is refused
        # rather than coerced.
        amount_micros: StrictInt,
        agent_id: str,
        agent_public_key: dict[str, str],
        currency: str = "USD",
        tenant: str = DEFAULT_TENANT,
    ) -> dict[str, Any]:
        if dispatched is not None:
            _quietly(dispatched, "refund.prepare")
        out = service.challenge(
            order_id=order_id,
            amount_micros=amount_micros,
            currency=currency,
            agent_id=agent_id,
            agent_public_key=agent_public_key,
            tenant=tenant,
        )
        # Bytes do not survive JSON. The challenge is opaque to the agent
        # either way; it is a correlation handle, not a secret.
        return {
            "challenge": base64.b64encode(out["challenge"]).decode("ascii"),
            "issued_at": out["issued_at"],
            "session_context": base64.b64encode(out["session_context"]).decode("ascii"),
            "expires_at": out["expires_at"],
            "verifier_id": out["verifier_id"],
            "parsed": out["parsed"],
        }

    @server.tool(
        name="refund.execute",
        description=(
            "Execute a prepared refund. The Ratify proof travels in _meta "
            f"under {PROOF_META_KEY}. The action is taken from this service's "
            "own pending record, never restated here."
        ),
    )
    async def refund_execute(challenge: str, ctx: Context) -> dict[str, Any]:
        if dispatched is not None:
            _quietly(dispatched, "refund.execute")
        if measure_proof is not None:
            _measure(measure_proof, ctx)
        try:
            raw_challenge = base64.b64decode(challenge, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProofCarriageError(f"invalid base64 challenge: {exc}") from exc
        # Structural validation before the value is used to look anything up.
        # The transport bound stops unbounded allocation; this stops a
        # well-formed-but-wrong-shaped value from reaching the receiver at all.
        if len(raw_challenge) != CHALLENGE_BYTES:
            raise ProofCarriageError(
                f"challenge must decode to exactly {CHALLENGE_BYTES} bytes"
            )

        proof = extract_proof(ctx, arguments={"challenge": challenge})
        decision = service.execute(challenge=raw_challenge, proof=proof)

        # The receipt identifier travels back as an outcome. The receipt
        # itself stays in receiver-side audit state, and no proof material is
        # echoed to the caller.
        result = {
            "decision": decision["decision"],
            "status": decision["status"],
            "reason": decision["reason"],
            "refunded_micros": decision["refunded_micros"],
            "receipt_id": decision["receipt_id"],
        }
        # Instrumentation only, and strictly after the fact. Deliberately not
        # part of the result: the caller already knows what it sent, and an
        # authorization response is the wrong place for attacker-controlled
        # strings.
        #
        # Isolated because the action has ALREADY happened by this point. An
        # observer that raised here would turn an executed refund into an MCP
        # error, and a caller seeing an error after money moved may retry and
        # pay twice. Observability must never be able to manufacture that
        # ambiguity, and it must never leak its own failure text to a caller.
        _observe_quietly(observe, "refund.execute", ctx, service)
        return result

    return server
