# SPDX-License-Identifier: Apache-2.0
"""An MCP-speaking refund client, interface-compatible with ``RefundClient``.

This is the piece that makes one execution traverse every layer. The NOOA
presentation adapter takes any object with
``request_refund(order_id, amount_micros)``,
so swapping the direct-HTTP client for this one puts MCP Streamable HTTP, and
therefore an OpenShell MCP policy, inside the same call the agent makes.

    NOOA capability -> agent_call middleware -> this client -> MCP -> OpenShell
    -> MCP server -> RefundService -> Ratify -> receipt back up the same stack

Standard library only, apart from the Ratify v2 SDK. It runs inside an OpenShell
sandbox whose egress is restricted to the MCP endpoint by the very policy under
test, so it can reach nothing else, including any package index.

The two-phase split is the whole point and is preserved exactly:

    refund.prepare   carries the business request. The receiver parses it,
                     decides what the operation *is*, and returns its own
                     challenge and session binding.
    refund.execute   carries the proof in ``_meta`` and restates nothing but
                     the challenge. There is no amount, tenant, or order id to
                     substitute, because the receiver reads its own record.

The agent signs with a key it generated itself, in its own process. No key
material is ever carried into the sandbox from outside.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

from ratify_protocol_v2.protocol_v2 import (
    ProofBundleV2,
    encode_proof_bundle_v2,
    sign_proof_bundle_v2,
)

#: Where the proof travels. Must match mcp_server.PROOF_META_KEY.
PROOF_META_KEY = "com.ratifyprotocol/proof"

MCP_PROTOCOL_VERSION = "2026-07-28"
HTTP_TIMEOUT_SECONDS = 30

_ENV = {
    "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


#: No clock safety margin. Protocol v1 had the presenter choose
#: ``challenge_at`` from its own clock, and this client, the only presenter that
#: signs inside the sandbox, once led the receiver's clock and was refused with a
#: negative challenge age; it backdated by two seconds to compensate. In v2 the
#: presentation's ``challenge_at`` must equal the receiver's own issuance time,
#: returned by ``refund.prepare``, so the presenter's clock is never consulted.


class MCPTransportError(RuntimeError):
    """The MCP endpoint could not be reached or answered unusably.

    Distinct from a denial. A denial is a decision the receiver made and is
    returned as a normal value; this means no decision was obtained at all,
    and the two must never be conflated.
    """


class MCPRefundClient:
    """Presents delegated authority over MCP and reports the verdict.

    Decides nothing. Every field the receiver trusts comes from the receiver's
    own phase-one record, and this client cannot influence any of them after
    the challenge is issued.
    """

    def __init__(
        self,
        url: str,
        agent_id: str,
        agent_pub,
        agent_priv,
        delegations,
        tenant: str,
        *,
        prepare_tool: str = "refund.prepare",
        execute_tool: str = "refund.execute",
        trace_context: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.agent_id = agent_id
        self.agent_pub = agent_pub
        self.agent_priv = agent_priv
        self.delegations = list(delegations)
        self.tenant = tenant
        self.prepare_tool = prepare_tool
        self.execute_tool = execute_tool
        self.trace_context = dict(trace_context or {})
        self.session: str | None = None
        #: An ordered record of what crossed the boundary, for the harness.
        #: Contains no proof material: only the tool, the HTTP status, and the
        #: proof's length and hash prefix.
        self.trace: list[dict] = []

    # -- transport ---------------------------------------------------------

    def _post(self, body: dict, *, method_header: str, name_header: str | None = None):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "mcp-method": method_header,
        }
        if self.session:
            headers["mcp-session-id"] = self.session
        if name_header:
            headers["mcp-name"] = name_header
        request = urllib.request.Request(
            self.url, data=json.dumps(body).encode(), method="POST", headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                return response.status, response.read().decode(errors="replace"), dict(
                    response.headers
                )
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
        except Exception as exc:  # noqa: BLE001 - a blocked socket is a result
            return None, f"TRANSPORT_ERROR:{type(exc).__name__}:{exc}", {}

    @staticmethod
    def _decode(text: str):
        if not text:
            return {}
        try:
            return json.loads(text.split("data: ", 1)[1] if "data: " in text else text)
        except Exception:  # noqa: BLE001
            return {"_unparsed": text[:300]}

    @staticmethod
    def _tool_result(payload):
        """The tool's JSON result, or None when it answered with an error.

        A refusal comes back as ``isError`` with plain text rather than JSON.
        Returning None here and letting the caller inspect ``isError`` keeps a
        transport refusal from being read as an authorization outcome.
        """
        try:
            return json.loads(payload["result"]["content"][0]["text"])
        except Exception:  # noqa: BLE001
            return None

    def _call_tool(self, tool: str, arguments: dict, meta_extra: dict | None = None):
        body = {
            "jsonrpc": "2.0",
            "id": len(self.trace) + 10,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments,
                "_meta": {**_ENV, **self.trace_context, **(meta_extra or {})},
            },
        }
        status, text, _ = self._post(body, method_header="tools/call", name_header=tool)
        payload = self._decode(text)
        entry = {
            "tool": tool,
            "http_status": status,
            "policy_denied": isinstance(text, str) and "policy_denied" in text,
            "is_error": (
                payload.get("result", {}).get("isError")
                if isinstance(payload.get("result"), dict)
                else None
            ),
        }
        if meta_extra and PROOF_META_KEY in meta_extra:
            proof = meta_extra[PROOF_META_KEY]
            entry["proof_len"] = len(proof)
        self.trace.append(entry)
        return status, payload

    # -- handshake ---------------------------------------------------------

    def connect(self) -> None:
        """initialize, then notifications/initialized. Idempotent."""
        if self.session:
            return
        status, text, headers = self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "nooa-refund-agent", "version": "1"},
                },
            },
            method_header="initialize",
        )
        self.trace.append({"tool": "initialize", "http_status": status})
        if status != 200:
            raise MCPTransportError(f"initialize failed: http={status} {text[:200]}")
        self.session = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            method_header="notifications/initialized",
        )

    def list_tools(self) -> list[str]:
        status, text, _ = self._post(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": _ENV}},
            method_header="tools/list",
        )
        self.trace.append({"tool": "tools/list", "http_status": status})
        payload = self._decode(text)
        return sorted(
            t.get("name") for t in payload.get("result", {}).get("tools", []) or []
        )

    # -- the two phases ----------------------------------------------------

    def fetch_challenge(self, order_id: str, amount_micros: int, currency: str = "USD") -> dict:
        self.connect()
        status, payload = self._call_tool(
            self.prepare_tool,
            {
                "order_id": order_id,
                "amount_micros": amount_micros,
                "agent_id": self.agent_id,
                "agent_public_key": {
                    "ed25519": base64.b64encode(bytes(self.agent_pub.ed25519)).decode(),
                    "ml_dsa_65": base64.b64encode(bytes(self.agent_pub.ml_dsa_65)).decode(),
                },
                "currency": currency,
                "tenant": self.tenant,
            },
        )
        prepared = self._tool_result(payload)
        if status != 200 or not prepared or "challenge" not in prepared:
            raise MCPTransportError(
                f"{self.prepare_tool} did not return a challenge: http={status}"
            )
        return prepared

    def present(self, prepared: dict) -> dict:
        """Sign the receiver's challenge and present the bundle.

        The signature covers the challenge and the session context the
        *receiver* derived, so a bundle built for one request cannot be moved
        to another.
        """
        bundle = sign_proof_bundle_v2(
            ProofBundleV2(
                version=2,
                verifier_id=prepared["verifier_id"],
                agent_id=self.agent_id,
                agent_pub_key=self.agent_pub,
                delegations=list(self.delegations),
                delegation_digest=b"",  # computed by sign_proof_bundle_v2
                challenge=base64.b64decode(prepared["challenge"]),
                # The receiver's issuance time, compared exactly by the verifier.
                challenge_at=prepared["issued_at"],
                challenge_sig=None,  # computed by sign_proof_bundle_v2
                session_context=base64.b64decode(prepared["session_context"]),
            ),
            self.agent_priv,
        )
        proof = base64.b64encode(encode_proof_bundle_v2(bundle)).decode()
        status, payload = self._call_tool(
            self.execute_tool,
            # Only the challenge. No amount, tenant, order, or currency: the
            # receiver already holds its own authoritative values.
            {"challenge": prepared["challenge"]},
            {PROOF_META_KEY: proof},
        )
        decision = self._tool_result(payload)
        if decision is None:
            error = ""
            try:
                error = payload["result"]["content"][0]["text"][:200]
            except Exception:  # noqa: BLE001
                error = str(payload)[:200]
            raise MCPTransportError(f"{self.execute_tool} refused before deciding: {error}")
        return decision

    def request_refund(self, order_id: str, amount_micros: int, currency: str = "USD") -> dict:
        """The whole flow, as one call. Matches ``RefundClient.request_refund``."""
        return self.present(self.fetch_challenge(order_id, amount_micros, currency))
