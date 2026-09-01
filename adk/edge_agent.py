"""Google ADK tool that presents Ratify authority to the edge receiver.

The model sees only the business arguments. This adapter obtains a fresh
challenge from the Linux receiver, signs the proof locally, and sends the
proof bundle to the protected action endpoint.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from ratify_protocol import encode_proof_bundle

# Reuse the already-published ADK authority fixture and its protocol handling.
from authority_reference.authority import AuthorityFixture, issue_authority


def _json_request(url: str, *, method: str = "GET", body: bytes | None = None,
                  headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = Request(url, data=body, method=method, headers=headers or {})
    try:
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        # A denied action is an expected receiver decision, not a transport
        # failure. Preserve its JSON so an ADK agent can report it accurately.
        try:
            return json.loads(error.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"allow": False, "status": "http_error", "detail": str(error)}


def build_edge_tool(authority: AuthorityFixture, *, edge_url: str) -> FunctionTool:
    edge_url = edge_url.rstrip("/")

    def actuate_edge(zone: str, duration_ms: int) -> dict[str, Any]:
        """Request one bounded physical actuation through the edge verifier."""
        scope = "physical:actuate"
        challenge = _json_request(
            f"{edge_url}/challenge",
            headers={
                "X-Sentinel-Scope": scope,
                "X-Sentinel-Zone": zone,
                "X-Sentinel-Duration-Ms": str(duration_ms),
            },
        )
        challenge_bytes = bytes.fromhex(challenge["challenge"])
        session_context = bytes.fromhex(challenge["session_context"])
        bundle = authority.present(
            challenge=challenge_bytes,
            session_context=session_context,
        )
        payload = encode_proof_bundle(bundle).encode("utf-8")
        return _json_request(
            f"{edge_url}/action",
            method="POST",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "X-Sentinel-Scope": scope,
                "X-Sentinel-Zone": zone,
                "X-Sentinel-Duration-Ms": str(duration_ms),
            },
        )

    return FunctionTool(actuate_edge)


def build_edge_agent(authority: AuthorityFixture, *, edge_url: str,
                     model: Any = "gemini-3.6-flash") -> LlmAgent:
    """Construct a real ADK agent whose tool is guarded by the edge verifier."""
    return LlmAgent(
        name="ratify_physical_edge_agent",
        description="Requests bounded physical actions through Ratify.",
        model=model,
        instruction=(
            "Use actuate_edge only for requested physical actions. Report the "
            "receiver decision exactly and never claim a denied action succeeded."
        ),
        tools=[build_edge_tool(authority, edge_url=edge_url)],
    )


def issue_edge_authority() -> AuthorityFixture:
    """Issue the same bounded authority shape used by the ADK reference."""
    return issue_authority(region="greenhouse-b", max_nodes=1)
