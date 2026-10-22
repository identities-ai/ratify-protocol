"""Optional Jev tool-selection adapter.

The adapter proposes a tool. Ratify verification remains in the receiver path.
It uses the documented TypeSafe HTTP API so the reference gate does not need a
hosted-model dependency or an API key.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class JevToolDecision:
    tool_name: str
    probabilities: Mapping[str, float]
    confidence: float | None


class JevClient:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        endpoint: str = "https://api.typesafe.ai/v1/systemone",
        model: str = "jev-latest",
        timeout: float = 30.0,
    ) -> None:
        api_key = api_key or os.environ.get("TYPESAFE_API_KEY", "")
        if not api_key:
            raise ValueError("typesafe_api_key_required")
        self.api_key = api_key
        self.endpoint = endpoint
        self.model = model
        self.timeout = timeout

    def choose_tool(
        self,
        state: str | Mapping[str, Any],
        tools: Mapping[str, str],
    ) -> JevToolDecision:
        if not tools:
            raise ValueError("jev_tool_choices_required")

        payload = {
            "state": state,
            "model": self.model,
            "questions": {
                "tool": {
                    "type": "choice",
                    "instructions": "Which tool should the agent consider next?",
                    "criteria": dict(tools),
                }
            },
        }
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.load(response)
        except (HTTPError, URLError) as exc:
            raise RuntimeError("typesafe_jev_request_failed") from exc

        answer = result.get("answers", {}).get("tool", {})
        tool_name = answer.get("choice")
        if tool_name not in tools:
            raise ValueError("jev_returned_unknown_tool")

        probabilities = answer.get("probabilities", {})
        return JevToolDecision(
            tool_name=tool_name,
            probabilities={name: float(value) for name, value in probabilities.items()},
            confidence=(
                float(answer["confidence"])
                if answer.get("confidence") is not None
                else None
            ),
        )


def select_tool_with_jev(
    jev_client: Any,
    state: str | Mapping[str, Any],
    tools: Mapping[str, str],
) -> JevToolDecision:
    """Ask Jev for a proposal without granting execution authority."""

    decision = jev_client.choose_tool(state, tools)
    if decision.tool_name not in tools:
        raise ValueError("jev_returned_unknown_tool")
    return decision
