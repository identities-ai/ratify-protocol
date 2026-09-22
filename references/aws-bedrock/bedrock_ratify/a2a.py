"""The envelope that crosses between the two agents.

Only two things travel: the request agent 1 wants performed, and the Ratify
proof of the authority behind it. No API key, no shared filesystem, no shared
process state. The transport carries the proof; it is not trusted by it.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .receiver import DirectoryRequest


@dataclass
class RequestEnvelope:
    """agent 1 -> agent 2."""

    request: DirectoryRequest
    proof_bundle: str  # canonical JSON from encode_proof_bundle

    def to_json(self) -> str:
        return json.dumps(
            {"request": asdict(self.request), "proof_bundle": self.proof_bundle},
            indent=2,
        )

    @staticmethod
    def from_json(raw: str) -> "RequestEnvelope":
        obj = json.loads(raw)
        return RequestEnvelope(
            request=DirectoryRequest(**obj["request"]),
            proof_bundle=obj["proof_bundle"],
        )


@dataclass
class ResponseEnvelope:
    """agent 2 -> agent 1."""

    allowed: bool
    reason: str
    entries: list[dict]
    receipt_hash: str
    summary: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)
