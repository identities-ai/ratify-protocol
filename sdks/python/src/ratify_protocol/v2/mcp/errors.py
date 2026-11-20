"""Errors of the Verify MCP signer. Messages never carry key material,
proofs or tool arguments."""
from __future__ import annotations

from typing import Any, Optional

INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
METHOD_NOT_FOUND = -32601
INVALID_REQUEST = -32600
PARSE_ERROR = -32700


class McpSignerError(ValueError):
    """Base class of the library's refusals."""


class InvalidArgumentsError(McpSignerError):
    """The tool or its arguments are outside the restricted value model; nothing is signed."""


class InvalidConfigError(McpSignerError):
    """The console client configuration is missing a field or has a field of the wrong form."""


class ChallengeRefusedError(McpSignerError):
    """The challenge does not match the pinned configuration or the call, or expires too soon."""


class InvalidConnectTokenError(McpSignerError):
    """The text is not a well-formed connect token from the console."""


class McpError(Exception):
    """A JSON-RPC error destined for the MCP client (stdio signer).

    ``error`` is the JSON-RPC error object; for hosted errors it is the object
    the hosted service returned, unchanged."""

    def __init__(self, code: int, message: str, data: Optional[Any] = None, *, hosted: bool = False):
        super().__init__(message)
        self.error: dict = {"code": code, "message": message}
        if data is not None:
            self.error["data"] = data
        self.hosted = hosted

    @classmethod
    def from_hosted(cls, error: dict) -> "McpError":
        e = cls(error.get("code", INTERNAL_ERROR), str(error.get("message", "")), hosted=True)
        e.error = error
        return e

    @property
    def code(self) -> int:
        return self.error["code"]


class ConfigError(Exception):
    """Configuration, key storage or permission problem of the stdio signer. Fatal at startup."""


class TransportError(Exception):
    """The hosted endpoint could not be reached or answered outside the contract."""
