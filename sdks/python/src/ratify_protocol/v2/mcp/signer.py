"""In-process client of the hosted Verify MCP endpoint: one proof per tool call.

The signer configuration file is the console's client configuration plus a
``key`` reference (OS credential store or a 0600 file). Each tool call makes
two HTTPS round trips to the pinned endpoint: ``POST /challenge``, then the
``tools/call`` with the proof in ``params._meta``."""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .._version import __version__
from ..context_v2 import background
from ..signing_v2 import key_id_v2, public_key_of
from ..types import HybridPrivateKey
from . import binding, keys
from ._files import read_private_file
from .config import ClientConfig, parse_client_config
from .errors import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    ChallengeRefusedError,
    ConfigError,
    InvalidArgumentsError,
    InvalidConfigError,
    McpError,
    TransportError,
)
from .toolcall import new_tool_call, sign_tool_call, sign_tool_call_with_signer
from .transport import HttpsClient

log = logging.getLogger("ratify_mcp_signer")


def _request_meta() -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": binding.PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "ratify-mcp-signer", "version": __version__},
    }


@dataclass(frozen=True)
class SignerConfig:
    """The signer configuration file: the console fields and a key reference."""

    path: Optional[str]
    client: ClientConfig
    key: dict

    @classmethod
    def from_dict(cls, raw: Any, path: Optional[str] = None) -> "SignerConfig":
        if not isinstance(raw, dict):
            raise ConfigError("configuration must be a JSON object")
        if "key" not in raw:
            raise ConfigError("configuration has no key reference (run ratify-mcp-signer init first)")
        keys.validate_key_ref(raw["key"])
        try:
            client = parse_client_config(raw)
        except InvalidConfigError as exc:
            raise ConfigError(f"{exc} (run ratify-mcp-signer configure with the console's configuration)") from None
        return cls(path, client, raw["key"])

    @classmethod
    def load(cls, path: str) -> "SignerConfig":
        data = read_private_file(path, "config file")
        try:
            raw = json.loads(data)
        except ValueError:
            raise ConfigError(f"config file {path} is not valid JSON") from None
        return cls.from_dict(raw, os.path.abspath(path))


class Signer:
    """In-process client for the Verify MCP server.

    ``Signer.from_config(path)`` loads the configuration and the agent key.
    Use :meth:`call_tool`, :meth:`list_tools` and :meth:`discover`. Hosted
    JSON-RPC errors are raised as :class:`McpError` with the hosted error
    object unchanged in ``.error``."""

    def __init__(self, config: ClientConfig, *, private_key: Optional[HybridPrivateKey] = None,
                 external_signer=None, ca_file: Optional[str] = None,
                 clock: Callable[[], float] = time.time):
        if (private_key is None) == (external_signer is None):
            raise ConfigError("exactly one of private_key or external_signer is required")
        self._config = config
        self._private_key = private_key
        self._external = external_signer
        pub = external_signer.public_key_v2() if external_signer is not None else public_key_of(private_key)
        self.agent_id = key_id_v2(pub)
        if config.delegations[-1].subject_id != self.agent_id:
            raise ConfigError("the last delegation certificate is not issued to this agent key "
                              "(the connection was made for a different key)")
        self._http = HttpsClient(config.endpoint, ca_file=ca_file)
        self._clock = clock
        self._lock = threading.Lock()
        self._next_id = 0

    def __repr__(self) -> str:
        return f"Signer(agent_id={self.agent_id!r}, endpoint={self._config.endpoint!r})"

    @classmethod
    def from_config(cls, path: str, *, ca_file: Optional[str] = None,
                    clock: Callable[[], float] = time.time) -> "Signer":
        sc = SignerConfig.load(path)
        _, priv = keys.load_key(sc.key)
        return cls(sc.client, private_key=priv, ca_file=ca_file, clock=clock)

    @property
    def config(self) -> ClientConfig:
        return self._config

    def discover(self) -> dict:
        return self._rpc("server/discover", {})

    def list_tools(self, cursor: Optional[str] = None) -> dict:
        params: dict = {}
        if cursor is not None:
            if not isinstance(cursor, str):
                raise McpError(INVALID_PARAMS, "invalid_params", {"reason": "cursor must be a string"})
            params["cursor"] = cursor
        return self._rpc("tools/list", params)

    def call_tool(self, name: Any, arguments: Optional[dict] = None) -> dict:
        """Call a hosted tool. ``arguments`` is a dict (or None for ``{}``)."""
        if arguments is not None and not isinstance(arguments, dict):
            raise McpError(INVALID_PARAMS, "invalid_params", {"reason": "arguments must be an object"})
        try:
            call = new_tool_call(name, arguments)
        except InvalidArgumentsError as exc:
            raise McpError(INVALID_PARAMS, "invalid_params", {"reason": str(exc)}) from None
        resp = self._post("/challenge", self._config.challenge_request(call), {})
        msg = resp.message
        if resp.status != 200:
            if isinstance(msg, dict) and isinstance(msg.get("error"), dict) and isinstance(msg["error"].get("code"), int):
                raise McpError.from_hosted(msg["error"])
            raise McpError(INTERNAL_ERROR, f"challenge request failed (HTTP {resp.status})")
        try:
            challenge = self._config.check_challenge(call.tool, json.dumps(msg), int(self._clock()))
            if self._external is not None:
                envelope = sign_tool_call_with_signer(background(), self._config, self._external, call, challenge)
            else:
                envelope = sign_tool_call(self._config, self._private_key, call, challenge)
        except ChallengeRefusedError as exc:
            raise McpError(INTERNAL_ERROR, "signer refused the challenge: " + str(exc)) from None
        except Exception:
            raise McpError(INTERNAL_ERROR, "could not sign the proof bundle") from None
        params = {
            "name": call.tool,
            # The canonical arguments are what the proof binds; the hosted
            # service canonicalizes this value to the same bytes.
            "arguments": json.loads(call.canonical_arguments),
            "_meta": {**_request_meta(), binding.PROOF_META_KEY: envelope.to_dict()},
        }
        return self._rpc("tools/call", params, tool=call.tool, with_meta=False)

    def _rpc(self, method: str, params: dict, *, tool: Optional[str] = None, with_meta: bool = True) -> dict:
        if with_meta:
            params = {**params, "_meta": _request_meta()}
        with self._lock:
            self._next_id += 1
            rid = self._next_id
        body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params},
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"MCP-Protocol-Version": binding.PROTOCOL_VERSION, "Mcp-Method": method}
        if tool is not None:
            headers["Mcp-Name"] = tool
        resp = self._post("/mcp", body, headers)
        msg = resp.message
        if not isinstance(msg, dict):
            raise McpError(INTERNAL_ERROR, f"hosted endpoint returned HTTP {resp.status} without a JSON-RPC message")
        if msg.get("jsonrpc") != "2.0" or msg.get("id") != rid:
            raise McpError(INTERNAL_ERROR, "hosted endpoint returned a response for another request")
        if "error" in msg:
            if not isinstance(msg["error"], dict) or not isinstance(msg["error"].get("code"), int):
                raise McpError(INTERNAL_ERROR, "hosted endpoint returned a malformed error")
            raise McpError.from_hosted(msg["error"])
        if not isinstance(msg.get("result"), dict):
            raise McpError(INTERNAL_ERROR, "hosted endpoint returned a malformed result")
        return msg["result"]

    def _post(self, path: str, body: bytes, headers: dict):
        try:
            return self._http.post(path, body, headers)
        except TransportError as exc:
            log.warning("hosted request %s failed: %s", path, exc)
            raise McpError(INTERNAL_ERROR, str(exc)) from None
