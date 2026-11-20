"""stdio MCP server: newline-delimited JSON-RPC on stdin/stdout.

stdout carries only MCP messages. Logs go to stderr and never include keys,
proofs, bundles, or tool arguments."""
from __future__ import annotations

import json
import logging
from typing import Any, BinaryIO, Optional

from .._version import __version__
from . import binding
from .errors import INTERNAL_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, McpError
from .signer import Signer

log = logging.getLogger("ratify_mcp_signer")

LEGACY_VERSION = "2025-11-25"


class StdioServer:
    def __init__(self, signer: Signer, stdin: BinaryIO, stdout: BinaryIO):
        self.signer = signer
        self.stdin = stdin
        self.stdout = stdout
        # True once a 2025-11-25 client sent initialize: results then omit
        # resultType, which that revision does not define.
        self.legacy = False

    def serve(self) -> None:
        for line in self.stdin:
            if not line.strip():
                continue
            reply = self.handle_line(line)
            if reply is not None:
                self._write(reply)

    def _write(self, msg: dict) -> None:
        data = json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.stdout.write(data + b"\n")
        self.stdout.flush()

    def handle_line(self, line: bytes) -> Optional[dict]:
        try:
            msg = loads_strict(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return _error(None, {"code": PARSE_ERROR, "message": "Parse error"})
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            rid = msg.get("id") if isinstance(msg, dict) else None
            return _error(rid if _valid_id(rid) else None, {"code": INVALID_REQUEST, "message": "Invalid Request"})
        if "id" not in msg:
            return None  # notification (notifications/initialized, cancelled, ...)
        rid = msg["id"]
        if not _valid_id(rid):
            return _error(None, {"code": INVALID_REQUEST, "message": "Invalid Request"})
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(rid, {"code": INVALID_REQUEST, "message": "params must be an object"})
        method = msg["method"]
        try:
            result = self._dispatch(method, params)
        except McpError as exc:
            log.info("%s -> error %s", _describe(method, params), exc.code)
            return _error(rid, exc.error)
        except Exception:
            log.error("%s -> internal failure", _describe(method, params))
            return _error(rid, {"code": INTERNAL_ERROR, "message": "internal error"})
        log.info("%s -> ok", _describe(method, params))
        if self.legacy and isinstance(result, dict):
            result = {k: v for k, v in result.items() if k != "resultType"}
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def _dispatch(self, method: str, params: dict) -> Any:
        if method == "initialize":
            self.legacy = True
            return {
                "protocolVersion": LEGACY_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ratify-mcp-signer", "version": __version__},
            }
        if method == "ping":
            return {}
        if method == "server/discover":
            self.legacy = False
            return self.signer.discover()
        if method == "tools/list":
            return self.signer.list_tools(params.get("cursor"))
        if method == "tools/call":
            return self.signer.call_tool(params.get("name"), params.get("arguments"))
        raise McpError(METHOD_NOT_FOUND, "Method not found")


class DuplicateKeyObject(dict):
    """A JSON object that repeated a key."""


class JsonFloat(float):
    """A JSON number written with a fraction or exponent."""


def _pairs_hook(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    return DuplicateKeyObject(pairs) if len(set(keys)) != len(keys) else dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def loads_strict(data: bytes) -> Any:
    """Parse one JSON-RPC message keeping what the argument value model needs:
    a duplicated key yields a DuplicateKeyObject and a fraction a JsonFloat,
    both of which the binding refuses."""
    return json.loads(data, object_pairs_hook=_pairs_hook, parse_float=JsonFloat,
                      parse_constant=_reject_constant)


def _valid_id(rid: Any) -> bool:
    return isinstance(rid, str) or (isinstance(rid, int) and not isinstance(rid, bool))


def _describe(method: str, params: dict) -> str:
    if method == "tools/call" and isinstance(params.get("name"), str) and binding.tool_scope(params["name"]) is not None:
        return f"tools/call {params['name']}"
    return method if method in ("initialize", "ping", "server/discover", "tools/list", "tools/call") else "unknown method"


def _error(rid: Any, error: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": error}
