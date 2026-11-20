"""The tool-call binding: tool table, argument value model, and the hashes.

Every hash is the SPEC-v2 operation or session context; this module only
decides which values go in. Shared vectors: ``testvectors/v2/mcp/binding.json``.
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any, Union

from ..operation_context_v2 import operation_context_v2_hash, session_context_v2_hash
from .errors import InvalidArgumentsError

ACTION = "mcp.tools/call"
PROOF_META_KEY = "com.ratifyprotocol/proof"
PROTOCOL_VERSION = "2026-07-28"
MIN_CHALLENGE_SECONDS_LEFT = 10
CONNECT_POSSESSION_DOMAIN = "ratify-verify-mcp/connect-possession/v1"
MAX_ARGUMENT_DEPTH = 4
MAX_SAFE_INTEGER = 2**53 - 1

#: The hosted tools and the exact custom scope each requires, in a fixed order.
TOOLS: tuple[tuple[str, str], ...] = (
    ("get_metrics", "custom:verify.metrics:read"),
    ("list_decisions", "custom:verify.decisions:read"),
    ("get_decision", "custom:verify.decisions:read"),
    ("list_events", "custom:verify.events:read"),
    ("list_agents", "custom:verify.agents:read"),
    ("list_evidence", "custom:verify.evidence:read"),
    ("get_evidence_package", "custom:verify.evidence:read"),
)
_SCOPES = dict(TOOLS)


def tool_scope(name: Any) -> str | None:
    """The scope a tool requires, or ``None`` for a tool the table does not name."""
    return _SCOPES.get(name) if isinstance(name, str) else None


def _allowed(cp: int) -> bool:
    return not (cp < 0x20 or 0x7F <= cp <= 0x9F or cp in (0x2028, 0x2029) or 0xD800 <= cp <= 0xDFFF)


class _Parser:
    """Strict JSON reader for the restricted value model (see canonical_arguments)."""

    def __init__(self, text: str):
        self.s = text
        self.i = 0

    def fail(self) -> InvalidArgumentsError:
        return InvalidArgumentsError("tool arguments are not a JSON object under the restricted value model")

    def space(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t\r\n":
            self.i += 1

    def value(self, depth: int) -> Any:
        if depth > MAX_ARGUMENT_DEPTH:
            raise self.fail()
        self.space()
        if self.i >= len(self.s):
            raise self.fail()
        c = self.s[self.i]
        if c == "{":
            self.i += 1
            obj: dict = {}
            self.space()
            if self.s.startswith("}", self.i):
                self.i += 1
                return obj
            while True:
                self.space()
                key = self.string()
                if key in obj:
                    raise self.fail()
                self.space()
                if not self.s.startswith(":", self.i):
                    raise self.fail()
                self.i += 1
                obj[key] = self.value(depth + 1)
                self.space()
                if self.s.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.s.startswith("}", self.i):
                    self.i += 1
                    return obj
                raise self.fail()
        if c == "[":
            self.i += 1
            items: list = []
            self.space()
            if self.s.startswith("]", self.i):
                self.i += 1
                return items
            while True:
                items.append(self.value(depth + 1))
                self.space()
                if self.s.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.s.startswith("]", self.i):
                    self.i += 1
                    return items
                raise self.fail()
        if c == '"':
            return self.string()
        if self.s.startswith("true", self.i):
            self.i += 4
            return True
        if self.s.startswith("false", self.i):
            self.i += 5
            return False
        if c == "-" or "0" <= c <= "9":
            return self.number()
        raise self.fail()

    def number(self) -> int:
        start = self.i
        if self.s[self.i] == "-":
            self.i += 1
        if self.i >= len(self.s):
            raise self.fail()
        if self.s[self.i] == "0":
            self.i += 1
        elif "1" <= self.s[self.i] <= "9":
            while self.i < len(self.s) and "0" <= self.s[self.i] <= "9":
                self.i += 1
        else:
            raise self.fail()
        if self.i < len(self.s) and self.s[self.i] in ".eE":
            raise self.fail()
        text = self.s[start:self.i]
        if text == "-0" or len(text) > 17:
            raise self.fail()
        n = int(text)
        if abs(n) > MAX_SAFE_INTEGER:
            raise self.fail()
        return n

    def hex4(self) -> int:
        h = self.s[self.i:self.i + 4]
        if len(h) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
            raise self.fail()
        self.i += 4
        return int(h, 16)

    def string(self) -> str:
        if not self.s.startswith('"', self.i):
            raise self.fail()
        self.i += 1
        out: list[str] = []
        while True:
            if self.i >= len(self.s):
                raise self.fail()
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                return "".join(out)
            if c == "\\":
                self.i += 1
                if self.i >= len(self.s):
                    raise self.fail()
                e = self.s[self.i]
                self.i += 1
                if e in '"\\/':
                    out.append(e)
                    continue
                if e != "u":
                    raise self.fail()
                cp = self.hex4()
                if 0xD800 <= cp <= 0xDFFF:
                    if cp >= 0xDC00 or not self.s.startswith("\\u", self.i):
                        raise self.fail()
                    self.i += 2
                    low = self.hex4()
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise self.fail()
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                if not _allowed(cp):
                    raise self.fail()
                out.append(chr(cp))
                continue
            if not _allowed(ord(c)):
                raise self.fail()
            out.append(c)
            self.i += 1


def _check_python_value(v: Any, depth: int) -> None:
    """Refuse Python values with no restricted-model JSON form before they are
    serialized (json.dumps would turn a float into a fraction and an int key
    into a string)."""
    if depth > MAX_ARGUMENT_DEPTH:
        raise InvalidArgumentsError("tool arguments are nested too deeply")
    if isinstance(v, bool) or isinstance(v, str):
        return
    if isinstance(v, int):
        return
    if isinstance(v, (list, tuple)):
        for item in v:
            _check_python_value(item, depth + 1)
        return
    if isinstance(v, dict) and type(v) is dict:
        for k, item in v.items():
            if not isinstance(k, str):
                raise InvalidArgumentsError("tool argument keys must be strings")
            _check_python_value(item, depth + 1)
        return
    raise InvalidArgumentsError("tool arguments hold a value outside the restricted value model")


def _write(v: Any, out: list[str]) -> None:
    if isinstance(v, dict):
        out.append("{")
        for n, k in enumerate(sorted(v)):
            if n:
                out.append(",")
            _write_str(k, out)
            out.append(":")
            _write(v[k], out)
        out.append("}")
    elif isinstance(v, list):
        out.append("[")
        for n, item in enumerate(v):
            if n:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(v, str):
        _write_str(v, out)
    elif isinstance(v, bool):
        out.append("true" if v else "false")
    else:
        out.append(str(v))


def _write_str(s: str, out: list[str]) -> None:
    out.append('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"')


def parse_arguments(arguments: Union[str, bytes, bytearray, dict, None]) -> dict:
    """Parse tool arguments under the restricted value model and return them as
    a dict. See :func:`canonical_arguments` for the model."""
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        _check_python_value(arguments, 0)
        try:
            arguments = json.dumps(arguments, ensure_ascii=False).encode("utf-8")
        except (UnicodeEncodeError, ValueError):
            raise InvalidArgumentsError("tool arguments are not valid UTF-8") from None
    if isinstance(arguments, (bytes, bytearray)):
        try:
            text = bytes(arguments).decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidArgumentsError("tool arguments are not valid UTF-8") from None
    elif isinstance(arguments, str):
        text = arguments
    else:
        raise InvalidArgumentsError("tool arguments must be a JSON object")
    stripped = text.strip(" \t\r\n")
    if stripped in ("", "null"):
        return {}
    p = _Parser(text)
    p.space()
    if not p.s.startswith("{", p.i):
        raise p.fail()
    value = p.value(0)
    p.space()
    if p.i != len(p.s):
        raise p.fail()
    return value


def canonical_arguments(arguments: Union[str, bytes, bytearray, dict, None]) -> bytes:
    """Canonical bytes of the tool arguments.

    ``arguments`` is the JSON text of ``params.arguments`` (str or bytes), a
    dict, or ``None``. The restricted value model allows objects with unique
    keys, strings, integers in the safe range (no fraction, exponent or
    negative zero), booleans and arrays, nested at most ``MAX_ARGUMENT_DEPTH``
    deep. Strings and keys must be valid UTF-8 without control characters
    (U+0000 to U+001F, U+007F to U+009F), U+2028, U+2029 or unpaired
    surrogates. Empty input, whitespace and ``null`` mean the empty object.

    Canonical form: keys sorted by UTF-8 bytes, no insignificant whitespace,
    only ``"`` and ``\\`` escaped, integers in decimal.
    Raises :class:`InvalidArgumentsError`."""
    out: list[str] = []
    _write(parse_arguments(arguments), out)
    return "".join(out).encode("utf-8")


def payload_digest(canonical: bytes) -> bytes:
    """SHA-256 of the canonical argument bytes."""
    return hashlib.sha256(canonical).digest()


def payload_digest_text(digest: bytes) -> str:
    """The ``sha256:<hex>`` form the challenge request carries."""
    return "sha256:" + digest.hex()


def request_hash(tool: str, connection_id: str, audience: str, digest: bytes) -> bytes:
    """The SPEC-v2 operation context of one tool call."""
    scope = tool_scope(tool)
    if scope is None:
        raise InvalidArgumentsError("unknown tool")
    return operation_context_v2_hash(
        required_scope=scope, operation=ACTION + ":" + tool, resource_id=connection_id,
        requested_path=audience, payload_digest=digest,
    )


def session_context(verifier_id: str, workspace_id: str, agent_id: str, connection_id: str,
                    invocation_id: str, req_hash: bytes) -> bytes:
    """The SPEC-v2 session context a tool-call proof signs (session = connection)."""
    return session_context_v2_hash(verifier_id, workspace_id, agent_id, connection_id, invocation_id, req_hash)


def connect_possession_context(workspace_id: str, receiver_id: str, audience: str, challenge_id: str,
                               agent_id: str) -> bytes:
    """Session context of the connect proof of possession: SHA-256 of the
    domain, then each field prefixed with its 8-byte big-endian length."""
    h = hashlib.sha256(CONNECT_POSSESSION_DOMAIN.encode())
    for field in (workspace_id, receiver_id, audience, challenge_id, agent_id):
        raw = field.encode("utf-8")
        h.update(struct.pack(">Q", len(raw)))
        h.update(raw)
    return h.digest()
