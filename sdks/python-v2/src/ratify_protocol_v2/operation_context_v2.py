"""Protocol v2 operation and session context construction (Go operation_context_v2.go, SPEC-v2 §2.4)."""
from __future__ import annotations

from hashlib import sha256
import re

from .errors_v2 import V2ErrorClass, classified
from .scope import validate_required_scope_v2

_OPERATION_TAG = b"ratify/operation-context/v2"
_SESSION_TAG = b"ratify/session-context/v2"
_KEY_ID = re.compile(r"^[0-9a-f]{64}$")
_PAYLOAD_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_WORKSPACE_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def _text(name: str, value: str | None) -> bytes:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} is not well-formed Unicode") from exc


def _field(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def operation_context_v2_bytes(
    required_scope: str,
    operation: str | None = None,
    resource_id: str | None = None,
    requested_path: str | None = None,
    payload_digest: bytes | None = None,
) -> bytes:
    """Build the length-prefixed operation-context preimage from SPEC-v2 §2.2."""
    validate_required_scope_v2(required_scope)
    digest = b"" if payload_digest is None else payload_digest
    if not isinstance(digest, bytes):
        raise TypeError("payload digest must be bytes or None")
    if len(digest) not in (0, 32):
        raise ValueError("payload digest must be empty or 32 bytes")
    fields = (
        _text("required scope", required_scope),
        _text("operation", operation),
        _text("resource ID", resource_id),
        _text("requested path", requested_path),
        digest,
    )
    return _OPERATION_TAG + b"".join(_field(item) for item in fields)


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def operation_context_v2_hash(
    required_scope: str,
    operation: str | None = None,
    resource_id: str | None = None,
    requested_path: str | None = None,
    payload_digest: bytes | None = None,
) -> bytes:
    """Return SHA-256 of :func:`operation_context_v2_bytes`."""
    return sha256(operation_context_v2_bytes(
        required_scope, operation, resource_id, requested_path, payload_digest
    )).digest()


@classified(V2ErrorClass.MALFORMED)
def decode_payload_digest(encoded: str | None) -> bytes | None:
    """Decode the Verify API's canonical ``sha256:<lowercase hex>`` value."""
    if encoded is None:
        return None
    if not isinstance(encoded, str):
        raise TypeError("payload digest must be a string or None")
    if not _PAYLOAD_DIGEST.fullmatch(encoded):
        raise ValueError("payload digest must be sha256: followed by 64 lowercase hexadecimal characters")
    try:
        return bytes.fromhex(encoded[7:])
    except ValueError as exc:
        raise ValueError("payload digest must be sha256: followed by 64 lowercase hexadecimal characters") from exc


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def session_context_v2_bytes(
    verifier_id: str,
    workspace_id: str,
    agent_id: str,
    session_id: str,
    invocation_id: str,
    request_hash: bytes,
) -> bytes:
    """Build the length-prefixed session-context preimage from SPEC-v2 §2.2."""
    if not _KEY_ID.fullmatch(verifier_id):
        raise ValueError("verifier ID must be 64 lowercase hexadecimal characters")
    if not _WORKSPACE_ID.fullmatch(workspace_id):
        raise ValueError("workspace ID must be a canonical lowercase UUID")
    if not _KEY_ID.fullmatch(agent_id):
        raise ValueError("agent ID must be 64 lowercase hexadecimal characters")
    if not isinstance(request_hash, bytes) or len(request_hash) != 32:
        raise ValueError("request hash must be 32 bytes")
    fields = (
        _text("verifier ID", verifier_id),
        _text("workspace ID", workspace_id),
        _text("agent ID", agent_id),
        _text("session ID", session_id),
        _text("invocation ID", invocation_id),
        request_hash,
    )
    return _SESSION_TAG + b"".join(_field(item) for item in fields)


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def session_context_v2_hash(
    verifier_id: str,
    workspace_id: str,
    agent_id: str,
    session_id: str,
    invocation_id: str,
    request_hash: bytes,
) -> bytes:
    """Return SHA-256 of :func:`session_context_v2_bytes`."""
    return sha256(session_context_v2_bytes(
        verifier_id, workspace_id, agent_id, session_id, invocation_id, request_hash
    )).digest()
