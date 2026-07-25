"""Operation-context and session-context canonical constructions
(SPEC §6.4.9).

Both are raw binary, domain-separated, and length-prefixed — NOT JSON.
Length prefixes exist because raw concatenation is ambiguous
(``"ab" || "c"`` equals ``"a" || "bc"``); domain tags exist so a hash
computed for one construction can never collide with the other.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

_OPERATION_CONTEXT_DOMAIN_TAG = b"ratify/operation-context/v1"
_SESSION_CONTEXT_DOMAIN_TAG = b"ratify/session-context/v1"


@dataclass
class OperationContext:
    """The inputs that identify one specific action a presentation
    authorizes (SPEC §6.4.9). Which fields are populated is
    deployment-defined — empty fields encode as zero-length and the
    construction stays well-defined."""

    # Scope the action requires (e.g. "files:write").
    required_scope: str = ""
    # Action/operation type (e.g. "git.push", "tool.invoke").
    operation: str = ""
    # Target resource identity.
    resource_id: str = ""
    # Path within the resource.
    requested_path: str = ""
    # Empty, or exactly 32 bytes: the SHA-256 of the canonical request
    # payload, where one exists.
    payload_digest: bytes = b""


@dataclass
class SessionContextInputs:
    """The inputs that identify the session a presentation belongs to,
    plus the ``request_hash`` binding the specific operation (SPEC
    §6.4.9). The Middleware Custody Profile (SPEC §15.2.1) requires all
    of them; other deployments populate what they have.

    ``request_hash`` must be exactly 32 bytes — the
    :func:`operation_context_hash` of the action being authorized. A
    deployment with no operation-specific inputs derives it from an
    all-empty :class:`OperationContext`. Binding the session but not the
    operation would let an intermediary attach a valid proof to the
    wrong action inside the right session."""

    # The verifier's identity (e.g. its public key ID). Including it
    # makes cross-verifier challenge forwarding detectable at the
    # cryptographic layer (SPEC §15.1).
    verifier_id: str = ""
    # The deployment's workspace/tenant identifier.
    workspace_id: str = ""
    # The presenting agent's identity.
    agent_id: str = ""
    # The session identifier.
    session_id: str = ""
    # The specific invocation within the session.
    invocation_id: str = ""
    # Exactly 32 bytes; see class docstring.
    request_hash: bytes = field(default=b"")


def _lp(data: bytes) -> bytes:
    """Big-endian uint64 length prefix followed by the bytes."""
    return struct.pack(">Q", len(data)) + data


def operation_context_bytes(ctx: OperationContext) -> bytes:
    """The SPEC §6.4.9 operation-context preimage: the domain tag
    followed by every field length-prefixed, in canonical order. Raises
    ``ValueError`` if ``payload_digest`` is neither empty nor exactly 32
    bytes."""
    if ctx.payload_digest and len(ctx.payload_digest) != 32:
        raise ValueError(
            f"payload digest must be empty or 32 bytes, got {len(ctx.payload_digest)}"
        )
    return (
        _OPERATION_CONTEXT_DOMAIN_TAG
        + _lp(ctx.required_scope.encode("utf-8"))
        + _lp(ctx.operation.encode("utf-8"))
        + _lp(ctx.resource_id.encode("utf-8"))
        + _lp(ctx.requested_path.encode("utf-8"))
        + _lp(bytes(ctx.payload_digest))
    )


def operation_context_hash(ctx: OperationContext) -> bytes:
    """The 32-byte ``request_hash``: SHA-256 over the SPEC §6.4.9
    operation-context bytes."""
    return hashlib.sha256(operation_context_bytes(ctx)).digest()


def session_context_bytes(inputs: SessionContextInputs) -> bytes:
    """The SPEC §6.4.9 session-context preimage: the domain tag followed
    by every field length-prefixed, in canonical order. Raises
    ``ValueError`` unless ``request_hash`` is exactly 32 bytes — use
    :func:`operation_context_hash` to derive it, over an all-empty
    :class:`OperationContext` when the deployment has no
    operation-specific inputs."""
    if len(inputs.request_hash) != 32:
        raise ValueError(
            f"request hash must be exactly 32 bytes, got {len(inputs.request_hash)}"
        )
    return (
        _SESSION_CONTEXT_DOMAIN_TAG
        + _lp(inputs.verifier_id.encode("utf-8"))
        + _lp(inputs.workspace_id.encode("utf-8"))
        + _lp(inputs.agent_id.encode("utf-8"))
        + _lp(inputs.session_id.encode("utf-8"))
        + _lp(inputs.invocation_id.encode("utf-8"))
        + _lp(bytes(inputs.request_hash))
    )


def build_session_context(inputs: SessionContextInputs) -> bytes:
    """The 32-byte ``session_context``: SHA-256 over the SPEC §6.4.9
    session-context bytes — what a session-bound deployment passes as
    ``VerifyOptions.session_context`` (and what the agent side includes
    in the challenge signing bytes, SPEC §6.4.2). Verification receipts
    and audit records bind this hash, never the preimage."""
    return hashlib.sha256(session_context_bytes(inputs)).digest()
