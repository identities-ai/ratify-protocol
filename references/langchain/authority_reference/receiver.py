"""Independent receiver-side challenge and verification boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import threading
import time
from typing import Any

from ratify_protocol import (
    MemoryChallengeStore,
    OperationContext,
    ProofBundle,
    SessionContextInputs,
    VerifierContext,
    VerifyOptions,
    build_session_context,
    decode_proof_bundle,
    operation_context_hash,
    verify_bundle,
)

from .authority import (
    INFRA_SCOPE,
    NODE_LIMIT_CONSTRAINT,
    VERIFIER_ID,
    WORKSPACE_ID,
    region_resource,
)


_SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


@dataclass(frozen=True)
class OperationRequest:
    request_id: str
    region: str
    instance_type: str
    count: int

    def validate(self) -> None:
        if not self.request_id or len(self.request_id) > 128:
            raise ValueError("request_id must contain 1..128 characters")
        if not _SAFE_NAME.fullmatch(self.region):
            raise ValueError("region is not a canonical deployment name")
        if not _SAFE_NAME.fullmatch(self.instance_type):
            raise ValueError("instance_type is not a canonical deployment name")
        if isinstance(self.count, bool) or not isinstance(self.count, int):
            raise ValueError("count must be an integer")
        if self.count < 1 or self.count > 1000:
            raise ValueError("count must be between 1 and 1000")

    def canonical_payload(self) -> bytes:
        self.validate()
        return json.dumps(
            {
                "count": self.count,
                "instance_type": self.instance_type,
                "region": self.region,
                "request_id": self.request_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class ChallengeGrant:
    challenge: bytes
    session_context: bytes
    expires_at: int


@dataclass(frozen=True)
class _PendingOperation:
    request: OperationRequest
    session_context: bytes
    expected_agent_id: str
    expires_at: int


class StaticRevocationProvider:
    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def revoke(self, cert_id: str) -> None:
        self._revoked.add(cert_id)

    def is_revoked(self, cert_id: str) -> tuple[bool, None]:
        return cert_id in self._revoked, None


class NodeLimitEvaluator:
    """Receiver-owned evaluator for the signed LangChain max-node profile."""

    def __init__(self, requested_count: int) -> None:
        self.requested_count = requested_count

    def evaluate(
        self, constraint: Any, cert_id: str, context: Any, now_unix: int
    ) -> tuple[bool, str | None]:
        params = constraint.params
        if not isinstance(params, dict):
            return False, "constraint_unverifiable: max_nodes params missing"
        max_nodes = params.get("max_nodes")
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
            return False, "constraint_unverifiable: max_nodes must be a positive integer"
        if self.requested_count > max_nodes:
            return False, f"requested {self.requested_count} nodes exceeds max {max_nodes}"
        return True, None


class InfrastructureReceiver:
    """The only component allowed to invoke the protected tool."""

    def __init__(self, *, trusted_root_id: str, trusted_root_public_key: Any) -> None:
        self.trusted_root_id = trusted_root_id
        self.trusted_root_public_key = trusted_root_public_key
        self.challenge_store = MemoryChallengeStore(max_size=128)
        self.revocation = StaticRevocationProvider()
        self._pending: dict[str, _PendingOperation] = {}
        self._max_pending = 128
        self._state_lock = threading.Lock()
        self.tool_invocations = 0

    def issue_challenge(
        self, request: OperationRequest, *, expected_agent_id: str
    ) -> ChallengeGrant:
        """Define the operation and bind a single-use challenge to it."""
        payload = request.canonical_payload()
        if not expected_agent_id:
            raise ValueError("expected_agent_id is required")
        now = int(time.time())
        with self._state_lock:
            self._pending = {
                key: value for key, value in self._pending.items()
                if value.expires_at > now
            }
            if request.request_id in self._pending:
                raise ValueError("request_id already has a pending operation")
            if len(self._pending) >= self._max_pending:
                raise ValueError("receiver_pending_capacity")
        operation = OperationContext(
            required_scope=INFRA_SCOPE,
            operation="infra.provision",
            resource_id=region_resource(request.region),
            payload_digest=hashlib.sha256(payload).digest(),
        )
        session_context = build_session_context(
            SessionContextInputs(
                verifier_id=VERIFIER_ID,
                workspace_id=WORKSPACE_ID,
                agent_id=expected_agent_id,
                session_id="langchain-reference",
                invocation_id=request.request_id,
                request_hash=operation_context_hash(operation),
            )
        )
        with self._state_lock:
            if request.request_id in self._pending:
                raise ValueError("request_id already has a pending operation")
            if len(self._pending) >= self._max_pending:
                raise ValueError("receiver_pending_capacity")
            try:
                challenge, expires_at = self.challenge_store.issue(session_context, 300)
            except RuntimeError as exc:
                raise ValueError("receiver_challenge_capacity") from exc
            self._pending[request.request_id] = _PendingOperation(
                request, session_context, expected_agent_id, expires_at
            )
        return ChallengeGrant(challenge, session_context, expires_at)

    def execute(
        self,
        request: OperationRequest,
        presentation: ProofBundle | str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify authority, then and only then invoke the protected tool."""
        decision_at = int(time.time()) if now is None else now
        try:
            request.validate()
        except ValueError as exc:
            return self._deny("invalid_request", str(exc))

        with self._state_lock:
            pending = self._pending.get(request.request_id)
        if pending is None:
            return self._deny("unknown_operation", "no pending receiver operation")
        if request != pending.request:
            return self._deny("operation_binding_failed", "request changed after challenge")

        try:
            bundle = decode_proof_bundle(presentation) if isinstance(presentation, str) else presentation
        except (TypeError, ValueError) as exc:
            return self._deny("invalid_presentation", str(exc))

        if bundle.agent_id != pending.expected_agent_id:
            return self._deny(
                "agent_binding_failed",
                "presentation agent does not match the challenge subject",
            )

        if not self._terminates_at_trusted_root(bundle):
            return self._deny("untrusted_root", "delegation does not terminate at the pinned root")

        result = verify_bundle(
            bundle,
            VerifyOptions(
                required_scope=INFRA_SCOPE,
                now=decision_at,
                session_context=pending.session_context,
                challenge_store=self.challenge_store,
                revocation=self.revocation,
                force_revocation_check=True,
                context=VerifierContext(
                    requested_resource_id=region_resource(request.region),
                    has_resource=True,
                ),
                constraint_evaluators={
                    NODE_LIMIT_CONSTRAINT: NodeLimitEvaluator(request.count)
                },
            ),
        )
        if not result.valid:
            return self._deny(result.identity_status, result.error_reason)

        with self._state_lock:
            self._pending.pop(request.request_id, None)
            self.tool_invocations += 1
        return {
            "decision": "allow",
            "status": result.identity_status,
            "resource": region_resource(request.region),
            "nodes_provisioned": request.count,
            "tool_invocations": self.tool_invocations,
        }

    def _terminates_at_trusted_root(self, bundle: ProofBundle) -> bool:
        if not bundle.delegations:
            return False
        root = bundle.delegations[-1]
        return (
            root.issuer_id == self.trusted_root_id
            and root.issuer_pub_key == self.trusted_root_public_key
        )

    def _deny(self, status: str, reason: str) -> dict[str, Any]:
        return {
            "decision": "deny",
            "status": status,
            "reason": reason,
            "tool_invocations": self.tool_invocations,
        }
