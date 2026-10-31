"""Independent receiver-side challenge and verification boundary."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, Callable

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
    ADMISSION_SCOPE,
    INFRA_SCOPE,
    NODE_LIMIT_CONSTRAINT,
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
class DualPresentation:
    """Two independently anchored bundles for one challenged operation."""

    authority: ProofBundle | str
    admission: ProofBundle | str


@dataclass(frozen=True)
class _PendingOperation:
    request: OperationRequest
    challenge: bytes
    session_context: bytes
    expected_agent_id: str
    expires_at: int


@dataclass(frozen=True)
class FederationRoute:
    """Receiver-owned exact identity route for one accepted leaf agent."""

    agent_id: str
    root_id: str
    subjects_leaf_to_root: tuple[str, ...]


class FederationPolicy:
    """Receiver-owned trust anchors and approved cross-domain agent routes."""

    def __init__(self, *, roots: dict[str, Any], routes: list[FederationRoute]) -> None:
        if not roots:
            raise ValueError("at least one trust root is required")
        if len({route.agent_id for route in routes}) != len(routes):
            raise ValueError("duplicate federation route for agent")
        for route in routes:
            if not route.subjects_leaf_to_root:
                raise ValueError("federation route must contain at least one subject")
            if route.subjects_leaf_to_root[0] != route.agent_id:
                raise ValueError("federation route leaf must match agent_id")
            if route.root_id not in roots:
                raise ValueError("federation route references an unknown root")
        self.roots = dict(roots)
        self.routes = {route.agent_id: route for route in routes}

    def validate(self, bundle: ProofBundle, expected_agent_id: str) -> str | None:
        route = self.routes.get(expected_agent_id)
        if route is None:
            return "agent has no approved federation route"
        root = bundle.delegations[-1] if bundle.delegations else None
        trusted_key = self.roots.get(route.root_id)
        if (
            root is None
            or root.issuer_id != route.root_id
            or root.issuer_pub_key != trusted_key
        ):
            return "untrusted_root: delegation does not terminate at the route's pinned root"
        subjects = tuple(cert.subject_id for cert in bundle.delegations)
        if subjects != route.subjects_leaf_to_root:
            return "delegation path is not an approved federation route"
        return None


class StaticRevocationProvider:
    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def revoke(self, cert_id: str) -> None:
        with self._lock:
            self._revoked.add(cert_id)

    def is_revoked(self, cert_id: str) -> tuple[bool, None]:
        with self._lock:
            return cert_id in self._revoked, None


class SnapshotRevocationProvider:
    """Fail-closed revocation snapshot with an explicit freshness budget."""

    def __init__(
        self,
        *,
        max_staleness_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_staleness_seconds < 0:
            raise ValueError("max_staleness_seconds must be non-negative")
        self._max_staleness = max_staleness_seconds
        self._clock = clock
        self._revoked: frozenset[str] = frozenset()
        self._published_at: int | None = None
        self._lock = threading.Lock()

    def update(self, revoked: set[str], *, published_at: int) -> None:
        if published_at > int(self._clock()) + 60:
            raise ValueError("revocation snapshot timestamp is in the future")
        with self._lock:
            if self._published_at is not None and published_at < self._published_at:
                raise ValueError("revocation snapshot rollback")
            self._revoked = frozenset(revoked)
            self._published_at = published_at

    def is_revoked(self, cert_id: str) -> tuple[bool, str | None]:
        with self._lock:
            published_at = self._published_at
            revoked = self._revoked
        if published_at is None:
            return False, "revocation snapshot unavailable"
        age = int(self._clock()) - published_at
        if age > self._max_staleness:
            return False, "revocation snapshot stale"
        return cert_id in revoked, None


class NodeLimitEvaluator:
    """Receiver-owned evaluator for the signed ADK max-node profile."""

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


class MemoryNodeProvisioner:
    """Deterministic protected action used by tests and the scale harness."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.operations: dict[str, OperationRequest] = {}

    def provision(self, request: OperationRequest) -> None:
        with self._lock:
            if request.request_id in self.operations:
                raise ValueError("protected action request_id already exists")
            self.operations[request.request_id] = request


class SqliteNodeProvisioner:
    """Durable local protected action with receiver-owned idempotency."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS provisioned_nodes (
                    request_id TEXT PRIMARY KEY,
                    region TEXT NOT NULL,
                    instance_type TEXT NOT NULL,
                    node_count INTEGER NOT NULL,
                    provisioned_at INTEGER NOT NULL
                )
                """
            )

    def provision(self, request: OperationRequest) -> None:
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                """
                INSERT INTO provisioned_nodes (
                    request_id, region, instance_type, node_count, provisioned_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    request.request_id,
                    request.region,
                    request.instance_type,
                    request.count,
                    int(time.time()),
                ),
            )


class InfrastructureReceiver:
    """The only component allowed to invoke the protected tool."""

    def __init__(
        self,
        *,
        trusted_root_id: str,
        trusted_root_public_key: Any,
        federation_policy: FederationPolicy | None = None,
        admission_policy: FederationPolicy | None = None,
        receiver_public_key: Any | None = None,
        workspace_id: str = WORKSPACE_ID,
        revocation: Any | None = None,
        provisioner: Any | None = None,
        challenge_ttl_seconds: int = 300,
        challenge_capacity: int = 128,
        pending_capacity: int = 128,
    ) -> None:
        if challenge_ttl_seconds < 1:
            raise ValueError("challenge_ttl_seconds must be positive")
        if challenge_capacity < 1 or pending_capacity < 1:
            raise ValueError("receiver capacities must be positive")
        self.trusted_root_id = trusted_root_id
        self.trusted_root_public_key = trusted_root_public_key
        self.federation_policy = federation_policy
        self.admission_policy = admission_policy
        self.workspace_id = workspace_id
        self.verifier_id = (
            _derive_verifier_id(receiver_public_key)
            if receiver_public_key is not None
            else _ephemeral_verifier_id()
        )
        self.challenge_store = MemoryChallengeStore(max_size=challenge_capacity)
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.revocation = revocation or StaticRevocationProvider()
        self.provisioner = provisioner or MemoryNodeProvisioner()
        self._pending: dict[str, _PendingOperation] = {}
        self._max_pending = pending_capacity
        self.session_id = secrets.token_urlsafe(16)
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
            resource_id=region_resource(request.region, self.workspace_id),
            payload_digest=hashlib.sha256(payload).digest(),
        )
        session_context = build_session_context(
            SessionContextInputs(
                verifier_id=self.verifier_id,
                workspace_id=self.workspace_id,
                agent_id=expected_agent_id,
                session_id=self.session_id,
                invocation_id=secrets.token_urlsafe(16),
                request_hash=operation_context_hash(operation),
            )
        )
        with self._state_lock:
            if request.request_id in self._pending:
                raise ValueError("request_id already has a pending operation")
            if len(self._pending) >= self._max_pending:
                raise ValueError("receiver_pending_capacity")
            try:
                challenge, expires_at = self.challenge_store.issue(
                    session_context, self.challenge_ttl_seconds
                )
            except RuntimeError as exc:
                raise ValueError("receiver_challenge_capacity") from exc
            self._pending[request.request_id] = _PendingOperation(
                request, challenge, session_context, expected_agent_id, expires_at
            )
        return ChallengeGrant(challenge, session_context, expires_at)

    def execute(
        self,
        request: OperationRequest,
        presentation: ProofBundle | str | DualPresentation,
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
            authority_presentation = (
                presentation.authority if isinstance(presentation, DualPresentation) else presentation
            )
            bundle = (
                decode_proof_bundle(authority_presentation)
                if isinstance(authority_presentation, str)
                else authority_presentation
            )
        except (TypeError, ValueError) as exc:
            return self._deny("invalid_presentation", str(exc))

        if bundle.agent_id != pending.expected_agent_id:
            return self._deny(
                "agent_binding_failed",
                "presentation agent does not match the challenge subject",
            )

        if self.federation_policy is not None:
            route_error = self.federation_policy.validate(
                bundle, pending.expected_agent_id
            )
            if route_error:
                status = (
                    "untrusted_root"
                    if route_error.startswith("untrusted_root:")
                    else "federation_route_denied"
                )
                return self._deny(status, route_error)
        elif not self._terminates_at_trusted_root(bundle):
            return self._deny("untrusted_root", "delegation does not terminate at the pinned root")

        admission_bundle = None
        if self.admission_policy is not None:
            admission_presentation = (
                presentation.admission if isinstance(presentation, DualPresentation) else None
            )
            if isinstance(admission_presentation, str):
                try:
                    admission_bundle = decode_proof_bundle(admission_presentation)
                except (TypeError, ValueError) as exc:
                    return self._deny("invalid_presentation", str(exc))
            elif isinstance(admission_presentation, ProofBundle):
                admission_bundle = admission_presentation
            if admission_bundle is None:
                return self._deny("missing_admission", "workload admission is required")
            if admission_bundle.challenge != pending.challenge:
                return self._deny("admission_binding_failed", "authority and admission use different challenges")
            if admission_bundle.agent_id != bundle.agent_id or admission_bundle.agent_pub_key != bundle.agent_pub_key:
                return self._deny("admission_binding_failed", "authority and admission identify different workers")
            admission_error = self.admission_policy.validate(admission_bundle, pending.expected_agent_id)
            if admission_error:
                return self._deny("admission_denied", admission_error)
            admission_result = verify_bundle(
                admission_bundle,
                VerifyOptions(
                    required_scope=ADMISSION_SCOPE,
                    now=decision_at,
                    session_context=pending.session_context,
                    revocation=self.revocation,
                    force_revocation_check=True,
                    context=VerifierContext(
                        has_resource=False,
                    ),
                ),
            )
            if not admission_result.valid:
                return self._deny("admission_denied", admission_result.error_reason)

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
                    requested_resource_id=region_resource(
                        request.region, self.workspace_id
                    ),
                    has_resource=True,
                ),
                constraint_evaluators={
                    NODE_LIMIT_CONSTRAINT: NodeLimitEvaluator(request.count)
                },
            ),
        )
        if not result.valid:
            # A valid presentation consumes its exact challenge before policy
            # evaluation. Remove only that consumed attempt; a malformed or
            # forged presentation must leave an honest pending attempt intact.
            if (
                bundle.challenge == pending.challenge
                # validate returns None when still usable; a non-None result
                # therefore means Ratify consumed or expired this exact attempt.
                and self.challenge_store.validate(
                    bundle.challenge, pending.session_context, decision_at
                ) is not None
            ):
                with self._state_lock:
                    self._pending.pop(request.request_id, None)
            verification_code = (
                result.error_reason.split(":", 1)[0]
                if result.error_reason
                else result.identity_status
            )
            return self._deny(
                result.identity_status,
                result.error_reason,
                verification_code=verification_code,
            )

        with self._state_lock:
            self._pending.pop(request.request_id, None)
        try:
            self.provisioner.provision(request)
        except Exception as exc:
            return self._deny("protected_action_failed", str(exc))
        with self._state_lock:
            self.tool_invocations += 1
            action_count = self.tool_invocations
        return {
            "decision": "allow",
            "status": result.identity_status,
            "resource": region_resource(request.region, self.workspace_id),
            "nodes_provisioned": request.count,
            "tool_invocations": action_count,
            "protected_action_invoked": True,
        }

    def _terminates_at_trusted_root(self, bundle: ProofBundle) -> bool:
        if not bundle.delegations:
            return False
        root = bundle.delegations[-1]
        return (
            root.issuer_id == self.trusted_root_id
            and root.issuer_pub_key == self.trusted_root_public_key
        )

    def _deny(
        self,
        status: str,
        reason: str,
        *,
        verification_code: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "decision": "deny",
            "status": status,
            "reason": reason,
            "tool_invocations": self.tool_invocations,
            "protected_action_invoked": False,
        }
        if verification_code is not None:
            result["verification_code"] = verification_code
        return result


def _derive_verifier_id(public_key: Any) -> str:
    material = bytes(public_key.ed25519) + bytes(public_key.ml_dsa_65)
    return f"ratify-verifier:{hashlib.sha256(material).hexdigest()}"


def _ephemeral_verifier_id() -> str:
    return f"ratify-verifier:ephemeral:{secrets.token_hex(16)}"
