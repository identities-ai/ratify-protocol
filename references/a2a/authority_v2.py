"""Ratify Protocol v2 authority fixture and receiver for the A2A draft.

The principal's root delegates to a commander, which narrows authority to one
infrastructure specialist. Each issuer signs its own status under a separate
status key. The receiver issues challenges with the SDK issuance helper,
verifies with the v2 decision path, publishes the signed receipt, and acts
only on a released ``allowed()`` decision.

DEVELOPMENT ONLY. The claim store, receipt log, checkpoint, journal store and
challenge issuance store are the in-memory reference stores that the SDK
ships for tests (``ratify_protocol.v2.v2reference``). They are not durable and
cannot back a production verifier or a durable-issuance claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
import secrets
import threading
import time
from typing import Any, Callable

from ratify_protocol.v2 import (
    HybridPrivateKey,
    HybridPublicKey,
    background,
    error_class_of,
    generate_keypair_v2,
    key_id_v2,
    operation_context_v2_hash,
    session_context_v2_hash,
)
from ratify_protocol.v2.challenge_issuance_v2 import (
    V2ChallengeIssueRequest,
    V2ChallengeIssuer,
    load_expected_challenge_v2,
)
from ratify_protocol.v2.constraint_evaluator_v2 import (
    CONSTRAINT_MAX_COUNT_V2,
    new_constraint_evaluator_registry_v2,
    standard_max_count_evaluator_v2,
)
from ratify_protocol.v2.constraints_v2 import (
    CONSTRAINT_RECEIVER_AUDIENCE,
    CONSTRAINT_RESOURCE_PATH,
    TZDB_VERSION_V2,
    ConstraintContextV2,
    ConstraintV2,
)
from ratify_protocol.v2.context_policy_v2 import (
    VERIFY_SESSION_CONTEXT_FIELDS_V2,
    VERIFY_SESSION_CONTEXT_PROFILE_V2,
    new_v2_context_policy,
)
from ratify_protocol.v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    decode_proof_bundle_v2,
    encode_proof_bundle_v2,
    encode_revocation_list_v2,
    encode_revocation_push_v2,
    sign_delegation_cert_v2,
    sign_proof_bundle_v2,
)
from ratify_protocol.v2.release_v2 import V2_RELEASE_RELEASED, V2ReleaseConfig, release_v2_decision
from ratify_protocol.v2.scope import SCOPE_IDENTITY_DELEGATE
from ratify_protocol.v2.security_journal_v2 import configure_status_key_epoch_v2, record_security_key_role_v2
from ratify_protocol.v2.status_batch_v2 import V2StatusEvidenceBatch, V2StatusEvidenceObject
from ratify_protocol.v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol.v2.status_publisher_v2 import new_v2_status_publisher_with_key
from ratify_protocol.v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol.v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol.v2.v2reference.journal import new_journal_store
from ratify_protocol.v2.v2reference.store import Store
from ratify_protocol.v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2_STAGE_PREFLIGHT,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)


INFRA_SCOPE = "custom:infra:provision"
NODE_COUNTER = "nodes"
PROJECT_ID = "customer-project"
# Session contexts name the workspace by a canonical UUID (SPEC-v2 §2.2).
WORKSPACE_ID = "6f1c2a4e-3b7d-4e59-9a0c-2d8e5f7b1c34"
# The stable receiver identifier signed into ratify.receiver_audience. It is
# not the verifier key ID.
RECEIVER_ID = "a2a:customer-project/infra-provisioner"
OPERATION = "infra.provision"
STATUS_LIST_LIFETIME = 3600
LIST_OBJECT, PUSH_OBJECT = 3, 5

_SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def region_resource(region: str) -> str:
    return f"gcp:projects/{PROJECT_ID}/regions/{region}"


def status_policy() -> RevocationStatusPolicyV2:
    return RevocationStatusPolicyV2(
        max_list_lifetime_seconds=STATUS_LIST_LIFETIME,
        max_status_age_seconds=STATUS_LIST_LIFETIME,
        clock_skew_seconds=5,
    )


@dataclass(frozen=True)
class OperationRequest:
    request_id: str
    region: str
    instance_type: str
    count: int
    task_id: str = ""
    context_id: str = ""

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
        if bool(self.task_id) != bool(self.context_id):
            raise ValueError("task and context IDs must be supplied together")
        if len(self.task_id) > 128 or len(self.context_id) > 128:
            raise ValueError("task and context IDs must be at most 128 characters")

    def canonical_payload(self) -> bytes:
        self.validate()
        payload: dict[str, Any] = {
            "count": self.count,
            "instance_type": self.instance_type,
            "region": self.region,
            "request_id": self.request_id,
        }
        if self.task_id:
            payload["task_id"] = self.task_id
            payload["context_id"] = self.context_id
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def request_hash(self) -> bytes:
        """Hash of the receiver-constructed operation (SPEC-v2 §2.2)."""
        return operation_context_v2_hash(
            INFRA_SCOPE, OPERATION, region_resource(self.region), None,
            hashlib.sha256(self.canonical_payload()).digest(),
        )


# ---------------------------------------------------------------------------
# Issuer side: principal root, commander, specialist, and status publishers


@dataclass
class _IssuerStatus:
    """One issuer's status publisher and its durable state."""

    issuer_pub: HybridPublicKey
    status_pub: HybridPublicKey
    publisher: Any
    state: Any
    objects: list = field(default_factory=list)


@dataclass
class AuthorityFixture:
    root_id: str
    root_public_key: HybridPublicKey
    commander_id: str
    commander_public_key: HybridPublicKey
    specialist_id: str
    specialist_public_key: HybridPublicKey
    specialist_private_key: HybridPrivateKey
    delegations: list
    status: dict  # issuer ID -> _IssuerStatus

    def present(self, *, challenge: bytes, challenge_at: int, verifier_id: str,
                session_context: bytes) -> bytes:
        """Sign a receiver-issued, operation-bound challenge."""
        bundle = sign_proof_bundle_v2(ProofBundleV2(
            version=2, verifier_id=verifier_id, agent_id=self.specialist_id,
            agent_pub_key=self.specialist_public_key, delegations=self.delegations,
            challenge=challenge, challenge_at=challenge_at, session_context=session_context,
            delegation_digest=b"", challenge_sig=None,  # computed by sign_proof_bundle_v2
        ), self.specialist_private_key)
        return encode_proof_bundle_v2(bundle)

    def status_keys(self) -> dict[str, HybridPublicKey]:
        return {issuer_id: s.status_pub for issuer_id, s in self.status.items()}

    def status_objects(self) -> dict[str, list[tuple[int, bytes]]]:
        """The current signed status objects, keyed by issuer ID."""
        return {issuer_id: list(s.objects) for issuer_id, s in self.status.items()}

    def revoke(self, cert_id: str, *, at: int | None = None) -> dict[str, list[tuple[int, bytes]]]:
        """Revoke a certificate under its issuer's status key; return the
        signed push and cumulative list for distribution to receivers."""
        for cert in self.delegations:
            if cert.cert_id != cert_id:
                continue
            issuer = self.status[cert.issuer_id]
            # The publisher requires each update to be strictly later than the
            # issuer's last list, which may have been published this second.
            when = max(int(time.time()), issuer.state.updated_at + 1) if at is None else at
            publication = issuer.publisher.revoke(background(), issuer.state, [cert_id], when)
            issuer.state = publication.state
            issuer.objects = [
                (PUSH_OBJECT, encode_revocation_push_v2(publication.push)),
                (LIST_OBJECT, encode_revocation_list_v2(publication.list)),
            ]
            return self.status_objects()
        raise ValueError("unknown certificate")


def issue_authority(*, now: int | None = None, region: str = "us-central1",
                    max_nodes: int = 1, receiver_id: str = RECEIVER_ID) -> AuthorityFixture:
    """Create root -> commander -> specialist authority with signed status."""
    ctx = background()
    issued_at = int(time.time()) if now is None else now
    root_pub, root_priv = generate_keypair_v2()
    commander_pub, commander_priv = generate_keypair_v2()
    specialist_pub, specialist_priv = generate_keypair_v2()
    root_id, commander_id, specialist_id = key_id_v2(root_pub), key_id_v2(commander_pub), key_id_v2(specialist_pub)

    commander_cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id=f"commander-{secrets.token_hex(16)}",
        issuer_id=root_id, issuer_pub_key=root_pub,
        subject_id=commander_id, subject_pub_key=commander_pub,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE], constraints=[],
        issued_at=issued_at, expires_at=issued_at + 3600,
    ), root_priv)
    specialist_cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2, cert_id=f"specialist-{secrets.token_hex(16)}",
        issuer_id=commander_id, issuer_pub_key=commander_pub,
        subject_id=specialist_id, subject_pub_key=specialist_pub,
        scope=[INFRA_SCOPE],
        constraints=[
            ConstraintV2(type=CONSTRAINT_RESOURCE_PATH, resource_id=region_resource(region)),
            ConstraintV2(type=CONSTRAINT_MAX_COUNT_V2, params={"counter": NODE_COUNTER, "max": max_nodes}),
            ConstraintV2(type=CONSTRAINT_RECEIVER_AUDIENCE,
                         params={"exact_receiver_ids": [receiver_id], "trust_domain_ids": []}),
        ],
        issued_at=issued_at, expires_at=issued_at + 3600,
    ), commander_priv)

    status: dict[str, _IssuerStatus] = {}
    for issuer_pub in (root_pub, commander_pub):
        # Each issuer's operator keeps its own journal; the status key is
        # separate from the issuer key, which the publisher enforces.
        status_pub, status_priv = generate_keypair_v2()
        journal = new_journal_store()
        record_security_key_role_v2(ctx, journal, "issuer", issuer_pub)
        configure_status_key_epoch_v2(ctx, journal, key_id_v2(issuer_pub), 1, status_pub)
        publisher = new_v2_status_publisher_with_key(ctx, journal, issuer_pub, status_priv, STATUS_LIST_LIFETIME)
        genesis = publisher.genesis(ctx, issued_at)
        status[key_id_v2(issuer_pub)] = _IssuerStatus(
            issuer_pub, status_pub, publisher, genesis.state,
            [(LIST_OBJECT, encode_revocation_list_v2(genesis.list))],
        )

    return AuthorityFixture(
        root_id, root_pub, commander_id, commander_pub, specialist_id, specialist_pub,
        specialist_priv, [specialist_cert, commander_cert], status,
    )


# ---------------------------------------------------------------------------
# Receiver side


@dataclass(frozen=True)
class ChallengeGrant:
    challenge: bytes
    challenge_at: int
    expires_at: int
    session_context: bytes
    verifier_id: str
    session_inputs: dict


@dataclass(frozen=True)
class _PendingOperation:
    request: OperationRequest
    challenge: bytes
    session_context: bytes
    expected_agent_id: str
    expires_at: int


class MemoryNodeProvisioner:
    """Deterministic protected action used by the tests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.operations: dict[str, OperationRequest] = {}

    def provision(self, request: OperationRequest) -> None:
        with self._lock:
            if request.request_id in self.operations:
                raise ValueError("protected action request_id already exists")
            self.operations[request.request_id] = request


class InfrastructureReceiverV2:
    """The only component allowed to invoke the protected provisioner."""

    def __init__(
        self,
        *,
        trusted_root_id: str,
        trusted_root_public_key: HybridPublicKey,
        expected_agent_public_key: HybridPublicKey,
        status_keys: dict[str, HybridPublicKey],
        status_objects: dict[str, list[tuple[int, bytes]]],
        receiver_id: str = RECEIVER_ID,
        provisioner: Any | None = None,
        clock: Callable[[], int] = lambda: int(time.time()),
        challenge_ttl_seconds: int = 300,
        pending_capacity: int = 128,
    ) -> None:
        if not 1 <= challenge_ttl_seconds <= 300:
            raise ValueError("challenge_ttl_seconds must be 1..300")
        if pending_capacity < 1:
            raise ValueError("pending_capacity must be positive")
        if key_id_v2(trusted_root_public_key) != trusted_root_id:
            raise ValueError("trusted root ID does not match the pinned root key")
        if any(key_id_v2(key) == trusted_root_id for key in status_keys.values()):
            raise ValueError("a status key must be separate from the root key")
        self._ctx = background()
        self._clock = clock
        self.trusted_root_id = trusted_root_id
        self.trusted_root_public_key = trusted_root_public_key
        self.expected_agent_public_key = expected_agent_public_key
        self.expected_agent_id = key_id_v2(expected_agent_public_key)
        self.receiver_id = receiver_id
        verifier_pub, verifier_priv = generate_keypair_v2()
        self.verifier_public_key = verifier_pub
        self.verifier_id = key_id_v2(verifier_pub)
        self.namespace = f"a2a-receiver-{secrets.token_hex(8)}"
        self.replay_epoch = 1
        self.log_id = secrets.token_hex(16)
        now = clock()
        # TestOnly reference Part B stores: claim store, receipt log and
        # checkpoint in one object, plus the journal and issuance store.
        self.store = Store(now, 30, self.log_id, verifier_priv)
        self.issuance = TestOnlyChallengeIssuanceStore()
        self.journal = new_journal_store()
        record_security_key_role_v2(self._ctx, self.journal, "verifier", verifier_pub)
        self.status_keys = {
            issuer_id: V2StatusKeyConfig(epoch=1, key=key) for issuer_id, key in status_keys.items()
        }
        for issuer_id, key in status_keys.items():
            configure_status_key_epoch_v2(self._ctx, self.journal, issuer_id, 1, key)
        self._status_objects = {k: list(v) for k, v in status_objects.items()}
        self.evaluators = new_constraint_evaluator_registry_v2(1.0, standard_max_count_evaluator_v2())
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.provisioner = provisioner or MemoryNodeProvisioner()
        self.session_id = secrets.token_urlsafe(16)
        self._pending: dict[str, _PendingOperation] = {}
        self._max_pending = pending_capacity
        self._lock = threading.Lock()
        self.tool_invocations = 0

    # Status distribution: the issuers push signed objects; the verifier
    # checks every signature against the configured status key and applies it
    # to its journal during verification.
    def accept_status(self, objects: dict[str, list[tuple[int, bytes]]]) -> None:
        with self._lock:
            self._status_objects = {k: list(v) for k, v in objects.items()}

    def _now(self) -> int:
        now = self._clock()
        self.store.set_time(now)
        return now

    def has_pending_task(self, task_id: str) -> bool:
        now = self._clock()
        with self._lock:
            return any(p.request.task_id == task_id and p.expires_at > now for p in self._pending.values())

    def issue_challenge(self, request: OperationRequest, *, expected_agent_id: str) -> ChallengeGrant:
        """Define the operation and bind a single-use challenge to it."""
        request_hash = request.request_hash()
        if expected_agent_id != self.expected_agent_id:
            raise ValueError("expected_agent_id is not the pinned presenter")
        invocation_id = secrets.token_urlsafe(16)
        session_context = session_context_v2_hash(
            self.verifier_id, WORKSPACE_ID, expected_agent_id, self.session_id, invocation_id, request_hash,
        )
        now = self._now()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v.expires_at > now}
            if request.request_id in self._pending:
                raise ValueError("request_id already has a pending operation")
            if len(self._pending) >= self._max_pending:
                raise ValueError("receiver_pending_capacity")
            # The helper persists the record before it exposes the challenge.
            expected = V2ChallengeIssuer(clock=self.store, store=self.issuance).issue_challenge_v2(
                self._ctx, V2ChallengeIssueRequest(
                    verifier_namespace=self.namespace, replay_epoch=self.replay_epoch,
                    verifier_id=self.verifier_id, lifetime_seconds=self.challenge_ttl_seconds,
                    expected_agent_id=expected_agent_id,
                    expected_agent_public_key=self.expected_agent_public_key,
                    expected_receiver_id=self.receiver_id,
                    expected_session_context=session_context,
                ))
            self._pending[request.request_id] = _PendingOperation(
                request, expected.value, session_context, expected_agent_id, expected.expires_at,
            )
        return ChallengeGrant(
            expected.value, expected.issued_at, expected.expires_at, session_context, self.verifier_id,
            {
                "verifier_id": self.verifier_id, "workspace_id": WORKSPACE_ID,
                "agent_id": expected_agent_id, "session_id": self.session_id,
                "invocation_id": invocation_id, "request_hash": request_hash.hex(),
            },
        )

    def execute(self, request: OperationRequest, presentation: bytes | str) -> dict[str, Any]:
        """Verify, publish, release; invoke the protected tool only on allow."""
        try:
            request.validate()
        except ValueError as exc:
            return self._deny("invalid_request", str(exc))
        with self._lock:
            pending = self._pending.get(request.request_id)
        if pending is None:
            return self._deny("unknown_operation", "no pending receiver operation")
        if request != pending.request:
            return self._deny("operation_binding_failed", "request changed after challenge")
        try:
            wire = presentation.encode("utf-8") if isinstance(presentation, str) else bytes(presentation)
            bundle = decode_proof_bundle_v2(wire)
        except Exception as exc:  # noqa: BLE001 - any decode failure is a deny
            return self._deny("invalid_presentation", str(exc))
        if bundle.challenge != pending.challenge:
            return self._deny("challenge_binding_failed", "proof answers a different challenge")

        ctx = self._ctx
        now = self._now()
        try:
            expected = load_expected_challenge_v2(ctx, self.issuance, self.namespace, self.replay_epoch,
                                                  bundle.challenge)
        except Exception as exc:  # noqa: BLE001 - any lookup failure is a deny
            return self._deny("expected_challenge_unavailable", str(exc))

        def trust(_ctx, chain):
            root = chain[-1]
            if root.issuer_id == self.trusted_root_id and root.issuer_pub_key == self.trusted_root_public_key:
                return V2TrustResolution(outcome="trusted", root_key=self.trusted_root_public_key)
            return V2TrustResolution(outcome="untrusted")

        def status_evidence(_ctx, req):
            # The provider answers for one issuer at a time.
            with self._lock:
                objects = list(self._status_objects.get(req.issuer_id, []))
            return V2StatusEvidenceBatch(objects=[V2StatusEvidenceObject(object_type=t, wire=w) for t, w in objects])

        outcome = verify_proof_bundle_v2(ctx, V2VerifyRequest(
            bundle=wire, expected=expected,
            context_policy=new_v2_context_policy(
                VERIFY_SESSION_CONTEXT_PROFILE_V2, True, list(VERIFY_SESSION_CONTEXT_FIELDS_V2),
                pending.session_context),
            required_scope=INFRA_SCOPE, verifier_namespace=self.namespace, replay_epoch=self.replay_epoch,
            # The receiver's own verifier key ID; the expected challenge and
            # the proof must both name it.
            verifier_id=self.verifier_id,
            now=now, max_challenge_age_seconds=300, future_skew_seconds=5, tzdb_version=TZDB_VERSION_V2,
            # Every request input comes from the receiver's parsed operation,
            # never from the proof.
            context=ConstraintContextV2(
                has_resource=True, requested_resource_id=region_resource(request.region),
                extension_counts={NODE_COUNTER: request.count},
            ),
            constraint_evaluators=self.evaluators,
            status_keys=self.status_keys, status_policy=status_policy(),
        ), V2VerifyCallbacks(
            claim_store=self.store, trust=trust, status_evidence=status_evidence,
            status_journal=self.journal,
            # Exact receiver audience only; no trust-domain membership source.
            audience=lambda _ctx, _deferred, _receiver_id: [],
        ))
        if outcome.stage == V2_STAGE_PREFLIGHT:
            # Nothing was claimed: an honest pending attempt stays usable.
            return self._deny(outcome.error_class or "preflight_failed", str(outcome.error))
        # The challenge is claimed from here on, whatever the result.
        with self._lock:
            self._pending.pop(request.request_id, None)
        if outcome.stage != V2_STAGE_COMMITTED:
            return self._deny(outcome.disposition or outcome.stage, str(outcome.error or outcome.stage))

        receipt_wire = self.store.publish_v2_receipt(ctx, outcome.committed.claim_id(),
                                                     outcome.committed.receipt_body())
        result = release_v2_decision(ctx, outcome.committed, receipt_wire, V2ReleaseConfig(
            verifier_public_key=self.verifier_public_key, log_id=self.log_id,
            claim_store=self.store, checkpoint=self.store,
        ))
        if result.status != V2_RELEASE_RELEASED:
            return self._deny(f"release_{result.status}", result.reason)
        decision = result.decision
        if not decision.allowed(ctx, self.store):
            return self._deny(decision.reason(), f"released decision {decision.decision()}")
        try:
            self.provisioner.provision(request)
        except Exception as exc:  # noqa: BLE001
            return self._deny("protected_action_failed", str(exc))
        with self._lock:
            self.tool_invocations += 1
            count = self.tool_invocations
        return {
            "decision": "allow", "status": decision.identity_status(),
            "resource": region_resource(request.region), "nodes_provisioned": request.count,
            "receipt_log_id": self.log_id, "tool_invocations": count, "protected_action_invoked": True,
        }

    def _deny(self, status: str, reason: str) -> dict[str, Any]:
        return {
            "decision": "deny", "status": status, "reason": reason,
            "tool_invocations": self.tool_invocations, "protected_action_invoked": False,
        }


def receiver_for(authority: AuthorityFixture, **kwargs: Any) -> InfrastructureReceiverV2:
    """Configure a receiver with only the authority's public trust material."""
    return InfrastructureReceiverV2(
        trusted_root_id=authority.root_id, trusted_root_public_key=authority.root_public_key,
        expected_agent_public_key=authority.specialist_public_key,
        status_keys=authority.status_keys(), status_objects=authority.status_objects(), **kwargs,
    )


__all__ = [
    "INFRA_SCOPE", "RECEIVER_ID", "WORKSPACE_ID", "AuthorityFixture", "ChallengeGrant",
    "InfrastructureReceiverV2", "OperationRequest", "error_class_of", "issue_authority",
    "receiver_for", "region_resource",
]
