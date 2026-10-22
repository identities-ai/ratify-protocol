"""Independent receiver-side challenge, verification and release boundary.

Protocol v2 (SPEC-v2 §6 and §7). The receiver issues each challenge through
the SDK issuance helper, verifies the proof, publishes the signed
verification receipt, waits for the checkpoint acknowledgement, and releases
the decision. Only a released ``allow`` that is still ``allowed()`` at the
receiver's clock can reach the protected handler.

DEVELOPMENT ONLY. The claim store, receipt log, checkpoint, challenge
issuance store and security journal are the SDK's in-memory reference stores
(``ratify_protocol_v2.v2reference``). They exist for tests and examples:
nothing survives a restart, spans processes, or provides an independent
checkpoint. A production receiver supplies durable Part B stores and an
independent checkpoint (SPEC-v2 §7).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
import secrets
import threading
import time
from typing import Any, Callable

from ratify_protocol_v2 import background, key_id_v2, session_context_v2_hash
from ratify_protocol_v2.challenge_issuance_v2 import (
    V2ChallengeIssuer,
    V2ChallengeIssueRequest,
    load_expected_challenge_v2,
)
from ratify_protocol_v2.constraint_evaluator_v2 import (
    new_constraint_evaluator_registry_v2,
    standard_max_count_evaluator_v2,
)
from ratify_protocol_v2.constraints_v2 import TZDB_VERSION_V2, ConstraintContextV2
from ratify_protocol_v2.context_policy_v2 import new_v2_context_policy
from ratify_protocol_v2.operation_context_v2 import operation_context_v2_hash
from ratify_protocol_v2.protocol_v2 import (
    ProofBundleV2,
    decode_proof_bundle_v2,
    decode_revocation_list_v2,
    decode_revocation_push_v2,
    encode_proof_bundle_v2,
)
from ratify_protocol_v2.release_v2 import (
    V2_RELEASE_RELEASED,
    V2ReleaseConfig,
    release_v2_decision,
)
from ratify_protocol_v2.security_journal_v2 import (
    apply_revocation_list_to_journal_v2,
    apply_revocation_push_to_journal_v2,
    configure_status_key_epoch_v2,
    record_security_key_role_v2,
)
from ratify_protocol_v2.signing_v2 import REVOCATION_LIST, generate_keypair_v2, public_key_of
from ratify_protocol_v2.status_batch_v2 import V2StatusEvidenceBatch
from ratify_protocol_v2.status_provenance_v2 import V2StatusKeyConfig
from ratify_protocol_v2.status_state_v2 import RevocationStatusPolicyV2
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey
from ratify_protocol_v2.v2reference.challenges import TestOnlyChallengeIssuanceStore
from ratify_protocol_v2.v2reference.journal import new_journal_store
from ratify_protocol_v2.v2reference.store import HeadOfLineBlockedError, Store
from ratify_protocol_v2.verify_v2 import (
    V2_STAGE_COMMITTED,
    V2_STAGE_PREFLIGHT,
    V2_STAGE_REPLAY,
    V2TrustResolution,
    V2VerifyCallbacks,
    V2VerifyRequest,
    verify_proof_bundle_v2,
)

from .authority import INFRA_SCOPE, NODE_COUNTER, WORKSPACE_ID, ChallengeGrant, region_resource
from .status_feed import StatusSource


NAMESPACE = "langchain-reference"
REPLAY_EPOCH = 1
OPERATION = "infra.provision"
SESSION_ID = "langchain-reference"
CONTEXT_POLICY_PROFILE = "com.ratifyprotocol.reference.langchain.session-context/v1"
CONTEXT_POLICY_FIELDS = (
    "verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash",
)
# Finite status freshness bounds; status is never current without them.
STATUS_POLICY = RevocationStatusPolicyV2(
    max_list_lifetime_seconds=86_400, max_status_age_seconds=86_400, clock_skew_seconds=5,
)

_SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_CTX = background()


@dataclass(frozen=True)
class OperationRequest:
    request_id: str
    region: str
    instance_type: str
    count: int

    def validate(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id or len(self.request_id) > 128:
            raise ValueError("request_id must contain 1..128 characters")
        if not isinstance(self.region, str) or not _SAFE_NAME.fullmatch(self.region):
            raise ValueError("region is not a canonical deployment name")
        if not isinstance(self.instance_type, str) or not _SAFE_NAME.fullmatch(self.instance_type):
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

    def request_hash(self) -> bytes:
        """SPEC-v2 §2.4 request hash of the exact operation."""
        return operation_context_v2_hash(
            INFRA_SCOPE, OPERATION, region_resource(self.region), None,
            hashlib.sha256(self.canonical_payload()).digest(),
        )


@dataclass(frozen=True)
class _PendingOperation:
    request: OperationRequest
    agent_id: str
    agent_public_key: HybridPublicKey
    session_context: bytes
    challenge: bytes
    expires_at: int


class _Deny(Exception):
    def __init__(self, status: str, reason: str, **extra: Any) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.extra = extra


# Pre-claim failures leave the challenge unconsumed.
_PREFLIGHT_STATUS = {
    "expected_agent_mismatch": "agent_binding_failed",
    "session_context_mismatch": "operation_binding_failed",
    "challenge_mismatch": "challenge_binding_failed",
    "challenge_not_fresh": "challenge_expired",
    "expected_challenge_unavailable": "unknown_challenge",
    "verifier_id_mismatch": "verifier_binding_failed",
}
# Released Protocol decisions: decision_reason -> reference status.
_REASON_STATUS = {
    "delegation_expired": "expired",
    "delegation_revoked": "revoked",
    "unauthorized": "untrusted_root",
}


class InfrastructureReceiver:
    """The only component allowed to invoke the protected tool."""

    def __init__(
        self,
        *,
        trusted_root_id: str,
        trusted_root_public_key: HybridPublicKey,
        status_keys: dict[str, HybridPublicKey],
        status_source: StatusSource,
        verifier_private_key: HybridPrivateKey | None = None,
        clock: Callable[[], int] | None = None,
        log_id: str | None = None,
    ) -> None:
        if key_id_v2(trusted_root_public_key) != trusted_root_id:
            raise ValueError("trusted root ID does not match its complete public key")
        self.trusted_root_id = trusted_root_id
        self.trusted_root_public_key = trusted_root_public_key
        self._clock = clock or (lambda: int(time.time()))
        if verifier_private_key is None:
            _, verifier_private_key = generate_keypair_v2()
        self.verifier_public_key = public_key_of(verifier_private_key)
        self.verifier_id = key_id_v2(self.verifier_public_key)
        self.log_id = log_id or secrets.token_hex(16)
        # Development-only Part B stores (see the module docstring).
        self.store = Store(self._clock(), 30, self.log_id, verifier_private_key)
        self.issuance = TestOnlyChallengeIssuanceStore()
        self.journal = new_journal_store()
        self._issuer = V2ChallengeIssuer(clock=self.store, store=self.issuance)
        self._registry = new_constraint_evaluator_registry_v2(1.0, standard_max_count_evaluator_v2())
        self._status_source = status_source
        record_security_key_role_v2(_CTX, self.journal, "verifier", self.verifier_public_key)
        record_security_key_role_v2(_CTX, self.journal, "issuer", trusted_root_public_key)
        self._status_keys = {}
        for issuer_id, key in sorted(status_keys.items()):
            configure_status_key_epoch_v2(_CTX, self.journal, issuer_id, 1, key)
            self._status_keys[issuer_id] = V2StatusKeyConfig(epoch=1, key=key)
        self._status_ingested: dict[str, tuple[bytes, ...]] = {}
        self._recorded_agents: set[str] = set()
        self._status_lock = threading.Lock()
        self._pending: dict[str, _PendingOperation] = {}
        self._max_pending = 128
        self._state_lock = threading.Lock()
        self._clock_lock = threading.Lock()
        self.tool_invocations = 0

    def issue_challenge(
        self, request: OperationRequest, *, agent_public_key: HybridPublicKey
    ) -> ChallengeGrant:
        """Define the operation and bind a single-use challenge to it.

        The SDK issuance helper persists the challenge before returning it.
        """
        request_hash = request.request_hash()
        agent_id = key_id_v2(agent_public_key)
        self._tick()
        now = self.store.now()
        with self._state_lock:
            self._pending = {
                key: value for key, value in self._pending.items() if value.expires_at > now
            }
            if request.request_id in self._pending:
                raise ValueError("request_id already has a pending operation")
            if len(self._pending) >= self._max_pending:
                raise ValueError("receiver_pending_capacity")
            self._pending[request.request_id] = _PendingOperation(
                request, agent_id, agent_public_key, b"", b"", now + 300,
            )
        try:
            with self._status_lock:
                if agent_id not in self._recorded_agents:
                    record_security_key_role_v2(_CTX, self.journal, "delegation", agent_public_key)
                    self._recorded_agents.add(agent_id)
            session_context = session_context_v2_hash(
                verifier_id=self.verifier_id, workspace_id=WORKSPACE_ID, agent_id=agent_id,
                session_id=SESSION_ID, invocation_id=request.request_id, request_hash=request_hash,
            )
            record = self._issuer.issue_challenge_v2(_CTX, V2ChallengeIssueRequest(
                verifier_namespace=NAMESPACE, replay_epoch=REPLAY_EPOCH, verifier_id=self.verifier_id,
                lifetime_seconds=300, expected_agent_id=agent_id,
                expected_agent_public_key=agent_public_key, expected_session_context=session_context,
            ))
        except Exception:
            with self._state_lock:
                self._pending.pop(request.request_id, None)
            raise
        with self._state_lock:
            self._pending[request.request_id] = _PendingOperation(
                request, agent_id, agent_public_key, session_context, record.value, record.expires_at,
            )
        return ChallengeGrant(
            record.value, record.issued_at, record.expires_at, self.verifier_id, session_context,
        )

    def execute(
        self,
        request: OperationRequest,
        presentation: ProofBundleV2 | bytes | str,
        *,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Verify and release authority, then and only then invoke the tool."""
        self._tick(now)
        try:
            request.validate()
        except ValueError as exc:
            return self._deny("invalid_request", str(exc))
        with self._state_lock:
            pending = self._pending.get(request.request_id)
        if pending is None or not pending.challenge:
            return self._deny("unknown_operation", "no pending receiver operation")
        if request != pending.request:
            return self._deny("operation_binding_failed", "request changed after challenge")
        try:
            bundle, wire = self._precheck(pending, presentation)
            decision = self._verify_and_release(pending, bundle, wire)
        except _Deny as denial:
            return self._deny(denial.status, denial.reason, **denial.extra)
        receipt = decision.receipt()
        if decision.decision() != "allow":
            reason = decision.reason()
            return self._deny(
                _REASON_STATUS.get(reason, reason), f"released Protocol decision: {reason}",
                protocol_reason=reason, receipt_sequence=receipt.sequence,
            )
        self._tick()
        if not decision.allowed(_CTX, self.store):
            return self._deny("allow_expired", "the released allow ended before the action")
        with self._state_lock:
            self.tool_invocations += 1
            count = self.tool_invocations
        return {
            "decision": "allow",
            "status": receipt.identity_status,
            "reason": "authorized",
            "resource": region_resource(request.region),
            "nodes_provisioned": request.count,
            "receipt_sequence": receipt.sequence,
            "tool_invocations": count,
        }

    def _precheck(self, pending: _PendingOperation, presentation: Any) -> tuple[ProofBundleV2, bytes]:
        """Pure, pre-claim receiver checks. Nothing here consumes a challenge."""
        try:
            if isinstance(presentation, ProofBundleV2):
                wire = encode_proof_bundle_v2(presentation)
            elif isinstance(presentation, str):
                wire = base64.b64decode(presentation.encode("ascii"), validate=True)
            elif isinstance(presentation, (bytes, bytearray)):
                wire = bytes(presentation)
            else:
                raise ValueError("presentation is missing")
            bundle = decode_proof_bundle_v2(wire)
        except Exception as exc:  # noqa: BLE001 - any decode failure denies
            raise _Deny("invalid_presentation", str(exc)[:200] or type(exc).__name__) from exc
        if bundle.agent_id != pending.agent_id or bundle.agent_pub_key != pending.agent_public_key:
            raise _Deny("agent_binding_failed", "presentation agent does not match the challenge subject")
        if bundle.challenge != pending.challenge:
            raise _Deny("challenge_binding_failed", "presentation answers a different challenge")
        root = bundle.delegations[-1] if bundle.delegations else None
        if root is None or root.issuer_id != self.trusted_root_id or root.issuer_pub_key != self.trusted_root_public_key:
            raise _Deny("untrusted_root", "delegation does not terminate at the pinned root")
        return bundle, wire

    def _verify_and_release(self, pending: _PendingOperation, bundle: ProofBundleV2, wire: bytes):
        request = pending.request

        def trust(_ctx, chain):
            # Pinned to the complete root public key, never a key ID alone.
            root = chain[-1] if chain else None
            if root is not None and root.issuer_id == self.trusted_root_id and (
                root.issuer_pub_key == self.trusted_root_public_key
            ):
                return V2TrustResolution(outcome="trusted", root_key=self.trusted_root_public_key)
            return V2TrustResolution(outcome="untrusted")

        def status_evidence(_ctx, _status_request):
            # Signed status was ingested into the journal just before this
            # verification; the result comes from that retained state.
            return V2StatusEvidenceBatch(objects=[])

        expected = load_expected_challenge_v2(_CTX, self.issuance, NAMESPACE, REPLAY_EPOCH, bundle.challenge)
        self._tick()
        self._ingest_status({cert.issuer_id for cert in bundle.delegations or []})
        outcome = verify_proof_bundle_v2(_CTX, V2VerifyRequest(
            bundle=wire,
            expected=expected,
            context_policy=new_v2_context_policy(
                CONTEXT_POLICY_PROFILE, True, list(CONTEXT_POLICY_FIELDS), pending.session_context,
            ),
            required_scope=INFRA_SCOPE,
            verifier_namespace=NAMESPACE,
            replay_epoch=REPLAY_EPOCH,
            now=self.store.now(),
            max_challenge_age_seconds=300,
            future_skew_seconds=5,
            # Resource and quantity come from the authenticated request.
            context=ConstraintContextV2(
                requested_resource_id=region_resource(request.region),
                has_resource=True,
                extension_counts={NODE_COUNTER: request.count},
            ),
            tzdb_version=TZDB_VERSION_V2,
            status_keys=self._status_keys,
            status_policy=STATUS_POLICY,
            constraint_evaluators=self._registry,
        ), V2VerifyCallbacks(
            claim_store=self.store, trust=trust, status_evidence=status_evidence,
            status_journal=self.journal,
        ))
        if outcome.stage == V2_STAGE_PREFLIGHT:
            status = _PREFLIGHT_STATUS.get(outcome.error_class, "invalid_presentation")
            raise _Deny(status, str(outcome.error)[:200], error_class=outcome.error_class)
        # From here the challenge is claimed: the attempt is terminal.
        self._finish(pending)
        if outcome.stage == V2_STAGE_REPLAY:
            raise _Deny("replay", f"challenge already claimed ({outcome.disposition})")
        if outcome.stage != V2_STAGE_COMMITTED:
            raise _Deny("evaluation_failed", str(outcome.error)[:200], error_class=outcome.error_class)
        receipt_wire = self._publish(outcome.committed)
        result = release_v2_decision(_CTX, outcome.committed, receipt_wire, V2ReleaseConfig(
            verifier_public_key=self.verifier_public_key, log_id=self.log_id,
            claim_store=self.store, checkpoint=self.store,
        ))
        if result.status != V2_RELEASE_RELEASED:
            raise _Deny("release_withheld", f"release {result.status}: {result.reason}")
        return result.decision

    def _ingest_status(self, issuer_ids: set[str]) -> None:
        """Apply any new signed status for these issuers to the journal.

        The journal authenticates each object against the configured status
        key before it changes state; a rejected object changes nothing.
        """
        with self._status_lock:
            now = self.store.now()
            for issuer_id in sorted(issuer_ids):
                config = self._status_keys.get(issuer_id)
                if config is None:
                    continue
                batch = self._status_source(issuer_id)
                marker = tuple(bytes(obj.wire) for obj in batch.objects)
                if self._status_ingested.get(issuer_id) == marker:
                    continue
                self._status_ingested[issuer_id] = marker
                for obj in batch.objects:
                    try:
                        if obj.object_type == REVOCATION_LIST:
                            apply_revocation_list_to_journal_v2(
                                _CTX, self.journal, decode_revocation_list_v2(bytes(obj.wire)),
                                issuer_id, config.epoch, config.key, STATUS_POLICY, now,
                            )
                        else:
                            apply_revocation_push_to_journal_v2(
                                _CTX, self.journal, decode_revocation_push_v2(bytes(obj.wire)),
                                issuer_id, config.epoch, config.key, STATUS_POLICY, now,
                            )
                    except Exception:  # noqa: BLE001 - rejected status never changes accepted state
                        continue

    def _publish(self, committed) -> bytes:
        """Append the signed receipt; the log is strictly sequential."""
        deadline = time.monotonic() + 10
        while True:
            try:
                return self.store.publish_v2_receipt(_CTX, committed.claim_id(), committed.receipt_body())
            except HeadOfLineBlockedError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.0005)

    def _finish(self, pending: _PendingOperation) -> None:
        with self._state_lock:
            if self._pending.get(pending.request.request_id) is pending:
                self._pending.pop(pending.request.request_id, None)

    def _tick(self, at: int | None = None) -> None:
        """Advance the reference store's authoritative clock; never backward."""
        with self._clock_lock:
            target = self._clock() if at is None else at
            if target > self.store.now():
                self.store.set_time(target)

    def _deny(self, status: str, reason: str, **extra: Any) -> dict[str, Any]:
        return {
            "decision": "deny",
            "status": status,
            "reason": reason,
            "tool_invocations": self.tool_invocations,
            **extra,
        }


def encode_presentation(bundle: ProofBundleV2) -> str:
    """Transport form: base64 of the exact v2 wire bytes."""
    return base64.b64encode(encode_proof_bundle_v2(bundle)).decode("ascii")
