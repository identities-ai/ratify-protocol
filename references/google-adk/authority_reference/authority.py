"""Issue the bounded authorities used by the reference (Protocol v2).

The baseline root delegates to an ADK commander, who narrows authority to one
infrastructure specialist. The federation fixture adds a broker hop in a
second modeled trust domain. The dual-root fixture adds a second, independent
root that approves the same exact action for the same worker key, for the
SPEC-v2 §7.14 dual-root composition profile.

Every issuer also holds a separate status key and signs its own revocation
list through the SDK status publisher (see ``status_feed``). Private keys
never cross the receiver boundary; the receiver is configured only with
accepted public trust material.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import time
import uuid

from ratify_protocol_v2 import key_id_v2
from ratify_protocol_v2.constraint_evaluator_v2 import CONSTRAINT_MAX_COUNT_V2
from ratify_protocol_v2.constraints_v2 import CONSTRAINT_RESOURCE_PATH, ConstraintV2
from ratify_protocol_v2.protocol_v2 import (
    DelegationCertV2,
    ProofBundleV2,
    sign_delegation_cert_v2,
    sign_proof_bundle_v2,
)
from ratify_protocol_v2.scope import SCOPE_IDENTITY_DELEGATE
from ratify_protocol_v2.signing_v2 import generate_keypair_v2
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey

from .status_feed import StatusAuthority


# One exact custom scope. Protocol v2 matches it by byte equality; it is
# never a wildcard or a family (SPEC-v2 §2.4).
INFRA_SCOPE = "custom:infra:provision"
# The standard extension evaluator profile com.ratifyprotocol.max_count/v1
# (SPEC-v2 §5.2). The receiver supplies the requested quantity under this
# counter name from the authenticated request, never from the proof.
NODE_COUNTER = "nodes"
# A canonical lowercase UUID, as the v2 session context requires (§2.4).
WORKSPACE_ID = "5d7c2f4e-8a1b-4c3d-9e6f-0a1b2c3d4e5f"
# The logical project name used in resource identifiers.
PROJECT_ID = "customer-project"


@dataclass(frozen=True)
class ChallengeGrant:
    """What the receiver hands the presenter for one verification."""

    challenge: bytes
    issued_at: int
    expires_at: int
    verifier_id: str
    session_context: bytes

    def to_json(self) -> dict:
        return {
            "challenge": base64.b64encode(self.challenge).decode("ascii"),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "verifier_id": self.verifier_id,
            "session_context": base64.b64encode(self.session_context).decode("ascii"),
        }

    @classmethod
    def from_json(cls, data: dict) -> "ChallengeGrant":
        return cls(
            challenge=base64.b64decode(data["challenge"], validate=True),
            issued_at=int(data["issued_at"]),
            expires_at=int(data["expires_at"]),
            verifier_id=str(data["verifier_id"]),
            session_context=base64.b64decode(data["session_context"], validate=True),
        )


@dataclass(frozen=True)
class AuthorityFixture:
    root_id: str
    root_public_key: HybridPublicKey
    specialist_id: str
    specialist_public_key: HybridPublicKey
    specialist_private_key: HybridPrivateKey
    delegations: list[DelegationCertV2]
    status: StatusAuthority | None = None
    agent_path: tuple[str, ...] = ()
    admission_root_id: str | None = None
    admission_root_public_key: HybridPublicKey | None = None
    admission_delegations: list[DelegationCertV2] | None = None
    broker_id: str | None = None
    broker_public_key: HybridPublicKey | None = None
    broker_private_key: HybridPrivateKey | None = None
    authority_issued_at: int | None = None
    authority_expires_at: int | None = None

    def present(self, grant: ChallengeGrant) -> ProofBundleV2:
        """Sign a receiver-issued, operation-bound challenge."""
        return _present(self, self.delegations, grant)

    def present_admission(self, grant: ChallengeGrant) -> ProofBundleV2:
        """Present the second root's approval with the same worker key.

        Under the dual-root profile this answers its own challenge, distinct
        from the authority challenge (SPEC-v2 §7.14 step 3).
        """
        if not self.admission_delegations:
            raise ValueError("fixture has no admission chain")
        return _present(self, self.admission_delegations, grant)

    def narrow_worker_authority(
        self, *, region: str, max_nodes: int, now: int | None = None
    ) -> "AuthorityFixture":
        """Mint a fresh worker certificate at broker decision time.

        The broker can sign anything; it cannot widen what the chain above it
        allows. The receiver evaluates every certificate's constraints for
        the same request, so a widened leaf is denied.
        """
        if not self.broker_id or not self.broker_public_key or not self.broker_private_key:
            raise ValueError("fixture has no runtime broker issuer")
        issued_at = int(time.time()) if now is None else now
        expires_at = min(self.authority_expires_at or issued_at + 3600, issued_at + 300)
        cert = sign_delegation_cert_v2(DelegationCertV2(
            version=2,
            cert_id=f"runtime-worker-{uuid.uuid4().hex}",
            issuer_id=self.broker_id,
            issuer_pub_key=self.broker_public_key,
            subject_id=self.specialist_id,
            subject_pub_key=self.specialist_public_key,
            scope=[INFRA_SCOPE],
            constraints=bounds(region, max_nodes),
            issued_at=issued_at,
            expires_at=expires_at,
        ), self.broker_private_key)
        return replace(
            self,
            delegations=[cert, *self.delegations[1:]],
            agent_path=(self.specialist_id, *self.agent_path[1:]),
        )


def _present(
    fixture: AuthorityFixture, chain: list[DelegationCertV2], grant: ChallengeGrant
) -> ProofBundleV2:
    return sign_proof_bundle_v2(ProofBundleV2(
        version=2,
        verifier_id=grant.verifier_id,
        agent_id=fixture.specialist_id,
        agent_pub_key=fixture.specialist_public_key,
        delegations=list(chain),
        delegation_digest=b"",  # computed by sign_proof_bundle_v2
        challenge=grant.challenge,
        challenge_at=grant.issued_at,
        challenge_sig=None,  # computed by sign_proof_bundle_v2
        session_context=grant.session_context,
    ), fixture.specialist_private_key)


def bounds(region: str, max_nodes: int) -> list[ConstraintV2]:
    """The signed per-action ceiling: one region and a node count."""
    return [
        ConstraintV2(type=CONSTRAINT_RESOURCE_PATH, resource_id=region_resource(region)),
        ConstraintV2(
            type=CONSTRAINT_MAX_COUNT_V2,
            params={"counter": NODE_COUNTER, "max": max_nodes},
        ),
    ]


def _keys() -> tuple[str, HybridPublicKey, HybridPrivateKey]:
    public, private = generate_keypair_v2()
    return key_id_v2(public), public, private


def _delegate(
    *,
    cert_id: str,
    issuer: tuple[str, HybridPublicKey, HybridPrivateKey],
    subject: tuple[str, HybridPublicKey, HybridPrivateKey],
    scope: list[str],
    constraints: list[ConstraintV2],
    issued_at: int,
    expires_at: int,
) -> DelegationCertV2:
    return sign_delegation_cert_v2(DelegationCertV2(
        version=2,
        cert_id=cert_id,
        issuer_id=issuer[0],
        issuer_pub_key=issuer[1],
        subject_id=subject[0],
        subject_pub_key=subject[1],
        scope=scope,
        constraints=constraints,
        issued_at=issued_at,
        expires_at=expires_at,
    ), issuer[2])


def _window(now: int | None, expires_at: int | None) -> tuple[int, int]:
    issued_at = int(time.time()) if now is None else now
    return issued_at, issued_at + 3600 if expires_at is None else expires_at


def issue_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
    status_lifetime_seconds: int = 3600,
) -> AuthorityFixture:
    """Create root -> commander -> specialist authority.

    Region is a ``resource_path`` constraint on a logical resource. Node
    count is the standard ``com.ratifyprotocol.max_count/v1`` profile.
    """
    issued_at, expiry = _window(now, expires_at)
    root, commander, specialist = _keys(), _keys(), _keys()
    commander_cert = _delegate(
        cert_id=f"commander-{uuid.uuid4().hex}", issuer=root, subject=commander,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE], constraints=[],
        issued_at=issued_at, expires_at=expiry,
    )
    specialist_cert = _delegate(
        cert_id=f"specialist-{uuid.uuid4().hex}", issuer=commander, subject=specialist,
        scope=[INFRA_SCOPE], constraints=bounds(region, max_nodes),
        issued_at=issued_at, expires_at=expiry,
    )
    status = StatusAuthority(lifetime_seconds=status_lifetime_seconds)
    for issuer in (root, commander):
        status.add_issuer(issuer[1], at=issued_at)
    return AuthorityFixture(
        root_id=root[0],
        root_public_key=root[1],
        specialist_id=specialist[0],
        specialist_public_key=specialist[1],
        specialist_private_key=specialist[2],
        delegations=[specialist_cert, commander_cert],
        status=status,
        agent_path=(specialist[0], commander[0]),
    )


def issue_federated_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
    status_lifetime_seconds: int = 3600,
) -> AuthorityFixture:
    """Create a three-agent chain spanning modeled trust domains A and B."""
    issued_at, expiry = _window(now, expires_at)
    root, coordinator, broker, worker = _keys(), _keys(), _keys(), _keys()
    coordinator_cert = _delegate(
        cert_id=f"domain-a-coordinator-{uuid.uuid4().hex}", issuer=root, subject=coordinator,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE], constraints=bounds(region, max_nodes),
        issued_at=issued_at, expires_at=expiry,
    )
    broker_cert = _delegate(
        cert_id=f"domain-b-broker-{uuid.uuid4().hex}", issuer=coordinator, subject=broker,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE], constraints=bounds(region, max_nodes),
        issued_at=issued_at, expires_at=expiry,
    )
    worker_cert = _delegate(
        cert_id=f"domain-b-worker-{uuid.uuid4().hex}", issuer=broker, subject=worker,
        scope=[INFRA_SCOPE], constraints=bounds(region, max_nodes),
        issued_at=issued_at, expires_at=expiry,
    )
    status = StatusAuthority(lifetime_seconds=status_lifetime_seconds)
    for issuer in (root, coordinator, broker):
        status.add_issuer(issuer[1], at=issued_at)
    return AuthorityFixture(
        root_id=root[0],
        root_public_key=root[1],
        specialist_id=worker[0],
        specialist_public_key=worker[1],
        specialist_private_key=worker[2],
        delegations=[worker_cert, broker_cert, coordinator_cert],
        status=status,
        agent_path=(worker[0], broker[0], coordinator[0]),
        broker_id=broker[0],
        broker_public_key=broker[1],
        broker_private_key=broker[2],
        authority_issued_at=issued_at,
        authority_expires_at=expiry,
    )


def issue_dual_root_federated_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
    status_lifetime_seconds: int = 3600,
) -> AuthorityFixture:
    """Add a second, independent root that approves the same exact action.

    Root A (domain A) issues the operation-specific authority chain. Root B
    (the receiving domain) directly approves the same worker key for the same
    exact scope and region. Under the dual-root composition profile both
    approvals name one approval set, so both must carry the set's single
    required scope (SPEC-v2 §7.14 step 5).
    """
    authority = issue_federated_authority(
        now=now, expires_at=expires_at, region=region, max_nodes=max_nodes,
        status_lifetime_seconds=status_lifetime_seconds,
    )
    issued_at, expiry = _window(now, expires_at)
    admission_root = _keys()
    worker = (authority.specialist_id, authority.specialist_public_key, authority.specialist_private_key)
    admission_cert = _delegate(
        cert_id=f"domain-b-worker-approval-{uuid.uuid4().hex}", issuer=admission_root, subject=worker,
        scope=[INFRA_SCOPE], constraints=[ConstraintV2(
            type=CONSTRAINT_RESOURCE_PATH, resource_id=region_resource(region),
        )],
        issued_at=issued_at, expires_at=expiry,
    )
    authority.status.add_issuer(admission_root[1], at=issued_at)
    return replace(
        authority,
        admission_root_id=admission_root[0],
        admission_root_public_key=admission_root[1],
        admission_delegations=[admission_cert],
    )


def region_resource(region: str) -> str:
    return f"gcp:projects/{PROJECT_ID}/regions/{region}"
