"""Issue the bounded authorities used by the reference.

The baseline root delegates to an ADK commander, who narrows authority to one
infrastructure specialist. The federation fixture adds a broker hop in a
second modeled trust domain. Private keys never cross the receiver boundary;
the receiver is configured only with accepted public trust material.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
import uuid

from ratify_protocol import (
    Constraint,
    DelegationCert,
    HybridPrivateKey,
    HybridPublicKey,
    HybridSignature,
    PROTOCOL_VERSION,
    ProofBundle,
    SCOPE_IDENTITY_DELEGATE,
    generate_agent,
    generate_human_root,
    issue_delegation,
    sign_challenge,
)


INFRA_SCOPE = "custom:infra:provision"
ADMISSION_SCOPE = "custom:workload:admit"
NODE_LIMIT_CONSTRAINT = "com.ratifyprotocol.adk.max_nodes"
WORKSPACE_ID = "customer-project"


@dataclass(frozen=True)
class AuthorityFixture:
    root_id: str
    root_public_key: HybridPublicKey
    specialist_id: str
    specialist_private_key: HybridPrivateKey
    delegations: list[DelegationCert]
    agent_path: tuple[str, ...] = ()
    admission_root_id: str | None = None
    admission_root_public_key: HybridPublicKey | None = None
    admission_delegations: list[DelegationCert] | None = None
    broker_id: str | None = None
    broker_public_key: HybridPublicKey | None = None
    broker_private_key: HybridPrivateKey | None = None
    authority_issued_at: int | None = None
    authority_expires_at: int | None = None

    def present(
        self,
        *,
        challenge: bytes,
        session_context: bytes,
        now: int | None = None,
    ) -> ProofBundle:
        """Sign a receiver-issued, operation-bound challenge."""
        signed_at = int(time.time()) if now is None else now
        return ProofBundle(
            agent_id=self.specialist_id,
            agent_pub_key=self.delegations[0].subject_pub_key,
            delegations=self.delegations,
            challenge=challenge,
            challenge_at=signed_at,
            challenge_sig=sign_challenge(
                challenge,
                signed_at,
                self.specialist_private_key,
                session_context,
            ),
            session_context=session_context,
        )

    def present_admission(
        self,
        *,
        challenge: bytes,
        session_context: bytes,
        now: int | None = None,
    ) -> ProofBundle:
        """Present workload admission for the same leaf key and challenge."""
        if not self.admission_delegations:
            raise ValueError("fixture has no admission chain")
        signed_at = int(time.time()) if now is None else now
        return ProofBundle(
            agent_id=self.specialist_id,
            agent_pub_key=self.admission_delegations[0].subject_pub_key,
            delegations=self.admission_delegations,
            challenge=challenge,
            challenge_at=signed_at,
            challenge_sig=sign_challenge(
                challenge,
                signed_at,
                self.specialist_private_key,
                session_context,
            ),
            session_context=session_context,
        )

    def narrow_worker_authority(
        self, *, region: str, max_nodes: int, now: int | None = None
    ) -> "AuthorityFixture":
        """Mint a fresh, narrower worker certificate at broker decision time."""
        if not self.broker_id or not self.broker_public_key or not self.broker_private_key:
            raise ValueError("fixture has no runtime broker issuer")
        issued_at = int(time.time()) if now is None else now
        expires_at = min(self.authority_expires_at or issued_at + 3600, issued_at + 300)
        cert = DelegationCert(
            cert_id=f"runtime-worker-{uuid.uuid4().hex}",
            version=PROTOCOL_VERSION,
            issuer_id=self.broker_id,
            issuer_pub_key=self.broker_public_key,
            subject_id=self.specialist_id,
            subject_pub_key=self.delegations[0].subject_pub_key,
            scope=[INFRA_SCOPE],
            constraints=[
                Constraint(type="resource_path", resource_id=region_resource(region)),
                Constraint(type=NODE_LIMIT_CONSTRAINT, params={"max_nodes": max_nodes}),
            ],
            issued_at=issued_at,
            expires_at=expires_at,
            signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
        )
        issue_delegation(cert, self.broker_private_key)
        return AuthorityFixture(
            root_id=self.root_id,
            root_public_key=self.root_public_key,
            specialist_id=self.specialist_id,
            specialist_private_key=self.specialist_private_key,
            delegations=[cert, *self.delegations[1:]],
            agent_path=(self.specialist_id, *self.agent_path[1:]),
            admission_root_id=self.admission_root_id,
            admission_root_public_key=self.admission_root_public_key,
            admission_delegations=self.admission_delegations,
            broker_id=self.broker_id,
            broker_public_key=self.broker_public_key,
            broker_private_key=self.broker_private_key,
            authority_issued_at=self.authority_issued_at,
            authority_expires_at=self.authority_expires_at,
        )


def issue_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
) -> AuthorityFixture:
    """Create root -> commander -> specialist authority.

    Region is expressed as a canonical logical resource. Node count is an
    integration-profile extension constraint evaluated by the receiver.
    """
    issued_at = int(time.time()) if now is None else now
    expiry = issued_at + 3600 if expires_at is None else expires_at
    root, root_private = generate_human_root()
    commander, commander_private = generate_agent("ADK Commander", "custom")
    specialist, specialist_private = generate_agent(
        "Infrastructure Specialist", "custom"
    )

    commander_cert = DelegationCert(
        cert_id=f"commander-{uuid.uuid4().hex}",
        version=PROTOCOL_VERSION,
        issuer_id=root.id,
        issuer_pub_key=root.public_key,
        subject_id=commander.id,
        subject_pub_key=commander.public_key,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE],
        constraints=[],
        issued_at=issued_at,
        expires_at=expiry,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    issue_delegation(commander_cert, root_private)

    specialist_cert = DelegationCert(
        cert_id=f"specialist-{uuid.uuid4().hex}",
        version=PROTOCOL_VERSION,
        issuer_id=commander.id,
        issuer_pub_key=commander.public_key,
        subject_id=specialist.id,
        subject_pub_key=specialist.public_key,
        scope=[INFRA_SCOPE],
        constraints=[
            Constraint(
                type="resource_path",
                resource_id=region_resource(region),
            ),
            Constraint(
                type=NODE_LIMIT_CONSTRAINT,
                params={"max_nodes": max_nodes},
            ),
        ],
        issued_at=issued_at,
        expires_at=expiry,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    issue_delegation(specialist_cert, commander_private)

    return AuthorityFixture(
        root_id=root.id,
        root_public_key=root.public_key,
        specialist_id=specialist.id,
        specialist_private_key=specialist_private,
        delegations=[specialist_cert, commander_cert],
        agent_path=(specialist.id, commander.id),
    )


def issue_federated_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
) -> AuthorityFixture:
    """Create a three-agent chain spanning modeled trust domains A and B."""
    issued_at = int(time.time()) if now is None else now
    expiry = issued_at + 3600 if expires_at is None else expires_at
    root, root_private = generate_human_root()
    coordinator, coordinator_private = generate_agent(
        "Domain A Coordinator", "custom"
    )
    broker, broker_private = generate_agent("Domain B Broker", "custom")
    worker, worker_private = generate_agent("Domain B Worker", "custom")

    def delegation(
        *,
        cert_id: str,
        issuer_id: str,
        issuer_public_key: HybridPublicKey,
        issuer_private_key: HybridPrivateKey,
        subject_id: str,
        subject_public_key: HybridPublicKey,
        leaf: bool,
    ) -> DelegationCert:
        cert = DelegationCert(
            cert_id=cert_id,
            version=PROTOCOL_VERSION,
            issuer_id=issuer_id,
            issuer_pub_key=issuer_public_key,
            subject_id=subject_id,
            subject_pub_key=subject_public_key,
            scope=[INFRA_SCOPE] + ([] if leaf else [SCOPE_IDENTITY_DELEGATE]),
            constraints=[
                Constraint(type="resource_path", resource_id=region_resource(region)),
                Constraint(type=NODE_LIMIT_CONSTRAINT, params={"max_nodes": max_nodes}),
            ],
            issued_at=issued_at,
            expires_at=expiry,
            signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
        )
        issue_delegation(cert, issuer_private_key)
        return cert

    coordinator_cert = delegation(
        cert_id=f"domain-a-coordinator-{uuid.uuid4().hex}",
        issuer_id=root.id,
        issuer_public_key=root.public_key,
        issuer_private_key=root_private,
        subject_id=coordinator.id,
        subject_public_key=coordinator.public_key,
        leaf=False,
    )
    broker_cert = delegation(
        cert_id=f"domain-b-broker-{uuid.uuid4().hex}",
        issuer_id=coordinator.id,
        issuer_public_key=coordinator.public_key,
        issuer_private_key=coordinator_private,
        subject_id=broker.id,
        subject_public_key=broker.public_key,
        leaf=False,
    )
    worker_cert = delegation(
        cert_id=f"domain-b-worker-{uuid.uuid4().hex}",
        issuer_id=broker.id,
        issuer_public_key=broker.public_key,
        issuer_private_key=broker_private,
        subject_id=worker.id,
        subject_public_key=worker.public_key,
        leaf=True,
    )
    return AuthorityFixture(
        root_id=root.id,
        root_public_key=root.public_key,
        specialist_id=worker.id,
        specialist_private_key=worker_private,
        delegations=[worker_cert, broker_cert, coordinator_cert],
        agent_path=(worker.id, broker.id, coordinator.id),
        broker_id=broker.id,
        broker_public_key=broker.public_key,
        broker_private_key=broker_private,
        authority_issued_at=issued_at,
        authority_expires_at=expiry,
    )


def issue_dual_root_federated_authority(
    *,
    now: int | None = None,
    expires_at: int | None = None,
    region: str = "us-central1",
    max_nodes: int = 1,
) -> AuthorityFixture:
    """Issue authority from Identities AI and workload admission from Kekwanu.

    The worker key is shared by the two independently anchored bundles. The
    authority chain remains operation-specific; the admission chain recognizes
    the worker as belonging to the receiving organization.
    """
    authority = issue_federated_authority(
        now=now, expires_at=expires_at, region=region, max_nodes=max_nodes
    )
    admission_root, admission_private = generate_human_root()
    worker_cert = DelegationCert(
        cert_id=f"kekwanu-worker-admission-{uuid.uuid4().hex}",
        version=PROTOCOL_VERSION,
        issuer_id=admission_root.id,
        issuer_pub_key=admission_root.public_key,
        subject_id=authority.specialist_id,
        subject_pub_key=authority.delegations[0].subject_pub_key,
        scope=[ADMISSION_SCOPE],
        constraints=[],
        issued_at=int(time.time()) if now is None else now,
        expires_at=(int(time.time()) if now is None else now) + 3600
        if expires_at is None
        else expires_at,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    issue_delegation(worker_cert, admission_private)
    return AuthorityFixture(
        **{field: getattr(authority, field) for field in AuthorityFixture.__dataclass_fields__
           if field not in {"admission_root_id", "admission_root_public_key", "admission_delegations"}},
        admission_root_id=admission_root.id,
        admission_root_public_key=admission_root.public_key,
        admission_delegations=[worker_cert],
    )


def region_resource(region: str, workspace_id: str = WORKSPACE_ID) -> str:
    return f"gcp:projects/{workspace_id}/regions/{region}"
