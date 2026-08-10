"""Issue the two-hop authority used by the reference.

The root delegates to an ADK commander. The commander narrows that authority
to one infrastructure specialist. Private keys never cross the receiver
boundary; the receiver is configured only with the accepted root public key.
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
NODE_LIMIT_CONSTRAINT = "ai.identities.ratify.adk.max_nodes"
WORKSPACE_ID = "customer-project"
VERIFIER_ID = "independent-infrastructure-receiver"


@dataclass(frozen=True)
class AuthorityFixture:
    root_id: str
    root_public_key: HybridPublicKey
    specialist_id: str
    specialist_private_key: HybridPrivateKey
    delegations: list[DelegationCert]

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
    )


def region_resource(region: str) -> str:
    return f"gcp:projects/{WORKSPACE_ID}/regions/{region}"
