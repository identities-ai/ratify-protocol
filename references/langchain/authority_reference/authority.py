"""Issue the two-hop authority used by the reference (Protocol v2).

The root delegates to a LangChain commander. The commander narrows that
authority to one infrastructure specialist. Each issuer also holds a separate
status key and signs its own revocation list through the SDK status publisher
(see ``status_feed``). Private keys never cross the receiver boundary; the
receiver is configured only with accepted public trust material.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
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


# One exact custom scope, matched by byte equality (SPEC-v2 §2.4).
INFRA_SCOPE = "custom:infra:provision"
# The standard com.ratifyprotocol.max_count/v1 profile (SPEC-v2 §5.2). The
# receiver supplies the requested quantity under this counter name.
NODE_COUNTER = "nodes"
# A canonical lowercase UUID, as the v2 session context requires (§2.4).
WORKSPACE_ID = "0b6f3c1e-2d4a-4e5f-8a9b-1c2d3e4f5a6b"
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

    def present(self, grant: ChallengeGrant) -> ProofBundleV2:
        """Sign a receiver-issued, operation-bound challenge."""
        return sign_proof_bundle_v2(ProofBundleV2(
            version=2,
            verifier_id=grant.verifier_id,
            agent_id=self.specialist_id,
            agent_pub_key=self.specialist_public_key,
            delegations=list(self.delegations),
            delegation_digest=b"",  # computed by sign_proof_bundle_v2
            challenge=grant.challenge,
            challenge_at=grant.issued_at,
            challenge_sig=None,  # computed by sign_proof_bundle_v2
            session_context=grant.session_context,
        ), self.specialist_private_key)


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
    issued_at = int(time.time()) if now is None else now
    expiry = issued_at + 3600 if expires_at is None else expires_at
    root_public, root_private = generate_keypair_v2()
    commander_public, commander_private = generate_keypair_v2()
    specialist_public, specialist_private = generate_keypair_v2()
    root_id, commander_id, specialist_id = (
        key_id_v2(root_public), key_id_v2(commander_public), key_id_v2(specialist_public),
    )

    commander_cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2,
        cert_id=f"commander-{uuid.uuid4().hex}",
        issuer_id=root_id,
        issuer_pub_key=root_public,
        subject_id=commander_id,
        subject_pub_key=commander_public,
        scope=[INFRA_SCOPE, SCOPE_IDENTITY_DELEGATE],
        constraints=[],
        issued_at=issued_at,
        expires_at=expiry,
    ), root_private)
    specialist_cert = sign_delegation_cert_v2(DelegationCertV2(
        version=2,
        cert_id=f"specialist-{uuid.uuid4().hex}",
        issuer_id=commander_id,
        issuer_pub_key=commander_public,
        subject_id=specialist_id,
        subject_pub_key=specialist_public,
        scope=[INFRA_SCOPE],
        constraints=[
            ConstraintV2(type=CONSTRAINT_RESOURCE_PATH, resource_id=region_resource(region)),
            ConstraintV2(
                type=CONSTRAINT_MAX_COUNT_V2,
                params={"counter": NODE_COUNTER, "max": max_nodes},
            ),
        ],
        issued_at=issued_at,
        expires_at=expiry,
    ), commander_private)

    status = StatusAuthority(lifetime_seconds=status_lifetime_seconds)
    status.add_issuer(root_public, at=issued_at)
    status.add_issuer(commander_public, at=issued_at)
    return AuthorityFixture(
        root_id=root_id,
        root_public_key=root_public,
        specialist_id=specialist_id,
        specialist_public_key=specialist_public,
        specialist_private_key=specialist_private,
        delegations=[specialist_cert, commander_cert],
        status=status,
    )


def region_resource(region: str) -> str:
    return f"gcp:projects/{PROJECT_ID}/regions/{region}"
