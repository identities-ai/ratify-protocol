r"""Principals, agents, and the delegation chain.

Three parties hold keys:

  principal  the person accountable for C:\SideEvents. Signs the delegation.
  agent1     the requesting agent (Bedrock client #1). Holds the delegation
             and signs a fresh challenge on every request.
  agent2     the receiving agent (Bedrock client #2). Verifies, and signs the
             verification receipt.

Keys are generated per run and held in memory. Nothing here talks to AWS: the
proof is portable, so who runs the model is independent of who holds authority.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from ratify_protocol import (
    AgentIdentity,
    Constraint,
    DelegationCert,
    HumanRoot,
    HybridPrivateKey,
    HybridSignature,
    PROTOCOL_VERSION,
    generate_agent,
    generate_human_root,
    intersect_scopes,
    issue_delegation,
    validate_resource_constraints,
)

from .config import DELEGATION_TTL_SECONDS, RESOURCE_ID


@dataclass
class Party:
    """An identity plus the private key that proves it."""

    identity: object          # HumanRoot or AgentIdentity
    private_key: HybridPrivateKey

    @property
    def id(self) -> str:
        return self.identity.id

    @property
    def public_key(self):
        return self.identity.public_key


@dataclass
class Cast:
    principal: Party
    agent1: Party
    agent2: Party
    stranger: Party           # an untrusted root, for the deny cases


def build_cast() -> Cast:
    root, root_priv = generate_human_root()
    a1, a1_priv = generate_agent("SideEvents Requester", "api_agent")
    a2, a2_priv = generate_agent("SideEvents Custodian", "api_agent")
    other, other_priv = generate_human_root()
    return Cast(
        principal=Party(root, root_priv),
        agent1=Party(a1, a1_priv),
        agent2=Party(a2, a2_priv),
        stranger=Party(other, other_priv),
    )


def issue_directory_delegation(
    issuer: Party,
    subject: Party,
    *,
    scopes: list[str],
    path_prefix: str = "/",
    ttl_seconds: int = DELEGATION_TTL_SECONDS,
    resource_id: str = RESOURCE_ID,
    now: int | None = None,
    parent: DelegationCert | None = None,
) -> DelegationCert:
    """Sign a delegation bound to one resource and one path prefix inside it.

    When ``parent`` is given this is a narrowing hop: scopes are intersected
    with the parent's, and the child's lifetime is clamped to whatever the
    parent has left. Authority can only shrink along a chain.
    """
    now = int(time.time()) if now is None else now

    if parent is not None:
        scopes = intersect_scopes(parent.scope, scopes)
        if not scopes:
            raise ValueError("narrowed delegation would carry no scope")
        remaining = parent.expires_at - now
        if remaining <= 0:
            raise ValueError("parent delegation has already expired")
        ttl_seconds = min(ttl_seconds, remaining)

    constraint = Constraint(
        type="resource_path",
        points=[],
        resource_id=resource_id,
        path_prefix=path_prefix,
    )
    cert = DelegationCert(
        cert_id=f"cert-{uuid.uuid4()}",
        version=PROTOCOL_VERSION,
        issuer_id=issuer.id,
        issuer_pub_key=issuer.public_key,
        subject_id=subject.id,
        subject_pub_key=subject.public_key,
        scope=sorted(scopes),
        constraints=[constraint],
        issued_at=now,
        expires_at=now + ttl_seconds,
        signature=HybridSignature(ed25519=b"", ml_dsa_65=b""),
    )
    validate_resource_constraints(cert.constraints)
    issue_delegation(cert, issuer.private_key)
    return cert
