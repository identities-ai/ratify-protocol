# SPDX-License-Identifier: Apache-2.0
"""The principal side: identities and signed delegations.

This is the only place authority is *created*. In a real deployment this code
runs wherever the principal's root key lives, a person's device, an HSM, a
CI signing step, and never inside the agent.
"""

from __future__ import annotations

import uuid

from ratify_protocol import (
    PROTOCOL_VERSION,
    AgentIdentity,
    Constraint,
    DelegationCert,
    HumanRoot,
    HybridPrivateKey,
    HybridPublicKey,
    generate_agent,
    generate_human_root,
    issue_delegation,
)


def new_principal() -> tuple[HumanRoot, HybridPrivateKey]:
    """A principal's hybrid root identity."""
    return generate_human_root()


def new_agent(name: str) -> tuple[AgentIdentity, HybridPrivateKey]:
    """An agent's own hybrid keypair. The agent generates this itself; the
    private half never leaves the agent."""
    return generate_agent(name, "assistant")


def sign_cert(
    *,
    issuer_id: str,
    issuer_pub: HybridPublicKey,
    issuer_priv: HybridPrivateKey,
    subject_id: str,
    subject_pub: HybridPublicKey,
    scope: list[str],
    constraints: list[Constraint],
    issued_at: int,
    expires_at: int,
) -> DelegationCert:
    """Sign one delegation from an issuer to a subject.

    Used for both the principal's root delegation and for subdelegation, the
    protocol treats them identically, which is why non-amplification has to be
    enforced at verification rather than at issuance.
    """
    cert = DelegationCert(
        cert_id=uuid.uuid4().hex,
        version=PROTOCOL_VERSION,
        issuer_id=issuer_id,
        issuer_pub_key=issuer_pub,
        subject_id=subject_id,
        subject_pub_key=subject_pub,
        scope=list(scope),
        constraints=list(constraints),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    issue_delegation(cert, issuer_priv)
    return cert
