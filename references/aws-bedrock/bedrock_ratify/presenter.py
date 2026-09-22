"""Agent 1's proof side: turn a delegation into a bundle for one request.

Agent 1 holds a certificate the principal signed and its own private key. It
never sends the key anywhere. On each request it signs the receiver's fresh
challenge, bound to the session context for that exact request, and ships the
bundle as canonical JSON.
"""
from __future__ import annotations

import time

from ratify_protocol import (
    DelegationCert,
    ProofBundle,
    encode_proof_bundle,
    sign_challenge,
)

from .identity import Party


def build_proof(
    agent: Party,
    chain: list[DelegationCert],
    challenge: bytes,
    session_context: bytes,
    *,
    challenge_at: int | None = None,
) -> ProofBundle:
    """Sign the challenge and assemble the bundle agent 1 presents."""
    challenge_at = int(time.time()) if challenge_at is None else challenge_at
    return ProofBundle(
        agent_id=agent.id,
        agent_pub_key=agent.public_key,
        delegations=list(chain),
        challenge=challenge,
        challenge_at=challenge_at,
        challenge_sig=sign_challenge(
            challenge, challenge_at, agent.private_key, session_context
        ),
        session_context=session_context,
    )


def wire(bundle: ProofBundle) -> str:
    """The bytes that actually cross between the two agents."""
    return encode_proof_bundle(bundle)
