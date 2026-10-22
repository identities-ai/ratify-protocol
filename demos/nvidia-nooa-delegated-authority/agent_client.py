# SPDX-License-Identifier: Apache-2.0
"""The agent side: carry the proof, answer the challenge, report the verdict.

There is deliberately no authorization logic in this file. The client asks the
service what it intends to do, signs the challenge the service issues, and
returns whatever the service decided. It has no ability to allow anything, and
no knowledge of what the delegation permits.

Protocol v2. The proof is a ``ProofBundleV2`` signed with the agent's hybrid
key and sent as its exact wire bytes (base64), because v2 decodes the wire
strictly and a re-serialized object is not the object that was signed.
"""

from __future__ import annotations

import base64
import json
import urllib.request

from ratify_protocol_v2.protocol_v2 import (
    ProofBundleV2,
    encode_proof_bundle_v2,
    sign_proof_bundle_v2,
)

from refund_service import encode_public_key


def post_json(url: str, payload: dict) -> dict:
    """POST JSON and decode the JSON response."""
    body = json.dumps(payload, default=_encode).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request) as response:  # noqa: S310, loopback demo
        out = json.loads(response.read())
    for field in ("challenge", "session_context"):
        if isinstance(out.get(field), str):
            out[field] = base64.b64decode(out[field])
    return out


def _encode(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(f"not JSON-serializable: {type(value).__name__}")


def sign_presentation(
    *, verifier_id, agent_id, agent_pub, agent_priv, delegations, challenge,
    challenge_at, session_context,
) -> bytes:
    """Sign a v2 proof bundle over the receiver's challenge and binding.

    Returns the exact wire bytes. ``challenge_at`` is the receiver's issuance
    time for this challenge, which the verifier compares exactly."""
    bundle = sign_proof_bundle_v2(
        ProofBundleV2(
            version=2,
            verifier_id=verifier_id,
            agent_id=agent_id,
            agent_pub_key=agent_pub,
            delegations=list(delegations),
            delegation_digest=b"",  # computed by sign_proof_bundle_v2
            challenge=challenge,
            challenge_at=challenge_at,
            challenge_sig=None,  # computed by sign_proof_bundle_v2
            session_context=session_context,
        ),
        agent_priv,
    )
    return encode_proof_bundle_v2(bundle)


class RefundClient:
    """Presents delegated authority to the refund service."""

    def __init__(self, base_url, agent_id, agent_pub, agent_priv, delegations):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_pub = agent_pub
        self.agent_priv = agent_priv
        # Chain order is [leaf, ... root].
        self.delegations = list(delegations)

    def fetch_challenge(self, order_id: str, amount_micros: int, currency: str = "USD") -> dict:
        """Phase 1, describe the intended action and receive a challenge
        bound to the *receiver's* canonical reading of it."""
        return post_json(
            self.base_url + "/refunds/challenge",
            {
                "order_id": order_id,
                "amount_micros": amount_micros,
                "currency": currency,
                "agent_id": self.agent_id,
                "agent_public_key": encode_public_key(self.agent_pub),
            },
        )

    def sign(self, challenge: dict) -> bytes:
        return sign_presentation(
            verifier_id=challenge["verifier_id"],
            agent_id=self.agent_id,
            agent_pub=self.agent_pub,
            agent_priv=self.agent_priv,
            delegations=self.delegations,
            challenge=challenge["challenge"],
            challenge_at=challenge["issued_at"],
            session_context=challenge["session_context"],
        )

    def present(self, challenge: dict) -> dict:
        """Phase 2, prove possession of the agent key and submit the chain."""
        return post_json(
            self.base_url + "/refunds",
            {"challenge": challenge["challenge"], "proof": self.sign(challenge)},
        )

    def request_refund(self, order_id: str, amount_micros: int, currency: str = "USD") -> dict:
        """Both phases. Returns the service's decision verbatim."""
        return self.present(self.fetch_challenge(order_id, amount_micros, currency))
