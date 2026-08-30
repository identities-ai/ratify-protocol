# SPDX-License-Identifier: Apache-2.0
"""The agent side: carry the proof, answer the challenge, report the verdict.

There is deliberately no authorization logic in this file. The client asks the
service what it intends to do, signs the challenge the service issues, and
returns whatever the service decided. It has no ability to allow anything, and
no knowledge of what the delegation permits.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.request

from ratify_protocol import ProofBundle, sign_challenge
from ratify_protocol.wire import encode_proof_bundle


def post_json(url: str, payload: dict) -> dict:
    """POST JSON and decode the JSON response.

    Proof bundles are serialized through the protocol's own canonical wire
    codec rather than an ad-hoc encoding, so what crosses the boundary here is
    the real interop format.
    """
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
    if isinstance(value, ProofBundle):
        return json.loads(encode_proof_bundle(value))
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    raise TypeError(f"not JSON-serializable: {type(value).__name__}")


class RefundClient:
    """Presents delegated authority to the refund service."""

    def __init__(self, base_url, agent_id, agent_pub, agent_priv, delegations):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_pub = agent_pub
        self.agent_priv = agent_priv
        # Chain order is [leaf, ... root].
        self.delegations = list(delegations)

    def fetch_challenge(self, order_id: str, amount: float, currency: str = "USD") -> dict:
        """Phase 1, describe the intended action and receive a challenge
        bound to the *receiver's* canonical reading of it."""
        return post_json(
            self.base_url + "/refunds/challenge",
            {
                "order_id": order_id,
                "amount": amount,
                "currency": currency,
                "agent_id": self.agent_id,
            },
        )

    def present(self, challenge: dict) -> dict:
        """Phase 2, prove possession of the agent key and submit the chain."""
        at = int(time.time())
        bundle = ProofBundle(
            agent_id=self.agent_id,
            agent_pub_key=self.agent_pub,
            delegations=self.delegations,
            challenge=challenge["challenge"],
            challenge_at=at,
            challenge_sig=sign_challenge(
                challenge["challenge"], at, self.agent_priv, challenge["session_context"]
            ),
            session_context=challenge["session_context"],
        )
        return post_json(
            self.base_url + "/refunds",
            {"challenge": challenge["challenge"], "bundle": bundle},
        )

    def request_refund(self, order_id: str, amount: float, currency: str = "USD") -> dict:
        """Both phases. Returns the service's decision verbatim."""
        return self.present(self.fetch_challenge(order_id, amount, currency))
