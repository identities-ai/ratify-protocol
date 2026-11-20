"""Connect proof of possession. Shared vectors: ``testvectors/v2/mcp/connect.json``.

The console issues a single-use challenge (a one-line token) to the owner or
admin connecting an agent. :func:`prove_possession` signs a SPEC-v2 proof
bundle with no delegations over it, whose session context binds the
workspace, its MCP receiver, the endpoint audience, the challenge ID and the
agent key. It never contacts the network."""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from ..context_v2 import Context
from ..protocol_v2 import sign_proof_bundle_v2, sign_proof_bundle_v2_with_signer
from ..signing_v2 import key_id_v2, public_key_of
from ..types import HybridPrivateKey, HybridPublicKey
from . import binding
from .config import HEX64, UUID, decode_std_base64, load_json, valid_endpoint
from .errors import InvalidConnectTokenError
from .toolcall import sign_presentation

CONNECT_TOKEN_PREFIX = "ratify-mcp-connect-1."
MAX_CONNECT_TOKEN_LENGTH = 4096
_FIELDS = {"challenge_id", "challenge", "issued_at", "workspace_id", "receiver_id", "audience", "verifier_id"}
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


@dataclass(frozen=True)
class ConnectToken:
    challenge_id: str
    challenge: bytes
    issued_at: int
    workspace_id: str
    receiver_id: str
    audience: str
    verifier_id: str


@dataclass(frozen=True)
class PossessionProof:
    """What the connect request carries besides the certificate."""

    connect_challenge_id: str
    possession_proof: str

    def to_dict(self) -> dict:
        return {"connect_challenge_id": self.connect_challenge_id, "possession_proof": self.possession_proof}


def parse_connect_token(token: Any) -> ConnectToken:
    """Parse ``ratify-mcp-connect-1.`` followed by unpadded base64url of a JSON
    object with exactly challenge_id, challenge, issued_at, workspace_id,
    receiver_id, audience and verifier_id. Raises :class:`InvalidConnectTokenError`."""
    invalid = InvalidConnectTokenError("not a ratify-mcp-connect-1 token from the console")
    if not isinstance(token, str) or len(token) > MAX_CONNECT_TOKEN_LENGTH or not token.startswith(CONNECT_TOKEN_PREFIX):
        raise invalid
    body = token[len(CONNECT_TOKEN_PREFIX):]
    if not _BASE64URL.fullmatch(body):
        raise invalid
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        raise invalid from None
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != body:
        raise invalid
    obj = load_json(raw, InvalidConnectTokenError)
    if not isinstance(obj, dict) or set(obj) != _FIELDS:
        raise invalid
    for field in ("challenge_id", "workspace_id", "receiver_id"):
        if not isinstance(obj[field], str) or not UUID.fullmatch(obj[field]):
            raise invalid
    if not isinstance(obj["verifier_id"], str) or not HEX64.fullmatch(obj["verifier_id"]):
        raise invalid
    issued = obj["issued_at"]
    if not isinstance(issued, int) or isinstance(issued, bool) or not 0 < issued <= binding.MAX_SAFE_INTEGER:
        raise invalid
    audience = obj["audience"]
    if not isinstance(audience, str) or not audience.endswith("/mcp") or not valid_endpoint(audience[:-4], audience):
        raise invalid
    challenge = decode_std_base64(obj["challenge"])
    if challenge is None or len(challenge) != 32:
        raise invalid
    return ConnectToken(obj["challenge_id"], challenge, issued, obj["workspace_id"], obj["receiver_id"],
                        audience, obj["verifier_id"])


def _prove(token: str, pub: HybridPublicKey, sign) -> PossessionProof:
    t = parse_connect_token(token)
    agent_id = key_id_v2(pub)
    session = binding.connect_possession_context(t.workspace_id, t.receiver_id, t.audience, t.challenge_id, agent_id)
    wire = sign_presentation(t.verifier_id, agent_id, pub, [], t.challenge, t.issued_at, session, sign)
    return PossessionProof(t.challenge_id, base64.b64encode(wire).decode())


def prove_possession(token: str, agent_key: HybridPrivateKey) -> PossessionProof:
    """Sign the connect challenge with the agent key being connected."""
    return _prove(token, public_key_of(agent_key), lambda b: sign_proof_bundle_v2(b, agent_key))


def prove_possession_with_signer(ctx: Context, token: str, signer) -> PossessionProof:
    """:func:`prove_possession` with an external ``SignerV2``."""
    return _prove(token, signer.public_key_v2(), lambda b: sign_proof_bundle_v2_with_signer(ctx, b, signer))
