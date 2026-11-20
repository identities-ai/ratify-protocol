"""Tool-call proofs. Shared vectors: ``testvectors/v2/mcp/tool-call.json``.

The only thing signed is a SPEC-v2 challenge presentation for a call this
module was asked to make, with ``request_hash`` and ``session_context``
recomputed from the call and the pinned configuration; a hash the server
supplies is never used."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Callable, Union

from ..context_v2 import Context
from ..protocol_v2 import (
    ProofBundleV2,
    encode_proof_bundle_v2,
    placeholder_signature_v2,
    sign_proof_bundle_v2,
    sign_proof_bundle_v2_with_signer,
)
from ..signing_v2 import key_id_v2, public_key_of
from ..types import HybridPrivateKey, HybridPublicKey
from . import binding
from .config import UUID, ClientConfig, decode_std_base64, load_json
from .errors import ChallengeRefusedError, InvalidArgumentsError


@dataclass(frozen=True)
class ToolCall:
    """A validated tool call. Send ``json.loads(canonical_arguments)`` as
    ``params.arguments`` so the server computes the same payload digest."""

    tool: str
    canonical_arguments: bytes
    payload_digest: bytes


def new_tool_call(tool: Any, arguments: Union[str, bytes, bytearray, dict, None]) -> ToolCall:
    """Validate the tool name and its arguments. Raises :class:`InvalidArgumentsError`."""
    if binding.tool_scope(tool) is None:
        raise InvalidArgumentsError("unknown tool")
    canonical = binding.canonical_arguments(arguments)
    return ToolCall(tool, canonical, binding.payload_digest(canonical))


def verified_digest(call: ToolCall) -> bytes:
    """Re-derive the payload digest from the call's canonical arguments, so a
    ToolCall built or changed by hand cannot make the signer bind one
    argument set while the client sends another."""
    if not isinstance(call, ToolCall) or binding.tool_scope(call.tool) is None:
        raise InvalidArgumentsError("not a tool call")
    canonical = bytes(call.canonical_arguments)
    if not canonical or binding.canonical_arguments(canonical) != canonical:
        raise InvalidArgumentsError("tool call arguments are not canonical")
    digest = binding.payload_digest(canonical)
    if digest != bytes(call.payload_digest):
        raise InvalidArgumentsError("tool call digest does not match its arguments")
    return digest


@dataclass(frozen=True)
class Challenge:
    """A challenge response :func:`check_challenge` accepted. It signs only a
    call to ``tool`` under the configuration (verifier, workspace,
    connection) it was checked for."""

    tool: str
    verifier_id: str
    workspace_id: str
    connection_id: str
    challenge: bytes
    invocation_id: str
    issued_at: int
    expires_at: int


def _integer(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) <= binding.MAX_SAFE_INTEGER


def check_challenge(config: ClientConfig, tool: str, response: Union[str, bytes, bytearray], now: int) -> Challenge:
    """Accept the JSON response of ``POST <endpoint>/challenge`` only if
    verifier_id and workspace_id equal the pinned values, required_scope is
    the tool's scope, invocation_id is a lowercase UUID, challenge is 32 bytes
    in canonical standard base64, issued_at and expires_at are integers with
    0 < issued_at <= expires_at, and at least MIN_CHALLENGE_SECONDS_LEFT
    seconds remain at ``now`` (Unix seconds). Raises :class:`ChallengeRefusedError`."""
    scope = binding.tool_scope(tool)
    msg = load_json(response, ChallengeRefusedError)
    if scope is None or not isinstance(msg, dict):
        raise ChallengeRefusedError("malformed challenge response")
    if msg.get("verifier_id") != config.verifier_id:
        raise ChallengeRefusedError("verifier_id differs from the pinned value")
    if msg.get("workspace_id") != config.workspace_id:
        raise ChallengeRefusedError("workspace_id differs from the pinned value")
    if msg.get("required_scope") != scope:
        raise ChallengeRefusedError("required_scope differs from this tool's scope")
    inv = msg.get("invocation_id")
    if not isinstance(inv, str) or not UUID.fullmatch(inv):
        raise ChallengeRefusedError("invocation_id is not a lowercase UUID")
    raw = decode_std_base64(msg.get("challenge"))
    if raw is None or len(raw) != 32:
        raise ChallengeRefusedError("challenge is not 32 bytes in canonical base64")
    issued, expires = msg.get("issued_at"), msg.get("expires_at")
    if not _integer(issued) or not _integer(expires) or issued <= 0 or issued > expires:
        raise ChallengeRefusedError("issued_at/expires_at are invalid")
    if now > expires - binding.MIN_CHALLENGE_SECONDS_LEFT:
        raise ChallengeRefusedError("challenge expires too soon")
    return Challenge(tool, config.verifier_id, config.workspace_id, config.connection_id, raw, inv, issued, expires)


@dataclass(frozen=True)
class ProofEnvelope:
    """The value of ``params._meta["com.ratifyprotocol/proof"]`` on tools/call."""

    connection_id: str
    invocation_id: str
    challenge: str
    bundle: str

    def to_dict(self) -> dict:
        return {"connection_id": self.connection_id, "invocation_id": self.invocation_id,
                "challenge": self.challenge, "bundle": self.bundle}


def sign_presentation(verifier_id: str, agent_id: str, pub: HybridPublicKey, delegations: list,
                      challenge: bytes, challenge_at: int, session: bytes,
                      sign: Callable[[ProofBundleV2], ProofBundleV2]) -> bytes:
    unsigned = ProofBundleV2(
        version=2, verifier_id=verifier_id, agent_id=agent_id, agent_pub_key=pub, delegations=list(delegations),
        delegation_digest=bytes(48), challenge=bytes(challenge), challenge_at=challenge_at,
        challenge_sig=placeholder_signature_v2(), session_context=bytes(session),
    )
    return encode_proof_bundle_v2(sign(unsigned))


def _sign_tool_call(config: ClientConfig, pub: HybridPublicKey, call: ToolCall, challenge: Challenge,
                    sign: Callable[[ProofBundleV2], ProofBundleV2]) -> ProofEnvelope:
    if not isinstance(challenge, Challenge) or not isinstance(call, ToolCall) or challenge.tool != call.tool:
        raise ChallengeRefusedError("the challenge was checked for another tool")
    if (challenge.verifier_id, challenge.workspace_id, challenge.connection_id) != (
            config.verifier_id, config.workspace_id, config.connection_id):
        raise ChallengeRefusedError("the challenge was checked under another configuration")
    digest = verified_digest(call)
    agent_id = key_id_v2(pub)
    if not config.delegations or config.delegations[-1].subject_id != agent_id:
        raise ChallengeRefusedError("the last delegation certificate is not issued to this agent key")
    req = binding.request_hash(call.tool, config.connection_id, config.audience, digest)
    session = binding.session_context(config.verifier_id, config.workspace_id, agent_id,
                                      config.connection_id, challenge.invocation_id, req)
    # The configuration lists the chain root side first; a SPEC-v2 bundle
    # carries it leaf first.
    wire = sign_presentation(config.verifier_id, agent_id, pub, list(reversed(config.delegations)),
                             challenge.challenge, challenge.issued_at, session, sign)
    return ProofEnvelope(config.connection_id, challenge.invocation_id,
                         base64.b64encode(challenge.challenge).decode(), base64.b64encode(wire).decode())


def sign_tool_call(config: ClientConfig, agent_key: HybridPrivateKey, call: ToolCall,
                   challenge: Challenge) -> ProofEnvelope:
    """Sign the tool-call proof with an in-process agent key (native signing)."""
    return _sign_tool_call(config, public_key_of(agent_key), call, challenge,
                           lambda b: sign_proof_bundle_v2(b, agent_key))


def sign_tool_call_with_signer(ctx: Context, config: ClientConfig, signer, call: ToolCall,
                               challenge: Challenge) -> ProofEnvelope:
    """Sign the tool-call proof with an external ``SignerV2``."""
    return _sign_tool_call(config, signer.public_key_v2(), call, challenge,
                           lambda b: sign_proof_bundle_v2_with_signer(ctx, b, signer))
