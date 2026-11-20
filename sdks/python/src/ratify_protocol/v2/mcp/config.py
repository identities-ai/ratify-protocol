"""The console's client configuration. Shared vectors:
``testvectors/v2/mcp/client-config.json``."""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any, Union

from ..protocol_v2 import DelegationCertV2, decode_delegation_cert_v2
from .errors import InvalidConfigError

ENDPOINT = re.compile(r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HEX64 = re.compile(r"[0-9a-f]{64}")

#: The fields the console's client_config carries.
CONSOLE_FIELDS = ("endpoint", "audience", "verifier_id", "workspace_id", "connection_id", "delegations")


def valid_endpoint(endpoint: Any, audience: Any) -> bool:
    """``https://`` and a lowercase host with an optional port, nothing else,
    and ``audience`` is exactly the endpoint followed by ``/mcp``."""
    return (isinstance(endpoint, str) and isinstance(audience, str) and ENDPOINT.fullmatch(endpoint) is not None
            and audience == endpoint + "/mcp")


def decode_std_base64(text: Any) -> bytes | None:
    """Canonical padded standard base64 only: re-encoding must give the text back."""
    if not isinstance(text, str) or not text.isascii():
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw).decode() == text else None


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid JSON constant {name}")


def load_json(data: Union[str, bytes, bytearray], error: type) -> Any:
    """Parse UTF-8 JSON text; NaN and Infinity are refused."""
    try:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8")
        if not isinstance(data, str):
            raise ValueError("not text")
        return json.loads(data, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise error("not valid JSON") from None


@dataclass(frozen=True)
class ClientConfig:
    """Pinned endpoint and audience, verifier, workspace, connection, and the
    delegation chain (root side first; the last certificate is issued to the
    agent key; a proof bundle carries them leaf first)."""

    endpoint: str
    audience: str
    verifier_id: str
    workspace_id: str
    connection_id: str
    delegations: tuple[DelegationCertV2, ...]

    def challenge_request(self, call) -> bytes:
        """The JSON body of ``POST <endpoint>/challenge`` for ``call``."""
        from .binding import payload_digest_text
        from .toolcall import verified_digest
        return json.dumps({"connection_id": self.connection_id, "tool": call.tool,
                           "payload_digest": payload_digest_text(verified_digest(call))},
                          separators=(",", ":")).encode()

    def check_challenge(self, tool: str, response: Union[str, bytes, bytearray], now: int):
        from .toolcall import check_challenge
        return check_challenge(self, tool, response, now)


def parse_client_config(data: Union[str, bytes, bytearray, dict]) -> ClientConfig:
    """Parse the console's client configuration: the client_config object, or
    an object that carries it under ``client_config`` (the connect response).
    Other fields are ignored, so a signer file with a key reference parses.

    - endpoint: ``https://`` and a lowercase host with an optional port only
    - audience: exactly endpoint + ``/mcp``
    - verifier_id: 64 lowercase hex characters
    - workspace_id, connection_id: lowercase UUIDs
    - delegations: a non-empty list of canonical standard base64 SPEC-v2
      delegation certificates, root side first: each certificate's subject
      (ID and key) is the next one's issuer

    Raises :class:`InvalidConfigError`."""
    raw = data if isinstance(data, dict) else load_json(data, InvalidConfigError)
    if not isinstance(raw, dict):
        raise InvalidConfigError("configuration must be a JSON object")
    if isinstance(raw.get("client_config"), dict):
        raw = raw["client_config"]
    missing = [k for k in CONSOLE_FIELDS if k not in raw]
    if missing:
        raise InvalidConfigError("configuration is missing " + ", ".join(missing))
    if not valid_endpoint(raw["endpoint"], raw["audience"]):
        raise InvalidConfigError("endpoint must be https:// and a lowercase host (optional port), and audience the endpoint followed by /mcp")
    if not isinstance(raw["verifier_id"], str) or not HEX64.fullmatch(raw["verifier_id"]):
        raise InvalidConfigError("verifier_id must be 64 lowercase hex characters")
    for field in ("workspace_id", "connection_id"):
        if not isinstance(raw[field], str) or not UUID.fullmatch(raw[field]):
            raise InvalidConfigError(f"{field} must be a lowercase UUID")
    dels = raw["delegations"]
    if not isinstance(dels, list) or not dels:
        raise InvalidConfigError("delegations must be a non-empty list of base64 certificates")
    certs = []
    for d in dels:
        wire = decode_std_base64(d)
        if wire is None:
            raise InvalidConfigError("delegations must be canonical standard base64")
        try:
            certs.append(decode_delegation_cert_v2(wire))
        except Exception:
            raise InvalidConfigError("a delegation is not a v2 delegation certificate") from None
    for parent, child in zip(certs, certs[1:]):
        if (parent.subject_id != child.issuer_id
                or bytes(parent.subject_pub_key.ed25519) != bytes(child.issuer_pub_key.ed25519)
                or bytes(parent.subject_pub_key.ml_dsa_65) != bytes(child.issuer_pub_key.ml_dsa_65)):
            raise InvalidConfigError("delegations must be root side first, each issued by the previous subject")
    return ClientConfig(raw["endpoint"], raw["audience"], raw["verifier_id"], raw["workspace_id"],
                        raw["connection_id"], tuple(certs))
