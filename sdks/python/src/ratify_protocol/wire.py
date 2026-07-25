"""Wire codec for Ratify Protocol v1 signed structures.

The wire JSON shape is normative (SPEC §5.7, §5.8, §6): object keys in
lexicographic order, byte fields as base64-standard strings with padding,
optional fields omitted when absent. Encoders emit canonical JSON text
(via canonical_json), so encode output is exactly the canonical bytes.

Decoders are strict and fail closed:
  - malformed or non-canonical base64 is rejected;
  - required fields and types are validated;
  - cryptographic byte lengths are validated against the protocol constants
    (Ed25519 / ML-DSA-65 key and signature sizes);
  - unknown fields in signed structures (DelegationCert, Constraint,
    HybridPublicKey, HybridSignature, ProofBundle, SessionToken) are
    rejected;
  - duplicated JSON object keys are rejected at every nesting depth
    (json decodes string escapes before keys are compared, so a
    Unicode-escaped spelling of a key collides with its literal form);
  - errors name the offending field and the reason.

Round-trip guarantees for canonical inputs:
  decode_proof_bundle(encode_proof_bundle(b)) equals b, and
  encode_proof_bundle(decode_proof_bundle(json)) is byte-identical to the
  canonical JSON of the original document.
"""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .canonical import canonical_json
from .types import (
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    MLDSA65_PUBLIC_KEY_SIZE,
    MLDSA65_SIGNATURE_SIZE,
    Constraint,
    DelegationCert,
    HybridPublicKey,
    HybridSignature,
    ProofBundle,
    SessionToken,
)

# Fixed size for the 32-byte binding/digest fields on the wire (SPEC §5.8
# session_context / stream_id, §6.4.1 challenge, §16.3 SessionToken
# chain_hash / mac).
_BINDING_SIZE = 32


# ============================================================================
# Encoders
# ============================================================================

def encode_delegation_cert(cert: DelegationCert) -> str:
    """Encode a DelegationCert as canonical wire JSON (SPEC §5.7)."""
    return canonical_json(_cert_wire_dict(cert)).decode("utf-8")


def encode_proof_bundle(bundle: ProofBundle) -> str:
    """Encode a ProofBundle as canonical wire JSON (SPEC §5.8)."""
    out: dict[str, Any] = {
        "agent_id": bundle.agent_id,
        "agent_pub_key": bundle.agent_pub_key,
        "challenge": bundle.challenge,
        "challenge_at": bundle.challenge_at,
        "challenge_sig": bundle.challenge_sig,
        "delegations": [_cert_wire_dict(c) for c in bundle.delegations],
    }
    # Optional v1.1 fields carry Go's omitempty semantics: empty values are
    # omitted from the wire form.
    if bundle.session_context:
        out["session_context"] = bundle.session_context
    if bundle.stream_id:
        out["stream_id"] = bundle.stream_id
    if bundle.stream_seq:
        out["stream_seq"] = bundle.stream_seq
    return canonical_json(out).decode("utf-8")


def encode_session_token(token: SessionToken) -> str:
    """Encode a SessionToken as canonical wire JSON (SPEC §16.3)."""
    return canonical_json({
        "agent_id": token.agent_id,
        "agent_pub_key": token.agent_pub_key,
        "chain_hash": token.chain_hash,
        "granted_scope": token.granted_scope,
        "human_id": token.human_id,
        "issued_at": token.issued_at,
        "mac": token.mac,
        "session_id": token.session_id,
        "valid_until": token.valid_until,
        "version": token.version,
    }).decode("utf-8")


def _cert_wire_dict(cert: DelegationCert) -> dict[str, Any]:
    return {
        "cert_id": cert.cert_id,
        "constraints": [c.to_canonical_dict() for c in (cert.constraints or [])],
        "expires_at": cert.expires_at,
        "issued_at": cert.issued_at,
        "issuer_id": cert.issuer_id,
        "issuer_pub_key": cert.issuer_pub_key,
        "scope": cert.scope,
        "signature": cert.signature,
        "subject_id": cert.subject_id,
        "subject_pub_key": cert.subject_pub_key,
        "version": cert.version,
    }


# ============================================================================
# Decoders
# ============================================================================

def decode_delegation_cert(data: str | bytes) -> DelegationCert:
    """Decode a DelegationCert from wire JSON.

    Strict: rejects unknown fields, malformed base64, and wrong
    cryptographic byte lengths.
    """
    return _decode_cert_obj(_as_object(_parse(data), "DelegationCert"), "DelegationCert")


def decode_proof_bundle(data: str | bytes) -> ProofBundle:
    """Decode a ProofBundle from wire JSON.

    Strict: rejects unknown fields, malformed base64, wrong cryptographic
    byte lengths, and unpaired v1.1 stream fields.
    """
    path = "ProofBundle"
    obj = _as_object(_parse(data), path)
    _check_keys(obj, (
        "agent_id", "agent_pub_key", "challenge", "challenge_at",
        "challenge_sig", "delegations", "session_context", "stream_id",
        "stream_seq",
    ), path)
    delegations_raw = _get_array(obj, "delegations", path)
    if not delegations_raw:
        raise ValueError(
            f"wire: {path}.delegations: must contain at least one certificate (SPEC §10)"
        )
    has_stream_id = "stream_id" in obj
    has_stream_seq = "stream_seq" in obj
    if has_stream_id != has_stream_seq:
        raise ValueError(
            f"wire: {path}: stream_id and stream_seq must be present together (SPEC §5.8)"
        )
    stream_id = b""
    stream_seq = 0
    if has_stream_id:
        stream_id = _get_bytes(obj, "stream_id", path, _BINDING_SIZE)
        stream_seq = _get_int(obj, "stream_seq", path)
        if stream_seq < 1:
            raise ValueError(f"wire: {path}.stream_seq: must be >= 1, got {stream_seq}")
    return ProofBundle(
        agent_id=_get_string(obj, "agent_id", path),
        agent_pub_key=_decode_pub_key_obj(obj.get("agent_pub_key"), f"{path}.agent_pub_key"),
        delegations=[
            _decode_cert_obj(
                _as_object(c, f"{path}.delegations[{i}]"), f"{path}.delegations[{i}]"
            )
            for i, c in enumerate(delegations_raw)
        ],
        challenge=_get_bytes(obj, "challenge", path, _BINDING_SIZE),
        challenge_at=_get_int(obj, "challenge_at", path),
        challenge_sig=_decode_signature_obj(obj.get("challenge_sig"), f"{path}.challenge_sig"),
        session_context=(
            _get_bytes(obj, "session_context", path, _BINDING_SIZE)
            if "session_context" in obj
            else b""
        ),
        stream_id=stream_id,
        stream_seq=stream_seq,
    )


def decode_session_token(data: str | bytes) -> SessionToken:
    """Decode a SessionToken from wire JSON.

    Strict: rejects unknown fields, malformed base64, and wrong byte lengths.
    """
    path = "SessionToken"
    obj = _as_object(_parse(data), path)
    _check_keys(obj, (
        "agent_id", "agent_pub_key", "chain_hash", "granted_scope",
        "human_id", "issued_at", "mac", "session_id", "valid_until",
        "version",
    ), path)
    return SessionToken(
        version=_get_int(obj, "version", path),
        session_id=_get_string(obj, "session_id", path),
        agent_id=_get_string(obj, "agent_id", path),
        agent_pub_key=_decode_pub_key_obj(obj.get("agent_pub_key"), f"{path}.agent_pub_key"),
        human_id=_get_string(obj, "human_id", path),
        granted_scope=_get_string_array(obj, "granted_scope", path),
        issued_at=_get_int(obj, "issued_at", path),
        valid_until=_get_int(obj, "valid_until", path),
        chain_hash=_get_bytes(obj, "chain_hash", path, _BINDING_SIZE),
        mac=_get_bytes(obj, "mac", path, _BINDING_SIZE),
    )


# ----- Nested structures -----

def _decode_cert_obj(obj: dict, path: str) -> DelegationCert:
    _check_keys(obj, (
        "cert_id", "constraints", "expires_at", "issued_at", "issuer_id",
        "issuer_pub_key", "scope", "signature", "subject_id",
        "subject_pub_key", "version",
    ), path)
    constraints_raw = _get_array(obj, "constraints", path)
    return DelegationCert(
        cert_id=_get_string(obj, "cert_id", path),
        version=_get_int(obj, "version", path),
        issuer_id=_get_string(obj, "issuer_id", path),
        issuer_pub_key=_decode_pub_key_obj(obj.get("issuer_pub_key"), f"{path}.issuer_pub_key"),
        subject_id=_get_string(obj, "subject_id", path),
        subject_pub_key=_decode_pub_key_obj(obj.get("subject_pub_key"), f"{path}.subject_pub_key"),
        scope=_get_string_array(obj, "scope", path),
        constraints=[
            _decode_constraint_obj(
                _as_object(c, f"{path}.constraints[{i}]"), f"{path}.constraints[{i}]"
            )
            for i, c in enumerate(constraints_raw)
        ],
        issued_at=_get_int(obj, "issued_at", path),
        expires_at=_get_int(obj, "expires_at", path),
        signature=_decode_signature_obj(obj.get("signature"), f"{path}.signature"),
    )


def _decode_pub_key_obj(raw: Any, path: str) -> HybridPublicKey:
    obj = _as_object(raw, path)
    _check_keys(obj, ("ed25519", "ml_dsa_65"), path)
    return HybridPublicKey(
        ed25519=_get_bytes(obj, "ed25519", path, ED25519_PUBLIC_KEY_SIZE),
        ml_dsa_65=_get_bytes(obj, "ml_dsa_65", path, MLDSA65_PUBLIC_KEY_SIZE),
    )


def _decode_signature_obj(raw: Any, path: str) -> HybridSignature:
    obj = _as_object(raw, path)
    _check_keys(obj, ("ed25519", "ml_dsa_65"), path)
    return HybridSignature(
        ed25519=_get_bytes(obj, "ed25519", path, ED25519_SIGNATURE_SIZE),
        ml_dsa_65=_get_bytes(obj, "ml_dsa_65", path, MLDSA65_SIGNATURE_SIZE),
    )


def _decode_constraint_obj(obj: dict, path: str) -> Constraint:
    """Decode one tagged Constraint object.

    Per-kind canonical field sets (SPEC §5.7.2; mirrors
    Constraint.to_canonical_dict): kind-relevant fields are always present,
    other fields never appear. Unknown constraint types carry only the tag —
    the verifier rejects them with constraint_unknown, but they must decode
    so they can reach the verifier.
    """
    ctype = _get_string(obj, "type", path)
    kwargs: dict[str, Any] = {"type": ctype}
    if ctype == "geo_circle":
        _check_keys(obj, ("lat", "lon", "radius_m", "type"), path)
        kwargs["lat"] = _get_number(obj, "lat", path)
        kwargs["lon"] = _get_number(obj, "lon", path)
        kwargs["radius_m"] = _get_number(obj, "radius_m", path)
    elif ctype == "geo_polygon":
        _check_keys(obj, ("points", "type"), path)
        kwargs["points"] = _get_points(obj, "points", path)
    elif ctype == "geo_bbox":
        _check_keys(
            obj,
            ("max_alt_m", "max_lat", "max_lon", "min_alt_m", "min_lat", "min_lon", "type"),
            path,
        )
        kwargs["max_lat"] = _get_number(obj, "max_lat", path)
        kwargs["max_lon"] = _get_number(obj, "max_lon", path)
        kwargs["min_lat"] = _get_number(obj, "min_lat", path)
        kwargs["min_lon"] = _get_number(obj, "min_lon", path)
        has_min_alt = "min_alt_m" in obj
        has_max_alt = "max_alt_m" in obj
        if has_min_alt != has_max_alt:
            raise ValueError(f"wire: {path}: min_alt_m and max_alt_m must be present together")
        if has_min_alt:
            kwargs["min_alt_m"] = _get_number(obj, "min_alt_m", path)
            kwargs["max_alt_m"] = _get_number(obj, "max_alt_m", path)
    elif ctype == "time_window":
        _check_keys(obj, ("end", "start", "type", "tz"), path)
        kwargs["start"] = _get_string(obj, "start", path)
        kwargs["end"] = _get_string(obj, "end", path)
        kwargs["tz"] = _get_string(obj, "tz", path)
    elif ctype == "max_speed_mps":
        _check_keys(obj, ("max_mps", "type"), path)
        kwargs["max_mps"] = _get_number(obj, "max_mps", path)
    elif ctype == "max_amount":
        _check_keys(obj, ("currency", "max_amount", "type"), path)
        kwargs["currency"] = _get_string(obj, "currency", path)
        kwargs["max_amount"] = _get_number(obj, "max_amount", path)
    elif ctype == "max_rate":
        _check_keys(obj, ("count", "type", "window_s"), path)
        kwargs["count"] = _get_int(obj, "count", path)
        kwargs["window_s"] = _get_int(obj, "window_s", path)
    else:
        # Unknown kind: the canonical form carries only the tag.
        _check_keys(obj, ("type",), path)
    return Constraint(**kwargs)


# ============================================================================
# Strict field accessors
# ============================================================================

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    """object_pairs_hook that fails closed on duplicated object keys.

    json.loads would otherwise keep the last occurrence silently, letting a
    document carry two values for the same field where only one survives
    decoding.
    """
    obj: dict = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f'wire: duplicate key "{k}" in JSON object')
        obj[k] = v
    return obj


def _parse(data: str | bytes) -> Any:
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"wire: invalid JSON: {e}") from e


def _as_object(v: Any, path: str) -> dict:
    if not isinstance(v, dict):
        raise ValueError(f"wire: {path}: expected JSON object")
    return v


def _check_keys(obj: dict, allowed: tuple[str, ...], path: str) -> None:
    for k in obj:
        if k not in allowed:
            raise ValueError(f'wire: {path}: unknown field "{k}"')


def _get_string(obj: dict, key: str, path: str) -> str:
    v = obj.get(key)
    if not isinstance(v, str):
        raise ValueError(f"wire: {path}.{key}: expected string")
    return v


def _get_number(obj: dict, key: str, path: str) -> float:
    v = obj.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError(f"wire: {path}.{key}: expected number")
    return v


def _get_int(obj: dict, key: str, path: str) -> int:
    v = obj.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"wire: {path}.{key}: expected integer")
    return v


def _get_array(obj: dict, key: str, path: str) -> list:
    v = obj.get(key)
    if not isinstance(v, list):
        raise ValueError(f"wire: {path}.{key}: expected array")
    return v


def _get_string_array(obj: dict, key: str, path: str) -> list[str]:
    arr = _get_array(obj, key, path)
    for i, s in enumerate(arr):
        if not isinstance(s, str):
            raise ValueError(f"wire: {path}.{key}[{i}]: expected string")
    return list(arr)


def _get_points(obj: dict, key: str, path: str) -> list[list[float]]:
    arr = _get_array(obj, key, path)
    out: list[list[float]] = []
    for i, p in enumerate(arr):
        if (
            not isinstance(p, list)
            or len(p) != 2
            or any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in p)
        ):
            raise ValueError(f"wire: {path}.{key}[{i}]: expected [lat, lon] number pair")
        out.append(list(p))
    return out


def _get_bytes(obj: dict, key: str, path: str, expected_len: int) -> bytes:
    v = obj.get(key)
    if not isinstance(v, str):
        raise ValueError(f"wire: {path}.{key}: expected base64 string")
    return _decode_base64_strict(v, f"{path}.{key}", expected_len)


def _decode_base64_strict(s: str, path: str, expected_len: int) -> bytes:
    """Standard base64 with padding, rejecting malformed and non-canonical
    encodings (the re-encode comparison catches nonzero trailing bits and
    missing padding), so decode(encode(x)) is byte-exact."""
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"wire: {path}: malformed base64: {e}") from e
    if base64.b64encode(raw).decode("ascii") != s:
        raise ValueError(f"wire: {path}: non-canonical base64")
    if len(raw) != expected_len:
        raise ValueError(f"wire: {path}: expected {expected_len} bytes, got {len(raw)}")
    return raw
