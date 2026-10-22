"""Protocol v2 wire objects: delegation certificates, proof bundles, and
issuer status objects (mirrors Go protocol_v2_wire.go).

Decoders are strict and bounded. Field semantics follow Go encoding/json: a
JSON ``null`` or absent nested field takes its zero value (the top-level
required-field check rejects null where the schema forbids it), unknown
fields and wrong JSON types are rejected, and every failure is classified.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, replace
from hashlib import sha384
from typing import Any, Callable, Optional

from . import _v2json
from ._v2json import MAX_SAFE_INTEGER, canonical
from .errors_v2 import V2Error, V2ErrorClass, classify
from .resource_path import is_canonical_constraint_type, validate_params_value
from .scope import CUSTOM_SCOPE_PREFIX, scope_wildcards, vocabulary
from .signing_v2 import (
    CHALLENGE_PRESENTATION,
    DELEGATION_CERTIFICATE,
    REVOCATION_LIST,
    REVOCATION_PUSH,
    equal_public_keys,
    key_id_v2,
    public_key_of,
    _sign_v2_statement,
    verify_v2_statement,
)
from .types import (
    MAX_CONSTRAINTS_PER_CERT,
    MAX_DELEGATION_CHAIN_DEPTH,
    MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_PROOF_BUNDLE_BYTES,
    MAX_SCOPE_LENGTH_BYTES,
    MAX_SCOPES_PER_CERT,
    Constraint,
    HybridPrivateKey,
    HybridPublicKey,
    HybridSignature,
)

RECEIVER_AUDIENCE = "ratify.receiver_audience"
SCOPE_IDENTITY_DELEGATE = "identity:delegate"

# ---------------------------------------------------------------------------
# Generic strict field access (Go encoding/json semantics)


def _run(class_: str, fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except V2Error:
        raise
    except (ValueError, TypeError, KeyError, IndexError, OverflowError) as exc:
        raise classify(class_, exc) from exc


def require_fields(obj: Any, names, nullable=()) -> dict:
    """Go ``requireV2Fields``: object, required members present, non-null."""
    if not isinstance(obj, dict):
        raise ValueError("wire v2: expected a JSON object")
    for name in names:
        if name not in obj:
            raise ValueError(f'wire v2: required field "{name}" is missing')
        if obj[name] is None and name not in nullable:
            raise ValueError(f'wire v2: required field "{name}" must not be null')
    return obj


def check_keys(obj: dict, allowed, where: str = "object") -> None:
    for key in obj:
        if key not in allowed:
            raise ValueError(f'wire v2: {where}: unknown field "{key}"')


def get_str(obj: dict, key: str) -> str:
    value = obj.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"wire v2: {key} must be a string")
    return value


def get_int(obj: dict, key: str, lo: int = -(2**63), hi: int = 2**63 - 1) -> int:
    value = obj.get(key)
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or isinstance(value, float):
        raise ValueError(f"wire v2: {key} must be an integer")
    if value < lo or value > hi:
        raise ValueError(f"wire v2: {key} is out of range")
    return value


def get_float(obj: dict, key: str) -> float:
    value = obj.get(key)
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"wire v2: {key} must be a number")
    return float(value)


def decode_bytes_value(value: Any, key: str) -> Optional[bytes]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"wire v2: {key} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"wire v2: {key} is not valid base64") from exc


def get_bytes(obj: dict, key: str) -> Optional[bytes]:
    return decode_bytes_value(obj.get(key), key)


def get_str_list(obj: dict, key: str) -> Optional[list[str]]:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"wire v2: {key} must be an array")
    out = []
    for item in value:
        if item is None:
            out.append("")
        elif isinstance(item, str):
            out.append(item)
        else:
            raise ValueError(f"wire v2: {key} must contain strings")
    return out


def get_obj(obj: dict, key: str) -> dict:
    value = obj.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"wire v2: {key} must be an object")
    return value


def decode_public_key(value: Any, key: str = "public key") -> HybridPublicKey:
    if value is None:
        return HybridPublicKey(ed25519=b"", ml_dsa_65=b"")
    if not isinstance(value, dict):
        raise ValueError(f"wire v2: {key} must be an object")
    check_keys(value, ("ed25519", "ml_dsa_65"), key)
    return HybridPublicKey(
        ed25519=get_bytes(value, "ed25519") or b"", ml_dsa_65=get_bytes(value, "ml_dsa_65") or b""
    )


def decode_signature(value: Any, key: str = "signature") -> HybridSignature:
    pub = decode_public_key(value, key)
    return HybridSignature(ed25519=pub.ed25519, ml_dsa_65=pub.ml_dsa_65)


def key_dict(key: HybridPublicKey | HybridSignature) -> dict:
    return {"ed25519": bytes(key.ed25519), "ml_dsa_65": bytes(key.ml_dsa_65)}


def valid_v2_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and _LOWER_HEX.fullmatch(value) is not None


def lower_hex_string(value: str) -> bool:
    return _LOWER_HEX_ANY.fullmatch(value) is not None


_LOWER_HEX = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_ANY = re.compile(r"[0-9a-f]*")


def valid_prefixed_digest_v2(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha384:")
        and len(value) == 7 + 96
        and re.fullmatch(r"[0-9a-f]{96}", value[7:]) is not None
    )


def validate_hybrid_signature_v2(sig: HybridSignature) -> None:
    if len(sig.ed25519) != 64 or len(sig.ml_dsa_65) != 3309:
        raise ValueError(
            "wire v2: signature must contain 64-byte Ed25519 and 3309-byte ML-DSA-65 components"
        )


def placeholder_signature_v2() -> HybridSignature:
    return HybridSignature(ed25519=bytes(64), ml_dsa_65=bytes(3309))


def utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


# ---------------------------------------------------------------------------
# Scopes


def _is_valid_scope(scope: str) -> bool:
    return (
        scope in _VOCABULARY
        or scope in scope_wildcards()
        or (scope.startswith(CUSTOM_SCOPE_PREFIX) and len(scope) > len(CUSTOM_SCOPE_PREFIX))
    )


_VOCABULARY = frozenset(vocabulary())


def validate_scopes_v2(scopes: list[str]) -> None:
    """Go ``ValidateScopesV2``."""
    if not scopes:
        raise ValueError("scope must be a non-empty array")
    for scope in scopes:
        if not _is_valid_scope(scope):
            raise ValueError(f"unknown scope {scope!r}: not in canonical vocabulary and not a custom: extension")
    seen = set()
    for scope in scopes:
        if scope == "custom:*":
            raise ValueError("custom:* is not a valid scope")
        if scope in seen:
            raise ValueError(f"duplicate scope {scope!r}")
        seen.add(scope)


def validate_required_scope_v2(scope: str) -> None:
    """Go ``ValidateRequiredScopeV2``: one registered canonical scope."""
    if (
        not isinstance(scope, str)
        or scope not in _VOCABULARY
        or scope in scope_wildcards()
        or scope.startswith(CUSTOM_SCOPE_PREFIX)
    ):
        raise ValueError("required scope must be one non-empty canonical scope")


# ---------------------------------------------------------------------------
# Constraints

_CONSTRAINT_FIELDS = frozenset({
    "count", "currency", "end", "lat", "lon", "max_alt_m", "max_amount", "max_lat",
    "max_lon", "max_mps", "min_alt_m", "min_lat", "min_lon", "params", "path_prefix",
    "points", "radius_m", "resource_id", "start", "type", "tz", "window_s",
})
_REQUIRED = {
    "geo_circle": ("lat", "lon", "radius_m"),
    "geo_polygon": ("points",),
    "geo_bbox": ("min_lat", "min_lon", "max_lat", "max_lon"),
    "time_window": ("start", "end", "tz"),
    "max_speed_mps": ("max_mps",),
    "max_amount": ("max_amount", "currency"),
    "max_rate": ("count", "window_s"),
    "resource_path": ("resource_id",),
}
_ALLOWED = {
    "geo_circle": ("type", "lat", "lon", "radius_m"),
    "geo_polygon": ("type", "points"),
    "geo_bbox": ("type", "min_lat", "min_lon", "max_lat", "max_lon", "min_alt_m", "max_alt_m"),
    "time_window": ("type", "start", "end", "tz"),
    "max_speed_mps": ("type", "max_mps"),
    "max_amount": ("type", "max_amount", "currency"),
    "max_rate": ("type", "count", "window_s"),
    "resource_path": ("type", "resource_id", "path_prefix"),
}
_FLOAT_FIELDS = ("lat", "lon", "max_alt_m", "max_amount", "max_lat", "max_lon", "max_mps",
                 "min_alt_m", "min_lat", "min_lon", "radius_m")
_STR_FIELDS = ("currency", "end", "start", "tz", "resource_id", "path_prefix")


def _check_v2_nulls(value: Any) -> None:
    if value is None:
        raise ValueError("null is not allowed in this v2 object")
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "params":
                continue
            _check_v2_nulls(item)
    elif isinstance(value, list):
        for item in value:
            _check_v2_nulls(item)


def _go_unmarshal_constraint(obj: dict) -> Constraint:
    """Go ``Constraint.UnmarshalJSON`` (alias decode with unknown-field rejection)."""
    if "path_prefix" in obj:
        pp = obj["path_prefix"]
        if pp is not None and not isinstance(pp, str):
            raise ValueError("constraint path_prefix must be a string")
        if not pp:
            raise ValueError("constraint path_prefix must not be empty or null")
    check_keys(obj, _CONSTRAINT_FIELDS, "constraint")
    kwargs: dict[str, Any] = {"type": get_str(obj, "type")}
    for name in _FLOAT_FIELDS:
        kwargs[name] = get_float(obj, name)
    for name in _STR_FIELDS:
        kwargs[name] = get_str(obj, name)
    kwargs["count"] = get_int(obj, "count")
    kwargs["window_s"] = get_int(obj, "window_s")
    points = obj.get("points")
    if points is not None:
        if not isinstance(points, list):
            raise ValueError("constraint points must be an array")
        parsed = []
        for point in points:
            if point is None:
                parsed.append([0.0, 0.0])
                continue
            if not isinstance(point, list) or len(point) != 2:
                raise ValueError("constraint points must be [lat, lon] pairs")
            pair = []
            for coordinate in point:
                if coordinate is None:
                    coordinate = 0.0
                if isinstance(coordinate, bool) or not isinstance(coordinate, (int, float)):
                    raise ValueError("constraint points must be numbers")
                pair.append(float(coordinate))
            parsed.append(pair)
        kwargs["points"] = parsed
    else:
        kwargs["points"] = None
    params = obj.get("params")
    if params is not None and not isinstance(params, dict):
        raise ValueError("constraint params must be an object")
    kwargs["params"] = params
    if kwargs["type"] == "resource_path":
        rid = obj.get("resource_id")
        if not isinstance(rid, str) or rid == "":
            raise ValueError("resource_path constraint requires a non-empty resource_id string")
    return Constraint(**kwargs)


def _plain_ints(value: Any) -> Any:
    """Params decode as Go map[string]any (numbers are float64)."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, list):
        return [_plain_ints(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain_ints(item) for key, item in value.items()}
    return value


def validate_v2_constraint_fields(raw: Any) -> Constraint:
    """Go ``validateV2ConstraintFields``; returns the decoded constraint."""
    _check_v2_nulls(raw)
    if not isinstance(raw, dict):
        raise ValueError("constraint must be an object")
    c = _go_unmarshal_constraint(raw)
    allowed = _ALLOWED.get(c.type, ())
    for key in raw:
        if key in allowed:
            continue
        if c.type == RECEIVER_AUDIENCE and key in ("type", "params"):
            continue
        if not allowed and c.type != RECEIVER_AUDIENCE and key in ("type", "params"):
            continue
        raise ValueError(f"field {key!r} is not allowed for constraint type {c.type!r}")
    for name in _REQUIRED.get(c.type, ()):
        if name not in raw:
            raise ValueError(f"constraint type {c.type!r} requires field {name!r}")
    if c.type == "geo_bbox" and (("min_alt_m" in raw) != ("max_alt_m" in raw)):
        raise ValueError("geo_bbox altitude bounds must be both present or both absent")
    if c.type == RECEIVER_AUDIENCE:
        params = raw.get("params")
        if not isinstance(params, dict):
            raise ValueError("receiver audience requires params object")
        exact = params.get("exact_receiver_ids")
        domains = params.get("trust_domain_ids")
        if not isinstance(exact, list) or not isinstance(domains, list) or not all(
            isinstance(v, str) or v is None for v in exact + domains
        ):
            raise ValueError("receiver audience requires exact_receiver_ids and trust_domain_ids arrays")
        exact = ["" if v is None else v for v in exact]
        domains = ["" if v is None else v for v in domains]
        if len(exact) + len(domains) == 0:
            raise ValueError("receiver audience must name an exact receiver or trust domain")
        for values in (exact, domains):
            seen = set()
            for value in values:
                if value == "" or value in seen:
                    raise ValueError("receiver audience IDs must be non-empty and unique")
                seen.add(value)
        has_age = "max_membership_age_seconds" in params
        age = params.get("max_membership_age_seconds")
        if domains and (not has_age or age is None):
            raise ValueError("receiver audience trust domains require max_membership_age_seconds")
        if has_age:
            if age is None:
                age = 0
            if isinstance(age, bool) or not isinstance(age, int) or isinstance(age, float) or age <= 0 or age > MAX_SAFE_INTEGER:
                raise ValueError("max_membership_age_seconds must be a positive safe integer")
        if not domains and has_age:
            raise ValueError("receiver audience without trust domains must omit max_membership_age_seconds")
        validate_params_value(_plain_ints(params), 0)
        for key in params:
            if key not in ("exact_receiver_ids", "trust_domain_ids", "max_membership_age_seconds"):
                raise ValueError(f"unknown receiver audience parameter {key!r}")
    return c


def constraint_canonical_dict(c: Constraint) -> dict:
    """Go ``Constraint.MarshalJSON``."""
    out: dict[str, Any] = {"type": c.type}
    t = c.type
    if t == "geo_circle":
        out.update(lat=float(c.lat), lon=float(c.lon), radius_m=float(c.radius_m))
    elif t == "geo_polygon":
        out["points"] = None if c.points is None else [[float(p[0]), float(p[1])] for p in c.points]
    elif t == "geo_bbox":
        out.update(max_lat=float(c.max_lat), max_lon=float(c.max_lon), min_lat=float(c.min_lat), min_lon=float(c.min_lon))
        if c.min_alt_m != 0 or c.max_alt_m != 0:
            out.update(max_alt_m=float(c.max_alt_m), min_alt_m=float(c.min_alt_m))
    elif t == "time_window":
        out.update(end=c.end, start=c.start, tz=c.tz)
    elif t == "max_speed_mps":
        out["max_mps"] = float(c.max_mps)
    elif t == "max_amount":
        out.update(currency=c.currency, max_amount=float(c.max_amount))
    elif t == "max_rate":
        out.update(count=c.count, window_s=c.window_s)
    elif t == "resource_path":
        if not c.resource_id:
            raise ValueError("resource_path constraint requires a non-empty resource_id")
        out["resource_id"] = c.resource_id
        if c.path_prefix:
            out["path_prefix"] = c.path_prefix
    else:
        if c.params is not None:
            validate_params_value(_plain_ints(c.params), 0)
            out["params"] = _plain_ints(c.params)
    if t != "" and c.params is not None and is_canonical_constraint_type(t):
        raise ValueError(f"canonical constraint type {t!r} must not carry params")
    return out


def constraint_canonical_json(c: Constraint) -> bytes:
    return canonical(constraint_canonical_dict(c))


# ---------------------------------------------------------------------------
# Delegation certificates


@dataclass
class DelegationCertV2:
    version: int
    cert_id: str
    issuer_id: str
    issuer_pub_key: HybridPublicKey
    subject_id: str
    subject_pub_key: HybridPublicKey
    scope: Optional[list[str]]
    constraints: Optional[list[Constraint]]
    issued_at: int
    expires_at: int
    signature: HybridSignature


DELEGATION_V2_FIELDS = ("version", "cert_id", "issuer_id", "issuer_pub_key", "subject_id",
                        "subject_pub_key", "scope", "constraints", "issued_at", "expires_at", "signature")


def _validate_v2_scope_array(value: Any) -> None:
    if not isinstance(value, list):
        raise ValueError("wire v2: scope must be an array of strings")
    if len(value) > MAX_SCOPES_PER_CERT:
        raise ValueError("wire v2: scope count exceeds protocol bound")
    for i, item in enumerate(value):
        if item is not None and not isinstance(item, str):
            raise ValueError(f"wire v2: scope {i} must be a bounded string")
        if item is not None and utf8_len(item) > MAX_SCOPE_LENGTH_BYTES:
            raise ValueError(f"wire v2: scope {i} must be a bounded string")


def _cert_from_obj(obj: dict) -> DelegationCertV2:
    """Pre-struct shape checks plus the strict struct decode."""
    raw_constraints = obj.get("constraints")
    if not isinstance(raw_constraints, list):
        raise ValueError("wire v2: constraints must be an array")
    _validate_v2_scope_array(obj.get("scope"))
    constraints = [validate_v2_constraint_fields(raw) for raw in raw_constraints]
    check_keys(obj, DELEGATION_V2_FIELDS, "delegation")
    return DelegationCertV2(
        version=get_int(obj, "version"),
        cert_id=get_str(obj, "cert_id"),
        issuer_id=get_str(obj, "issuer_id"),
        issuer_pub_key=decode_public_key(obj.get("issuer_pub_key"), "issuer_pub_key"),
        subject_id=get_str(obj, "subject_id"),
        subject_pub_key=decode_public_key(obj.get("subject_pub_key"), "subject_pub_key"),
        scope=get_str_list(obj, "scope"),
        constraints=constraints,
        issued_at=get_int(obj, "issued_at"),
        expires_at=get_int(obj, "expires_at"),
        signature=decode_signature(obj.get("signature")),
    )


def validate_delegation_cert_v2(c: DelegationCertV2) -> None:
    """Go ``validateDelegationCertV2`` (raises V2Error key_id_mismatch or ValueError)."""
    if c.version != 2:
        raise ValueError("version must be 2")
    for value in (c.issued_at, c.expires_at):
        if value < -MAX_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise ValueError("issued_at and expires_at must be safe integers")
    if c.cert_id == "" or utf8_len(c.cert_id) > MAX_IDENTIFIER_LENGTH_BYTES:
        raise ValueError("cert_id must be non-empty and within the identifier byte limit")
    if not valid_v2_id(c.issuer_id) or not valid_v2_id(c.subject_id):
        raise ValueError("issuer_id and subject_id must be 64 lowercase hexadecimal characters")
    issuer = key_id_v2(c.issuer_pub_key)
    subject = key_id_v2(c.subject_pub_key)
    if c.issuer_id != issuer or c.subject_id != subject:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "key ID does not match complete public key")
    if c.scope is None:
        raise ValueError("scope must be an array")
    for scope in c.scope:
        if utf8_len(scope) > MAX_SCOPE_LENGTH_BYTES:
            raise ValueError("scope exceeds the protocol byte limit")
    if c.constraints is None:
        raise ValueError("constraints must be an array")
    if len(c.scope) > MAX_SCOPES_PER_CERT or len(c.constraints) > MAX_CONSTRAINTS_PER_CERT:
        raise ValueError("scope or constraint count exceeds protocol bound")
    for constraint in c.constraints:
        encoded = constraint_canonical_json(constraint)
        validate_v2_constraint_fields(_v2json.parse(encoded))


def _cert_canonical_dict(c: DelegationCertV2, *, signature: bool, constraints_default: bool) -> dict:
    constraints = c.constraints
    if constraints is None and constraints_default:
        constraints = []
    out = {
        "cert_id": c.cert_id,
        "constraints": None if constraints is None else [constraint_canonical_dict(x) for x in constraints],
        "expires_at": c.expires_at,
        "issued_at": c.issued_at,
        "issuer_id": c.issuer_id,
        "issuer_pub_key": key_dict(c.issuer_pub_key),
        "scope": c.scope,
        "subject_id": c.subject_id,
        "subject_pub_key": key_dict(c.subject_pub_key),
        "version": c.version,
    }
    if signature:
        out["signature"] = key_dict(c.signature)
    return out


def cert_signable_bytes_v2(c: DelegationCertV2) -> bytes:
    return canonical(_cert_canonical_dict(c, signature=False, constraints_default=True))


def decode_delegation_cert_v2(data: bytes) -> DelegationCertV2:
    def run() -> DelegationCertV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError("wire v2: certificate exceeds MAX_PROOF_BUNDLE_BYTES")
        obj = _v2json.check_wire_json(data)
        require_fields(obj, DELEGATION_V2_FIELDS)
        cert = _cert_from_obj(obj)
        validate_delegation_cert_v2(cert)
        validate_hybrid_signature_v2(cert.signature)
        return cert

    return _run(V2ErrorClass.MALFORMED, run)


def encode_delegation_cert_v2(c: DelegationCertV2) -> bytes:
    validate_delegation_cert_v2(c)
    validate_hybrid_signature_v2(c.signature)
    encoded = canonical(_cert_canonical_dict(c, signature=True, constraints_default=False))
    decode_delegation_cert_v2(encoded)
    return encoded


def verify_delegation_cert_v2_signature(cert: DelegationCertV2) -> None:
    if cert is None:
        raise V2Error(V2ErrorClass.MALFORMED, "v2 delegation certificate is nil")

    def structure() -> bytes:
        validate_delegation_cert_v2(cert)
        validate_hybrid_signature_v2(cert.signature)
        return cert_signable_bytes_v2(cert)

    signable = _run(V2ErrorClass.MALFORMED, structure)
    verify_v2_statement(DELEGATION_CERTIFICATE, signable, cert.signature, cert.issuer_pub_key)


def sign_delegation_cert_v2(cert: DelegationCertV2, issuer_key: HybridPrivateKey) -> DelegationCertV2:
    issuer_pub = public_key_of(issuer_key)
    issuer_id = key_id_v2(issuer_pub)
    if cert.issuer_id != issuer_id or not equal_public_keys(cert.issuer_pub_key, issuer_pub):
        raise ValueError("v2 issuer key does not match certificate issuer")
    validate_delegation_cert_v2(cert)
    validate_scopes_v2(cert.scope or [])
    prepared = decode_delegation_cert_v2(encode_delegation_cert_v2(replace(cert, signature=placeholder_signature_v2())))
    signable = cert_signable_bytes_v2(prepared)
    prepared.signature = _sign_v2_statement(DELEGATION_CERTIFICATE, signable, issuer_key)
    signed = decode_delegation_cert_v2(encode_delegation_cert_v2(prepared))
    verify_v2_statement(DELEGATION_CERTIFICATE, signable, signed.signature, issuer_pub)
    return signed


# ---------------------------------------------------------------------------
# Proof bundles


@dataclass
class ProofBundleV2:
    version: int
    verifier_id: str
    agent_id: str
    agent_pub_key: HybridPublicKey
    delegations: Optional[list[DelegationCertV2]]
    delegation_digest: bytes
    challenge: bytes
    challenge_at: int
    challenge_sig: HybridSignature
    session_context: Optional[bytes] = None
    stream_id: Optional[bytes] = None
    stream_seq: Optional[int] = None


PROOF_BUNDLE_V2_FIELDS = ("version", "verifier_id", "agent_id", "agent_pub_key", "delegations",
                          "delegation_digest", "challenge", "challenge_at", "challenge_sig",
                          "session_context", "stream_id", "stream_seq")


def decode_proof_bundle_v2(data: bytes) -> ProofBundleV2:
    def run() -> ProofBundleV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError(f"wire v2: proof bundle exceeds MAX_PROOF_BUNDLE_BYTES ({MAX_PROOF_BUNDLE_BYTES})")
        obj = _v2json.check_wire_json(data, ("delegation_digest",))
        require_fields(obj, PROOF_BUNDLE_V2_FIELDS, ("session_context", "stream_id", "stream_seq"))
        raw_delegations = obj.get("delegations")
        if not isinstance(raw_delegations, list):
            raise ValueError("wire v2: delegations must be an array")
        delegations = []
        for raw_cert in raw_delegations:
            require_fields(raw_cert, DELEGATION_V2_FIELDS)
            delegations.append(_cert_from_obj(raw_cert))
        check_keys(obj, PROOF_BUNDLE_V2_FIELDS, "proof bundle")
        stream_seq = obj.get("stream_seq")
        if stream_seq is not None:
            stream_seq = get_int(obj, "stream_seq")
        bundle = ProofBundleV2(
            version=get_int(obj, "version"),
            verifier_id=get_str(obj, "verifier_id"),
            agent_id=get_str(obj, "agent_id"),
            agent_pub_key=decode_public_key(obj.get("agent_pub_key"), "agent_pub_key"),
            delegations=delegations,
            delegation_digest=get_bytes(obj, "delegation_digest") or b"",
            challenge=get_bytes(obj, "challenge") or b"",
            challenge_at=get_int(obj, "challenge_at"),
            challenge_sig=decode_signature(obj.get("challenge_sig"), "challenge_sig"),
            session_context=get_bytes(obj, "session_context"),
            stream_id=get_bytes(obj, "stream_id"),
            stream_seq=stream_seq,
        )
        if bundle.version != 2:
            raise ValueError("wire v2: version must be 2")
        if not valid_v2_id(bundle.verifier_id) or not valid_v2_id(bundle.agent_id):
            raise ValueError("wire v2: verifier_id and agent_id must be 64 lowercase hexadecimal characters")
        if len(delegations) > MAX_DELEGATION_CHAIN_DEPTH:
            raise ValueError("wire v2: delegation chain exceeds MAX_DELEGATION_CHAIN_DEPTH")
        if len(bundle.challenge) != 32:
            raise ValueError("wire v2: challenge must be 32 bytes")
        if len(bundle.delegation_digest) != 48:
            raise ValueError("wire v2: delegation_digest must be 48 bytes")
        if bundle.session_context is not None and len(bundle.session_context) != 32:
            raise ValueError("wire v2: session_context must be null or 32 bytes")
        if (bundle.stream_id is None) != (bundle.stream_seq is None):
            raise ValueError("wire v2: stream_id and stream_seq must both be null or both set")
        if bundle.stream_id is not None and (len(bundle.stream_id) != 32 or bundle.stream_seq <= 0):
            raise ValueError("wire v2: bound stream requires 32-byte stream_id and positive stream_seq")
        if bundle.stream_seq is not None and bundle.stream_seq > MAX_SAFE_INTEGER:
            raise ValueError("wire v2: stream_seq exceeds the safe integer range")
        validate_hybrid_signature_v2(bundle.challenge_sig)
        for cert in delegations:
            validate_delegation_cert_v2(cert)
            validate_hybrid_signature_v2(cert.signature)
        return bundle

    return _run(V2ErrorClass.MALFORMED, run)


def _bundle_canonical_dict(b: ProofBundleV2) -> dict:
    return {
        "agent_id": b.agent_id,
        "agent_pub_key": key_dict(b.agent_pub_key),
        "challenge": bytes(b.challenge),
        "challenge_at": b.challenge_at,
        "challenge_sig": key_dict(b.challenge_sig),
        "delegation_digest": bytes(b.delegation_digest),
        "delegations": None if b.delegations is None else [
            _cert_canonical_dict(c, signature=True, constraints_default=False) for c in b.delegations
        ],
        "session_context": b.session_context,
        "stream_id": b.stream_id,
        "stream_seq": b.stream_seq,
        "verifier_id": b.verifier_id,
        "version": b.version,
    }


def encode_proof_bundle_v2(b: ProofBundleV2) -> bytes:
    if b is None:
        raise ValueError("v2 proof bundle is nil")
    encoded = canonical(_bundle_canonical_dict(b))
    try:
        decode_proof_bundle_v2(encoded)
    except V2Error as exc:
        raise V2Error(exc.error_class, f"invalid v2 proof bundle: {exc}") from exc
    return encoded


def presentation_signable_bytes_v2(b: ProofBundleV2) -> bytes:
    return canonical({
        "agent_id": b.agent_id,
        "agent_pub_key": key_dict(b.agent_pub_key),
        "challenge": bytes(b.challenge),
        "challenge_at": b.challenge_at,
        "delegation_digest": bytes(b.delegation_digest),
        "session_context": b.session_context,
        "stream_id": b.stream_id,
        "stream_seq": b.stream_seq,
        "verifier_id": b.verifier_id,
        "version": b.version,
    })


def delegation_digest_v2(certs: list[DelegationCertV2]) -> bytes:
    ordered = [_cert_canonical_dict(c, signature=True, constraints_default=True) for c in certs]
    return sha384(b"ratify-protocol-delegations-v2\x00" + canonical(ordered)).digest()


def bundle_hash_v2(bundle: ProofBundleV2) -> str:
    """BundleHashV2: ``sha384:`` hex of the complete canonical signed bundle."""
    encoded = encode_proof_bundle_v2(bundle)
    return "sha384:" + sha384(b"ratify-protocol-bundle-v2\x00" + encoded).hexdigest()


def verify_proof_bundle_v2_structure(b: ProofBundleV2) -> None:
    """Every key ID, delegation digest, duplicate CertificateRef, and linkage."""
    malformed = V2ErrorClass.MALFORMED
    if b is None:
        raise V2Error(malformed, "v2 proof bundle is nil")
    if b.version != 2:
        raise V2Error(malformed, "v2 proof bundle version must be 2")
    if b.delegations is None:
        raise V2Error(malformed, "v2 delegations must be an array")
    if len(b.delegations) > MAX_DELEGATION_CHAIN_DEPTH or len(b.challenge) != 32 or len(b.delegation_digest) != 48:
        raise V2Error(malformed, "v2 proof bundle exceeds a chain bound or has an invalid challenge/digest length")
    if b.stream_seq is not None and b.stream_seq > MAX_SAFE_INTEGER:
        raise V2Error(malformed, "v2 stream sequence exceeds the safe integer range")
    if b.session_context is not None and len(b.session_context) != 32:
        raise V2Error(malformed, "v2 session_context must be null or 32 bytes")
    stream_null = b.stream_id is None
    if stream_null != (b.stream_seq is None) or (not stream_null and (len(b.stream_id) != 32 or b.stream_seq <= 0)):
        raise V2Error(malformed, "v2 stream_id and stream_seq must both be null or a 32-byte ID and positive sequence")
    if not valid_v2_id(b.agent_id) or not valid_v2_id(b.verifier_id):
        raise V2Error(malformed, "v2 verifier and agent IDs must be canonical")
    agent_id = _run(malformed, lambda: key_id_v2(b.agent_pub_key))
    if agent_id != b.agent_id:
        raise V2Error(V2ErrorClass.KEY_ID_MISMATCH, "agent_id does not match agent_pub_key")
    for cert in b.delegations:
        _run(malformed, lambda cert=cert: validate_delegation_cert_v2(cert))
    digest = _run(malformed, lambda: delegation_digest_v2(b.delegations))
    if digest != bytes(b.delegation_digest):
        raise V2Error(V2ErrorClass.DELEGATION_DIGEST_MISMATCH, "delegation_digest mismatch")
    seen = set()
    for i, c in enumerate(b.delegations):
        ref = (c.issuer_id, c.cert_id)
        if ref in seen:
            raise V2Error(V2ErrorClass.DUPLICATE_CERTIFICATE_REF, "duplicate delegation reference")
        seen.add(ref)
        if i + 1 < len(b.delegations):
            parent = b.delegations[i + 1]
            if c.issuer_id != parent.subject_id or not equal_public_keys(c.issuer_pub_key, parent.subject_pub_key):
                raise V2Error(V2ErrorClass.CHAIN_LINKAGE_MISMATCH, f"delegation chain link {i} does not match parent subject")
    if b.delegations:
        leaf = b.delegations[0]
        if leaf.subject_id != b.agent_id or not equal_public_keys(leaf.subject_pub_key, b.agent_pub_key):
            raise V2Error(V2ErrorClass.CHAIN_LINKAGE_MISMATCH, "agent key does not match leaf delegation subject")


def verify_proof_bundle_v2_signatures_only(b: ProofBundleV2) -> None:
    for c in b.delegations:
        signable = _run(V2ErrorClass.MALFORMED, lambda c=c: cert_signable_bytes_v2(c))
        verify_v2_statement(DELEGATION_CERTIFICATE, signable, c.signature, c.issuer_pub_key)
    signable = _run(V2ErrorClass.MALFORMED, lambda: presentation_signable_bytes_v2(b))
    verify_v2_statement(CHALLENGE_PRESENTATION, signable, b.challenge_sig, b.agent_pub_key)


def verify_proof_bundle_v2_signatures(b: ProofBundleV2) -> None:
    """All structural checks first, then every certificate and the challenge signature."""
    verify_proof_bundle_v2_structure(b)
    verify_proof_bundle_v2_signatures_only(b)


def sign_proof_bundle_v2(bundle: ProofBundleV2, agent_key: HybridPrivateKey) -> ProofBundleV2:
    agent_pub = public_key_of(agent_key)
    if bundle.agent_id != key_id_v2(agent_pub) or not equal_public_keys(bundle.agent_pub_key, agent_pub):
        raise ValueError("v2 agent key does not match proof bundle agent")
    unsigned = replace(bundle, challenge_sig=placeholder_signature_v2(), delegation_digest=bytes(48))
    prepared = decode_proof_bundle_v2(encode_proof_bundle_v2(unsigned))
    prepared.delegation_digest = delegation_digest_v2(prepared.delegations)
    signable = presentation_signable_bytes_v2(prepared)
    prepared.challenge_sig = _sign_v2_statement(CHALLENGE_PRESENTATION, signable, agent_key)
    signed = decode_proof_bundle_v2(encode_proof_bundle_v2(prepared))
    verify_proof_bundle_v2_signatures(signed)
    return signed


# ---------------------------------------------------------------------------
# Revocation list and push


@dataclass
class RevocationListV2:
    version: int
    issuer_id: str
    updated_at: int
    next_update: int
    sequence: int
    revoked: Optional[list[str]]  # issuer-scoped cert IDs, wire [{"cert_id": ...}]
    signature: HybridSignature


@dataclass
class RevocationPushV2:
    version: int
    issuer_id: str
    sequence: int
    pushed_at: int
    revoked: Optional[list[str]]
    signature: HybridSignature


REVOCATION_LIST_V2_FIELDS = ("version", "issuer_id", "updated_at", "next_update", "sequence", "revoked", "signature")
REVOCATION_PUSH_V2_FIELDS = ("version", "issuer_id", "sequence", "pushed_at", "revoked", "signature")


def _decode_revoked(value: Any) -> Optional[list[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("wire v2: revoked must be an array")
    out = []
    for item in value:
        if item is None:
            out.append("")
            continue
        if not isinstance(item, dict):
            raise ValueError("wire v2: revoked entries must be objects")
        check_keys(item, ("cert_id",), "revoked entry")
        out.append(get_str(item, "cert_id"))
    return out


def _validate_revoked(refs: Optional[list[str]]) -> None:
    if refs is None:
        raise ValueError("v2 revoked must be an array")
    seen = set()
    for ref in refs:
        if ref == "" or ref in seen:
            raise ValueError("v2 revoked cert IDs must be non-empty and unique")
        seen.add(ref)


def _safe(value: int) -> bool:
    return -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER


def validate_revocation_list_v2(lst: RevocationListV2) -> None:
    if (
        lst is None or lst.version != 2 or not valid_v2_id(lst.issuer_id) or lst.sequence <= 0
        or lst.sequence > MAX_SAFE_INTEGER or not _safe(lst.updated_at) or not _safe(lst.next_update)
        or lst.next_update <= lst.updated_at
    ):
        raise ValueError("v2 revocation list has invalid version, issuer, sequence, or time bounds")
    _validate_revoked(lst.revoked)


def validate_revocation_push_v2(push: RevocationPushV2) -> None:
    if (
        push is None or push.version != 2 or not valid_v2_id(push.issuer_id) or push.sequence <= 0
        or push.sequence > MAX_SAFE_INTEGER or not _safe(push.pushed_at)
    ):
        raise ValueError("v2 revocation push has invalid version, issuer, sequence, or timestamp")
    _validate_revoked(push.revoked)


def _revoked_dicts(refs: Optional[list[str]]) -> Optional[list[dict]]:
    return None if refs is None else [{"cert_id": ref} for ref in refs]


def revocation_list_signable_bytes_v2(lst: RevocationListV2) -> bytes:
    validate_revocation_list_v2(lst)
    return canonical({
        "issuer_id": lst.issuer_id, "next_update": lst.next_update, "revoked": _revoked_dicts(lst.revoked),
        "sequence": lst.sequence, "updated_at": lst.updated_at, "version": lst.version,
    })


def revocation_push_signable_bytes_v2(push: RevocationPushV2) -> bytes:
    validate_revocation_push_v2(push)
    return canonical({
        "issuer_id": push.issuer_id, "pushed_at": push.pushed_at, "revoked": _revoked_dicts(push.revoked),
        "sequence": push.sequence, "version": push.version,
    })


def decode_revocation_list_v2(data: bytes) -> RevocationListV2:
    def run() -> RevocationListV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError("wire v2: revocation list exceeds MAX_PROOF_BUNDLE_BYTES")
        obj = _v2json.check_wire_json(data)
        require_fields(obj, REVOCATION_LIST_V2_FIELDS)
        check_keys(obj, REVOCATION_LIST_V2_FIELDS, "revocation list")
        lst = RevocationListV2(
            version=get_int(obj, "version"), issuer_id=get_str(obj, "issuer_id"),
            updated_at=get_int(obj, "updated_at"), next_update=get_int(obj, "next_update"),
            sequence=get_int(obj, "sequence"), revoked=_decode_revoked(obj.get("revoked")),
            signature=decode_signature(obj.get("signature")),
        )
        validate_revocation_list_v2(lst)
        validate_hybrid_signature_v2(lst.signature)
        return lst

    return _run(V2ErrorClass.MALFORMED, run)


def decode_revocation_push_v2(data: bytes) -> RevocationPushV2:
    def run() -> RevocationPushV2:
        if len(data) > MAX_PROOF_BUNDLE_BYTES:
            raise ValueError("wire v2: revocation push exceeds MAX_PROOF_BUNDLE_BYTES")
        obj = _v2json.check_wire_json(data)
        require_fields(obj, REVOCATION_PUSH_V2_FIELDS)
        check_keys(obj, REVOCATION_PUSH_V2_FIELDS, "revocation push")
        push = RevocationPushV2(
            version=get_int(obj, "version"), issuer_id=get_str(obj, "issuer_id"),
            sequence=get_int(obj, "sequence"), pushed_at=get_int(obj, "pushed_at"),
            revoked=_decode_revoked(obj.get("revoked")), signature=decode_signature(obj.get("signature")),
        )
        validate_revocation_push_v2(push)
        validate_hybrid_signature_v2(push.signature)
        return push

    return _run(V2ErrorClass.MALFORMED, run)


def encode_revocation_list_v2(lst: RevocationListV2) -> bytes:
    validate_revocation_list_v2(lst)
    validate_hybrid_signature_v2(lst.signature)
    encoded = canonical({
        "issuer_id": lst.issuer_id, "next_update": lst.next_update, "revoked": _revoked_dicts(lst.revoked),
        "sequence": lst.sequence, "signature": key_dict(lst.signature), "updated_at": lst.updated_at,
        "version": lst.version,
    })
    decode_revocation_list_v2(encoded)
    return encoded


def encode_revocation_push_v2(push: RevocationPushV2) -> bytes:
    validate_revocation_push_v2(push)
    validate_hybrid_signature_v2(push.signature)
    encoded = canonical({
        "issuer_id": push.issuer_id, "pushed_at": push.pushed_at, "revoked": _revoked_dicts(push.revoked),
        "sequence": push.sequence, "signature": key_dict(push.signature), "version": push.version,
    })
    decode_revocation_push_v2(encoded)
    return encoded


def verify_revocation_list_v2_signature(lst: RevocationListV2, trusted_issuer_id: str, status_key: HybridPublicKey) -> None:
    _run(V2ErrorClass.MALFORMED, lambda: validate_revocation_list_v2(lst))
    if trusted_issuer_id != lst.issuer_id:
        raise V2Error(V2ErrorClass.STATUS_KEY_BINDING_MISMATCH,
                      "v2 revocation list issuer does not match authenticated status-key binding")
    signable = revocation_list_signable_bytes_v2(lst)
    verify_v2_statement(REVOCATION_LIST, signable, lst.signature, status_key)


def verify_revocation_push_v2_signature(push: RevocationPushV2, trusted_issuer_id: str, status_key: HybridPublicKey) -> None:
    _run(V2ErrorClass.MALFORMED, lambda: validate_revocation_push_v2(push))
    if trusted_issuer_id != push.issuer_id:
        raise V2Error(V2ErrorClass.STATUS_KEY_BINDING_MISMATCH,
                      "v2 revocation push issuer does not match authenticated status-key binding")
    signable = revocation_push_signable_bytes_v2(push)
    verify_v2_statement(REVOCATION_PUSH, signable, push.signature, status_key)


def _sign_status(kind: str, obj, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                 status_key: HybridPrivateKey):
    if kind == "list":
        validate, encode, decode, signable_of, code, verify = (
            validate_revocation_list_v2, encode_revocation_list_v2, decode_revocation_list_v2,
            revocation_list_signable_bytes_v2, REVOCATION_LIST, verify_revocation_list_v2_signature)
    else:
        validate, encode, decode, signable_of, code, verify = (
            validate_revocation_push_v2, encode_revocation_push_v2, decode_revocation_push_v2,
            revocation_push_signable_bytes_v2, REVOCATION_PUSH, verify_revocation_push_v2_signature)
    validate(obj)
    if not bound_issuer_id or obj.issuer_id != bound_issuer_id:
        raise ValueError("status object issuer does not match caller-authenticated status-key binding")
    if not equal_public_keys(bound_status_key, public_key_of(status_key)):
        raise ValueError("status private key does not match caller-authenticated issuer status-key binding")
    prepared = decode(encode(replace(obj, signature=placeholder_signature_v2())))
    prepared.signature = _sign_v2_statement(code, signable_of(prepared), status_key)
    signed = decode(encode(prepared))
    verify(signed, bound_issuer_id, bound_status_key)
    return signed


def sign_revocation_list_v2(lst: RevocationListV2, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                            status_key: HybridPrivateKey) -> RevocationListV2:
    return _sign_status("list", lst, bound_issuer_id, bound_status_key, status_key)


def sign_revocation_push_v2(push: RevocationPushV2, bound_issuer_id: str, bound_status_key: HybridPublicKey,
                            status_key: HybridPrivateKey) -> RevocationPushV2:
    return _sign_status("push", push, bound_issuer_id, bound_status_key, status_key)


def status_evidence_digest(object_type: int, obj: Any) -> bytes:
    """StatusEvidenceDigest over the complete canonical signed status object."""
    if object_type == REVOCATION_LIST:
        if not isinstance(obj, RevocationListV2):
            raise ValueError("status evidence type 0x0003 requires RevocationListV2")
        encoded = encode_revocation_list_v2(obj)
    elif object_type == REVOCATION_PUSH:
        if not isinstance(obj, RevocationPushV2):
            raise ValueError("status evidence type 0x0005 requires RevocationPushV2")
        encoded = encode_revocation_push_v2(obj)
    else:
        raise ValueError(f"unsupported status evidence object type: {object_type:04x}")
    return sha384(b"ratify-protocol-status-evidence-v2\x00" + object_type.to_bytes(2, "big") + encoded).digest()

