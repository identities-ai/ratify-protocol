"""Wire codec for Ratify Protocol v1 signed structures.

The wire JSON shape is normative (SPEC §5.7, §5.8, §6): object keys in
lexicographic order, byte fields as base64-standard strings with padding,
optional fields omitted when absent. Encoders emit canonical JSON text
(via canonical_json), so encode output is exactly the canonical bytes.

Decoders are strict and fail closed:
  - byte input must be valid UTF-8 with no byte-order mark;
  - malformed or non-canonical base64 is rejected;
  - required fields and types are validated; integer fields must lie
    within the IEEE-754 safe-integer range (SPEC §6.2);
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
from .resource_path import is_canonical_constraint_type, validate_params_value
from .types import (
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    MAX_CONSTRAINTS_PER_CERT,
    MAX_IDENTIFIER_LENGTH_BYTES,
    MAX_JSON_NESTING_DEPTH,
    MAX_PROOF_BUNDLE_BYTES,
    MAX_SCOPE_LENGTH_BYTES,
    MAX_SCOPES_PER_CERT,
    MLDSA65_PUBLIC_KEY_SIZE,
    MLDSA65_SIGNATURE_SIZE,
    PROTOCOL_VERSION,
    Constraint,
    DelegationCert,
    HybridPublicKey,
    HybridSignature,
    ProofBundle,
    SessionToken,
    VerificationReceipt,
)

# Fixed size for the 32-byte binding/digest fields on the wire (SPEC §5.8
# session_context / stream_id, §6.4.1 challenge, §16.3 SessionToken
# chain_hash / mac).
_BINDING_SIZE = 32

# Interoperable integer domain for JSON wire fields (SPEC §6.2): the
# IEEE-754 safe-integer range. Binary signable representations use 64-bit
# fields, but a JSON integer outside this range does not survive a
# double-precision JSON parser, so strict decoders reject it.
_MAX_SAFE_INTEGER = 2**53 - 1


# ============================================================================
# Encoders
# ============================================================================

def encode_delegation_cert(cert: DelegationCert) -> str:
    """Encode a DelegationCert as canonical wire JSON (SPEC §5.7)."""
    return canonical_json(_cert_wire_dict(cert, "DelegationCert")).decode("utf-8")


def encode_proof_bundle(bundle: ProofBundle) -> str:
    """Encode a ProofBundle as canonical wire JSON (SPEC §5.8)."""
    out: dict[str, Any] = {
        "agent_id": bundle.agent_id,
        "agent_pub_key": bundle.agent_pub_key,
        "challenge": bundle.challenge,
        "challenge_at": _check_wire_int(bundle.challenge_at, "ProofBundle.challenge_at"),
        "challenge_sig": bundle.challenge_sig,
        "delegations": [
            _cert_wire_dict(c, f"ProofBundle.delegations[{i}]")
            for i, c in enumerate(bundle.delegations)
        ],
    }
    # Optional v1.1 fields carry Go's omitempty semantics: empty values are
    # omitted from the wire form.
    if bundle.session_context:
        out["session_context"] = bundle.session_context
    if bundle.stream_id:
        out["stream_id"] = bundle.stream_id
    if bundle.stream_seq:
        out["stream_seq"] = _check_wire_int(bundle.stream_seq, "ProofBundle.stream_seq")
    return canonical_json(out).decode("utf-8")


def encode_session_token(token: SessionToken) -> str:
    """Encode a SessionToken as canonical wire JSON (SPEC §16.3)."""
    return canonical_json({
        "agent_id": token.agent_id,
        "agent_pub_key": token.agent_pub_key,
        "chain_hash": token.chain_hash,
        "granted_scope": token.granted_scope,
        "human_id": token.human_id,
        "issued_at": _check_wire_int(token.issued_at, "SessionToken.issued_at"),
        "mac": token.mac,
        "session_id": token.session_id,
        "valid_until": _check_wire_int(token.valid_until, "SessionToken.valid_until"),
        "version": _check_wire_int(token.version, "SessionToken.version"),
    }).decode("utf-8")


def _cert_wire_dict(cert: DelegationCert, path: str) -> dict[str, Any]:
    return {
        "cert_id": cert.cert_id,
        "constraints": [
            _checked_constraint_dict(c, f"{path}.constraints[{i}]")
            for i, c in enumerate(cert.constraints or [])
        ],
        "expires_at": _check_wire_int(cert.expires_at, f"{path}.expires_at"),
        "issued_at": _check_wire_int(cert.issued_at, f"{path}.issued_at"),
        "issuer_id": cert.issuer_id,
        "issuer_pub_key": cert.issuer_pub_key,
        "scope": cert.scope,
        "signature": cert.signature,
        "subject_id": cert.subject_id,
        "subject_pub_key": cert.subject_pub_key,
        "version": _check_wire_int(cert.version, f"{path}.version"),
    }


def _checked_constraint_dict(c: Constraint, path: str) -> dict:
    """The only integer-valued constraint fields are max_rate's count and
    window_s; the remaining constraint numerics are floats and are not
    subject to the integer domain."""
    # params is permitted only on non-canonical types and only under the
    # restricted value model (SPEC §5.7.1) — mirror Go's Constraint.MarshalJSON
    # so the encoder never emits what its own decoder would reject.
    if c.params is not None:
        if is_canonical_constraint_type(c.type):
            raise ValueError(
                f"wire: {path}: canonical constraint type {c.type!r} must not "
                f"carry params"
            )
        validate_params_value(c.params, 0)
    out = c.to_canonical_dict()
    if "count" in out:
        _check_wire_int(out["count"], f"{path}.count")
    if "window_s" in out:
        _check_wire_int(out["window_s"], f"{path}.window_s")
    return out


def _check_wire_int(v: Any, field: str) -> int:
    """Encoders must never emit an integer their own decoder rejects: JSON
    integer wire fields are bounded by the IEEE-754 safe-integer range
    (SPEC §6.2)."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"wire: {field}: expected integer")
    if v > _MAX_SAFE_INTEGER or v < -_MAX_SAFE_INTEGER:
        raise ValueError(
            f"wire: {field}: integer outside the safe-integer range "
            f"[-(2^53-1), 2^53-1]"
        )
    return v


# ============================================================================
# Decoders
# ============================================================================

def _check_cert_bounds(cert: DelegationCert, path: str) -> None:
    """Per-cert count and length limits (SPEC §5.1), enforced during decode.

    Does NOT enforce issuance hygiene (jointly-satisfiable resource
    constraints): decoders accept what issuance rejects — wire compatibility
    is not conditioned on issuance hygiene — and verification fails
    unsatisfiable sets closed.
    """
    if len(cert.scope) > MAX_SCOPES_PER_CERT:
        raise ValueError(
            f"wire: {path}: {len(cert.scope)} scopes exceeds "
            f"MAX_SCOPES_PER_CERT ({MAX_SCOPES_PER_CERT})"
        )
    if len(cert.constraints) > MAX_CONSTRAINTS_PER_CERT:
        raise ValueError(
            f"wire: {path}: {len(cert.constraints)} constraints exceeds "
            f"MAX_CONSTRAINTS_PER_CERT ({MAX_CONSTRAINTS_PER_CERT})"
        )
    for s in cert.scope:
        n = len(s.encode("utf-8"))
        if n > MAX_SCOPE_LENGTH_BYTES:
            raise ValueError(
                f"wire: {path}: scope of {n} bytes exceeds "
                f"MAX_SCOPE_LENGTH_BYTES ({MAX_SCOPE_LENGTH_BYTES})"
            )
    for c in cert.constraints:
        n = len(c.resource_id.encode("utf-8"))
        if n > MAX_IDENTIFIER_LENGTH_BYTES:
            raise ValueError(
                f"wire: {path}: resource_id of {n} bytes exceeds "
                f"MAX_IDENTIFIER_LENGTH_BYTES ({MAX_IDENTIFIER_LENGTH_BYTES})"
            )


def decode_delegation_cert(data: str | bytes) -> DelegationCert:
    """Decode a DelegationCert from wire JSON.

    Strict: rejects unknown fields, malformed base64, wrong cryptographic
    byte lengths, and SPEC §5.1 per-cert count/length bounds.
    """
    cert = _decode_cert_obj(_as_object(_parse(data), "DelegationCert"), "DelegationCert")
    _check_cert_bounds(cert, "DelegationCert")
    return cert


def decode_proof_bundle(data: str | bytes) -> ProofBundle:
    """Decode a ProofBundle from wire JSON.

    Strict: rejects unknown fields, malformed base64, wrong cryptographic
    byte lengths, and unpaired v1.1 stream fields. The MAX_PROOF_BUNDLE_BYTES
    check (SPEC §5.1) runs BEFORE any parsing: an oversized payload is
    rejected without being parsed at all.
    """
    path = "ProofBundle"
    raw_len = len(data) if isinstance(data, (bytes, bytearray)) else len(data.encode("utf-8"))
    if raw_len > MAX_PROOF_BUNDLE_BYTES:
        raise ValueError(
            f"wire: proof bundle of {raw_len} bytes exceeds "
            f"MAX_PROOF_BUNDLE_BYTES ({MAX_PROOF_BUNDLE_BYTES})"
        )
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
    bundle = ProofBundle(
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
    # Per-cert count/length bounds (SPEC §5.1). Chain-depth is enforced by the
    # verifier (verify_bundle), not here — see the Python-divergence note: the
    # conformance harness routes the over-depth fixture through this decoder,
    # so depth must reach the verifier to yield the expected chain_too_deep
    # result rather than a decode error.
    for i, cert in enumerate(bundle.delegations):
        _check_cert_bounds(cert, f"{path}.delegations[{i}]")
    return bundle


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
    elif ctype == "resource_path":
        # SPEC §5.7.3. resource_id is required and non-empty; path_prefix is
        # optional but, when the KEY is present, its value must be a non-empty
        # string. A present-but-empty ("") / null / non-string path_prefix is
        # REJECTED — a malformed path restriction must NEVER silently widen
        # into whole-resource authority. Absence of the key (distinguished
        # here by membership test, since json maps null -> None) is the sole
        # encoding of "entire resource".
        _check_keys(obj, ("path_prefix", "resource_id", "type"), path)
        rid = obj.get("resource_id")
        if not isinstance(rid, str) or rid == "":
            raise ValueError(
                f"wire: {path}: resource_path constraint requires a non-empty "
                f"resource_id string"
            )
        kwargs["resource_id"] = rid
        if "path_prefix" in obj:
            pp = obj["path_prefix"]
            if not isinstance(pp, str) or pp == "":
                raise ValueError(
                    f"wire: {path}.path_prefix: must be a non-empty string; "
                    f"omit the field to authorize the entire resource"
                )
            kwargs["path_prefix"] = pp
    else:
        # Extension kind (SPEC §5.7.1): the canonical form carries the tag plus
        # an optional params object under the restricted value model. Unknown
        # constraint types must decode so they can reach the verifier, which
        # rejects them with constraint_unknown.
        _check_keys(obj, ("params", "type"), path)
        if "params" in obj:
            params = obj["params"]
            if not isinstance(params, dict):
                raise ValueError(f"wire: {path}.params: expected JSON object")
            try:
                validate_params_value(params, 0)
            except ValueError as e:
                raise ValueError(f"wire: {path}.params: {e}") from e
            kwargs["params"] = params
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
    # Strict byte decoding: malformed UTF-8 is normalized into the wire
    # error style rather than escaping as a raw UnicodeDecodeError. A
    # leading BOM is NOT stripped (this is the plain "utf-8" codec, not
    # "utf-8-sig"), so it reaches json.loads and is rejected there.
    if isinstance(data, (bytes, bytearray)):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"wire: invalid UTF-8: {e}") from e
    else:
        text = data
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as e:
        raise ValueError(f"wire: invalid JSON: {e}") from e
    # JSON container nesting is bounded (SPEC §5.1). Go enforces this during
    # parse via CheckWireJSON; Python's json has no per-parse hook for depth,
    # so we walk the parsed structure — semantically identical for
    # acceptance/rejection. The root container counts as depth 1.
    _check_nesting_depth(parsed, 0)
    return parsed


def _check_nesting_depth(v: Any, depth: int) -> None:
    if isinstance(v, (dict, list)):
        if depth + 1 > MAX_JSON_NESTING_DEPTH:
            raise ValueError(
                f"wire: JSON nesting exceeds MAX_JSON_NESTING_DEPTH "
                f"({MAX_JSON_NESTING_DEPTH})"
            )
        children = v.values() if isinstance(v, dict) else v
        for child in children:
            _check_nesting_depth(child, depth + 1)


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
    if v > _MAX_SAFE_INTEGER or v < -_MAX_SAFE_INTEGER:
        raise ValueError(
            f"wire: {path}.{key}: integer outside the safe-integer range "
            f"[-(2^53-1), 2^53-1]"
        )
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


# ============================================================================
# VerificationReceipt codec (SPEC §17.5)
# ============================================================================

# The closed identity_status vocabulary a receipt may attest (SPEC §5.9,
# §17.5). Receipts record verifier decisions; a string outside the enum is
# structurally invalid on both codec sides. "unauthorized" is reserved in the
# §5.9 enum (never emitted by the reference verifier) but is enum-valid on the
# wire.
_VALID_RECEIPT_DECISIONS = frozenset({
    "authorized_agent", "verified_human", "expired", "revoked",
    "scope_denied", "constraint_denied", "constraint_unverifiable",
    "constraint_unknown", "invalid_scope", "delegation_not_authorized",
    "invalid", "unauthorized",
})


def _check_receipt_structure(r: VerificationReceipt | None) -> None:
    """Structural invariants of a wire VerificationReceipt (SPEC §17.5),
    shared by encoder and decoder so the codec pair never emits a document its
    counterpart rejects. Raises ValueError on violation."""
    if r is None:
        raise ValueError("wire: nil verification receipt")
    if r.version != PROTOCOL_VERSION:
        raise ValueError(
            f"wire: receipt version {r.version} is not PROTOCOL_VERSION "
            f"({PROTOCOL_VERSION})"
        )
    if not r.verifier_id:
        raise ValueError("wire: receipt verifier_id must be non-empty")
    if r.decision not in _VALID_RECEIPT_DECISIONS:
        raise ValueError(
            f"wire: receipt decision {r.decision!r} is not a known identity_status"
        )
    if len(r.bundle_hash) != _BINDING_SIZE:
        raise ValueError(
            f"wire: bundle_hash must be {_BINDING_SIZE} bytes, got {len(r.bundle_hash)}"
        )
    if len(r.prev_hash) != _BINDING_SIZE:
        raise ValueError(
            f"wire: prev_hash must be {_BINDING_SIZE} bytes, got {len(r.prev_hash)}"
        )
    if len(r.verifier_pub.ed25519) != ED25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"wire: verifier_pub.ed25519 must be {ED25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(r.verifier_pub.ed25519)}"
        )
    if len(r.verifier_pub.ml_dsa_65) != MLDSA65_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"wire: verifier_pub.ml_dsa_65 must be {MLDSA65_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(r.verifier_pub.ml_dsa_65)}"
        )
    if len(r.signature.ed25519) != ED25519_SIGNATURE_SIZE:
        raise ValueError(
            f"wire: signature.ed25519 must be {ED25519_SIGNATURE_SIZE} bytes, "
            f"got {len(r.signature.ed25519)}"
        )
    if len(r.signature.ml_dsa_65) != MLDSA65_SIGNATURE_SIZE:
        raise ValueError(
            f"wire: signature.ml_dsa_65 must be {MLDSA65_SIGNATURE_SIZE} bytes, "
            f"got {len(r.signature.ml_dsa_65)}"
        )


def encode_verification_receipt(r: VerificationReceipt) -> str:
    """Encode a VerificationReceipt as canonical wire JSON (SPEC §17.5):
    lex-sorted keys, byte fields as base64-standard strings, optional fields
    omitted when empty. A structurally invalid receipt (wrong hash or key
    lengths, unknown decision, wrong version) is an error, never emitted — the
    codec pair never produces a document its own decoder rejects. Integer
    fields outside the safe-integer domain are an error, never emitted."""
    _check_receipt_structure(r)
    out: dict[str, Any] = {
        "bundle_hash": r.bundle_hash,
        "decision": r.decision,
        "prev_hash": r.prev_hash,
        "signature": r.signature,
        "verified_at": _check_wire_int(r.verified_at, "VerificationReceipt.verified_at"),
        "verifier_id": r.verifier_id,
        "verifier_pub": r.verifier_pub,
        "version": _check_wire_int(r.version, "VerificationReceipt.version"),
    }
    if r.agent_id:
        out["agent_id"] = r.agent_id
    if r.error_reason:
        out["error_reason"] = r.error_reason
    if r.granted_scope:
        out["granted_scope"] = r.granted_scope
    if r.human_id:
        out["human_id"] = r.human_id
    return canonical_json(out).decode("utf-8")


def decode_verification_receipt(data: str | bytes) -> VerificationReceipt:
    """Decode a VerificationReceipt from wire JSON under strict wire
    acceptance and the same structural invariants the encoder enforces (hash
    and key component lengths, known decision, protocol version). Signature
    verification is the caller's job via verify_verification_receipt."""
    path = "VerificationReceipt"
    obj = _as_object(_parse(data), path)
    _check_keys(obj, (
        "agent_id", "bundle_hash", "decision", "error_reason",
        "granted_scope", "human_id", "prev_hash", "signature",
        "verified_at", "verifier_id", "verifier_pub", "version",
    ), path)
    r = VerificationReceipt(
        version=_get_int(obj, "version", path),
        verifier_id=_get_string(obj, "verifier_id", path),
        verifier_pub=_decode_pub_key_obj(obj.get("verifier_pub"), f"{path}.verifier_pub"),
        bundle_hash=_get_bytes(obj, "bundle_hash", path, _BINDING_SIZE),
        decision=_get_string(obj, "decision", path),
        human_id=_get_string(obj, "human_id", path) if "human_id" in obj else "",
        agent_id=_get_string(obj, "agent_id", path) if "agent_id" in obj else "",
        granted_scope=(
            _get_string_array(obj, "granted_scope", path)
            if "granted_scope" in obj else []
        ),
        error_reason=_get_string(obj, "error_reason", path) if "error_reason" in obj else "",
        verified_at=_get_int(obj, "verified_at", path),
        prev_hash=_get_bytes(obj, "prev_hash", path, _BINDING_SIZE),
        signature=_decode_signature_obj(obj.get("signature"), f"{path}.signature"),
    )
    _check_receipt_structure(r)
    return r
