"""Protocol v2 ``max_rate`` reservation batches (mirrors Go rate_reservation_v2.go).

Every signed ``max_rate`` counter of an already preflight-verified proof is
sealed into the immutable challenge claim; reservation is deferred until
status and the other ordered checks have completed (SPEC-v2 §6.8, §7.6).
"""
from __future__ import annotations

from dataclasses import dataclass

from . import _v2json
from .context_policy_v2 import V2DeferredConstraint
from .types_v2 import is_int, valid_v2_id

MAX_RATE = "max_rate"
RECEIVER_AUDIENCE = "ratify.receiver_audience"
_MAX_SAFE_INTEGER = 2**53 - 1
_MAX_IDENTIFIER_LENGTH_BYTES = 512
_MAX_RATE_WINDOW_SECONDS = 86400


class V2RateLimitExceededError(Exception):
    """Go ``ErrV2RateLimitExceeded``: a complete atomic batch had no capacity.

    Unclassified by design, as in Go: it is a store outcome, not a failure
    class, and the verifier maps it to ``constraint_denied``. Any other store
    error is unavailable or ambiguous and can never authorize."""

    def __init__(self, message: str = "v2 signed rate limit has no remaining capacity"):
        super().__init__(message)


@dataclass(frozen=True)
class V2RateReservation:
    """One issuer-scoped rolling-window counter. The effective limit is the
    smallest signed limit for this certificate and window; duplicate
    constraints never consume more than one slot per claim."""

    issuer_id: str
    cert_id: str
    window_s: int
    limit: int


def decode_sealed_constraint_v2(data: bytes):
    """Validate one sealed constraint against the closed registry, decode it,
    and require that it is exactly its own canonical encoding. Returns the
    ``ConstraintV2``; raises ValueError otherwise."""
    from . import constraints_v2

    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("sealed constraint must be bytes")
    data = bytes(data)
    constraint = constraints_v2.constraint_v2_from_fields(_v2json.parse(data))
    if encode_constraint_canonical_v2(constraint) != data:
        raise ValueError("sealed constraint is not canonical")
    return constraint


def encode_constraint_canonical_v2(constraint) -> bytes:
    """RatifyCanonicalJSON of one constraint (Go ``CanonicalJSON(constraint)``)."""
    return _v2json.canonical(constraint.to_canonical_dict())


def signed_v2_rate_reservation_batch(bundle) -> list:
    """Seal every rate counter from an already preflight-verified proof."""
    deferred = []
    for i, cert in enumerate(bundle.delegations or ()):
        for j, constraint in enumerate(cert.constraints or ()):
            if constraint.type != MAX_RATE:
                continue
            deferred.append(V2DeferredConstraint(
                delegation_index=i, constraint_index=j, issuer_id=cert.issuer_id, cert_id=cert.cert_id,
                type=MAX_RATE, canonical_json=encode_constraint_canonical_v2(constraint),
            ))
    return build_v2_rate_reservation_batch(deferred)


def build_v2_rate_reservation_batch(deferred) -> list:
    """Derive a deterministic atomic reservation request from signed
    ``max_rate`` constraints retained in the claimed proof. Raises
    ValueError on an invalid, duplicated, or noncanonical input."""
    counters: dict = {}
    seen_positions: set = set()
    for item in deferred or ():
        if not isinstance(item, V2DeferredConstraint):
            raise ValueError("v2 rate batch item must be a V2DeferredConstraint")
        position = (item.delegation_index, item.constraint_index)
        if (
            not is_int(item.delegation_index) or not is_int(item.constraint_index)
            or item.delegation_index < 0 or item.constraint_index < 0 or position in seen_positions
            or not valid_v2_id(item.issuer_id) or not isinstance(item.cert_id, str) or item.cert_id == ""
            or len(item.cert_id.encode("utf-8", "surrogatepass")) > _MAX_IDENTIFIER_LENGTH_BYTES
        ):
            raise ValueError("v2 rate constraint has invalid identity or duplicate position")
        seen_positions.add(position)
        try:
            constraint = decode_sealed_constraint_v2(item.canonical_json)
        except Exception as exc:  # noqa: BLE001 - any decode failure is invalid
            raise ValueError(f"v2 rate constraint is invalid: {exc}") from exc
        if constraint.type != item.type:
            raise ValueError("v2 rate constraint has wrong type")
        if item.type not in (MAX_RATE, RECEIVER_AUDIENCE):
            raise ValueError("v2 rate batch contains an unexpected deferred constraint type")
        if item.type == RECEIVER_AUDIENCE:
            continue
        count, window = constraint.count, constraint.window_s
        if not is_int(count) or not is_int(window) or count <= 0 or count > _MAX_SAFE_INTEGER or window <= 0 or window > _MAX_RATE_WINDOW_SECONDS:
            raise ValueError("v2 rate constraint has noncanonical or invalid limits")
        key = (item.issuer_id, item.cert_id, window)
        previous = counters.get(key)
        if previous is None or count < previous:
            counters[key] = count
    batch = [V2RateReservation(issuer_id=k[0], cert_id=k[1], window_s=k[2], limit=v) for k, v in counters.items()]
    batch.sort(key=lambda r: (r.issuer_id.encode("utf-8"), r.cert_id.encode("utf-8", "surrogatepass"), r.window_s))
    return batch

