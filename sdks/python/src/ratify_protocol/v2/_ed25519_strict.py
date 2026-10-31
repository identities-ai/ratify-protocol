"""Strict Ed25519 encoding checks for Protocol v2 (mirrors crypto_v2.go).

``valid_prime_order_point`` accepts exactly the encodings that Go's
``validV2Ed25519Point`` accepts: a canonical encoding (y < p, and no negative
zero x) of an on-curve point P with [L]P = identity and P != identity. That
rejects small-order and mixed-order points. ``valid_canonical_scalar``
accepts exactly 32-byte little-endian scalars below the group order L.
"""
from __future__ import annotations

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)


def valid_canonical_scalar(s: bytes) -> bool:
    if not isinstance(s, (bytes, bytearray)) or len(s) != 32:
        return False
    return int.from_bytes(s, "little") < L


def _decode(encoded: bytes):
    """Decode as RFC 8032 with canonical-encoding checks; None if invalid."""
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= P:
        # SetBytes would reduce y; the re-encoding then differs from input.
        return None
    y2 = y * y % P
    u = (y2 - 1) % P
    v = (_D * y2 + 1) % P
    # x = u v^3 (u v^7)^((p-5)/8)
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = x * _SQRT_M1 % P
    else:
        return None
    if x == 0 and sign:
        # Accepted by SetBytes as -0, but re-encodes with sign bit clear.
        return None
    if (x & 1) != sign:
        x = P - x
    return x, y


def _add(p1, p2):
    # Extended twisted Edwards coordinates (X, Y, Z, T), a = -1.
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * _D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _is_identity(pt) -> bool:
    x, y, z, _ = pt
    return x % P == 0 and (y - z) % P == 0


def valid_prime_order_point(encoded: bytes) -> bool:
    if not isinstance(encoded, (bytes, bytearray)) or len(encoded) != 32:
        return False
    decoded = _decode(bytes(encoded))
    if decoded is None:
        return False
    x, y = decoded
    point = (x, y, 1, x * y % P)
    if _is_identity(point):
        return False
    acc = (0, 1, 1, 0)
    for bit in range(252, -1, -1):
        acc = _add(acc, acc)
        if (L >> bit) & 1:
            acc = _add(acc, point)
    return _is_identity(acc)
