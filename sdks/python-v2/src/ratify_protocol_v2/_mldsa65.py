"""Pure-Python ML-DSA-65 (FIPS 204) verification.

Implements the pure (non-prehash) external verification interface with a
context string, and the external-mu helpers that Protocol v2 vectors pin.
Only ``hashlib`` is required.

This module is verification-only and deliberately has no key generation or
signing: Python big-integer arithmetic is not constant-time, which is
acceptable for public data only. Every private-key operation goes through the
``ratify-protocol-native-v2`` extension.
"""
from __future__ import annotations

from functools import lru_cache
from hashlib import shake_128, shake_256

Q = 8380417
N = 256
D = 13
TAU = 49
LAMBDA = 192
GAMMA1 = 1 << 19
GAMMA2 = (Q - 1) // 32
K = 6
L = 5
ETA = 4
BETA = TAU * ETA
OMEGA = 55
C_TILDE_BYTES = LAMBDA // 4

PUBLIC_KEY_SIZE = 32 + K * 320
SECRET_KEY_SIZE = 32 + 32 + 64 + (K + L) * 128 + K * 416
SIGNATURE_SIZE = C_TILDE_BYTES + L * 640 + OMEGA + K

_N_INV = pow(N, Q - 2, Q)


def _brv8(x: int) -> int:
    return int(f"{x:08b}"[::-1], 2)


_ZETAS = [pow(1753, _brv8(k), Q) for k in range(256)]


# ---------------------------------------------------------------------------
# NTT
# ---------------------------------------------------------------------------

def _ntt(f):
    w = list(f)
    m = 0
    length = 128
    while length >= 1:
        for start in range(0, N, 2 * length):
            m += 1
            z = _ZETAS[m]
            mid = start + length
            end = mid + length
            lo = w[start:mid]
            t = [z * x % Q for x in w[mid:end]]
            w[start:mid] = [(a + b) % Q for a, b in zip(lo, t)]
            w[mid:end] = [(a - b) % Q for a, b in zip(lo, t)]
        length >>= 1
    return w


def _intt(f):
    w = list(f)
    m = 256
    length = 1
    while length < N:
        for start in range(0, N, 2 * length):
            m -= 1
            z = Q - _ZETAS[m]
            mid = start + length
            end = mid + length
            lo = w[start:mid]
            hi = w[mid:end]
            w[start:mid] = [(a + b) % Q for a, b in zip(lo, hi)]
            w[mid:end] = [z * (a - b) % Q for a, b in zip(lo, hi)]
        length <<= 1
    return [x * _N_INV % Q for x in w]


def _mat_vec(a_hat, v_hat):
    out = []
    for row in a_hat:
        acc = [0] * N
        for a, v in zip(row, v_hat):
            acc = [s + x * y for s, x, y in zip(acc, a, v)]
        out.append([s % Q for s in acc])
    return out


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------

def _rej_ntt_poly(seed: bytes):
    nbytes = 840
    while True:
        buf = shake_128(seed).digest(nbytes)
        usable = len(buf) - len(buf) % 3
        coeffs = [
            b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
            for b0, b1, b2 in zip(buf[0:usable:3], buf[1:usable:3], buf[2:usable:3])
        ]
        coeffs = [c for c in coeffs if c < Q]
        if len(coeffs) >= N:
            return coeffs[:N]
        nbytes *= 2


@lru_cache(maxsize=64)
def _expand_a(rho: bytes):
    return tuple(
        tuple(_rej_ntt_poly(rho + bytes([s, r])) for s in range(L))
        for r in range(K)
    )


def _sample_in_ball(seed: bytes):
    nbytes = 8 + 256
    while True:
        buf = shake_256(seed).digest(nbytes)
        signs = int.from_bytes(buf[:8], "little")
        c = [0] * N
        pos = 8
        ok = True
        for i in range(N - TAU, N):
            while True:
                if pos >= len(buf):
                    ok = False
                    break
                j = buf[pos]
                pos += 1
                if j <= i:
                    break
            if not ok:
                break
            c[i] = c[j]
            c[j] = Q - 1 if (signs >> (i + TAU - N)) & 1 else 1
        if ok:
            return c
        nbytes *= 2


# ---------------------------------------------------------------------------
# Rounding
# ---------------------------------------------------------------------------

def _centered(r: int, alpha: int) -> int:
    r0 = r % alpha
    if r0 > alpha // 2:
        r0 -= alpha
    return r0


def _decompose(r: int):
    r = r % Q
    r0 = _centered(r, 2 * GAMMA2)
    if r - r0 == Q - 1:
        return 0, r0 - 1
    return (r - r0) // (2 * GAMMA2), r0


def _use_hint(h: int, r: int) -> int:
    r1, r0 = _decompose(r)
    if h:
        return (r1 + 1) % 16 if r0 > 0 else (r1 - 1) % 16
    return r1


def _inf_norm(poly) -> int:
    best = 0
    half = (Q - 1) // 2
    for x in poly:
        v = Q - x if x > half else x
        if v > best:
            best = v
    return best


# ---------------------------------------------------------------------------
# Bit packing (little-endian bit order, as FIPS 204 BitsToBytes)
# ---------------------------------------------------------------------------

def _pack(values, bits: int) -> bytes:
    acc = 0
    for i, v in enumerate(values):
        acc |= v << (i * bits)
    return acc.to_bytes(len(values) * bits // 8, "little")


def _unpack(buf: bytes, bits: int):
    acc = int.from_bytes(buf, "little")
    mask = (1 << bits) - 1
    return [(acc >> (i * bits)) & mask for i in range(len(buf) * 8 // bits)]


def _unpack_centered(buf: bytes, bound: int, bits: int):
    return [(bound - v) % Q for v in _unpack(buf, bits)]


def _w1_encode(w1) -> bytes:
    return b"".join(_pack(p, 4) for p in w1)


def _hint_unpack(y: bytes):
    h = [[0] * N for _ in range(K)]
    index = 0
    for i in range(K):
        end = y[OMEGA + i]
        if end < index or end > OMEGA:
            return None
        first = index
        while index < end:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    for i in range(index, OMEGA):
        if y[i] != 0:
            return None
    return h


def _h(data: bytes, n: int) -> bytes:
    return shake_256(data).digest(n)


# ---------------------------------------------------------------------------
# Key and signature encodings
# ---------------------------------------------------------------------------

@lru_cache(maxsize=64)
def _public_precompute(pk: bytes):
    """Return (A_hat, NTT(t1 * 2^d), tr) for a well-sized public key."""
    rho = pk[:32]
    t1_hat = []
    for i in range(K):
        t1 = _unpack(pk[32 + 320 * i: 32 + 320 * (i + 1)], 10)
        t1_hat.append(_ntt([(x << D) % Q for x in t1]))
    return _expand_a(rho), t1_hat, _h(pk, 64)


def _message_prime(message: bytes, ctx: bytes) -> bytes:
    if len(ctx) > 255:
        raise ValueError("ML-DSA context exceeds 255 bytes")
    return b"\x00" + bytes([len(ctx)]) + bytes(ctx) + bytes(message)


def compute_tr(pk: bytes) -> bytes:
    """tr = H(pk, 64)."""
    return _h(bytes(pk), 64)


def compute_mu(pk: bytes, message: bytes, ctx: bytes) -> bytes:
    """External mu = H(tr || 0x00 || len(ctx) || ctx || M, 64)."""
    return _h(compute_tr(pk) + _message_prime(message, ctx), 64)


def verify(pk: bytes, message: bytes, ctx: bytes, sig: bytes) -> bool:
    """ML-DSA-65 pure verification with context. Never raises."""
    try:
        return _verify(bytes(pk), bytes(message), bytes(ctx), bytes(sig))
    except Exception:  # noqa: BLE001 - fail closed on any malformed input
        return False


def _verify(pk: bytes, message: bytes, ctx: bytes, sig: bytes) -> bool:
    if len(pk) != PUBLIC_KEY_SIZE or len(sig) != SIGNATURE_SIZE or len(ctx) > 255:
        return False
    c_tilde = sig[:C_TILDE_BYTES]
    off = C_TILDE_BYTES
    z = [_unpack_centered(sig[off + 640 * i: off + 640 * (i + 1)], GAMMA1, 20) for i in range(L)]
    h = _hint_unpack(sig[off + 640 * L:])
    if h is None:
        return False
    if max(_inf_norm(p) for p in z) >= GAMMA1 - BETA:
        return False
    a_hat, t1_hat, tr = _public_precompute(pk)
    mu = _h(tr + _message_prime(message, ctx), 64)
    c_hat = _ntt(_sample_in_ball(c_tilde))
    az = _mat_vec(a_hat, [_ntt(p) for p in z])
    w1 = []
    for azp, tp, hp in zip(az, t1_hat, h):
        approx = _intt([(a - c * t) % Q for a, c, t in zip(azp, c_hat, tp)])
        w1.append([_use_hint(hb, x) for hb, x in zip(hp, approx)])
    return _h(mu + _w1_encode(w1), C_TILDE_BYTES) == c_tilde
