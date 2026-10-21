"""Pure-Python ML-DSA-65 (FIPS 204), used when the native extra is absent.

Implements ML-DSA.KeyGen_internal from a 32-byte seed, the pure (non-prehash)
external interface with a context string, and the external-mu helpers that
Protocol v2 vectors pin. Signing with an all-zero ``rnd`` is the FIPS 204
deterministic variant. Only ``hashlib`` is required.

This module is a correctness fallback, not a constant-time implementation:
Python big-integer arithmetic leaks timing. Verification handles only public
data. Signing with long-term production keys should use a hardened,
constant-time provider.
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


def _mul(a, b):
    return [x * y % Q for x, y in zip(a, b)]


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


def _rej_bounded_poly(seed: bytes):
    nbytes = 272
    while True:
        buf = shake_256(seed).digest(nbytes)
        out = []
        for byte in buf:
            for nib in (byte & 0x0F, byte >> 4):
                if nib < 9:
                    out.append((ETA - nib) % Q)
            if len(out) >= N:
                return out[:N]
        nbytes *= 2


def _expand_s(rho_prime: bytes):
    s1 = [_rej_bounded_poly(rho_prime + r.to_bytes(2, "little")) for r in range(L)]
    s2 = [_rej_bounded_poly(rho_prime + (r + L).to_bytes(2, "little")) for r in range(K)]
    return s1, s2


def _expand_mask(rho2: bytes, kappa: int):
    out = []
    for r in range(L):
        buf = shake_256(rho2 + (kappa + r).to_bytes(2, "little")).digest(640)
        out.append([(GAMMA1 - v) % Q for v in _unpack(buf, 20)])
    return out


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


def _high_bits(r: int) -> int:
    return _decompose(r)[0]


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


def _pack_centered(poly, bound: int, bits: int) -> bytes:
    # BitPack(w, a, b) stores b - w_i.
    return _pack([(bound - _centered(x, Q)) for x in poly], bits)


def _unpack_centered(buf: bytes, bound: int, bits: int):
    return [(bound - v) % Q for v in _unpack(buf, bits)]


def _w1_encode(w1) -> bytes:
    return b"".join(_pack(p, 4) for p in w1)


def _hint_pack(h) -> bytes:
    out = bytearray(OMEGA + K)
    index = 0
    for i, poly in enumerate(h):
        for j, bit in enumerate(poly):
            if bit:
                out[index] = j
                index += 1
        out[OMEGA + i] = index
    return bytes(out)


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


def keygen_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """ML-DSA-65 KeyGen_internal(xi). Returns (public_key, secret_key)."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("ML-DSA-65 seed must be 32 bytes")
    expanded = _h(bytes(seed) + bytes([K, L]), 128)
    rho, rho_prime, key = expanded[:32], expanded[32:96], expanded[96:]
    a_hat = _expand_a(rho)
    s1, s2 = _expand_s(rho_prime)
    s1_hat = [_ntt(p) for p in s1]
    t = [
        [(x + y) % Q for x, y in zip(_intt(row), e)]
        for row, e in zip(_mat_vec(a_hat, s1_hat), s2)
    ]
    t1, t0 = [], []
    for poly in t:
        hi, lo = [], []
        for x in poly:
            r0 = _centered(x, 1 << D)
            hi.append((x - r0) >> D)
            lo.append(r0 % Q)
        t1.append(hi)
        t0.append(lo)
    pk = rho + b"".join(_pack(p, 10) for p in t1)
    tr = _h(pk, 64)
    sk = (
        rho + key + tr
        + b"".join(_pack_centered(p, ETA, 4) for p in s1)
        + b"".join(_pack_centered(p, ETA, 4) for p in s2)
        + b"".join(_pack_centered(p, 1 << (D - 1), 13) for p in t0)
    )
    return pk, sk



def public_key_from_secret(sk: bytes) -> bytes:
    """Recompute the public key from a FIPS 204 secret key and check its tr."""
    if not isinstance(sk, (bytes, bytearray)) or len(sk) != SECRET_KEY_SIZE:
        raise ValueError("ML-DSA-65 secret key has the wrong length")
    sk = bytes(sk)
    rho, tr = sk[:32], sk[64:128]
    offset = 128
    s1 = []
    for _ in range(L):
        s1.append(_unpack_centered(sk[offset:offset + 128], ETA, 4))
        offset += 128
    s2 = []
    for _ in range(K):
        s2.append(_unpack_centered(sk[offset:offset + 128], ETA, 4))
        offset += 128
    a_hat = _expand_a(rho)
    s1_hat = [_ntt(p) for p in s1]
    t = [
        [(x + y) % Q for x, y in zip(_intt(row), e)]
        for row, e in zip(_mat_vec(a_hat, s1_hat), s2)
    ]
    t1 = [[(x - _centered(x, 1 << D)) >> D for x in poly] for poly in t]
    pk = rho + b"".join(_pack(p, 10) for p in t1)
    if _h(pk, 64) != tr:
        raise ValueError("ML-DSA-65 secret key is inconsistent with its public key hash")
    return pk

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


def sign(sk: bytes, message: bytes, ctx: bytes, rnd: bytes = bytes(32)) -> bytes:
    """ML-DSA-65 pure signing with context. All-zero ``rnd`` is deterministic."""
    sk = bytes(sk)
    if len(sk) != SECRET_KEY_SIZE:
        raise ValueError("ML-DSA-65 secret key must be 4032 bytes")
    if len(rnd) != 32:
        raise ValueError("ML-DSA-65 rnd must be 32 bytes")
    m_prime = _message_prime(message, ctx)
    rho, key, tr = sk[:32], sk[32:64], sk[64:128]
    off = 128
    s1 = [_unpack_centered(sk[off + 128 * i: off + 128 * (i + 1)], ETA, 4) for i in range(L)]
    off += 128 * L
    s2 = [_unpack_centered(sk[off + 128 * i: off + 128 * (i + 1)], ETA, 4) for i in range(K)]
    off += 128 * K
    t0 = [_unpack_centered(sk[off + 416 * i: off + 416 * (i + 1)], 1 << (D - 1), 13) for i in range(K)]
    s1_hat = [_ntt(p) for p in s1]
    s2_hat = [_ntt(p) for p in s2]
    t0_hat = [_ntt(p) for p in t0]
    a_hat = _expand_a(rho)
    mu = _h(tr + m_prime, 64)
    rho2 = _h(key + bytes(rnd) + mu, 64)
    kappa = 0
    bound_z = GAMMA1 - BETA
    bound_r0 = GAMMA2 - BETA
    while True:
        y = _expand_mask(rho2, kappa)
        kappa += L
        w = [_intt(p) for p in _mat_vec(a_hat, [_ntt(p) for p in y])]
        w1 = [[_high_bits(x) for x in p] for p in w]
        c_tilde = _h(mu + _w1_encode(w1), C_TILDE_BYTES)
        c_hat = _ntt(_sample_in_ball(c_tilde))
        cs1 = [_intt(_mul(c_hat, p)) for p in s1_hat]
        z = [[(a + b) % Q for a, b in zip(yp, cp)] for yp, cp in zip(y, cs1)]
        if max(_inf_norm(p) for p in z) >= bound_z:
            continue
        cs2 = [_intt(_mul(c_hat, p)) for p in s2_hat]
        w_minus = [[(a - b) % Q for a, b in zip(wp, cp)] for wp, cp in zip(w, cs2)]
        if max(max(abs(_decompose(x)[1]) for x in p) for p in w_minus) >= bound_r0:
            continue
        ct0 = [_intt(_mul(c_hat, p)) for p in t0_hat]
        if max(_inf_norm(p) for p in ct0) >= GAMMA2:
            continue
        hint = []
        count = 0
        for cp, wp in zip(ct0, w_minus):
            row = []
            for c0, wm in zip(cp, wp):
                # MakeHint(-ct0, w - cs2 + ct0)
                r = (wm + c0) % Q
                bit = 1 if _high_bits(r) != _high_bits(wm) else 0
                count += bit
                row.append(bit)
            hint.append(row)
        if count > OMEGA:
            continue
        return (
            c_tilde
            + b"".join(_pack_centered(p, GAMMA1, 20) for p in z)
            + _hint_pack(hint)
        )


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
