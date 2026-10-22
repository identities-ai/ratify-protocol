"""Pure-Python ML-DSA-65 verification and strict Ed25519 checks against the
shared v2 vectors.

These primitives verify Protocol v2 signatures without the native extension,
so they must agree with Go on external tr/mu and on every accept/reject. The
module is verification-only: key generation and signing live in the native
extension (see test_native_signing_v2.py).
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from ratify_protocol_v2 import _ed25519_strict as ed
from ratify_protocol_v2 import _mldsa65 as mldsa

VECTORS = Path(os.environ.get("RATIFY_V2_VECTOR_DIR") or Path(__file__).resolve().parents[3] / "testvectors" / "v2")


def _load(name: str):
    return json.loads((VECTORS / name).read_text())


def _b64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


KEYS = _load("keys.json")["keys"]
KEYS_BY_ID = {k["key_id_v2"]: k for k in KEYS}
DELEGATION = _load("delegation-signature.json")
OBJECTS = _load("objects.json")["objects"]
NEGATIVES = {v["name"]: v for v in _load("object-negatives.json")["vectors"]}


def test_sizes():
    assert (mldsa.PUBLIC_KEY_SIZE, mldsa.SECRET_KEY_SIZE, mldsa.SIGNATURE_SIZE) == (1952, 4032, 3309)


def test_module_has_no_private_key_operations():
    # Pure-Python signing and key generation were removed: Python big-integer
    # arithmetic is not constant-time, so only public-data verification stays.
    for name in ("sign", "keygen_from_seed", "public_key_from_secret", "_expand_s", "_expand_mask"):
        assert not hasattr(mldsa, name), name


class TestDelegationSignatureVector:
    pk_expected = _b64(DELEGATION["issuer_public_key"]["ml_dsa_65"])
    message = _b64(DELEGATION["message"])
    ctx = _b64(DELEGATION["mldsa_context"])
    sig = _b64(DELEGATION["signature"]["ml_dsa_65"])

    def test_tr_and_mu(self):
        assert mldsa.compute_tr(self.pk_expected) == _b64(DELEGATION["mldsa_tr"])
        assert mldsa.compute_mu(self.pk_expected, self.message, self.ctx) == _b64(DELEGATION["mldsa_mu"])

    def test_verify_and_wrong_context(self):
        assert mldsa.verify(self.pk_expected, self.message, self.ctx, self.sig)
        alt = _b64(DELEGATION["alternate_mldsa_context"])
        assert not mldsa.verify(self.pk_expected, self.message, alt, self.sig)
        assert not mldsa.verify(self.pk_expected, self.message, b"", self.sig)

    @pytest.mark.parametrize("target", DELEGATION["negative_mutations"]["targets"])
    def test_negative_mutations(self, target):
        mask = DELEGATION["negative_mutations"]["xor_mask"]
        pk, message, sig = bytearray(self.pk_expected), bytearray(self.message), bytearray(self.sig)
        if target == "signable_bytes":
            # Mutating the signable projection changes the SHA-384 in M.
            message[-1] ^= mask
        elif target == "signature.ml_dsa_65":
            sig[0] ^= mask
        elif target == "issuer_public_key.ml_dsa_65":
            pk[0] ^= mask
        else:
            # Ed25519-only targets leave the ML-DSA component valid; the hybrid
            # AND is enforced above this primitive.
            assert mldsa.verify(bytes(pk), bytes(message), self.ctx, bytes(sig))
            return
        assert not mldsa.verify(bytes(pk), bytes(message), self.ctx, bytes(sig))


SIGNATURE_ENTRIES = [
    (obj["name"], entry) for obj in OBJECTS for entry in obj["signatures"]
]


@pytest.mark.parametrize(
    "name,entry", SIGNATURE_ENTRIES, ids=[f"{n}/{e['field']}" for n, e in SIGNATURE_ENTRIES]
)
def test_objects_signatures(name, entry):
    pk = _b64(KEYS_BY_ID[entry["signer_key_id_v2"]]["public_key"]["ml_dsa_65"])
    message = _b64(entry["message_b64"])
    ctx = entry["mldsa_context"].encode("ascii")
    sig = _b64(entry["signature"]["ml_dsa_65"])
    assert ctx == f"ratify-protocol/2/{int(entry['object_type_code']):04x}".encode()
    assert mldsa.compute_tr(pk) == _b64(entry["mldsa_tr_b64"])
    assert mldsa.compute_mu(pk, message, ctx) == _b64(entry["mldsa_mu_b64"])
    assert mldsa.verify(pk, message, ctx, sig)
    assert ed.valid_prime_order_point(_b64(entry["signature"]["ed25519"])[:32])
    assert ed.valid_canonical_scalar(_b64(entry["signature"]["ed25519"])[32:])


# --- FIPS 204 malformed-signature rejection ---------------------------------

def _sig_parts():
    return bytearray(TestDelegationSignatureVector.sig)


def test_verify_rejects_wrong_lengths():
    pk = TestDelegationSignatureVector.pk_expected
    msg, ctx, sig = TestDelegationSignatureVector.message, TestDelegationSignatureVector.ctx, TestDelegationSignatureVector.sig
    assert not mldsa.verify(pk[:-1], msg, ctx, sig)
    assert not mldsa.verify(pk, msg, ctx, sig[:-1])
    assert not mldsa.verify(pk, msg, ctx, sig + b"\x00")
    assert not mldsa.verify(pk, msg, b"x" * 256, sig)


def test_verify_rejects_z_out_of_bound():
    pk = TestDelegationSignatureVector.pk_expected
    sig = _sig_parts()
    # First z coefficient is stored as gamma1 - z in 20 bits; storing
    # gamma1 - (gamma1 - beta) puts ||z|| exactly at the rejection bound.
    off = mldsa.C_TILDE_BYTES
    acc = int.from_bytes(sig[off:off + 640], "little")
    acc = (acc & ~0xFFFFF) | (mldsa.BETA & 0xFFFFF)
    sig[off:off + 640] = acc.to_bytes(640, "little")
    assert not mldsa.verify(pk, TestDelegationSignatureVector.message, TestDelegationSignatureVector.ctx, bytes(sig))


def _hint_region(sig: bytearray) -> int:
    return mldsa.C_TILDE_BYTES + 640 * mldsa.L


def test_verify_rejects_malformed_hints():
    pk = TestDelegationSignatureVector.pk_expected
    msg, ctx = TestDelegationSignatureVector.message, TestDelegationSignatureVector.ctx
    base = _sig_parts()
    h = _hint_region(base)
    counts = [base[h + mldsa.OMEGA + i] for i in range(mldsa.K)]
    total = counts[-1]
    assert total <= mldsa.OMEGA

    # Count above omega.
    bad = bytearray(base)
    bad[h + mldsa.OMEGA + mldsa.K - 1] = mldsa.OMEGA + 1
    assert not mldsa.verify(pk, msg, ctx, bytes(bad))

    # Decreasing cumulative count.
    if counts[0] > 0:
        bad = bytearray(base)
        bad[h + mldsa.OMEGA + 1] = counts[0] - 1
        assert not mldsa.verify(pk, msg, ctx, bytes(bad))

    # Non-zero padding after the last index.
    if total < mldsa.OMEGA:
        bad = bytearray(base)
        bad[h + mldsa.OMEGA - 1] = 1
        assert not mldsa.verify(pk, msg, ctx, bytes(bad))

    # Indices within one polynomial not strictly increasing.
    first_nonempty = next((i for i, c in enumerate(counts) if c - (counts[i - 1] if i else 0) >= 2), None)
    assert first_nonempty is not None, "vector signature has no polynomial with two hints"
    start = counts[first_nonempty - 1] if first_nonempty else 0
    bad = bytearray(base)
    bad[h + start + 1] = bad[h + start]
    assert not mldsa.verify(pk, msg, ctx, bytes(bad))


def test_verify_never_raises_on_garbage():
    assert not mldsa.verify(b"\xff" * 1952, b"m", b"c", b"\xff" * 3309)
    assert not mldsa.verify(None, b"m", b"c", b"\x00" * 3309)  # type: ignore[arg-type]


# --- Strict Ed25519 --------------------------------------------------------

L_BYTES = ed.L.to_bytes(32, "little")


def _decoded(name: str):
    return json.loads(_b64(NEGATIVES[name]["wire_b64"]))


def test_ed25519_scalar_bounds():
    assert ed.valid_canonical_scalar(bytes(32))
    assert ed.valid_canonical_scalar((ed.L - 1).to_bytes(32, "little"))
    assert not ed.valid_canonical_scalar(L_BYTES)
    assert not ed.valid_canonical_scalar(b"\xff" * 32)
    assert not ed.valid_canonical_scalar(bytes(31))


def test_ed25519_point_basics():
    identity = (1).to_bytes(32, "little")
    assert not ed.valid_prime_order_point(identity)
    # y = p + 1 is the non-canonical encoding of the identity's y.
    assert not ed.valid_prime_order_point((ed.P + 1).to_bytes(32, "little"))
    # Negative zero x: identity encoding with the sign bit set.
    assert not ed.valid_prime_order_point((1 | (1 << 255)).to_bytes(32, "little"))
    # Order-2 point (0, -1).
    assert not ed.valid_prime_order_point((ed.P - 1).to_bytes(32, "little"))
    # y = 2 is not on the curve.
    assert not ed.valid_prime_order_point((2).to_bytes(32, "little"))
    for key in KEYS:
        assert ed.valid_prime_order_point(_b64(key["public_key"]["ed25519"]))


def test_ed25519_negative_vectors():
    s_plus = _decoded("delegation_certificate/ed25519_s_plus_order")
    sig = _b64(s_plus["signature"]["ed25519"])
    assert ed.valid_prime_order_point(sig[:32])
    assert not ed.valid_canonical_scalar(sig[32:])

    ident_a = _decoded("delegation_certificate/ed25519_identity_public_key")
    assert not ed.valid_prime_order_point(_b64(ident_a["issuer_pub_key"]["ed25519"]))

    ident_r = _decoded("delegation_certificate/ed25519_identity_r")
    assert not ed.valid_prime_order_point(_b64(ident_r["signature"]["ed25519"])[:32])

    noncanon = _decoded("delegation_certificate/ed25519_noncanonical_public_key")
    assert not ed.valid_prime_order_point(_b64(noncanon["issuer_pub_key"]["ed25519"]))

    mixed = _decoded("delegation_certificate/ed25519_mixed_order_public_key")
    mixed_a = _b64(mixed["issuer_pub_key"]["ed25519"])
    # On-curve and canonically encoded, but not in the prime-order subgroup.
    assert ed._decode(mixed_a) is not None
    assert not ed.valid_prime_order_point(mixed_a)
    mixed_sig = _b64(mixed["signature"]["ed25519"])
    assert ed.valid_prime_order_point(mixed_sig[:32])
    assert ed.valid_canonical_scalar(mixed_sig[32:])
