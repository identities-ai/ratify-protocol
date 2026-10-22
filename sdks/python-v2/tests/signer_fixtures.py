"""Test-only external signers for the v2 typed-signer interface.

These emulate providers in software over the native key. A real external-mu
provider signs the 64-byte mu directly; the native backend has no external-mu
entry point, so the emulation checks that mu equals the value recomputed from
M and the registered context and then signs (M, context), as the Go reference
tests do. Never use these outside tests.
"""
from __future__ import annotations

from ratify_protocol_v2 import _native
from ratify_protocol_v2.signing_v2 import (
    SignerModeV2,
    SignRequestV2,
    external_mu_v2,
    key_id_v2,
    mldsa_context_v2,
    new_local_signer_v2,
)
from ratify_protocol_v2.types import HybridPrivateKey, HybridPublicKey, HybridSignature


class CountingSigner:
    """Wraps a signer and counts every interface method call."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = 0
        self.requests: list[SignRequestV2] = []

    def public_key_v2(self) -> HybridPublicKey:
        self.calls += 1
        return self.inner.public_key_v2()

    def mode_v2(self) -> SignerModeV2:
        self.calls += 1
        return self.inner.mode_v2()

    def sign_v2(self, ctx, req: SignRequestV2) -> HybridSignature:
        self.calls += 1
        self.requests.append(req)
        return self.inner.sign_v2(ctx, req)


class ExternalMuSigner:
    """An emulated external-mu provider bound to one hybrid key."""

    def __init__(self, priv: HybridPrivateKey, pub: HybridPublicKey):
        self._key = _native.signing_key(priv.ed25519, priv.ml_dsa_65)
        self._pub = pub
        self.requests: list[SignRequestV2] = []

    def public_key_v2(self) -> HybridPublicKey:
        return HybridPublicKey(bytes(self._pub.ed25519), bytes(self._pub.ml_dsa_65))

    def mode_v2(self) -> SignerModeV2:
        return SignerModeV2.EXTERNAL_MU

    def sign_v2(self, ctx, req: SignRequestV2) -> HybridSignature:
        self.requests.append(req)
        assert req.mode == SignerModeV2.EXTERNAL_MU and req.mldsa_context is None
        assert req.key_id == key_id_v2(self._pub)
        code = int.from_bytes(req.message[27:29], "big")
        context = mldsa_context_v2(code)
        assert req.mldsa_mu == external_mu_v2(self._pub.ml_dsa_65, context, req.message)
        ed, ml = self._key.sign(req.message, context)
        return HybridSignature(bytes(ed), bytes(ml))


class FaultySigner:
    """A direct-mode signer whose output can be corrupted or delayed."""

    def __init__(self, priv: HybridPrivateKey, fault: str, on_sign=None):
        self.inner = new_local_signer_v2(priv)
        self.fault = fault
        self.on_sign = on_sign

    def public_key_v2(self) -> HybridPublicKey:
        return self.inner.public_key_v2()

    def mode_v2(self):
        if self.fault == "bad_mode":
            return 7
        return self.inner.mode_v2()

    def sign_v2(self, ctx, req: SignRequestV2) -> HybridSignature:
        if self.on_sign is not None:
            self.on_sign()
        if self.fault == "error":
            raise RuntimeError("provider unavailable")
        sig = self.inner.sign_v2(ctx, req)
        if self.fault == "flip_ed25519":
            return HybridSignature(bytes([sig.ed25519[0] ^ 1]) + sig.ed25519[1:], sig.ml_dsa_65)
        if self.fault == "flip_ml_dsa":
            return HybridSignature(sig.ed25519, bytes([sig.ml_dsa_65[0] ^ 1]) + sig.ml_dsa_65[1:])
        if self.fault == "short":
            return HybridSignature(sig.ed25519[:63], sig.ml_dsa_65)
        if self.fault == "none":
            return None
        return sig
