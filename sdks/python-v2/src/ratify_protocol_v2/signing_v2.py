"""Protocol v2 signing transcripts, strict hybrid verification, and the
typed-signer interface (Go crypto_v2.go and signer_v2.go).

Every object code has its own 77-byte transcript
``"ratify-protocol-signature\\x00\\x02" || u16be(code) || SHA-384(signable)``
and ML-DSA-65 context ``"ratify-protocol/2/<code>"``. Verification is pure
Python and strict AND: canonical non-identity prime-order Ed25519 A and R,
canonical S, a valid Ed25519 signature, and a valid ML-DSA-65 signature under
the code's context.

Signing goes only through the typed signing functions, which take either a
:class:`HybridPrivateKey` or an external :class:`SignerV2` provider. A
private key is signed with inside the ``ratify-protocol-native-v2``
extension through an internal signer that is never returned to callers;
there is no pure-Python signing path, and without the extension signing
raises ``ImportError``. External signers (an HSM or a key-management
service) implement :class:`SignerV2` in direct or external-mu mode and hold
their own keys. The SDK computes ``M``, the context and ``mu`` itself and
verifies every returned signature with the ordinary verifier before using
it. No public function in this package signs caller-selected bytes, object
codes, or contexts, and no local :class:`SignerV2` is exported (SPEC-v2
§3.2).
"""
from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha256, sha384, shake_256
from typing import Optional, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import _ed25519_strict, _mldsa65, _native
from .context_v2 import Context, require_context
from .errors_v2 import V2Error, V2ErrorClass, classified, classify
from .types import HybridPrivateKey, HybridPublicKey, HybridSignature

DELEGATION_CERTIFICATE = 0x0001
CHALLENGE_PRESENTATION = 0x0002
REVOCATION_LIST = 0x0003
KEY_ROTATION_AUTHORIZATION = 0x0004
REVOCATION_PUSH = 0x0005
WITNESS_ENTRY = 0x0006
TRANSACTION_PARTY_STATEMENT = 0x0007
VERIFICATION_RECEIPT = 0x0008
KEY_ROTATION_PROOF_OF_POSSESSION = 0x0009

_SIGNATURE_PREFIX = b"ratify-protocol-signature\x00\x02"
_KEY_ID_PREFIX = b"ratify-key-id-v2\x00"
V2_SIGNING_MESSAGE_SIZE = 77


class V2SigningError(V2Error, ValueError):
    """A typed signer refused or failed. ``error_class`` names the SPEC-v2
    §2.7 class when the failure fixes one; otherwise the public signing
    function that raises it assigns the class of its row."""

    def __init__(self, message: str, error_class: str = V2ErrorClass.UNCLASSIFIED):
        V2Error.__init__(self, error_class, message)


def valid_object_type(code: object) -> bool:
    return type(code) is int and DELEGATION_CERTIFICATE <= code <= KEY_ROTATION_PROOF_OF_POSSESSION


def _bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise ValueError("key and signature components must be bytes")
    return bytes(value)


def key_id_v2(pub: HybridPublicKey) -> str:
    """Full 256-bit v2 key ID; raises ``ValueError`` on wrong component sizes
    (Go ``keyIDV2``)."""
    if not isinstance(pub, HybridPublicKey):
        raise ValueError("a HybridPublicKey is required")
    ed, ml = _bytes(pub.ed25519), _bytes(pub.ml_dsa_65)
    if len(ed) != 32:
        raise ValueError(f"Ed25519 public key wrong length: {len(ed)}")
    if len(ml) != _mldsa65.PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-DSA-65 public key wrong length: {len(ml)}")
    return sha256(_KEY_ID_PREFIX + ed + ml).hexdigest()


def key_id_v2_classified(pub: HybridPublicKey) -> str:
    """Go ``KeyIDV2``: the v2 key ID of a complete hybrid public key, failing
    with the ``malformed`` class unless both components have exact lengths."""
    try:
        return key_id_v2(pub)
    except ValueError as exc:
        raise V2Error(V2ErrorClass.MALFORMED, str(exc)) from exc


def signing_message_v2(code: int, signable: bytes) -> bytes:
    if not valid_object_type(code):
        raise ValueError(f"unsupported v2 object type: {code!r}")
    return _SIGNATURE_PREFIX + code.to_bytes(2, "big") + sha384(bytes(signable)).digest()


def mldsa_context_v2(code: int) -> bytes:
    if not valid_object_type(code):
        raise ValueError(f"unsupported v2 object type: {code!r}")
    return f"ratify-protocol/2/{code:04x}".encode("ascii")


def external_mu_v2(ml_pub: bytes, ml_context: bytes, message: bytes) -> bytes:
    """FIPS 204 external mu: ``SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)``
    with ``tr = SHAKE256(ml_dsa_65_public_key, 64)`` (Go ``externalMuV2``)."""
    tr = shake_256(bytes(ml_pub)).digest(64)
    return shake_256(tr + b"\x00" + bytes([len(ml_context)]) + bytes(ml_context) + bytes(message)).digest(64)


def equal_public_keys(a: HybridPublicKey, b: HybridPublicKey) -> bool:
    return bytes(a.ed25519) == bytes(b.ed25519) and bytes(a.ml_dsa_65) == bytes(b.ml_dsa_65)


def clone_public_key(pub: HybridPublicKey) -> HybridPublicKey:
    return HybridPublicKey(ed25519=bytes(pub.ed25519), ml_dsa_65=bytes(pub.ml_dsa_65))


# ---------------------------------------------------------------------------
# Verification


def _verify_unclassified(code: int, signable: bytes, sig: HybridSignature, pub: HybridPublicKey) -> None:
    if not isinstance(pub, HybridPublicKey) or not isinstance(sig, HybridSignature):
        raise ValueError("hybrid key and signature are required")
    pub_ed, pub_ml = _bytes(pub.ed25519), _bytes(pub.ml_dsa_65)
    sig_ed, sig_ml = _bytes(sig.ed25519), _bytes(sig.ml_dsa_65)
    if len(pub_ed) != 32 or len(pub_ml) != _mldsa65.PUBLIC_KEY_SIZE:
        raise ValueError("hybrid public key has invalid component length")
    if len(sig_ed) != 64 or len(sig_ml) != _mldsa65.SIGNATURE_SIZE:
        raise ValueError("hybrid signature has invalid component length")
    if not _ed25519_strict.valid_prime_order_point(pub_ed) or not _ed25519_strict.valid_prime_order_point(sig_ed[:32]):
        raise ValueError("Ed25519 v2 public key or R component is not a canonical non-identity prime-order point")
    if not _ed25519_strict.valid_canonical_scalar(sig_ed[32:]):
        raise ValueError("Ed25519 v2 S component is not a canonical scalar")
    message = signing_message_v2(code, signable)
    context = mldsa_context_v2(code)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub_ed).verify(sig_ed, message)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Ed25519 v2 signature invalid") from exc
    if not _mldsa65.verify(pub_ml, message, context, sig_ml):
        raise ValueError("ML-DSA-65 v2 signature invalid")


def verify_v2_statement(code: int, signable: bytes, sig: HybridSignature, pub: HybridPublicKey) -> None:
    """Go ``verifyV2Statement``: ``unsupported_object_type`` for an
    unregistered code and ``invalid_signature`` for every other failure."""
    if not valid_object_type(code):
        raise V2Error(V2ErrorClass.UNSUPPORTED_OBJECT_TYPE, f"unsupported v2 object type: {code!r}")
    try:
        _verify_unclassified(code, signable, sig, pub)
    except V2Error:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure is invalid_signature
        raise V2Error(V2ErrorClass.INVALID_SIGNATURE, str(exc)) from exc


# ---------------------------------------------------------------------------
# Signer interface


class SignerModeV2(IntEnum):
    """Which ML-DSA-65 input an external signer receives."""

    DIRECT = 1  # sign ``message`` under ``mldsa_context`` (FIPS 204 pure mode)
    EXTERNAL_MU = 2  # sign the 64-byte ``mldsa_mu`` the SDK derived


@dataclass(frozen=True)
class SignRequestV2:
    """Everything an external signer receives for one typed statement. The
    SDK computes every field; the provider never receives the object or its
    type code and never chooses a message or context. Ed25519 always signs
    ``message``."""

    mode: SignerModeV2
    message: bytes  # the 77-byte M
    mldsa_context: Optional[bytes]  # direct mode only
    mldsa_mu: Optional[bytes]  # external-mu mode only
    public_key: HybridPublicKey
    key_id: str


@runtime_checkable
class SignerV2(Protocol):
    """An external signing provider (Go ``SignerV2``).

    ``public_key_v2`` returns the complete hybrid key the provider signs
    under; it must be stable. ``mode_v2`` returns a :class:`SignerModeV2`.
    ``sign_v2(ctx, req)`` returns a :class:`HybridSignature`. The SDK never
    trusts the output: every returned signature is verified before use, and
    a signature returned after ``ctx`` was cancelled is discarded. ML-DSA
    signing may be hedged, so retries can return different valid bytes."""

    def public_key_v2(self) -> HybridPublicKey: ...

    def mode_v2(self) -> SignerModeV2: ...

    def sign_v2(self, ctx: Context, req: SignRequestV2) -> HybridSignature: ...


# Test-only switch for the FIPS 204 deterministic ML-DSA variant, which is how
# the shared vectors are generated. Set only through
# ratify_protocol_v2._testing.deterministic_test_vector_signing().
_DETERMINISTIC_FOR_TEST_VECTORS: ContextVar[bool] = ContextVar(
    "ratify_v2_deterministic_for_test_vectors", default=False
)


class _LocalSignerV2:
    """A direct-mode signer backed by a native in-process hybrid key.
    Internal: only the typed signing functions create one, and it is never
    returned to a caller, because a local SignerV2 in a caller's hands would
    sign any well-formed message under any context the caller chose."""

    __slots__ = ("_key", "_public")

    def __init__(self, native_key) -> None:
        self._key = native_key
        ed_pub, ml_pub = native_key.public_key()
        self._public = HybridPublicKey(ed25519=bytes(ed_pub), ml_dsa_65=bytes(ml_pub))

    def public_key_v2(self) -> HybridPublicKey:
        return clone_public_key(self._public)

    def mode_v2(self) -> SignerModeV2:
        return SignerModeV2.DIRECT

    @classified(V2ErrorClass.CONFIGURATION_INVALID)
    def sign_v2(self, ctx: Context, req: SignRequestV2) -> HybridSignature:
        err = require_context(ctx).err()
        if err is not None:
            raise err
        if req.mode != SignerModeV2.DIRECT or len(req.message) != V2_SIGNING_MESSAGE_SIZE or not req.mldsa_context:
            raise V2SigningError("local v2 signer supports only direct-mode requests")
        ed_sig, ml_sig = self._key._sign(
            bytes(req.message), bytes(req.mldsa_context),
            deterministic_for_test_vectors=_DETERMINISTIC_FOR_TEST_VECTORS.get(),
        )
        return HybridSignature(ed25519=bytes(ed_sig), ml_dsa_65=bytes(ml_sig))

    def __repr__(self) -> str:
        return "<LocalSignerV2>"


@classified(V2ErrorClass.CONFIGURATION_INVALID)
def _new_local_signer_v2(private_key: HybridPrivateKey) -> SignerV2:
    """Internal: the direct-mode signer the typed signing functions use for
    an in-process hybrid private key. Not public API and not re-exported.
    The key is loaded into the native extension (ImportError without it).
    ML-DSA-65 signatures are hedged."""
    if not isinstance(private_key, HybridPrivateKey):
        raise V2SigningError("a HybridPrivateKey is required")
    ed, ml = bytes(private_key.ed25519), bytes(private_key.ml_dsa_65)
    if len(ed) != 32 or len(ml) != _mldsa65.SECRET_KEY_SIZE:
        raise V2SigningError("incomplete hybrid private key")
    try:
        native = _native.signing_key(ed, ml)
    except ImportError:
        raise
    except Exception as exc:  # noqa: BLE001 - the extension reports malformed keys as ValueError
        raise V2SigningError(f"invalid hybrid private key: {exc}") from exc
    return _LocalSignerV2(native)


def _as_signer(signer_or_key) -> SignerV2:
    """Typed private-key signing functions accept a HybridPrivateKey and wrap
    it in a local signer, so local and external signing share one path."""
    if isinstance(signer_or_key, HybridPrivateKey):
        return _new_local_signer_v2(signer_or_key)
    return signer_or_key


def signer_public_key_v2(signer: SignerV2) -> HybridPublicKey:
    """Go ``signerPublicKeyV2``: the complete key a signer signs under."""
    if signer is None:
        raise V2SigningError("v2 signer is required", V2ErrorClass.CONFIGURATION_INVALID)
    if isinstance(signer, _LocalSignerV2):
        return signer.public_key_v2()
    pub = signer.public_key_v2()
    try:
        key_id_v2(pub)
    except ValueError as exc:
        raise V2SigningError(f"v2 signer public key: {exc}", V2ErrorClass.CONFIGURATION_INVALID) from exc
    return clone_public_key(pub)


def _sign_v2_statement_with_signer(
    ctx: Context, code: int, signable: bytes, signer: SignerV2, pub: HybridPublicKey
) -> HybridSignature:
    """Go ``signV2StatementWithSigner``: prepare the typed request, call the
    signer, and verify the returned signature under ``pub`` before returning
    it. Internal: only the typed signers call it."""
    if not isinstance(ctx, Context):
        raise V2SigningError("v2 signing requires a context", V2ErrorClass.CONFIGURATION_INVALID)
    err = ctx.err()
    if err is not None:
        raise err
    message = signing_message_v2(code, signable)
    ml_context = mldsa_context_v2(code)
    key_id = key_id_v2(pub)
    try:
        mode = SignerModeV2(signer.mode_v2())
    except ValueError as exc:
        raise V2SigningError("v2 signer reports an unsupported mode", V2ErrorClass.CONFIGURATION_INVALID) from exc
    if mode == SignerModeV2.DIRECT:
        req = SignRequestV2(mode, message, ml_context, None, clone_public_key(pub), key_id)
    else:
        req = SignRequestV2(mode, message, None, external_mu_v2(bytes(pub.ml_dsa_65), ml_context, message),
                            clone_public_key(pub), key_id)
    try:
        signature = signer.sign_v2(ctx, req)
    except ImportError:
        raise
    except Exception as exc:  # noqa: BLE001 - provider errors fail signing
        if isinstance(exc, (V2SigningError,)) or exc is ctx.err():
            classify(V2ErrorClass.CONFIGURATION_INVALID, exc)
            raise
        raise V2SigningError(f"v2 signer: {exc}", V2ErrorClass.CONFIGURATION_INVALID) from exc
    err = ctx.err()
    if err is not None:
        raise err
    if not isinstance(signature, HybridSignature):
        raise V2SigningError("v2 signer returned no hybrid signature", V2ErrorClass.INVALID_SIGNATURE)
    try:
        signature = HybridSignature(ed25519=_bytes(signature.ed25519), ml_dsa_65=_bytes(signature.ml_dsa_65))
    except ValueError as exc:
        raise V2SigningError(f"v2 signer returned a malformed signature: {exc}", V2ErrorClass.INVALID_SIGNATURE) from exc
    try:
        verify_v2_statement(code, signable, signature, pub)
    except V2Error as exc:
        raise V2SigningError(f"v2 signer returned a signature that does not verify: {exc}", V2ErrorClass.INVALID_SIGNATURE) from exc
    return signature


# ---------------------------------------------------------------------------
# Key material (native only)


def keypair_from_seeds_v2(ed_seed: bytes, ml_seed: bytes) -> tuple[HybridPublicKey, HybridPrivateKey]:
    """Deterministic hybrid keypair from two 32-byte seeds (Go
    ``HybridKeypairFromSeeds``). Requires the native extension."""
    if len(ed_seed) != 32 or len(ml_seed) != 32:
        raise ValueError("hybrid seeds must be 32 bytes each")
    ed_pub, ml_pub, ed_priv, ml_priv = _native.keypair_from_seeds(bytes(ed_seed), bytes(ml_seed))
    return (
        HybridPublicKey(ed25519=bytes(ed_pub), ml_dsa_65=bytes(ml_pub)),
        HybridPrivateKey(ed25519=bytes(ed_priv), ml_dsa_65=bytes(ml_priv)),
    )


def generate_keypair_v2() -> tuple[HybridPublicKey, HybridPrivateKey]:
    """A fresh hybrid keypair from operating-system randomness (native)."""
    return keypair_from_seeds_v2(os.urandom(32), os.urandom(32))


def public_key_of(priv: HybridPrivateKey) -> HybridPublicKey:
    """The hybrid public key of a private key (native; ImportError without it)."""
    return _new_local_signer_v2(priv).public_key_v2()
