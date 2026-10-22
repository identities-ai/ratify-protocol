"""Protocol v2 typed signing transcripts and strict hybrid verification.

Mirrors Go crypto_v2.go: every object code has its own 77-byte transcript
``"ratify-protocol-signature\\x00\\x02" || code || SHA-384(signable)`` and
ML-DSA-65 context ``"ratify-protocol/2/<code>"``. Verification is pure Python
and strict AND: canonical non-identity prime-order Ed25519 A and R, canonical
S, a valid Ed25519 signature, and a valid ML-DSA-65 signature under the code's
context. It handles only public data.

Every private-key operation goes through the ``ratify-protocol-native-v2``
extension (constant-time Ed25519 and ML-DSA-65); there is no pure-Python
signing path, and signing without the extension raises ImportError.
"""
from __future__ import annotations

from contextvars import ContextVar
from hashlib import sha256, sha384

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import _ed25519_strict, _mldsa65, _native
from .errors_v2 import V2Error, V2ErrorClass
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


def valid_object_type(code: int) -> bool:
    return isinstance(code, int) and DELEGATION_CERTIFICATE <= code <= KEY_ROTATION_PROOF_OF_POSSESSION


def key_id_v2(pub: HybridPublicKey) -> str:
    """Full 256-bit v2 key ID; raises ValueError on wrong component sizes."""
    if len(pub.ed25519) != 32:
        raise ValueError(f"Ed25519 public key wrong length: {len(pub.ed25519)}")
    if len(pub.ml_dsa_65) != _mldsa65.PUBLIC_KEY_SIZE:
        raise ValueError(f"ML-DSA-65 public key wrong length: {len(pub.ml_dsa_65)}")
    return sha256(_KEY_ID_PREFIX + bytes(pub.ed25519) + bytes(pub.ml_dsa_65)).hexdigest()


def signing_message_v2(code: int, signable: bytes) -> bytes:
    if not valid_object_type(code):
        raise ValueError(f"unsupported v2 object type: {code:04x}")
    return _SIGNATURE_PREFIX + code.to_bytes(2, "big") + sha384(signable).digest()


def mldsa_context_v2(code: int) -> bytes:
    if not valid_object_type(code):
        raise ValueError(f"unsupported v2 object type: {code:04x}")
    return f"ratify-protocol/2/{code:04x}".encode("ascii")


def keypair_from_seeds_v2(ed_seed: bytes, ml_seed: bytes) -> tuple[HybridPublicKey, HybridPrivateKey]:
    """Deterministic hybrid keypair (Go HybridKeypairFromSeeds).

    Requires the ``ratify-protocol-native-v2`` extension; raises ImportError
    without it. The returned private key is bytes-backed, so the key material
    crosses into Python here.
    """
    if len(ed_seed) != 32 or len(ml_seed) != 32:
        raise ValueError("hybrid seeds must be 32 bytes each")
    ed_pub, ml_pub, ed_priv, ml_priv = _native.keypair_from_seeds(bytes(ed_seed), bytes(ml_seed))
    return (
        HybridPublicKey(ed25519=bytes(ed_pub), ml_dsa_65=bytes(ml_pub)),
        HybridPrivateKey(ed25519=bytes(ed_priv), ml_dsa_65=bytes(ml_priv)),
    )


def _signing_key(priv: HybridPrivateKey):
    if len(priv.ed25519) != 32 or len(priv.ml_dsa_65) != _mldsa65.SECRET_KEY_SIZE:
        raise ValueError("incomplete hybrid private key")
    return _native.signing_key(bytes(priv.ed25519), bytes(priv.ml_dsa_65))


def public_key_of(priv: HybridPrivateKey) -> HybridPublicKey:
    """Derive the hybrid public key of a private key (native; ImportError without it)."""
    ed_pub, ml_pub = _signing_key(priv).public_key()
    return HybridPublicKey(ed25519=bytes(ed_pub), ml_dsa_65=bytes(ml_pub))


# Test-only switch for the FIPS 204 deterministic ML-DSA variant, which is how
# the shared vectors are generated. Set only through
# ratify_protocol_v2._testing.deterministic_test_vector_signing().
_DETERMINISTIC_FOR_TEST_VECTORS: ContextVar[bool] = ContextVar(
    "ratify_v2_deterministic_for_test_vectors", default=False
)


def _sign_v2_statement(code: int, signable: bytes, priv: HybridPrivateKey) -> HybridSignature:
    """Sign under the code's transcript and context through the native signer.

    Internal: callers are the typed signers, which first check that the key
    matches the object's bound signer. ML-DSA-65 is hedged unless the
    test-only deterministic switch is set. The signature is verified with the
    ordinary pure-Python verifier before it is returned.
    """
    key = _signing_key(priv)
    message = signing_message_v2(code, signable)
    context = mldsa_context_v2(code)
    ed_sig, ml_sig = key.sign(
        message, context, deterministic_for_test_vectors=_DETERMINISTIC_FOR_TEST_VECTORS.get()
    )
    signature = HybridSignature(ed25519=bytes(ed_sig), ml_dsa_65=bytes(ml_sig))
    ed_pub, ml_pub = key.public_key()
    try:
        verify_v2_statement(code, signable, signature, HybridPublicKey(ed25519=bytes(ed_pub), ml_dsa_65=bytes(ml_pub)))
    except V2Error as exc:
        raise RuntimeError(f"native v2 signature failed verification: {exc}") from exc
    return signature


def _verify_unclassified(code: int, signable: bytes, sig: HybridSignature, pub: HybridPublicKey) -> None:
    if len(pub.ed25519) != 32 or len(pub.ml_dsa_65) != _mldsa65.PUBLIC_KEY_SIZE:
        raise ValueError("hybrid public key has invalid component length")
    if len(sig.ed25519) != 64 or len(sig.ml_dsa_65) != _mldsa65.SIGNATURE_SIZE:
        raise ValueError("hybrid signature has invalid component length")
    if not _ed25519_strict.valid_prime_order_point(bytes(pub.ed25519)) or not _ed25519_strict.valid_prime_order_point(
        bytes(sig.ed25519[:32])
    ):
        raise ValueError(
            "Ed25519 v2 public key or R component is not a canonical non-identity prime-order point"
        )
    if not _ed25519_strict.valid_canonical_scalar(bytes(sig.ed25519[32:])):
        raise ValueError("Ed25519 v2 S component is not a canonical scalar")
    message = signing_message_v2(code, signable)
    context = mldsa_context_v2(code)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes(pub.ed25519)).verify(bytes(sig.ed25519), message)
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("Ed25519 v2 signature invalid") from exc
    if not _mldsa65.verify(bytes(pub.ml_dsa_65), message, context, bytes(sig.ml_dsa_65)):
        raise ValueError("ML-DSA-65 v2 signature invalid")


def verify_v2_statement(code: int, signable: bytes, sig: HybridSignature, pub: HybridPublicKey) -> None:
    """Go ``verifyV2Statement``: raises V2Error(unsupported_object_type) for an
    unregistered code and V2Error(invalid_signature) for every other failure."""
    if not valid_object_type(code):
        raise V2Error(V2ErrorClass.UNSUPPORTED_OBJECT_TYPE, f"unsupported v2 object type: {code:04x}")
    try:
        _verify_unclassified(code, signable, sig, pub)
    except V2Error:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure is invalid_signature
        raise V2Error(V2ErrorClass.INVALID_SIGNATURE, str(exc)) from exc


def equal_public_keys(a: HybridPublicKey, b: HybridPublicKey) -> bool:
    return bytes(a.ed25519) == bytes(b.ed25519) and bytes(a.ml_dsa_65) == bytes(b.ml_dsa_65)
