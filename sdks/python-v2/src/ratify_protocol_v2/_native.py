"""The native extension for Protocol v2 (`ratify-protocol-native-v2`).

Every private-key operation (key generation, public-key derivation from a
private key, and signing) runs in this extension, which uses constant-time
Ed25519 and ML-DSA-65 implementations. There is no pure-Python signing path.
Verification handles only public data and stays in this package, so a
verify-only environment imports and verifies without the extension; any
private-key operation there raises ImportError.

The extension's version must equal this SDK's lockstep version; a mismatch
fails the import of ratify_protocol_v2 rather than pairing with an extension
built for a different release.
"""
from __future__ import annotations

from ._version import NATIVE_VERSION, __version__

try:
    import ratify_protocol_native_v2 as _ext
except ModuleNotFoundError as exc:
    if exc.name != "ratify_protocol_native_v2":
        raise
    _ext = None

if _ext is not None:
    _found = _ext.version()
    if _found != NATIVE_VERSION:
        raise ImportError(
            "ratify-protocol-native-v2 version mismatch: "
            f"ratify-protocol-v2 {__version__} requires native {NATIVE_VERSION}, "
            f"found {_found}"
        )

AVAILABLE = _ext is not None

MISSING_MESSAGE = (
    "Ratify Protocol v2 key generation and signing require the "
    f"ratify-protocol-native-v2=={__version__} extension, which is not installed. "
    "There is no pure-Python signing fallback; verification works without it."
)


def require():
    """Return the extension module, or raise ImportError if it is absent."""
    if _ext is None:
        raise ImportError(MISSING_MESSAGE, name="ratify_protocol_native_v2")
    return _ext


def keypair_from_seeds(ed_seed: bytes, ml_seed: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (ed_pub, ml_pub, ed_priv, ml_priv) from the native extension."""
    return require().hybrid_keypair_from_seeds_py(ed_seed, ml_seed)


def signing_key(ed25519: bytes, ml_dsa_65: bytes):
    """Load a native HybridSigningKey from the SDK's private-key bytes."""
    return require().HybridSigningKey.from_private_bytes(ed25519, ml_dsa_65)
