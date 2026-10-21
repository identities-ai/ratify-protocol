"""Optional native extra for Protocol v2 (`ratify-protocol-native-v2`).

The extension supplies native deterministic key generation only. It is not a
wire verifier: every signature and object check stays in this package.

Without the extension, everything works through the pure-Python fallback. With
it, its version must equal this SDK's lockstep version; a mismatch fails the
import of ratify_protocol_v2 rather than pairing with an extension built for a
different release.
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


def keypair_from_seeds(ed_seed: bytes, ml_seed: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Return (ed_pub, ml_pub, ed_priv, ml_priv) from the native extension."""
    if _ext is None:
        raise RuntimeError("ratify-protocol-native-v2 is not installed")
    return _ext.hybrid_keypair_from_seeds_py(ed_seed, ml_seed)
