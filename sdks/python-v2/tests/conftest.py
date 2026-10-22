"""RATIFY_REQUIRE_NATIVE=1 turns a missing ratify-protocol-native-v2 into a
hard error instead of skipped signing tests."""
from __future__ import annotations

import os

from ratify_protocol_v2 import _native


def pytest_configure(config):
    if os.environ.get("RATIFY_REQUIRE_NATIVE") == "1" and not _native.AVAILABLE:
        raise RuntimeError("RATIFY_REQUIRE_NATIVE=1 but ratify-protocol-native-v2 is not installed")
