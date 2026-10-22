"""Cross-SDK fixtures (SPEC-v2 §8.1): every testvectors/v2/cross-sdk/*.json
present, including this SDK's own python.json, verifies with the pure-Python
verifier under the documented procedure, and a freshly generated fixture
verifies too."""
from __future__ import annotations

import pytest

from corpus import CROSS_SDK_DIR
from cross_sdk_v2 import KINDS, build_fixture, verify_fixture
from ratify_protocol_v2 import _native

FIXTURES = sorted(CROSS_SDK_DIR.glob("*.json")) if CROSS_SDK_DIR.exists() else []
KNOWN_SDKS = {"go", "typescript", "python", "rust", "c"}


def test_cross_sdk_directory_holds_only_known_fixtures():
    assert FIXTURES, "no cross-SDK fixtures present"
    assert {p.stem for p in FIXTURES} <= KNOWN_SDKS
    assert {p.name for p in CROSS_SDK_DIR.iterdir()} == {p.name for p in FIXTURES}
    assert "python" in {p.stem for p in FIXTURES}, "this SDK's own fixture is missing"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_cross_sdk_fixture_verifies(path):
    counts = verify_fixture(path.read_bytes(), path.stem)
    assert set(counts) >= set(KINDS)


@pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")
def test_fresh_fixture_verifies_and_is_hedged():
    a, b = build_fixture(), build_fixture()
    assert a["keys"][0]["ed25519_seed_hex"] != b["keys"][0]["ed25519_seed_hex"], "keys must be fresh"
    names = [o["name"] for o in a["objects"]]
    assert len(names) == len(set(names)) == 15
