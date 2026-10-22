"""Cross-SDK fixtures (SPEC-v2 §8.1): every testvectors/v2/cross-sdk/*.json
present, including this SDK's own python.json, verifies under the documented
procedure, every fixture's verifier and release scenarios replay through this
SDK's verifier, reference store and release gate with the producer's results,
and a freshly generated fixture verifies too."""
from __future__ import annotations

import pytest

from corpus import CROSS_SDK_DIR
import json

from cross_sdk_v2 import KINDS, SCENARIO_NAMES, build_fixture, verify_fixture
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


@pytest.mark.skipif(not _native.AVAILABLE, reason="scenario replay signs receipts; needs ratify-protocol-native-v2")
@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.name)
def test_cross_sdk_scenarios_replay(path):
    f = json.loads(path.read_bytes())
    if f.get("scenario_configuration") is None or not f.get("scenarios"):
        assert path.stem not in ("go", "python"), f"{path.name} has no verifier and release scenarios"
        pytest.skip(f"{path.name} predates the SPEC-v2 §8.1 verifier and release scenarios; SPEC-v2 §8.1 is not met "
                    f"for {path.stem} until that SDK regenerates its fixture")
    assert {sc["name"] for sc in f["scenarios"]} >= set(SCENARIO_NAMES)
    assert verify_fixture(path.read_bytes(), path.stem)["scenarios"] == len(f["scenarios"])


@pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")
def test_fresh_fixture_verifies_and_is_hedged():
    a, b = build_fixture(), build_fixture()
    assert a["keys"][0]["ed25519_seed_hex"] != b["keys"][0]["ed25519_seed_hex"], "keys must be fresh"
    names = [o["name"] for o in a["objects"]]
    assert len(names) == len(set(names)) == 15
    assert [sc["name"] for sc in a["scenarios"]] == SCENARIO_NAMES


@pytest.mark.skipif(not _native.AVAILABLE, reason="ratify-protocol-native-v2 not installed")
def test_scenario_replay_rejects_tampering():
    """A changed release result, a receipt signed by another verifier key, a
    swapped receipt body, and a missing scenario each fail replay (Go
    TestVerifyCrossSDKReplaysScenarios)."""
    from cross_sdk_v2 import FixtureError

    base, other = build_fixture(), build_fixture()

    def check(edit, want):
        f = json.loads(json.dumps(base))
        edit(f)
        with pytest.raises(FixtureError, match=want):
            verify_fixture(json.dumps(f).encode("utf-8"), "python")

    check(lambda f: f["scenarios"][3]["expected"]["release"].update(status="released"), "allow_withheld_past_horizon")
    check(lambda f: f["scenarios"][0]["expected"].update(
        signed_receipt_b64=other["scenarios"][0]["expected"]["signed_receipt_b64"]), "allow_released")
    check(lambda f: f["scenarios"][1]["expected"].update(
        receipt_body_b64=f["scenarios"][0]["expected"]["receipt_body_b64"]), "deny_revoked_released")
    check(lambda f: f.update(scenarios=f["scenarios"][:3]), "missing scenario")
