#!/usr/bin/env bash
# Deterministic gate for the Google ADK reference on Ratify Protocol v2.
#
# Builds the v2 SDK from this repository into an isolated virtual environment,
# installs the pinned platform packages, runs the full test matrix (it must
# pass every test, with nothing skipped), and runs the dual-root HTTP MCP demo.
#
#   RATIFY_REFERENCE_VENV  virtual environment to use (default: .venv here)
#   PYTHON                 interpreter that creates it (default: python3)
set -euo pipefail

DEMO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DEMO/../.." && pwd)"
VENV="${RATIFY_REFERENCE_VENV:-$DEMO/.venv}"
EXPECTED_TESTS=58
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PIP=(--disable-pip-version-check -q)

"${PYTHON:-python3}" -m venv "$VENV"
"$VENV/bin/python" -m pip install "${PIP[@]}" --upgrade pip 'maturin>=1.7,<2'

# RATIFY_V2_PIN: until 2.0.0-beta.1 is published, the SDK comes from this
# repository. At release, replace these two steps with the published pins.
(cd "$REPO/sdks/python-native-v2" && "$VENV/bin/maturin" build --release --quiet --out "$WORK/dist")
"$VENV/bin/python" -m pip install "${PIP[@]}" --force-reinstall \
  --find-links "$WORK/dist" "$REPO/sdks/python[protocol-v2]"
"$VENV/bin/python" -m pip install "${PIP[@]}" -r "$DEMO/requirements.txt"

DEMO="$DEMO" REPO="$REPO" "$VENV/bin/python" - <<'PY'
import importlib.metadata as metadata
import os
from pathlib import Path
import re
import ratify_protocol.v2

repo = Path(os.environ["REPO"]).resolve()
module = Path(ratify_protocol.v2.__file__).resolve()
if (repo / "sdks") in module.parents:
    raise SystemExit(f"FAIL: ratify_protocol.v2 imported from the source tree: {module}")
tree = re.search(r'^version = "([^"]+)"', (repo / "sdks/python/pyproject.toml").read_text(), re.M).group(1)
expected = {
    "google-adk": "2.6.3",
    "mcp": "1.30.0",
    "pytest": "9.0.3",
    "ratify-protocol": tree,
    "ratify-protocol-native-v2": tree,
}
for package, version in expected.items():
    installed = metadata.version(package)
    if installed != version:
        raise SystemExit(f"FAIL: {package}={installed}; expected {version}")
print(f"installed Ratify v2 SDK: {module}")
print(" ".join(f"{package}=={version}" for package, version in expected.items()))
PY

RESULTS="$WORK/results.xml"
(cd "$DEMO" && PYTHONPATH="$DEMO" "$VENV/bin/pytest" -q -rsxX -p no:cacheprovider \
  --junitxml "$RESULTS" "$DEMO/tests")

EXPECTED_TESTS="$EXPECTED_TESTS" "$VENV/bin/python" - "$RESULTS" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

expected = int(os.environ["EXPECTED_TESTS"])
cases = list(ET.parse(sys.argv[1]).getroot().iter("testcase"))
skipped = sum(case.find("skipped") is not None for case in cases)
failed = sum(
    case.find("failure") is not None or case.find("error") is not None
    for case in cases
)
if len(cases) != expected or skipped or failed:
    raise SystemExit(
        f"FAIL: expected {expected} passed, zero skipped/failed; "
        f"got total={len(cases)} skipped={skipped} failed={failed}"
    )
print(f"gate: {expected}/{expected} passed; zero skipped, xfailed, failed, or errored")
PY
(cd "$DEMO" && PYTHONPATH="$DEMO" "$VENV/bin/python" -W ignore "$DEMO/demo.py")
