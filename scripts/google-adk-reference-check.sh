#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/references/google-adk"
VENV="$DEMO/.venv"

python3 -m venv "$VENV"
"$VENV/bin/pip" install --disable-pip-version-check -q -r "$DEMO/requirements.txt"

DEMO="$DEMO" "$VENV/bin/python" - <<'PY'
import importlib.metadata as metadata
import os
from pathlib import Path
import ratify_protocol

demo = Path(os.environ["DEMO"]).resolve()
repo = demo.parents[1]
module = Path(ratify_protocol.__file__).resolve()
local_sdk = (repo / "sdks" / "python").resolve()
if local_sdk == module or local_sdk in module.parents:
    raise SystemExit(f"FAIL: Ratify resolved from the repository: {module}")

expected = {
    "google-adk": "2.6.3",
    "mcp": "1.29.0",
    "ratify-protocol": "1.0.0a16",
}
for package, version in expected.items():
    installed = metadata.version(package)
    if installed != version:
        raise SystemExit(f"FAIL: {package}={installed}; expected {version}")

print(f"published Ratify: {module}")
print("pins: google-adk==2.6.3 mcp==1.29.0 ratify-protocol==1.0.0a16")
PY

RESULTS="$DEMO/.reference-results.xml"
trap 'rm -f "$RESULTS"' EXIT
PYTHONPATH="$DEMO" "$VENV/bin/pytest" -q -rsxX -p no:cacheprovider \
  --junitxml "$RESULTS" "$DEMO/tests"

"$VENV/bin/python" - "$RESULTS" <<'PY'
import sys
import xml.etree.ElementTree as ET

cases = list(ET.parse(sys.argv[1]).getroot().iter("testcase"))
skipped = sum(case.find("skipped") is not None for case in cases)
failed = sum(
    case.find("failure") is not None or case.find("error") is not None
    for case in cases
)
if len(cases) != 33 or skipped or failed:
    raise SystemExit(
        f"FAIL: expected 33 passed, zero skipped/failed; "
        f"got total={len(cases)} skipped={skipped} failed={failed}"
    )
print("gate: 33/33 passed; zero skipped, xfailed, failed, or errored")
PY
PYTHONPATH="$DEMO" "$VENV/bin/python" "$DEMO/demo.py"
