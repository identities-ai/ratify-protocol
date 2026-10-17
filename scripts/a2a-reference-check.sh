#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="$ROOT/references/a2a"
VENV="$REF/.venv"

python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --disable-pip-version-check -q -r "$REF/requirements.txt"

REF="$REF" "$VENV/bin/python" - <<'PY'
import importlib.metadata as metadata
import os
from pathlib import Path
import ratify_protocol

ref = Path(os.environ["REF"]).resolve()
repo = ref.parents[1]
module = Path(ratify_protocol.__file__).resolve()
local_sdk = (repo / "sdks" / "python").resolve()
if local_sdk == module or local_sdk in module.parents:
    raise SystemExit(f"FAIL: Ratify resolved from the repository: {module}")
for package, expected in {
    "a2a-sdk": "1.2.2", "google-adk": "2.6.3", "mcp": "1.29.0",
    "ratify-protocol": "1.0.0a20",
}.items():
    actual = metadata.version(package)
    if actual != expected:
        raise SystemExit(f"FAIL: {package}={actual}; expected {expected}")
print(f"published Ratify: {module}")
PY

RESULTS="$REF/.reference-results.xml"
trap 'rm -f "$RESULTS"' EXIT
PYTHONPATH="$REF" "$VENV/bin/pytest" -q -rsxX -p no:cacheprovider \
  --junitxml "$RESULTS" "$REF/tests"

"$VENV/bin/python" - "$RESULTS" <<'PY'
import sys
import xml.etree.ElementTree as ET

cases = list(ET.parse(sys.argv[1]).getroot().iter("testcase"))
skipped = sum(case.find("skipped") is not None for case in cases)
failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
if len(cases) != 4 or skipped or failed:
    raise SystemExit(f"FAIL: expected 4 passed, zero skipped/failed; got total={len(cases)} skipped={skipped} failed={failed}")
print("gate: 4/4 passed; zero skipped, xfailed, failed, or errored")
PY
