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

PYTHONPATH="$DEMO" "$VENV/bin/pytest" -q "$DEMO/tests"
PYTHONPATH="$DEMO" "$VENV/bin/python" "$DEMO/demo.py"
