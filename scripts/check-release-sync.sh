#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python - <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(".")

def read(path: str) -> str:
    return (root / path).read_text()

def fail(msg: str) -> None:
    print(f"release-sync: {msg}", file=sys.stderr)
    sys.exit(1)

ts_pkg = json.loads(read("sdks/typescript/package.json"))
ts_lock = json.loads(read("sdks/typescript/package-lock.json"))
ts_version = ts_pkg["version"]
if ts_lock.get("version") != ts_version:
    fail(f"package-lock root version {ts_lock.get('version')} != package.json {ts_version}")
lock_pkg = ts_lock.get("packages", {}).get("", {})
if lock_pkg.get("version") != ts_version:
    fail(f"package-lock packages[''] version {lock_pkg.get('version')} != package.json {ts_version}")

pyproject = read("sdks/python/pyproject.toml")
py_match = re.search(r'^version = "([^"]+)"$', pyproject, re.M)
if not py_match:
    fail("missing Python version in sdks/python/pyproject.toml")
py_version = py_match.group(1)
py_init = read("sdks/python/src/ratify_protocol/__init__.py")
init_match = re.search(r'^__version__ = "([^"]+)"$', py_init, re.M)
if not init_match:
    fail("missing Python __version__")
if init_match.group(1) != py_version:
    fail(f"Python __version__ {init_match.group(1)} != pyproject {py_version}")

rust_toml = read("sdks/rust/Cargo.toml")
rust_match = re.search(r'^version = "([^"]+)"$', rust_toml, re.M)
if not rust_match:
    fail("missing Rust version in sdks/rust/Cargo.toml")
rust_version = rust_match.group(1)
rust_lock = read("sdks/rust/Cargo.lock")
lock_match = re.search(r'\[\[package\]\]\nname = "ratify-protocol"\nversion = "([^"]+)"', rust_lock)
if not lock_match:
    fail("missing ratify-protocol entry in Cargo.lock")
if lock_match.group(1) != rust_version:
    fail(f"Cargo.lock ratify-protocol {lock_match.group(1)} != Cargo.toml {rust_version}")

def py_to_semver(v: str) -> str:
    return re.sub(r'a(\d+)$', r'-alpha.\1', v)

if py_to_semver(py_version) != ts_version:
    fail(f"Python version {py_version} does not match TypeScript {ts_version}")
if rust_version != ts_version:
    fail(f"Rust version {rust_version} does not match TypeScript {ts_version}")

protocol_tag = f"v{ts_version}"
must_contain = {
    "README.md": protocol_tag,
    "SPEC.md": protocol_tag,
    "docs/RELEASES.md": protocol_tag,
    "sdks/rust/README.md": rust_version,
}
for path, needle in must_contain.items():
    if needle not in read(path):
        fail(f"{path} does not contain {needle}")

# Wire-format fixture count. cross_sdk_vectors.json is a separate
# alpha.7 byte-equivalence corpus and is not part of this count.
fixture_count = len([
    p for p in (root / "testvectors/v1").glob("*.json")
    if p.name != "cross_sdk_vectors.json"
])
fixture_needles = {
    "README.md": [
        f"{fixture_count} canonical test vectors",
        f"passes all {fixture_count}",
        f"{fixture_count}/{fixture_count}",
    ],
    "docs/SDKS.md": [
        f"{fixture_count}/{fixture_count} fixtures",
        f"Must pass all {fixture_count} fixtures",
        f"{fixture_count} ×",
    ],
    "docs/TESTING.md": [
        f"{fixture_count} canonical test vectors",
        f"all {fixture_count} fixtures",
    ],
    "docs/TEST_PLAN.md": [
        f"**{fixture_count} fixtures**",
        f"**{fixture_count} canonical fixtures**",
        f"every one of the {fixture_count} fixtures",
    ],
    "docs/RELEASES.md": [
        f"{fixture_count} canonical fixtures",
        f"pass all {fixture_count} fixtures",
    ],
    "sdks/python/README.md": [
        f"{fixture_count} canonical test vectors",
        f"runs {fixture_count}/{fixture_count} conformance fixtures",
        f"All {fixture_count} must pass",
    ],
    "sdks/rust/README.md": [
        f"{fixture_count} canonical test vectors",
        f"All {fixture_count} must pass",
    ],
    ".github/workflows/ci.yml": [
        f"conformance tests ({fixture_count} fixtures)",
    ],
}
for path, needles in fixture_needles.items():
    text = read(path)
    for needle in needles:
        if needle not in text:
            fail(f"{path} does not contain fixture-count marker: {needle}")

print(f"release-sync: ok ({protocol_tag})")
PY
