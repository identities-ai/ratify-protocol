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

c_toml = read("sdks/c/Cargo.toml")
c_match = re.search(r'^version = "([^"]+)"$', c_toml, re.M)
if not c_match:
    fail("missing C version in sdks/c/Cargo.toml")
c_version = c_match.group(1)
c_dep_match = re.search(r'ratify-protocol = \{ path = "\.\./rust", version = "([^"]+)" \}', c_toml)
if not c_dep_match:
    fail("missing ratify-protocol dependency pin in sdks/c/Cargo.toml")
cbindgen = read("sdks/c/cbindgen.toml")
c_banner_match = re.search(r'\* Version: (\S+)', cbindgen)

def py_to_semver(v: str) -> str:
    return re.sub(r'a(\d+)$', r'-alpha.\1', v)

if py_to_semver(py_version) != ts_version:
    fail(f"Python version {py_version} does not match TypeScript {ts_version}")
if rust_version != ts_version:
    fail(f"Rust version {rust_version} does not match TypeScript {ts_version}")
if c_version != ts_version:
    fail(f"C version {c_version} does not match TypeScript {ts_version}")
if c_dep_match.group(1) != ts_version:
    fail(f"C ratify-protocol dependency pin {c_dep_match.group(1)} does not match {ts_version}")
if not c_banner_match or c_banner_match.group(1) != ts_version:
    got = c_banner_match.group(1) if c_banner_match else "missing"
    fail(f"cbindgen.toml header banner version {got} does not match {ts_version}")

# Install pins. The alpha.13 npm tarball shipped with a README that still
# pinned alpha.10 — registries render the README snapshotted at publish
# time, so a stale pin becomes the package's public install instruction
# until the next release. Two-part check: the pinned install command must
# be present, and no OTHER release version may appear anywhere in these
# files. (Pattern covers pre-release forms; extend when stable versions
# ship.)
install_pins = {
    "sdks/typescript/README.md": [f"npm install @identities-ai/ratify-protocol@{ts_version}"],
    "sdks/python/README.md": [f"pip install ratify-protocol=={py_version}"],
    "sdks/rust/README.md": [f'ratify-protocol = "{rust_version}"'],
    "sdks/go/README.md": [f"go get github.com/identities-ai/ratify-protocol@v{ts_version}"],
    "README.md": [
        f"go get github.com/identities-ai/ratify-protocol@v{ts_version}",
        f"pip install ratify-protocol=={py_version}",
        f"cargo add ratify-protocol@{rust_version}",
    ],
}
for path, needles in install_pins.items():
    content = read(path)
    for needle in needles:
        if needle not in content:
            fail(f"{path} is missing the pinned install command: {needle}")

release_version_re = re.compile(r"\d+\.\d+\.\d+-(?:alpha|beta|rc)\.\d+|\d+\.\d+\.\d+(?:a|b|rc)\d+")
current_versions = {ts_version, py_version, rust_version, c_version}
for path in [*install_pins, "sdks/c/README.md"]:
    for found in sorted(set(release_version_re.findall(read(path)))):
        if found not in current_versions:
            fail(f"{path} references release version {found} but current is {ts_version} — stale pin?")

# One protocol, one description. The canonical tagline must appear on every
# public face of the project: root README, SPEC subtitle, all five SDK
# READMEs, the three registry metadata descriptions, and the Go package doc
# (pkg.go.dev). Edit it everywhere or nowhere.
CANONICAL_TAGLINE = "delegated-authority proofs for human-agent and agent-agent interactions"
tagline_files = [
    "README.md",
    "SPEC.md",
    "sdks/go/README.md",
    "sdks/typescript/README.md",
    "sdks/python/README.md",
    "sdks/rust/README.md",
    "sdks/c/README.md",
    "sdks/typescript/package.json",
    "sdks/python/pyproject.toml",
    "sdks/rust/Cargo.toml",
    "sdks/python/src/ratify_protocol/__init__.py",
    "sdks/rust/src/lib.rs",
    "verify.go",
]
for path in tagline_files:
    if CANONICAL_TAGLINE not in read(path).lower().replace("\n// ", " "):
        fail(f"{path} does not carry the canonical tagline ({CANONICAL_TAGLINE!r})")

protocol_tag = f"v{ts_version}"
# docs/RELEASES.md is deliberately absent: its version strings are
# historical (the §3.2 ladder) or illustrative examples, not release-synced.
must_contain = {
    "README.md": protocol_tag,
    "SPEC.md": protocol_tag,
    "sdks/go/README.md": protocol_tag,
    "sdks/typescript/README.md": ts_version,
    "sdks/python/README.md": py_version,
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
        f"full {fixture_count}-fixture conformance suite",
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
        f"The fixture count of {fixture_count} breaks down",
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
    "SPEC.md": [
        f"{fixture_count} fixtures as of",
        f"The {fixture_count} fixtures in",
    ],
    "sdks/typescript/README.md": [
        f"{fixture_count} canonical test vectors",
    ],
    "sdks/go/README.md": [
        f"{fixture_count} canonical test vectors",
    ],
    "sdks/c/README.md": [
        f"{fixture_count} canonical test vectors",
        f"{fixture_count}/{fixture_count} fixtures",
    ],
}
for path, needles in fixture_needles.items():
    text = read(path)
    for needle in needles:
        if needle not in text:
            fail(f"{path} does not contain fixture-count marker: {needle}")

# Canonical scope count, derived from the Go reference vocabulary. Docs that
# state the count must agree with scope.go.
scope_count = len(re.findall(r'^\tScope\w+\s+=\s+"', read("scope.go"), re.M))
scope_needles = {
    "README.md": [f"Canonical {scope_count}-scope vocabulary"],
    "SPEC.md": [f"{scope_count} canonical scope strings"],
    "docs/ROADMAP.md": [f"**{scope_count} canonical scopes**"],
    "sdks/typescript/README.md": [f"{scope_count} canonical scopes"],
    "sdks/python/README.md": [f"{scope_count} canonical scopes"],
    "sdks/rust/README.md": [f"{scope_count} canonical scopes"],
}
for path, needles in scope_needles.items():
    text = read(path)
    for needle in needles:
        if needle not in text:
            fail(f"{path} does not contain scope-count marker: {needle}")

print(f"release-sync: ok ({protocol_tag}, {fixture_count} fixtures, {scope_count} scopes)")
PY
