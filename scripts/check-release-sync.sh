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

# The IANA time zone database must stay declared. Without it a verifier
# resolves no zone and denies every time_window constraint, so the same bundle
# verifies on one host and is rejected on another. The only CI job that would
# notice is the Windows wheel leg, so a dependency tidy-up could drop this and
# look green everywhere else.
if not re.search(r'^\s*"tzdata[><=~ ]', pyproject, re.M):
    fail("sdks/python/pyproject.toml must declare tzdata (time_window needs an IANA database)")

native_toml = read("sdks/python-native/Cargo.toml")
native_match = re.search(r'^version = "([^"]+)"$', native_toml, re.M)
if not native_match:
    fail("missing version in sdks/python-native/Cargo.toml")
native_version = native_match.group(1)

# sdks/rust is the v2 crate, so the v1 extension must not build against it
# through a path dependency. It pins the published v1 crate exactly instead.
native_core = re.search(r'^ratify-protocol = "=(1\.[^"]+)"$', native_toml, re.M)
if not native_core:
    fail(
        "sdks/python-native/Cargo.toml must pin the v1 ratify-protocol crate "
        'exactly (ratify-protocol = "=1.x"), not the v2 path crate'
    )

# The Python SDK pins the optional v1 native extra to an exact version, so the
# two must move together. If they drift, `pip install ratify-protocol[native]`
# resolves to nothing and the extra silently becomes uninstallable.
pyproject_native = re.search(r'"ratify-protocol-native==([^"]+)"', pyproject)
if not pyproject_native:
    fail("missing ratify-protocol-native pin in sdks/python/pyproject.toml")

# Optional-dependency groups (extras) of sdks/python. pip 25.0 fails to
# resolve the package at all, with or without extras, when an extra name
# parses as a PEP 440 version (as "v2" does), so no extra may.
extras_section = re.search(r'^\[project\.optional-dependencies\]\n(.*?)(?=^\[)', pyproject, re.M | re.S)
if not extras_section:
    fail("missing [project.optional-dependencies] in sdks/python/pyproject.toml")
extras = dict(re.findall(r'^([A-Za-z0-9][A-Za-z0-9._-]*) = \[(.*?)^\]', extras_section.group(1), re.M | re.S))
try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    print("release-sync: note: packaging is not importable; skipped the check that no extra name parses as a version")
else:
    for extra in extras:
        try:
            Version(extra)
        except InvalidVersion:
            continue
        fail(f"sdks/python/pyproject.toml extra {extra!r} parses as a version; pip 25.0 cannot resolve the package")
if "protocol-v2" not in extras:
    fail("sdks/python/pyproject.toml must define the protocol-v2 extra (Protocol v2's requirements)")


def py_to_semver(v: str) -> str:
    v = re.sub(r'a(\d+)$', r'-alpha.\1', v)
    v = re.sub(r'b(\d+)$', r'-beta.\1', v)
    return re.sub(r'rc(\d+)$', r'-rc.\1', v)

def semver_to_py(v: str) -> str:
    v = re.sub(r'-alpha\.(\d+)$', r'a\1', v)
    v = re.sub(r'-beta\.(\d+)$', r'b\1', v)
    return re.sub(r'-rc\.(\d+)$', r'rc\1', v)

# Two release lines live in this tree.
#   v2: TypeScript, Rust, C, Go (module path /v2), the ratify-protocol Python
#       distribution (sdks/python: v1 at ratify_protocol, v2 at
#       ratify_protocol.v2) and python-native-v2
#   v1: the v1 native extra (sdks/python-native) and the v1 maintenance
#       release it belongs to, which the [native] extra pins
# Each line must agree with itself; the lines do not have to agree with each
# other.
v2_version = ts_version
v1_version = native_version
v1_py_version = semver_to_py(v1_version)
if not v2_version.startswith("2."):
    fail(f"TypeScript version {v2_version} is not on the v2 line")
if not v1_version.startswith("1."):
    fail(f"Python native extra version {v1_version} is not on the v1 line")

# The Python distribution is on the v2 line, with v2's requirements in the
# protocol-v2 extra: the v2 native extension, pinned to this release, and the
# exact tzdata release SPEC-v2 evaluates against.
if py_version != semver_to_py(v2_version):
    fail(f"Python SDK version {py_version} is not the v2 line {v2_version} in PEP 440 form")
pyv2_ver_py = read("sdks/python/src/ratify_protocol/v2/_version.py")
pyv2_init = re.search(r'^__version__ = "([^"]+)"$', pyv2_ver_py, re.M)
pyv2_native_const = re.search(r'^NATIVE_VERSION = "([^"]+)"$', pyv2_ver_py, re.M)
if not pyv2_init or not pyv2_native_const:
    fail("sdks/python/src/ratify_protocol/v2/_version.py must define __version__ and NATIVE_VERSION")
if pyv2_init.group(1) != py_version:
    fail(f"ratify_protocol.v2 __version__ {pyv2_init.group(1)} != pyproject {py_version}")
if pyv2_native_const.group(1) != v2_version:
    fail(f"ratify_protocol.v2 NATIVE_VERSION {pyv2_native_const.group(1)} != v2 line {v2_version}")
protocol_v2_extra = extras["protocol-v2"]
pyv2_native_pin = re.search(r'"ratify-protocol-native-v2==([^"]+)"', protocol_v2_extra)
if not pyv2_native_pin or pyv2_native_pin.group(1) != py_version:
    got = pyv2_native_pin.group(1) if pyv2_native_pin else "missing"
    fail(f"protocol-v2 extra ratify-protocol-native-v2 pin {got} does not match the Python SDK {py_version}")
if not re.search(r'"tzdata==[^"]+"', protocol_v2_extra):
    fail("the protocol-v2 extra must pin tzdata exactly (SPEC-v2 time_window evaluation)")
# The base requirements must stay v1's, so a v1 install that resolves to this
# release is unaffected.
base_deps = re.search(r'^dependencies = \[(.*?)^\]', pyproject, re.M | re.S)
if not base_deps or "ratify-protocol-native-v2" in base_deps.group(1):
    fail("sdks/python/pyproject.toml base dependencies must not require ratify-protocol-native-v2")
native_v2_toml = read("sdks/python-native-v2/Cargo.toml")
native_v2_match = re.search(r'^version = "([^"]+)"$', native_v2_toml, re.M)
if not native_v2_match:
    fail("missing version in sdks/python-native-v2/Cargo.toml")
if native_v2_match.group(1) != v2_version:
    fail(f"python-native-v2 version {native_v2_match.group(1)} does not match v2 line {v2_version}")

# npm dist-tag. A v2 prerelease must publish under `next` (publishConfig and
# the release workflow agree) so it never becomes `latest`; `latest` stays on
# v1 until 2.0.0.
if "-" in v2_version and ts_pkg.get("publishConfig", {}).get("tag") != "next":
    fail(f"sdks/typescript/package.json publishConfig.tag must be 'next' for v2 prerelease {v2_version}")
if "2.*-*) DIST_TAG=next ;;" not in read(".github/workflows/release.yml"):
    fail(".github/workflows/release.yml must publish v2 prereleases under the next dist-tag")

if rust_version != ts_version:
    fail(f"Rust version {rust_version} does not match TypeScript {ts_version}")
if c_version != ts_version:
    fail(f"C version {c_version} does not match TypeScript {ts_version}")
if pyproject_native.group(1) != v1_py_version:
    fail(
        f"ratify-protocol-native pin {pyproject_native.group(1)} does not match "
        f"the v1 native extra version {v1_py_version}"
    )
if c_dep_match.group(1) != ts_version:
    fail(f"C ratify-protocol dependency pin {c_dep_match.group(1)} does not match {ts_version}")
if not c_banner_match or c_banner_match.group(1) != ts_version:
    got = c_banner_match.group(1) if c_banner_match else "missing"
    fail(f"cbindgen.toml header banner version {got} does not match {ts_version}")
header_banner = re.search(r'^ \* Version: (\S+)$', read("sdks/c/include/ratify.h"), re.M)
if not header_banner or header_banner.group(1) != ts_version:
    got = header_banner.group(1) if header_banner else "missing"
    fail(f"sdks/c/include/ratify.h banner version {got} does not match {ts_version}")

# Programs that build against the in-tree v2 SDKs record its version in their
# lockfiles, and the cross-SDK fixture generator defaults to a development
# build of it. scripts/release.sh rewrites all of these on a bump.
for lock_file in ("demos/rust/Cargo.lock", "examples/v2/rust/Cargo.lock",
                  "sdks/python/bench_v2/rust/Cargo.lock"):
    entry = re.search(r'\[\[package\]\]\nname = "ratify-protocol"\nversion = "([^"]+)"', read(lock_file))
    if not entry or entry.group(1) != ts_version:
        got = entry.group(1) if entry else "missing"
        fail(f"{lock_file} ratify-protocol {got} does not match {ts_version}")
for lock_file, key in (("examples/v2/typescript/package-lock.json", "../../../sdks/typescript"),
                       ("references/github-copilot/package-lock.json", "../../sdks/typescript")):
    got = json.loads(read(lock_file)).get("packages", {}).get(key, {}).get("version", "missing")
    if got != ts_version:
        fail(f"{lock_file} in-tree SDK entry {got} does not match {ts_version}")
cross_sdk_default = re.search(r'"sdk-version", "([^"]+)\+dev"', read("cmd/ratify-v2-cross-sdk/main.go"))
if not cross_sdk_default or cross_sdk_default.group(1) != ts_version:
    got = cross_sdk_default.group(1) if cross_sdk_default else "missing"
    fail(f"cmd/ratify-v2-cross-sdk default sdk-version {got} does not match {ts_version}+dev")
# The committed cross-SDK fixtures name the SDK release that produced them;
# a fixture from another release would claim interoperability nobody ran.
# Go may also record the untagged "+dev" form of the line.
for sdk, want in (("go", ts_version), ("typescript", ts_version), ("python", py_version),
                  ("rust", ts_version), ("c", ts_version)):
    got = json.loads(read(f"testvectors/v2/cross-sdk/{sdk}.json")).get("sdk_version", "missing")
    if got != want and not (sdk == "go" and got == want + "+dev"):
        fail(f"testvectors/v2/cross-sdk/{sdk}.json sdk_version {got} is not the v2 line {want}; regenerate it")
for line in read("docs/V2_REFERENCE_COMPATIBILITY.md").splitlines():
    if line.startswith("| ") and "| `sdks/" in line:
        for found in re.findall(r"`(2\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+|(?:a|b|rc)\d+))`", line):
            if found not in (ts_version, py_version):
                fail(f"docs/V2_REFERENCE_COMPATIBILITY.md SDK row names {found}; the v2 line is {ts_version}")

# Install pins. The alpha.13 npm tarball shipped with a README that still
# pinned alpha.10 — registries render the README snapshotted at publish
# time, so a stale pin becomes the package's public install instruction
# until the next release. Two-part check: the pinned install command must
# be present, and no OTHER release version may appear anywhere in these
# files. (Pattern covers pre-release forms; extend when stable versions
# ship.)
install_pins = {
    "sdks/typescript/README.md": [f"npm install @identities-ai/ratify-protocol@{ts_version}"],
    "sdks/python/README.md": [
        f'pip install "ratify-protocol[protocol-v2]=={py_version}"',
        f"ratify-protocol=={v1_py_version}",
    ],
    # The native extension comes with the protocol-v2 extra and is never
    # imported directly, so its README installs the SDK with that extra.
    "sdks/python-native-v2/README.md": [f'pip install "ratify-protocol[protocol-v2]=={py_version}"'],
    "sdks/rust/README.md": [f'ratify-protocol = "{rust_version}"'],
    "sdks/go/README.md": [f"go get github.com/identities-ai/ratify-protocol/v2@v{v2_version}"],
    "README.md": [
        f"go get github.com/identities-ai/ratify-protocol/v2@v{v2_version}",
        f'pip install "ratify-protocol[protocol-v2]=={py_version}"',
        f"pip install ratify-protocol=={v1_py_version}",
        f"cargo add ratify-protocol@{rust_version}",
    ],
}
for path, needles in install_pins.items():
    content = read(path)
    for needle in needles:
        if needle not in content:
            fail(f"{path} is missing the pinned install command: {needle}")

release_version_re = re.compile(r"\d+\.\d+\.\d+-(?:alpha|beta|rc)\.\d+|\d+\.\d+\.\d+(?:a|b|rc)\d+")
current_versions = {v2_version, py_version, v1_version, v1_py_version}
# Older v1 versions that a README may name on purpose, each with the reason.
# Keep this list short and explicit: anything not here is treated as stale.
DOCUMENTED_V1_PINS = {
    # The v1 tag before the v1.0.0-alpha.21 maintenance release. The Go,
    # TypeScript, Rust, and root READMEs keep a v1 install section that pins it.
    "1.0.0-alpha.20",
}
for path in [*install_pins, "sdks/c/README.md"]:
    for found in sorted(set(release_version_re.findall(read(path)))):
        if found not in current_versions and found not in DOCUMENTED_V1_PINS:
            fail(
                f"{path} references release version {found}; current lines are "
                f"v2 {v2_version} and v1 {v1_version} — stale pin?"
            )

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

protocol_tag = f"v{v2_version}"
# docs/RELEASES.md is deliberately absent: its version strings are
# historical (the §3.2 ladder) or illustrative examples, not release-synced.
# SPEC.md is the v1 specification, so it carries the v1 line's tag.
must_contain = {
    "README.md": protocol_tag,
    "SPEC.md": f"v{v1_version}",
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

print(
    f"release-sync: ok (v2 line {protocol_tag}, v1 line v{v1_version}, "
    f"{fixture_count} fixtures, {scope_count} scopes)"
)
PY

# SDK READMEs are generated from sdks/readme-src/preamble.md + per-SDK
# README.body.md files; hand-edits to README.md drift and fail here.
python3 "$(dirname "$0")/gen-sdk-readmes.py" --check
