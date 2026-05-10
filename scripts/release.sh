#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-}"
PUSH="${PUSH:-0}"
PUBLISH="${PUBLISH:-0}"
GITHUB_RELEASE="${GITHUB_RELEASE:-0}"
GOCACHE="${GOCACHE:-/tmp/ratify-protocol-go-cache}"

cd "$ROOT"

usage() {
  echo "usage: make release VERSION=vX.Y.Z[-tag.N] [PUSH=1] [PUBLISH=1] [GITHUB_RELEASE=1]" >&2
}

if [[ -z "$VERSION" ]]; then
  usage
  exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]]; then
  echo "release: invalid VERSION '$VERSION'" >&2
  usage
  exit 1
fi

NPM_VERSION="${VERSION#v}"
PY_VERSION="$(python - "$NPM_VERSION" <<'PY'
import re
import sys
v = sys.argv[1]
print(re.sub(r"-alpha\.(\d+)$", r"a\1", v))
PY
)"

SDK_TAGS=(
  "sdk-go-$VERSION"
  "sdk-typescript-$VERSION"
  "sdk-python-$VERSION"
  "sdk-rust-$VERSION"
)

require_clean() {
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "release: working tree is not clean" >&2
    git status --short >&2
    exit 1
  fi
}

require_tag_absent() {
  local tag="$1"
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    echo "release: local tag already exists: $tag" >&2
    exit 1
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    echo "release: remote tag already exists: $tag" >&2
    exit 1
  fi
}

run_tests() {
  ./scripts/test-all.sh
}

bump_versions() {
  python - "$VERSION" "$NPM_VERSION" "$PY_VERSION" <<'PY'
import json
import pathlib
import re
import sys

protocol_tag, npm_version, py_version = sys.argv[1:4]
root = pathlib.Path(".")

def read(path: str) -> str:
    return (root / path).read_text()

def write(path: str, text: str) -> None:
    (root / path).write_text(text)

pkg_path = root / "sdks/typescript/package.json"
pkg = json.loads(pkg_path.read_text())
old_npm = pkg["version"]
pkg["version"] = npm_version
pkg_path.write_text(json.dumps(pkg, indent=2) + "\n")

lock_path = root / "sdks/typescript/package-lock.json"
lock = json.loads(lock_path.read_text())
lock["version"] = npm_version
lock.setdefault("packages", {}).setdefault("", {})["version"] = npm_version
lock_path.write_text(json.dumps(lock, indent=2) + "\n")

pyproject = read("sdks/python/pyproject.toml")
old_py_match = re.search(r'^version = "([^"]+)"$', pyproject, re.M)
if not old_py_match:
    raise SystemExit("missing Python version")
old_py = old_py_match.group(1)
write("sdks/python/pyproject.toml", re.sub(r'^version = "[^"]+"$', f'version = "{py_version}"', pyproject, flags=re.M))

py_init = read("sdks/python/src/ratify_protocol/__init__.py")
write("sdks/python/src/ratify_protocol/__init__.py", re.sub(r'^__version__ = "[^"]+"$', f'__version__ = "{py_version}"', py_init, flags=re.M))

rust_toml = read("sdks/rust/Cargo.toml")
old_rust_match = re.search(r'^version = "([^"]+)"$', rust_toml, re.M)
if not old_rust_match:
    raise SystemExit("missing Rust version")
old_rust = old_rust_match.group(1)
write("sdks/rust/Cargo.toml", re.sub(r'^version = "[^"]+"$', f'version = "{npm_version}"', rust_toml, count=1, flags=re.M))

rust_lock = read("sdks/rust/Cargo.lock")
write(
    "sdks/rust/Cargo.lock",
    re.sub(
        r'(\[\[package\]\]\nname = "ratify-protocol"\nversion = ")[^"]+(")',
        rf'\g<1>{npm_version}\2',
        rust_lock,
        count=1,
    ),
)

old_protocol = "v" + old_npm
paths = [
    "README.md",
    "SPEC.md",
    "docs/RELEASES.md",
    "sdks/rust/README.md",
    "sdks/typescript/package.json",
    "sdks/typescript/package-lock.json",
]
for path in paths:
    text = read(path)
    text = text.replace(old_protocol, protocol_tag)
    text = text.replace(old_npm, npm_version)
    text = text.replace(old_rust, npm_version)
    write(path, text)

py_paths = [
    "sdks/python/README.md",
    "sdks/python/pyproject.toml",
    "sdks/python/src/ratify_protocol/__init__.py",
]
for path in py_paths:
    text = read(path).replace(old_py, py_version)
    write(path, text)
PY
}

publish_registries() {
  echo "==> Publishing npm"
  (cd sdks/typescript && npm publish --access public)

  echo "==> Publishing PyPI"
  (cd sdks/python && python -m pip install --upgrade build twine && rm -rf dist build *.egg-info && python -m build && twine upload dist/*)

  echo "==> Publishing crates.io"
  (cd sdks/rust && cargo publish)
}

create_github_release() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "release: gh is required for GITHUB_RELEASE=1" >&2
    exit 1
  fi
  local archive="/tmp/ratify-protocol-testvectors-${VERSION}.tar.gz"
  tar -czf "$archive" testvectors/v1
  gh release create "$VERSION" "$archive" --generate-notes --title "Ratify Protocol $VERSION"
}

if [[ "$(git branch --show-current)" != "main" && "${ALLOW_NON_MAIN:-0}" != "1" ]]; then
  echo "release: must run from main (set ALLOW_NON_MAIN=1 to override)" >&2
  exit 1
fi

require_clean
require_tag_absent "$VERSION"
for tag in "${SDK_TAGS[@]}"; do
  require_tag_absent "$tag"
done

echo "==> Bumping versions to $VERSION"
bump_versions
./scripts/check-release-sync.sh

echo "==> Running full release test suite"
GOCACHE="$GOCACHE" run_tests

if [[ -n "$(git status --porcelain)" ]]; then
  echo "==> Committing release version bump"
  git add -A
  git commit -s -m "chore: release $VERSION"
fi

require_clean

echo "==> Creating coordinated tags"
git tag "$VERSION"
for tag in "${SDK_TAGS[@]}"; do
  git tag "$tag"
done

if [[ "$PUSH" == "1" ]]; then
  echo "==> Pushing main and tags"
  git push origin main
  git push origin "$VERSION" "${SDK_TAGS[@]}"
else
  echo "==> PUSH=0: tags created locally only"
fi

if [[ "$PUBLISH" == "1" ]]; then
  publish_registries
else
  echo "==> PUBLISH=0: registry publishing skipped"
fi

if [[ "$GITHUB_RELEASE" == "1" ]]; then
  create_github_release
else
  echo "==> GITHUB_RELEASE=0: GitHub release creation skipped"
fi

echo "release: ok ($VERSION)"
