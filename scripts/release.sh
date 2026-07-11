#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
VERSION="${2:-}"
PUBLISH="${PUBLISH:-0}"
GITHUB_RELEASE="${GITHUB_RELEASE:-0}"
GOCACHE="${GOCACHE:-/tmp/ratify-protocol-go-cache}"

cd "$ROOT"

usage() {
  cat >&2 <<'EOF'
usage:
  make release-prepare VERSION=vX.Y.Z[-alpha.N|-beta.N|-rc.N]
      From clean, up-to-date main: creates release/<version>, bumps all SDK
      versions, runs the full cross-SDK gate, commits, pushes, opens the PR.

  make release-tag VERSION=vX.Y.Z[-alpha.N|-beta.N|-rc.N]
      After the release PR is merged, from clean, up-to-date main: creates
      the protocol + sdk-* tags and pushes them. The tag push triggers the
      CI publish workflow — registry publishing is CI's job on this path.

  make release-publish VERSION=vX.Y.Z[-alpha.N|-beta.N|-rc.N] RELEASE_CI_FAILED=1 [GITHUB_RELEASE=1]
      Break-glass ONLY: manually publish to the registries after the
      tag-triggered CI release run has definitively failed. Refuses to run
      without RELEASE_CI_FAILED=1 so it can never race the CI publish.

Releases go through a PR like every other change to main. There is no
single-step release: it required a direct push to main, which the branch
ruleset forbids.
EOF
}

# The old single-step invocation passed the version as the first argument.
if [[ "$MODE" =~ ^v[0-9] ]]; then
  echo "release: the single-step release flow was removed — it required a direct push to main." >&2
  usage
  exit 1
fi

if [[ "$MODE" != "prepare" && "$MODE" != "tag" && "$MODE" != "publish" ]] || [[ -z "$VERSION" ]]; then
  usage
  exit 1
fi

# Only prerelease forms the whole pipeline normalizes are accepted:
# the Python bump below and the release workflow's tag check both map
# alpha/beta/rc to PEP 440 (a/b/rc). Anything else (e.g. -dev.1) would
# mutate files here and fail later in CI with Python metadata in a form
# the workflow does not expect.
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]; then
  echo "release: invalid VERSION '$VERSION' — vX.Y.Z with optional -alpha.N / -beta.N / -rc.N" >&2
  usage
  exit 1
fi

NPM_VERSION="${VERSION#v}"
PY_VERSION="$(python - "$NPM_VERSION" <<'PY'
import re
import sys
v = sys.argv[1]
print(re.sub(r"-alpha\.(\d+)$", r"a\1",
      re.sub(r"-beta\.(\d+)$", r"b\1",
      re.sub(r"-rc\.(\d+)$", r"rc\1", v))))
PY
)"

SDK_TAGS=(
  "sdk-go-$VERSION"
  "sdk-typescript-$VERSION"
  "sdk-python-$VERSION"
  "sdk-rust-$VERSION"
  "sdk-c-$VERSION"
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

# C SDK: crate version, the ratify-protocol dependency pin (used by
# cargo publish to substitute the path dependency), the cbindgen header
# banner, and both package entries in its lockfile. Forgetting these left
# ratify-c stuck at alpha.10 in-tree (and alpha.8 on crates.io) through
# two releases.
c_toml = read("sdks/c/Cargo.toml")
c_toml = re.sub(r'^version = "[^"]+"$', f'version = "{npm_version}"', c_toml, count=1, flags=re.M)
c_toml = re.sub(
    r'(ratify-protocol = \{ path = "\.\./rust", version = ")[^"]+("\ \})',
    rf'\g<1>{npm_version}\2',
    c_toml,
)
write("sdks/c/Cargo.toml", c_toml)

c_lock = read("sdks/c/Cargo.lock")
for pkg in ("ratify-c", "ratify-protocol"):
    c_lock = re.sub(
        rf'(\[\[package\]\]\nname = "{pkg}"\nversion = ")[^"]+(")',
        rf'\g<1>{npm_version}\2',
        c_lock,
        count=1,
    )
write("sdks/c/Cargo.lock", c_lock)

cbindgen = read("sdks/c/cbindgen.toml")
write("sdks/c/cbindgen.toml", re.sub(r'(\* Version: )[^\n"]+', rf'\g<1>{npm_version}', cbindgen, count=1))

old_protocol = "v" + old_npm
# docs/RELEASES.md is deliberately NOT in this list: it contains historical
# version references (the alpha ladder in §3.2) that a blanket old→new
# replacement corrupts — this happened at alpha.11, rewriting the alpha.10
# ladder entry. Its version examples are illustrative, not release-synced.
paths = [
    "README.md",
    "SPEC.md",
    "sdks/go/README.md",
    "sdks/rust/README.md",
    "sdks/typescript/README.md",
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
    "README.md",  # root README pins the pip install command in PEP 440 form
    "sdks/python/README.md",
    "sdks/python/pyproject.toml",
    "sdks/python/src/ratify_protocol/__init__.py",
]
for path in py_paths:
    text = read(path).replace(old_py, py_version)
    write(path, text)
PY
}

# Registry probes are tri-state: live / absent / unknown. Publishing must
# only happen on a definite 404 — a transient lookup failure (network,
# 5xx, rate limit) must NOT be read as "missing", or recovery would try to
# republish a live version and die on "already exists" before converging.
RELEASE_UA="ratify-protocol-release-script (https://github.com/identities-ai/ratify-protocol)"

registry_http_state() {
  local status
  status="$(curl -sS -o /dev/null -w "%{http_code}" --max-time 30 --retry 2 \
    -A "$RELEASE_UA" "$1" 2>/dev/null)" || status="000"
  case "$status" in
    200) echo live ;;
    404) echo absent ;;
    *)   echo "unknown:$status" ;;
  esac
}
registry_state_npm() {
  registry_http_state "https://registry.npmjs.org/@identities-ai%2Fratify-protocol/${NPM_VERSION}"
}
registry_state_pypi() {
  registry_http_state "https://pypi.org/pypi/ratify-protocol/${PY_VERSION}/json"
}
registry_state_crate() {
  # crates.io returns 403 to requests without a descriptive User-Agent —
  # with the UA above, 403 lands in "unknown" rather than a false "absent".
  registry_http_state "https://crates.io/api/v1/crates/$1/${NPM_VERSION}"
}

# ensure_published <label> <state> <publish-command...>
# live → skip; absent → publish; unknown → refuse to publish blind.
ensure_published() {
  local label="$1" state="$2"; shift 2
  case "$state" in
    live)
      echo "==> ${label} already has this version — skipping" ;;
    absent)
      echo "==> Publishing ${label}"
      "$@" ;;
    *)
      echo "release: could not verify ${label} (probe: ${state}) — refusing to publish blind." >&2
      echo "  A transient registry failure read as 'missing' would republish a live version." >&2
      echo "  Re-run release-publish when the registry is reachable." >&2
      exit 1 ;;
  esac
}

publish_registries() {
  # Converge to fully-published. The CI release publishes each registry in an
  # independent job, so a failed run can leave a PARTIAL state (npm + PyPI
  # live, crates missing). Recovery must finish the missing registries, not
  # die with "already exists" on the completed ones — so probe first, publish
  # only what is missing, and verify everything at the end.
  local rust_state
  rust_state="$(registry_state_crate ratify-protocol)"

  ensure_published "npm" "$(registry_state_npm)" \
    bash -c 'cd sdks/typescript && npm publish --access public'

  ensure_published "PyPI" "$(registry_state_pypi)" \
    bash -c "cd sdks/python && python -m pip install --upgrade build twine && rm -rf dist build *.egg-info && python -m build && twine upload dist/*"

  ensure_published "crates.io ratify-protocol" "$rust_state" \
    bash -c 'cd sdks/rust && cargo publish'

  # The C SDK depends on ratify-protocol via a local path. Crates.io requires
  # the dependency to be indexed before the dependent publishes — wait only
  # if we just published the Rust SDK in this run. Cargo substitutes
  # path = "../rust" → version = "$NPM_VERSION" in the published metadata.
  c_publish() {
    if [ "$rust_state" = "absent" ]; then
      echo "==> Waiting 60s for ratify-protocol to be indexed on crates.io..."
      sleep 60
    fi
    (cd sdks/c && cargo publish)
  }
  ensure_published "crates.io ratify-c" "$(registry_state_crate ratify-c)" c_publish

  echo "==> Verifying all registries carry ${NPM_VERSION}"
  local not_live=0 state
  for probe in "npm:registry_state_npm" "PyPI:registry_state_pypi" \
               "crates ratify-protocol:registry_state_crate ratify-protocol" \
               "crates ratify-c:registry_state_crate ratify-c"; do
    label="${probe%%:*}"
    state="$(${probe#*:})"
    if [ "$state" != "live" ]; then
      echo "  ✗ ${label}: ${state}"
      not_live=1
    fi
  done
  if [ "$not_live" = "1" ]; then
    echo "release: not all registries verified live for ${NPM_VERSION} (absent = still" >&2
    echo "  missing or indexing; unknown = could not verify) — re-run release-publish" >&2
    echo "  to converge." >&2
    exit 1
  fi
  echo "  ✓ npm, PyPI, crates (ratify-protocol, ratify-c) all live"
}

create_github_release() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "release: gh is required for GITHUB_RELEASE=1" >&2
    exit 1
  fi
  local archive="/tmp/ratify-protocol-testvectors-${VERSION}.tar.gz"
  tar -czf "$archive" testvectors/v1

  # Build C SDK release artifacts (static + shared library + header)
  echo "==> Building C SDK release artifacts"
  (cd sdks/c && cargo build --release 2>&1)
  local header_archive="/tmp/ratify-c-${VERSION}-header.tar.gz"
  tar -czf "$header_archive" \
    -C sdks/c \
    include/ratify.h \
    README.md

  gh release create "$VERSION" \
    "$archive" \
    "$header_archive" \
    --generate-notes \
    --title "Ratify Protocol $VERSION"
}

require_main() {
  if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "release: must run from main" >&2
    exit 1
  fi
}

require_main_up_to_date() {
  git fetch origin main
  if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
    echo "release: local main is not in sync with origin/main — pull first" >&2
    exit 1
  fi
}

require_all_tags_absent() {
  require_tag_absent "$VERSION"
  for tag in "${SDK_TAGS[@]}"; do
    require_tag_absent "$tag"
  done
}

current_npm_version() {
  python -c "import json; print(json.load(open('sdks/typescript/package.json'))['version'])"
}

prepare() {
  local branch="release/$VERSION"
  require_main
  require_clean
  require_main_up_to_date
  require_all_tags_absent
  if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
    echo "release: branch already exists: $branch" >&2
    exit 1
  fi

  echo "==> Creating $branch"
  git checkout -b "$branch"

  echo "==> Bumping versions to $VERSION"
  bump_versions

  # Stamp the changelog entry for this version, if one is marked unreleased.
  python - "$VERSION" <<'PY'
import datetime
import pathlib
import sys

version = sys.argv[1]
path = pathlib.Path("CHANGELOG.md")
text = path.read_text()
marker = f"## {version} (unreleased)"
if marker in text:
    today = datetime.date.today().isoformat()
    path.write_text(text.replace(marker, f"## {version} ({today})", 1))
PY

  ./scripts/check-release-sync.sh

  echo "==> Running full release test suite"
  GOCACHE="$GOCACHE" run_tests

  echo "==> Committing release version bump"
  git add -A
  git commit -s -m "chore: release $VERSION"

  echo "==> Pushing $branch"
  git push -u origin "$branch"

  if command -v gh >/dev/null 2>&1; then
    echo "==> Opening release PR"
    gh pr create --base main \
      --title "chore: release $VERSION" \
      --body "Coordinated version bump for $VERSION across all SDK manifests. Full cross-SDK gate passed locally; CI re-runs it here. After merge, run: \`make release-tag VERSION=$VERSION\`."
  else
    echo "==> gh not found — open the PR manually for branch $branch"
  fi

  echo "release-prepare: ok ($VERSION) — merge the PR, then run: make release-tag VERSION=$VERSION"
}

# Break-glass manual publish: for when the tag exists but the CI release
# run has definitively failed. Isolated from the tag push so it can never
# race the tag-triggered workflow — requires the operator to assert the
# CI failure explicitly.
publish_release() {
  if [[ "${RELEASE_CI_FAILED:-0}" != "1" ]]; then
    echo "release: manual publishing races the tag-triggered CI release unless that run" >&2
    echo "  has already failed. Confirm it (gh run list --workflow=release.yml) and" >&2
    echo "  re-run with RELEASE_CI_FAILED=1." >&2
    exit 1
  fi
  require_main
  require_clean
  require_main_up_to_date

  local live_version
  live_version="$(current_npm_version)"
  if [[ "$live_version" != "$NPM_VERSION" ]]; then
    echo "release: main is at $live_version, expected $NPM_VERSION" >&2
    exit 1
  fi
  if ! git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
    echo "release: tag $VERSION does not exist — run make release-tag first" >&2
    exit 1
  fi
  ./scripts/check-release-sync.sh

  publish_registries
  if [[ "$GITHUB_RELEASE" == "1" ]]; then
    create_github_release
  fi
}

tag_release() {
  if [[ "$PUBLISH" == "1" || "$GITHUB_RELEASE" == "1" ]]; then
    echo "release: PUBLISH=1 / GITHUB_RELEASE=1 no longer run during release-tag —" >&2
    echo "  the tag push already triggers the CI publish, so a local publish here" >&2
    echo "  races it. Use: make release-publish VERSION=$VERSION RELEASE_CI_FAILED=1" >&2
    exit 1
  fi
  require_main
  require_clean
  require_main_up_to_date

  local live_version
  live_version="$(current_npm_version)"
  if [[ "$live_version" != "$NPM_VERSION" ]]; then
    echo "release: main is at $live_version, expected $NPM_VERSION — has the release-prepare PR been merged?" >&2
    exit 1
  fi
  ./scripts/check-release-sync.sh
  require_all_tags_absent

  echo "==> Creating coordinated tags"
  git tag "$VERSION"
  for tag in "${SDK_TAGS[@]}"; do
    git tag "$tag"
  done

  echo "==> Pushing tags"
  # Push the protocol tag on its own: GitHub does not create push events
  # when more than three tags arrive in a single push, so pushing all six
  # tags together silently suppresses the tag-triggered release workflow.
  # The sdk-* tags carry no workflow trigger and can go together after.
  git push origin "$VERSION"
  git push origin "${SDK_TAGS[@]}"
  echo "==> Verify the Release workflow started: gh run list --workflow=release.yml --limit 1"
  echo "    If it did not, dispatch it manually: gh workflow run release.yml -f tag=$VERSION"

  echo "==> Registry publishing is CI-driven off the tag push (normal path)."
  echo "    Break-glass manual publish (only after the CI release run has"
  echo "    definitively failed): make release-publish VERSION=$VERSION RELEASE_CI_FAILED=1"

  echo "release-tag: ok ($VERSION)"
  cat <<'EOF'

REMAINING RELEASE-DAY STEPS (docs/RELEASES.md §4.2):
  11. Bump downstream claims — a PR in EACH of:
      - ratify-docs:            src/constants/protocol.ts + RELEASE_BUMP.md sweep
      - identities-marketing:   lib/protocol-facts.ts + public/llms.txt
      Also add this release's line to the RELEASES.md §3.2 ladder.
  12. Phase 4 — verify every registry actually serves the new version
      (npm, crates.io BOTH crates, PyPI, GitHub release assets).
      A green publish job is not proof.
EOF
}

case "$MODE" in
  prepare) prepare ;;
  tag)     tag_release ;;
  publish) publish_release ;;
esac
