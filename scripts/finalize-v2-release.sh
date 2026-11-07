#!/usr/bin/env bash
# Publish a vetted v2 draft only after its coordinated registry run succeeds.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:?usage: finalize-v2-release.sh vX.Y.Z candidate-run [release-run]}"
candidate_run="${2:?candidate run ID required}"
release_run="${3:-}"
[[ "$version" =~ ^v2\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]
[[ "$candidate_run" =~ ^[0-9]+$ ]]
[[ "$(gh release view "$version" --json isDraft --jq .isDraft)" == true ]]

if [[ -z "$release_run" ]]; then
  url="$(gh workflow run release.yml --ref main -f "tag=$version" -f dry_run=false -f "mobile_candidate_run=$candidate_run")"
  [[ "$url" =~ /actions/runs/([0-9]+)$ ]]
  release_run="${BASH_REMATCH[1]}"
fi
[[ "$release_run" =~ ^[0-9]+$ ]]
echo "Release workflow: https://github.com/identities-ai/ratify-protocol/actions/runs/$release_run"
gh run watch "$release_run" --exit-status
[[ "$(gh run view "$release_run" --json conclusion --jq .conclusion)" == success ]]
[[ "$(gh run view "$release_run" --json displayTitle --jq .displayTitle)" == "Release $version" ]]

stage_dir="$(mktemp -d)"
trap 'rm -rf "$stage_dir"' EXIT
gh run download "$release_run" -n release-assets -D "$stage_dir"
python3 - "$version" "$stage_dir" <<'PY'
import pathlib, sys, tarfile, zipfile
version, root = sys.argv[1], pathlib.Path(sys.argv[2])
expected = {f"ratify-testvectors-{version}.tar.gz"}
expected |= {f"c-artifacts/ratify-c-{version}-{target}{suffix}" for target, suffix in (
    ("linux-aarch64", ".tar.gz"), ("linux-armv7", ".tar.gz"),
    ("linux-x86_64", ".tar.gz"), ("macos-aarch64", ".tar.gz"),
    ("macos-x86_64", ".tar.gz"), ("windows-x86_64", ".zip"),
)}
actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()}
if actual != expected:
    sys.exit(f"release assets differ from expected set: {sorted(actual ^ expected)}")
for name in expected:
    path = root / name
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            if archive.testzip() is not None:
                sys.exit(f"invalid archive: {name}")
    else:
        with tarfile.open(path, "r:gz") as archive:
            if not archive.getmembers():
                sys.exit(f"empty archive: {name}")
print("release assets: seven complete archives")
PY

gh release upload "$version" "$stage_dir/ratify-testvectors-$version.tar.gz" "$stage_dir"/c-artifacts/* --clobber
gh release view "$version" --json body --jq .body > "$stage_dir/notes.md"
python3 - "$stage_dir/notes.md" "$version" "$release_run" <<'PY'
import pathlib, subprocess, sys
path, version, run = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
body = path.read_text()
commit = subprocess.check_output(["git", "rev-parse", version], text=True).strip()
record = (f"Release commit: [{commit[:12]}](https://github.com/identities-ai/ratify-protocol/commit/{commit}).\n\n"
          f"Registry and artifact verification: [release run](https://github.com/identities-ai/ratify-protocol/actions/runs/{run}).")
placeholder = "Release commit and registry links will be added when the coordinated release is published."
if placeholder in body:
    body = body.replace(placeholder, record)
elif record not in body:
    body = body.rstrip() + "\n\n" + record + "\n"
path.write_text(body)
PY
gh release edit "$version" --draft=false --prerelease --notes-file "$stage_dir/notes.md"
echo "Published https://github.com/identities-ai/ratify-protocol/releases/tag/$version"
