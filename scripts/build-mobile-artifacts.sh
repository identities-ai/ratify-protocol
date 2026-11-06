#!/usr/bin/env bash
# Build the exact mobile release candidates from this tree, without uploading.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
export RATIFY_SWIFT_LOCAL_BINARY=1
if [ -n "$(git status --porcelain)" ]; then
  echo "mobile artifact build requires a clean source tree" >&2
  exit 1
fi
unset FEATURES
SLICES="macos ios ios-sim" sdks/swift/scripts/build-xcframework.sh
ABIS="arm64-v8a armeabi-v7a x86_64" sdks/kotlin/scripts/build-rust.sh
(cd sdks/kotlin && ./gradlew \
  :ratify-protocol:publishReleasePublicationToStagingRepository \
  :ratify-protocol-testing:publishReleasePublicationToStagingRepository)

python3 scripts/check-mobile-artifacts.py
bash scripts/smoke-kotlin-staging.sh
git diff --exit-code -- sdks/swift/Sources/RatifyProtocol/Generated/ratify_ffi.swift \
  sdks/kotlin/ratify-protocol/src/main/kotlin/com/ratifyprotocol/internal/ffi/ratify_ffi.kt
if [ -n "$(git status --porcelain)" ]; then
  echo "mobile artifact build changed the source tree" >&2
  exit 1
fi

out="$root/dist/mobile"
rm -rf "$out"
mkdir -p "$out"
ditto -c -k --sequesterRsrc --keepParent \
  sdks/swift/build/RatifyProtocolFFI.xcframework "$out/RatifyProtocolFFI.xcframework.zip"
cp sdks/kotlin/ratify-protocol/build/outputs/aar/ratify-protocol-release.aar "$out/"
cp sdks/kotlin/ratify-protocol-testing/build/outputs/aar/ratify-protocol-testing-release.aar "$out/"
(cd sdks/kotlin/build && zip -q -r "$out/kotlin-maven-staging.zip" mobile-staging)
bash scripts/smoke-swift-staging.sh

python3 - "$out" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
source = hashlib.sha256()
for entry in subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"]).split(b"\0"):
    if entry and entry.split(b"\t", 1)[1] != b"Package.swift":
        source.update(entry + b"\0")
manifest = {
    "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
    "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip(),
    "source_except_package_sha256": source.hexdigest(),
    "workflow_run": os.environ.get("GITHUB_RUN_ID"),
    "artifacts": {},
}
for path in sorted(out.iterdir()):
    if path.is_file():
        data = path.read_bytes()
        manifest["artifacts"][path.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(manifest, indent=2, sort_keys=True))
PY
