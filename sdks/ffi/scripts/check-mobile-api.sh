#!/usr/bin/env bash
# The Swift and Kotlin API inventory gate (build plan §3.1), end to end:
#  1. the checked-in core listing matches `cargo public-api` (needs nightly);
#  2. every listed item has an inventory disposition;
#  3. every mapped name is in the compiled public Swift and Kotlin APIs, and
#     neither exposes a generated FFI declaration;
#  4. full public signatures match the committed baselines (Kotlin BCV .api,
#     Swift digester baseline), so a changed overload or label fails.
# Expects the XCFramework (sdks/swift/scripts/build-xcframework.sh) and the
# Android native libraries (sdks/kotlin/scripts/build-rust.sh) to be built.
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$root"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cp sdks/ffi/public-api.txt "$tmp/checked-in.txt"
python3 sdks/ffi/scripts/api_inventory.py listing >/dev/null
if ! diff -u "$tmp/checked-in.txt" sdks/ffi/public-api.txt; then
  echo "sdks/ffi/public-api.txt is stale: the core's public API changed; update the inventory" >&2
  exit 1
fi
python3 sdks/ffi/scripts/api_inventory.py check

swift build -q
headers="$(ls -d sdks/swift/build/RatifyProtocolFFI.xcframework/macos-*/Headers)"
xcrun swift-api-digester -dump-sdk -module RatifyProtocol -o "$tmp/swift-api.json" \
  -I .build/debug/Modules -I "$headers" \
  -sdk "$(xcrun --show-sdk-path --sdk macosx)" -target "$(uname -m)-apple-macosx14.0"
# Full public signatures: Kotlin through BCV's committed .api dump, Swift
# through the committed digester baseline. UPDATE_API=1 rewrites both.
mode="${UPDATE_API:+update}"
python3 sdks/ffi/scripts/api_inventory.py swift-baseline "$tmp/swift-api.json" sdks/swift/api/RatifyProtocol.api.txt $mode
if [ -n "$mode" ]; then (cd sdks/kotlin && ./gradlew -q :ratify-protocol:apiDump); fi
(cd sdks/kotlin && ./gradlew -q :ratify-protocol:apiCheck)
python3 sdks/ffi/scripts/api_inventory.py names "$tmp/swift-api.json" sdks/kotlin/ratify-protocol/api/ratify-protocol.api
