#!/usr/bin/env bash
# Resolve the zipped XCFramework from a clean local SwiftPM consumer.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
asset="$root/dist/mobile/RatifyProtocolFFI.xcframework.zip"
test -f "$asset"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/sdk/sdks/swift/build" "$tmp/consumer/Sources/Smoke"
cp "$root/Package.swift" "$tmp/sdk/Package.swift"
cp -R "$root/sdks/swift/Sources" "$tmp/sdk/sdks/swift/Sources"
ditto -x -k "$asset" "$tmp/sdk/sdks/swift/build"
test -f "$tmp/sdk/sdks/swift/build/RatifyProtocolFFI.xcframework/Info.plist"
cat > "$tmp/consumer/Package.swift" <<'EOF'
// swift-tools-version:6.0
import PackageDescription
let package = Package(
    name: "RatifyMobileConsumerSmoke",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "../sdk")],
    targets: [.executableTarget(name: "Smoke", dependencies: [
        .product(name: "RatifyProtocol", package: "sdk"),
        .product(name: "RatifyProtocolTestSupport", package: "sdk"),
    ])]
)
EOF
cat > "$tmp/consumer/Sources/Smoke/main.swift" <<'EOF'
import Foundation
import RatifyProtocol
import RatifyProtocolTestSupport

do {
    _ = try Ratify.decodeProofBundle(Data())
    fatalError("empty proof unexpectedly decoded")
} catch {
    print("Swift staged XCFramework consumer: ok")
}
_ = Store.self
EOF
swift run --package-path "$tmp/consumer" Smoke
