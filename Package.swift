// swift-tools-version:6.0
//
// Ratify Protocol v2 SDK for Swift (iOS, macOS). The public API is the
// hand-written RatifyProtocol module; RatifyProtocolFFI is the prebuilt Rust
// core it calls. In this repository the framework is built locally with
// sdks/swift/scripts/build-xcframework.sh; release builds point at the
// published, checksummed asset instead.
import PackageDescription
import Foundation

// The release-prepare step fills these from the CI-built draft asset. Source
// builds opt into their local XCFramework with RATIFY_SWIFT_LOCAL_BINARY=1.
let releaseAssetURL = "https://github.com/identities-ai/ratify-protocol/releases/download/v2.0.0-beta.2/RatifyProtocolFFI.xcframework.zip"
let releaseAssetChecksum = "9e38fa532a40cd3c9db35e5843cb9290600ace0a884c54d58cc545209b174194"
let useLocalBinary = ProcessInfo.processInfo.environment["RATIFY_SWIFT_LOCAL_BINARY"] == "1"
let ffi: Target
if useLocalBinary || releaseAssetURL.isEmpty {
    ffi = .binaryTarget(name: "RatifyProtocolFFI", path: "sdks/swift/build/RatifyProtocolFFI.xcframework")
} else {
    ffi = .binaryTarget(name: "RatifyProtocolFFI", url: releaseAssetURL, checksum: releaseAssetChecksum)
}

let package = Package(
    name: "RatifyProtocol",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "RatifyProtocol", targets: ["RatifyProtocol"]),
        .library(name: "RatifyProtocolTestSupport", targets: ["RatifyProtocolTestSupport"]),
    ],
    targets: [
        ffi,
        .target(
            name: "RatifyProtocol",
            dependencies: ["RatifyProtocolFFI"],
            path: "sdks/swift/Sources/RatifyProtocol"
        ),
        .target(
            name: "RatifyProtocolTestSupport",
            dependencies: ["RatifyProtocol"],
            path: "sdks/swift/Sources/RatifyProtocolTestSupport"
        ),
        .testTarget(
            name: "RatifyProtocolTests",
            dependencies: ["RatifyProtocol", "RatifyProtocolTestSupport"],
            path: "sdks/swift/Tests/RatifyProtocolTests"
        ),
    ]
)
