// swift-tools-version:6.0
//
// Ratify Protocol v2 SDK for Swift (iOS, macOS). The public API is the
// hand-written RatifyProtocol module; RatifyProtocolFFI is the prebuilt Rust
// core it calls. In this repository the framework is built locally with
// sdks/swift/scripts/build-xcframework.sh; release builds point at the
// published, checksummed asset instead.
import PackageDescription

let ffi: Target = .binaryTarget(
    name: "RatifyProtocolFFI",
    path: "sdks/swift/build/RatifyProtocolFFI.xcframework"
)

let package = Package(
    name: "RatifyProtocol",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "RatifyProtocol", targets: ["RatifyProtocol"]),
    ],
    targets: [
        ffi,
        .target(
            name: "RatifyProtocol",
            dependencies: ["RatifyProtocolFFI"],
            path: "sdks/swift/Sources/RatifyProtocol"
        ),
        .testTarget(
            name: "RatifyProtocolTests",
            dependencies: ["RatifyProtocol"],
            path: "sdks/swift/Tests/RatifyProtocolTests"
        ),
    ]
)
