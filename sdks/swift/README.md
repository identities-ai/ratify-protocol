# Ratify Protocol for Swift

Ratify verifies signed agent authority before an iOS or macOS app acts on it. This v2 SDK exposes the full protocol API through hand-written Swift types. The cryptographic and verifier implementation is the repository's Rust v2 core. `RatifyProtocolTestSupport` contains reference stores for vectors and integration tests; applications must supply stores that meet the atomicity and durability requirements of SPEC-v2 Part B.

The package supports iOS 17+ and macOS 14+. The source tree currently uses a local XCFramework path in [`Package.swift`](../../Package.swift). The release process replaces it with a checksummed release asset before the package can be resolved from a tag. This branch is a release candidate, not a published SwiftPM version.

## Build and test from source

Install Xcode 26.5 and Rust with the Apple targets, then from the repository root:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
FEATURES=test-hooks sdks/swift/scripts/build-xcframework.sh
swift test
```

The build writes `sdks/swift/build/RatifyProtocolFFI.xcframework`. To build a candidate without test hooks and verify its slices and a clean consumer, run `bash scripts/build-mobile-artifacts.sh` on a clean tree with the Android toolchain also installed. Its manifest records the commit, tree, sizes, and SHA-256 digests.

Import `RatifyProtocol` for `Ratify`, typed objects, signing, verification, and release. The test support product provides `Store` and `TrustRegistry` for conformance work. A committed verifier outcome is not actionable until `Ratify.releaseDecision` returns a released decision and its action check succeeds.

## Key custody and limits

Software hybrid keys are stored as two 32-byte seeds in the Keychain using `KeychainKeyStore`. On iOS 26+ or macOS 26+, `SecureEnclaveKey` holds ML-DSA-65 in the Secure Enclave and keeps the Ed25519 seed in a device-bound Keychain record. Earlier OS versions do not have this platform key mode. An app can provide an external HSM or KMS signer; the SDK verifies both returned signature components.

The reference stores and device models are test components, not production persistence. Callback implementations must preserve the atomic store operations in SPEC-v2 Part B. Cancellation is cooperative, and a callback that does not return can delay its caller. Provider evidence is required before claiming that a particular device or external signer meets the profile.

See [`SPEC-v2.md`](../../SPEC-v2.md), [`KEY_STORAGE.md`](KEY_STORAGE.md), and the [mobile build plan](../../docs/SDKS.md) for the protocol and storage contracts.
