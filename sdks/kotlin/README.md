# Ratify Protocol for Android

Ratify verifies signed agent authority before an Android app acts on it. This v2 SDK is being built for full protocol API parity through hand-written Kotlin types. The cryptographic and verifier implementation is the repository's Rust v2 core. `ratify-protocol-testing` contains reference stores for vectors and integration tests; applications must supply stores that meet the atomicity and durability requirements of SPEC-v2 Part B.

The AAR targets Android API 28+. Its publication coordinates are `com.ratifyprotocol:ratify-protocol:2.0.0-beta.1` and `com.ratifyprotocol:ratify-protocol-testing:2.0.0-beta.1`. The packages are staged locally during development and are not yet available from Maven Central.

## Build and test from source

Install JDK 17, Android SDK platform 36, NDK 28.2, Rust Android targets, and `cargo-ndk`. From the repository root:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
ABIS="arm64-v8a armeabi-v7a x86_64" FEATURES=test-hooks sdks/kotlin/scripts/build-rust.sh
cd sdks/kotlin
./gradlew :ratify-protocol:apiCheck :ratify-protocol:testDebugUnitTest
./gradlew :ratify-protocol:connectedDebugAndroidTest
```

The instrumented suite requires a running Android emulator. The release gate runs API 28 and the current target API. To build release AARs, stage both Maven publications, inspect all three native ABIs, and compile a clean consumer, run `bash scripts/build-mobile-artifacts.sh` from a clean tree on a Mac with both Android and Apple toolchains.

Import `com.ratifyprotocol` for typed objects, signing, verification, and release. `com.ratifyprotocol.testing.Store` and related types are for conformance work. A committed verifier outcome is not actionable until `releaseDecision` returns a released decision and its action check succeeds.

## Key custody and limits

Software hybrid keys contain two 32-byte seeds and can be stored with the Android Keystore storage helper. On API 33+ devices that support Ed25519 in Android Keystore, `KeystoreKey` keeps that component in Keystore and the ML-DSA-65 seed in the sealed storage record. The reported Ed25519 custody may be StrongBox, TEE, software, or unknown; the SDK does not claim hardware custody when the device does not prove it. An app can provide an external HSM or KMS signer; the SDK verifies both returned signature components.

The reference stores and device models are test components, not production persistence. Callback implementations must preserve the atomic store operations in SPEC-v2 Part B. Cancellation is cooperative, and a callback that does not return can delay its caller. Provider evidence is required before claiming that a particular device or external signer meets the profile.

See [`SPEC-v2.md`](../../SPEC-v2.md), [`KEY_STORAGE.md`](KEY_STORAGE.md), and the [SDK overview](../../docs/SDKS.md) for the protocol and storage contracts.
