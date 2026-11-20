# Ratify Protocol for Android

Ratify verifies signed agent authority before an Android app acts on it. This v2 SDK provides hand-written Kotlin types over the repository's Rust v2 core. `ratify-protocol-testing` contains reference stores for vectors and integration tests; applications must supply stores that meet the atomicity and durability requirements of SPEC-v2 Part B.

The AAR targets Android API 28+. Install the tagged release from Maven Central:

```kotlin
repositories { mavenCentral() }
dependencies {
    implementation("com.ratifyprotocol:ratify-protocol:2.0.0-beta.2")
    testImplementation("com.ratifyprotocol:ratify-protocol-testing:2.0.0-beta.2")
}
```

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

## Verify MCP signer (Preview)

`Mcp` is the client side of the managed Ratify Verify MCP server: it signs the delegated-authority proof each MCP tool call carries, answers the console's connect challenge with a proof of possession of the agent key, and parses the console's client configuration. It is a preview and not part of SPEC-v2 conformance.

```kotlin
val config = Mcp.parseClientConfig(consoleJson)
val call = Mcp.newToolCall("get_metrics", "{}")
// POST config.endpoint + "/challenge" with config.challengeRequest(call)
val challenge = config.checkChallenge(call.tool, responseBody, System.currentTimeMillis() / 1000)
val envelope = Mcp.signToolCall(config, agentKey, call, challenge)
// tools/call params._meta[Mcp.PROOF_META_KEY] = envelope.toJson()
```

`Mcp.provePossession` answers a connect challenge, and the `ExternalSigner` and `SigningKey` overloads suspend. Refusals are `McpException` subclasses. See [`docs/VERIFY_MCP_SIGNER.md`](../../docs/VERIFY_MCP_SIGNER.md).
