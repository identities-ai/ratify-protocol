#!/usr/bin/env bash
# Resolve the staged AARs in an empty Android app, with no project substitution.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
staging="$root/sdks/kotlin/build/mobile-staging"
version="$(sed -n 's/^VERSION_NAME=//p' "$root/sdks/kotlin/gradle.properties")"
test -n "$version"
test -f "$staging/com/ratifyprotocol/ratify-protocol/$version/ratify-protocol-$version.aar"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src/main/kotlin" "$tmp/src/main"
echo 'android.useAndroidX=true' > "$tmp/gradle.properties"
cat > "$tmp/settings.gradle.kts" <<'EOF'
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri(System.getenv("RATIFY_STAGING_REPO")) }
        google()
        mavenCentral()
    }
}
rootProject.name = "ratify-mobile-consumer-smoke"
EOF
cat > "$tmp/build.gradle.kts" <<'EOF'
plugins {
    id("com.android.application") version "8.10.1"
    id("org.jetbrains.kotlin.android") version "2.1.21"
}
android {
    namespace = "com.ratifyprotocol.smoke"
    compileSdk = 36
    defaultConfig { applicationId = "com.ratifyprotocol.smoke"; minSdk = 28; targetSdk = 36 }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
kotlin { jvmToolchain(17) }
dependencies {
    implementation("com.ratifyprotocol:ratify-protocol:${System.getenv("RATIFY_VERSION")}")
    implementation("com.ratifyprotocol:ratify-protocol-testing:${System.getenv("RATIFY_VERSION")}")
}
EOF
cat > "$tmp/src/main/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application /></manifest>
EOF
cat > "$tmp/src/main/kotlin/Smoke.kt" <<'EOF'
package com.ratifyprotocol.smoke

import com.ratifyprotocol.CheckpointAcknowledgement
import com.ratifyprotocol.decodeProofBundle
import com.ratifyprotocol.testing.Store

fun consume(store: Store, wire: ByteArray): String {
    val ack = CheckpointAcknowledgement("0".repeat(32), 1, ByteArray(48), 1_800_000_000)
    return store.javaClass.name + decodeProofBundle(wire).javaClass.name + ack.logId
}
EOF
RATIFY_STAGING_REPO="$staging" RATIFY_VERSION="$version" "$root/sdks/kotlin/gradlew" -p "$tmp" assembleDebug
echo "Kotlin staged Maven consumer: ok"
