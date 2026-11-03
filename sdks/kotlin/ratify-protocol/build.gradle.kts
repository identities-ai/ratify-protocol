// Ratify Protocol v2 SDK for Kotlin (Android). The public API is the
// hand-written com.ratifyprotocol package; com.ratifyprotocol.internal.ffi is
// generated from sdks/ffi and is never public API.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val repoRoot = rootProject.projectDir.resolve("../..")

android {
    namespace = "com.ratifyprotocol"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main").jniLibs.srcDir(layout.buildDirectory.dir("rust/jniLibs"))
        // The shared corpus is read in place, never copied into the tree.
        getByName("androidTest").assets.srcDir(repoRoot.resolve("testvectors"))
        getByName("androidTest").assets.srcDir(layout.buildDirectory.dir("specAssets"))
        // One set of vector runners, driven by both the host and the device suites.
        getByName("test").kotlin.srcDir("src/sharedTest/kotlin")
        getByName("androidTest").kotlin.srcDir("src/sharedTest/kotlin")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.all {
            // Host unit tests load the host build of the Rust library.
            it.systemProperty("jna.library.path", repoRoot.resolve("sdks/ffi/target/release").absolutePath)
            it.systemProperty("ratify.corpus", repoRoot.resolve("testvectors").absolutePath)
            it.systemProperty("ratify.annex", repoRoot.resolve("SPEC-v2-ANNEX-A.md").absolutePath)
        }
    }
}

// The Annex A runner checks clause digests against the spec text itself.
val specAssets by tasks.registering(Copy::class) {
    from(repoRoot.resolve("SPEC-v2-ANNEX-A.md"))
    into(layout.buildDirectory.dir("specAssets/spec"))
}
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("AndroidTestAssets") }.configureEach { dependsOn(specAssets) }

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.15.0@aar")
    implementation("androidx.annotation:annotation:1.9.1")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    testImplementation("net.java.dev.jna:jna:5.15.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
