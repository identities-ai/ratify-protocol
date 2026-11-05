import org.gradle.api.publish.maven.MavenPublication

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.ratifyprotocol.testing"
    compileSdk = 36
    defaultConfig { minSdk = 28 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                pom {
                    name.set("Ratify Protocol Android Test Support")
                    description.set("Reference components for testing Protocol v2 Android integrations")
                    url.set("https://github.com/identities-ai/ratify-protocol")
                    licenses { license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    } }
                    developers { developer {
                        id.set("identities-ai")
                        name.set("Identities.AI, Inc.")
                    } }
                    scm {
                        connection.set("scm:git:https://github.com/identities-ai/ratify-protocol.git")
                        url.set("https://github.com/identities-ai/ratify-protocol")
                    }
                }
            }
        }
        repositories { maven {
            name = "staging"
            url = uri(rootProject.layout.buildDirectory.dir("mobile-staging").get().asFile)
        } }
    }
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    api(project(":ratify-protocol"))
}
