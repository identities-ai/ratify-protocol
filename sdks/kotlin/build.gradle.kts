plugins {
    id("com.android.library") version "8.10.1" apply false
    id("org.jetbrains.kotlin.android") version "2.1.21" apply false
    // Dumps the public Kotlin API (ratify-protocol/api/*.api); apiCheck fails
    // on any change, and the inventory gate reads the dump.
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.16.3"
}
