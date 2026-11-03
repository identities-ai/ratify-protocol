package com.ratifyprotocol

import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** The shared vector runners on the host JVM, against the host Rust build. */
class HostVectorsTest {
    companion object {
        @BeforeClass @JvmStatic
        fun corpus() {
            val root = File(System.getProperty("ratify.corpus")!!)
            Corpus.read = { File(root, it).readBytes() }
        }
    }

    @Test fun keys() = KeysVectors.corpus()
    @Test fun generate() = KeysVectors.generate()
    @Test fun badSeed() = KeysVectors.badSeed()
    @Test fun errorClassesPinned() = KeysVectors.errorClassesPinned()
}
