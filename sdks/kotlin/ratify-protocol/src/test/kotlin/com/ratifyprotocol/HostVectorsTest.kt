package com.ratifyprotocol

import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** The shared runners on the host JVM, against the host Rust build. */
class HostVectorsTest {
    companion object {
        @BeforeClass @JvmStatic
        fun setUpCorpus() {
            val root = File(System.getProperty("ratify.corpus")!!)
            val annex = File(System.getProperty("ratify.annex")!!)
            Corpus.read = { if (it == "spec/SPEC-v2-ANNEX-A.md") annex.readBytes() else File(root, it).readBytes() }
            Corpus.list = { File(root, it).list()!!.toList() }
        }
    }

    @Test fun corpus() = CorpusRunners.runAll()
    @Test fun generate() = KeysVectors.generate()
    @Test fun badSeed() = KeysVectors.badSeed()
    @Test fun errorClassesPinned() = KeysVectors.errorClassesPinned()
    @Test fun contextFieldValidation() = OperationContextVectors.fieldValidation()
    @Test fun panicInQuery() = PanicVectors.query()
    @Test fun panicInDecoder() = PanicVectors.decoder()
    @Test fun panicPoisonsOnlyThatHandle() = PanicVectors.poisonsOnlyThatHandle()
    @Test fun signingPoisonsTheKey() = PanicVectors.signingPoisonsTheKey()
    @Test fun internalKindsPinned() = PanicVectors.kindsPinned()
    @Test fun storageRecordRoundTrip() = KeyStorageVectors.roundTripAndLayout()
    @Test fun storageRecordRefusals() = KeyStorageVectors.refusals()
    @Test fun valuesAreImmutable() = PanicVectors.valuesAreImmutable()
}
