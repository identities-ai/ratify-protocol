package com.ratifyprotocol

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/** The shared vector runners on a device or emulator, against the Android build. */
@RunWith(AndroidJUnit4::class)
class DeviceVectorsTest {
    companion object {
        private lateinit var annex: String

        @BeforeClass @JvmStatic
        fun corpus() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            Corpus.read = { name -> assets.open(name).use { it.readBytes() } }
            annex = String(Corpus.read("spec/SPEC-v2-ANNEX-A.md"), Charsets.UTF_8)
        }
    }

    @Test fun keys() = KeysVectors.corpus()
    @Test fun generate() = KeysVectors.generate()
    @Test fun badSeed() = KeysVectors.badSeed()
    @Test fun errorClassesPinned() = KeysVectors.errorClassesPinned()
    @Test fun annexA() = AnnexAVectors.corpus(annex)
    @Test fun limits() = LimitsVectors.corpus()
    @Test fun operationSessionContext() = OperationContextVectors.corpus()
    @Test fun contextFieldValidation() = OperationContextVectors.fieldValidation()
}
