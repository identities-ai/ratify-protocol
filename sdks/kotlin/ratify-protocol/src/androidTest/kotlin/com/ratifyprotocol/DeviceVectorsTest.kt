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
        @BeforeClass @JvmStatic
        fun corpus() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            Corpus.read = { name -> assets.open(name).use { it.readBytes() } }
        }
    }

    @Test fun keys() = KeysVectors.corpus()
    @Test fun generate() = KeysVectors.generate()
    @Test fun badSeed() = KeysVectors.badSeed()
    @Test fun errorClassesPinned() = KeysVectors.errorClassesPinned()
}
