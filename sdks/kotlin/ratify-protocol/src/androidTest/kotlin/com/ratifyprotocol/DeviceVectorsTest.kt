package com.ratifyprotocol

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/** The shared runners on a device or emulator, against the Android build. */
@RunWith(AndroidJUnit4::class)
class DeviceVectorsTest {
    companion object {
        @BeforeClass @JvmStatic
        fun setUpCorpus() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            Corpus.read = { name -> assets.open(name).use { it.readBytes() } }
            Corpus.list = { dir -> assets.list(dir)!!.toList() }
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
    @Test fun referenceStoreClockAndClone() = ReferenceStoreVectors.clockAndClone()
    @Test fun referenceStoreClaimError() = ReferenceStoreVectors.invalidClaimId()
    @Test fun referenceStoreClaimReplayAndLease() = ReferenceStoreVectors.claimReplayAndLease()
    @Test fun referenceStoreCommittedReceiptCheckpointAndRelease() =
        ClaimTest().referenceStoreCommittedReceiptCheckpointAndRelease()
    @Test fun lifecycleAllowPublishedAcknowledgedReleased() =
        ClaimTest().lifecycleAllowPublishedAcknowledgedReleased()
}
