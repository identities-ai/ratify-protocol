package com.ratifyprotocol

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** The Android key store (build plan §4.3), against the device Keystore. */
@RunWith(AndroidJUnit4::class)
class AndroidKeyStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun storesLoadsAndDeletes() {
        val store = AndroidKeyStore(context)
        val key = SoftwarePrivateKey.generate()
        try {
            assertNull(store.load(key.keyId))
            store.save(key)
            assertEquals("configuration_invalid", classOf { store.save(key) })
            // A new store instance (as after process death) reads the same file.
            val loaded = AndroidKeyStore(context).load(key.keyId)!!
            assertEquals(key.keyId, loaded.keyId)
            assertEquals(key.publicKey, loaded.publicKey)
            store.delete(key.keyId)
            assertNull(store.load(key.keyId))
        } finally {
            store.delete(key.keyId)
        }
    }

    @Test
    fun corruptedSwappedAndRebadgedFilesAreRefused() {
        val store = AndroidKeyStore(context)
        val a = SoftwarePrivateKey.generate()
        val b = SoftwarePrivateKey.generate()
        try {
            store.save(a)
            store.save(b)
            val dir = File(context.filesDir, "ratify/keys")
            val fa = File(dir, "${a.keyId}.key")
            val original = fa.readBytes()
            // A flipped ciphertext byte fails authentication.
            fa.writeBytes(original.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() })
            assertEquals("malformed", classOf { store.load(a.keyId) })
            // A changed header byte (the record type, part of the associated
            // data) passes the name check but fails AES-GCM authentication.
            fa.writeBytes(original.copyOf().also { it[5] = 0x02 })
            assertEquals("malformed", classOf { store.load(a.keyId) })
            // b's file under a's name names another key.
            File(dir, "${b.keyId}.key").copyTo(fa, overwrite = true)
            assertEquals("key_id_mismatch", classOf { store.load(a.keyId) })
            // Truncated.
            fa.writeBytes(original.copyOf(20))
            assertEquals("malformed", classOf { store.load(a.keyId) })
        } finally {
            store.delete(a.keyId)
            store.delete(b.keyId)
        }
    }
}
