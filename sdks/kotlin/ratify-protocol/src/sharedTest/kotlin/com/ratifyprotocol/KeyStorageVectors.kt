package com.ratifyprotocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/** The documented storage record (build plan §4.3), on host and device. */
object KeyStorageVectors {
    fun roundTripAndLayout() {
        val key = SoftwarePrivateKey.fromSeeds(ByteArray(32) { 0x41 }, ByteArray(32) { 0xc1.toByte() })
        val record = key.storageRecord()
        assertTrue(record.copyOf(8).contentEquals("RFYK".toByteArray() + byteArrayOf(1, 1, 0, 64)))
        assertEquals(8 + 64 + 1 + 2 * (3 + 32), record.size)
        val parsed = KeyStorageRecord(record)
        assertEquals(KeyStorageRecord.RecordType.SOFTWARE, parsed.recordType)
        assertEquals(key.keyId, parsed.keyId)
        assertTrue(parsed.header.contentEquals(record.copyOf(72)))
        assertEquals(key.keyId, softwarePrivateKeyFromStorageRecord(record).keyId)
    }

    fun refusals() {
        val record = SoftwarePrivateKey.generate().storageRecord()
        fun load(mutate: (ByteArray) -> ByteArray) = classOf { softwarePrivateKeyFromStorageRecord(mutate(record.copyOf())) }
        assertEquals("malformed", load { it.copyOf(it.size - 1) })
        assertEquals("malformed", load { it + byteArrayOf(0) })
        assertEquals("malformed", load { it.also { b -> b[4] = 2 } })
        assertEquals("malformed", load { it.also { b -> b[0] = 0x58 } })
        assertEquals("key_id_mismatch", load { it.also { b -> b[76] = (b[76].toInt() xor 1).toByte() } })
        val other = SoftwarePrivateKey.generate().keyId.toByteArray()
        assertEquals("key_id_mismatch", load { it.also { b -> other.copyInto(b, 8) } })
    }
}
