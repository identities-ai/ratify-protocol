package com.ratifyprotocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals

/**
 * keys.json through the public API. Key IDs are also recomputed here with
 * java.security from the documented preimage, independent of the core.
 */
object KeysVectors {
    private fun independentKeyId(k: HybridPublicKey): String =
        sha256("ratify-key-id-v2".toByteArray() + byteArrayOf(0) + k.ed25519 + k.mlDsa65).hex()

    fun corpus() {
        val f = Corpus.load("keys.json")
        assertEquals("ratify-key-id-v2 || 0x00 || ed25519(32) || ml_dsa_65(1952)", f.getString("key_id_preimage"))
        val t = Tally()
        val keys = f.arr("keys")
        for (k in keys) {
            val pk = k.getJSONObject("public_key")
            val pinned = HybridPublicKey(pk.b64("ed25519"), pk.b64("ml_dsa_65"))
            val id = k.getString("key_id_v2")
            val v1 = k.getString("v1_key_id_128")
            val derived = SoftwarePrivateKey.fromSeeds(k.hex("ed25519_seed_hex"), k.hex("ml_dsa_65_seed_hex"))
            val ok = derived.publicKey == pinned &&
                derived.keyId == id &&
                keyId(pinned) == id &&
                independentKeyId(pinned) == id &&
                validId(id) &&
                !validId(v1) &&
                v1 != id.substring(0, 32)
            t.check("keys", k.getString("name"), ok) { "seeds, key ID, or v1 ID differ" }
        }
        val bad = f.arr("invalid_v2_key_ids")
        for (b in bad) {
            t.check("invalid_v2_key_ids format", b.getString("name"), !validId(b.getString("value"))) { "accepted" }
        }
        t.finish(listOf("keys" to keys.size, "invalid_v2_key_ids format" to bad.size))
    }

    fun generate() {
        val a = SoftwarePrivateKey.generate()
        val b = SoftwarePrivateKey.generate()
        assertNotEquals(a.keyId, b.keyId)
        assertEquals(a.keyId, keyId(a.publicKey))
        assertEquals(32, a.publicKey.ed25519.size)
        assertEquals(1952, a.publicKey.mlDsa65.size)
    }

    fun badSeed() {
        assertEquals("malformed", classOf { SoftwarePrivateKey.fromSeeds(ByteArray(31), ByteArray(32)) })
    }

    fun errorClassesPinned() {
        assertEquals(errorClassSpellings(), ErrorClass.entries.map { it.spelling })
    }
}
