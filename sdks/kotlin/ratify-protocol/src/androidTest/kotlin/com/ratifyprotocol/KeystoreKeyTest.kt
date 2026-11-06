package com.ratifyprotocol

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ratifyprotocol.internal.ffi.FfiCancelToken
import com.ratifyprotocol.internal.ffi.FfiEd25519Signer
import com.ratifyprotocol.internal.ffi.FfiSignContext
import com.ratifyprotocol.internal.ffi.ffiSignDelegationCertWithSplitKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The Keystore split-custody key (build plan §4.2). It needs Android 13
 * (API 33) Keystore Ed25519, so these run on an API 33+ device or emulator;
 * on older releases the type is unavailable (RequiresApi) and they return.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreKeyTest {
    companion object {
        @BeforeClass @JvmStatic
        fun setUpCorpus() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            Corpus.read = { name -> assets.open(name).use { it.readBytes() } }
            Corpus.list = { dir -> assets.list(dir)!!.toList() }
        }
    }

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun cert(issuer: HybridPublicKey, keyId: String): DelegationCert {
        val c = decodeDelegationCert(objectByKind(Corpus.load("objects.json"), "delegation_certificate").b64("wire_b64"))
        return DelegationCert(c.version, c.certId, keyId, issuer, c.subjectId, c.subjectPubKey, c.scope, c.constraints,
            c.issuedAt, c.expiresAt, c.signature)
    }

    @Test
    fun signsVerifiesStoresAndReloads() = runBlocking {
        if (Build.VERSION.SDK_INT < 33) return@runBlocking
        val store = AndroidKeyStore(context)
        val key = KeystoreKey.generate()
        try {
            assertNotEquals(KeystoreKey.Custody.UNKNOWN, key.custody.first)
            assertEquals(KeystoreKey.Custody.SOFTWARE, key.custody.second)
            val signed = signDelegationCert(cert(key.publicKey, key.keyId), SigningKey.Platform(key))
            verifyDelegationCertSignature(signed)
            store.save(key)
            val reloaded = AndroidKeyStore(context).loadKeystoreKey(key.keyId)!!
            assertEquals(key.keyId, reloaded.keyId)
            verifyDelegationCertSignature(signDelegationCert(cert(reloaded.publicKey, reloaded.keyId), SigningKey.Platform(reloaded)))
        } finally {
            store.delete(key.keyId)
        }
        assertEquals(null, store.loadKeystoreKey(key.keyId))
    }

    /**
     * Every bad component the platform could return is refused. The Keystore
     * Ed25519 half is the only one the platform returns: ML-DSA-65 is signed
     * in Rust from the seed over the core's message and context.
     */
    @Test
    fun badComponentsAreRefused() {
        if (Build.VERSION.SDK_INT < 33) return
        val key = KeystoreKey.generate()
        val other = KeystoreKey.generate()
        try {
            val real = key.ed25519Half()
            val otherHalf = other.ed25519Half()
            fun tamper(mutate: (ByteArray, FfiSignContext) -> ByteArray) = object : FfiEd25519Signer {
                override fun sign(message: ByteArray, context: FfiSignContext) = mutate(message, context)
            }
            val cases = mapOf<String, (ByteArray, FfiSignContext) -> ByteArray>(
                "missing Ed25519" to { _, _ -> ByteArray(0) },
                "malformed Ed25519" to { m, c -> real.sign(m, c).copyOf(63) },
                "flipped Ed25519" to { m, c -> real.sign(m, c).also { it[0] = (it[0].toInt() xor 1).toByte() } },
                "valid Ed25519 from a different key" to { m, c -> otherHalf.sign(m, c) },
                "Ed25519 over another message" to { m, c -> real.sign(m.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, c) },
            )
            for ((name, mutate) in cases) {
                val got = classOf {
                    ffi { ffiSignDelegationCertWithSplitKey(FfiCancelToken(null), cert(key.publicKey, key.keyId).toFfi(), key.split, tamper(mutate)) }
                }
                assertEquals(name, "invalid_signature", got)
            }
        } finally {
            key.deleteKeystoreEntry()
            other.deleteKeystoreEntry()
        }
    }

    /** A software root rotates into a Keystore key, and the core verifies both halves. */
    @Test
    fun softwareRootRotatesIntoKeystore() = runBlocking {
        if (Build.VERSION.SDK_INT < 33) return@runBlocking
        val software = SoftwarePrivateKey.generate()
        val platform = KeystoreKey.generate()
        try {
            val v = Corpus.load("key-rotation-signature.json")
            val stmt = KeyRotationStatement(2, v.getString("authority_id"), 1, v.getString("role"), 1, ByteArray(48),
                software.publicKey, platform.publicKey, software.keyId, platform.keyId, 1_800_000_000, 1_800_000_000,
                HybridSignature(ByteArray(0), ByteArray(0)), HybridSignature(ByteArray(0), ByteArray(0)))
            val signed = signKeyRotationStatement(stmt, SigningKey.Software(software), SigningKey.Platform(platform))
            val signable = keyRotationStatementSignableBytes(signed)
            verifyStatement(ObjectType.KEY_ROTATION_AUTHORIZATION, signable, signed.oldSignature, software.publicKey)
            verifyStatement(ObjectType.KEY_ROTATION_PROOF_OF_POSSESSION, signable, signed.newSignature, platform.publicKey)
        } finally {
            platform.deleteKeystoreEntry()
        }
    }
}
