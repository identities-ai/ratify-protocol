package com.ratifyprotocol

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ratifyprotocol.internal.ffi.FfiSignContext
import com.ratifyprotocol.internal.ffi.FfiSignRequest
import com.ratifyprotocol.internal.ffi.FfiSignature
import com.ratifyprotocol.internal.ffi.FfiSigner
import com.ratifyprotocol.internal.ffi.FfiCancelToken
import com.ratifyprotocol.internal.ffi.ffiSignDelegationCertWithSigner
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

    /** Every bad component the platform signer could return is refused. */
    @Test
    fun badComponentsAreRefused() {
        if (Build.VERSION.SDK_INT < 33) return
        val key = KeystoreKey.generate()
        val other = KeystoreKey.generate()
        try {
            val inner = key.ffiSigner()
            val alt = other.ffiSigner()
            fun tamper(mutate: (FfiSignRequest, FfiSignContext) -> FfiSignature) = object : FfiSigner {
                override fun publicKey() = inner.publicKey()
                override fun mode() = inner.mode()
                override fun sign(request: FfiSignRequest, context: FfiSignContext) = mutate(request, context)
            }
            fun flip(b: ByteArray) = b.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            val cases = mapOf<String, (FfiSignRequest, FfiSignContext) -> FfiSignature>(
                "missing ML-DSA" to { r, c -> inner.sign(r, c).let { FfiSignature(it.ed25519, ByteArray(0)) } },
                "malformed ML-DSA" to { r, c -> inner.sign(r, c).let { FfiSignature(it.ed25519, it.mlDsa65.copyOf(it.mlDsa65.size - 1)) } },
                "wrong context" to { r, c ->
                    inner.sign(FfiSignRequest(r.mode, r.message, "ratify-v2-wrong-context".toByteArray(), r.mlDsaMu, r.publicKey, r.keyId), c)
                },
                "wrong-key ML-DSA" to { r, c ->
                    val o = alt.sign(FfiSignRequest(r.mode, r.message, r.mlDsaContext, r.mlDsaMu, alt.publicKey(), ffi { other.keyId }), c)
                    FfiSignature(inner.sign(r, c).ed25519, o.mlDsa65)
                },
                "flipped Ed25519" to { r, c -> inner.sign(r, c).let { FfiSignature(flip(it.ed25519), it.mlDsa65) } },
            )
            for ((name, mutate) in cases) {
                val got = classOf {
                    ffi { ffiSignDelegationCertWithSigner(FfiCancelToken(null), cert(key.publicKey, key.keyId).toFfi(), tamper(mutate)) }
                }
                assertEquals(name, "invalid_signature", got)
            }
        } finally {
            key.deleteKeystoreEntry()
            other.deleteKeystoreEntry()
        }
    }
}
