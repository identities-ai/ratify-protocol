package com.ratifyprotocol


import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.ratifyprotocol.internal.ffi.FfiEd25519Signer
import com.ratifyprotocol.internal.ffi.FfiSignContext
import com.ratifyprotocol.internal.ffi.FfiSignerException
import com.ratifyprotocol.internal.ffi.FfiSplitKey
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * A split-custody hybrid key (build plan §4.2): Ed25519 generated in Android
 * Keystore (API 33+, TEE or StrongBox where the device has them) and
 * ML-DSA-65 from a software seed held only in the key's sealed type 0x03
 * storage record. It signs only SDK-computed requests through the typed
 * signing functions; there is no API that signs arbitrary bytes. The SDK
 * verifies both returned components before using them.
 */
@RequiresApi(33)
public class KeystoreKey private constructor(internal val split: FfiSplitKey, private val alias: String) {
    public val publicKey: HybridPublicKey = HybridPublicKey(ffi { split.publicKey() })
    public val keyId: String = ffi { split.keyId() }

    /** Where a key component is held, from the platform's own report. */
    public enum class Custody { STRONGBOX, TEE, SOFTWARE, UNKNOWN }

    /** Ed25519 custody from Keystore's KeyInfo; ML-DSA-65 is always software here. */
    public val custody: Pair<Custody, Custody> get() = ed25519Custody() to Custody.SOFTWARE

    private fun privateKey(): PrivateKey =
        keystore().getKey(alias, null) as? PrivateKey
            ?: throw RatifyException.Protocol(ErrorClass.CONFIGURATION_INVALID, "the Keystore Ed25519 key is missing")

    private fun ed25519Custody(): Custody {
        val pk = privateKey()
        // Keystore reports an Ed25519 key's algorithm under different names by release.
        val info = listOf(pk.algorithm, KeyProperties.KEY_ALGORITHM_EC, "Ed25519", "EdDSA").distinct().firstNotNullOfOrNull { alg ->
            runCatching { KeyFactory.getInstance(alg, "AndroidKeyStore").getKeySpec(pk, KeyInfo::class.java) }.getOrNull()
        } ?: return Custody.UNKNOWN
        return when (info.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> Custody.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Custody.TEE
            KeyProperties.SECURITY_LEVEL_SOFTWARE -> Custody.SOFTWARE
            else -> Custody.UNKNOWN
        }
    }

    /** This key's type 0x03 storage record (seal it with [AndroidKeyStore]). */
    public fun storageRecord(): ByteArray = ffi { split.storageRecord(alias) }

    /** The Keystore half: signs the SDK's 77-byte message with Ed25519. */
    internal inner class Ed25519Half : FfiEd25519Signer {
        override fun sign(message: ByteArray, context: FfiSignContext): ByteArray =
            try {
                Signature.getInstance("Ed25519").run {
                    initSign(privateKey())
                    update(message)
                    sign()
                }
            } catch (e: Exception) {
                throw FfiSignerException.Provider("Keystore Ed25519 signing failed: $e")
            }
    }

    internal fun ed25519Half(): FfiEd25519Signer = Ed25519Half()

    /** Remove the Keystore half of a key that was never stored (tests, failed setup). */
    internal fun deleteKeystoreEntry() {
        keystore().let { if (it.containsAlias(alias)) it.deleteEntry(alias) }
    }

    public companion object {
        private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        /**
         * Generate a new key: Ed25519 in Keystore (StrongBox if [strongBox]
         * and available), and a fresh ML-DSA-65 seed. Store its record with
         * [AndroidKeyStore.save]. Requires a device whose Keystore supports
         * Ed25519; otherwise throws `configuration_invalid`.
         */
        public fun generate(strongBox: Boolean = false, requireUserAuthentication: Boolean = false): KeystoreKey {
            val alias = "ratify.v2.ed25519.${UUID.randomUUID()}"
            val publicEncoded = try {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                    .setIsStrongBoxBacked(strongBox)
                    .setUserAuthenticationRequired(requireUserAuthentication)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
                    initialize(spec)
                    generateKeyPair().public.encoded
                }
            } catch (e: Exception) {
                throw RatifyException.Protocol(ErrorClass.CONFIGURATION_INVALID, "this device's Keystore cannot create an Ed25519 key: $e")
            }
            // X.509 SubjectPublicKeyInfo for Ed25519 is a 12-byte prefix and the 32-byte key.
            val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            if (publicEncoded.size != 44 || !publicEncoded.copyOf(12).contentEquals(prefix)) {
                keystore().deleteEntry(alias)
                throw RatifyException.Protocol(ErrorClass.CONFIGURATION_INVALID, "unexpected Keystore Ed25519 public key encoding")
            }
            val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
            try {
                return KeystoreKey(ffi { FfiSplitKey(seed, publicEncoded.copyOfRange(12, 44)) }, alias)
            } finally {
                seed.fill(0)
            }
        }

        /** Load a key from its type 0x03 record; its Keystore half must still exist. */
        public fun fromStorageRecord(record: ByteArray): KeystoreKey {
            val split = ffi { FfiSplitKey.fromStorageRecord(record) }
            val alias = String(ffi { com.ratifyprotocol.internal.ffi.ffiParseStorageRecord(record) }.fields.first { it.tag.toInt() == 0x06 }.value)
            return KeystoreKey(split, alias).also { it.privateKey() }
        }

    }
}

/** The key a typed signing function signs with (build plan §4.1). */
public sealed class SigningKey {
    /** A software key, held as its two seeds. */
    public class Software(public val key: SoftwarePrivateKey) : SigningKey()

    /** An app-held key (HSM, KMS, remote service) behind your [ExternalSigner]. */
    public class External(public val signer: ExternalSigner) : SigningKey()

    /** A Keystore split-custody key (API 33+). */
    public class Platform @RequiresApi(33) constructor(internal val key: KeystoreKey) : SigningKey()
}
