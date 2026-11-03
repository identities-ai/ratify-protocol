package com.ratifyprotocol

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores software keys on Android (build plan §4.3): each key is the file
 * `files/ratify/keys/<key_id>.key` holding `header || nonce[12] ||
 * ciphertext || tag`, where `header` is the storage record's cleartext header
 * and the ciphertext is AES-256-GCM of the record's fields under the
 * non-exportable Keystore key `ratify.v2.wrap.<key_id>` (StrongBox when the
 * device has it), with the header as associated data.
 *
 * @param requireUserAuthentication when true, the wrap key is usable only
 *   after the user authenticated within [authValiditySeconds].
 */
public class AndroidKeyStore(
    context: Context,
    private val requireUserAuthentication: Boolean = false,
    private val authValiditySeconds: Int = 30,
) {
    private val dir = File(context.filesDir, "ratify/keys")
    private val hasStrongBox = Build.VERSION.SDK_INT >= 28 &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private companion object {
        val saveLock = Any()
    }

    private fun file(keyId: String): File {
        if (!validId(keyId)) throw RatifyException.Protocol(ErrorClass.MALFORMED, "not a v2 key ID")
        return File(dir, "$keyId.key")
    }

    private fun alias(keyId: String) = "ratify.v2.wrap.$keyId"

    private fun keystore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createWrapKey(keyId: String): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias(keyId), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (requireUserAuthentication) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= 30) {
                        setUserAuthenticationParameters(authValiditySeconds, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(authValiditySeconds)
                    }
                }
            }
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(hasStrongBox)); gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(false)); gen.generateKey()
        }
    }

    /** Store a key. Fails with `configuration_invalid` if one with this ID exists. */
    public fun save(key: SoftwarePrivateKey): Unit = saveRecord(key.keyId, key.storageRecord())

    /** Store a Keystore key's ML-DSA-65 half (its type 0x03 record). */
    public fun save(key: KeystoreKey): Unit = saveRecord(key.keyId, key.storageRecord())

    internal fun saveRecord(keyId: String, record: ByteArray) {
        val f = file(keyId)
        try {
            // One save at a time in this process: two saves of one ID must not
            // replace each other's wrap key.
            synchronized(saveLock) {
                if (f.exists()) throw RatifyException.Protocol(ErrorClass.CONFIGURATION_INVALID, "a key with this ID is already stored")
                val header = KeyStorageRecord(record).header
                // A wrap key with no file is left over from an interrupted save.
                keystore().let { if (it.containsAlias(alias(keyId))) it.deleteEntry(alias(keyId)) }
                val wrap = createWrapKey(keyId)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrap) }
                cipher.updateAAD(header)
                val sealed = cipher.doFinal(record, header.size, record.size - header.size)
                dir.mkdirs()
                val tmp = File.createTempFile("$keyId.", ".tmp", dir)
                try {
                    tmp.writeBytes(header + cipher.iv + sealed)
                    // A move without REPLACE_EXISTING refuses an existing key file.
                    // (Android's SELinux policy denies hard links in app storage.)
                    // Saves are serialized in this process; two processes of one
                    // app saving the same key at once is the remaining window.
                    try {
                        java.nio.file.Files.move(tmp.toPath(), f.toPath())
                    } catch (e: java.nio.file.FileAlreadyExistsException) {
                        throw RatifyException.Protocol(ErrorClass.CONFIGURATION_INVALID, "a key with this ID is already stored")
                    }
                } finally {
                    tmp.delete()
                }
            }
        } finally {
            record.fill(0)
        }
    }

    /** Load the software key with this ID, or null if none is stored. */
    public fun load(keyId: String): SoftwarePrivateKey? {
        val record = loadRecord(keyId) ?: return null
        try {
            return softwarePrivateKeyFromStorageRecord(record)
        } finally {
            record.fill(0)
        }
    }

    /** Load the Keystore key with this ID, or null if none is stored. */
    public fun loadKeystoreKey(keyId: String): KeystoreKey? {
        val record = loadRecord(keyId) ?: return null
        try {
            return KeystoreKey.fromStorageRecord(record)
        } finally {
            record.fill(0)
        }
    }

    internal fun loadRecord(keyId: String): ByteArray? {
        val f = file(keyId)
        if (!f.exists()) return null
        val bytes = f.readBytes()
        try {
            return open(keyId, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun open(keyId: String, bytes: ByteArray): ByteArray {
        val bad = { m: String -> RatifyException.Protocol(ErrorClass.MALFORMED, "stored key file: $m") }
        if (bytes.size < 8) throw bad("truncated")
        val headerLen = 8 + (((bytes[6].toInt() and 0xFF) shl 8) or (bytes[7].toInt() and 0xFF))
        if (bytes.size < headerLen + 12 + 16) throw bad("truncated")
        val header = bytes.copyOfRange(0, headerLen)
        if (String(header, 8, headerLen - 8, Charsets.US_ASCII) != keyId) {
            throw RatifyException.Protocol(ErrorClass.KEY_ID_MISMATCH, "stored key file names another key")
        }
        val wrap = keystore().getKey(alias(keyId), null) as? SecretKey ?: throw bad("its wrap key is missing")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrap, GCMParameterSpec(128, bytes, headerLen, 12))
        cipher.updateAAD(header)
        val fields = try {
            cipher.doFinal(bytes, headerLen + 12, bytes.size - headerLen - 12)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw bad("authentication failed (corrupted, or its header was changed)")
        }
        try {
            return header + fields
        } finally {
            fields.fill(0)
        }
    }

    /**
     * Delete the key with this ID, its wrap key and, for a [KeystoreKey], its
     * Keystore Ed25519 key (named in its record); deleting an absent key succeeds.
     */
    public fun delete(keyId: String) {
        val ed25519Alias = runCatching { loadRecord(keyId) }.getOrNull()?.let { record ->
            try {
                ffi { com.ratifyprotocol.internal.ffi.ffiParseStorageRecord(record) }.fields.firstOrNull { it.tag.toInt() == 0x06 }
                    ?.let { String(it.value, Charsets.US_ASCII) }
            } finally {
                record.fill(0)
            }
        }
        file(keyId).delete()
        keystore().let { ks ->
            for (a in listOfNotNull(alias(keyId), ed25519Alias)) if (ks.containsAlias(a)) ks.deleteEntry(a)
        }
    }
}
