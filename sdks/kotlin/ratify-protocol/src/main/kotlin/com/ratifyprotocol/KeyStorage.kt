package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiSoftwareKey
import com.ratifyprotocol.internal.ffi.ffiParseStorageRecord

/**
 * A parsed key storage record (sdks/kotlin/KEY_STORAGE.md): the documented,
 * implementation-neutral form a key is stored in.
 */
public class KeyStorageRecord(data: ByteArray) {
    public enum class RecordType(public val code: UByte) {
        /** An Ed25519 seed and an ML-DSA-65 seed held in software. */
        SOFTWARE(0x01u),

        /** An Ed25519 seed and a Secure Enclave ML-DSA-65 key (device-bound). */
        SECURE_ENCLAVE_HYBRID(0x02u),

        /** An ML-DSA-65 seed and an Android Keystore Ed25519 key. */
        ANDROID_SPLIT(0x03u),
    }

    private val r = ffi { ffiParseStorageRecord(data) }
    public val recordType: RecordType =
        RecordType.entries.firstOrNull { it.code == r.recordType } ?: throw RatifyException.Protocol(ErrorClass.MALFORMED, "unknown record type")
    public val keyId: String = r.keyId
    private val h = r.header.copyOf()

    /** The cleartext header bytes (bound as associated data where encrypted). */
    public val header: ByteArray get() = h.copyOf()
}

/**
 * This key's storage record (type 0x01: its two seeds). The record is key
 * material: store it only in protected storage and wipe your copy.
 */
public fun SoftwarePrivateKey.storageRecord(): ByteArray = ffi { handle.storageRecord() }

/**
 * Load a key from its storage record. The key is re-derived from the seeds; a
 * record whose seeds derive another key ID is refused with `key_id_mismatch`.
 */
public fun softwarePrivateKeyFromStorageRecord(record: ByteArray): SoftwarePrivateKey =
    SoftwarePrivateKey(ffi { FfiSoftwareKey.fromStorageRecord(record) })
