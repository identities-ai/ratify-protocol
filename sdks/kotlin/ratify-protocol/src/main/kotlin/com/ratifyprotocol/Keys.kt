package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiPublicKey
import com.ratifyprotocol.internal.ffi.FfiSoftwareKey
import com.ratifyprotocol.internal.ffi.ffiKeyId
import com.ratifyprotocol.internal.ffi.ffiValidId

/** A complete hybrid public key: Ed25519 (32 bytes) and ML-DSA-65 (1952 bytes). */
public class HybridPublicKey(ed25519: ByteArray, mlDsa65: ByteArray) {
    private val ed = ed25519.copyOf()
    private val ml = mlDsa65.copyOf()

    public val ed25519: ByteArray get() = ed.copyOf()
    public val mlDsa65: ByteArray get() = ml.copyOf()

    internal constructor(k: FfiPublicKey) : this(k.ed25519, k.mlDsa65)

    internal fun toFfi(): FfiPublicKey = FfiPublicKey(ed.copyOf(), ml.copyOf())

    override fun equals(other: Any?): Boolean =
        other is HybridPublicKey && ed.contentEquals(other.ed) && ml.contentEquals(other.ml)

    override fun hashCode(): Int = 31 * ed.contentHashCode() + ml.contentHashCode()
}

/**
 * A hybrid Ed25519 + ML-DSA-65 private key held in software, kept as its two
 * 32-byte seeds (an Ed25519 seed and a FIPS 204 ML-DSA-65 seed), the
 * documented storage form.
 */
public class SoftwarePrivateKey internal constructor(internal val handle: FfiSoftwareKey) {
    /** The public half. */
    public val publicKey: HybridPublicKey = HybridPublicKey(handle.publicKey())

    /** `key_id_v2` of the public key (64 lowercase hex characters). */
    public val keyId: String = handle.keyId()

    public companion object {
        /** Derive the key from its two 32-byte seeds. */
        public fun fromSeeds(ed25519Seed: ByteArray, mlDsa65Seed: ByteArray): SoftwarePrivateKey =
            SoftwarePrivateKey(ffi { FfiSoftwareKey.fromSeeds(ed25519Seed, mlDsa65Seed) })

        /** Generate a fresh key from the operating-system random source. */
        public fun generate(): SoftwarePrivateKey = SoftwarePrivateKey(ffi { FfiSoftwareKey.generate() })
    }
}

/** `key_id_v2` of a complete public key (SPEC-v2 §2.3). */
public fun keyId(key: HybridPublicKey): String = ffi { ffiKeyId(key.toFfi()) }

/** Whether [id] is a well-formed v2 key ID: 64 lowercase hex characters. */
public fun validId(id: String): Boolean = ffiValidId(id)
