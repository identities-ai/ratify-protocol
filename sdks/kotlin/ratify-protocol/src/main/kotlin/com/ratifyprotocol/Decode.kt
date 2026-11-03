package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiParamsValue
import com.ratifyprotocol.internal.ffi.ffiDecodeDelegationCert
import com.ratifyprotocol.internal.ffi.ffiDecodeKeyRotationStatement
import com.ratifyprotocol.internal.ffi.ffiDecodeProofBundle
import com.ratifyprotocol.internal.ffi.ffiDecodeRevocationList
import com.ratifyprotocol.internal.ffi.ffiDecodeRevocationPush
import com.ratifyprotocol.internal.ffi.ffiDecodeStatusEvidenceBatch
import com.ratifyprotocol.internal.ffi.ffiDecodeTransactionReceipt
import com.ratifyprotocol.internal.ffi.ffiDecodeVerificationReceipt
import com.ratifyprotocol.internal.ffi.ffiDecodeVerificationReceiptBody
import com.ratifyprotocol.internal.ffi.ffiDecodeWitnessEntry

/** A constraint `params` value: JSON without floats. */
public sealed class ParamsValue {
    public object Null : ParamsValue()
    public data class Bool(val value: Boolean) : ParamsValue()
    public data class Int(val value: Long) : ParamsValue()
    public data class Str(val value: String) : ParamsValue()
    public data class Array(val items: List<ParamsValue>) : ParamsValue()
    public data class Object(val entries: Map<String, ParamsValue>) : ParamsValue()

    internal fun toFfi(): FfiParamsValue = when (this) {
        Null -> FfiParamsValue.Null
        is Bool -> FfiParamsValue.Bool(value)
        is Int -> FfiParamsValue.Int(value)
        is Str -> FfiParamsValue.Str(value)
        is Array -> FfiParamsValue.Array(items.map { it.toFfi() })
        is Object -> FfiParamsValue.Object(entries.mapValues { it.value.toFfi() })
    }

    internal companion object {
        fun fromFfi(f: FfiParamsValue): ParamsValue = when (f) {
            FfiParamsValue.Null -> Null
            is FfiParamsValue.Bool -> Bool(f.value)
            is FfiParamsValue.Int -> Int(f.value)
            is FfiParamsValue.Str -> Str(f.value)
            is FfiParamsValue.Array -> Array(f.items.map(::fromFfi))
            is FfiParamsValue.Object -> Object(f.entries.mapValues { fromFfi(it.value) })
        }
    }
}

// Strict decoders (SPEC-v2 §2): each accepts only the canonical wire form of
// one object kind and throws its §2.7 class otherwise.

public fun decodeDelegationCert(data: ByteArray): DelegationCert = DelegationCert(ffi { ffiDecodeDelegationCert(data) })
public fun decodeProofBundle(data: ByteArray): ProofBundle = ProofBundle(ffi { ffiDecodeProofBundle(data) })
public fun decodeRevocationList(data: ByteArray): RevocationList = RevocationList(ffi { ffiDecodeRevocationList(data) })
public fun decodeRevocationPush(data: ByteArray): RevocationPush = RevocationPush(ffi { ffiDecodeRevocationPush(data) })
public fun decodeKeyRotationStatement(data: ByteArray): KeyRotationStatement =
    KeyRotationStatement(ffi { ffiDecodeKeyRotationStatement(data) })
public fun decodeWitnessEntry(data: ByteArray): WitnessEntry = WitnessEntry(ffi { ffiDecodeWitnessEntry(data) })
public fun decodeVerificationReceipt(data: ByteArray): VerificationReceipt =
    VerificationReceipt(ffi { ffiDecodeVerificationReceipt(data) })
public fun decodeVerificationReceiptBody(data: ByteArray): VerificationReceipt =
    VerificationReceipt(ffi { ffiDecodeVerificationReceiptBody(data) })
public fun decodeTransactionReceipt(data: ByteArray): TransactionReceipt =
    TransactionReceipt(ffi { ffiDecodeTransactionReceipt(data) })
public fun decodeStatusEvidenceBatch(data: ByteArray): List<StatusEvidenceObject> =
    ffi { ffiDecodeStatusEvidenceBatch(data) }.map { StatusEvidenceObject(it) }
