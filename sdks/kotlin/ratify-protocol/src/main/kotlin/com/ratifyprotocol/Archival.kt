package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiArchivalProofBundleResult
import com.ratifyprotocol.internal.ffi.FfiArchivalVerification
import com.ratifyprotocol.internal.ffi.FfiStatusObject
import com.ratifyprotocol.internal.ffi.ffiArchivalProofBundleResultJson
import com.ratifyprotocol.internal.ffi.ffiStatementBodyDigest
import com.ratifyprotocol.internal.ffi.ffiStatusEvidenceDigest
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalDelegationCert
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalKeyRotationStatement
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalProofBundle
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalRevocationList
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalRevocationPush
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalTransactionReceipt
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalVerificationReceipt
import com.ratifyprotocol.internal.ffi.ffiVerifyArchivalWitnessEntry
import java.util.Collections

/**
 * One stored object decoded strictly with its signatures verified (SPEC-v2
 * §6.10). Never an authorization decision: [actionable] is always false.
 */
public class ArchivalVerification internal constructor(f: FfiArchivalVerification) {
    public val objectType: UShort = f.objectType
    public val freshness: String = f.freshness
    public val actionable: Boolean = f.actionable

    /** `sha384:` + 96 hex of the registered digest; empty when the object has none. */
    public val digest: String = f.digest

    /** The v2 key IDs whose signatures were verified, in object order. */
    public val signerKeyIds: List<String> = Collections.unmodifiableList(ArrayList(f.signerKeyIds))
}

/** The §6.10 archival proof-bundle result; never actionable. [errorClass] is null when every check passed. */
public class ArchivalProofBundleResult internal constructor(private val f: FfiArchivalProofBundleResult) {
    public val assessment: String = f.assessment
    public val actionable: Boolean = f.actionable
    public val bundleHash: String = f.bundleHash
    public val agentId: String = f.agentId
    public val issuerIds: List<String> = Collections.unmodifiableList(ArrayList(f.issuerIds))
    public val errorClass: ErrorClass? = f.errorClass?.let { ErrorClass.fromSpelling(it) ?: error("unknown error class $it") }

    /** The diagnostic for [errorClass]; not part of the language-neutral result. */
    public val errorMessage: String = f.errorMessage

    /** The language-neutral canonical JSON of this result. */
    public fun json(): ByteArray = ffi { ffiArchivalProofBundleResultJson(f) }
}

/** A status object: a full revocation list or an incremental push. */
public sealed class StatusObject {
    public class List(public val list: RevocationList) : StatusObject()
    public class Push(public val push: RevocationPush) : StatusObject()

    internal fun toFfi(): FfiStatusObject = when (this) {
        is List -> FfiStatusObject.List(list.toFfi())
        is Push -> FfiStatusObject.Push(push.toFfi())
    }
}

public fun verifyArchivalProofBundle(data: ByteArray): ArchivalProofBundleResult =
    ArchivalProofBundleResult(ffi { ffiVerifyArchivalProofBundle(data) })
public fun verifyArchivalDelegationCert(data: ByteArray): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalDelegationCert(data) })
public fun verifyArchivalRevocationList(data: ByteArray, issuerId: String, statusKey: HybridPublicKey): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalRevocationList(data, issuerId, statusKey.toFfi()) })
public fun verifyArchivalRevocationPush(data: ByteArray, issuerId: String, statusKey: HybridPublicKey): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalRevocationPush(data, issuerId, statusKey.toFfi()) })
public fun verifyArchivalKeyRotationStatement(data: ByteArray): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalKeyRotationStatement(data) })
public fun verifyArchivalWitnessEntry(data: ByteArray, witnessKey: HybridPublicKey): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalWitnessEntry(data, witnessKey.toFfi()) })
public fun verifyArchivalVerificationReceipt(data: ByteArray, verifierKey: HybridPublicKey): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalVerificationReceipt(data, verifierKey.toFfi()) })
public fun verifyArchivalTransactionReceipt(data: ByteArray): ArchivalVerification =
    ArchivalVerification(ffi { ffiVerifyArchivalTransactionReceipt(data) })

/** `StatementBodyDigestV2` under an explicit object type code (SPEC-v2 §4). */
public fun statementBodyDigest(objectTypeCode: UShort, signableBody: ByteArray): ByteArray =
    ffi { ffiStatementBodyDigest(objectTypeCode, signableBody) }

/** `StatusEvidenceDigest` under an explicit code: 0x0003 takes a list, 0x0005 a push. */
public fun statusEvidenceDigest(objectTypeCode: UShort, obj: StatusObject): ByteArray =
    ffi { ffiStatusEvidenceDigest(objectTypeCode, obj.toFfi()) }
