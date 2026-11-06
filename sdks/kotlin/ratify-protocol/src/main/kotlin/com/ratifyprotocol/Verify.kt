package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiLogResult
import com.ratifyprotocol.internal.ffi.FfiReceiptHead
import com.ratifyprotocol.internal.ffi.FfiRotationState
import com.ratifyprotocol.internal.ffi.FfiWitnessHead
import com.ratifyprotocol.internal.ffi.ffiBundleHash
import com.ratifyprotocol.internal.ffi.ffiChallengeClaimDigest
import com.ratifyprotocol.internal.ffi.ffiCheckVerificationReceiptBundleBinding
import com.ratifyprotocol.internal.ffi.ffiDelegationCertSignableBytes
import com.ratifyprotocol.internal.ffi.ffiEncodeDelegationCert
import com.ratifyprotocol.internal.ffi.ffiEncodeKeyRotationStatement
import com.ratifyprotocol.internal.ffi.ffiEncodeProofBundle
import com.ratifyprotocol.internal.ffi.ffiEncodeRevocationList
import com.ratifyprotocol.internal.ffi.ffiEncodeRevocationPush
import com.ratifyprotocol.internal.ffi.ffiEncodeTransactionReceipt
import com.ratifyprotocol.internal.ffi.ffiEncodeVerificationReceipt
import com.ratifyprotocol.internal.ffi.ffiEncodeWitnessEntry
import com.ratifyprotocol.internal.ffi.ffiExternalMu
import com.ratifyprotocol.internal.ffi.ffiKeyRotationStatementDigest
import com.ratifyprotocol.internal.ffi.ffiKeyRotationStatementSignableBytes
import com.ratifyprotocol.internal.ffi.ffiMldsaContext
import com.ratifyprotocol.internal.ffi.ffiPresentationSignableBytes
import com.ratifyprotocol.internal.ffi.ffiProtocolClaimId
import com.ratifyprotocol.internal.ffi.ffiRevocationListSignableBytes
import com.ratifyprotocol.internal.ffi.ffiRevocationPushSignableBytes
import com.ratifyprotocol.internal.ffi.ffiSigningMessage
import com.ratifyprotocol.internal.ffi.ffiStatusEvidenceDigestList
import com.ratifyprotocol.internal.ffi.ffiStatusEvidenceDigestPush
import com.ratifyprotocol.internal.ffi.ffiTransactionContextHash
import com.ratifyprotocol.internal.ffi.ffiTransactionPartyRequestHash
import com.ratifyprotocol.internal.ffi.ffiTransactionReceiptSignBytes
import com.ratifyprotocol.internal.ffi.ffiVerificationReceiptBody
import com.ratifyprotocol.internal.ffi.ffiVerificationReceiptDigest
import com.ratifyprotocol.internal.ffi.ffiVerificationReceiptSignableBytes
import com.ratifyprotocol.internal.ffi.ffiVerifyDelegationCertSignature
import com.ratifyprotocol.internal.ffi.ffiVerifyKeyRotationStatement
import com.ratifyprotocol.internal.ffi.ffiVerifyProofBundleSignatures
import com.ratifyprotocol.internal.ffi.ffiVerifyRevocationListSignature
import com.ratifyprotocol.internal.ffi.ffiVerifyRevocationPushSignature
import com.ratifyprotocol.internal.ffi.ffiVerifyStatement
import com.ratifyprotocol.internal.ffi.ffiVerifyTransactionReceiptSignatures
import com.ratifyprotocol.internal.ffi.ffiVerifyVerificationReceipt
import com.ratifyprotocol.internal.ffi.ffiVerifyWitnessEntry
import com.ratifyprotocol.internal.ffi.ffiWitnessEntryDigest
import com.ratifyprotocol.internal.ffi.ffiWitnessEntrySignableBytes
import java.util.Collections

/** A SPEC-v2 signed-object type and its 16-bit code. */
public enum class ObjectType(public val code: UShort) {
    DELEGATION_CERTIFICATE(0x0001u),
    CHALLENGE_PRESENTATION(0x0002u),
    REVOCATION_LIST(0x0003u),
    KEY_ROTATION_AUTHORIZATION(0x0004u),
    REVOCATION_PUSH(0x0005u),
    WITNESS_ENTRY(0x0006u),
    TRANSACTION_PARTY_STATEMENT(0x0007u),
    VERIFICATION_RECEIPT(0x0008u),
    KEY_ROTATION_PROOF_OF_POSSESSION(0x0009u),
    ;

    public companion object {
        /** The type with this code, or null for an unregistered code. */
        public fun fromCode(code: UShort): ObjectType? = entries.firstOrNull { it.code == code }
    }
}

private fun copyDigests(m: Map<Long, ByteArray>): Map<Long, ByteArray> =
    Collections.unmodifiableMap(LinkedHashMap(m.mapValues { it.value.copyOf() }))

/** Caller-authenticated rotation state for one authority and role. */
public class RotationState(
    public val authorityId: String,
    public val recoveryEpoch: Long,
    public val role: String,
    public val sequence: Long,
    headHash: ByteArray,
    public val currentKey: HybridPublicKey,
    usedKeyIds: List<String>,
) {
    private val head = headHash.copyOf()
    public val headHash: ByteArray get() = head.copyOf()

    /** Complete retained history for this authority, including the current key. */
    public val usedKeyIds: List<String> = Collections.unmodifiableList(ArrayList(usedKeyIds))

    internal fun toFfi(): FfiRotationState =
        FfiRotationState(authorityId, recoveryEpoch, role, sequence, head.copyOf(), currentKey.toFfi(), usedKeyIds)
}

/** Caller-authenticated witness-log state before an entry. */
public class WitnessHead(
    public val logId: String,
    public val sequence: Long,
    headHash: ByteArray,
    acceptedDigests: Map<Long, ByteArray> = emptyMap(),
    public val frozen: Boolean = false,
) {
    private val head = headHash.copyOf()
    private val accepted = copyDigests(acceptedDigests)
    public val headHash: ByteArray get() = head.copyOf()

    /** Every accepted sequence's body digest (copies), for replay and fork checks. */
    public val acceptedDigests: Map<Long, ByteArray> get() = copyDigests(accepted)

    internal fun toFfi(): FfiWitnessHead = FfiWitnessHead(logId, sequence, head.copyOf(), copyDigests(accepted), frozen)
}

/** Caller-authenticated receipt-log state before a receipt. */
public class ReceiptHead(
    public val logId: String,
    public val verifierId: String,
    public val sequence: Long,
    headHash: ByteArray,
    acceptedDigests: Map<Long, ByteArray> = emptyMap(),
    public val frozen: Boolean = false,
) {
    private val head = headHash.copyOf()
    private val accepted = copyDigests(acceptedDigests)
    public val headHash: ByteArray get() = head.copyOf()
    public val acceptedDigests: Map<Long, ByteArray> get() = copyDigests(accepted)

    internal fun toFfi(): FfiReceiptHead =
        FfiReceiptHead(logId, verifierId, sequence, head.copyOf(), copyDigests(accepted), frozen)
}

/** What a valid log entry does to its log. */
public enum class LogResult {
    /** The next valid entry; persist the new head atomically. */
    APPENDED,

    /** An exact accepted body at an accepted sequence; state is unchanged. */
    REPLAY,
    ;

    internal companion object {
        fun of(f: FfiLogResult): LogResult = when (f) {
            FfiLogResult.APPENDED -> APPENDED
            FfiLogResult.REPLAY -> REPLAY
        }
    }
}

// Encoders: the canonical wire form of each object (SPEC-v2 §2).
public fun encodeDelegationCert(v: DelegationCert): ByteArray = ffi { ffiEncodeDelegationCert(v.toFfi()) }
public fun encodeProofBundle(v: ProofBundle): ByteArray = ffi { ffiEncodeProofBundle(v.toFfi()) }
public fun encodeRevocationList(v: RevocationList): ByteArray = ffi { ffiEncodeRevocationList(v.toFfi()) }
public fun encodeRevocationPush(v: RevocationPush): ByteArray = ffi { ffiEncodeRevocationPush(v.toFfi()) }
public fun encodeKeyRotationStatement(v: KeyRotationStatement): ByteArray = ffi { ffiEncodeKeyRotationStatement(v.toFfi()) }
public fun encodeWitnessEntry(v: WitnessEntry): ByteArray = ffi { ffiEncodeWitnessEntry(v.toFfi()) }
public fun encodeVerificationReceipt(v: VerificationReceipt): ByteArray = ffi { ffiEncodeVerificationReceipt(v.toFfi()) }
public fun encodeTransactionReceipt(v: TransactionReceipt): ByteArray = ffi { ffiEncodeTransactionReceipt(v.toFfi()) }

// Signature verification (SPEC-v2 §3, §5). Each throws the failure's §2.7 class.
public fun verifyDelegationCertSignature(cert: DelegationCert): Unit = ffi { ffiVerifyDelegationCertSignature(cert.toFfi()) }
public fun verifyProofBundleSignatures(bundle: ProofBundle): Unit = ffi { ffiVerifyProofBundleSignatures(bundle.toFfi()) }
public fun verifyRevocationListSignature(list: RevocationList, trustedIssuerId: String, statusKey: HybridPublicKey): Unit =
    ffi { ffiVerifyRevocationListSignature(list.toFfi(), trustedIssuerId, statusKey.toFfi()) }
public fun verifyRevocationPushSignature(push: RevocationPush, trustedIssuerId: String, statusKey: HybridPublicKey): Unit =
    ffi { ffiVerifyRevocationPushSignature(push.toFfi(), trustedIssuerId, statusKey.toFfi()) }
public fun verifyKeyRotationStatement(statement: KeyRotationStatement, state: RotationState, now: Long, futureSkew: Long): Unit =
    ffi { ffiVerifyKeyRotationStatement(statement.toFfi(), state.toFfi(), now, futureSkew) }
public fun verifyWitnessEntry(entry: WitnessEntry, head: WitnessHead, witnessKey: HybridPublicKey): LogResult =
    LogResult.of(ffi { ffiVerifyWitnessEntry(entry.toFfi(), head.toFfi(), witnessKey.toFfi()) })
public fun verifyTransactionReceiptSignatures(receipt: TransactionReceipt): Unit =
    ffi { ffiVerifyTransactionReceiptSignatures(receipt.toFfi()) }
public fun verifyVerificationReceipt(receipt: VerificationReceipt, verifierKey: HybridPublicKey, head: ReceiptHead): LogResult =
    LogResult.of(ffi { ffiVerifyVerificationReceipt(receipt.toFfi(), verifierKey.toFfi(), head.toFfi()) })
public fun checkVerificationReceiptBundleBinding(receipt: VerificationReceipt, bundle: ProofBundle): Unit =
    ffi { ffiCheckVerificationReceiptBundleBinding(receipt.toFfi(), bundle.toFfi()) }

// The signing transcript (SPEC-v2 §3).
/** The 77-byte signing message `M` over an object's signable bytes. */
public fun signingMessage(type: ObjectType, signable: ByteArray): ByteArray = ffi { ffiSigningMessage(type.code, signable) }

/** The 22-byte ML-DSA-65 context string for an object type. */
public fun mldsaContext(type: ObjectType): ByteArray = ffi { ffiMldsaContext(type.code) }

/** Verify both components of a hybrid signature over signable bytes. */
public fun verifyStatement(type: ObjectType, signable: ByteArray, signature: HybridSignature, publicKey: HybridPublicKey): Unit =
    ffi { ffiVerifyStatement(type.code, signable, signature.toFfi(), publicKey.toFfi()) }

/** The FIPS 204 external `mu` for an ML-DSA-65 public key, context and message. */
public fun externalMu(mlDsaPublicKey: ByteArray, mlDsaContext: ByteArray, message: ByteArray): ByteArray =
    ffi { ffiExternalMu(mlDsaPublicKey, mlDsaContext, message) }

// Digests (SPEC-v2 §4, §6, §7).
public fun bundleHash(bundle: ProofBundle): String = ffi { ffiBundleHash(bundle.toFfi()) }
public fun challengeClaimDigest(challenge: ByteArray): ByteArray = ffi { ffiChallengeClaimDigest(challenge) }
public fun protocolClaimId(namespace: String, replayEpoch: Long, challenge: ByteArray): String =
    ffi { ffiProtocolClaimId(namespace, replayEpoch, challenge) }
public fun verificationReceiptBody(receipt: VerificationReceipt): ByteArray = ffi { ffiVerificationReceiptBody(receipt.toFfi()) }
public fun statusEvidenceDigest(list: RevocationList): ByteArray = ffi { ffiStatusEvidenceDigestList(list.toFfi()) }
public fun statusEvidenceDigest(push: RevocationPush): ByteArray = ffi { ffiStatusEvidenceDigestPush(push.toFfi()) }
public fun keyRotationStatementDigest(statement: KeyRotationStatement): ByteArray =
    ffi { ffiKeyRotationStatementDigest(statement.toFfi()) }
public fun witnessEntryDigest(entry: WitnessEntry): ByteArray = ffi { ffiWitnessEntryDigest(entry.toFfi()) }
public fun verificationReceiptDigest(receipt: VerificationReceipt): ByteArray = ffi { ffiVerificationReceiptDigest(receipt.toFfi()) }
public fun transactionContextHash(receipt: TransactionReceipt): ByteArray = ffi { ffiTransactionContextHash(receipt.toFfi()) }
public fun transactionPartyRequestHash(transactionHash: ByteArray, requiredScope: String): ByteArray =
    ffi { ffiTransactionPartyRequestHash(transactionHash, requiredScope) }

// Signable projections (SPEC-v2 §5): the exact bytes each signature covers.
public fun delegationCertSignableBytes(v: DelegationCert): ByteArray = ffi { ffiDelegationCertSignableBytes(v.toFfi()) }
public fun presentationSignableBytes(v: ProofBundle): ByteArray = ffi { ffiPresentationSignableBytes(v.toFfi()) }
public fun revocationListSignableBytes(v: RevocationList): ByteArray = ffi { ffiRevocationListSignableBytes(v.toFfi()) }
public fun revocationPushSignableBytes(v: RevocationPush): ByteArray = ffi { ffiRevocationPushSignableBytes(v.toFfi()) }
public fun keyRotationStatementSignableBytes(v: KeyRotationStatement): ByteArray =
    ffi { ffiKeyRotationStatementSignableBytes(v.toFfi()) }
public fun witnessEntrySignableBytes(v: WitnessEntry): ByteArray = ffi { ffiWitnessEntrySignableBytes(v.toFfi()) }
public fun verificationReceiptSignableBytes(v: VerificationReceipt): ByteArray =
    ffi { ffiVerificationReceiptSignableBytes(v.toFfi()) }
public fun transactionReceiptSignBytes(v: TransactionReceipt): ByteArray = ffi { ffiTransactionReceiptSignBytes(v.toFfi()) }
