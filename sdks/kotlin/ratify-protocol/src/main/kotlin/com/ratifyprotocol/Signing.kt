package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiPublicKey
import com.ratifyprotocol.internal.ffi.FfiSignContext
import com.ratifyprotocol.internal.ffi.FfiSignRequest
import com.ratifyprotocol.internal.ffi.FfiSignature
import com.ratifyprotocol.internal.ffi.FfiSigner
import com.ratifyprotocol.internal.ffi.FfiSignerException
import com.ratifyprotocol.internal.ffi.FfiSignerMode
import com.ratifyprotocol.internal.ffi.ffiSignDelegationCertWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignKeyRotationStatementWithSigners
import com.ratifyprotocol.internal.ffi.ffiSignPreparedVerificationReceiptWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignProofBundleWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignRevocationListWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignRevocationPushWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignTransactionReceiptPartyWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignVerificationReceiptWithSigner
import com.ratifyprotocol.internal.ffi.ffiSignWitnessEntryWithSigner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.cancellation.CancellationException

/** How an external signer computes its ML-DSA-65 component (SPEC-v2 §3.2). */
public enum class SignerMode {
    /** Sign `M` with the supplied 22-byte context. */
    DIRECT,

    /** Sign the supplied FIPS 204 external `mu`. */
    EXTERNAL_MU,
    ;

    internal fun toFfi(): FfiSignerMode = if (this == DIRECT) FfiSignerMode.DIRECT else FfiSignerMode.EXTERNAL_MU

    internal companion object {
        fun of(f: FfiSignerMode): SignerMode = if (f == FfiSignerMode.DIRECT) DIRECT else EXTERNAL_MU
    }
}

/**
 * What the SDK asks an external signer to sign. The SDK computed every
 * field; the signer must not substitute its own message or context.
 */
public class SignRequest internal constructor(f: FfiSignRequest) {
    public val mode: SignerMode = SignerMode.of(f.mode)
    private val m = f.message.copyOf()
    private val ctx = f.mlDsaContext?.copyOf()
    private val mu = f.mlDsaMu?.copyOf()

    /** The 77-byte signing message `M`; the Ed25519 component signs it. */
    public val message: ByteArray get() = m.copyOf()

    /** The 22-byte ML-DSA-65 context, in direct mode. */
    public val mlDsaContext: ByteArray? get() = ctx?.copyOf()

    /** The external `mu`, in external-mu mode. */
    public val mlDsaMu: ByteArray? get() = mu?.copyOf()
    public val publicKey: HybridPublicKey = HybridPublicKey(f.publicKey)
    public val keyId: String = f.keyId
}

/**
 * An app-held key (an HSM, KMS or remote service the app already controls)
 * that signs SDK-computed requests. The SDK verifies both returned
 * components before using them. Coroutine cancellation is how the SDK asks
 * the signer to stop; throwing [CancellationException] reports that it did.
 */
public interface ExternalSigner {
    public val publicKey: HybridPublicKey
    public val mode: SignerMode
    public suspend fun sign(request: SignRequest): HybridSignature
}

/**
 * Runs a suspending [ExternalSigner] from a blocked SDK worker thread: the
 * signer runs as a coroutine on Dispatchers.Default (never an SDK thread),
 * and the call's cancellation cancels that coroutine.
 */
internal class SignerBridge(private val signer: ExternalSigner) : FfiSigner {
    override fun publicKey(): FfiPublicKey = signer.publicKey.toFfi()
    override fun mode(): FfiSignerMode = signer.mode.toFfi()

    override fun sign(request: FfiSignRequest, context: FfiSignContext): FfiSignature {
        val req = SignRequest(request)
        val result = runCatching {
            runBlocking {
                val job = CoroutineScope(Dispatchers.Default).async { signer.sign(req) }
                val watcher = launch(Dispatchers.Default) {
                    while (isActive && !job.isCompleted) {
                        if (runCatching { context.isCancelled() }.getOrDefault(false)) {
                            job.cancel()
                            break
                        }
                        delay(5)
                    }
                }
                try {
                    job.await()
                } finally {
                    watcher.cancel()
                }
            }
        }
        return result.fold(
            onSuccess = { it.toFfi() },
            onFailure = { e ->
                throw if (e is CancellationException) FfiSignerException.Cancelled() else FfiSignerException.Provider(e.toString())
            },
        )
    }
}

/** Why a signing call refused or failed (SPEC-v2 §3.2); each maps to one §2.7 class. */
public enum class SigningErrorKind(public val spelling: String) {
    /** The object fails its schema, bounds or encoding. */
    INVALID_OBJECT("invalid_object"),

    /** An issuer duty (SPEC-v2 §5.1, §5.4) refuses the object. */
    ISSUER_DUTY("issuer_duty"),

    /** The signer's key is not the key the object names for this role. */
    KEY_BINDING("key_binding"),

    /** The signer reported an invalid public key or private key material. */
    INVALID_SIGNER_KEY("invalid_signer_key"),

    /** The signer reported a mode the SDK does not implement. */
    UNSUPPORTED_MODE("unsupported_mode"),

    /** The provider failed or refused. */
    PROVIDER("provider"),

    /** The call was cancelled; any late signature was discarded. */
    CANCELLED("cancelled"),

    /** The provider's signature does not verify over the SDK's message. */
    SIGNATURE_REJECTED("signature_rejected"),
}

// Typed signing with a software key (synchronous; no callbacks).
public fun signDelegationCert(cert: DelegationCert, key: SoftwarePrivateKey): DelegationCert =
    DelegationCert(ffi { key.handle.signDelegationCert(cert.toFfi()) })
public fun signProofBundle(bundle: ProofBundle, key: SoftwarePrivateKey): ProofBundle =
    ProofBundle(ffi { key.handle.signProofBundle(bundle.toFfi()) })
public fun signRevocationList(list: RevocationList, boundIssuerId: String, boundStatusKey: HybridPublicKey, key: SoftwarePrivateKey): RevocationList =
    RevocationList(ffi { key.handle.signRevocationList(list.toFfi(), boundIssuerId, boundStatusKey.toFfi()) })
public fun signRevocationPush(push: RevocationPush, boundIssuerId: String, boundStatusKey: HybridPublicKey, key: SoftwarePrivateKey): RevocationPush =
    RevocationPush(ffi { key.handle.signRevocationPush(push.toFfi(), boundIssuerId, boundStatusKey.toFfi()) })

/** The old key signs the authorization; the new key signs the proof of possession. */
public fun signKeyRotationStatement(statement: KeyRotationStatement, oldKey: SoftwarePrivateKey, newKey: SoftwarePrivateKey): KeyRotationStatement =
    KeyRotationStatement(ffi { oldKey.handle.signKeyRotationStatement(statement.toFfi(), newKey.handle) })
public fun signWitnessEntry(entry: WitnessEntry, key: SoftwarePrivateKey): WitnessEntry =
    WitnessEntry(ffi { key.handle.signWitnessEntry(entry.toFfi()) })
public fun signVerificationReceipt(receipt: VerificationReceipt, key: SoftwarePrivateKey): VerificationReceipt =
    VerificationReceipt(ffi { key.handle.signVerificationReceipt(receipt.toFfi()) })
public fun signPreparedVerificationReceipt(data: ByteArray, head: ReceiptHead, key: SoftwarePrivateKey): VerificationReceipt =
    VerificationReceipt(ffi { key.handle.signPreparedVerificationReceipt(data.copyOf(), head.toFfi()) })
public fun signTransactionReceiptParty(receipt: TransactionReceipt, partyId: String, key: SoftwarePrivateKey): TransactionReceiptSignature =
    TransactionReceiptSignature(ffi { key.handle.signTransactionReceiptParty(receipt.toFfi(), partyId) })

// Typed signing with an external signer (suspending; the signer may be remote).
public suspend fun signDelegationCert(cert: DelegationCert, signer: ExternalSigner): DelegationCert {
    val c = cert.toFfi()
    val s = SignerBridge(signer)
    return DelegationCert(onWorker { t -> ffi { ffiSignDelegationCertWithSigner(t, c, s) } })
}
public suspend fun signProofBundle(bundle: ProofBundle, signer: ExternalSigner): ProofBundle {
    val b = bundle.toFfi()
    val s = SignerBridge(signer)
    return ProofBundle(onWorker { t -> ffi { ffiSignProofBundleWithSigner(t, b, s) } })
}
public suspend fun signRevocationList(list: RevocationList, boundIssuerId: String, boundStatusKey: HybridPublicKey, signer: ExternalSigner): RevocationList {
    val l = list.toFfi()
    val k = boundStatusKey.toFfi()
    val s = SignerBridge(signer)
    return RevocationList(onWorker { t -> ffi { ffiSignRevocationListWithSigner(t, l, boundIssuerId, k, s) } })
}
public suspend fun signRevocationPush(push: RevocationPush, boundIssuerId: String, boundStatusKey: HybridPublicKey, signer: ExternalSigner): RevocationPush {
    val p = push.toFfi()
    val k = boundStatusKey.toFfi()
    val s = SignerBridge(signer)
    return RevocationPush(onWorker { t -> ffi { ffiSignRevocationPushWithSigner(t, p, boundIssuerId, k, s) } })
}
public suspend fun signKeyRotationStatement(statement: KeyRotationStatement, oldSigner: ExternalSigner, newSigner: ExternalSigner): KeyRotationStatement {
    val st = statement.toFfi()
    val o = SignerBridge(oldSigner)
    val n = SignerBridge(newSigner)
    return KeyRotationStatement(onWorker { t -> ffi { ffiSignKeyRotationStatementWithSigners(t, st, o, n) } })
}
public suspend fun signWitnessEntry(entry: WitnessEntry, signer: ExternalSigner): WitnessEntry {
    val e = entry.toFfi()
    val s = SignerBridge(signer)
    return WitnessEntry(onWorker { t -> ffi { ffiSignWitnessEntryWithSigner(t, e, s) } })
}
public suspend fun signVerificationReceipt(receipt: VerificationReceipt, signer: ExternalSigner): VerificationReceipt {
    val r = receipt.toFfi()
    val s = SignerBridge(signer)
    return VerificationReceipt(onWorker { t -> ffi { ffiSignVerificationReceiptWithSigner(t, r, s) } })
}
public suspend fun signPreparedVerificationReceipt(data: ByteArray, head: ReceiptHead, signer: ExternalSigner): VerificationReceipt {
    val d = data.copyOf()
    val h = head.toFfi()
    val s = SignerBridge(signer)
    return VerificationReceipt(onWorker { t -> ffi { ffiSignPreparedVerificationReceiptWithSigner(t, d, h, s) } })
}
public suspend fun signTransactionReceiptParty(receipt: TransactionReceipt, partyId: String, signer: ExternalSigner): TransactionReceiptSignature {
    val r = receipt.toFfi()
    val s = SignerBridge(signer)
    return TransactionReceiptSignature(onWorker { t -> ffi { ffiSignTransactionReceiptPartyWithSigner(t, r, partyId, s) } })
}
