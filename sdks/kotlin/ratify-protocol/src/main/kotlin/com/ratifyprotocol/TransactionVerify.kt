package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiTransactionPartyVerification
import com.ratifyprotocol.internal.ffi.FfiTransactionVerification
import com.ratifyprotocol.internal.ffi.FfiTransactionVerifyRequest
import com.ratifyprotocol.internal.ffi.ffiVerifyTransactionReceipt
import kotlin.time.Duration

/** Caller-authenticated sources for composed transaction receipt verification. */
public class TransactionVerifyRequest(
    receipt: ByteArray, public val now: Long, public val futureSkewSeconds: Long,
    statusKeys: Map<String, StatusKeyConfig>, public val statusPolicy: RevocationStatusPolicy,
) {
    private val wire = receipt.copyOf()
    private val keys = statusKeys.toMap()
    public val receipt: ByteArray get() = wire.copyOf()
    public val statusKeys: Map<String, StatusKeyConfig> get() = keys.toMap()
    internal fun toFfi() = FfiTransactionVerifyRequest(wire.copyOf(), now, futureSkewSeconds,
        keys.mapValues { it.value.toFfi() }, statusPolicy.toFfi())
}

public class TransactionPartyVerification internal constructor(f: FfiTransactionPartyVerification) {
    public val partyId: String = f.partyId
    public val agentId: String = f.agentId
    public val requiredScope: String = f.requiredScope
    public val trustAssessment: String = f.trustAssessment
    public val delegationAssessment: String = f.delegationAssessment
    public val delegationExpiresAt: Long? = f.delegationExpiresAt
    public val statusAssessment: String = f.statusAssessment
    public val scopeAssessment: String = f.scopeAssessment
    public val freshness: String = f.freshness
    public val statusEvidence: List<StatusEvidenceEntry> = f.statusEvidence.map(::StatusEvidenceEntry)
}

/** Signed authority evidence; it never authorizes an action or consumes a challenge. */
public class TransactionReceiptVerification internal constructor(f: FfiTransactionVerification) {
    public val transactionId: String = f.transactionId
    public val actionable: Boolean = f.actionable
    public val parties: List<TransactionPartyVerification> = f.parties.map(::TransactionPartyVerification)
}

public suspend fun verifyTransactionReceipt(request: TransactionVerifyRequest,
    trust: TrustProvider? = null, statusEvidence: StatusEvidenceProvider? = null,
    statusJournal: SecurityJournalStore? = null, timeout: Duration? = null): TransactionReceiptVerification =
    onWorker(timeout) { token -> TransactionReceiptVerification(ffi { ffiVerifyTransactionReceipt(
        request.toFfi(), trust?.let(::TrustProviderBridge),
        statusEvidence?.let(::StatusEvidenceProviderBridge),
        statusJournal?.let(::JournalStoreBridge), token) }) }
