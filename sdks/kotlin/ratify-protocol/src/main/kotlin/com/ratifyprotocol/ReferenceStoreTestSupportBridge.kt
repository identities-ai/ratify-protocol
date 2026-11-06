package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.FfiReferenceStore
import com.ratifyprotocol.internal.ffi.FfiReferenceStoreReply
import com.ratifyprotocol.internal.ffi.FfiReferenceStoreFailure
import com.ratifyprotocol.internal.ffi.ffiForgedCommittedOutcomeTestOnly

internal fun referenceStoreError(failure: FfiReferenceStoreFailure): Throwable = when (failure.kind) {
    "classified" -> StoreError.Classified(
        ErrorClass.fromSpelling(failure.`class`)
            ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "unknown reference store error class"),
        failure.detail)
    "unavailable" -> StoreError.Unavailable(failure.detail)
    "claim_proof_conflict" -> StoreError.ClaimProofConflict()
    "rate_limit_exceeded" -> StoreError.RateLimitExceeded()
    "release_state_mismatch" -> StoreError.ReleaseStateMismatch()
    "acknowledgement_not_found" -> StoreError.AcknowledgementNotFound()
    "challenge_issuance_conflict" -> StoreError.ChallengeIssuanceConflict()
    "challenge_issuance_not_found" -> StoreError.ChallengeIssuanceNotFound()
    else -> RatifyException.Internal(InternalErrorKind.PANIC, "unknown reference store failure kind")
}

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class ReferenceStoreBridge internal constructor(internal val handle: FfiReferenceStore) {
    public companion object {
        public fun forgedCommittedOutcomeTestOnly(): CommittedOutcome =
            CommittedOutcome(ffi { ffiForgedCommittedOutcomeTestOnly() })
    }
    public constructor(now: Long, leaseSeconds: Long, logId: String, verifierKey: SoftwarePrivateKey) :
        this(ffi { FfiReferenceStore(now, leaseSeconds, logId, verifierKey.handle) })

    public fun cloneStore(): ReferenceStoreBridge = ReferenceStoreBridge(ffi { handle.cloneStore() })
    public fun enableRateAtFinalization(): Unit = ffi { handle.enableRateAtFinalization() }
    public fun setTime(now: Long): Unit = ffi { handle.setTime(now) }
    public fun now(): Long = ffi { handle.now() }
    public fun setSignerFailure(failing: Boolean): Unit = ffi { handle.setSignerFailure(failing) }
    public fun setAcknowledgementWithheld(withheld: Boolean): Unit = ffi { handle.setAcknowledgementWithheld(withheld) }
    public fun logLength(): ULong = ffi { handle.logLength() }
    public fun plantReleaseTestOnly(claimId: String, ackTimestamp: Long): Unit = ffi { handle.plantReleaseTestOnly(claimId, ackTimestamp) }
    public fun corruptSealedStateTestOnly(claimId: String): Unit = ffi { handle.corruptSealedStateTestOnly(claimId) }
    public fun abandonPendingReceipts(): List<String> = ffi { handle.abandonPendingReceipts() }

    private fun check(reply: FfiReferenceStoreReply) {
        val failure = reply.failure ?: return
        throw referenceStoreError(failure)
    }

    private fun <T : Any> value(reply: FfiReferenceStoreReply, field: (FfiReferenceStoreReply) -> T?): T {
        check(reply)
        return field(reply) ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "reference store omitted a success value")
    }

    public fun authoritativeTime(): Long = value(ffi { handle.authoritativeTime() }) { it.time }
    public fun claim(claim: ChallengeClaim): ClaimResult = ClaimResult(value(ffi { handle.claim(claim.toFfi()) }) { it.claim })
    public fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
        receiptBody: ByteArray, allowValidUntil: Long): Boolean =
        value(ffi { handle.finalize(claimId, ownerToken, terminalResult, receiptBody, allowValidUntil) }) { it.boolean }
    public fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress): Unit =
        check(ffi { handle.recordProgress(claimId, ownerToken, progress.toFfi()) })
    public fun loadInterrupted(claimId: String): InterruptedClaim =
        InterruptedClaim(value(ffi { handle.loadInterrupted(claimId) }) { it.interrupted })
    public fun recoverInterrupted(claimId: String, terminalResult: ByteArray, receiptBody: ByteArray): Boolean =
        value(ffi { handle.recoverInterrupted(claimId, terminalResult, receiptBody) }) { it.boolean }

    public fun loadCommitted(claimId: String): CommittedClaim =
        CommittedClaim(value(ffi { handle.loadCommitted(claimId) }) { it.committed })
    public fun loadTerminal(claimId: String): TerminalClaimRecord =
        TerminalClaimRecord(value(ffi { handle.loadTerminal(claimId) }) { it.terminal })
    public fun recordRelease(record: ReleaseRecord): Unit = check(ffi { handle.recordRelease(record.toFfi()) })
    public fun publish(claimId: String, receiptBody: ByteArray): ByteArray =
        value(ffi { handle.publishReceipt(claimId, receiptBody) }) { it.receipt }.copyOf()
    public fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray): CheckpointAcknowledgement = CheckpointAcknowledgement(value(ffi {
        handle.acknowledgeReceipt(logId, sequence, previousEntryHash, entryHash)
    }) { it.acknowledgement })
    public fun get(logId: String, sequence: Long): CheckpointAcknowledgement =
        CheckpointAcknowledgement(value(ffi { handle.getAcknowledgement(logId, sequence) }) { it.acknowledgement })
}
