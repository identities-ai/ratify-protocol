package com.ratifyprotocol.testing

import com.ratifyprotocol.ReferenceStoreBridge
import com.ratifyprotocol.SoftwarePrivateKey
import com.ratifyprotocol.ClaimStore
import com.ratifyprotocol.ChallengeClaim
import com.ratifyprotocol.ClaimResult
import com.ratifyprotocol.EvaluationProgress
import com.ratifyprotocol.InterruptedClaim
import com.ratifyprotocol.CommittedClaim
import com.ratifyprotocol.CommittedClaimStore
import com.ratifyprotocol.ReleaseClaimStore
import com.ratifyprotocol.ReleaseRecord
import com.ratifyprotocol.TerminalClaimRecord
import com.ratifyprotocol.ReceiptPublisher
import com.ratifyprotocol.ReceiptCheckpoint
import com.ratifyprotocol.CheckpointAcknowledgement
import com.ratifyprotocol.RateAtFinalizationClaimStore

/** Rust Part B reference store for conformance tests. */
public class Store private constructor(internal val bridge: ReferenceStoreBridge) :
    ClaimStore, CommittedClaimStore, ReleaseClaimStore, ReceiptPublisher, ReceiptCheckpoint {
    public constructor(now: Long, leaseSeconds: Long, logId: String, verifierKey: SoftwarePrivateKey) :
        this(ReferenceStoreBridge(now, leaseSeconds, logId, verifierKey))

    public fun cloneStore(): Store = Store(bridge.cloneStore())
    /** Enables rate admission on this store and returns its verifier capability view. */
    public fun withRateAtFinalization(): RateStore {
        bridge.enableRateAtFinalization()
        return RateStore(this)
    }
    public fun setTime(now: Long): Unit = bridge.setTime(now)
    public fun now(): Long = bridge.now()
    public fun setSignerFailure(failing: Boolean): Unit = bridge.setSignerFailure(failing)
    public fun setAcknowledgementWithheld(withheld: Boolean): Unit = bridge.setAcknowledgementWithheld(withheld)
    public fun logLength(): ULong = bridge.logLength()
    public fun plantReleaseTestOnly(claimId: String, ackTimestamp: Long): Unit = bridge.plantReleaseTestOnly(claimId, ackTimestamp)
    public fun abandonPendingReceipts(): List<String> = bridge.abandonPendingReceipts()

    override suspend fun authoritativeTime(): Long = bridge.authoritativeTime()
    override suspend fun claim(claim: ChallengeClaim): ClaimResult = bridge.claim(claim)
    override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
        receiptBody: ByteArray, allowValidUntil: Long): Boolean =
        bridge.finalize(claimId, ownerToken, terminalResult, receiptBody, allowValidUntil)
    override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress): Unit =
        bridge.recordProgress(claimId, ownerToken, progress)
    override suspend fun loadInterrupted(claimId: String): InterruptedClaim = bridge.loadInterrupted(claimId)
    override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray, receiptBody: ByteArray): Boolean =
        bridge.recoverInterrupted(claimId, terminalResult, receiptBody)

    override suspend fun loadCommitted(claimId: String): CommittedClaim = bridge.loadCommitted(claimId)
    override suspend fun loadTerminal(claimId: String): TerminalClaimRecord = bridge.loadTerminal(claimId)
    override suspend fun recordRelease(record: ReleaseRecord): Unit = bridge.recordRelease(record)
    override suspend fun publish(claimId: String, receiptBody: ByteArray): ByteArray = bridge.publish(claimId, receiptBody)
    override suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray): CheckpointAcknowledgement = bridge.acknowledge(logId, sequence, previousEntryHash, entryHash)
    override suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement = bridge.get(logId, sequence)
}

/** The same reference store with atomic rate admission during finalization. */
public class RateStore internal constructor(private val store: Store) : RateAtFinalizationClaimStore {
    override suspend fun authoritativeTime(): Long = store.authoritativeTime()
    override suspend fun claim(claim: ChallengeClaim): ClaimResult = store.claim(claim)
    override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
        receiptBody: ByteArray, allowValidUntil: Long): Boolean =
        store.finalize(claimId, ownerToken, terminalResult, receiptBody, allowValidUntil)
    override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress): Unit =
        store.recordProgress(claimId, ownerToken, progress)
    override suspend fun loadInterrupted(claimId: String): InterruptedClaim = store.loadInterrupted(claimId)
    override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
        receiptBody: ByteArray): Boolean = store.recoverInterrupted(claimId, terminalResult, receiptBody)
}
