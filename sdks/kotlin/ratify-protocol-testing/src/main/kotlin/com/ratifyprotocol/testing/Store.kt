package com.ratifyprotocol.testing

import com.ratifyprotocol.ReferenceStoreBridge
import com.ratifyprotocol.SoftwarePrivateKey
import com.ratifyprotocol.ClaimStore
import com.ratifyprotocol.ChallengeClaim
import com.ratifyprotocol.ClaimResult
import com.ratifyprotocol.EvaluationProgress
import com.ratifyprotocol.InterruptedClaim

/** Rust Part B reference store for conformance tests. */
public class Store private constructor(private val bridge: ReferenceStoreBridge) : ClaimStore {
    public constructor(now: Long, leaseSeconds: Long, logId: String, verifierKey: SoftwarePrivateKey) :
        this(ReferenceStoreBridge(now, leaseSeconds, logId, verifierKey))

    public fun cloneStore(): Store = Store(bridge.cloneStore())
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
}
