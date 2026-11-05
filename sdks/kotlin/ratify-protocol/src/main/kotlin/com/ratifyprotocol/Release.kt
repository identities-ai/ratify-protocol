package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiCheckpointAcknowledgement
import com.ratifyprotocol.internal.ffi.FfiReceiptCheckpoint
import com.ratifyprotocol.internal.ffi.FfiReceiptPublisher
import com.ratifyprotocol.internal.ffi.FfiReleaseClaimStore
import com.ratifyprotocol.internal.ffi.FfiReleaseRecord
import com.ratifyprotocol.internal.ffi.FfiReleaseResult
import com.ratifyprotocol.internal.ffi.FfiReleasedDecision
import com.ratifyprotocol.internal.ffi.FfiStoreContext
import com.ratifyprotocol.internal.ffi.FfiTerminalClaimRecord
import com.ratifyprotocol.internal.ffi.ffiPublishReceipt
import com.ratifyprotocol.internal.ffi.ffiReleaseDecision
import com.ratifyprotocol.internal.ffi.ffiReceiptOutboxDigest
import com.ratifyprotocol.internal.ffi.ffiValidReleaseRecordOutcome
import kotlin.time.Duration

public enum class ReleaseStatus(public val spelling: String) {
    RELEASED("released"), PENDING("pending"), WITHHELD("withheld"), REJECTED("rejected")
}

public fun receiptOutboxDigest(body: ByteArray): String = ffi { ffiReceiptOutboxDigest(body.copyOf()) }
public fun validReleaseRecordOutcome(outcome: ReleaseStatus, reason: String): Boolean =
    ffi { ffiValidReleaseRecordOutcome(outcome.spelling, reason) }

public class ReleaseRecord(
    public val claimId: String, entryHash: ByteArray, public val ackTimestamp: Long,
    public val outcome: ReleaseStatus, public val reason: String,
) {
    private val hash = entryHash.copyOf()
    public val entryHash: ByteArray get() = hash.copyOf()
    internal constructor(f: FfiReleaseRecord) : this(f.claimId, f.entryHash, f.ackTimestamp,
        ReleaseStatus.entries.single { it.spelling == f.outcome }, f.reason)
    internal fun toFfi() = FfiReleaseRecord(claimId, hash.copyOf(), ackTimestamp, outcome.spelling, reason)
}

public class TerminalClaimRecord(
    public val terminal: Boolean, public val receiptOutboxDigest: String,
    public val challengeExpiresAt: Long, public val allowHorizon: Long,
    public val finalizedAt: Long, public val receiptAbandoned: Boolean,
    public val release: ReleaseRecord?,
) {
    internal constructor(f: FfiTerminalClaimRecord) : this(f.terminal, f.receiptOutboxDigest,
        f.challengeExpiresAt, f.allowHorizon, f.finalizedAt, f.receiptAbandoned,
        f.release?.let(::ReleaseRecord))
    internal fun toFfi() = FfiTerminalClaimRecord(terminal, receiptOutboxDigest,
        challengeExpiresAt, allowHorizon, finalizedAt, receiptAbandoned, release?.toFfi())
}

public class CheckpointAcknowledgement(
    public val logId: String, public val sequence: Long, entryHash: ByteArray,
    public val timestamp: Long,
) {
    private val hash = entryHash.copyOf()
    public val entryHash: ByteArray get() = hash.copyOf()
    internal constructor(f: FfiCheckpointAcknowledgement) : this(f.logId, f.sequence, f.entryHash, f.timestamp)
    internal fun toFfi() = FfiCheckpointAcknowledgement(logId, sequence, hash.copyOf(), timestamp)
}

/** Durable terminal state and first-write-wins release record for the same claim store used by verification. */
public interface ReleaseClaimStore : AuthoritativeClock {
    public suspend fun loadTerminal(claimId: String): TerminalClaimRecord
    public suspend fun recordRelease(record: ReleaseRecord)
}

/** An independently anchored checkpoint, separate from the receipt log. */
public interface ReceiptCheckpoint {
    public suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray): CheckpointAcknowledgement
    public suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement
}

/** Signs and appends the exact committed body once, returning signed receipt wire. */
public interface ReceiptPublisher {
    public suspend fun publish(claimId: String, receiptBody: ByteArray): ByteArray
}

internal class ReleaseStoreBridge(private val store: ReleaseClaimStore) : FfiReleaseClaimStore {
    override fun authoritativeTime(context: FfiStoreContext): Long = try {
        callbackWait(context) { store.authoritativeTime() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun loadTerminal(claimId: String, context: FfiStoreContext): FfiTerminalClaimRecord = try {
        callbackWait(context) { store.loadTerminal(claimId).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun recordRelease(record: FfiReleaseRecord, context: FfiStoreContext): Unit = try {
        callbackWait(context) { store.recordRelease(ReleaseRecord(record)) }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

internal class CheckpointBridge(private val checkpoint: ReceiptCheckpoint) : FfiReceiptCheckpoint {
    override fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray, context: FfiStoreContext): FfiCheckpointAcknowledgement = try {
        callbackWait(context) { checkpoint.acknowledge(logId, sequence, previousEntryHash.copyOf(), entryHash.copyOf()).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun get(logId: String, sequence: Long, context: FfiStoreContext): FfiCheckpointAcknowledgement = try {
        callbackWait(context) { checkpoint.get(logId, sequence).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

internal class PublisherBridge(private val publisher: ReceiptPublisher) : FfiReceiptPublisher {
    override fun publish(claimId: String, receiptBody: ByteArray, context: FfiStoreContext): ByteArray = try {
        callbackWait(context) { publisher.publish(claimId, receiptBody.copyOf()).copyOf() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

/** Created only by the core release gate. Check [isAllowed] immediately before a side effect. */
public class ReleasedDecision private constructor(internal val handle: FfiReleasedDecision) {
    public val claimId: String = ffi { handle.claimId() }
    /** Receipt decision only; use [isAllowed] immediately before a side effect. */
    public val decision: String = ffi { handle.decision() }
    public val reason: String = ffi { handle.reason() }
    public val identityStatus: String = ffi { handle.identityStatus() }
    public val grantedScope: List<String> = ffi { handle.grantedScope() }.toList()
    private val wire = ffi { handle.receiptWire() }.copyOf()
    public val receiptWire: ByteArray get() = wire.copyOf()
    public val releaseTime: Long = ffi { handle.releaseTime() }
    public val challengeExpiresAt: Long = ffi { handle.challengeExpiresAt() }
    public val allowHorizon: Long? = ffi { handle.allowHorizon() }
    public fun receipt(): VerificationReceipt = VerificationReceipt(ffi { handle.receipt() })
    public suspend fun isAllowed(clock: AuthoritativeClock, timeout: Duration? = null): Boolean =
        onWorker(timeout) { token -> ffi { handle.allowed(ClockBridge(clock), token) } }
    internal companion object { fun fromHandle(handle: FfiReleasedDecision) = ReleasedDecision(handle) }
}

public class ReleaseResult internal constructor(f: FfiReleaseResult) {
    public val status: ReleaseStatus = ReleaseStatus.entries.single { it.spelling == f.status }
    public val reason: String = f.reason
    public val decision: ReleasedDecision? = f.decision?.let(ReleasedDecision::fromHandle)
}

public suspend fun publishReceipt(committed: CommittedOutcome, publisher: ReceiptPublisher,
    timeout: Duration? = null): ByteArray = onWorker(timeout) { token ->
    ffi { ffiPublishReceipt(PublisherBridge(publisher), committed.claimId, committed.receiptBody, token) }.copyOf()
}

public suspend fun releaseDecision(committed: CommittedOutcome, signedReceipt: ByteArray?,
    verifierPublicKey: HybridPublicKey, logId: String, claimStore: ReleaseClaimStore,
    checkpoint: ReceiptCheckpoint, timeout: Duration? = null): ReleaseResult = onWorker(timeout) { token ->
    ReleaseResult(ffi { ffiReleaseDecision(committed.handle, signedReceipt?.copyOf(), verifierPublicKey.toFfi(),
        logId, ReleaseStoreBridge(claimStore), CheckpointBridge(checkpoint), token) })
}
