package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiChallengeClaim
import com.ratifyprotocol.internal.ffi.FfiClaimDisposition
import com.ratifyprotocol.internal.ffi.FfiClaimResult
import com.ratifyprotocol.internal.ffi.FfiClaimStore
import com.ratifyprotocol.internal.ffi.FfiCommittedClaim
import com.ratifyprotocol.internal.ffi.FfiCommittedClaimStore
import com.ratifyprotocol.internal.ffi.FfiCommittedOutcome
import com.ratifyprotocol.internal.ffi.FfiEvaluationProgress
import com.ratifyprotocol.internal.ffi.FfiInterruptedClaim
import com.ratifyprotocol.internal.ffi.FfiRateReservation
import com.ratifyprotocol.internal.ffi.FfiRateReservationStore
import com.ratifyprotocol.internal.ffi.FfiStoreContext
import com.ratifyprotocol.internal.ffi.FfiStoreException
import com.ratifyprotocol.internal.ffi.ffiResumeCommittedClaim
import com.ratifyprotocol.internal.ffi.ffiRecoverInterruptedClaim
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration

/** One signed rolling-window counter sealed into a claim. */
public class RateReservation(public val issuerId: String, public val certId: String,
    public val windowSeconds: Long, public val limit: Long) {
    internal constructor(f: FfiRateReservation) : this(f.issuerId, f.certId, f.windowS, f.limit)
    internal fun toFfi() = FfiRateReservation(issuerId, certId, windowSeconds, limit)
    override fun equals(other: Any?): Boolean = other is RateReservation &&
        issuerId == other.issuerId && certId == other.certId &&
        windowSeconds == other.windowSeconds && limit == other.limit
    override fun hashCode(): Int = listOf(issuerId, certId, windowSeconds, limit).hashCode()
}

/** Immutable values the claim store must compare on every replay. */
public class ChallengeClaim(
    public val claimId: String, public val namespace: String, public val replayEpoch: Long,
    public val challengeDigest: String, public val proofDigest: String, public val bundleHash: String,
    issuerIds: List<String>, public val requiredScope: String, public val contextPolicyDigest: String,
    public val verifierId: String, public val agentId: String, public val requiresRate: Boolean,
    rateBatch: List<RateReservation>, public val issuedAt: Long, public val expiresAt: Long,
    public val maxAgeSeconds: Long, public val clockSkewSeconds: Long, streamId: ByteArray?,
    public val streamSeq: Long?, constraintEvaluators: List<ConstraintEvaluatorRef>,
) {
    public val issuerIds: List<String> = issuerIds.toList()
    public val rateBatch: List<RateReservation> = rateBatch.toList()
    private val stream = streamId?.copyOf()
    public val streamId: ByteArray? get() = stream?.copyOf()
    public val constraintEvaluators: List<ConstraintEvaluatorRef> = constraintEvaluators.toList()

    internal constructor(f: FfiChallengeClaim) : this(f.claimId, f.namespace, f.replayEpoch,
        f.challengeDigest, f.proofDigest, f.bundleHash, f.issuerIds, f.requiredScope,
        f.contextPolicyDigest, f.verifierId, f.agentId, f.requiresRate, f.rateBatch.map(::RateReservation),
        f.issuedAt, f.expiresAt, f.maxAgeSeconds, f.clockSkewSeconds, f.streamId, f.streamSeq,
        f.constraintEvaluators.map(::ConstraintEvaluatorRef))
    internal fun toFfi() = FfiChallengeClaim(claimId, namespace, replayEpoch, challengeDigest,
        proofDigest, bundleHash, issuerIds, requiredScope, contextPolicyDigest, verifierId, agentId,
        requiresRate, rateBatch.map(RateReservation::toFfi), issuedAt, expiresAt, maxAgeSeconds,
        clockSkewSeconds, stream?.copyOf(), streamSeq, constraintEvaluators.map(ConstraintEvaluatorRef::toFfi))
    override fun equals(other: Any?): Boolean = other is ChallengeClaim &&
        claimId == other.claimId && namespace == other.namespace && replayEpoch == other.replayEpoch &&
        challengeDigest == other.challengeDigest && proofDigest == other.proofDigest &&
        bundleHash == other.bundleHash && issuerIds == other.issuerIds &&
        requiredScope == other.requiredScope && contextPolicyDigest == other.contextPolicyDigest &&
        verifierId == other.verifierId && agentId == other.agentId && requiresRate == other.requiresRate &&
        rateBatch == other.rateBatch && issuedAt == other.issuedAt && expiresAt == other.expiresAt &&
        maxAgeSeconds == other.maxAgeSeconds && clockSkewSeconds == other.clockSkewSeconds &&
        ((stream == null && other.stream == null) || (stream != null && other.stream != null && stream.contentEquals(other.stream))) &&
        streamSeq == other.streamSeq && constraintEvaluators == other.constraintEvaluators
    override fun hashCode(): Int = listOf(claimId, namespace, replayEpoch, challengeDigest,
        proofDigest, bundleHash, issuerIds, requiredScope, contextPolicyDigest, verifierId, agentId,
        requiresRate, rateBatch, issuedAt, expiresAt, maxAgeSeconds, clockSkewSeconds,
        stream?.contentHashCode(), streamSeq, constraintEvaluators).hashCode()
}

public enum class ClaimDisposition(public val spelling: String) {
    CREATED("created"), IN_PROGRESS("in_progress"), TERMINAL_REPLAY("terminal_replay")
}

private fun ClaimDisposition.toFfi(): FfiClaimDisposition = when (this) {
    ClaimDisposition.CREATED -> FfiClaimDisposition.CREATED
    ClaimDisposition.IN_PROGRESS -> FfiClaimDisposition.IN_PROGRESS
    ClaimDisposition.TERMINAL_REPLAY -> FfiClaimDisposition.TERMINAL_REPLAY
}

/** The store's atomic claim result. Only a newly created claim receives an owner token. */
public class ClaimResult(public val disposition: ClaimDisposition, public val claimedAt: Long,
    ownerToken: ByteArray) {
    private val token = ownerToken.copyOf()
    public val ownerToken: ByteArray get() = token.copyOf()
    internal constructor(f: FfiClaimResult) : this(ClaimDisposition.valueOf(f.disposition.name), f.claimedAt, f.ownerToken)
    internal fun toFfi() = FfiClaimResult(disposition.toFfi(), claimedAt, token.copyOf())
    override fun equals(other: Any?): Boolean = other is ClaimResult &&
        disposition == other.disposition && claimedAt == other.claimedAt && token.contentEquals(other.token)
    override fun hashCode(): Int = listOf(disposition, claimedAt, token.contentHashCode()).hashCode()
}

public class EvaluationProgress(public val trustAssessment: String, public val statusAssessment: String,
    public val contextAssessment: String, public val contextPolicyDigest: String?,
    statusEvidence: List<StatusEvidenceEntry>) {
    public val statusEvidence: List<StatusEvidenceEntry> = statusEvidence.toList()
    internal constructor(f: FfiEvaluationProgress) : this(f.trustAssessment, f.statusAssessment,
        f.contextAssessment, f.contextPolicyDigest, f.statusEvidence.map(::StatusEvidenceEntry))
    internal fun toFfi() = FfiEvaluationProgress(trustAssessment, statusAssessment,
        contextAssessment, contextPolicyDigest, statusEvidence.map(StatusEvidenceEntry::toFfi))
    override fun equals(other: Any?): Boolean = other is EvaluationProgress &&
        trustAssessment == other.trustAssessment && statusAssessment == other.statusAssessment &&
        contextAssessment == other.contextAssessment && contextPolicyDigest == other.contextPolicyDigest &&
        statusEvidence == other.statusEvidence
    override fun hashCode(): Int = listOf(trustAssessment, statusAssessment, contextAssessment,
        contextPolicyDigest, statusEvidence).hashCode()
}

public class InterruptedClaim(public val claim: ChallengeClaim, public val claimedAt: Long,
    public val progress: EvaluationProgress) {
    internal constructor(f: FfiInterruptedClaim) : this(ChallengeClaim(f.claim), f.claimedAt, EvaluationProgress(f.progress))
    internal fun toFfi() = FfiInterruptedClaim(claim.toFfi(), claimedAt, progress.toFfi())
}

public class CommittedClaim(public val claim: ChallengeClaim, terminalResult: ByteArray,
    receiptBody: ByteArray, public val allowHorizon: Long) {
    private val terminal = terminalResult.copyOf()
    private val body = receiptBody.copyOf()
    public val terminalResult: ByteArray get() = terminal.copyOf()
    public val receiptBody: ByteArray get() = body.copyOf()
    internal constructor(f: FfiCommittedClaim) : this(ChallengeClaim(f.claim), f.terminalResult, f.receiptBody, f.allowHorizon)
    internal fun toFfi() = FfiCommittedClaim(claim.toFfi(), terminal.copyOf(), body.copyOf(), allowHorizon)
}

/** One durable clock and atomic store for claim, progress, finalization and recovery. */
public interface ClaimStore : AuthoritativeClock {
    public suspend fun claim(claim: ChallengeClaim): ClaimResult
    public suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
        receiptBody: ByteArray, allowValidUntil: Long): Boolean
    public suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress)
    public suspend fun loadInterrupted(claimId: String): InterruptedClaim
    public suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray, receiptBody: ByteArray): Boolean
}

/** Finalization atomically admits the sealed rate batch and commits the claim.
 * RateLimitExceeded requires definitive rollback. Keep this capability active
 * for the claim's lifetime and reject legacy reservations.
 */
public interface RateAtFinalizationClaimStore : ClaimStore

/** Loads the exact terminal record when the committed handoff was lost. */
public interface CommittedClaimStore {
    public suspend fun loadCommitted(claimId: String): CommittedClaim
}

/** Reserves a sealed batch as one durable, all-or-nothing operation. */
public interface RateReservationStore {
    public suspend fun reserve(claimId: String, ownerToken: ByteArray, bundleHash: String,
        batch: List<RateReservation>)
}

internal fun claimStoreError(error: Throwable, context: FfiStoreContext): FfiStoreException = when {
    error is CancellationException && runCatching { context.isCancelled() }.getOrDefault(false) -> FfiStoreException.Cancelled()
    error is RatifyException.Internal -> FfiStoreException.Internal(error.kind.spelling, error.detail)
    error is StoreError -> error.toFfi()
    else -> FfiStoreException.Unavailable(error.toString())
}

internal class ClaimStoreBridge(private val store: ClaimStore) : FfiClaimStore {
    override fun authoritativeTime(context: FfiStoreContext): Long = try {
        callbackWait(context) { store.authoritativeTime() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun claim(claim: FfiChallengeClaim, context: FfiStoreContext): FfiClaimResult = try {
        callbackWait(context) { store.claim(ChallengeClaim(claim)).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
        receiptBody: ByteArray, allowValidUntil: Long, context: FfiStoreContext): Boolean = try {
        callbackWait(context) { store.finalize(claimId, ownerToken.copyOf(), terminalResult.copyOf(),
            receiptBody.copyOf(), allowValidUntil) }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun recordProgress(claimId: String, ownerToken: ByteArray, progress: FfiEvaluationProgress,
        context: FfiStoreContext): Unit = try {
        callbackWait(context) { store.recordProgress(claimId, ownerToken.copyOf(), EvaluationProgress(progress)) }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun loadInterrupted(claimId: String, context: FfiStoreContext): FfiInterruptedClaim = try {
        callbackWait(context) { store.loadInterrupted(claimId).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
    override fun recoverInterrupted(claimId: String, terminalResult: ByteArray, receiptBody: ByteArray,
        context: FfiStoreContext): Boolean = try {
        callbackWait(context) { store.recoverInterrupted(claimId, terminalResult.copyOf(), receiptBody.copyOf()) }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

internal class CommittedClaimStoreBridge(private val store: CommittedClaimStore) : FfiCommittedClaimStore {
    override fun loadCommitted(claimId: String, context: FfiStoreContext): FfiCommittedClaim = try {
        callbackWait(context) { store.loadCommitted(claimId).toFfi() }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

internal class RateReservationStoreBridge(private val store: RateReservationStore) : FfiRateReservationStore {
    override fun reserve(claimId: String, ownerToken: ByteArray, bundleHash: String,
        batch: List<FfiRateReservation>, context: FfiStoreContext): Unit = try {
        callbackWait(context) { store.reserve(claimId, ownerToken.copyOf(), bundleHash, batch.map(::RateReservation)) }
    } catch (e: Throwable) { throw claimStoreError(e, context) }
}

/** Non-actionable handoff; only a released decision can authorize work. */
public class CommittedOutcome internal constructor(internal val handle: FfiCommittedOutcome) {
    public val claimId: String = ffi { handle.claimId() }
    public val receiptBody: ByteArray get() = ffi { handle.receiptBody() }.copyOf()
    public val receiptBodyDigest: String = ffi { handle.receiptBodyDigest() }
    public val challengeExpiresAt: Long = ffi { handle.challengeExpiresAt() }
    public val allowHorizon: Long? = ffi { handle.allowHorizon() }
}

public suspend fun resumeCommittedClaim(store: CommittedClaimStore, claimId: String,
    timeout: Duration? = null): CommittedOutcome = onWorker(timeout) { token ->
    CommittedOutcome(ffi { ffiResumeCommittedClaim(CommittedClaimStoreBridge(store), token, claimId) })
}

/** Recovers an expired evaluator lease into a non-actionable committed handoff. */
public suspend fun recoverInterruptedClaim(store: ClaimStore, claimId: String,
    timeout: Duration? = null): CommittedOutcome = onWorker(timeout) { token ->
    CommittedOutcome(ffi { ffiRecoverInterruptedClaim(ClaimStoreBridge(store), token, claimId) })
}
