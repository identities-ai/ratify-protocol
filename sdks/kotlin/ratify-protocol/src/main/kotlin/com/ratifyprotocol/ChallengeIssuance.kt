package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiAuthoritativeClock
import com.ratifyprotocol.internal.ffi.FfiChallengeIssuanceStore
import com.ratifyprotocol.internal.ffi.FfiChallengeIssueRequest
import com.ratifyprotocol.internal.ffi.FfiExpectedChallenge
import com.ratifyprotocol.internal.ffi.FfiRandomException
import com.ratifyprotocol.internal.ffi.FfiRandomSource
import com.ratifyprotocol.internal.ffi.FfiStoreContext
import com.ratifyprotocol.internal.ffi.FfiStoreException
import com.ratifyprotocol.internal.ffi.ffiIssueChallenge
import com.ratifyprotocol.internal.ffi.ffiLoadExpectedChallenge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration

/** Authenticated issuance context, supplied by the verifier rather than the presenter. */
public class ChallengeIssueRequest(
    public val verifierNamespace: String,
    public val replayEpoch: Long,
    public val verifierId: String,
    public val lifetimeSeconds: Long,
    public val expectedAgentId: String = "",
    public val expectedAgentPublicKey: HybridPublicKey? = null,
    public val expectedReceiverId: String = "",
    expectedSessionContext: ByteArray? = null,
) {
    private val context = expectedSessionContext?.copyOf()
    public val expectedSessionContext: ByteArray? get() = context?.copyOf()
    internal fun toFfi() = FfiChallengeIssueRequest(verifierNamespace, replayEpoch, verifierId, lifetimeSeconds,
        expectedAgentId, expectedAgentPublicKey?.toFfi(), expectedReceiverId, context?.copyOf())
}

/** Complete durable challenge record. Persist it before exposing the challenge value. */
public class ExpectedChallenge(
    value: ByteArray,
    public val issuedAt: Long,
    public val expiresAt: Long,
    public val verifierNamespace: String,
    public val replayEpoch: Long,
    public val verifierId: String,
    public val expectedAgentId: String = "",
    public val expectedAgentPublicKey: HybridPublicKey? = null,
    public val expectedReceiverId: String = "",
    expectedSessionContext: ByteArray? = null,
    public val contextPolicy: ContextPolicy? = null,
) {
    private val bytes = value.copyOf()
    private val context = expectedSessionContext?.copyOf()
    public val value: ByteArray get() = bytes.copyOf()
    public val expectedSessionContext: ByteArray? get() = context?.copyOf()
    internal constructor(f: FfiExpectedChallenge) : this(f.value, f.issuedAt, f.expiresAt,
        f.verifierNamespace, f.replayEpoch, f.verifierId, f.expectedAgentId,
        f.expectedAgentPublicKey?.let(::HybridPublicKey), f.expectedReceiverId,
        f.expectedSessionContext, f.contextPolicy?.let(::ContextPolicy))
    internal fun toFfi() = FfiExpectedChallenge(bytes.copyOf(), issuedAt, expiresAt,
        verifierNamespace, replayEpoch, verifierId, expectedAgentId,
        expectedAgentPublicKey?.toFfi(), expectedReceiverId, context?.copyOf(), contextPolicy?.handle)
}

/** Part B store failures; conflicts and missing records have distinct cases. */
public sealed class StoreError(message: String) : Exception(message) {
    public open val errorClass: ErrorClass? get() = null
    public class Classified(override val errorClass: ErrorClass, detail: String) : StoreError(detail)
    public class Unavailable(detail: String) : StoreError(detail)
    public class ClaimProofConflict : StoreError("claim proof conflict") {
        override val errorClass: ErrorClass get() = ErrorClass.CLAIM_REPLAY
    }
    public class RateLimitExceeded : StoreError("rate limit exceeded") {
        override val errorClass: ErrorClass get() = ErrorClass.CLAIM_STORE_UNAVAILABLE
    }
    public class ReleaseStateMismatch : StoreError("release state mismatch")
    public class AcknowledgementNotFound : StoreError("acknowledgement not found")
    public class ChallengeIssuanceConflict : StoreError("challenge issuance conflict")
    public class ChallengeIssuanceNotFound : StoreError("challenge issuance not found")

    internal fun toFfi(): FfiStoreException = when (this) {
        is Classified -> FfiStoreException.Classified(errorClass.spelling, message ?: "")
        is Unavailable -> FfiStoreException.Unavailable(message ?: "")
        is ClaimProofConflict -> FfiStoreException.ClaimProofConflict()
        is RateLimitExceeded -> FfiStoreException.RateLimitExceeded()
        is ReleaseStateMismatch -> FfiStoreException.ReleaseStateMismatch()
        is AcknowledgementNotFound -> FfiStoreException.AcknowledgementNotFound()
        is ChallengeIssuanceConflict -> FfiStoreException.ChallengeIssuanceConflict()
        is ChallengeIssuanceNotFound -> FfiStoreException.ChallengeIssuanceNotFound()
    }
}

public interface AuthoritativeClock {
    public suspend fun authoritativeTime(): Long
}

/** Persist inserts atomically and durably. Load uses namespace, epoch and claim digest. */
public interface ChallengeIssuanceStore {
    public suspend fun persist(record: ExpectedChallenge)
    public suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge
}

/** Caller-controlled unpredictable bytes; return exactly count bytes. */
public interface ChallengeRandomSource {
    public suspend fun fill(count: Int): ByteArray
}

private fun <T> callbackWait(context: FfiStoreContext, operation: suspend () -> T): T = runBlocking {
    val job = CoroutineScope(Dispatchers.Default).async { operation() }
    val watcher = launch(Dispatchers.Default) {
        while (isActive && !job.isCompleted) {
            if (runCatching { context.isCancelled() }.getOrDefault(false)) { job.cancel(); break }
            delay(5)
        }
    }
    try {
        val value = job.await()
        if (context.isCancelled()) throw kotlinx.coroutines.CancellationException("challenge callback cancelled")
        value
    } finally { watcher.cancel() }
}

internal class ClockBridge(private val clock: AuthoritativeClock) : FfiAuthoritativeClock {
    override fun authoritativeTime(context: FfiStoreContext): Long = try {
        callbackWait(context) { clock.authoritativeTime() }
    } catch (e: Throwable) { throw when (e) {
        is CancellationException -> if (runCatching { context.isCancelled() }.getOrDefault(false)) FfiStoreException.Cancelled() else FfiStoreException.Unavailable(e.toString())
        is StoreError -> e.toFfi()
        else -> FfiStoreException.Unavailable(e.toString())
    } }
}

internal class ChallengeStoreBridge(private val store: ChallengeIssuanceStore) : FfiChallengeIssuanceStore {
    override fun persist(record: FfiExpectedChallenge, context: FfiStoreContext): Unit = try {
        callbackWait(context) { store.persist(ExpectedChallenge(record)) }
    } catch (e: Throwable) { throw when (e) {
        is CancellationException -> if (runCatching { context.isCancelled() }.getOrDefault(false)) FfiStoreException.Cancelled() else FfiStoreException.Unavailable(e.toString())
        is StoreError -> e.toFfi()
        else -> FfiStoreException.Unavailable(e.toString())
    } }

    override fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray,
                      context: FfiStoreContext): FfiExpectedChallenge = try {
        callbackWait(context) { store.load(namespace, replayEpoch, claimDigest.copyOf()).toFfi() }
    } catch (e: Throwable) { throw when (e) {
        is CancellationException -> if (runCatching { context.isCancelled() }.getOrDefault(false)) FfiStoreException.Cancelled() else FfiStoreException.Unavailable(e.toString())
        is StoreError -> e.toFfi()
        else -> FfiStoreException.Unavailable(e.toString())
    } }
}

internal class RandomBridge(private val source: ChallengeRandomSource) : FfiRandomSource {
    override fun fill(count: UInt, context: FfiStoreContext): ByteArray = try {
        callbackWait(context) { source.fill(count.toInt()).copyOf() }
    } catch (e: Throwable) { throw if (e is CancellationException && runCatching { context.isCancelled() }.getOrDefault(false)) FfiRandomException.Cancelled() else FfiRandomException.Failed(e.toString()) }
}

/** Return only after the complete record is durable; failures expose no challenge. */
public suspend fun issueChallenge(
    request: ChallengeIssueRequest, clock: AuthoritativeClock, store: ChallengeIssuanceStore,
    random: ChallengeRandomSource? = null, timeout: Duration? = null,
): ExpectedChallenge = onWorker(timeout) { token ->
    ExpectedChallenge(ffi { ffiIssueChallenge(ClockBridge(clock), ChallengeStoreBridge(store), random?.let(::RandomBridge), token, request.toFfi()) })
}

/** Load by claim digest; the caller still performs every pre-claim check. */
public suspend fun loadExpectedChallenge(
    store: ChallengeIssuanceStore, namespace: String, replayEpoch: Long, challenge: ByteArray,
    timeout: Duration? = null,
): ExpectedChallenge = onWorker(timeout) { token ->
    ExpectedChallenge(ffi { ffiLoadExpectedChallenge(ChallengeStoreBridge(store), token, namespace, replayEpoch, challenge.copyOf()) })
}
