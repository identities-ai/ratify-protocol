package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiJournalHead
import com.ratifyprotocol.internal.ffi.FfiJournalContext
import com.ratifyprotocol.internal.ffi.FfiJournalSnapshot
import com.ratifyprotocol.internal.ffi.FfiJournalStore
import com.ratifyprotocol.internal.ffi.FfiJournalStoreException
import com.ratifyprotocol.internal.ffi.ffiApplyRevocationListToJournal
import com.ratifyprotocol.internal.ffi.ffiApplyRevocationPushToJournal
import com.ratifyprotocol.internal.ffi.ffiConfigureStatusKeyEpoch
import com.ratifyprotocol.internal.ffi.ffiEmptySecurityJournalSnapshot
import com.ratifyprotocol.internal.ffi.ffiRecordSecurityKeyRole
import com.ratifyprotocol.internal.ffi.ffiRevocationStatusFromJournal
import com.ratifyprotocol.internal.ffi.ffiSecurityJournalSnapshotDigest
import com.ratifyprotocol.internal.ffi.ffiMigrateSecurityJournalJson
import com.ratifyprotocol.internal.ffi.ffiValidateSecurityJournalTransition
import com.ratifyprotocol.internal.ffi.ffiValidateSecurityJournalSnapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration

/** An independently anchored journal head, persisted separately from the snapshot. */
public class SecurityJournalHead(public val generation: ULong, public val digest: String) {
    internal fun toFfi(): FfiJournalHead = FfiJournalHead(generation, digest)
    override fun equals(other: Any?): Boolean =
        other is SecurityJournalHead && generation == other.generation && digest == other.digest
    override fun hashCode(): Int = 31 * generation.hashCode() + digest.hashCode()
}

/** Canonical journal bytes and the head they were exported against. */
public class SecurityJournalSnapshot(
    snapshot: ByteArray,
    public val head: SecurityJournalHead,
) {
    private val bytes = snapshot.copyOf()
    public val snapshot: ByteArray get() = bytes.copyOf()
    internal fun toFfi(): FfiJournalSnapshot = FfiJournalSnapshot(bytes.copyOf(), head.toFfi())
    override fun equals(other: Any?): Boolean =
        other is SecurityJournalSnapshot && head == other.head && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = 31 * head.hashCode() + bytes.contentHashCode()
}

/** The head must be independently anchored; compare-and-swap advances it with the snapshot atomically. */
public interface SecurityJournalStore {
    public suspend fun load(): SecurityJournalSnapshot
    public suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot)
}

public sealed class SecurityJournalStoreError(message: String) : Exception(message) {
    public class Conflict : SecurityJournalStoreError("security journal compare-and-swap conflict")
    public class Cancelled : SecurityJournalStoreError("journal store callback cancelled")
}

internal class JournalStoreBridge(private val store: SecurityJournalStore) : FfiJournalStore {
    private fun <T> call(context: FfiJournalContext, operation: suspend () -> T): T {
        val result = runCatching {
            runBlocking {
                val job = CoroutineScope(Dispatchers.Default).async { operation() }
                val watcher = launch(Dispatchers.Default) {
                    while (isActive && !job.isCompleted) {
                        if (runCatching { context.isCancelled() }.getOrDefault(false)) {
                            job.cancel()
                            break
                        }
                        delay(5)
                    }
                }
                try { job.await() } finally { watcher.cancel() }
            }
        }
        return result.fold(
            onSuccess = { it },
            onFailure = { e ->
                throw when (e) {
                    is SecurityJournalStoreError.Conflict -> FfiJournalStoreException.Conflict()
                    is SecurityJournalStoreError.Cancelled, is CancellationException -> FfiJournalStoreException.Cancelled()
                    else -> FfiJournalStoreException.Failed(e.toString())
                }
            },
        )
    }

    override fun load(context: FfiJournalContext): FfiJournalSnapshot = call(context) { store.load().toFfi() }

    override fun compareAndSwap(expected: FfiJournalHead, next: FfiJournalSnapshot, context: FfiJournalContext): Unit =
        call(context) {
            store.compareAndSwap(
                SecurityJournalHead(expected.generation, expected.digest),
                SecurityJournalSnapshot(next.snapshot, SecurityJournalHead(next.head.generation, next.head.digest)),
            )
        }
}

public fun emptySecurityJournalSnapshot(): SecurityJournalSnapshot = ffi {
    val s = ffiEmptySecurityJournalSnapshot()
    SecurityJournalSnapshot(s.snapshot, SecurityJournalHead(s.head.generation, s.head.digest))
}

/** Rejects noncanonical bytes and a snapshot that does not match its independent head. */
public fun validateSecurityJournalSnapshot(snapshot: ByteArray, head: SecurityJournalHead): Unit =
    ffi { ffiValidateSecurityJournalSnapshot(snapshot.copyOf(), head.toFfi()) }

public fun securityJournalSnapshotDigest(snapshot: ByteArray): String =
    ffi { ffiSecurityJournalSnapshotDigest(snapshot.copyOf()) }

public fun migrateSecurityJournalJson(legacyJson: ByteArray): SecurityJournalSnapshot = ffi {
    val r = ffiMigrateSecurityJournalJson(legacyJson.copyOf())
    SecurityJournalSnapshot(r.snapshot, SecurityJournalHead(r.head.generation, r.head.digest))
}

public fun validateSecurityJournalTransition(current: SecurityJournalSnapshot, next: SecurityJournalSnapshot): Unit =
    ffi { ffiValidateSecurityJournalTransition(current.toFfi(), next.toFfi()) }

public suspend fun recordSecurityKeyRole(
    store: SecurityJournalStore, role: String, key: HybridPublicKey, timeout: Duration? = null,
): SecurityJournalSnapshot = onWorker(timeout) { token ->
    val r = ffi { ffiRecordSecurityKeyRole(JournalStoreBridge(store), token, role, key.toFfi()) }
    SecurityJournalSnapshot(r.snapshot, SecurityJournalHead(r.head.generation, r.head.digest))
}

public suspend fun configureStatusKeyEpoch(
    store: SecurityJournalStore, issuerId: String, epoch: ULong, key: HybridPublicKey, timeout: Duration? = null,
): SecurityJournalSnapshot = onWorker(timeout) { token ->
    val r = ffi { ffiConfigureStatusKeyEpoch(JournalStoreBridge(store), token, issuerId, epoch, key.toFfi()) }
    SecurityJournalSnapshot(r.snapshot, SecurityJournalHead(r.head.generation, r.head.digest))
}

public suspend fun applyRevocationListToJournal(
    store: SecurityJournalStore, list: RevocationList, issuerId: String, epoch: ULong, key: HybridPublicKey,
    policy: RevocationStatusPolicy, now: Long, timeout: Duration? = null,
): SecurityJournalSnapshot = onWorker(timeout) { token ->
    val r = ffi { ffiApplyRevocationListToJournal(JournalStoreBridge(store), token, list.toFfi(), issuerId, epoch, key.toFfi(), policy.toFfi(), now) }
    SecurityJournalSnapshot(r.snapshot, SecurityJournalHead(r.head.generation, r.head.digest))
}

public suspend fun applyRevocationPushToJournal(
    store: SecurityJournalStore, push: RevocationPush, issuerId: String, epoch: ULong, key: HybridPublicKey,
    policy: RevocationStatusPolicy, now: Long, timeout: Duration? = null,
): SecurityJournalSnapshot = onWorker(timeout) { token ->
    val r = ffi { ffiApplyRevocationPushToJournal(JournalStoreBridge(store), token, push.toFfi(), issuerId, epoch, key.toFfi(), policy.toFfi(), now) }
    SecurityJournalSnapshot(r.snapshot, SecurityJournalHead(r.head.generation, r.head.digest))
}

public suspend fun revocationStatusFromJournal(
    store: SecurityJournalStore, issuerId: String, certId: String, epoch: ULong, key: HybridPublicKey,
    policy: RevocationStatusPolicy, now: Long, timeout: Duration? = null,
): RevocationStatusResult = onWorker(timeout) { token ->
    val r = ffi { ffiRevocationStatusFromJournal(JournalStoreBridge(store), token, issuerId, certId, epoch, key.toFfi(), policy.toFfi(), now) }
    RevocationStatusResult(r.status, r.reason, r.evidence.map { StatusEvidenceEntry(it) }, r.freshUntil)
}
