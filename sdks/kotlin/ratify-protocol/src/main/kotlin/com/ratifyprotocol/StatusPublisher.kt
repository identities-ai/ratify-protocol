package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiStatusPublisher
import com.ratifyprotocol.internal.ffi.FfiStatusPublisherState
import com.ratifyprotocol.internal.ffi.FfiStatusPublication
import com.ratifyprotocol.internal.ffi.ffiNewStatusPublisherWithKey
import com.ratifyprotocol.internal.ffi.ffiNewStatusPublisherWithSigner
import java.util.Collections
import kotlin.time.Duration

/** Persist this state durably before publishing either signed object. */
public class StatusPublisherState(
    public val issuerId: String,
    public val statusKeyId: String,
    public val sequence: Long,
    public val updatedAt: Long,
    revoked: List<String>,
) {
    public val revoked: List<String> = Collections.unmodifiableList(ArrayList(revoked))

    internal constructor(f: FfiStatusPublisherState) : this(f.issuerId, f.statusKeyId, f.sequence, f.updatedAt, f.revoked)
    internal fun toFfi(): FfiStatusPublisherState = FfiStatusPublisherState(issuerId, statusKeyId, sequence, updatedAt, revoked)
    override fun equals(other: Any?): Boolean = other is StatusPublisherState &&
        issuerId == other.issuerId && statusKeyId == other.statusKeyId && sequence == other.sequence &&
        updatedAt == other.updatedAt && revoked == other.revoked
    override fun hashCode(): Int = listOf(issuerId, statusKeyId, sequence, updatedAt, revoked).hashCode()
}

/** A transition's durable state and signed objects. Publish only after saving state. */
public class StatusPublication internal constructor(f: FfiStatusPublication) {
    public val state: StatusPublisherState = StatusPublisherState(f.state)
    public val list: RevocationList = RevocationList(f.list)
    public val push: RevocationPush? = f.push?.let(::RevocationPush)
    override fun equals(other: Any?): Boolean = other is StatusPublication &&
        state == other.state && list == other.list && push == other.push
    override fun hashCode(): Int = listOf(state, list, push).hashCode()
}

public class StatusPublisher internal constructor(private val handle: FfiStatusPublisher) {
    public val issuerId: String = ffi { handle.issuerId() }
    public val statusKey: HybridPublicKey = HybridPublicKey(ffi { handle.statusKey() })

    public suspend fun genesis(updatedAt: Long, timeout: Duration? = null): StatusPublication =
        onWorker(timeout) { token -> StatusPublication(ffi { handle.genesis(token, updatedAt) }) }

    public suspend fun heartbeat(state: StatusPublisherState, updatedAt: Long, timeout: Duration? = null): StatusPublication =
        onWorker(timeout) { token -> StatusPublication(ffi { handle.heartbeat(token, state.toFfi(), updatedAt) }) }

    public suspend fun revoke(state: StatusPublisherState, certIds: List<String>, at: Long,
                              timeout: Duration? = null): StatusPublication =
        onWorker(timeout) { token -> StatusPublication(ffi { handle.revoke(token, state.toFfi(), certIds.toList(), at) }) }
}

/** Bind a separate status key to the issuer role. Lifetime is 1..86400 seconds and within verifier policy; bad configuration is refused as configuration_invalid. */
public suspend fun newStatusPublisher(
    store: SecurityJournalStore, issuerKey: HybridPublicKey, statusKey: SoftwarePrivateKey,
    lifetimeSeconds: Long, timeout: Duration? = null,
): StatusPublisher = onWorker(timeout) { token ->
    StatusPublisher(ffi { ffiNewStatusPublisherWithKey(JournalStoreBridge(store), token, issuerKey.toFfi(), statusKey.handle, lifetimeSeconds) })
}

/** The external signer variant, with the same role and lifetime checks. */
public suspend fun newStatusPublisher(
    store: SecurityJournalStore, issuerKey: HybridPublicKey, statusSigner: ExternalSigner,
    lifetimeSeconds: Long, timeout: Duration? = null,
): StatusPublisher = onWorker(timeout) { token ->
    StatusPublisher(ffi { ffiNewStatusPublisherWithSigner(JournalStoreBridge(store), token, issuerKey.toFfi(), SignerBridge(statusSigner), lifetimeSeconds) })
}
