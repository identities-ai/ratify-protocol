package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiStatusObservation
import com.ratifyprotocol.internal.ffi.FfiStatusPolicy
import com.ratifyprotocol.internal.ffi.FfiStatusState
import com.ratifyprotocol.internal.ffi.ffiApplyRevocationList
import com.ratifyprotocol.internal.ffi.ffiApplyRevocationPush
import com.ratifyprotocol.internal.ffi.ffiEmptyStatusState
import com.ratifyprotocol.internal.ffi.ffiProtocolClaimIdFromDigest
import com.ratifyprotocol.internal.ffi.ffiRevocationStatusForCert
import com.ratifyprotocol.internal.ffi.ffiTransitionRevocationStatusEpoch
import java.util.Collections

/** The relying party's freshness policy for status evidence. */
public class RevocationStatusPolicy(
    public val maxListLifetimeSeconds: Long,
    public val maxStatusAgeSeconds: Long,
    public val clockSkewSeconds: Long,
) {
    internal fun toFfi() = FfiStatusPolicy(maxListLifetimeSeconds, maxStatusAgeSeconds, clockSkewSeconds)
}

/** One status object the reducer observed. */
public class RevocationObservation internal constructor(private val f: FfiStatusObservation) {
    public val objectType: UShort = f.objectType
    public val statusKeyEpoch: ULong = f.statusKeyEpoch
    public val statusKeyId: String = f.statusKeyId
    public val sequence: Long = f.sequence
    public val evidenceDigest: ByteArray get() = f.evidenceDigest.copyOf()
    public val bodyDigest: ByteArray get() = f.bodyDigest.copyOf()
    public val revokedSetDigest: ByteArray get() = f.revokedSetDigest.copyOf()
    public val revokedCertIds: List<String> = Collections.unmodifiableList(ArrayList(f.revokedCertIds))
    public val futureDated: Boolean = f.futureDated
    public val fork: Boolean = f.fork
    public val gap: Boolean = f.gap
    public val accepted: Boolean = f.accepted
}

/**
 * Caller-persisted revocation status state for one issuer (SPEC-v2 §6.6).
 * Start from [emptyRevocationStatusState] and persist each result. Opaque
 * to callers except for its read-only fields.
 */
public class RevocationStatusState internal constructor(internal val f: FfiStatusState) {
    public val issuerId: String get() = f.issuerId
    public val statusKeyEpoch: ULong get() = f.statusKeyEpoch
    public val statusKeyId: String get() = f.statusKeyId
    public val retiredStatusKeyIds: List<String> get() = Collections.unmodifiableList(ArrayList(f.retiredStatusKeyIds))
    public val hasFloor: Boolean get() = f.hasFloor
    public val floor: Long get() = f.floor
    public val acceptedSnapshot: RevocationList? get() = f.acceptedSnapshot?.let { RevocationList(it) }
    public val acceptedCertIds: List<String> get() = Collections.unmodifiableList(ArrayList(f.acceptedCertIds))
    public val hasPrecedingCheckpoint: Boolean get() = f.hasPrecedingCheckpoint
    public val precedingFloor: Long get() = f.precedingFloor
    public val precedingAcceptedCertIds: List<String> get() = Collections.unmodifiableList(ArrayList(f.precedingAcceptedCertIds))
    public val denyUnionCertIds: List<String> get() = Collections.unmodifiableList(ArrayList(f.denyUnionCertIds))
    public val observations: List<RevocationObservation> get() = f.observations.map { RevocationObservation(it) }
    public val maxObservedSequence: Long get() = f.maxObservedSequence
    public val forkSequence: Long get() = f.forkSequence
    public val reconciliationRequired: Boolean get() = f.reconciliationRequired
    public val futureDatedObjectObserved: Boolean get() = f.futureDatedObjectObserved
}

/** A certificate's revocation status. */
public class RevocationStatusResult internal constructor(
    /** "not_revoked", "revoked", or "indeterminate". */
    public val status: String,
    /** "" or, for indeterminate, "unavailable" / "stale". */
    public val reason: String,
    evidence: List<StatusEvidenceEntry>,
    public val freshUntil: Long,
) {
    public val evidence: List<StatusEvidenceEntry> = Collections.unmodifiableList(ArrayList(evidence))
}

public fun emptyRevocationStatusState(): RevocationStatusState = RevocationStatusState(ffi { ffiEmptyStatusState() })

public fun applyRevocationList(
    state: RevocationStatusState, list: RevocationList, boundIssuerId: String, statusKeyEpoch: ULong,
    statusKey: HybridPublicKey, policy: RevocationStatusPolicy, now: Long,
): RevocationStatusState = RevocationStatusState(ffi {
    ffiApplyRevocationList(state.f, list.toFfi(), boundIssuerId, statusKeyEpoch, statusKey.toFfi(), policy.toFfi(), now)
})

public fun applyRevocationPush(
    state: RevocationStatusState, push: RevocationPush, boundIssuerId: String, statusKeyEpoch: ULong,
    statusKey: HybridPublicKey, policy: RevocationStatusPolicy, now: Long,
): RevocationStatusState = RevocationStatusState(ffi {
    ffiApplyRevocationPush(state.f, push.toFfi(), boundIssuerId, statusKeyEpoch, statusKey.toFfi(), policy.toFfi(), now)
})

public fun transitionRevocationStatusEpoch(
    state: RevocationStatusState, issuerId: String, nextEpoch: ULong, nextStatusKey: HybridPublicKey,
): RevocationStatusState = RevocationStatusState(ffi { ffiTransitionRevocationStatusEpoch(state.f, issuerId, nextEpoch, nextStatusKey.toFfi()) })

public fun revocationStatusForCert(
    state: RevocationStatusState, issuerId: String, certId: String, statusKeyEpoch: ULong,
    statusKey: HybridPublicKey, policy: RevocationStatusPolicy, now: Long,
): RevocationStatusResult {
    val r = ffi { ffiRevocationStatusForCert(state.f, issuerId, certId, statusKeyEpoch, statusKey.toFfi(), policy.toFfi(), now) }
    return RevocationStatusResult(r.status, r.reason, r.evidence.map { StatusEvidenceEntry(it) }, r.freshUntil)
}

/** The claim ID from a precomputed challenge claim digest. */
public fun protocolClaimIdFromDigest(namespace: String, replayEpoch: Long, digest: ByteArray): String =
    ffi { ffiProtocolClaimIdFromDigest(namespace, replayEpoch, digest) }
