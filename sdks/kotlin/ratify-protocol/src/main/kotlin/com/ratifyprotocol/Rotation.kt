package com.ratifyprotocol

import com.ratifyprotocol.internal.ffi.FfiRotationAcceptedEntry
import com.ratifyprotocol.internal.ffi.FfiRotationJournal
import com.ratifyprotocol.internal.ffi.FfiRotationState
import com.ratifyprotocol.internal.ffi.ffiAcceptKeyRotationStatement
import com.ratifyprotocol.internal.ffi.ffiNewKeyRotationJournal
import com.ratifyprotocol.internal.ffi.ffiRecoverKeyRotation
import java.util.Collections

/** One accepted rotation, retained for replay and fork checks. */
public class RotationAcceptedEntry(public val sequence: Long, bodyDigest: ByteArray, public val oldKey: HybridPublicKey) {
    private val digest = bodyDigest.copyOf()
    public val bodyDigest: ByteArray get() = digest.copyOf()
    internal fun toFfi() = FfiRotationAcceptedEntry(sequence, digest.copyOf(), oldKey.toFfi())
}

/**
 * Caller-persisted key-rotation continuity state for one authority (SPEC-v2
 * §5.4). Persist it atomically after every accepted statement.
 */
public class RotationJournal(public val state: RotationState, accepted: List<RotationAcceptedEntry>, public val frozen: Boolean) {
    public val accepted: List<RotationAcceptedEntry> = Collections.unmodifiableList(ArrayList(accepted))

    internal constructor(f: FfiRotationJournal) : this(
        rotationState(f.state),
        f.accepted.map { RotationAcceptedEntry(it.sequence, it.bodyDigest, HybridPublicKey(it.oldKey)) },
        f.frozen,
    )

    internal fun toFfi() = FfiRotationJournal(state.toFfi(), accepted.map { it.toFfi() }, frozen)
}

internal fun rotationState(f: FfiRotationState) =
    RotationState(f.authorityId, f.recoveryEpoch, f.role, f.sequence, f.headHash, HybridPublicKey(f.currentKey), f.usedKeyIds)

/**
 * The next journal (which can change even when the statement is refused: a
 * fork freezes it) and what the statement did: exactly one of [result] and
 * [error] is set.
 */
public class RotationAcceptance internal constructor(
    public val journal: RotationJournal,
    public val result: LogResult?,
    public val error: RatifyException.Protocol?,
)

/** The initial journal from a caller-authenticated genesis key. */
public fun newKeyRotationJournal(authorityId: String, recoveryEpoch: Long, role: String, genesisKey: HybridPublicKey): RotationJournal =
    RotationJournal(ffi { ffiNewKeyRotationJournal(authorityId, recoveryEpoch, role, genesisKey.toFfi()) })

/** Accept one rotation statement against [journal]. */
public fun acceptKeyRotationStatement(statement: KeyRotationStatement, journal: RotationJournal, now: Long, futureSkew: Long): RotationAcceptance {
    val a = ffi { ffiAcceptKeyRotationStatement(statement.toFfi(), journal.toFfi(), now, futureSkew) }
    return RotationAcceptance(
        RotationJournal(a.journal),
        a.result?.let { LogResult.of(it) },
        a.error?.let {
            RatifyException.Protocol(ErrorClass.fromSpelling(it.`class`) ?: error("unknown error class ${it.`class`}"), it.detail)
        },
    )
}

/** Start a new recovery epoch from a caller-authenticated genesis key. */
public fun recoverKeyRotation(journal: RotationJournal, newRecoveryEpoch: Long, newGenesisKey: HybridPublicKey): RotationJournal =
    RotationJournal(ffi { ffiRecoverKeyRotation(journal.toFfi(), newRecoveryEpoch, newGenesisKey.toFfi()) })
