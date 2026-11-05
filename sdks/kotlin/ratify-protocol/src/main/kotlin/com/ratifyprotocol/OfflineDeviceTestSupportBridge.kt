package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.FfiDeviceReply
import com.ratifyprotocol.internal.ffi.FfiDeviceSnapshot
import com.ratifyprotocol.internal.ffi.FfiOfflineDevice

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class OfflineDeviceReplyBridge internal constructor(value: FfiDeviceReply) {
    public val acknowledged: List<Long> = value.acknowledged
    public val uploaded: List<Long> = value.uploaded
    public val ackTime: Long? = value.ackTime
    public val status: String? = value.status
    public val failure: String? = value.failure
    private val acknowledgement = value.acknowledgement
    private val storeFailure = value.storeFailure

    public fun requiredAcknowledgement(): CheckpointAcknowledgement {
        if (storeFailure != null) throw referenceStoreError(storeFailure)
        if (failure != null) throw StoreError.Unavailable(failure)
        return CheckpointAcknowledgement(acknowledgement
            ?: throw RatifyException.Internal(InternalErrorKind.PANIC, "device omitted acknowledgement"))
    }
}

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class OfflineDeviceSnapshotBridge internal constructor(internal val handle: FfiDeviceSnapshot)

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class OfflineDeviceBridge internal constructor(private val handle: FfiOfflineDevice) {
    public constructor(store: ReferenceStoreBridge, replayEpoch: Long, seed: ByteArray, capacity: UInt) :
        this(ffi { FfiOfflineDevice(store.handle, replayEpoch, seed, capacity) })

    public fun startup(): OfflineDeviceReplyBridge = OfflineDeviceReplyBridge(ffi { handle.startup() })
    public fun snapshot(): OfflineDeviceSnapshotBridge = OfflineDeviceSnapshotBridge(ffi { handle.snapshot() })
    public fun restore(snapshot: OfflineDeviceSnapshotBridge): OfflineDeviceBridge =
        OfflineDeviceBridge(ffi { handle.restore(snapshot.handle) })
    public fun primaryStore(): ReferenceStoreBridge = ReferenceStoreBridge(ffi { handle.primaryStore() })
    public fun setPowerLoss(mode: String): Unit = ffi { handle.setPowerLoss(mode) }
    public fun submitPending(): OfflineDeviceReplyBridge = OfflineDeviceReplyBridge(ffi { handle.submitPending() })
    public fun resubmit(sequence: Long): OfflineDeviceReplyBridge = OfflineDeviceReplyBridge(ffi { handle.resubmit(sequence) })
    public fun upload(): OfflineDeviceReplyBridge = OfflineDeviceReplyBridge(ffi { handle.upload() })
    public fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray): OfflineDeviceReplyBridge = OfflineDeviceReplyBridge(ffi {
        handle.acknowledgeReceipt(logId, sequence, previousEntryHash, entryHash)
    })
    public fun get(logId: String, sequence: Long): OfflineDeviceReplyBridge =
        OfflineDeviceReplyBridge(ffi { handle.getAcknowledgement(logId, sequence) })
}
