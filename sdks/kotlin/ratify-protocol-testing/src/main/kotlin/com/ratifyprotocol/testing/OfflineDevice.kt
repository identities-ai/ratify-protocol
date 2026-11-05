package com.ratifyprotocol.testing

import com.ratifyprotocol.CheckpointAcknowledgement
import com.ratifyprotocol.OfflineDeviceBridge
import com.ratifyprotocol.OfflineDeviceReplyBridge
import com.ratifyprotocol.ReceiptCheckpoint

public class DeviceReply internal constructor(value: OfflineDeviceReplyBridge) {
    public val acknowledged: List<Long> = value.acknowledged
    public val ackTime: Long? = value.ackTime
    public val failure: String? = value.failure
}

/** Single-device reference checkpoint and outbox for conformance tests. */
public class OfflineDevice(store: Store, replayEpoch: Long, seed: ByteArray, capacity: UInt) : ReceiptCheckpoint {
    private val bridge = OfflineDeviceBridge(store.bridge, replayEpoch, seed, capacity)

    public fun startup(): String = bridge.startup().status ?: ""
    public fun setPowerLoss(mode: String): Unit = bridge.setPowerLoss(mode)
    public fun submitPending(): DeviceReply = DeviceReply(bridge.submitPending())
    public fun resubmit(sequence: Long): DeviceReply = DeviceReply(bridge.resubmit(sequence))
    public fun upload(): List<Long> = bridge.upload().uploaded

    override suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
        entryHash: ByteArray): CheckpointAcknowledgement =
        bridge.acknowledge(logId, sequence, previousEntryHash, entryHash).requiredAcknowledgement()
    override suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement =
        bridge.get(logId, sequence).requiredAcknowledgement()
}
