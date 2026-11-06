package com.ratifyprotocol.testing

import com.ratifyprotocol.DeviceStateProjectionBridge

/** §7.13 projection from a reference primary. For vector tests only. */
public class DeviceStateProjection(stateJson: ByteArray) {
    private val value: DeviceStateProjectionBridge = DeviceStateProjectionBridge.fromRecordsTestOnly(stateJson)

    public val claims: ByteArray get() = value.claims
    public val streams: ByteArray get() = value.streams
    public val rateCounters: ByteArray get() = value.rateCounters
    public val receiptLog: ByteArray get() = value.receiptLog
    public val issuanceRecords: ByteArray get() = value.issuanceRecords
    public val projection: ByteArray get() = value.projection
    public val completeStateDigest: ByteArray get() = value.completeStateDigest
}
