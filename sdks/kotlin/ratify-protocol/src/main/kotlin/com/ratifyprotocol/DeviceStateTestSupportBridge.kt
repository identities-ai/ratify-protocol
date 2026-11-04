package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.ffiDeviceStateProjectionTestOnly

/** Bridge for the separate testing artifact; not an application API. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class DeviceStateProjectionBridge private constructor(
    public val claims: ByteArray,
    public val streams: ByteArray,
    public val rateCounters: ByteArray,
    public val receiptLog: ByteArray,
    public val issuanceRecords: ByteArray,
    public val projection: ByteArray,
    public val completeStateDigest: ByteArray,
) {
    public companion object {
        @RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
        public fun fromRecordsTestOnly(stateJson: ByteArray): DeviceStateProjectionBridge {
            val value = ffi { ffiDeviceStateProjectionTestOnly(stateJson) }
            return DeviceStateProjectionBridge(
                value.claims, value.streams, value.rateCounters, value.receiptLog,
                value.issuanceRecords, value.projection, value.completeStateDigest,
            )
        }
    }
}
