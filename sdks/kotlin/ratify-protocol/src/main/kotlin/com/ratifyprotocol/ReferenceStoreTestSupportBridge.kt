package com.ratifyprotocol

import androidx.annotation.RestrictTo
import com.ratifyprotocol.internal.ffi.FfiReferenceStore

/** Bridge for the separate testing artifact. */
@RestrictTo(RestrictTo.Scope.LIBRARY_GROUP)
public class ReferenceStoreBridge private constructor(private val handle: FfiReferenceStore) {
    public constructor(now: Long, leaseSeconds: Long, logId: String, verifierKey: SoftwarePrivateKey) :
        this(ffi { FfiReferenceStore(now, leaseSeconds, logId, verifierKey.handle) })

    public fun cloneStore(): ReferenceStoreBridge = ReferenceStoreBridge(ffi { handle.cloneStore() })
    public fun setTime(now: Long): Unit = ffi { handle.setTime(now) }
    public fun now(): Long = ffi { handle.now() }
    public fun setSignerFailure(failing: Boolean): Unit = ffi { handle.setSignerFailure(failing) }
    public fun setAcknowledgementWithheld(withheld: Boolean): Unit = ffi { handle.setAcknowledgementWithheld(withheld) }
    public fun logLength(): ULong = ffi { handle.logLength() }
    public fun plantReleaseTestOnly(claimId: String, ackTimestamp: Long): Unit = ffi { handle.plantReleaseTestOnly(claimId, ackTimestamp) }
    public fun abandonPendingReceipts(): List<String> = ffi { handle.abandonPendingReceipts() }
}
