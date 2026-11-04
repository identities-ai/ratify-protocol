package com.ratifyprotocol.testing

import com.ratifyprotocol.ReferenceStoreBridge
import com.ratifyprotocol.SoftwarePrivateKey

/** Rust Part B reference store for conformance tests. */
public class Store private constructor(private val bridge: ReferenceStoreBridge) {
    public constructor(now: Long, leaseSeconds: Long, logId: String, verifierKey: SoftwarePrivateKey) :
        this(ReferenceStoreBridge(now, leaseSeconds, logId, verifierKey))

    public fun cloneStore(): Store = Store(bridge.cloneStore())
    public fun setTime(now: Long): Unit = bridge.setTime(now)
    public fun now(): Long = bridge.now()
    public fun setSignerFailure(failing: Boolean): Unit = bridge.setSignerFailure(failing)
    public fun setAcknowledgementWithheld(withheld: Boolean): Unit = bridge.setAcknowledgementWithheld(withheld)
    public fun logLength(): ULong = bridge.logLength()
    public fun plantReleaseTestOnly(claimId: String, ackTimestamp: Long): Unit = bridge.plantReleaseTestOnly(claimId, ackTimestamp)
    public fun abandonPendingReceipts(): List<String> = bridge.abandonPendingReceipts()
}
