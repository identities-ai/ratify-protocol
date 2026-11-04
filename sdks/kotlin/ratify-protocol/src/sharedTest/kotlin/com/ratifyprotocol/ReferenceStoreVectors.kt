package com.ratifyprotocol

import com.ratifyprotocol.testing.Store

/** The reference store's clone is independent while preserving the snapshot clock. */
object ReferenceStoreVectors {
    fun clockAndClone() {
        val key = SoftwarePrivateKey.fromSeeds(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val store = Store(100, 5, "a".repeat(32), key)
        check(store.now() == 100L)
        store.setTime(101)
        val copy = store.cloneStore()
        check(copy.now() == 101L)
        copy.setTime(200)
        check(store.now() == 101L)
        check(copy.now() == 200L)
        check(store.logLength() == 0UL)
        check(store.abandonPendingReceipts().isEmpty())
        try {
            Store(100, 0, "a".repeat(32), key)
            error("zero lease was accepted")
        } catch (e: RatifyException) {
            check(e.errorClass == ErrorClass.CONFIGURATION_INVALID)
        }
    }
}
