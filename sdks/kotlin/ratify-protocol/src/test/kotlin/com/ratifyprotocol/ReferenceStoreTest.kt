package com.ratifyprotocol

import org.junit.Test

public class ReferenceStoreTest {
    @Test public fun clockAndCloneHaveIndependentState() = ReferenceStoreVectors.clockAndClone()
    @Test public fun claimKeepsReferenceStoreErrorClass() = ReferenceStoreVectors.invalidClaimId()
    @Test public fun claimReplayAndLease() = ReferenceStoreVectors.claimReplayAndLease()
}
