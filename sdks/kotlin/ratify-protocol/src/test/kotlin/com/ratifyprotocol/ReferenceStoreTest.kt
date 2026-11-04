package com.ratifyprotocol

import org.junit.Test

public class ReferenceStoreTest {
    @Test public fun clockAndCloneHaveIndependentState() = ReferenceStoreVectors.clockAndClone()
}
