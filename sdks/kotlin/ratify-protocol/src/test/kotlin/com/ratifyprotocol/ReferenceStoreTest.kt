package com.ratifyprotocol

import org.junit.Test
import org.junit.BeforeClass

public class ReferenceStoreTest {
    public companion object {
        @BeforeClass @JvmStatic public fun setUpCorpus() = CorpusSetup.configure()
    }
    @Test public fun clockAndCloneHaveIndependentState() = ReferenceStoreVectors.clockAndClone()
    @Test public fun claimKeepsReferenceStoreErrorClass() = ReferenceStoreVectors.invalidClaimId()
    @Test public fun claimReplayAndLease() = ReferenceStoreVectors.claimReplayAndLease()
    @Test public fun rateCountersKeepSharedCertIdsSeparateByIssuer() =
        ReferenceStoreVectors.rateCountersKeepSharedCertIdsSeparateByIssuer()
}
