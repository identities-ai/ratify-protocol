package com.ratifyprotocol

import com.ratifyprotocol.testing.Store
import kotlinx.coroutines.runBlocking

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
        runBlocking { check(store.authoritativeTime() == 101L) }
        store.setTime(99)
        try {
            runBlocking { store.authoritativeTime() }
            error("a regressed store clock was accepted")
        } catch (e: StoreError.Classified) {
            check(e.errorClass == ErrorClass.CLOCK_REGRESSED)
        }
        check(store.logLength() == 0UL)
        check(store.abandonPendingReceipts().isEmpty())
        try {
            Store(100, 0, "a".repeat(32), key)
            error("zero lease was accepted")
        } catch (e: RatifyException) {
            check(e.errorClass == ErrorClass.CONFIGURATION_INVALID)
        }
    }

    fun invalidClaimId() = runBlocking {
        val key = SoftwarePrivateKey.fromSeeds(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val store = Store(100, 5, "a".repeat(32), key)
        val claim = ChallengeClaim("invalid", "test", 1, "invalid", "invalid", "invalid", emptyList(),
            "", "", "", "", false, emptyList(), 90, 200, 100, 0, null, null, emptyList())
        try {
            store.claim(claim)
            error("a claim ID unrelated to its replay key was accepted")
        } catch (e: StoreError.Classified) {
            check(e.errorClass == ErrorClass.CONFIGURATION_INVALID)
        }
    }

    fun claimReplayAndLease() = runBlocking {
        val key = SoftwarePrivateKey.fromSeeds(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val store = Store(100, 5, "a".repeat(32), key)
        val challenge = ByteArray(32) { 3 }
        val digest = "sha384:" + challengeClaimDigest(challenge).hex()
        val claim = ChallengeClaim(protocolClaimId("test", 1, challenge), "test", 1, digest, "proof", "bundle",
            emptyList(), "data:read", "", key.keyId, "agent", false, emptyList(), 90, 200, 100, 0,
            null, null, emptyList())
        val created = store.claim(claim)
        check(created.disposition == ClaimDisposition.CREATED)
        check(created.claimedAt == 100L)
        check(created.ownerToken.size == 32)
        val replay = store.claim(claim)
        check(replay.disposition == ClaimDisposition.IN_PROGRESS)
        check(replay.ownerToken.isEmpty())
        try {
            store.loadInterrupted(claim.claimId)
            error("an unexpired evaluator lease was interrupted")
        } catch (e: StoreError.Classified) {
            check(e.errorClass == ErrorClass.CLAIM_LEASE_LIVE)
        }
        store.setTime(106)
        val interrupted = store.loadInterrupted(claim.claimId)
        check(interrupted.claim == claim)
        check(interrupted.claimedAt == 100L)
    }
}
