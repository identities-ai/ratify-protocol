package com.ratifyprotocol

import com.ratifyprotocol.testing.Store
import kotlinx.coroutines.runBlocking
import org.json.JSONObject

/** The reference store's clone is independent while preserving the snapshot clock. */
object ReferenceStoreVectors {
    fun rateCountersKeepSharedCertIdsSeparateByIssuer() = runBlocking {
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors")
        val collision = vectors.first { it.getString("name") == "issuer_scoped_cert_id_collision" }
        val rates = collision.getJSONObject("expected").getJSONArray("rate_batch")
        check(rates.length() == 2)
        val issuers = (0..1).map { rates.getJSONObject(it).getString("issuer_id") }
        check(issuers[0] != issuers[1])
        check((0..1).all { rates.getJSONObject(it).getString("cert_id") == "shared-id" })
        val fixture = vectors.first { it.getString("name") == "allow_bound_context" }
        val receiptBody = fixture.getJSONObject("expected").b64("receipt_body_b64")
        val body = JSONObject(String(receiptBody))
        val terminal = """{"decision":"allow","decision_reason":"authorized","identity_status":"authorized_agent"}""".toByteArray()
        val store = Store(1_800_000_000L, 30, "a".repeat(32), Fixture.privateKey("verifier"))
        val rateStore = store.withRateAtFinalization()

        suspend fun admit(byte: Byte, issuer: String): Boolean {
            val challenge = ByteArray(32) { byte }
            val digest = "sha384:" + challengeClaimDigest(challenge).hex()
            val claim = ChallengeClaim(protocolClaimId("ns", 1, challenge), "ns", 1, digest,
                "proof-$byte", body.getString("bundle_hash"), body.getJSONArray("issuer_ids").strings(),
                body.getString("required_scope"), body.getString("context_policy_digest"),
                body.getString("verifier_id"), body.getString("agent_id"), true,
                listOf(RateReservation(issuer, "shared-id", 60, 1)), 1_799_999_990L,
                1_800_000_290L, 300, 0, null, null, emptyList())
            val created = rateStore.claim(claim)
            check(created.disposition == ClaimDisposition.CREATED)
            return rateStore.finalize(claim.claimId, created.ownerToken, terminal, receiptBody, 1_800_000_100L)
        }

        check(admit(1, issuers[0]))
        check(admit(2, issuers[1]))
        try {
            admit(3, issuers[0])
            error("an exhausted issuer counter was admitted")
        } catch (_: StoreError.RateLimitExceeded) {}
    }

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
        val claim = ChallengeClaim(protocolClaimId("test", 1, challenge), "test", 1, digest, digest, digest,
            emptyList(), "data:read", "", key.keyId, "", false, emptyList(), 90, 200, 100, 0,
            null, null, emptyList())
        val created = store.claim(claim)
        check(created.disposition == ClaimDisposition.CREATED)
        check(created.claimedAt == 100L)
        check(created.ownerToken.size == 32)
        val replay = store.claim(claim)
        check(replay.disposition == ClaimDisposition.IN_PROGRESS)
        check(replay.ownerToken.isEmpty())
        val terminal = store.loadTerminal(claim.claimId)
        check(!terminal.terminal && terminal.challengeExpiresAt == 200L)
        try {
            store.loadCommitted(claim.claimId)
            error("an evaluating claim was reported committed")
        } catch (e: StoreError.Classified) { check(e.errorClass == ErrorClass.CLAIM_LEASE_LIVE) }
        try {
            store.get("a".repeat(32), 1)
            error("a missing checkpoint was reported acknowledged")
        } catch (_: StoreError.AcknowledgementNotFound) {}
        try {
            store.publish(claim.claimId, ByteArray(0))
            error("an evaluating claim published a receipt")
        } catch (e: StoreError.Unavailable) { check(e.message?.contains("no committed outbox body") == true) }
        try {
            store.recordRelease(ReleaseRecord(claim.claimId, ByteArray(48), 100, ReleaseStatus.RELEASED, ""))
            error("an evaluating claim recorded a release")
        } catch (_: StoreError.ReleaseStateMismatch) {}
        try {
            store.loadInterrupted(claim.claimId)
            error("an unexpired evaluator lease was interrupted")
        } catch (e: StoreError.Classified) {
            check(e.errorClass == ErrorClass.CLAIM_LEASE_LIVE)
        }
        try {
            recoverInterruptedClaim(store, claim.claimId)
            error("recovery replaced an active evaluator")
        } catch (e: RatifyException.Protocol) {
            check(e.errorClass == ErrorClass.CLAIM_LEASE_LIVE)
        }
        store.setTime(106)
        val interrupted = store.loadInterrupted(claim.claimId)
        check(interrupted.claim == claim)
        check(interrupted.claimedAt == 100L)
        try {
            store.loadCommitted(claim.claimId)
            error("an expired evaluating claim was reported committed")
        } catch (e: StoreError.Classified) { check(e.errorClass == ErrorClass.CLAIM_LEASE_LOST) }
        val recovered = recoverInterruptedClaim(store, claim.claimId)
        check(org.json.JSONObject(String(recovered.receiptBody)).getString("decision_reason") == "evaluation_interrupted")
        check(store.loadCommitted(claim.claimId).receiptBody.contentEquals(recovered.receiptBody))
        check(recoverInterruptedClaim(store, claim.claimId).receiptBody.contentEquals(recovered.receiptBody))
    }
}
