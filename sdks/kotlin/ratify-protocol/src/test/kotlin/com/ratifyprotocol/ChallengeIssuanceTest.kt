package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Duration.Companion.milliseconds

class ChallengeIssuanceTest {
    companion object {
        @BeforeClass @JvmStatic fun setUpCorpus() {
            val root = File(System.getProperty("ratify.corpus")!!)
            Corpus.read = { File(root, it).readBytes() }
            Corpus.list = { File(root, it).list()!!.toList() }
        }
    }

    private class Clock(private val time: Long) : AuthoritativeClock {
        override suspend fun authoritativeTime(): Long = time
    }

    private class Random(private val bytes: ByteArray) : ChallengeRandomSource {
        override suspend fun fill(count: Int): ByteArray = bytes.copyOf()
    }

    private class SlowClock : AuthoritativeClock {
        override suspend fun authoritativeTime(): Long { delay(10_000); return 1_799_999_990 }
    }

    private class CancelledClock : AuthoritativeClock {
        override suspend fun authoritativeTime(): Long = throw CancellationException("inner clock cancelled")
    }

    private class CancelledRandom : ChallengeRandomSource {
        override suspend fun fill(count: Int): ByteArray = throw CancellationException("inner random cancelled")
    }

    private class CancelledStore : ChallengeIssuanceStore {
        override suspend fun persist(record: ExpectedChallenge): Unit = throw CancellationException("inner store cancelled")
        override suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge =
            throw StoreError.ChallengeIssuanceNotFound()
    }

    private class SlowRandom : ChallengeRandomSource {
        override suspend fun fill(count: Int): ByteArray { delay(10_000); return ByteArray(count) { 0x11 } }
    }

    private class SlowStore : ChallengeIssuanceStore {
        override suspend fun persist(record: ExpectedChallenge) { delay(10_000) }
        override suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge =
            throw StoreError.ChallengeIssuanceNotFound()
    }

    private class ReenteringRandom(private val request: ChallengeIssueRequest) : ChallengeRandomSource {
        val calls = AtomicInteger()
        private val innerStore = Store()
        override suspend fun fill(count: Int): ByteArray = if (calls.incrementAndGet() == 1) {
            issueChallenge(request, Clock(1_799_999_990), innerStore, this, 3.seconds)
            ByteArray(count) { 0x22 }
        } else ByteArray(count) { 0x11 }
    }

    private class CountingRandom : ChallengeRandomSource {
        val calls = AtomicInteger()
        override suspend fun fill(count: Int): ByteArray {
            val value = calls.incrementAndGet().toByte()
            return ByteArray(count) { value }
        }
    }

    private class ConflictStore : ChallengeIssuanceStore {
        override suspend fun persist(record: ExpectedChallenge) { throw StoreError.ChallengeIssuanceConflict() }
        override suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge =
            throw StoreError.ChallengeIssuanceNotFound()
    }

    private class Store(private val failAfterCommit: Boolean = false) : ChallengeIssuanceStore {
        private var record: ExpectedChallenge? = null
        override suspend fun persist(record: ExpectedChallenge) {
            synchronized(this) {
                if (this.record != null) throw StoreError.ChallengeIssuanceConflict()
                this.record = record
                if (failAfterCommit) throw StoreError.Unavailable("commit acknowledgement lost")
            }
        }
        override suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge =
            synchronized(this) {
                val record = this.record ?: throw StoreError.ChallengeIssuanceNotFound()
                if (record.verifierNamespace != namespace || record.replayEpoch != replayEpoch ||
                    !challengeClaimDigest(record.value).contentEquals(claimDigest)) throw StoreError.ChallengeIssuanceNotFound()
                record
            }
    }

    @Test fun challengeIssuanceCorpusAllSteps() = ChallengeIssuanceVectors.run()

    @Test fun issuePersistsBeforeExposureAndLoadsByDigest() = runBlocking {
        val step = Corpus.load("challenge-issuance.json").arr("scenarios")[0].arr("steps")[0]
        val req = step.getJSONObject("request")
        val expect = step.getJSONObject("expect")
        val store = Store()
        val issued = issueChallenge(ChallengeIssueRequest(req.getString("verifier_namespace"), req.getLong("replay_epoch"),
            req.getString("verifier_id"), req.getLong("lifetime_seconds"),
            Fixture.keyId(req.getString("expected_agent")), Fixture.key(req.getString("expected_agent")),
            expectedSessionContext = req.b64("expected_session_context_b64")),
            Clock(step.getLong("at")), store, Random(expect.b64("challenge_b64")))
        assertTrue(issued.value.contentEquals(expect.b64("challenge_b64")))
        assertEquals(expect.getLong("issued_at"), issued.issuedAt)
        assertEquals(expect.getLong("expires_at"), issued.expiresAt)
        val loaded = loadExpectedChallenge(store, issued.verifierNamespace, issued.replayEpoch, issued.value)
        assertTrue(loaded.value.contentEquals(issued.value))
        assertEquals(issued.expectedAgentId, loaded.expectedAgentId)
    }

    @Test fun ambiguousCommitDoesNotExposeChallenge() = runBlocking {
        val store = Store(failAfterCommit = true)
        val bytes = ByteArray(32) { 0x11 }
        val request = ChallengeIssueRequest("test", 1, Fixture.keyId("verifier"), 30)
        try {
            issueChallenge(request, Clock(1_799_999_990), store, Random(bytes))
            fail("ambiguous commit exposed a challenge")
        } catch (e: RatifyException) {
            assertEquals(ErrorClass.CLAIM_STORE_UNAVAILABLE, e.errorClass)
        }
        val loaded = loadExpectedChallenge(store, "test", 1, bytes)
        assertTrue(loaded.value.contentEquals(bytes))
    }

    @Test fun randomSourceCanReenterIssuance() = runBlocking {
        val request = ChallengeIssueRequest("test", 1, Fixture.keyId("verifier"), 30)
        val random = ReenteringRandom(request)
        val outer = withTimeout(5_000) { issueChallenge(request, Clock(1_799_999_990), Store(), random, 3.seconds) }
        assertTrue(outer.value.contentEquals(ByteArray(32) { 0x22 }))
        assertEquals(2, random.calls.get())
    }

    @Test fun threeConflictsExposeNoChallenge() = runBlocking {
        val request = ChallengeIssueRequest("test", 1, Fixture.keyId("verifier"), 30)
        val random = CountingRandom()
        try {
            issueChallenge(request, Clock(1_799_999_990), ConflictStore(), random)
            fail("conflicting issuance exposed a challenge")
        } catch (e: RatifyException) {
            assertEquals(ErrorClass.CONFIGURATION_INVALID, e.errorClass)
        }
        assertEquals(3, random.calls.get())
    }

    @Test fun timeoutAtEachCallbackIsEvaluationCancelled() = runBlocking {
        val request = ChallengeIssueRequest("test", 1, Fixture.keyId("verifier"), 30)
        for (phase in 0..2) {
            val clock: AuthoritativeClock = if (phase == 0) SlowClock() else Clock(1_799_999_990)
            val store: ChallengeIssuanceStore = if (phase == 1) SlowStore() else Store()
            val random: ChallengeRandomSource = if (phase == 2) SlowRandom() else Random(ByteArray(32) { 0x11 })
            try {
                issueChallenge(request, clock, store, random, 100.toLong().milliseconds)
                fail("timeout exposed a challenge at phase $phase")
            } catch (e: RatifyException) {
                assertEquals(ErrorClass.EVALUATION_CANCELLED, e.errorClass)
            }
        }
    }

    @Test fun callbackCancellationWithoutCallCancellationIsFailure() = runBlocking {
        val request = ChallengeIssueRequest("test", 1, Fixture.keyId("verifier"), 30)
        for (phase in 0..2) {
            val clock: AuthoritativeClock = if (phase == 0) CancelledClock() else Clock(1_799_999_990)
            val store: ChallengeIssuanceStore = if (phase == 1) CancelledStore() else Store()
            val random: ChallengeRandomSource = if (phase == 2) CancelledRandom() else Random(ByteArray(32) { 0x11 })
            try {
                issueChallenge(request, clock, store, random)
                fail("callback cancellation exposed a challenge at phase $phase")
            } catch (e: RatifyException) {
                assertEquals(if (phase == 2) ErrorClass.CONFIGURATION_INVALID else ErrorClass.CLAIM_STORE_UNAVAILABLE, e.errorClass)
            }
        }
    }
}
