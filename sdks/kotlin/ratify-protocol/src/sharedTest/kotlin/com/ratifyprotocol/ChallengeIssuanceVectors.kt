package com.ratifyprotocol

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/** Stateful challenge issuance corpus through the public SDK on host and device. */
object ChallengeIssuanceVectors {
    private class ScenarioClock(private val time: Long) : AuthoritativeClock {
        override suspend fun authoritativeTime(): Long = time
    }

    private class ScenarioStore : ChallengeIssuanceStore {
        private val records = mutableMapOf<String, ExpectedChallenge>()
        private var fault = ""
        val count: Int get() = synchronized(this) { records.size }
        fun arm(next: String) { synchronized(this) { fault = next } }
        override suspend fun persist(record: ExpectedChallenge) {
            synchronized(this) {
                val active = fault
                fault = ""
                if (active == "fail_before_commit") throw StoreError.Unavailable("before commit")
                val digest = java.util.Base64.getEncoder().encodeToString(challengeClaimDigest(record.value))
                if (records.containsKey(digest)) throw StoreError.ChallengeIssuanceConflict()
                records[digest] = record
                if (active == "fail_after_commit") throw StoreError.Unavailable("after commit")
            }
        }
        override suspend fun load(namespace: String, replayEpoch: Long, claimDigest: ByteArray): ExpectedChallenge =
            synchronized(this) {
                val record = records[java.util.Base64.getEncoder().encodeToString(claimDigest)]
                    ?: throw StoreError.ChallengeIssuanceNotFound()
                if (record.verifierNamespace != namespace || record.replayEpoch != replayEpoch)
                    throw StoreError.ChallengeIssuanceNotFound()
                record
            }
    }

    private class ScenarioClaimStore : ClaimStore {
        private val claims = mutableMapOf<String, Pair<ChallengeClaim, Long>>()
        private val finalized = mutableSetOf<String>()
        @Volatile private var now = 0L
        private var claimCalls = 0
        private var finalizeCalls = 0
        private var progressCalls = 0
        private var proofConflicts = 0
        fun snapshot(): List<Int> = synchronized(this) {
            listOf(claimCalls, finalizeCalls, progressCalls, proofConflicts)
        }
        fun setTime(value: Long) { now = value }
        override suspend fun authoritativeTime(): Long = now
        override suspend fun claim(claim: ChallengeClaim): ClaimResult = synchronized(this) {
            claimCalls++
            val existing = claims[claim.claimId]
            if (existing != null) {
                if (existing.first.proofDigest != claim.proofDigest) {
                    proofConflicts++
                    throw StoreError.ClaimProofConflict()
                }
                ClaimResult(ClaimDisposition.IN_PROGRESS, existing.second, ByteArray(0))
            } else {
                claims[claim.claimId] = claim to now
                ClaimResult(ClaimDisposition.CREATED, now, ByteArray(32) { 7 })
            }
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean = synchronized(this) {
            if (!claims.containsKey(claimId) || !ownerToken.contentEquals(ByteArray(32) { 7 }) ||
                claimId in finalized) throw StoreError.Unavailable("invalid finalization")
            finalized.add(claimId)
            finalizeCalls++
            true
        }
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress) {
            synchronized(this) {
                if (!claims.containsKey(claimId) || !ownerToken.contentEquals(ByteArray(32) { 7 }) ||
                    claimId in finalized) throw StoreError.Unavailable("invalid progress")
                progressCalls++
            }
        }
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim =
            throw StoreError.Unavailable("no interruption")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = false
    }

    private class ScenarioRandom(private val values: List<ByteArray>) : ChallengeRandomSource {
        private var index = 0
        private var attempts = 0
        private var exhausted = false
        val calls: Int get() = synchronized(this) { attempts }
        val wasExhausted: Boolean get() = synchronized(this) { exhausted }
        val available: Int get() = values.size
        override suspend fun fill(count: Int): ByteArray = synchronized(this) {
            attempts++
            if (index >= values.size) {
                exhausted = true
                throw StoreError.Unavailable("random fixture exhausted")
            }
            val value = values[index++].copyOf()
            assertEquals(count, value.size)
            value
        }
    }

    private fun assertBindings(record: ExpectedChallenge, request: ChallengeIssueRequest, label: String) {
        assertEquals(label, request.verifierNamespace, record.verifierNamespace)
        assertEquals(label, request.replayEpoch, record.replayEpoch)
        assertEquals(label, request.verifierId, record.verifierId)
        assertEquals(label, request.expectedAgentId, record.expectedAgentId)
        assertEquals(label, request.expectedAgentPublicKey, record.expectedAgentPublicKey)
        assertEquals(label, request.expectedReceiverId, record.expectedReceiverId)
        org.junit.Assert.assertArrayEquals(label, request.expectedSessionContext, record.expectedSessionContext)
    }

    private suspend fun presentIssued(wire: ByteArray, at: Long, issuance: ScenarioStore,
        claims: ScenarioClaimStore): String {
        val bundle = try { decodeProofBundle(wire) }
            catch (e: RatifyException) { return "preflight:" + (e.errorClass?.spelling ?: "internal") }
        val expected = try { loadExpectedChallenge(issuance, "verify-test", 3, bundle.challenge) }
            catch (e: RatifyException) { return "preflight:" + (e.errorClass?.spelling ?: "internal") }
        return try {
            val policy = expected.expectedSessionContext?.let {
                ContextPolicy("ratify.verify.session-context/v1", true,
                    listOf("verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash"), it)
            } ?: ContextPolicy("ratify.conformance.context-not-required/v1", false, emptyList())
            val request = VerifyRequest(wire, expected, policy, "data:read", "verify-test", 3,
                expected.verifierId, at, 300, 5, ConstraintContext(), "2025a", emptyMap(),
                RevocationStatusPolicy(300, 300, 5))
            val outcome = verifyProofBundle(request, claims)
            outcome.disposition?.spelling ?: if (outcome.errorClass == ErrorClass.CLAIM_REPLAY)
                "proof_conflict" else "preflight:" + (outcome.errorClass?.spelling ?: "internal")
        } catch (e: RatifyException) { "preflight:" + (e.errorClass?.spelling ?: "internal") }
    }

    fun run() = runBlocking {
        val scenarios = Corpus.load("challenge-issuance.json").arr("scenarios")
        assertEquals(11, scenarios.size)
        var checked = 0
        for (scenario in scenarios) {
            val name = scenario.getString("name")
            val store = ScenarioStore()
            val claims = ScenarioClaimStore()
            val random = ScenarioRandom(scenario.strings("random_b64").map(java.util.Base64.getDecoder()::decode))
            val issuedRequests = mutableMapOf<String, ChallengeIssueRequest>()
            val firstRequest = scenario.arr("steps").first { it.getString("op") == "issue" }.getJSONObject("request")
            for ((index, step) in scenario.arr("steps").withIndex()) {
                val label = "$name step $index"
                val expect = step.getJSONObject("expect")
                when (step.getString("op")) {
                    "issue" -> {
                        checked++
                        val input = step.getJSONObject("request")
                        val agent = input.getString("expected_agent")
                        val request = ChallengeIssueRequest(input.getString("verifier_namespace"),
                            input.getLong("replay_epoch"), input.getString("verifier_id"),
                            input.getLong("lifetime_seconds"), Fixture.keyId(agent), Fixture.key(agent),
                            input.opt("expected_receiver_id") as? String ?: "",
                            (input.opt("expected_session_context_b64") as? String)?.let(java.util.Base64.getDecoder()::decode))
                        store.arm(step.optString("persist_fault"))
                        try {
                            val issued = issueChallenge(request, ScenarioClock(step.getLong("at")), store, random)
                            assertEquals(label, "issued", expect.getString("result"))
                            if (expect.getString("result") == "issued") {
                                assertTrue(label, issued.value.contentEquals(expect.b64("challenge_b64")))
                                assertEquals(label, expect.getLong("issued_at"), issued.issuedAt)
                                assertEquals(label, expect.getLong("expires_at"), issued.expiresAt)
                                assertBindings(issued, request, label)
                                issuedRequests[java.util.Base64.getEncoder().encodeToString(issued.value)] = request
                            }
                        } catch (e: RatifyException) {
                            assertEquals(label + ": $e", "error", expect.getString("result"))
                            val expectedClass = if (expect.has("error_class")) expect.getString("error_class") else
                                if (step.has("persist_fault")) "claim_store_unavailable" else "configuration_invalid"
                            assertEquals(label, expectedClass, e.errorClass?.spelling)
                        }
                        assertEquals(label, expect.getInt("records_after"), store.count)
                    }
                    "load" -> {
                        checked++
                        assertTrue(label, !step.has("verifier_namespace") && !step.has("replay_epoch"))
                        try {
                            val loaded = loadExpectedChallenge(store, firstRequest.getString("verifier_namespace"),
                                firstRequest.getLong("replay_epoch"), step.b64("challenge_b64"))
                            assertEquals(label, "found", expect.getString("result"))
                            if (expect.getString("result") == "found") {
                                assertTrue(label, loaded.value.contentEquals(step.b64("challenge_b64")))
                                assertEquals(label, expect.getLong("issued_at"), loaded.issuedAt)
                                assertEquals(label, expect.getLong("expires_at"), loaded.expiresAt)
                                val original = issuedRequests[java.util.Base64.getEncoder().encodeToString(loaded.value)]
                                assertTrue("$label loaded challenge has no issued request", original != null)
                                assertBindings(loaded, original!!, label)
                                if (expect.has("expected_receiver_id"))
                                    assertEquals(label, expect.getString("expected_receiver_id"), loaded.expectedReceiverId)
                            }
                        } catch (e: RatifyException) {
                            assertEquals(label, "expected_challenge_unavailable", e.errorClass?.spelling)
                            assertEquals(label, "expected_challenge_unavailable", expect.getString("result"))
                        }
                    }
                    "present", "present_concurrent" -> {
                        checked++
                        val at = step.getLong("at")
                        claims.setTime(at)
                        val before = claims.snapshot()
                        val wires = step.strings("bundles_b64").map(java.util.Base64.getDecoder()::decode)
                        val actual = coroutineScope {
                            wires.map { wire -> async(Dispatchers.Default) { presentIssued(wire, at, store, claims) } }
                                .awaitAll().sorted()
                        }
                        val wanted = if (expect.getString("result") == "preflight")
                            listOf("preflight:" + expect.getString("error_class")) else
                            expect.strings("dispositions").sorted()
                        assertEquals(label, wanted, actual)
                        val delta = claims.snapshot().zip(before) { after, prior -> after - prior }
                        if (expect.getString("result") == "preflight") {
                            assertEquals(label, listOf(0, 0, 0, 0), delta)
                        } else {
                            assertEquals(label, wires.size, delta[0])
                            assertEquals(label, wanted.count { it == "created" }, delta[1])
                            assertEquals(label, wanted.count { it == "proof_conflict" }, delta[3])
                        }
                    }
                    else -> fail("unsupported corpus operation: ${step.getString("op")}")
                }
            }
            assertTrue(name, !random.wasExhausted)
            assertEquals(name, random.available - if (name == "expiry_at_timestamp_domain_end") 1 else 0, random.calls)
        }
        assertEquals(42, checked)
        Manifest.record("challenge-issuance.json", checked)
    }

}
