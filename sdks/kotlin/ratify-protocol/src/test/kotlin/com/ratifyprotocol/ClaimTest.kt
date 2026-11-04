package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import kotlinx.coroutines.delay

class ClaimTest {
    private class UnavailableClaimStore : ClaimStore {
        var calls = 0
        override suspend fun authoritativeTime(): Long = error("preflight must not read store time")
        override suspend fun claim(claim: ChallengeClaim): ClaimResult {
            org.junit.Assert.assertTrue(claim.claimId.isNotEmpty())
            calls++
            throw StoreError.Unavailable("claim store offline")
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean = error("claim failed")
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress): Unit = error("claim failed")
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim = error("claim failed")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = error("claim failed")
    }

    private fun request(name: String, evaluators: ConstraintEvaluatorRegistry? = null): VerifyRequest {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
        val corpus = Corpus.load("verifier-ordering.json")
        val vector = corpus.arr("vectors").first { it.getString("name") == name }
        val expected = vector.getJSONObject("expected_challenge")
        val key = expected.getJSONObject("expected_agent_public_key")
        val policy = vector.getJSONObject("context_policy")
        val contextPolicy = ContextPolicy(policy.getString("profile"), policy.getBoolean("require_bound"),
            policy.strings("required_fields"), policy.b64("expected_session_context_b64"))
        val challenge = ExpectedChallenge(expected.b64("value_b64"), expected.getLong("issued_at"),
            expected.getLong("expires_at"), expected.getString("verifier_namespace"),
            expected.getLong("replay_epoch"), expected.getString("verifier_id"),
            expected.getString("expected_agent_id"), publicKeyOf(key),
            expectedSessionContext = expected.b64("expected_session_context_b64"))
        val policyBounds = vector.getJSONObject("status_policy")
        val statusKeysObject = vector.getJSONObject("status_keys")
        val statusKeys = statusKeysObject.keys().asSequence().associateWith { issuer ->
            val config = statusKeysObject.getJSONObject(issuer)
            StatusKeyConfig(config.getLong("epoch").toULong(), publicKeyOf(config.getJSONObject("public_key")))
        }
        val requestContext = vector.optJSONObject("request_context") ?: JSONObject()
        val countsObject = requestContext.optJSONObject("extension_counts") ?: JSONObject()
        val valuesObject = requestContext.optJSONObject("extension_values") ?: JSONObject()
        val counts = countsObject.keys().asSequence().associateWith { countsObject.getLong(it) }
        val values = valuesObject.keys().asSequence().associateWith { valuesObject.getString(it) }
        return VerifyRequest(Base64.getDecoder().decode(corpus.getJSONObject("bundles_b64").getString(vector.getString("bundle"))),
            challenge, contextPolicy, vector.getString("required_scope"), vector.getString("configured_namespace"),
            vector.getLong("configured_replay_epoch"), vector.getString("configured_verifier_id"),
            vector.getLong("now"), vector.getLong("max_challenge_age_seconds"),
            vector.getLong("future_skew_seconds"), ConstraintContext(extensionCounts = counts, extensionValues = values),
            vector.getString("tzdb_version"),
            statusKeys, RevocationStatusPolicy(policyBounds.getLong("max_list_lifetime_seconds"),
                policyBounds.getLong("max_status_age_seconds"), policyBounds.getLong("clock_skew_seconds")), evaluators)
    }

    @Test fun liveVerifierReachesClaimStoreAfterPreflight() = runBlocking {
        val request = request("claim_store_unavailable")
        val store = UnavailableClaimStore()
        val outcome = verifyProofBundle(request, store)
        assertEquals(VerifyStage.PREFLIGHT, outcome.stage)
        assertEquals(ErrorClass.CLAIM_STORE_UNAVAILABLE, outcome.errorClass)
        assertEquals(1, store.calls)
    }

    private class CreatedClaimStore(private val onFinalize: (suspend () -> Unit)? = null) : RateAtFinalizationClaimStore {
        var claims = 0
        var progressWrites = 0
        var finalizations = 0
        override suspend fun authoritativeTime(): Long = 1_800_000_000
        override suspend fun claim(claim: ChallengeClaim): ClaimResult {
            claims++
            return ClaimResult(ClaimDisposition.CREATED, 1_800_000_000, ByteArray(32) { 7 })
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean {
            if (onFinalize != null) withContext(NonCancellable) { onFinalize.invoke() }
            org.junit.Assert.assertArrayEquals(ByteArray(32) { 7 }, ownerToken)
            org.junit.Assert.assertTrue(terminalResult.isNotEmpty())
            org.junit.Assert.assertTrue(receiptBody.isNotEmpty())
            finalizations++
            return true
        }
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress) {
            progressWrites++
        }
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim = error("no interruption")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = error("no interruption")
    }

    private class UnavailableTrust : TrustProvider {
        var calls = 0
        override suspend fun resolve(chain: List<DelegationCert>): TrustResolution {
            org.junit.Assert.assertTrue(chain.isNotEmpty())
            calls++
            return TrustResolution(TrustOutcome.UNAVAILABLE, HybridPublicKey(ByteArray(0), ByteArray(0)))
        }
    }

    private class VectorJournal(initial: SecurityJournalSnapshot) : SecurityJournalStore {
        private var current = initial
        override suspend fun load(): SecurityJournalSnapshot = synchronized(this) { current }
        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            synchronized(this) {
                if (current.head != expected) throw SecurityJournalStoreError.Conflict()
                current = next
            }
        }
    }

    private class VectorEvaluator(private val mode: String) : ConstraintEvaluator {
        val calls = AtomicInteger()
        @Volatile var observedType: String? = null
        @Volatile var observedParams: ByteArray? = null
        override suspend fun evaluate(input: ConstraintEvaluationInput): ConstraintEvaluationResult {
            calls.incrementAndGet()
            observedType = input.type
            observedParams = input.paramsJson
            if (mode == "error") error("scripted evaluator failure")
            if (mode == "timeout") delay(100)
            return ConstraintEvaluationResult(if (mode == "denied") ConstraintOutcome.DENIED else ConstraintOutcome.PASS)
        }
    }

    @Test fun extensionEvaluatorsRunThroughLiveVerifier() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        val corpus = JSONObject(File(root, "v2/verifier-ordering.json").readText())
        val cases = listOf(
            Triple("extension_max_count_pass", "pass", "authorized"),
            Triple("extension_max_count_exceeded", "denied", "constraint_denied"),
            Triple("extension_evaluator_error", "error", "constraint_unverifiable"),
            Triple("extension_evaluator_timeout", "timeout", "constraint_unverifiable"),
        )
        for ((name, mode, reason) in cases) {
            val vectors = corpus.getJSONArray("vectors")
            val vector = (0 until vectors.length()).asSequence().map(vectors::getJSONObject)
                .first { it.getString("name") == name }
            val registration = vector.getJSONArray("constraint_evaluators").getJSONObject(0)
            val evaluator = VectorEvaluator(mode)
            val registry = ConstraintEvaluatorRegistry(if (mode == "timeout") 10u else 1000u,
                listOf(ConstraintEvaluatorRegistration(ConstraintProfileDescriptor(
                    registration.getString("profile"), registration.getString("type")), evaluator)))
            val req = request(name, registry)
            val trustKey = publicKeyOf(vector.getJSONObject("trust").getJSONObject("root_public_key"))
            val trust = object : TrustProvider {
                override suspend fun resolve(chain: List<DelegationCert>) = TrustResolution(TrustOutcome.TRUSTED, trustKey)
            }
            val evidenceObject = vector.getJSONObject("status_evidence")
            val evidence = evidenceObject.keys().asSequence().associateWith { issuer ->
                val objects = evidenceObject.getJSONObject(issuer).getJSONArray("objects")
                (0 until objects.length()).map { index ->
                    val item = objects.getJSONObject(index)
                    StatusEvidenceObject(item.getInt("object_type_code").toUShort(), item.b64("wire_b64"))
                }
            }
            val status = object : StatusEvidenceProvider {
                override suspend fun provide(request: StatusEvidenceRequest) = evidence[request.issuerId] ?: emptyList()
            }
            val audience = object : AudienceProvider {
                override suspend fun memberships(deferred: List<DeferredConstraint>, receiverId: String) = emptyList<AudienceMembership>()
            }
            val journal = VectorJournal(emptySecurityJournalSnapshot())
            for (issuer in req.statusKeys.keys.sorted()) {
                val key = req.statusKeys.getValue(issuer)
                configureStatusKeyEpoch(journal, issuer, key.epoch, key.key)
            }
            val outcome = verifyProofBundle(req, CreatedClaimStore(), trust = trust, audience = audience,
                statusEvidence = status, statusJournal = journal)
            assertEquals(name + ": " + (outcome.errorDetail ?: ""), VerifyStage.COMMITTED, outcome.stage)
            assertEquals(name, reason, JSONObject(String(outcome.committed!!.receiptBody)).getString("decision_reason"))
            assertEquals(name, 1, evaluator.calls.get())
            assertEquals(name, registration.getString("type"), evaluator.observedType)
            org.junit.Assert.assertNotNull(name, evaluator.observedParams)
        }
    }

    @Test fun trustUnavailabilityCommitsOnlyANonactionableHandoff() = runBlocking {
        val store = CreatedClaimStore()
        val trust = UnavailableTrust()
        val outcome = verifyProofBundle(request("trust_unavailable"), store, trust = trust)
        assertEquals(VerifyStage.COMMITTED, outcome.stage)
        assertEquals(null, outcome.errorClass)
        org.junit.Assert.assertNotNull(outcome.committed)
        assertEquals(1, store.claims)
        assertEquals(2, store.progressWrites)
        assertEquals(1, store.finalizations)
        assertEquals(1, trust.calls)
    }

    @Test fun cancellationAfterStoreCommitPreservesCommittedHandoff() = runBlocking {
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val store = CreatedClaimStore(onFinalize = { started.complete(Unit); release.await() })
        val trust = UnavailableTrust()
        val observed = AtomicReference<VerifyOutcome?>()
        val request = request("trust_unavailable")
        val call = launch { observed.set(verifyProofBundle(request, store, trust = trust)) }
        started.await()
        call.cancel()
        release.complete(Unit)
        call.join()
        assertEquals(VerifyStage.COMMITTED, observed.get()?.stage)
        org.junit.Assert.assertNotNull(observed.get()?.committed)
    }

    @Test fun replayComparesSealedClaimValuesIncludingBytes() {
        fun claim(stream: ByteArray) = ChallengeClaim("id", "ns", 1, "challenge", "proof", "bundle",
            listOf("issuer"), "scope", "policy", "verifier", "agent", true,
            listOf(RateReservation("issuer", "cert", 60, 2)), 10, 20, 5, 1, stream, 4,
            listOf(ConstraintEvaluatorRef("kind", "digest")))
        val input = byteArrayOf(1, 2)
        val stored = claim(input)
        input[0] = 9
        assertEquals(claim(byteArrayOf(1, 2)), stored)
        assertEquals(claim(byteArrayOf(1, 2)).hashCode(), stored.hashCode())
        org.junit.Assert.assertNotEquals(claim(byteArrayOf(2, 1)), stored)
    }

    private class MissingCommittedStore : CommittedClaimStore {
        var calls = 0
        override suspend fun loadCommitted(claimId: String): CommittedClaim {
            assertEquals("missing", claimId)
            calls++
            throw StoreError.Classified(ErrorClass.CLAIM_NOT_FOUND, "no terminal record")
        }
    }

    @Test fun resumePreservesStoreErrorAndCallsOnce() = runBlocking {
        val store = MissingCommittedStore()
        try {
            resumeCommittedClaim(store, "missing")
            fail("missing committed claim returned a handoff")
        } catch (e: RatifyException) {
            assertEquals(ErrorClass.CLAIM_NOT_FOUND, e.errorClass)
        }
        assertEquals(1, store.calls)
    }
}
