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
    private class ReceiverProbe(private val reject: Boolean) : ReceiverBindingHook {
        val calls = AtomicInteger()
        override fun validate(bundle: ProofBundle, expected: ExpectedChallenge) {
            calls.incrementAndGet()
            if (reject) throw StoreError.Unavailable("scripted receiver rejection")
        }
    }
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
            expectedReceiverId = expected.opt("expected_receiver_id") as? String ?: "",
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
            vector.getLong("future_skew_seconds"), ConstraintContext(
                requestedAmountMicros = requestContext.optLong("requested_amount_micros"),
                requestedCurrency = requestContext.optString("requested_currency"),
                hasAmount = requestContext.optBoolean("has_amount"),
                requestedResourceId = requestContext.optString("requested_resource_id"),
                requestedPath = requestContext.optString("requested_path"),
                hasResource = requestContext.optBoolean("has_resource"),
                extensionCounts = counts, extensionValues = values),
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

    @Test fun verifierCorpusPreflightRefusesBeforeClaim() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector ->
            vector.getJSONObject("expected").getString("stage") == "preflight" &&
            vector.optJSONObject("expected_challenge")?.optJSONObject("expected_agent_public_key") != null &&
            vector.getJSONObject("expected_challenge").opt("expected_agent_id") is String &&
            vector.getJSONObject("expected_challenge").opt("expected_session_context_b64") is String &&
            vector.optJSONObject("context_policy")?.opt("expected_session_context_b64") is String &&
            vector.getString("claim_store") == "create"
        }
        assertEquals(129, vectors.size)
        for (vector in vectors) {
            val name = vector.getString("name")
            val store = UnavailableClaimStore()
            val expectedClass = vector.getJSONObject("expected").getString("error_class")
            val registrations = vector.optJSONArray("constraint_evaluators")?.let { array ->
                (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    ConstraintEvaluatorRegistration(ConstraintProfileDescriptor(
                        item.getString("profile"), item.getString("type")), VectorEvaluator("pass"))
                }
            } ?: emptyList()
            val registry = if (registrations.isEmpty()) null else ConstraintEvaluatorRegistry(1000u, registrations)
            val req = request(name, registry)
            val hookMode = vector.getString("receiver_binding_hook")
            val hook = if (hookMode == "absent") null else ReceiverProbe(hookMode == "reject")
            val outcome = verifyProofBundle(req, store, receiverBinding = hook)
            assertEquals(name, VerifyStage.PREFLIGHT, outcome.stage)
            assertEquals(name, expectedClass, outcome.errorClass?.spelling)
            assertEquals(name, vector.getJSONObject("expected").getJSONObject("callback_counts").getInt("receiver_binding"),
                hook?.calls?.get() ?: 0)
            assertEquals(name, 0, store.calls)
        }
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

    private suspend fun vectorProviders(vector: JSONObject, req: VerifyRequest): Triple<TrustProvider, StatusEvidenceProvider, VectorJournal> {
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
        val journal = VectorJournal(emptySecurityJournalSnapshot())
        for (issuer in req.statusKeys.keys.sorted()) {
            val key = req.statusKeys.getValue(issuer)
            configureStatusKeyEpoch(journal, issuer, key.epoch, key.key)
        }
        return Triple(trust, status, journal)
    }

    private val emptyAudience = object : AudienceProvider {
        override suspend fun memberships(deferred: List<DeferredConstraint>, receiverId: String) = emptyList<AudienceMembership>()
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
            val (trust, status, journal) = vectorProviders(vector, req)
            val outcome = verifyProofBundle(req, CreatedClaimStore(), trust = trust, audience = emptyAudience,
                statusEvidence = status, statusJournal = journal)
            assertEquals(name + ": " + (outcome.errorDetail ?: ""), VerifyStage.COMMITTED, outcome.stage)
            assertEquals(name, reason, JSONObject(String(outcome.committed!!.receiptBody)).getString("decision_reason"))
            assertEquals(name, 1, evaluator.calls.get())
            assertEquals(name, registration.getString("type"), evaluator.observedType)
            org.junit.Assert.assertNotNull(name, evaluator.observedParams)
        }
    }

    private class ExhaustedBarrierStore : RateAtFinalizationClaimStore {
        private var claimed: ChallengeClaim? = null
        private val counters = mutableMapOf<String, Long>()
        var observedBatch: List<RateReservation> = emptyList()
            private set
        val terminalDecisions = mutableListOf<String>()
        var finalizations = 0
            private set
        var allowAttempts = 0
            private set
        private fun key(r: RateReservation) = "${r.issuerId}|${r.certId}|${r.windowSeconds}"
        override suspend fun authoritativeTime(): Long = 1_800_000_000
        override suspend fun claim(claim: ChallengeClaim): ClaimResult = synchronized(this) {
            observedBatch = claim.rateBatch
            claimed = claim
            counters[key(claim.rateBatch.first())] = claim.rateBatch.first().limit
            ClaimResult(ClaimDisposition.CREATED, 1_800_000_000, ByteArray(32) { 7 })
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean = synchronized(this) {
            finalizations++
            val decision = JSONObject(String(terminalResult)).getString("decision")
            terminalDecisions.add(decision)
            if (decision == "allow") {
                allowAttempts++
                val batch = claimed!!.rateBatch
                if (batch.any { (counters[key(it)] ?: 0) >= it.limit }) throw StoreError.RateLimitExceeded()
                batch.forEach { counters[key(it)] = (counters[key(it)] ?: 0) + 1 }
            }
            true
        }
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress) {}
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim = error("not interrupted")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = false
        fun counterValues(): List<Long> = synchronized(this) { claimed!!.rateBatch.map { counters[key(it)] ?: 0 } }
    }

    @Test fun rateBarrierMapsCapacityRefusalAndRetriesDeny() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        val corpus = JSONObject(File(root, "v2/verifier-ordering.json").readText())
        val vectors = corpus.getJSONArray("vectors")
        val vector = (0 until vectors.length()).asSequence().map(vectors::getJSONObject)
            .first { it.getString("name") == "rate_multi_batch" }
        val batch = vector.getJSONObject("expected").getJSONArray("rate_batch")
        val expectedBatch = (0 until batch.length()).map { index ->
            val item = batch.getJSONObject(index)
            RateReservation(item.getString("issuer_id"), item.getString("cert_id"),
                item.getLong("window_s"), item.getLong("limit"))
        }
        val req = request("rate_multi_batch")
        val (trust, status, journal) = vectorProviders(vector, req)
        val store = ExhaustedBarrierStore()
        val outcome = verifyProofBundle(req, store, trust = trust, audience = emptyAudience,
            statusEvidence = status, statusJournal = journal)
        assertEquals(VerifyStage.COMMITTED, outcome.stage)
        assertEquals("constraint_denied", JSONObject(String(outcome.committed!!.receiptBody)).getString("decision_reason"))
        assertEquals(1, store.allowAttempts)
        assertEquals(2, store.finalizations)
        assertEquals(expectedBatch, store.observedBatch)
        assertEquals(listOf("allow", "deny"), store.terminalDecisions)
        assertEquals(listOf(3L, 0L, 0L), store.counterValues())
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

    private class PendingReleaseStore(private val committed: CommittedOutcome) : ReleaseClaimStore {
        var loads = 0
        override suspend fun authoritativeTime(): Long = error("no receipt means no clock read")
        override suspend fun loadTerminal(claimId: String): TerminalClaimRecord {
            assertEquals(committed.claimId, claimId)
            loads++
            return TerminalClaimRecord(true, committed.receiptBodyDigest, committed.challengeExpiresAt,
                committed.allowHorizon ?: 0, 1_800_000_000, false, null)
        }
        override suspend fun recordRelease(record: ReleaseRecord): Unit = error("no receipt means no release record")
    }

    private class NoAcknowledgement : ReceiptCheckpoint {
        override suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
            entryHash: ByteArray): CheckpointAcknowledgement = error("no receipt means no acknowledgement")
        override suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement =
            error("no receipt means no checkpoint read")
    }

    @Test fun committedHandoffCannotReleaseBeforeReceiptAppend() = runBlocking {
        val verified = verifyProofBundle(request("trust_unavailable"), CreatedClaimStore(), trust = UnavailableTrust())
        val committed = verified.committed!!
        val root = File(System.getProperty("ratify.corpus")!!)
        val keys = JSONObject(File(root, "v2/keys.json").readText()).getJSONArray("keys")
        val verifier = (0 until keys.length()).asSequence().map(keys::getJSONObject)
            .first { it.getString("name") == "verifier" }
        val store = PendingReleaseStore(committed)
        val result = releaseDecision(committed, null, publicKeyOf(verifier.getJSONObject("public_key")),
            "0123456789abcdef0123456789abcdef", store, NoAcknowledgement())
        assertEquals(ReleaseStatus.PENDING, result.status)
        assertEquals("receipt_not_appended", result.reason)
        assertEquals(null, result.decision)
        assertEquals(1, store.loads)
    }

    private class ReleasedStore(private val committed: CommittedOutcome) : ReleaseClaimStore {
        var recorded: ReleaseRecord? = null
        override suspend fun authoritativeTime(): Long = 1_800_000_000
        override suspend fun loadTerminal(claimId: String): TerminalClaimRecord =
            TerminalClaimRecord(true, committed.receiptBodyDigest, committed.challengeExpiresAt,
                committed.allowHorizon ?: 0, 1_800_000_000, false, recorded)
        override suspend fun recordRelease(record: ReleaseRecord) { recorded = record }
    }

    private class AcknowledgedReceipt(private val digest: ByteArray) : ReceiptCheckpoint {
        override suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
            entryHash: ByteArray): CheckpointAcknowledgement = error("release only reads acknowledgement")
        override suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement =
            CheckpointAcknowledgement(logId, sequence, digest, 1_800_000_000)
    }

    @Test fun signedReceiptNeedsIndependentCheckpointToRelease() = runBlocking {
        val verified = verifyProofBundle(request("trust_unavailable"), CreatedClaimStore(), trust = UnavailableTrust())
        val committed = verified.committed!!
        val root = File(System.getProperty("ratify.corpus")!!)
        val keys = JSONObject(File(root, "v2/keys.json").readText()).getJSONArray("keys")
        val verifier = (0 until keys.length()).asSequence().map(keys::getJSONObject)
            .first { it.getString("name") == "verifier" }
        val key = SoftwarePrivateKey.fromSeeds(verifier.hex("ed25519_seed_hex"), verifier.hex("ml_dsa_65_seed_hex"))
        val logId = "0123456789abcdef0123456789abcdef"
        val head = ReceiptHead(logId, key.keyId, 0, ByteArray(48))
        val receipt = signPreparedVerificationReceipt(committed.receiptBody, head, key)
        val wire = encodeVerificationReceipt(receipt)
        val digest = verificationReceiptDigest(receipt)
        val store = ReleasedStore(committed)
        val pending = releaseDecision(committed, wire, key.publicKey, logId, store, NoAcknowledgement())
        assertEquals(ReleaseStatus.PENDING, pending.status)
        assertEquals("acknowledgement_unavailable", pending.reason)
        assertEquals(null, pending.decision)
        assertEquals(null, store.recorded)
        val released = releaseDecision(committed, wire, key.publicKey, logId, store, AcknowledgedReceipt(digest))
        assertEquals(ReleaseStatus.RELEASED, released.status)
        org.junit.Assert.assertArrayEquals(wire, released.decision!!.receiptWire)
        assertEquals(false, released.decision!!.isAllowed(store))
        assertEquals(ReleaseStatus.RELEASED, store.recorded?.outcome)
    }
}
