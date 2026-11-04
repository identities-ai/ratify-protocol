package com.ratifyprotocol

import com.ratifyprotocol.testing.Store as ReferenceStore
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import kotlinx.coroutines.delay
import com.sun.jna.Library
import com.sun.jna.Native

class ClaimTest {
    companion object {
        @BeforeClass @JvmStatic fun setUpCorpus() = CorpusSetup.configure()
    }
    private interface CallbackPanicHooks : Library {
        fun ratify_ffi_test_arm_callback_panic(kind: Int)
        fun ratify_ffi_test_callback_panic_remaining(): Int
    }
    private val callbackPanicHooks: CallbackPanicHooks by lazy {
        Native.load("ratify_protocol_ffi", CallbackPanicHooks::class.java)
    }
    private class ReceiverProbe(private val reject: Boolean) : ReceiverBindingHook {
        val calls = AtomicInteger()
        override fun validate(bundle: ProofBundle, expected: ExpectedChallenge) {
            calls.incrementAndGet()
            if (reject) throw StoreError.Unavailable("scripted receiver rejection")
        }
    }
    private class UnavailableClaimStore(private val conflict: Boolean = false) : ClaimStore {
        var calls = 0
        override suspend fun authoritativeTime(): Long = error("preflight must not read store time")
        override suspend fun claim(claim: ChallengeClaim): ClaimResult {
            org.junit.Assert.assertTrue(claim.claimId.isNotEmpty())
            calls++
            if (conflict) throw StoreError.ClaimProofConflict()
            throw StoreError.Unavailable("claim store offline")
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean = error("claim failed")
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress): Unit = error("claim failed")
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim = error("claim failed")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = error("claim failed")
    }

    private fun request(name: String, evaluators: ConstraintEvaluatorRegistry? = null,
        corpusName: String = "verifier-ordering.json", atTime: Long? = null): VerifyRequest {
        val corpus = Corpus.load(corpusName)
        val vector = if (corpusName == "lifecycle-scenarios.json") corpus.getJSONObject("requests").getJSONObject(name)
            else corpus.arr("vectors").first { it.getString("name") == name }
        val policy = vector.optJSONObject("context_policy")
        val contextPolicy = policy?.let {
            ContextPolicy(it.getString("profile"), it.getBoolean("require_bound"),
                it.strings("required_fields"), (it.opt("expected_session_context_b64") as? String)
                    ?.let(Base64.getDecoder()::decode) ?: ByteArray(0))
        }
        val challenge = vector.optJSONObject("expected_challenge")?.let { expected ->
            ExpectedChallenge(expected.b64("value_b64"), expected.getLong("issued_at"),
                expected.getLong("expires_at"), expected.getString("verifier_namespace"),
                expected.getLong("replay_epoch"), expected.getString("verifier_id"),
                expectedAgentId = expected.opt("expected_agent_id") as? String ?: "",
                expectedAgentPublicKey = expected.optJSONObject("expected_agent_public_key")?.let(::publicKeyOf),
                expectedReceiverId = expected.opt("expected_receiver_id") as? String ?: "",
                expectedSessionContext = (expected.opt("expected_session_context_b64") as? String)
                    ?.let(Base64.getDecoder()::decode))
        }
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
            atTime ?: vector.getLong("now"), vector.getLong("max_challenge_age_seconds"),
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

    fun verifierCorpusPreflightOrdering() = runBlocking {
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector ->
            vector.getJSONObject("expected").getString("stage") == "preflight"
        }
        assertEquals(149, vectors.size)
        for (vector in vectors) {
            val name = vector.getString("name")
            val store = UnavailableClaimStore(vector.getString("claim_store") == "proof_conflict")
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
            val outcome = if (vector.getString("claim_store") == "absent") {
                verifyProofBundleWithoutClaimStore(req, receiverBinding = hook)
            } else {
                verifyProofBundle(req, store, receiverBinding = hook)
            }
            assertEquals(name, VerifyStage.PREFLIGHT, outcome.stage)
            assertEquals(name, expectedClass, outcome.errorClass?.spelling)
            assertEquals(name, vector.getJSONObject("expected").getJSONObject("callback_counts").getInt("receiver_binding"),
                hook?.calls?.get() ?: 0)
            assertEquals(name, vector.getJSONObject("expected").getJSONObject("callback_counts").getInt("claim"), store.calls)
        }
    }

    private class CreatedClaimStore(private val onFinalize: (suspend () -> Unit)? = null,
        private val claimedAt: Long = 1_800_000_000L,
        private val finalizeTimeOffset: Long = 0L,
        private val disposition: ClaimDisposition = ClaimDisposition.CREATED) : RateAtFinalizationClaimStore {
        private var claimed: ChallengeClaim? = null
        var claims = 0
        var progressWrites = 0
        val progressRecords = mutableListOf<EvaluationProgress>()
        var finalizations = 0
        val allowHorizons = mutableListOf<Long>()
        override suspend fun authoritativeTime(): Long = claimedAt
        override suspend fun claim(claim: ChallengeClaim): ClaimResult {
            claims++
            if (disposition == ClaimDisposition.CREATED) claimed = claim
            return ClaimResult(disposition, claimedAt,
                if (disposition == ClaimDisposition.CREATED) ByteArray(32) { 7 } else ByteArray(0))
        }
        override suspend fun finalize(claimId: String, ownerToken: ByteArray, terminalResult: ByteArray,
            receiptBody: ByteArray, allowValidUntil: Long): Boolean {
            if (onFinalize != null) withContext(NonCancellable) { onFinalize.invoke() }
            org.junit.Assert.assertArrayEquals(ByteArray(32) { 7 }, ownerToken)
            org.junit.Assert.assertTrue(terminalResult.isNotEmpty())
            org.junit.Assert.assertTrue(receiptBody.isNotEmpty())
            finalizations++
            allowHorizons.add(allowValidUntil)
            val finalTime = claimedAt + finalizeTimeOffset
            if (finalTime < claimedAt) throw StoreError.Classified(ErrorClass.CLOCK_REGRESSED, "finalization clock regressed")
            if (allowValidUntil != 0L && (finalTime >= allowValidUntil || finalTime >= claimed!!.expiresAt))
                throw StoreError.Classified(ErrorClass.ALLOW_HORIZON_PASSED, "allow horizon passed")
            return true
        }
        override suspend fun recordProgress(claimId: String, ownerToken: ByteArray, progress: EvaluationProgress) {
            progressWrites++
            progressRecords.add(progress)
        }
        override suspend fun loadInterrupted(claimId: String): InterruptedClaim = error("no interruption")
        override suspend fun recoverInterrupted(claimId: String, terminalResult: ByteArray,
            receiptBody: ByteArray): Boolean = error("no interruption")
    }

    fun verifierCorpusReplay() = runBlocking {
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            it.getJSONObject("expected").getString("stage") == "replay"
        }
        assertEquals(2, vectors.size)
        for (vector in vectors) {
            val name = vector.getString("name")
            val disposition = ClaimDisposition.entries.first {
                it.spelling == vector.getJSONObject("expected").getString("disposition")
            }
            val store = CreatedClaimStore(disposition = disposition)
            val trust = VectorTrust(HybridPublicKey(ByteArray(0), ByteArray(0)), TrustOutcome.TRUSTED)
            val status = VectorStatus(emptyMap())
            val audience = CountingAudience()
            val outcome = verifyProofBundle(request(name), store, trust = trust,
                audience = audience, statusEvidence = status)
            val callbacks = vector.getJSONObject("expected").getJSONObject("callback_counts")
            assertEquals(name, VerifyStage.REPLAY, outcome.stage)
            assertEquals(name, disposition, outcome.disposition)
            assertEquals(name, null, outcome.committed)
            assertEquals(name, callbacks.getInt("claim"), store.claims)
            assertEquals(name, callbacks.getInt("finalize"), store.finalizations)
            assertEquals(name, callbacks.getInt("progress"), store.progressWrites)
            assertEquals(name, callbacks.getInt("trust"), trust.calls.get())
            assertEquals(name, callbacks.getInt("status"), status.requests.size)
            assertEquals(name, callbacks.getInt("audience"), audience.calls.get())
            assertEquals(name, vector.getJSONObject("expected").arr("status_requests").size, status.requests.size)
        }
    }

    fun verifierCorpusFinalizationRefusals() = runBlocking {
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter {
            it.getJSONObject("expected").getString("stage") == "evaluating"
        }
        assertEquals(2, vectors.size)
        for (vector in vectors) {
            val name = vector.getString("name")
            val req = request(name)
            val (trust, status, journal) = vectorProviders(vector, req)
            val store = CreatedClaimStore(claimedAt = vector.getLong("now"),
                finalizeTimeOffset = vector.getLong("finalize_time_offset"))
            val audience = CountingAudience()
            val outcome = verifyProofBundle(req, store, trust = trust,
                audience = audience, statusEvidence = status, statusJournal = journal)
            val expected = vector.getJSONObject("expected")
            val callbacks = expected.getJSONObject("callback_counts")
            assertEquals(name, VerifyStage.EVALUATING, outcome.stage)
            assertEquals(name, expected.getString("error_class"), outcome.errorClass?.spelling)
            assertEquals(name, null, outcome.committed)
            assertEquals(name, callbacks.getInt("claim"), store.claims)
            assertEquals(name, callbacks.getInt("finalize"), store.finalizations)
            assertEquals(name, callbacks.getInt("progress"), store.progressWrites)
            assertEquals(name, callbacks.getInt("trust"), trust.calls.get())
            assertEquals(name, callbacks.getInt("status"), status.requests.size)
            assertEquals(name, callbacks.getInt("audience"), audience.calls.get())
            val expectedRequests = expected.arr("status_requests")
            assertEquals(name, expectedRequests.size, status.requests.size)
            for ((actual, scripted) in status.requests.zip(expectedRequests)) {
                assertEquals(name, scripted.getString("issuer_id"), actual.issuerId)
                assertEquals(name, scripted.getLong("status_key_epoch").toULong(), actual.statusKeyEpoch)
                assertEquals(name, scripted.getString("status_key_id"), actual.statusKeyId)
                val refs = scripted.arr("refs")
                assertEquals(name, refs.size, actual.refs.size)
                for ((actualRef, expectedRef) in actual.refs.zip(refs)) {
                    assertEquals(name, expectedRef.getString("issuer_id"), actualRef.issuerId)
                    assertEquals(name, expectedRef.getString("cert_id"), actualRef.certId)
                }
            }
        }
    }

    private class VectorRate(private val mode: String) : RateReservationStore {
        val batches = java.util.Collections.synchronizedList(mutableListOf<List<RateReservation>>())
        override suspend fun reserve(claimId: String, ownerToken: ByteArray, bundleHash: String,
            batch: List<RateReservation>) {
            org.junit.Assert.assertArrayEquals(ByteArray(32) { 7 }, ownerToken)
            org.junit.Assert.assertTrue(bundleHash.isNotEmpty())
            batches.add(batch)
            if (mode == "exceeded") throw StoreError.RateLimitExceeded()
            if (mode == "unavailable") throw StoreError.Unavailable("scripted rate failure")
        }
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
        private var mode = "anchored"
        private var conflicts = 0
        fun setMode(value: String) { synchronized(this) { mode = value } }
        override suspend fun load(): SecurityJournalSnapshot = synchronized(this) {
            if (mode == "load_error") error("scripted journal load failure")
            current
        }
        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            synchronized(this) {
                if (mode == "cas_conflict" || mode == "cas_conflict_once" && conflicts == 0) {
                    conflicts++
                    throw SecurityJournalStoreError.Conflict()
                }
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

    private class CorpusEvaluator(private val implementation: String, private val validUntil: Long) : ConstraintEvaluator {
        val calls = AtomicInteger()
        override suspend fun evaluate(input: ConstraintEvaluationInput): ConstraintEvaluationResult {
            calls.incrementAndGet()
            return when (implementation) {
                "com.ratifyprotocol.max_count/v1" -> evaluateMaxCount(input)
                "com.ratifyprotocol.allowed_values/v1" -> evaluateAllowedValues(input)
                "fault:pass_until" -> ConstraintEvaluationResult(ConstraintOutcome.PASS, validUntil)
                "fault:error" -> error("scripted evaluator failure")
                "fault:panic" -> ConstraintEvaluationResult(ConstraintOutcome.PASS)
                "fault:invalid_outcome" -> ConstraintEvaluationResult(ConstraintOutcome.INVALID)
                "fault:timeout" -> { delay(100); ConstraintEvaluationResult(ConstraintOutcome.PASS) }
                else -> error("Unsupported corpus evaluator: $implementation")
            }
        }
    }

    private class VectorTrust(private val key: HybridPublicKey, private val outcome: TrustOutcome,
        private val fails: Boolean = false, private val registry: List<HybridPublicKey>? = null) : TrustProvider {
        val calls = AtomicInteger()
        override suspend fun resolve(chain: List<DelegationCert>): TrustResolution {
            calls.incrementAndGet()
            if (fails) error("scripted trust failure")
            if (registry != null) {
                val root = chain.lastOrNull() ?: return TrustResolution(TrustOutcome.UNTRUSTED, key)
                var match: HybridPublicKey? = null
                for (candidate in registry) {
                    if (keyId(candidate) != root.issuerId &&
                        !candidate.ed25519.contentEquals(root.issuerPubKey.ed25519) &&
                        !candidate.mlDsa65.contentEquals(root.issuerPubKey.mlDsa65)) continue
                    if (match != null) return TrustResolution(TrustOutcome.AMBIGUOUS, key)
                    match = candidate
                }
                return if (match == null) TrustResolution(TrustOutcome.UNTRUSTED, key)
                    else TrustResolution(TrustOutcome.TRUSTED, match)
            }
            return TrustResolution(outcome, key)
        }
    }

    private class VectorStatus(private val evidence: Map<String, List<StatusEvidenceObject>>,
        private val failures: Set<String> = emptySet()) : StatusEvidenceProvider {
        val requests = java.util.Collections.synchronizedList(mutableListOf<StatusEvidenceRequest>())
        override suspend fun provide(request: StatusEvidenceRequest): List<StatusEvidenceObject> {
            requests.add(request)
            if (request.issuerId in failures) error("scripted status failure")
            return evidence[request.issuerId] ?: emptyList()
        }
    }

    private suspend fun vectorProviders(vector: JSONObject, req: VerifyRequest): Triple<VectorTrust, VectorStatus, VectorJournal> {
        val trustScript = vector.optJSONObject("trust") ?: JSONObject()
        val trustKey = trustScript.optJSONObject("root_public_key")?.let(::publicKeyOf)
            ?: HybridPublicKey(ByteArray(0), ByteArray(0))
        val trust = VectorTrust(trustKey,
            TrustOutcome.fromSpelling(trustScript.optString("outcome")) ?: TrustOutcome.UNAVAILABLE,
            trustScript.optString("mode") == "error",
            trustScript.optJSONArray("registry")?.let { records ->
                (0 until records.length()).map { publicKeyOf(records.getJSONObject(it)) }
            })
        val evidenceObject = vector.getJSONObject("status_evidence")
        val evidence = evidenceObject.keys().asSequence().associateWith { issuer ->
            val objects = evidenceObject.getJSONObject(issuer).getJSONArray("objects")
            (0 until objects.length()).map { index ->
                val item = objects.getJSONObject(index)
                StatusEvidenceObject(item.getInt("object_type_code").toUShort(), item.b64("wire_b64"))
            }
        }
        val failures = evidenceObject.keys().asSequence().filter { issuer ->
            evidenceObject.getJSONObject(issuer).getString("mode") == "error"
        }.toSet()
        val status = VectorStatus(evidence, failures)
        val journal = VectorJournal(emptySecurityJournalSnapshot())
        val script = vector.getJSONObject("journal")
        if (script.optJSONArray("setup") != null) {
            for (step in script.arr("setup")) {
                val key = publicKeyOf(step.getJSONObject("public_key"))
                when (step.getString("op")) {
                    "configure_status_key" -> configureStatusKeyEpoch(journal, step.getString("issuer_id"),
                        step.getLong("epoch").toULong(), key)
                    "apply" -> {
                        assertEquals(3, step.getInt("object_type_code"))
                        applyRevocationListToJournal(journal, decodeRevocationList(step.b64("wire_b64")),
                            step.getString("issuer_id"), step.getLong("epoch").toULong(), key,
                            req.statusPolicy, step.getLong("now"))
                    }
                    else -> error("unknown journal setup operation")
                }
            }
        } else if (script.getString("mode") !in listOf("unanchored", "absent")) {
            for (issuer in req.statusKeys.keys.sorted()) {
                val key = req.statusKeys.getValue(issuer)
                configureStatusKeyEpoch(journal, issuer, key.epoch, key.key)
            }
            for (step in script.arr("preload")) {
                assertEquals(3, step.getInt("object_type_code"))
                val key = req.statusKeys.getValue(step.getString("issuer_id"))
                applyRevocationListToJournal(journal, decodeRevocationList(step.b64("wire_b64")),
                    step.getString("issuer_id"), key.epoch, key.key, req.statusPolicy, step.getLong("now"))
            }
        }
        journal.setMode(script.getString("mode"))
        return Triple(trust, status, journal)
    }

    private class CountingAudience(private val values: List<AudienceMembership> = emptyList(),
        private val fails: Boolean = false) : AudienceProvider {
        val calls = AtomicInteger()
        override suspend fun memberships(deferred: List<DeferredConstraint>, receiverId: String): List<AudienceMembership> {
            calls.incrementAndGet()
            if (fails) error("scripted audience failure")
            return values
        }
    }

    fun verifierCorpusCommittedReceipts() = runBlocking {
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector ->
            vector.getJSONObject("expected").getString("stage") == "committed"
        }
        assertEquals(362, vectors.size)
        for (vector in vectors) {
            val name = vector.getString("name")
            val registrationsJson = vector.optJSONArray("constraint_evaluators")
            val entries = (0 until (registrationsJson?.length() ?: 0)).map { registrationsJson!!.getJSONObject(it) }
            val evaluators = entries.map { CorpusEvaluator(it.getString("implementation"), it.optLong("valid_until")) }
            val registrations = entries.zip(evaluators).map { (item, evaluator) ->
                ConstraintEvaluatorRegistration(ConstraintProfileDescriptor(
                    item.getString("profile"), item.getString("type")), evaluator)
            }
            val timeout = if (entries.any { it.getString("implementation") == "fault:timeout" }) 10uL else 1000uL
            val registry = if (registrations.isEmpty()) null else ConstraintEvaluatorRegistry(timeout, registrations)
            val req = request(name, registry)
            val (trust, status, journal) = vectorProviders(vector, req)
            val store = CreatedClaimStore(claimedAt = vector.getLong("now") + vector.optLong("claim_time_offset"),
                finalizeTimeOffset = vector.optLong("finalize_time_offset"))
            val baseStore: ClaimStore = store
            val memberships = vector.optJSONArray("audience_memberships")?.let { array ->
                (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    AudienceMembership(item.getLong("delegation_index").toULong(),
                        item.getLong("constraint_index").toULong(), item.getString("receiver_id"),
                        item.strings("trust_domain_ids"), item.getLong("issued_at"),
                        item.getLong("expires_at"), item.getString("evidence_digest"))
                }
            } ?: emptyList()
            val audience = CountingAudience(memberships, vector.getString("audience_mode") == "error")
            val rate = if (vector.getString("rate") == "absent") null else VectorRate(vector.getString("rate"))
            val receiver = if (vector.getString("receiver_binding_hook") == "accept") ReceiverProbe(false) else null
            val journalStore: SecurityJournalStore? = if (vector.getJSONObject("journal").getString("mode") == "absent")
                null else journal
            val panicKind = when (name) {
                "trust_provider_panic" -> 1
                "status_provider_panic" -> 2
                "audience_provider_panic" -> 3
                "rate_store_panic" -> 4
                "extension_evaluator_panic" -> 5
                else -> 0
            }
            if (panicKind == 1) assertEquals(name, "panic", vector.getJSONObject("trust").getString("mode"))
            if (panicKind == 2) org.junit.Assert.assertTrue(name,
                vector.getJSONObject("status_evidence").keys().asSequence().any {
                    vector.getJSONObject("status_evidence").getJSONObject(it).getString("mode") == "panic"
                })
            if (panicKind == 3) assertEquals(name, "panic", vector.getString("audience_mode"))
            if (panicKind == 4) assertEquals(name, "panic", vector.getString("rate"))
            if (panicKind == 5) org.junit.Assert.assertTrue(name,
                vector.getJSONArray("constraint_evaluators").let { array ->
                    (0 until array.length()).any { array.getJSONObject(it).getString("implementation") == "fault:panic" }
                })
            // A test-only Rust unwind after the foreign call exercises core
            // containment without treating a JVM throwable as a Rust panic.
            if (panicKind != 0) callbackPanicHooks.ratify_ffi_test_arm_callback_panic(panicKind)
            val (outcome, remaining) = try {
                val result = verifyProofBundle(req, baseStore, trust = trust, audience = audience,
                    receiverBinding = receiver, statusEvidence = status, statusJournal = journalStore, rate = rate)
                result to callbackPanicHooks.ratify_ffi_test_callback_panic_remaining()
            } finally {
                callbackPanicHooks.ratify_ffi_test_arm_callback_panic(0)
            }
            assertEquals("$name callback panic hook was not reached", 0,
                remaining)
            assertEquals(name + ": " + (outcome.errorDetail ?: ""), VerifyStage.COMMITTED, outcome.stage)
            org.junit.Assert.assertArrayEquals(name, vector.getJSONObject("expected").b64("receipt_body_b64"),
                outcome.committed?.receiptBody)
            assertEquals(name, 1, store.claims)
            assertEquals(name, 1, store.finalizations)
            assertEquals(name, listOf(vector.getJSONObject("expected").optLong("allow_valid_until")), store.allowHorizons)
            assertEquals(name, vector.getJSONObject("expected").getJSONObject("callback_counts").getInt("progress"),
                store.progressWrites)
            val expectedEvidence: List<StatusEvidenceEntry> = vector.getJSONObject("expected").optJSONArray("status_evidence")?.let { array ->
                (0 until array.length()).map { index ->
                    val item = array.getJSONObject(index)
                    StatusEvidenceEntry(item.getString("issuer_id"), item.getString("status_key_id"),
                        item.getLong("sequence"), item.getInt("object_type_code").toUShort(), item.getString("digest"))
                }
            } ?: emptyList()
            assertEquals(name, expectedEvidence, store.progressRecords.lastOrNull()?.statusEvidence ?: emptyList<StatusEvidenceEntry>())
            val callbacks = vector.getJSONObject("expected").getJSONObject("callback_counts")
            assertEquals(name, callbacks.getInt("receiver_binding"), receiver?.calls?.get() ?: 0)
            assertEquals(name, callbacks.getInt("trust"), trust.calls.get())
            assertEquals(name, callbacks.getInt("status"), status.requests.size)
            assertEquals(name, callbacks.getInt("audience"), audience.calls.get())
            assertEquals(name, callbacks.getInt("rate"), rate?.batches?.size ?: 0)
            rate?.batches?.firstOrNull()?.let { batch ->
                val expectedBatch = vector.getJSONObject("expected").arr("rate_batch").map {
                    RateReservation(it.getString("issuer_id"), it.getString("cert_id"),
                        it.getLong("window_s"), it.getLong("limit"))
                }
                assertEquals(name, expectedBatch, batch)
            }
            assertEquals(name, callbacks.optInt("evaluator"), evaluators.sumOf { it.calls.get() })
            val expectedRequests = vector.getJSONObject("expected").arr("status_requests")
            assertEquals(name, expectedRequests.size, status.requests.size)
            for ((actual, expected) in status.requests.zip(expectedRequests)) {
                assertEquals(name, expected.getString("issuer_id"), actual.issuerId)
                assertEquals(name, expected.getLong("status_key_epoch").toULong(), actual.statusKeyEpoch)
                assertEquals(name, expected.getString("status_key_id"), actual.statusKeyId)
                val refs = expected.arr("refs")
                assertEquals(name, refs.size, actual.refs.size)
                for ((actualRef, expectedRef) in actual.refs.zip(refs)) {
                    assertEquals(name, expectedRef.getString("issuer_id"), actualRef.issuerId)
                    assertEquals(name, expectedRef.getString("cert_id"), actualRef.certId)
                }
            }
        }
    }

    private val emptyAudience = object : AudienceProvider {
        override suspend fun memberships(deferred: List<DeferredConstraint>, receiverId: String) = emptyList<AudienceMembership>()
    }

    @Test fun extensionEvaluatorsRunThroughLiveVerifier() = runBlocking {
        val corpus = Corpus.load("verifier-ordering.json")
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
        val corpus = Corpus.load("verifier-ordering.json")
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
        val keys = Corpus.load("keys.json").getJSONArray("keys")
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
        val keys = Corpus.load("keys.json").getJSONArray("keys")
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

    @Test fun referenceStoreCommittedReceiptCheckpointAndRelease() = runBlocking {
        val req = request("trust_unavailable")
        val keys = Corpus.load("keys.json").getJSONArray("keys")
        val verifier = (0 until keys.length()).asSequence().map(keys::getJSONObject)
            .first { it.getString("name") == "verifier" }
        val key = SoftwarePrivateKey.fromSeeds(verifier.hex("ed25519_seed_hex"), verifier.hex("ml_dsa_65_seed_hex"))
        val logId = "0123456789abcdef0123456789abcdef"
        val store = ReferenceStore(req.now, 30, logId, key)
        store.setAcknowledgementWithheld(true)
        val outcome = verifyProofBundle(req, store, trust = UnavailableTrust())
        assertEquals(VerifyStage.COMMITTED, outcome.stage)
        val committed = outcome.committed!!
        val saved = store.loadCommitted(committed.claimId)
        assertEquals(committed.claimId, saved.claim.claimId)
        assertEquals("trust_unavailable", JSONObject(String(saved.terminalResult)).getString("decision_reason"))
        org.junit.Assert.assertArrayEquals(committed.receiptBody, saved.receiptBody)
        assertEquals(committed.allowHorizon ?: 0, saved.allowHorizon)
        val wire = store.publish(committed.claimId, saved.receiptBody)
        val digest = verificationReceiptDigest(decodeVerificationReceipt(wire))
        val acknowledgement = store.acknowledge(logId, 1, ByteArray(48), digest)
        assertEquals(logId, acknowledgement.logId)
        assertEquals(1L, acknowledgement.sequence)
        org.junit.Assert.assertArrayEquals(digest, acknowledgement.entryHash)
        assertEquals(req.now, acknowledgement.timestamp)
        org.junit.Assert.assertArrayEquals(digest, store.get(logId, 1).entryHash)
        val released = releaseDecision(committed, wire, key.publicKey, logId, store, store)
        assertEquals(ReleaseStatus.RELEASED, released.status)
        assertEquals(ReleaseStatus.RELEASED, store.loadTerminal(committed.claimId).release?.outcome)
    }

    private class WrongEntryCheckpoint(private val store: ReferenceStore) : ReceiptCheckpoint {
        override suspend fun acknowledge(logId: String, sequence: Long, previousEntryHash: ByteArray,
            entryHash: ByteArray): CheckpointAcknowledgement = store.acknowledge(logId, sequence, previousEntryHash, entryHash)
        override suspend fun get(logId: String, sequence: Long): CheckpointAcknowledgement {
            val ack = store.get(logId, sequence)
            val hash = ack.entryHash.copyOf()
            hash[0] = (hash[0].toInt() xor 1).toByte()
            return CheckpointAcknowledgement(ack.logId, ack.sequence, hash, ack.timestamp)
        }
    }

    private fun corruptReceiptSignature(wire: ByteArray): ByteArray {
        val receipt = decodeVerificationReceipt(wire)
        val ed25519 = receipt.signature.ed25519
        ed25519[0] = (ed25519[0].toInt() xor 1).toByte()
        return encodeVerificationReceipt(VerificationReceipt(receipt.version, receipt.logId, receipt.sequence,
            receipt.verifierId, receipt.agentId, receipt.humanId, receipt.bundleHash, receipt.issuerIds,
            receipt.decision, receipt.decisionReason, receipt.identityStatus, receipt.trustAssessment,
            receipt.statusAssessment, receipt.challengeAssessment, receipt.constraintEvaluators,
            receipt.contextAssessment, receipt.contextPolicyDigest, receipt.verifiedAt, receipt.requiredScope,
            receipt.grantedScope, receipt.statusEvidence, receipt.previousReceiptHash,
            HybridSignature(ed25519, receipt.signature.mlDsa65)))
    }

    @Test fun lifecycleBasicReleaseScenarios() = runBlocking {
        val corpus = Corpus.load("lifecycle-scenarios.json")
        val names = setOf("allow_published_acknowledged_released", "release_without_receipt_is_pending",
            "release_without_acknowledgement_is_pending_then_late_ack_releases",
            "late_ack_at_challenge_expiry_is_withheld", "release_one_second_before_challenge_expiry",
            "release_at_challenge_expiry_is_withheld", "release_at_allow_horizon_is_withheld",
            "release_before_allow_horizon", "signer_failure_then_retry", "head_of_line_blocking",
            "acknowledgement_for_another_entry_is_rejected", "repeated_release_reverifies_acknowledgement",
            "receipt_of_another_claim_is_rejected", "corrupt_receipt_signature_is_rejected",
            "resume_replaces_lost_allow_handoff", "resume_abandoned_claim", "crash_after_claim_lease_recovery")
        val scenarios = corpus.arr("scenarios").filter { it.getString("name") in names }
        assertEquals(names.size, scenarios.size)
        val counts = mapOf("allow_published_acknowledged_released" to 6, "release_without_receipt_is_pending" to 2,
            "release_without_acknowledgement_is_pending_then_late_ack_releases" to 7,
            "late_ack_at_challenge_expiry_is_withheld" to 6, "release_one_second_before_challenge_expiry" to 4,
            "release_at_challenge_expiry_is_withheld" to 4, "release_at_allow_horizon_is_withheld" to 4,
            "release_before_allow_horizon" to 3, "signer_failure_then_retry" to 5, "head_of_line_blocking" to 8,
            "acknowledgement_for_another_entry_is_rejected" to 4, "repeated_release_reverifies_acknowledgement" to 5,
            "receipt_of_another_claim_is_rejected" to 7, "corrupt_receipt_signature_is_rejected" to 5,
            "resume_replaces_lost_allow_handoff" to 5, "resume_abandoned_claim" to 6,
            "crash_after_claim_lease_recovery" to 9)
        val stepKeys = mapOf("verify" to setOf("op", "request", "expect"),
            "publish" to setOf("op", "request", "mode", "expect"),
            "release" to setOf("op", "request", "checkpoint", "expect"),
            "set_time" to setOf("op", "time", "expect"),
            "set_ack_withheld" to setOf("op", "withheld", "expect"),
            "resume" to setOf("op", "request", "expect"),
            "abandon" to setOf("op", "expect"), "claim_only" to setOf("op", "request", "expect"),
            "recover" to setOf("op", "request", "expect"))
        val keys = Corpus.load("keys.json").getJSONArray("keys")
        val verifier = (0 until keys.length()).asSequence().map(keys::getJSONObject)
            .first { it.getString("name") == corpus.getString("verifier_key") }
        val key = SoftwarePrivateKey.fromSeeds(verifier.hex("ed25519_seed_hex"), verifier.hex("ml_dsa_65_seed_hex"))
        val logId = corpus.getString("log_id")
        for (scenario in scenarios) {
            val name = scenario.getString("name")
            assertEquals(name, counts[name], scenario.arr("steps").size)
            val store = ReferenceStore(scenario.getLong("start_time"), corpus.getLong("lease_seconds"), logId, key)
            val committed = mutableMapOf<String, CommittedOutcome>()
            val claimed = mutableMapOf<String, ChallengeClaim>()
            val receipts = mutableMapOf<String, ByteArray>()
            val publishedWires = mutableMapOf<String, ByteArray>()
            for ((index, step) in scenario.arr("steps").withIndex()) {
                val op = step.getString("op")
                val requestName = step.optString("request")
                val want = step.getJSONObject("expect")
                val at = "$name step $index $op"
                val expectedStepKeys = stepKeys[op].orEmpty() + if (op == "release" && step.has("receipt_of"))
                    setOf("receipt_of") else emptySet()
                assertEquals(at, expectedStepKeys, step.keys().asSequence().toSet())
                when (op) {
                    "set_time" -> {
                        store.setTime(step.getLong("time"))
                        assertEquals(at, 0, want.length())
                    }
                    "set_ack_withheld" -> {
                        store.setAcknowledgementWithheld(step.getBoolean("withheld"))
                        assertEquals(at, 0, want.length())
                    }
                    "claim_only" -> {
                        assertEquals(at, setOf("disposition"), want.keys().asSequence().toSet())
                        val req = request(requestName, corpusName = "lifecycle-scenarios.json")
                        val expected = checkNotNull(req.expected) { at }
                        val bundle = decodeProofBundle(req.bundle)
                        org.junit.Assert.assertTrue(at, bundle.delegations.all { it.constraints.isEmpty() })
                        val hash = bundleHash(bundle)
                        val claim = ChallengeClaim(protocolClaimId(expected.verifierNamespace, expected.replayEpoch, expected.value),
                            expected.verifierNamespace, expected.replayEpoch, "sha384:" + challengeClaimDigest(expected.value).hex(),
                            hash, hash, bundle.delegations.map { it.issuerId }.distinct().sorted(), req.requiredScope,
                            req.contextPolicy?.digest ?: "", expected.verifierId, bundle.agentId, false, emptyList(),
                            expected.issuedAt, expected.expiresAt, req.maxChallengeAgeSeconds, req.futureSkewSeconds,
                            bundle.streamId, bundle.streamSeq, emptyList())
                        claimed[requestName] = claim
                        assertEquals(at, want.getString("disposition"), store.claim(claim).disposition.spelling)
                    }
                    "verify" -> {
                        assertEquals(at, if (want.has("decision"))
                            setOf("stage", "decision", "decision_reason", "allow_horizon")
                            else setOf("stage", "disposition"), want.keys().asSequence().toSet())
                        val fixtureRequest = request(requestName, corpusName = "lifecycle-scenarios.json")
                        val currentTime = store.now()
                        if (name == "crash_after_claim_lease_recovery" && index == 6) {
                            assertEquals(at, scenario.getLong("start_time"), fixtureRequest.now)
                            assertEquals(at, 1_800_000_030L, currentTime)
                        } else assertEquals(at, fixtureRequest.now, currentTime)
                        val req = if (fixtureRequest.now == currentTime) fixtureRequest
                            else request(requestName, corpusName = "lifecycle-scenarios.json", atTime = currentTime)
                        val (trust, status, journal) = vectorProviders(corpus.getJSONObject("requests").getJSONObject(requestName), req)
                        val result = verifyProofBundle(req, store, trust = trust, statusEvidence = status, statusJournal = journal)
                        assertEquals(at, want.getString("stage"), result.stage.spelling)
                        claimed[requestName]?.let { assertEquals(at, it, result.claim) }
                        if (want.has("disposition")) assertEquals(at, want.getString("disposition"), result.disposition?.spelling)
                        else assertEquals(at, ClaimDisposition.CREATED, result.disposition)
                        if (want.has("decision")) {
                            val value = checkNotNull(result.committed) { at }
                            committed[requestName] = value
                            val body = JSONObject(String(value.receiptBody))
                            assertEquals(at, want.getString("decision"), body.getString("decision"))
                            assertEquals(at, want.getString("decision_reason"), body.getString("decision_reason"))
                            assertEquals(at, want.getLong("allow_horizon"), value.allowHorizon)
                        } else assertEquals(at, null, result.committed)
                    }
                    "resume" -> {
                        assertEquals(at, setOf("stage", "decision", "decision_reason", "allow_horizon"),
                            want.keys().asSequence().toSet())
                        assertEquals(at, "committed", want.getString("stage"))
                        val claimId = checkNotNull(committed[requestName]) { at }.claimId
                        val value = resumeCommittedClaim(store, claimId)
                        committed[requestName] = value
                        val body = JSONObject(String(value.receiptBody))
                        assertEquals(at, want.getString("decision"), body.getString("decision"))
                        assertEquals(at, want.getString("decision_reason"), body.getString("decision_reason"))
                        assertEquals(at, want.getLong("allow_horizon"), value.allowHorizon)
                    }
                    "recover" -> {
                        val claimId = checkNotNull(claimed[requestName]) { at }.claimId
                        if (want.has("error_class")) {
                            assertEquals(at, setOf("error_class"), want.keys().asSequence().toSet())
                            try {
                                recoverInterruptedClaim(store, claimId)
                                fail("$at: recovery unexpectedly succeeded")
                            } catch (e: RatifyException.Protocol) {
                                assertEquals(at, want.getString("error_class"), e.errorClass.spelling)
                            }
                        } else {
                            assertEquals(at, setOf("stage", "decision", "decision_reason", "trust_assessment",
                                "status_assessment", "context_assessment"), want.keys().asSequence().toSet())
                            assertEquals(at, "committed", want.getString("stage"))
                            val value = recoverInterruptedClaim(store, claimId)
                            committed[requestName]?.let { org.junit.Assert.assertArrayEquals(at, it.receiptBody, value.receiptBody) }
                            committed[requestName] = value
                            val body = JSONObject(String(value.receiptBody))
                            for (field in listOf("decision", "decision_reason", "trust_assessment", "status_assessment", "context_assessment"))
                                assertEquals(at, want.getString(field), body.getString(field))
                            assertEquals(at, null, value.allowHorizon)
                        }
                    }
                    "abandon" -> {
                        assertEquals(at, setOf("abandoned"), want.keys().asSequence().toSet())
                        val expectedIds = want.getJSONArray("abandoned").strings().map {
                            checkNotNull(committed[it]) { at }.claimId
                        }
                        assertEquals(at, expectedIds, store.abandonPendingReceipts())
                    }
                    "publish" -> {
                        assertEquals(at, if (want.has("failed")) setOf("failed", "publish_error")
                            else setOf("receipt_sequence"), want.keys().asSequence().toSet())
                        val mode = step.getString("mode")
                        org.junit.Assert.assertTrue(at, mode in setOf("ok", "signer_failure", "corrupt_signature"))
                        if (mode == "signer_failure") assertEquals(at, "signer_unavailable", want.getString("publish_error"))
                        if (mode == "corrupt_signature") org.junit.Assert.assertFalse(at, want.has("failed"))
                        val value = checkNotNull(committed[requestName]) { at }
                        if (mode == "signer_failure") store.setSignerFailure(true)
                        if (want.has("failed")) {
                            org.junit.Assert.assertTrue(at, want.getBoolean("failed"))
                            val failureCode = want.getString("publish_error")
                            val messages = mapOf("signer_unavailable" to "v2reference: receipt signer unavailable",
                                "head_of_line_blocked" to "v2reference: an earlier receipt-log entry is still pending",
                                "log_frozen" to "v2reference: the receipt log is frozen after abandonment")
                            val expected = checkNotNull(messages[failureCode]) { at }
                            if (mode == "ok") org.junit.Assert.assertTrue(at,
                                failureCode == "head_of_line_blocked" || failureCode == "log_frozen")
                            try {
                                store.publish(value.claimId, value.receiptBody)
                                fail("$at: publication unexpectedly succeeded")
                            } catch (e: StoreError.Unavailable) {
                                assertEquals(at, expected, e.message)
                            }
                        } else {
                            val wire = store.publish(value.claimId, value.receiptBody)
                            publishedWires[requestName]?.let { org.junit.Assert.assertArrayEquals(at, it, wire) }
                            publishedWires[requestName] = wire
                            assertEquals(at, want.getLong("receipt_sequence"), decodeVerificationReceipt(wire).sequence)
                            receipts[requestName] = if (mode == "corrupt_signature") corruptReceiptSignature(wire) else wire
                        }
                        if (mode == "signer_failure") store.setSignerFailure(false)
                    }
                    "release" -> {
                        val checkpointMode = step.getString("checkpoint")
                        org.junit.Assert.assertTrue(at, checkpointMode == "reference" || checkpointMode == "wrong_entry")
                        assertEquals(at, if (want.has("decision"))
                            setOf("release_status", "decision", "release_time", "receipt_sequence")
                            else setOf("release_status", "release_reason"), want.keys().asSequence().toSet())
                        val value = checkNotNull(committed[requestName]) { at }
                        val checkpoint: ReceiptCheckpoint = if (checkpointMode == "wrong_entry") WrongEntryCheckpoint(store) else store
                        val receiptName = if (step.has("receipt_of")) step.getString("receipt_of") else requestName
                        if (step.has("receipt_of")) {
                            org.junit.Assert.assertNotEquals(at, requestName, receiptName)
                            checkNotNull(receipts[receiptName]) { at }
                        }
                        val result = releaseDecision(value, receipts[receiptName], key.publicKey, logId, store, checkpoint)
                        assertEquals(at, want.getString("release_status"), result.status.spelling)
                        if (want.has("release_reason")) assertEquals(at, want.getString("release_reason"), result.reason)
                        else assertEquals(at, "", result.reason)
                        if (want.has("decision")) {
                            val decision = checkNotNull(result.decision) { at }
                            assertEquals(at, want.getString("decision"), decision.decision)
                            org.junit.Assert.assertArrayEquals(at, checkNotNull(receipts[requestName]) { at }, decision.receiptWire)
                            assertEquals(at, want.getLong("release_time"), decision.releaseTime)
                            assertEquals(at, want.getLong("receipt_sequence"), decodeVerificationReceipt(decision.receiptWire).sequence)
                        } else assertEquals(at, null, result.decision)
                    }
                    else -> error("$at: unsupported operation")
                }
            }
        }
    }
}
