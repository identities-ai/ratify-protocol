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

    private fun request(name: String, evaluators: ConstraintEvaluatorRegistry? = null): VerifyRequest {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
        val corpus = Corpus.load("verifier-ordering.json")
        val vector = corpus.arr("vectors").first { it.getString("name") == name }
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

    @Test fun verifierCorpusPreflightOrdering() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector ->
            vector.getJSONObject("expected").getString("stage") == "preflight" &&
            vector.getString("claim_store") != "absent"
        }
        assertEquals(145, vectors.size)
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
            val outcome = verifyProofBundle(req, store, receiverBinding = hook)
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

    @Test fun verifierCorpusReplay() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
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

    @Test fun verifierCorpusFinalizationRefusals() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
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

    @Test fun verifierCorpusCommittedReceipts() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { File(root, it).readBytes() }
        val vectors = Corpus.load("verifier-ordering.json").arr("vectors").filter { vector ->
            val trust = vector.optJSONObject("trust") ?: JSONObject()
            val journal = vector.optJSONObject("journal") ?: JSONObject()
            val evidence = vector.optJSONObject("status_evidence") ?: JSONObject()
            vector.getJSONObject("expected").getString("stage") == "committed" &&
                vector.getString("claim_store") == "create" &&
                (vector.isNull("trust") || trust.optString("mode") in listOf("error", "registry") ||
                    trust.optString("mode") == "ok" &&
                    TrustOutcome.fromSpelling(trust.optString("outcome")) != null) &&
                vector.getString("audience_mode") in listOf("ok", "error") &&
                vector.getString("rate") in listOf("absent", "reserve", "exceeded", "unavailable") &&
                journal.optString("mode") in listOf("anchored", "absent", "unanchored", "load_error",
                    "cas_conflict", "cas_conflict_once") &&
                (vector.optJSONArray("constraint_evaluators")?.let { array ->
                    (0 until array.length()).none { index ->
                        array.getJSONObject(index).getString("implementation") == "fault:panic"
                    }
                } ?: true) &&
                vector.getString("receiver_binding_hook") in listOf("absent", "accept") &&
                evidence.keys().asSequence().all { issuer ->
                    evidence.getJSONObject(issuer).optString("mode") != "panic"
                }
        }
        assertEquals(357, vectors.size)
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
            val outcome = verifyProofBundle(req, baseStore, trust = trust, audience = audience,
                receiverBinding = receiver, statusEvidence = status, statusJournal = journalStore, rate = rate)
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
