package com.ratifyprotocol

import com.ratifyprotocol.testing.Store
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/** Fixture authoring through the public Kotlin signing, verifier and release APIs. */
class KotlinCrossSdkGeneratorTest {
    @Test fun generateWhenRequested() = runBlocking {
        HostVectorsTest.setUpCorpus()
        if (System.getenv("RATIFY_GENERATE_KOTLIN_FIXTURE") == "1") {
            val fixture = KotlinCrossSdkGenerator().generate()
            val root = File(System.getProperty("ratify.corpus")!!)
            File(root, "v2/cross-sdk/kotlin.json").writeText(fixture.toString(2) + "\n")
        }
        val fixture = Corpus.load("cross-sdk/kotlin.json")
        assertEquals("kotlin", fixture.getString("sdk"))
        assertEquals(11, fixture.arr("keys").size)
        assertEquals(15, fixture.arr("objects").size)
        assertEquals(4, fixture.arr("scenarios").size)
    }
}

private class KotlinCrossSdkGenerator {
    companion object {
        const val NOW = 1_800_000_000L
        const val WORKSPACE = "00000000-0000-4000-8000-000000000001"
        val NAMES = listOf("root", "intermediate", "agent", "verifier", "status_root", "status_intermediate",
            "witness", "party_b_root", "party_b_agent", "rotation_genesis", "rotation_second")
        val EMPTY_SIGNATURE = HybridSignature(byteArrayOf(), byteArrayOf())
    }

    private val random = SecureRandom()
    private val keys = linkedMapOf<String, SoftwarePrivateKey>()
    private val entries = JSONArray()
    private val objects = JSONArray()

    init {
        for (name in NAMES) {
            val ed = ByteArray(32).also(random::nextBytes)
            val ml = ByteArray(32).also(random::nextBytes)
            val key = SoftwarePrivateKey.fromSeeds(ed, ml)
            keys[name] = key
            entries.put(obj("name" to name, "ed25519_seed_hex" to ed.hex(), "ml_dsa_65_seed_hex" to ml.hex(),
                "public_key" to json(key.publicKey), "key_id_v2" to key.keyId,
                "v1_key_id_128" to sha256(key.publicKey.ed25519 + key.publicKey.mlDsa65).hex().take(32)))
        }
    }

    private fun key(name: String) = keys.getValue(name)
    private fun id(name: String) = key(name).keyId
    private fun pub(name: String) = key(name).publicKey
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun json(key: HybridPublicKey) = obj("ed25519" to b64(key.ed25519), "ml_dsa_65" to b64(key.mlDsa65))
    private fun json(sig: HybridSignature) = obj("ed25519" to b64(sig.ed25519), "ml_dsa_65" to b64(sig.mlDsa65))
    private fun obj(vararg fields: Pair<String, Any?>): JSONObject = JSONObject().also { o ->
        for ((k, v) in fields) o.put(k, v ?: JSONObject.NULL)
    }
    private fun array(values: Iterable<*>): JSONArray = JSONArray().also { a -> values.forEach(a::put) }

    private fun signatureRecord(wire: ByteArray, field: String, code: Int, signer: String): JSONObject {
        val raw = JSONObject(String(wire, Charsets.UTF_8))
        val carried = when {
            field.startsWith("delegations[") -> raw.getJSONArray("delegations").getJSONObject(field.substringAfter('[').substringBefore(']').toInt())
                .getJSONObject("signature")
            field.startsWith("party_signatures[") -> {
                val party = field.substringAfter('[').substringBefore(']')
                val sigs = raw.getJSONArray("party_signatures")
                (0 until sigs.length()).map(sigs::getJSONObject).first { it.getString("party_id") == party }
                    .getJSONObject("signature")
            }
            else -> raw.getJSONObject(field)
        }
        val signable = projection(wire, field)
        val type = ObjectType.fromCode(code.toUShort())!!
        verifyStatement(type, signable, signatureOf(carried), pub(signer))
        val message = signingMessage(type, signable)
        val context = mldsaContext(type)
        val ml = pub(signer).mlDsa65
        return obj("field" to field, "object_type_code" to code, "signer" to signer,
            "signer_key_id_v2" to id(signer), "signable_b64" to b64(signable),
            "signable_sha384_hex" to sha384(signable).hex(), "message_b64" to b64(message),
            "mldsa_context" to String(context, Charsets.UTF_8),
            "mldsa_tr_b64" to b64(Shake256.hash(ml, 64)),
            "mldsa_mu_b64" to b64(externalMu(ml, context, message)), "signature" to carried)
    }

    private fun add(name: String, kind: String, description: String, wire: ByteArray,
                    fields: List<Triple<String, Int, String>>, digests: JSONObject,
                    verify: JSONObject = obj(), bundle: ByteArray? = null) {
        val item = obj("name" to name, "kind" to kind, "description" to description,
            "wire_b64" to b64(wire), "verify" to verify, "digests" to digests,
            "signatures" to array(fields.map { signatureRecord(wire, it.first, it.second, it.third) }))
        if (bundle != null) item.put("bundle_b64", b64(bundle))
        if (kind == "receipt_bundle_binding") {
            verifyObject(kind, wire, bundle!!, verify, ::pub)
        } else {
            check(reencode(kind, wire).contentEquals(wire)) { "$name: noncanonical wire" }
            verifyObject(kind, wire, byteArrayOf(), verify, ::pub)
        }
        objects.put(item)
    }

    private fun cert(issuer: String, subject: String, certId: String, scope: List<String>,
                     constraints: List<Constraint> = emptyList()): DelegationCert = signDelegationCert(
        DelegationCert(2, certId, id(issuer), pub(issuer), id(subject), pub(subject), scope, constraints,
            NOW - 3600, NOW + 86400, EMPTY_SIGNATURE), key(issuer))

    private fun bundle(agent: String, certs: List<DelegationCert>, session: ByteArray?,
                       challenge: ByteArray = ByteArray(32) { (0xA0 + it).toByte() },
                       streamId: ByteArray? = null, streamSeq: Long? = null): ProofBundle = signProofBundle(
        ProofBundle(2, id("verifier"), id(agent), pub(agent), certs, ByteArray(48), challenge,
            NOW - 10, EMPTY_SIGNATURE, session, streamId, streamSeq), key(agent))

    private fun statusList(issuer: String, statusKey: String, sequence: Long, next: Long,
                           revoked: List<String>): RevocationList = signRevocationList(
        RevocationList(2, id(issuer), NOW - 60, next, sequence, revoked, EMPTY_SIGNATURE),
        id(issuer), pub(statusKey), key(statusKey))

    private fun constraint(kind: String, start: String = "", end: String = "", tz: String = "",
                           currency: String = "", amount: Long = 0, count: Long = 0,
                           window: Long = 0, resource: String = "", path: String = "",
                           params: Map<String, ParamsValue>? = null) = Constraint(kind, start, end, tz,
        currency, amount, count, window, resource, path, params)

    private data class Inputs(val plain: ProofBundle, val extended: ProofBundle, val root: DelegationCert,
                              val leaf: DelegationCert, val rootList: RevocationList,
                              val intermediateList: RevocationList, val session: ByteArray)

    private fun buildObjects(): Inputs {
        val root = cert("root", "intermediate", "cert-root", listOf("data:read", "files:read", "identity:delegate"))
        add("delegation_root_to_intermediate", "delegation_certificate", "Root delegates to an intermediate.",
            encodeDelegationCert(root), listOf(Triple("signature", 1, "root")),
            obj("issuer_key_id_v2" to id("root"), "subject_key_id_v2" to id("intermediate")))
        val constrained = cert("intermediate", "agent", "cert-leaf-constrained", listOf("data:read"), listOf(
            constraint("max_rate", count = 5, window = 60),
            constraint("ratify.receiver_audience", params = mapOf(
                "exact_receiver_ids" to ParamsValue.Array(listOf(ParamsValue.Str("receiver-1"))),
                "trust_domain_ids" to ParamsValue.Array(listOf(ParamsValue.Str("domain-a"))),
                "max_membership_age_seconds" to ParamsValue.Int(3600))),
            constraint("resource_path", resource = "customer/123", path = "/v1/customers/"),
            constraint("time_window", start = "22:00", end = "06:00", tz = "America/New_York"),
            constraint("max_amount", currency = "USD", amount = 2_500_000),
            constraint("com.ratifyprotocol.max_count", params = mapOf(
                "counter" to ParamsValue.Str("nodes"), "max" to ParamsValue.Int(10))),
        ))
        add("delegation_every_registered_constraint_and_extension", "delegation_certificate",
            "Every registered constraint and one extension.", encodeDelegationCert(constrained),
            listOf(Triple("signature", 1, "intermediate")),
            obj("issuer_key_id_v2" to id("intermediate"), "subject_key_id_v2" to id("agent")))
        val operation = OperationContext("data:read", "records.get", "customer/123", "/v1/customers/123")
        val session = buildSessionContext(SessionContextInputs(id("verifier"), WORKSPACE, id("agent"),
            "session-01", "invocation-01", operationContextHash(operation)))
        val leaf = cert("intermediate", "agent", "cert-leaf", listOf("data:read", "files:read"))
        val plain = bundle("agent", listOf(leaf, root), session)
        val chain = listOf(Triple("challenge_sig", 2, "agent"), Triple("delegations[0].signature", 1, "intermediate"),
            Triple("delegations[1].signature", 1, "root"))
        add("proof_bundle_two_link_bound_context", "proof_bundle", "Two-link chain with session context.",
            encodeProofBundle(plain), chain, obj("delegation_digest_hex" to plain.delegationDigest.hex(),
                "bundle_hash_v2" to bundleHash(plain), "session_context_hex" to session.hex(),
                "challenge_claim_digest_hex" to challengeClaimDigest(plain.challenge).hex(),
                "claim_id" to protocolClaimId("verify-test", 3, plain.challenge),
                "claim_verifier_namespace" to "verify-test", "claim_replay_epoch" to "3"))
        val extended = bundle("agent", listOf(constrained, root), session,
            challenge = ByteArray(32) { (0xB0 + it).toByte() })
        add("proof_bundle_constrained_chain", "proof_bundle", "Constrained chain with session context.",
            encodeProofBundle(extended), chain, obj("delegation_digest_hex" to extended.delegationDigest.hex(),
                "bundle_hash_v2" to bundleHash(extended), "session_context_hex" to session.hex()))
        val stream = bundle("agent", emptyList(), null, streamId = ByteArray(32) { 0x5a }, streamSeq = 1)
        add("proof_bundle_empty_chain_stream_bound", "proof_bundle", "Empty chain with a stream bound.",
            encodeProofBundle(stream), listOf(Triple("challenge_sig", 2, "agent")),
            obj("delegation_digest_hex" to stream.delegationDigest.hex(), "bundle_hash_v2" to bundleHash(stream)))

        val rootList = statusList("root", "status_root", 7, NOW + 3600, listOf("cert-a", "cert-b"))
        add("revocation_list_root", "revocation_list", "Root issuer status snapshot.", encodeRevocationList(rootList),
            listOf(Triple("signature", 3, "status_root")),
            obj("status_evidence_digest" to "sha384:${statusEvidenceDigest(rootList).hex()}"),
            verify = obj("bound_issuer_id" to id("root"), "status_key" to "status_root"))
        val intermediateList = statusList("intermediate", "status_intermediate", 1, NOW + 3600, emptyList())
        add("revocation_list_intermediate_empty", "revocation_list", "Empty intermediate issuer status snapshot.",
            encodeRevocationList(intermediateList), listOf(Triple("signature", 3, "status_intermediate")),
            obj("status_evidence_digest" to "sha384:${statusEvidenceDigest(intermediateList).hex()}"),
            verify = obj("bound_issuer_id" to id("intermediate"), "status_key" to "status_intermediate"))
        val push = signRevocationPush(RevocationPush(2, id("root"), 8, NOW - 30, listOf("cert-c"), EMPTY_SIGNATURE),
            id("root"), pub("status_root"), key("status_root"))
        add("revocation_push", "revocation_push", "Root issuer status push.", encodeRevocationPush(push),
            listOf(Triple("signature", 5, "status_root")),
            obj("status_evidence_digest" to "sha384:${statusEvidenceDigest(push).hex()}"),
            verify = obj("bound_issuer_id" to id("root"), "status_key" to "status_root"))
        return Inputs(plain, extended, root, leaf, rootList, intermediateList, session)
    }

    private fun buildStatements(input: Inputs) {
        val zeros = ByteArray(48)
        val authority = "0123456789abcdef0123456789abcdef"
        val rotation = signKeyRotationStatement(KeyRotationStatement(2, authority, 1, "issuer", 1,
            zeros, pub("rotation_genesis"), pub("rotation_second"), id("rotation_genesis"),
            id("rotation_second"), NOW - 600, NOW - 600, EMPTY_SIGNATURE, EMPTY_SIGNATURE),
            key("rotation_genesis"), key("rotation_second"))
        add("key_rotation_genesis", "key_rotation_statement", "Genesis hybrid key rotation.",
            encodeKeyRotationStatement(rotation), listOf(Triple("old_signature", 4, "rotation_genesis"),
                Triple("new_signature", 9, "rotation_second")),
            obj("statement_body_digest_hex" to keyRotationStatementDigest(rotation).hex()),
            verify = obj("rotation_state" to obj("authority_id" to authority, "recovery_epoch" to 1,
                "role" to "issuer", "sequence" to 0, "head_hash_b64" to b64(zeros),
                "current_key" to "rotation_genesis", "used_key_ids" to array(listOf(id("rotation_genesis")))),
                "now" to NOW, "future_skew_seconds" to 5))
        val witnessLog = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
        val witness = signWitnessEntry(WitnessEntry(2, witnessLog, 1, zeros, "entry-1".toByteArray(),
            NOW - 20, id("witness"), EMPTY_SIGNATURE), key("witness"))
        add("witness_entry_genesis", "witness_entry", "Genesis witness entry.", encodeWitnessEntry(witness),
            listOf(Triple("signature", 6, "witness")),
            obj("statement_body_digest_hex" to witnessEntryDigest(witness).hex()),
            verify = obj("witness_key" to "witness", "head" to obj("log_id" to witnessLog,
                "sequence" to 0, "head_hash_b64" to b64(zeros), "accepted_digests_b64" to obj(),
                "frozen" to false)))

        val terms = """{"amount":100,"currency":"USD","item":"widget"}""".toByteArray()
        val skeleton = TransactionReceipt(2, "tx-0001", NOW - 5, "https://example.com/terms/purchase/v1",
            terms, emptyList(), emptyList())
        val context = transactionContextHash(skeleton)
        val digests = obj("transaction_context_hex" to context.hex())
        val parties = mutableListOf<TransactionReceiptParty>()
        for ((party, role, agent, root, scope) in listOf(
            listOf("party-a", "buyer", "agent", "root", "transact:purchase"),
            listOf("party-b", "seller", "party_b_agent", "party_b_root", "transact:sell"))) {
            val request = transactionPartyRequestHash(context, scope)
            val session = buildSessionContext(SessionContextInputs(id("verifier"), WORKSPACE, id(agent),
                "session-$party", "invocation-$party", request))
            val partyBundle = bundle(agent, listOf(cert(root, agent, "cert-$party", listOf(scope))), session)
            val hash = bundleHash(partyBundle)
            parties += TransactionReceiptParty(party, role, id(agent), pub(agent), id("verifier"), WORKSPACE,
                "session-$party", "invocation-$party", scope, hash, partyBundle)
            digests.put("$party.transaction_party_request_hash_hex", request.hex())
            digests.put("$party.session_context_hex", session.hex())
            digests.put("$party.proof_bundle_hash", hash)
        }
        val unsigned = TransactionReceipt(2, "tx-0001", NOW - 5, "https://example.com/terms/purchase/v1",
            terms, parties, emptyList())
        val transaction = TransactionReceipt(2, "tx-0001", NOW - 5,
            "https://example.com/terms/purchase/v1", terms, parties,
            listOf(signTransactionReceiptParty(unsigned, "party-a", key("agent")),
                signTransactionReceiptParty(unsigned, "party-b", key("party_b_agent"))))
        add("transaction_receipt_two_parties", "transaction_receipt", "Two parties sign one transaction.",
            encodeTransactionReceipt(transaction), listOf(Triple("party_signatures[party-a]", 7, "agent"),
                Triple("party_signatures[party-b]", 7, "party_b_agent")), digests)

        val evidence = listOf(
            StatusEvidenceEntry(id("root"), id("status_root"), 7, 3u,
                "sha384:${statusEvidenceDigest(input.rootList).hex()}"),
            StatusEvidenceEntry(id("intermediate"), id("status_intermediate"), 1, 3u,
                "sha384:${statusEvidenceDigest(input.intermediateList).hex()}"),
        ).sortedWith(compareBy(StatusEvidenceEntry::issuerId, StatusEvidenceEntry::statusKeyId))
        addReceipt("verification_receipt_allow_genesis", input.plain,
            listOf("data:read", "files:read"), "cccccccccccccccccccccccccccccc01", evidence)
        val digest = constraintProfileDigest(ConstraintProfileDescriptor(
            "com.ratifyprotocol.max_count/v1", "com.ratifyprotocol.max_count"))
        addReceipt("verification_receipt_constraint_evaluators", input.extended,
            listOf("data:read"), "cccccccccccccccccccccccccccccc02", evidence,
            listOf(ConstraintEvaluatorRef("com.ratifyprotocol.max_count", digest)))
    }

    private fun addReceipt(name: String, bundle: ProofBundle, granted: List<String>, logId: String,
                           evidence: List<StatusEvidenceEntry>, evaluators: List<ConstraintEvaluatorRef> = emptyList()) {
        val zeros = ByteArray(48)
        val receipt = signVerificationReceipt(VerificationReceipt(2, logId, 1, id("verifier"), bundle.agentId,
            "", bundleHash(bundle), listOf(id("root"), id("intermediate")).sorted(), "allow", "authorized",
            "authorized_agent", "trusted", "current", "current", evaluators, "bound",
            "sha384:610c40faa472aa2a4f905988899733758cccf30f243aed35f1f42433228a28dbab1725cb2a4a6811029a8109da0b9b29",
            NOW, "data:read", granted, evidence, zeros, EMPTY_SIGNATURE), key("verifier"))
        val wire = encodeVerificationReceipt(receipt)
        add(name, "verification_receipt", "Signed genesis allow receipt.", wire,
            listOf(Triple("signature", 8, "verifier")),
            obj("statement_body_digest_hex" to verificationReceiptDigest(receipt).hex(),
                "receipt_outbox_body_b64" to b64(verificationReceiptBody(receipt))),
            verify = obj("verifier_key" to "verifier", "head" to obj("log_id" to logId,
                "verifier_id" to id("verifier"), "sequence" to 0, "head_hash_b64" to b64(zeros),
                "accepted_digests_b64" to obj(), "frozen" to false)))
        add("$name/bundle_binding", "receipt_bundle_binding", "Receipt bound to its proof bundle.",
            wire, emptyList(), obj(), bundle = encodeProofBundle(bundle))
    }

    private suspend fun scenario(name: String, description: String, first: Int,
                                 rootEvidence: RevocationList, intermediateEvidence: RevocationList?,
                                 input: Inputs, publishTime: Long, releaseTime: Long): JSONObject {
        val challenge = byteArrayOf(first.toByte()) + ByteArray(31) { (0xA1 + it).toByte() }
        val presented = bundle("agent", listOf(input.leaf, input.root), input.session, challenge)
        val wire = encodeProofBundle(presented)
        val fields = listOf("verifier_id", "workspace_id", "agent_id", "session_id", "invocation_id", "request_hash")
        val context = ContextPolicy("ratify.verify.session-context/v1", true, fields, input.session)
        val expected = ExpectedChallenge(challenge, NOW - 10, NOW + 290, "verify-test", 3,
            id("verifier"), id("agent"), pub("agent"), "", input.session)
        val journal = JournalVectors.Store()
        val statusKeys = linkedMapOf<String, StatusKeyConfig>()
        for ((issuer, statusKey) in listOf("root" to "status_root", "intermediate" to "status_intermediate")) {
            configureStatusKeyEpoch(journal, id(issuer), 1u, pub(statusKey))
            statusKeys[id(issuer)] = StatusKeyConfig(1u, pub(statusKey))
        }
        val policy = RevocationStatusPolicy(7200, 3660, 5)
        val request = VerifyRequest(wire, expected, context, "data:read", "verify-test", 3,
            id("verifier"), NOW, 300, 5, ConstraintContext(), "2025c", statusKeys, policy)
        val store = Store(NOW, 30, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01", key("verifier"))
        val evidence = linkedMapOf<String, List<StatusEvidenceObject>>(
            id("root") to listOf(StatusEvidenceObject(3u, encodeRevocationList(rootEvidence))))
        if (intermediateEvidence != null) evidence[id("intermediate")] =
            listOf(StatusEvidenceObject(3u, encodeRevocationList(intermediateEvidence)))
        val trust = object : TrustProvider {
            override suspend fun resolve(chain: List<DelegationCert>) = TrustResolution(TrustOutcome.TRUSTED, pub("root"))
        }
        val status = object : StatusEvidenceProvider {
            override suspend fun provide(request: StatusEvidenceRequest): List<StatusEvidenceObject> =
                evidence[request.issuerId] ?: emptyList()
        }
        val outcome = verifyProofBundle(request, store, trust = trust, statusEvidence = status, statusJournal = journal)
        check(outcome.stage == VerifyStage.COMMITTED) { "$name: ${outcome.errorDetail}" }
        val committed = checkNotNull(outcome.committed)
        store.setTime(publishTime)
        val published = store.publish(committed.claimId, committed.receiptBody)
        store.setTime(releaseTime)
        val result = releaseDecision(committed, published, pub("verifier"),
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01", store, store)
        val evidenceJson = obj()
        for ((issuer, values) in evidence) evidenceJson.put(issuer,
            array(values.map { obj("object_type_code" to it.objectType.toInt(), "wire_b64" to b64(it.wire)) }))
        val statusKeysJson = obj(id("root") to obj("epoch" to 1, "key" to "status_root"),
            id("intermediate") to obj("epoch" to 1, "key" to "status_intermediate"))
        val releaseJson = obj("status" to result.status.spelling,
            "reason" to result.reason.ifEmpty { null }, "decision" to result.decision?.decision,
            "release_time" to result.decision?.releaseTime)
        return obj("name" to name, "description" to description, "bundle_b64" to b64(wire),
            "required_scope" to "data:read",
            "expected_challenge" to obj("value_b64" to b64(challenge), "issued_at" to NOW - 10,
                "expires_at" to NOW + 290, "verifier_namespace" to "verify-test", "replay_epoch" to 3,
                "verifier_id" to id("verifier"), "expected_agent_id" to id("agent"),
                "expected_agent_public_key" to json(pub("agent")), "expected_receiver_id" to null,
                "expected_session_context_b64" to b64(input.session)),
            "context_policy" to obj("profile" to "ratify.verify.session-context/v1", "require_bound" to true,
                "required_fields" to array(fields), "expected_session_context_b64" to b64(input.session),
                "digest" to context.digest),
            "trust_root_key" to "root", "status_keys" to statusKeysJson, "status_evidence" to evidenceJson,
            "verify_time" to NOW, "publish_time" to publishTime, "release_time" to releaseTime,
            "expected" to obj("receipt_body_b64" to b64(committed.receiptBody),
                "allow_horizon" to committed.allowHorizon, "signed_receipt_b64" to b64(published),
                "release" to releaseJson))
    }

    suspend fun generate(): JSONObject {
        val input = buildObjects()
        buildStatements(input)
        val rootCurrent = statusList("root", "status_root", 1, NOW + 3600, emptyList())
        val rootShort = statusList("root", "status_root", 1, NOW + 60, emptyList())
        val intermediateCurrent = statusList("intermediate", "status_intermediate", 1, NOW + 3600, emptyList())
        val intermediateRevoked = statusList("intermediate", "status_intermediate", 1, NOW + 3600, listOf("cert-leaf"))
        val scenarios = array(listOf(
            scenario("allow_released", "An acknowledged allow is released.", 0xA1,
                rootCurrent, intermediateCurrent, input, NOW, NOW),
            scenario("deny_revoked_released", "A revoked leaf gives a non-actionable deny.", 0xA2,
                rootCurrent, intermediateRevoked, input, NOW, NOW),
            scenario("indeterminate_status_unavailable_released", "Missing status is indeterminate.", 0xA3,
                rootCurrent, null, input, NOW, NOW),
            scenario("allow_withheld_past_horizon", "The allow horizon expires before release.", 0xA4,
                rootShort, intermediateCurrent, input, NOW + 60, NOW + 60),
        ))
        return obj("version" to 2, "sdk" to "kotlin", "sdk_version" to "2.0.0-beta.2",
            "generator" to "RATIFY_GENERATE_KOTLIN_FIXTURE=1 ./gradlew :ratify-protocol:testDebugUnitTest --tests com.ratifyprotocol.KotlinCrossSdkGeneratorTest",
            "description" to "Fresh Kotlin SDK keys and hedged ML-DSA-65 signatures; verifier and release observations use the Kotlin public API.",
            "kind_object_type_codes" to obj("delegation_certificate" to 1, "proof_bundle" to 2,
                "revocation_list" to 3, "key_rotation_statement" to 4, "revocation_push" to 5,
                "witness_entry" to 6, "transaction_receipt" to 7, "verification_receipt" to 8),
            "keys" to entries, "objects" to objects,
            "scenario_configuration" to obj("verifier_namespace" to "verify-test", "replay_epoch" to 3,
                "verifier_key" to "verifier", "receipt_log_id" to "eeeeeeeeeeeeeeeeeeeeeeeeeeeeee01",
                "lease_seconds" to 30, "max_challenge_age_seconds" to 300, "future_skew_seconds" to 5,
                "status_policy" to obj("max_list_lifetime_seconds" to 7200, "max_status_age_seconds" to 3660,
                    "clock_skew_seconds" to 5), "tzdb_version" to "2025c"),
            "scenarios" to scenarios)
    }
}
