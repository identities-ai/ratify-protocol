package com.ratifyprotocol

import com.ratifyprotocol.testing.Store
import kotlinx.coroutines.runBlocking
import java.util.Base64

/** Replays the object half of every cross-SDK fixture through Kotlin's public API. */
object CrossSdkObjectVectors {
    fun run() {
        val names = Corpus.list("v2/cross-sdk").filter { it.endsWith(".json") }.sorted()
        check(names.toSet() == setOf("c", "go", "python", "rust", "typescript").map { "$it.json" }.toSet())
        val tally = Tally("cross-sdk-objects")
        var keyCount = 0
        var objectCount = 0
        var signatureCount = 0
        var digestCount = 0
        for (file in names) {
            val sdk = file.removeSuffix(".json")
            val fixture = Corpus.load("cross-sdk/$file")
            tally.check("files", sdk, fixture.getString("sdk") == sdk)
            check(fixture.arr("keys").size == 11 && fixture.arr("objects").size == 15) { "$file shape changed" }
            val keys = mutableMapOf<String, HybridPublicKey>()
            val ids = mutableMapOf<String, String>()
            for (entry in fixture.arr("keys")) {
                keyCount++
                val name = entry.getString("name")
                val derived = SoftwarePrivateKey.fromSeeds(entry.hex("ed25519_seed_hex"), entry.hex("ml_dsa_65_seed_hex"))
                val pinned = publicKeyOf(entry.getJSONObject("public_key"))
                val id = entry.getString("key_id_v2")
                keys[name] = pinned
                ids[name] = id
                val independent = sha256("ratify-key-id-v2".toByteArray() + byteArrayOf(0) +
                    pinned.ed25519 + pinned.mlDsa65).hex()
                tally.check("keys", "$sdk/$name", derived.publicKey == pinned &&
                    derived.keyId == id && independent == id)
            }
            for (obj in fixture.arr("objects")) {
                objectCount++
                val name = obj.getString("name")
                val kind = obj.getString("kind")
                val wire = obj.b64("wire_b64")
                val at = "$sdk/$name"
                val encoded = if (kind == "receipt_bundle_binding")
                    encodeVerificationReceipt(decodeVerificationReceipt(wire)) else reencode(kind, wire)
                tally.check("objects", at, encoded.contentEquals(wire))
                val result = classOf { verifyObject(kind, wire, obj.optB64("bundle_b64"),
                    obj.getJSONObject("verify"), { keys.getValue(it) }) }
                tally.check("verify", at, result == "ok") { result }
                val wireText = String(wire, Charsets.UTF_8)
                for (sig in obj.arr("signatures")) {
                    signatureCount++
                    val field = sig.getString("field")
                    val signer = sig.getString("signer")
                    val type = ObjectType.fromCode(sig.getInt("object_type_code").toUShort())!!
                    val signable = sig.b64("signable_b64")
                    val message = signingMessage(type, signable)
                    val context = mldsaContext(type)
                    val key = keys.getValue(signer)
                    val pinned = signatureOf(sig.getJSONObject("signature"))
                    val verified = classOf { verifyStatement(type, signable, pinned, key) }
                    val ok = projection(wire, field).contentEquals(signable) &&
                        sha384(signable).hex() == sig.getString("signable_sha384_hex") &&
                        message.contentEquals(sig.b64("message_b64")) && message.size == 77 &&
                        String(context, Charsets.UTF_8) == sig.getString("mldsa_context") && context.size == 22 &&
                        ids[signer] == sig.getString("signer_key_id_v2") &&
                        Shake256.hash(key.mlDsa65, 64).contentEquals(sig.b64("mldsa_tr_b64")) &&
                        externalMu(key.mlDsa65, context, message).contentEquals(sig.b64("mldsa_mu_b64")) &&
                        wireText.contains(Base64.getEncoder().encodeToString(pinned.ed25519)) &&
                        wireText.contains(Base64.getEncoder().encodeToString(pinned.mlDsa65)) && verified == "ok"
                    tally.check("signatures", "$at/$field", ok) { verified }
                }
                val digests = obj.getJSONObject("digests")
                for (digestName in digests.keys()) {
                    val got = ObjectsVectors.objectDigest(digestName, kind, wire, digests) ?: continue
                    digestCount++
                    tally.check("digests", "$at/$digestName", got == digests.getString(digestName)) {
                        "got $got, want ${digests.getString(digestName)}"
                    }
                }
            }
        }
        tally.finish(listOf("files" to names.size, "keys" to keyCount, "objects" to objectCount,
            "verify" to objectCount, "signatures" to signatureCount, "digests" to digestCount))
    }

    fun scenarios() = runBlocking {
        val names = Corpus.list("v2/cross-sdk").filter { it.endsWith(".json") }.sorted()
        val tally = Tally("cross-sdk-scenarios")
        var count = 0
        for (file in names) {
            val fixture = Corpus.load("cross-sdk/$file")
            val cfg = fixture.getJSONObject("scenario_configuration")
            check(fixture.arr("scenarios").map { it.getString("name") }.toSet() == setOf(
                "allow_released", "deny_revoked_released", "indeterminate_status_unavailable_released",
                "allow_withheld_past_horizon")) { "$file scenario set changed" }
            val keys = fixture.arr("keys").associate { entry ->
                entry.getString("name") to SoftwarePrivateKey.fromSeeds(
                    entry.hex("ed25519_seed_hex"), entry.hex("ml_dsa_65_seed_hex"),
                )
            }
            val policy = cfg.getJSONObject("status_policy")
            for (scenario in fixture.arr("scenarios")) {
                count++
                val at = "$file/${scenario.getString("name")}"
                val verifier = keys.getValue(cfg.getString("verifier_key"))
                val store = Store(scenario.getLong("verify_time"), cfg.getLong("lease_seconds"),
                    cfg.getString("receipt_log_id"), verifier)
                val journal = JournalVectors.Store()
                val statusKeys = linkedMapOf<String, StatusKeyConfig>()
                val rawStatusKeys = scenario.getJSONObject("status_keys")
                for (issuer in rawStatusKeys.keys().asSequence().sorted()) {
                    val binding = rawStatusKeys.getJSONObject(issuer)
                    val key = keys.getValue(binding.getString("key")).publicKey
                    val epoch = binding.getLong("epoch").toULong()
                    configureStatusKeyEpoch(journal, issuer, epoch, key)
                    statusKeys[issuer] = StatusKeyConfig(epoch, key)
                }
                val rawChallenge = scenario.getJSONObject("expected_challenge")
                val expectedKey = rawChallenge.optJSONObject("expected_agent_public_key")?.let(::publicKeyOf)
                val expected = ExpectedChallenge(rawChallenge.b64("value_b64"),
                    rawChallenge.getLong("issued_at"), rawChallenge.getLong("expires_at"),
                    rawChallenge.getString("verifier_namespace"), rawChallenge.getLong("replay_epoch"),
                    rawChallenge.getString("verifier_id"),
                    if (rawChallenge.isNull("expected_agent_id")) "" else rawChallenge.getString("expected_agent_id"),
                    expectedKey,
                    if (rawChallenge.isNull("expected_receiver_id")) "" else rawChallenge.getString("expected_receiver_id"),
                    if (rawChallenge.isNull("expected_session_context_b64")) null else rawChallenge.b64("expected_session_context_b64"),
                )
                val rawContext = scenario.optJSONObject("context_policy")
                val context = rawContext?.let { raw -> ContextPolicy(raw.getString("profile"),
                    raw.getBoolean("require_bound"), raw.strings("required_fields"),
                    if (raw.isNull("expected_session_context_b64")) ByteArray(0) else raw.b64("expected_session_context_b64")) }
                if (rawContext != null) tally.check("policy", at, context!!.digest == rawContext.getString("digest"))
                val statusPolicy = RevocationStatusPolicy(policy.getLong("max_list_lifetime_seconds"),
                    policy.getLong("max_status_age_seconds"), policy.getLong("clock_skew_seconds"))
                val request = VerifyRequest(scenario.b64("bundle_b64"), expected, context,
                    scenario.getString("required_scope"), cfg.getString("verifier_namespace"),
                    cfg.getLong("replay_epoch"), verifier.keyId, scenario.getLong("verify_time"),
                    cfg.getLong("max_challenge_age_seconds"), cfg.getLong("future_skew_seconds"),
                    ConstraintContext(), cfg.getString("tzdb_version"), statusKeys, statusPolicy)
                val root = keys.getValue(scenario.getString("trust_root_key")).publicKey
                val trust = object : TrustProvider {
                    override suspend fun resolve(chain: List<DelegationCert>) = TrustResolution(TrustOutcome.TRUSTED, root)
                }
                val rawEvidence = scenario.getJSONObject("status_evidence")
                val evidence = rawEvidence.keys().asSequence().associateWith { issuer ->
                    val values = rawEvidence.getJSONArray(issuer)
                    List(values.length()) { index ->
                        val item = values.getJSONObject(index)
                        StatusEvidenceObject(item.getInt("object_type_code").toUShort(), item.b64("wire_b64"))
                    }
                }
                val status = object : StatusEvidenceProvider {
                    override suspend fun provide(request: StatusEvidenceRequest): List<StatusEvidenceObject> =
                        evidence[request.issuerId] ?: emptyList()
                }
                val outcome = verifyProofBundle(request, store, trust = trust, statusEvidence = status, statusJournal = journal)
                val committed = requireNotNull(outcome.committed) { "$at: ${outcome.errorDetail}" }
                val want = scenario.getJSONObject("expected")
                tally.check("committed", at, outcome.stage == VerifyStage.COMMITTED &&
                    committed.receiptBody.contentEquals(want.b64("receipt_body_b64")) &&
                    committed.allowHorizon == (if (want.isNull("allow_horizon")) null else want.getLong("allow_horizon")))
                store.setTime(scenario.getLong("publish_time"))
                val published = store.publish(committed.claimId, committed.receiptBody)
                val receipt = decodeVerificationReceipt(published)
                val head = ReceiptHead(cfg.getString("receipt_log_id"), verifier.keyId, 0, ByteArray(48))
                tally.check("published", at, verificationReceiptBody(receipt).contentEquals(committed.receiptBody) &&
                    verifyVerificationReceipt(receipt, verifier.publicKey, head) == LogResult.APPENDED)
                store.setTime(scenario.getLong("release_time"))
                val result = releaseDecision(committed, want.b64("signed_receipt_b64"), verifier.publicKey,
                    cfg.getString("receipt_log_id"), store, store)
                val release = want.getJSONObject("release")
                tally.check("release", at, result.status.spelling == release.getString("status") &&
                    result.reason == (if (release.isNull("reason")) "" else release.getString("reason")) &&
                    result.decision?.decision == (if (release.isNull("decision")) null else release.getString("decision")) &&
                    result.decision?.releaseTime == (if (release.isNull("release_time")) null else release.getLong("release_time")))
            }
        }
        tally.finish(listOf("policy" to count, "committed" to count, "published" to count, "release" to count))
    }
}
