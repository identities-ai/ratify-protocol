package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import org.json.JSONObject

object TransactionVerifyVectors {
    private class Journal : SecurityJournalStore {
        private var current = emptySecurityJournalSnapshot()
        override suspend fun load(): SecurityJournalSnapshot = synchronized(this) { current }
        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            synchronized(this) {
                if (current.head != expected) throw SecurityJournalStoreError.Conflict()
                current = next
            }
        }
    }

    fun run() = runBlocking {
        val vectors = Corpus.load("transaction-verification.json").arr("vectors")
        val tally = Tally("transaction-verification.json")
        for (v in vectors) {
            val name = v.getString("name")
            val journalScript = v.getJSONObject("journal")
            val evidenceScripts = v.getJSONObject("status_evidence")
            val modesSupported = journalScript.getString("mode") == "anchored" &&
                journalScript.arr("preload").isEmpty() && !journalScript.has("setup") &&
                (v.optJSONObject("trust")?.getString("mode") ?: "ok") == "ok" &&
                evidenceScripts.keys().asSequence().all { evidenceScripts.getJSONObject(it).getString("mode") == "ok" }
            if (!modesSupported) {
                tally.check("vectors", name, false) { "unsupported fixture mode" }
                continue
            }
            val policy = v.getJSONObject("status_policy")
            val keyObject = v.getJSONObject("status_keys")
            val keys = keyObject.keys().asSequence().associateWith { issuer ->
                val item = keyObject.getJSONObject(issuer)
                StatusKeyConfig(item.getLong("epoch").toULong(), publicKeyOf(item.getJSONObject("public_key")))
            }
            val request = TransactionVerifyRequest(v.b64("receipt_b64"), v.getLong("now"),
                v.getLong("future_skew_seconds"), keys,
                RevocationStatusPolicy(policy.getLong("max_list_lifetime_seconds"),
                    policy.getLong("max_status_age_seconds"), policy.getLong("clock_skew_seconds")))
            val journal = Journal()
            for (issuer in keys.keys.sorted()) {
                val key = keys.getValue(issuer)
                configureStatusKeyEpoch(journal, issuer, key.epoch, key.key)
            }
            val scripts = v.getJSONObject("status_evidence")
            val evidence = scripts.keys().asSequence().associateWith { issuer ->
                scripts.getJSONObject(issuer).arr("objects").map {
                    StatusEvidenceObject(it.getInt("object_type_code").toUShort(), it.b64("wire_b64"))
                }
            }
            val status = object : StatusEvidenceProvider {
                override suspend fun provide(request: StatusEvidenceRequest): List<StatusEvidenceObject> =
                    evidence[request.issuerId] ?: emptyList()
            }
            val trustScript = v.optJSONObject("trust")
            val trust = trustScript?.let { script ->
                val outcome = TrustOutcome.entries.single { it.spelling == script.getString("outcome") }
                val key = script.optJSONObject("root_public_key")?.let(::publicKeyOf)
                    ?: HybridPublicKey(ByteArray(0), ByteArray(0))
                object : TrustProvider {
                    override suspend fun resolve(chain: List<DelegationCert>) = TrustResolution(outcome, key)
                }
            }
            val expected = v.getJSONObject("expected")
            try {
                val got = verifyTransactionReceipt(request, trust, status, journal)
                val error = expected.optString("error_class")
                if (error.isNotEmpty()) {
                    tally.check("vectors", name, false) { "expected $error, got success" }
                    continue
                }
                val result = expected.getJSONObject("result")
                val wantParties = result.arr("parties")
                val partiesMatch = got.parties.size == wantParties.size &&
                    got.parties.zip(wantParties).all { (p, w) ->
                        val wantEvidence = w.arr("status_evidence_digests")
                        p.partyId == w.getString("party_id") && p.agentId == w.getString("agent_id") &&
                            p.requiredScope == w.getString("required_scope") &&
                            p.trustAssessment == w.getString("trust_assessment") &&
                            p.delegationAssessment == w.getString("delegation_assessment") &&
                            p.delegationExpiresAt == w.optLong("delegation_expires_at").takeIf { !w.isNull("delegation_expires_at") } &&
                            p.statusAssessment == w.getString("status_assessment") &&
                            p.scopeAssessment == w.getString("scope_assessment") && p.freshness == w.getString("freshness") &&
                            p.statusEvidence.size == wantEvidence.size && p.statusEvidence.zip(wantEvidence).all { (e, x) ->
                                e.issuerId == x.getString("issuer_id") && e.statusKeyId == x.getString("status_key_id") &&
                                    e.sequence == x.getLong("sequence") && e.objectType.toInt() == x.getInt("object_type_code") &&
                                    e.digest == x.getString("digest")
                            }
                    }
                tally.check("vectors", name, got.transactionId == result.getString("transaction_id") &&
                    got.actionable == result.getBoolean("actionable") && !got.actionable && partiesMatch)
            } catch (e: RatifyException) {
                tally.check("vectors", name, e.errorClass?.spelling == expected.optString("error_class")) {
                    "got ${e.errorClass}"
                }
            }
        }
        tally.finish(listOf("vectors" to 13))
    }
}
