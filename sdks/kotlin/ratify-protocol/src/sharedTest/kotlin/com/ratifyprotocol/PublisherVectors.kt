package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import org.json.JSONObject

/** status-publisher.json through the public signer, journal and publisher APIs. */
object PublisherVectors {
    private fun policy(v: JSONObject) = RevocationStatusPolicy(
        v.getLong("max_list_lifetime_seconds"), v.getLong("max_status_age_seconds"), v.getLong("clock_skew_seconds"),
    )

    fun run() = runBlocking {
        val v = Corpus.load("status-publisher.json")
        val t = Tally("status-publisher.json")
        var steps = 0
        for (scenario in v.arr("scenarios")) for (external in listOf(false, true)) {
            steps += runScenario(scenario, policy(v.getJSONObject("status_policy")), external, t)
        }
        check(v.arr("scenarios").size == 13 && steps == 78)
        t.finish(listOf("setup" to 26, "construction" to 26, "steps" to 78))
    }

    private suspend fun runScenario(scenario: JSONObject, policy: RevocationStatusPolicy, external: Boolean, t: Tally): Int {
        val store = JournalVectors.Store()
        for (role in scenario.arr("role_keys")) {
            recordSecurityKeyRole(store, role.getString("role"), Fixture.key(role.getString("key")))
        }
        val issuer = scenario.getString("issuer")
        val statusKey = scenario.getString("status_key")
        val configuredFor = scenario.getString("status_configured_for")
        var setupRejected = false
        if (configuredFor.isNotEmpty()) {
            try {
                configureStatusKeyEpoch(store, Fixture.keyId(configuredFor), 1uL, Fixture.key(statusKey))
            } catch (e: RatifyException) {
                if (e.errorClass != ErrorClass.STATUS_OBJECT_REJECTED) throw e
                setupRejected = true
            }
        }
        t.check("setup", scenario.getString("name"), setupRejected == (scenario.getString("journal_setup") == "rejected"))
        val signer = ProviderSigner(statusKey)
        val publisher = try {
            if (external) newStatusPublisher(store, Fixture.key(issuer), signer, scenario.getLong("lifetime_seconds"))
            else newStatusPublisher(store, Fixture.key(issuer), Fixture.privateKey(statusKey), scenario.getLong("lifetime_seconds"))
        } catch (e: RatifyException) {
            if (e.errorClass != ErrorClass.CONFIGURATION_INVALID) throw e
            null
        }
        t.check("construction", scenario.getString("name"), (publisher != null) == (scenario.getString("publisher") == "ok") &&
            (publisher == null || (publisher.issuerId == Fixture.keyId(issuer) && publisher.statusKey == Fixture.key(statusKey))) &&
            (!external || publisher != null || signer.signCalls == 0))
        if (publisher == null) return 0

        var state: StatusPublisherState? = null
        val publications = mutableListOf<StatusPublication>()
        var count = 0
        for (step in scenario.arr("steps")) {
            count++
            val op = step.getString("op")
            val expect = step.getJSONObject("expect")
            val at = step.getLong("at")
            when (op) {
                "genesis", "heartbeat", "revoke" -> {
                    val output = try {
                        when (op) {
                            "genesis" -> publisher.genesis(at)
                            "heartbeat" -> publisher.heartbeat(state!!, at)
                            else -> publisher.revoke(state!!, step.optJSONArray("cert_ids")?.let { a ->
                                (0 until a.length()).map(a::getString)
                            } ?: emptyList(), at)
                        }
                    } catch (e: RatifyException) {
                        if (e.errorClass != ErrorClass.CONFIGURATION_INVALID) throw e
                        null
                    }
                    if (output == null) {
                        t.check("steps", "${scenario.getString("name")} $count", expect.getString("result") == "refused")
                    } else {
                        val list = expect.getJSONObject("list")
                        val push = expect.optJSONObject("push")
                        val matches = expect.getString("result") == "published" &&
                            output.list.sequence == list.getLong("sequence") &&
                            output.list.updatedAt == list.getLong("updated_at") &&
                            output.list.nextUpdate == list.getLong("next_update") &&
                            output.list.revoked == list.strings("revoked") &&
                            output.state.sequence == output.list.sequence &&
                            output.state.updatedAt == output.list.updatedAt &&
                            output.state.issuerId == Fixture.keyId(issuer) &&
                            output.state.statusKeyId == Fixture.keyId(statusKey) &&
                            output.state.revoked == output.list.revoked &&
                            (if (push == null) output.push == null else output.push?.let {
                                it.sequence == push.getLong("sequence") && it.pushedAt == push.getLong("pushed_at") &&
                                    it.revoked == push.strings("revoked")
                            } == true)
                        t.check("steps", "${scenario.getString("name")} $count", matches)
                        verifyRevocationListSignature(output.list, Fixture.keyId(issuer), Fixture.key(statusKey))
                        output.push?.let { verifyRevocationPushSignature(it, Fixture.keyId(issuer), Fixture.key(statusKey)) }
                        state = output.state
                        publications += output
                    }
                }
                "ingest" -> {
                    val publication = publications[step.getInt("publication")]
                    if (step.getString("object") == "list") {
                        applyRevocationListToJournal(store, publication.list, Fixture.keyId(issuer), 1uL,
                            Fixture.key(statusKey), policy, at)
                    } else {
                        applyRevocationPushToJournal(store, publication.push!!, Fixture.keyId(issuer), 1uL,
                            Fixture.key(statusKey), policy, at)
                    }
                    t.check("steps", "${scenario.getString("name")} $count", expect.getString("result") == "applied")
                }
                "status" -> {
                    val result = revocationStatusFromJournal(store, Fixture.keyId(issuer), step.getString("cert_id"),
                        1uL, Fixture.key(statusKey), policy, at)
                    t.check("steps", "${scenario.getString("name")} $count",
                        result.status == expect.getString("status") && result.reason == expect.optString("reason"))
                }
                else -> error("unknown status publisher operation $op")
            }
        }
        return count
    }
}
