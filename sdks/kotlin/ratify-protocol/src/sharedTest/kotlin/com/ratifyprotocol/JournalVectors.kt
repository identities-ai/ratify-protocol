package com.ratifyprotocol

import kotlinx.coroutines.runBlocking
import org.json.JSONObject

/** security-journal.json through the public store callbacks and snapshot API. */
object JournalVectors {
    class Store : SecurityJournalStore {
        private var state = emptySecurityJournalSnapshot()
        override suspend fun load(): SecurityJournalSnapshot = synchronized(this) { state }
        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            synchronized(this) {
                if (state.head.generation != expected.generation || state.head.digest != expected.digest) {
                    throw SecurityJournalStoreError.Conflict()
                }
                validateSecurityJournalTransition(state, next)
                state = next
            }
        }
    }

    private fun head(v: JSONObject) = SecurityJournalHead(v.getLong("generation").toULong(), v.getString("digest"))
    private fun sameHead(a: SecurityJournalHead, b: SecurityJournalHead) = a.generation == b.generation && a.digest == b.digest
    private fun policy(v: JSONObject) = RevocationStatusPolicy(
        v.getLong("max_list_lifetime_seconds"), v.getLong("max_status_age_seconds"), v.getLong("clock_skew_seconds"),
    )

    fun run() = runBlocking {
        val v = Corpus.load("security-journal.json")
        val t = Tally("security-journal.json")
        val genesis = emptySecurityJournalSnapshot()
        t.check("genesis", "snapshot", String(genesis.snapshot) == v.getString("genesis_snapshot") && genesis.head.digest == v.getString("genesis_digest"))
        var steps = 0
        for (scenario in v.arr("scenarios")) {
            val store = Store()
            for ((index, step) in scenario.arr("steps").withIndex()) {
                steps++
                val before = store.load()
                val key = publicKeyOf(step.getJSONObject("key").getJSONObject("public_key"))
                val op = step.getString("op")
                var errorClass = "ok"
                try {
                    when (op) {
                        "record_key_role" -> recordSecurityKeyRole(store, step.getString("role"), key)
                        "configure_status_key_epoch" -> configureStatusKeyEpoch(store, step.getString("issuer_id"), step.getLong("epoch").toULong(), key)
                        "apply_revocation_list" -> applyRevocationListToJournal(store,
                            decodeRevocationList(step.b64("wire_b64")), step.getString("issuer_id"), step.getLong("epoch").toULong(),
                            key, policy(step.getJSONObject("policy")), step.getLong("now"))
                        "apply_revocation_push" -> applyRevocationPushToJournal(store,
                            decodeRevocationPush(step.b64("wire_b64")), step.getString("issuer_id"), step.getLong("epoch").toULong(),
                            key, policy(step.getJSONObject("policy")), step.getLong("now"))
                        else -> error("unknown journal operation $op")
                    }
                } catch (e: RatifyException) {
                    errorClass = e.errorClass?.spelling ?: "internal"
                }
                val after = store.load()
                t.check("steps", "${scenario.getString("name")} $index",
                    (errorClass != "ok") == step.optBoolean("expect_rejected") &&
                        (!sameHead(before.head, after.head)) == step.getBoolean("expect_changed") &&
                        sameHead(after.head, head(step.getJSONObject("expect_head"))) &&
                        after.snapshot.contentEquals(step.b64("expect_snapshot_b64")))
                validateSecurityJournalSnapshot(after.snapshot, after.head)
            }
            if (scenario.getString("name") == "status_reducer_transitions") {
                val last = scenario.arr("steps").last()
                val key = publicKeyOf(last.getJSONObject("key").getJSONObject("public_key"))
                for ((certId, expected) in listOf("c1" to "revoked", "unlisted" to "not_revoked")) {
                    val result = revocationStatusFromJournal(store, last.getString("issuer_id"), certId,
                        last.getLong("epoch").toULong(), key, policy(last.getJSONObject("policy")), last.getLong("now"))
                    t.check("query", certId, result.status == expected && result.evidence.isNotEmpty())
                }
            }
        }
        val m = v.getJSONObject("migration")
        val migrated = migrateSecurityJournalJson(m.b64("legacy_record_b64"))
        t.check("migration", "valid", sameHead(migrated.head, head(m.getJSONObject("expect_head"))) &&
            migrated.snapshot.contentEquals(m.b64("expect_snapshot_b64")))
        t.check("migration", "tampered", classOf { migrateSecurityJournalJson(m.b64("tampered_legacy_record_b64")) } == "configuration_invalid")
        for (negative in v.arr("import_negatives")) {
            t.check("import", negative.getString("name"), classOf {
                validateSecurityJournalSnapshot(negative.b64("snapshot_b64"), head(negative.getJSONObject("head")))
            } == negative.getString("expect_error_class"))
        }
        for (negative in v.arr("transition_negatives")) {
            val current = SecurityJournalSnapshot(negative.b64("current_snapshot_b64"), head(negative.getJSONObject("current_head")))
            val next = SecurityJournalSnapshot(negative.b64("next_snapshot_b64"), head(negative.getJSONObject("next_head")))
            t.check("transition", negative.getString("name"), classOf {
                validateSecurityJournalTransition(current, next)
            } == negative.getString("expect_error_class"))
        }
        check(steps == 17 && v.arr("import_negatives").size == 20 && v.arr("transition_negatives").size == 6)
        t.finish(listOf("genesis" to 1, "steps" to steps, "query" to 2, "migration" to 2, "import" to 20, "transition" to 6))
    }
}
