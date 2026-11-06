package com.ratifyprotocol

/** log-sequences.json and rotation-sequences.json (model: sdks/rust/tests/v2_logs.rs). */
object LogsVectors {
    fun logSequences() {
        val f = Corpus.load("log-sequences.json")
        val scenarios = f.arr("scenarios")
        check(scenarios.size == 2) { "want witness and receipt log scenarios" }
        val t = Tally("log-sequences.json")
        val expected = mutableListOf<Pair<String, Int>>()
        for (sc in scenarios) {
            val kind = sc.getString("kind")
            val row = "log-sequences.json $kind"
            fun genesis(id: String) = WitnessHead(id, 0, ByteArray(48))
            var head = genesis(sc.getString("initial_log_id"))
            var nVerify = 0
            for ((n, step) in sc.arr("steps").withIndex()) {
                if (step.getString("op") == "recover") {
                    head = genesis(step.getString("log_id")); continue
                }
                check(step.getString("op") == "verify") { "unknown log op" }
                nVerify++
                val wire = step.b64("wire_b64")
                val key = Fixture.key(step.getString("key"))
                var digest: ByteArray? = null
                var seq = 0L
                val got = try {
                    val r = if (kind == "witness_entry") {
                        val e = decodeWitnessEntry(wire)
                        digest = runCatching { witnessEntryDigest(e) }.getOrNull()
                        seq = e.sequence
                        verifyWitnessEntry(e, head, key)
                    } else {
                        val rc = decodeVerificationReceipt(wire)
                        digest = runCatching { verificationReceiptDigest(rc) }.getOrNull()
                        seq = rc.sequence
                        verifyVerificationReceipt(rc, key, ReceiptHead(head.logId, sc.getString("verifier_id"), head.sequence,
                            head.headHash, head.acceptedDigests, head.frozen))
                    }
                    if (r == LogResult.APPENDED) "appended" else "replay"
                } catch (e: RatifyException) {
                    e.errorClass?.spelling ?: "internal"
                }
                val want = step.getString("expect")
                t.check(row, "step $n ${step.getString("label")}", got == want) { "got $got, want $want" }
                when (got) {
                    "appended" -> head = WitnessHead(head.logId, seq, digest!!, head.acceptedDigests + (seq to digest!!), head.frozen)
                    "log_fork" -> head = WitnessHead(head.logId, head.sequence, head.headHash, head.acceptedDigests, true)
                }
            }
            expected += row to nVerify
        }
        t.finish(expected)
    }

    fun rotationSequences() {
        val f = Corpus.load("rotation-sequences.json")
        val t = Tally("rotation-sequences.json")
        val expected = mutableListOf<Pair<String, Int>>()
        for (sc in f.arr("scenarios")) {
            var journal = newKeyRotationJournal(sc.getString("authority_id"), sc.getLong("recovery_epoch"), sc.getString("role"),
                Fixture.key(sc.getString("genesis_key")))
            val row = "rotation-sequences.json ${sc.getString("name")}"
            val steps = sc.arr("steps")
            for ((n, step) in steps.withIndex()) {
                val got = if (step.getString("op") == "recover") {
                    try {
                        journal = recoverKeyRotation(journal, step.getLong("new_recovery_epoch"), Fixture.key(step.getString("new_genesis_key")))
                        "recovered"
                    } catch (e: RatifyException) {
                        e.errorClass?.spelling ?: "internal"
                    }
                } else {
                    check(step.getString("op") == "accept") { "unknown rotation op" }
                    val a = acceptKeyRotationStatement(decodeKeyRotationStatement(step.b64("wire_b64")), journal,
                        step.getLong("now"), sc.getLong("future_skew_seconds"))
                    journal = a.journal
                    a.error?.errorClass?.spelling ?: if (a.result == LogResult.APPENDED) "appended" else "replay"
                }
                val want = step.getString("expect")
                val stateOk = journal.state.sequence == step.getLong("expect_sequence") &&
                    journal.state.currentKey.mlDsa65.contentEquals(Fixture.key(step.getString("expect_current_key")).mlDsa65) &&
                    journal.state.recoveryEpoch == step.getLong("expect_recovery_epoch") &&
                    journal.frozen == step.getBoolean("expect_frozen")
                t.check(row, "step $n ${step.getString("label")}", got == want && stateOk) {
                    "got $got (want $want); seq=${journal.state.sequence} epoch=${journal.state.recoveryEpoch} frozen=${journal.frozen}"
                }
            }
            expected += row to steps.size
        }
        t.finish(expected)
    }
}
