package com.ratifyprotocol

import org.json.JSONObject

/** status-sequences.json and challenge-claim.json (models: v2_status_sequences.rs, challenge_claim_v2.rs). */
object StatusVectors {
    private fun policy(v: JSONObject) =
        RevocationStatusPolicy(v.getLong("max_list_lifetime_seconds"), v.getLong("max_status_age_seconds"), v.getLong("clock_skew_seconds"))

    private fun evidence(v: JSONObject) = StatusEvidenceEntry(
        v.getString("issuer_id"), v.getString("status_key_id"), v.getLong("sequence"), v.getInt("object_type_code").toUShort(),
        v.getString("digest"),
    )

    /** Every member of an expect_state object is compared; an unknown member fails. */
    private fun stateProblems(st: RevocationStatusState, w: JSONObject): String? {
        var checked = 0
        val problems = mutableListOf<String>()
        fun cmp(name: String, got: Any, want: Any?) {
            if (want == null) return
            checked++
            if (got != want) problems += "$name: got $got, want $want"
        }
        cmp("has_floor", st.hasFloor, w.opt("has_floor"))
        cmp("floor", st.floor, if (w.has("floor")) w.getLong("floor") else null)
        cmp("max_observed_sequence", st.maxObservedSequence, if (w.has("max_observed_sequence")) w.getLong("max_observed_sequence") else null)
        cmp("fork_sequence", st.forkSequence, if (w.has("fork_sequence")) w.getLong("fork_sequence") else null)
        cmp("reconciliation_required", st.reconciliationRequired, w.opt("reconciliation_required"))
        cmp("future_dated_object_observed", st.futureDatedObjectObserved, w.opt("future_dated_object_observed"))
        cmp("accepted_set", st.acceptedCertIds, if (w.has("accepted_set")) w.strings("accepted_set") else null)
        cmp("deny_union", st.denyUnionCertIds, if (w.has("deny_union")) w.strings("deny_union") else null)
        if (checked != w.length()) problems += "expect_state has members this harness does not check"
        return problems.takeIf { it.isNotEmpty() }?.joinToString("; ")
    }

    private fun sameEvidence(a: List<StatusEvidenceEntry>, b: List<StatusEvidenceEntry>) = a.size == b.size && a.zip(b).all { (x, y) -> x == y }

    fun statusSequences() {
        val f = Corpus.load("status-sequences.json")
        val t = Tally("status-sequences.json")
        val scenarios = f.arr("scenarios")
        var steps = 0; var queries = 0; var errors = 0; var bodyDigests = 0
        for (sc in scenarios) {
            val name = sc.getString("name")
            val issuerId = sc.getString("issuer_id")
            var state = emptyRevocationStatusState()
            for ((n, step) in sc.arr("steps").withIndex()) {
                steps++
                val key = Fixture.key(step.getString("status_key"))
                val pol = step.optJSONObject("policy")?.let(::policy) ?: policy(sc.getJSONObject("policy"))
                val epoch = step.getLong("status_key_epoch").toULong()
                val now = step.optLong("now", 0)
                val op = step.getString("op")
                val id = "$name step $n $op ${step.optString("label", "")}"
                val next: Result<RevocationStatusState> = when (op) {
                    "apply_list" -> runCatching {
                        applyRevocationList(state, decodeRevocationList(step.b64("wire_b64")), issuerId, epoch, key, pol, now)
                    }
                    "apply_push" -> runCatching {
                        applyRevocationPush(state, decodeRevocationPush(step.b64("wire_b64")), issuerId, epoch, key, pol, now)
                    }
                    "transition_epoch" -> runCatching { transitionRevocationStatusEpoch(state, issuerId, epoch, key) }
                    "query" -> {
                        queries++
                        val r = revocationStatusForCert(state, issuerId, step.getString("cert_id"), epoch, key, pol, now)
                        val want = step.getJSONObject("expect_result")
                        t.check("steps", id, r.status == want.getString("status") && r.reason == want.optString("reason", "") &&
                            sameEvidence(r.evidence, want.arr("evidence").map(::evidence))) { "${r.status}/${r.reason}" }
                        continue
                    }
                    else -> error("unknown op $op")
                }
                if (step.has("expect_error_class")) {
                    errors++
                    val got = (next.exceptionOrNull() as? RatifyException)?.errorClass?.spelling ?: if (next.isSuccess) "ok" else "other"
                    t.check("steps", id, got == step.getString("expect_error_class")) { "class $got" }
                    continue
                }
                val s = next.getOrNull()
                if (s == null) {
                    t.check("steps", id, false) { "${next.exceptionOrNull()}" }
                    continue
                }
                state = s
                var problems = step.optJSONObject("expect_state")?.let { stateProblems(state, it) } ?: ""
                if (step.has("expect_body_digest")) {
                    bodyDigests++
                    val want = step.getString("expect_body_digest")
                    val code: UShort = if (op == "apply_push") 5u else 3u
                    if (state.observations.none { it.statusKeyEpoch == epoch && it.objectType == code && "sha384:${it.bodyDigest.hex()}" == want }) {
                        problems += " no observation with body_digest $want"
                    }
                }
                t.check("steps", id, problems.isEmpty()) { problems }
            }
        }
        check(scenarios.size == 22 && steps == 112) { "status-sequences shape changed" }
        check(queries == 43 && errors == 3 && bodyDigests == 63) { "status-sequences counts changed" }
        t.finish(listOf("steps" to steps))
    }

    fun challengeClaim() {
        val v = Corpus.load("challenge-claim.json")
        val t = Tally("challenge-claim.json")
        val challenge = v.hex("challenge_hex")
        val digest = challengeClaimDigest(challenge)
        t.check("claim", "digest", digest.hex() == v.getString("expected_challenge_claim_digest_hex"))
        val cases = listOf(JSONObject(v.getJSONObject("claim_id_input").toString()).put("expected_claim_id", v.getString("expected_claim_id"))) +
            v.arr("additional_claim_id_cases")
        for (c in cases) {
            val ns = c.getString("verifier_namespace")
            val epoch = c.getLong("replay_epoch")
            val want = c.getString("expected_claim_id")
            t.check("claim", "$ns/$epoch", protocolClaimId(ns, epoch, challenge) == want && protocolClaimIdFromDigest(ns, epoch, digest) == want)
        }
        for (len in listOf(0, 31, 33)) t.check("refusals", "challenge $len", classOf { challengeClaimDigest(ByteArray(len)) } != "ok")
        val zero = ByteArray(32)
        t.check("refusals", "empty namespace", classOf { protocolClaimId("", 7, zero) } != "ok")
        t.check("refusals", "epoch 2^53", classOf { protocolClaimId("verify-prod", 1L shl 53, zero) } != "ok")
        for (len in listOf(0, 47, 49)) t.check("refusals", "digest $len", classOf { protocolClaimIdFromDigest("verify-prod", 7, ByteArray(len)) } != "ok")
        t.finish(listOf("claim" to 1 + cases.size, "refusals" to 8))
    }
}
