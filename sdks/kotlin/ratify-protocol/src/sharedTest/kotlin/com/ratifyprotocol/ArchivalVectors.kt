package com.ratifyprotocol

import org.json.JSONArray
import org.json.JSONObject

/** Structural JSON equality (Android's org.json has no `similar`); numbers compare by value. */
fun jsonEqual(a: Any?, b: Any?): Boolean = when {
    a is JSONObject && b is JSONObject ->
        a.keys().asSequence().toSet() == b.keys().asSequence().toSet() && a.keys().asSequence().all { jsonEqual(a.opt(it), b.opt(it)) }
    a is JSONArray && b is JSONArray -> a.length() == b.length() && (0 until a.length()).all { jsonEqual(a.opt(it), b.opt(it)) }
    a is Number && b is Number -> a.toLong() == b.toLong() && a.toDouble() == b.toDouble()
    (a == null || a == JSONObject.NULL) && (b == null || b == JSONObject.NULL) -> true
    else -> a == b
}

/** archival.json and digest-functions.json (model: sdks/rust/tests/v2_archival_signer.rs). */
object ArchivalVectors {
    private fun json(r: ArchivalVerification): JSONObject = JSONObject()
        .put("object_type_code", r.objectType.toInt()).put("freshness", r.freshness).put("actionable", r.actionable)
        .put("digest", r.digest).put("signer_key_ids", JSONArray(r.signerKeyIds))

    fun archival() {
        val f = Corpus.load("archival.json")
        val t = Tally("archival.json")
        val kinds = mutableSetOf<String>()
        val cases = f.arr("cases")
        for (c in cases) {
            val name = c.getString("name")
            val kind = c.getString("kind")
            kinds += kind
            val wire = c.b64("wire_b64")
            val v = c.optJSONObject("verify") ?: JSONObject()
            val got = runCatching {
                when (kind) {
                    "proof_bundle" -> JSONObject(String(verifyArchivalProofBundle(wire).json()))
                    "delegation_certificate" -> json(verifyArchivalDelegationCert(wire))
                    "revocation_list" -> json(verifyArchivalRevocationList(wire, v.getString("issuer_id"), Fixture.key(v.getString("status_key"))))
                    "revocation_push" -> json(verifyArchivalRevocationPush(wire, v.getString("issuer_id"), Fixture.key(v.getString("status_key"))))
                    "key_rotation_statement" -> json(verifyArchivalKeyRotationStatement(wire))
                    "witness_entry" -> json(verifyArchivalWitnessEntry(wire, Fixture.key(v.getString("witness_key"))))
                    "verification_receipt" -> json(verifyArchivalVerificationReceipt(wire, Fixture.key(v.getString("verifier_key"))))
                    "transaction_receipt" -> json(verifyArchivalTransactionReceipt(wire))
                    else -> error("$name: unknown kind $kind")
                }
            }
            val wantClass = c.optString("expected_error_class", "")
            if (wantClass.isNotEmpty()) {
                val gotClass = (got.exceptionOrNull() as? RatifyException)?.errorClass?.spelling ?: if (got.isSuccess) "ok" else "other"
                t.check("archival", name, gotClass == wantClass) { "class $gotClass, want $wantClass" }
            } else {
                val r = got.getOrNull()
                t.check("archival", name, r != null && jsonEqual(r, c.getJSONObject("expected"))) { "result $got, want ${c.get("expected")}" }
            }
        }
        for (k in listOf("proof_bundle", "delegation_certificate", "revocation_list", "revocation_push",
            "key_rotation_statement", "witness_entry", "verification_receipt", "transaction_receipt")) {
            check(k in kinds) { "no archival case for $k" }
        }
        check(cases.size == 19) { "archival cases" }
        t.finish(listOf("archival" to cases.size))
    }

    fun digestFunctions() {
        val f = Corpus.load("digest-functions.json")
        val t = Tally("digest-functions.json")
        val cases = f.arr("cases")
        for (c in cases) {
            val name = c.getString("name")
            val input = c.b64("input_b64")
            val wantClass = c.optString("expected_error_class", "")
            val raw = c.getLong("object_type_code")
            if (raw !in 0..0xFFFF) {
                // The code parameter is 16 bits: such a code cannot be passed, and must never be truncated.
                t.check("digest-functions", name, wantClass == "unsupported_object_type") { "code outside 16 bits" }
                continue
            }
            val code = raw.toInt().toUShort()
            val digest = runCatching {
                when (c.getString("function")) {
                    "statement_body_digest" -> statementBodyDigest(code, input)
                    "status_evidence_digest" -> statusEvidenceDigest(code, StatusObject.List(decodeRevocationList(input)))
                    else -> error("$name: unknown function")
                }
            }
            if (wantClass.isNotEmpty()) {
                val got = (digest.exceptionOrNull() as? RatifyException)?.errorClass?.spelling ?: if (digest.isSuccess) "ok" else "other"
                t.check("digest-functions", name, got == wantClass) { "class $got, want $wantClass" }
            } else {
                t.check("digest-functions", name, digest.getOrNull()?.let { "sha384:${it.hex()}" } == c.getString("expected_digest")) { "$digest" }
            }
        }
        check(cases.size == 25) { "digest function cases" }
        t.finish(listOf("digest-functions" to cases.size))
    }
}
