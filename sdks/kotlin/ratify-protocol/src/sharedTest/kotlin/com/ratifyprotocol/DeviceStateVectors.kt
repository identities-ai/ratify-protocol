package com.ratifyprotocol

import com.ratifyprotocol.testing.DeviceStateProjection
import java.security.MessageDigest

/** All six §7.13 known answers through the testing artifact and Rust primary. */
object DeviceStateVectors {
    fun run() {
        val file = "device-state.json"
        val cases = Corpus.load(file).arr("cases")
        val tally = Tally(file)
        for (c in cases) {
            val name = c.getString("name")
            val got = DeviceStateProjection(c.getJSONObject("state").toString().toByteArray(Charsets.UTF_8))
            val want = c.getJSONObject("expect")
            for ((member, bytes) in listOf(
                "claims" to got.claims,
                "streams" to got.streams,
                "rate_counters" to got.rateCounters,
                "receipt_log" to got.receiptLog,
                "issuance_records" to got.issuanceRecords,
            )) {
                tally.check("members", "$name/$member/canonical", String(bytes, Charsets.UTF_8) == want.getString("${member}_canonical_json"))
                tally.check("members", "$name/$member/digest", MessageDigest.getInstance("SHA-384").digest(bytes).hex() == want.getString("${member}_sha384"))
            }
            tally.check("projection", name, String(got.projection, Charsets.UTF_8) == want.getString("projection_canonical_json"))
            tally.check("digest", name, got.completeStateDigest.hex() == want.getString("complete_state_digest_hex"))
        }
        tally.finish(listOf("members" to cases.size * 10, "projection" to cases.size, "digest" to cases.size))
    }
}
