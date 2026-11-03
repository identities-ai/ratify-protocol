package com.ratifyprotocol

import org.json.JSONObject
import org.junit.Assert.assertEquals
import java.io.ByteArrayOutputStream

/**
 * limits.json through the public decoders: every size and count limit is
 * accepted at the limit and rejected one past it, before parsing.
 */
object LimitsVectors {
    private fun build(c: JSONObject): ByteArray {
        val out = ByteArrayOutputStream()
        when (val m = c.getString("method")) {
            "inline" -> out.write(c.b64("wire_b64"))
            "pad" -> {
                val base = c.b64("base_b64")
                out.write(base, 0, base.size - 1)
                repeat(c.getInt("pad_count")) { out.write(' '.code) }
                out.write(base.last().toInt())
            }
            "repeat_items" -> {
                out.write(c.optB64("prefix_b64"))
                val digits = c.optInt("item_index_digits", 0)
                val prefix = c.optString("item_prefix", "")
                val suffix = c.optString("item_suffix", "")
                for (n in 0 until c.getInt("count")) {
                    if (n > 0) out.write(','.code)
                    out.write("$prefix${n.toString().padStart(digits, '0')}$suffix".toByteArray())
                }
                out.write(c.optB64("suffix_b64"))
            }
            "repeat_bytes" -> {
                out.write(c.optB64("prefix_b64"))
                val item = c.b64("item_b64")
                repeat(c.getInt("count")) { out.write(item) }
                out.write(c.optB64("suffix_b64"))
            }
            "repeat_item" -> {
                out.write(c.optB64("prefix_b64"))
                val item = c.b64("item_b64")
                for (n in 0 until c.getInt("count")) {
                    if (n > 0) out.write(','.code)
                    out.write(item)
                }
                out.write(c.optB64("suffix_b64"))
            }
            else -> error("unknown construction $m")
        }
        return out.toByteArray()
    }

    private fun decode(kind: String, data: ByteArray) {
        when (kind) {
            "delegation_certificate" -> decodeDelegationCert(data)
            "proof_bundle" -> decodeProofBundle(data)
            "key_rotation_statement" -> decodeKeyRotationStatement(data)
            "revocation_list" -> decodeRevocationList(data)
            "revocation_push" -> decodeRevocationPush(data)
            "witness_entry" -> decodeWitnessEntry(data)
            "verification_receipt" -> decodeVerificationReceipt(data)
            "verification_receipt_body" -> decodeVerificationReceiptBody(data)
            "transaction_receipt" -> decodeTransactionReceipt(data)
            "status_evidence_batch" -> decodeStatusEvidenceBatch(data)
            else -> error("no decoder for $kind")
        }
    }

    fun corpus() {
        val f = Corpus.load("limits.json")
        val table = f.getJSONObject("limits")
        val t = Tally()
        val vectors = f.arr("vectors")
        for (v in vectors) {
            val name = v.getString("name")
            val limit = v.getString("limit")
            assertEquals("$name: limit table", table.getLong(limit), v.getLong("limit_value"))
            val data = build(v.getJSONObject("construction"))
            assertEquals("$name: length", v.getInt("length"), data.size)
            assertEquals("$name: digest", v.getString("sha256_hex"), sha256(data).hex())
            val failure = try {
                decode(v.getString("kind"), data)
                null
            } catch (e: RatifyException) {
                e
            }
            val expectationOk = when (v.getString("expected")) {
                "accept" -> failure == null
                "reject" -> failure?.errorClass?.spelling == v.getString("expected_error_class")
                else -> error("unknown expectation")
            }
            val message = (failure as? RatifyException.Protocol)?.detail ?: ""
            val gateFailed = message.contains("exceeds $limit (") && message.contains("rejected before parsing")
            val gateOk = (v.getString("size_gate") == "fail") == gateFailed
            t.check("limits", name, expectationOk && gateOk) { "$failure" }
        }
        t.finish(listOf("limits" to vectors.size))
    }
}
