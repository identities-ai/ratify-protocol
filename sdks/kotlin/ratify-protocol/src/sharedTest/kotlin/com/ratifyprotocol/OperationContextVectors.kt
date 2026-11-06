package com.ratifyprotocol

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals

/**
 * operation-session-context.json through the public API: operation and
 * session context digests, the context policy digest, and payload digests.
 */
object OperationContextVectors {
    private fun operation(v: JSONObject, scope: String = v.getString("required_scope")) = OperationContext(
        scope, v.getString("operation"), v.getString("resource_id"), v.getString("requested_path"),
        if (v.has("payload_digest_hex") && !v.isNull("payload_digest_hex")) v.hex("payload_digest_hex") else ByteArray(0),
    )

    private fun session(v: JSONObject, requestHash: ByteArray, verifierId: String = v.getString("verifier_id"),
                        workspaceId: String = v.getString("workspace_id"),
                        agentId: String = v.getString("agent_id")) = SessionContextInputs(
        verifierId, workspaceId, agentId, v.getString("session_id"),
        v.getString("invocation_id"), requestHash,
    )

    fun corpus() {
        val f = Corpus.load("operation-session-context.json")
        val t = Tally("operation-session-context.json")

        val policy = f.getJSONObject("context_policy")
        val p = ContextPolicy(
            policy.getString("profile"), policy.getBoolean("require_bound"), policy.strings("required_fields"),
            f.hex("expected_session_context_hex"),
        )
        t.check("context_policy", "digest", p.digest == f.getString("context_policy_digest")) { p.digest }

        val hash = operationContextHash(operation(f.getJSONObject("operation_input")))
        t.check("request_hash", "operation_input", hash.hex() == f.getString("expected_request_hash_hex")) { hash.hex() }
        val input = f.getJSONObject("input")
        val ctx = buildSessionContext(session(input, input.hex("request_hash_hex")))
        t.check("session_context", "input", ctx.hex() == f.getString("expected_session_context_hex")) { ctx.hex() }

        val empty = operationContextHash(operation(f.getJSONObject("empty_payload_operation_input")))
        t.check("request_hash", "empty_payload", empty.hex() == f.getString("expected_empty_request_hash_hex")) { empty.hex() }
        val emptyCtx = buildSessionContext(session(input, empty))
        t.check("session_context", "empty_payload", emptyCtx.hex() == f.getString("expected_empty_session_context_hex")) {
            emptyCtx.hex()
        }

        val invalid = f.strings("invalid_required_scopes")
        for (scope in invalid) {
            t.check("invalid_required_scopes", scope,
                classOf { operationContextHash(operation(f.getJSONObject("operation_input"), scope)) } != "ok") { "accepted" }
        }

        val cases = f.arr("verify_api_payload_digest_decode_cases")
        for (c in cases) {
            val encoded = if (c.isNull("encoded")) null else c.getString("encoded")
            val ok = try {
                val decoded = decodePayloadDigest(encoded)
                c.getBoolean("valid") && (decoded?.hex() ?: "") == c.getString("expected_hex")
            } catch (e: RatifyException) {
                !c.getBoolean("valid")
            }
            t.check("payload_digest_decode", c.getString("name"), ok) { "case" }
        }

        val vin = f.getJSONObject("verify_api_operation_input")
        val digest = decodePayloadDigest(vin.getString("payload_digest"))!!
        val vhash = operationContextHash(
            OperationContext(vin.getString("required_scope"), vin.getString("operation"), vin.getString("resource_id"),
                vin.getString("requested_path"), digest),
        )
        t.check("request_hash", "verify_api",
            vhash.hex() == f.getString("expected_verify_api_request_hash_hex") && vhash.contentEquals(hash)) { vhash.hex() }

        t.finish(
            listOf(
                "context_policy" to 1, "request_hash" to 3, "session_context" to 2,
                "invalid_required_scopes" to invalid.size, "payload_digest_decode" to cases.size,
            ),
        )
    }

    fun fieldValidation() {
        val f = Corpus.load("operation-session-context.json")
        val op = operation(f.getJSONObject("operation_input"))
        val shortDigest = OperationContext(op.requiredScope, op.operation, op.resourceId, op.requestedPath,
            op.payloadDigest.copyOf(op.payloadDigest.size - 1))
        assertNotEquals("ok", classOf { operationContextHash(shortDigest) })
        val input = f.getJSONObject("input")
        assertEquals("ok", classOf { sessionContextBytes(session(input, ByteArray(32))) })
        assertEquals("configuration_invalid",
            classOf { sessionContextBytes(session(input, ByteArray(32), verifierId = input.getString("verifier_id").uppercase())) })
        assertEquals("configuration_invalid", classOf { sessionContextBytes(session(input, ByteArray(31))) })
        assertEquals("configuration_invalid",
            classOf { sessionContextBytes(session(input, ByteArray(32), workspaceId = "00000000-0000-4000-8000-00000000000A")) })
        assertEquals("configuration_invalid",
            classOf { sessionContextBytes(session(input, ByteArray(32), verifierId = input.getString("verifier_id").substring(0, 32))) })
        assertEquals("configuration_invalid", classOf { sessionContextBytes(session(input, ByteArray(32), agentId = "not-a-key-id")) })
        assertEquals("configuration_invalid",
            classOf { sessionContextBytes(session(input, ByteArray(32), agentId = input.getString("agent_id").substring(0, 32))) })

        // Length prefixes keep field boundaries from colliding.
        val left = OperationContext("data:read", "records.get", "r1", "/records/1")
        val right = OperationContext("data:read", "records.get", "r1/records", "/1")
        assertNotEquals(operationContextHash(left).hex(), operationContextHash(right).hex())
    }
}
