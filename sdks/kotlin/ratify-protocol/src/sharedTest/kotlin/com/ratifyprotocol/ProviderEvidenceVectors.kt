package com.ratifyprotocol

import org.json.JSONObject

/**
 * provider-evidence/: every device evidence record present, through the
 * public API. Each record's key must issue its certificate, prove
 * possession in its rotation, and sign its revocation list.
 */
object ProviderEvidenceVectors {
    fun run() {
        val files = Corpus.list("v2/provider-evidence").filter { it.endsWith(".json") }.sorted()
        check(files.isNotEmpty()) { "provider-evidence/ has no records" }
        val t = Tally("provider-evidence")
        for (file in files) {
            val r = JSONObject(String(Corpus.read("v2/provider-evidence/$file"), Charsets.UTF_8))
            t.check("records", "$file name", file == "${r.getString("platform")}-${r.getString("provider")}.json" && r.getInt("version") == 1)
            val key = publicKeyOf(r.getJSONObject("public_key"))
            val id = r.getString("key_id_v2")
            t.check("records", "$file key ID", keyId(key) == id)
            // Exactly one object of each kind, with its role.
            val pairs = r.arr("objects").map { "${it.getString("kind")}/${it.getString("role")}" }.sorted()
            t.check("records", "$file objects",
                pairs == listOf("delegation_certificate/issuer", "key_rotation_statement/new_key", "revocation_list/status_key")) { "$pairs" }
            for (o in r.arr("objects")) {
                val wire = o.b64("wire_b64")
                val name = "$file ${o.getString("kind")}"
                when (o.getString("kind")) {
                    "delegation_certificate" -> {
                        val c = decodeDelegationCert(wire)
                        t.check("objects", name, classOf { verifyDelegationCertSignature(c) } == "ok" &&
                            c.issuerPubKey == key && c.issuerId == id && encodeDelegationCert(c).contentEquals(wire))
                        val badSig = HybridSignature(c.signature.ed25519, c.signature.mlDsa65.also { it[0] = (it[0].toInt() xor 1).toByte() })
                        val bad = DelegationCert(c.version, c.certId, c.issuerId, c.issuerPubKey, c.subjectId, c.subjectPubKey, c.scope,
                            c.constraints, c.issuedAt, c.expiresAt, badSig)
                        t.check("negatives", name, classOf { verifyDelegationCertSignature(bad) } == "invalid_signature")
                    }
                    "key_rotation_statement" -> {
                        val s = decodeKeyRotationStatement(wire)
                        val signable = keyRotationStatementSignableBytes(s)
                        val old = classOf { verifyStatement(ObjectType.KEY_ROTATION_AUTHORIZATION, signable, s.oldSignature, s.oldKey) }
                        val new = classOf { verifyStatement(ObjectType.KEY_ROTATION_PROOF_OF_POSSESSION, signable, s.newSignature, s.newKey) }
                        t.check("objects", name, old == "ok" && new == "ok" && s.newKey == key && encodeKeyRotationStatement(s).contentEquals(wire))
                    }
                    "revocation_list" -> {
                        val l = decodeRevocationList(wire)
                        t.check("objects", name, classOf { verifyRevocationListSignature(l, id, key) } == "ok" && encodeRevocationList(l).contentEquals(wire))
                    }
                    else -> error("$name: unknown kind")
                }
            }
        }
        t.finish(listOf("records" to 3 * files.size, "objects" to 3 * files.size, "negatives" to files.size))
    }
}
