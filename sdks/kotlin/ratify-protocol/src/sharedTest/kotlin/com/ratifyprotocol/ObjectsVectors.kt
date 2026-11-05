package com.ratifyprotocol

import org.json.JSONObject
import java.nio.ByteBuffer
import java.util.Base64

/** objects.json, object-negatives.json and hedged-signatures.json (model: sdks/rust/tests/v2_objects.rs). */
object ObjectsVectors {
    private val b64 = Base64.getEncoder()
    private val notDigests = setOf("claim_verifier_namespace", "claim_replay_epoch", "transaction_context_hex")

    private fun sessionInputs(b: ProofBundle) = SessionContextInputs(
        b.verifierId, "00000000-0000-4000-8000-000000000001", b.agentId, "session-01", "invocation-01",
        operationContextHash(OperationContext("data:read", "records.get", "customer/123", "/v1/customers/123")),
    )

    private fun lengthPrefixed(b: ByteArray): ByteArray = ByteBuffer.allocate(8).putLong(b.size.toLong()).array() + b

    /** One fixture digest recomputed through the public API; null for non-digest inputs. */
    internal fun objectDigest(name: String, kind: String, wire: ByteArray, digests: JSONObject): String? = when (name) {
        "issuer_key_id_v2" -> independentKeyId(decodeDelegationCert(wire).issuerPubKey)
        "subject_key_id_v2" -> independentKeyId(decodeDelegationCert(wire).subjectPubKey)
        "delegation_digest_hex" -> decodeProofBundle(wire).delegationDigest.hex()
        "bundle_hash_v2" -> bundleHash(decodeProofBundle(wire))
        "session_context_hex" -> {
            val b = decodeProofBundle(wire)
            val ctx = buildSessionContext(sessionInputs(b))
            if (b.sessionContext?.contentEquals(ctx) != true) "bundle session_context does not match the recomputed fixture context"
            else ctx.hex()
        }
        "challenge_claim_digest_hex" -> challengeClaimDigest(decodeProofBundle(wire).challenge).hex()
        "claim_id" -> protocolClaimId(
            digests.getString("claim_verifier_namespace"), digests.getString("claim_replay_epoch").toLong(),
            decodeProofBundle(wire).challenge,
        )
        in notDigests -> null
        "receipt_outbox_body_b64" -> b64.encodeToString(verificationReceiptBody(decodeVerificationReceipt(wire)))
        "status_evidence_digest" -> "sha384:" + (
            if (kind == "revocation_list") statusEvidenceDigest(decodeRevocationList(wire))
            else statusEvidenceDigest(decodeRevocationPush(wire))
            ).hex()
        "statement_body_digest_hex" -> when (kind) {
            "key_rotation_statement" -> keyRotationStatementDigest(decodeKeyRotationStatement(wire)).hex()
            "witness_entry" -> witnessEntryDigest(decodeWitnessEntry(wire)).hex()
            "verification_receipt" -> verificationReceiptDigest(decodeVerificationReceipt(wire)).hex()
            else -> error("statement digest for $kind")
        }
        else -> {
            require(name.startsWith("party-")) { "unknown digest $name" }
            val r = decodeTransactionReceipt(wire)
            val (partyId, field) = name.split(".", limit = 2)
            val tx = sha256(
                "ratify/transaction-context/v2".toByteArray() + lengthPrefixed(r.transactionId.toByteArray()) +
                    lengthPrefixed(r.termsSchemaUri.toByteArray()) + sha384(r.termsCanonicalJson),
            )
            if (tx.hex() != digests.getString("transaction_context_hex") || !transactionContextHash(r).contentEquals(tx)) {
                "transaction context differs"
            } else {
                val p = r.parties.first { it.partyId == partyId }
                val req = transactionPartyRequestHash(tx, p.requiredScope)
                when (field) {
                    "transaction_party_request_hash_hex" -> req.hex()
                    "session_context_hex" -> buildSessionContext(
                        SessionContextInputs(p.verifierId, p.workspaceId, p.agentId, p.sessionId, p.invocationId, req),
                    ).hex()
                    "proof_bundle_hash" -> bundleHash(p.proofBundle!!)
                    else -> error("unknown party digest $field")
                }
            }
        }
    }

    private fun independentKeyId(k: HybridPublicKey): String =
        sha256("ratify-key-id-v2".toByteArray() + byteArrayOf(0) + k.ed25519 + k.mlDsa65).hex()

    fun objects() {
        val f = Corpus.load("objects.json")
        val t = Tally("objects.json")
        val codes = mutableSetOf<Int>()
        val objects = f.arr("objects")
        var nSignatures = 0
        var nDigests = 0
        for (o in objects) {
            val name = o.getString("name")
            val kind = o.getString("kind")
            val wire = o.b64("wire_b64")
            val re = runCatching { reencode(kind, wire) }
            t.check("re-encode", name, re.getOrNull()?.contentEquals(wire) == true) { "$re" }
            val v = classOf { verifyObject(kind, wire, ByteArray(0), o.getJSONObject("verify")) }
            t.check("verify", name, v == "ok") { v }
            for (sig in o.arr("signatures")) {
                nSignatures++
                val field = sig.getString("field")
                val code = sig.getInt("object_type_code")
                codes += code
                val ty = ObjectType.fromCode(code.toUShort())!!
                val signable = sig.b64("signable_b64")
                val m = signingMessage(ty, signable)
                val ctx = mldsaContext(ty)
                val signer = sig.getString("signer")
                val key = Fixture.key(signer)
                val pinned = signatureOf(sig.getJSONObject("signature"))
                val wireText = String(wire, Charsets.UTF_8)
                val verified = classOf { verifyStatement(ty, signable, pinned, key) }
                val ok = projection(wire, field).contentEquals(signable) &&
                    sha384(signable).hex() == sig.getString("signable_sha384_hex") &&
                    m.contentEquals(sig.b64("message_b64")) && m.size == 77 &&
                    String(ctx, Charsets.UTF_8) == sig.getString("mldsa_context") && ctx.size == 22 &&
                    Fixture.keyId(signer) == sig.getString("signer_key_id_v2") &&
                    Shake256.hash(key.mlDsa65, 64).contentEquals(sig.b64("mldsa_tr_b64")) &&
                    externalMu(key.mlDsa65, ctx, m).contentEquals(sig.b64("mldsa_mu_b64")) &&
                    wireText.contains(b64.encodeToString(pinned.ed25519)) &&
                    wireText.contains(b64.encodeToString(pinned.mlDsa65)) &&
                    verified == "ok"
                t.check("signatures", "$name/$field", ok) { "projection, transcript, or verification differs: $verified" }
            }
            val ds = o.optJSONObject("digests") ?: continue
            for (dname in ds.keys()) {
                val got = objectDigest(dname, kind, wire, ds) ?: continue
                nDigests++
                t.check("digests", "$name/$dname", got == ds.getString(dname)) { "got $got, want ${ds.getString(dname)}" }
            }
        }
        for (code in 1..9) t.check("codes", "code $code", code in codes) { "no signature for code" }
        val expectedDigests = objects.sumOf { o -> o.optJSONObject("digests")?.keys()?.asSequence()?.count { it !in notDigests } ?: 0 }
        check(objects.size == 13 && nSignatures == 19 && nDigests == expectedDigests) { "objects.json shape changed" }
        t.finish(listOf("re-encode" to objects.size, "verify" to objects.size, "signatures" to nSignatures, "codes" to 9,
            "digests" to expectedDigests))
    }

    fun negatives() {
        val f = Corpus.load("object-negatives.json")
        val t = Tally("object-negatives.json")
        val kinds = mutableSetOf<String>()
        val vectors = f.arr("vectors")
        for (v in vectors) {
            val kind = v.getString("kind")
            kinds += kind
            val bundle = if (v.has("bundle_b64")) v.b64("bundle_b64") else ByteArray(0)
            val want = v.getString("expected_error_class")
            check(ErrorClass.fromSpelling(want) != null) { "corpus class $want is outside SPEC-v2 §2.7" }
            val got = classOf { verifyObject(kind, v.b64("wire_b64"), bundle, v.getJSONObject("verify")) }
            t.check("negatives", v.getString("name"), got == want) { "class $got, want $want (${v.getString("mutation")})" }
        }
        check(kinds.size == 9) { "negative kinds: $kinds" }
        t.finish(listOf("negatives" to vectors.size))
    }

    private fun hedgedIdempotency(kind: String, vc: JSONObject, deterministic: ByteArray, hedged: ByteArray): Boolean = when (kind) {
        "witness_entry" -> {
            val first = decodeWitnessEntry(deterministic)
            val again = decodeWitnessEntry(hedged)
            val digest = witnessEntryDigest(first)
            val h = witnessHead(vc.getJSONObject("head"))
            witnessEntryDigest(again).contentEquals(digest) &&
                verifyWitnessEntry(again, WitnessHead(h.logId, first.sequence, digest, mapOf(first.sequence to digest), h.frozen),
                    Fixture.key(vc.getString("witness_key"))) == LogResult.REPLAY
        }
        "verification_receipt" -> {
            val first = decodeVerificationReceipt(deterministic)
            val again = decodeVerificationReceipt(hedged)
            val digest = verificationReceiptDigest(first)
            val h = receiptHead(vc.getJSONObject("head"))
            verificationReceiptDigest(again).contentEquals(digest) &&
                verifyVerificationReceipt(again, Fixture.key(vc.getString("verifier_key")),
                    ReceiptHead(h.logId, h.verifierId, first.sequence, digest, mapOf(first.sequence to digest), h.frozen)) == LogResult.REPLAY
        }
        "key_rotation_statement" -> keyRotationStatementDigest(decodeKeyRotationStatement(deterministic))
            .contentEquals(keyRotationStatementDigest(decodeKeyRotationStatement(hedged)))
        else -> true
    }

    fun hedged() {
        val f = Corpus.load("hedged-signatures.json")
        val t = Tally("hedged-signatures.json")
        val kinds = mutableSetOf<String>()
        var n = 0
        for (o in f.arr("objects")) {
            val name = o.getString("name")
            val kind = o.getString("kind")
            kinds += kind
            val deterministic = o.b64("deterministic_wire_b64")
            val fields = o.strings("resigned_fields")
            check(fields.isNotEmpty())
            val seen = mutableListOf(deterministic)
            val hedged = o.getJSONArray("hedged_wire_b64")
            for (i in 0 until hedged.length()) {
                n++
                val wire = Base64.getDecoder().decode(hedged.getString(i))
                val fresh = seen.none { it.contentEquals(wire) }
                seen += wire
                val re = runCatching { reencode(kind, wire) }.getOrNull()
                val v = classOf { verifyObject(kind, wire, ByteArray(0), o.getJSONObject("verify")) }
                val sameProjection = fields.all { projection(wire, it).contentEquals(projection(deterministic, it)) }
                val idem = runCatching { hedgedIdempotency(kind, o.getJSONObject("verify"), deterministic, wire) }.getOrDefault(false)
                t.check("hedged", "$name#$i", fresh && re?.contentEquals(wire) == true && v == "ok" && sameProjection && idem) {
                    "fresh=$fresh verify=$v projection=$sameProjection idempotency=$idem"
                }
            }
        }
        check(kinds.size == 8) { "hedged kinds: $kinds" }
        t.finish(listOf("hedged" to n))
    }
}
