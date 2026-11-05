package com.ratifyprotocol


import org.json.JSONObject
import java.security.MessageDigest

/** The keys.json fixture keys, by name, derived through the public API. */
object Fixture {
    private val keys: Map<String, SoftwarePrivateKey> by lazy {
        Corpus.load("keys.json").arr("keys").associate {
            it.getString("name") to SoftwarePrivateKey.fromSeeds(it.hex("ed25519_seed_hex"), it.hex("ml_dsa_65_seed_hex"))
        }
    }

    fun key(name: String): HybridPublicKey = keys.getValue(name).publicKey
    fun keyId(name: String): String = keys.getValue(name).keyId
    fun privateKey(name: String): SoftwarePrivateKey = keys.getValue(name)

    val seeds: Map<String, Pair<ByteArray, ByteArray>> by lazy {
        Corpus.load("keys.json").arr("keys").associate {
            it.getString("name") to (it.hex("ed25519_seed_hex") to it.hex("ml_dsa_65_seed_hex"))
        }
    }
}

fun publicKeyOf(v: JSONObject): HybridPublicKey = HybridPublicKey(v.b64("ed25519"), v.b64("ml_dsa_65"))
fun signatureOf(v: JSONObject): HybridSignature = HybridSignature(v.b64("ed25519"), v.b64("ml_dsa_65"))
fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

fun witnessHead(h: JSONObject): WitnessHead {
    val accepted = mutableMapOf<Long, ByteArray>()
    h.optJSONObject("accepted_digests_b64")?.let { m -> for (k in m.keys()) accepted[k.toLong()] = m.b64(k) }
    return WitnessHead(h.getString("log_id"), h.getLong("sequence"), h.b64("head_hash_b64"), accepted, h.optBoolean("frozen", false))
}

fun receiptHead(h: JSONObject): ReceiptHead {
    val w = witnessHead(h)
    return ReceiptHead(w.logId, h.getString("verifier_id"), w.sequence, w.headHash, w.acceptedDigests, w.frozen)
}

fun rotationState(v: JSONObject, key: (String) -> HybridPublicKey = Fixture::key): RotationState = RotationState(
    v.getString("authority_id"), v.getLong("recovery_epoch"), v.getString("role"), v.getLong("sequence"),
    v.b64("head_hash_b64"), key(v.getString("current_key")), v.strings("used_key_ids"),
)

/** The per-kind decode and verify procedure of the object corpora (Rust v2_common verify_object). */
fun verifyObject(kind: String, wire: ByteArray, bundle: ByteArray, vc: JSONObject,
                 key: (String) -> HybridPublicKey = Fixture::key) {
    when (kind) {
        "delegation_certificate" -> verifyDelegationCertSignature(decodeDelegationCert(wire))
        "proof_bundle" -> verifyProofBundleSignatures(decodeProofBundle(wire))
        "revocation_list" ->
            verifyRevocationListSignature(decodeRevocationList(wire), vc.getString("bound_issuer_id"), key(vc.getString("status_key")))
        "revocation_push" ->
            verifyRevocationPushSignature(decodeRevocationPush(wire), vc.getString("bound_issuer_id"), key(vc.getString("status_key")))
        "key_rotation_statement" -> verifyKeyRotationStatement(
            decodeKeyRotationStatement(wire), rotationState(vc.getJSONObject("rotation_state"), key),
            vc.getLong("now"), vc.getLong("future_skew_seconds"),
        )
        "witness_entry" -> verifyWitnessEntry(decodeWitnessEntry(wire), witnessHead(vc.getJSONObject("head")), key(vc.getString("witness_key")))
        "transaction_receipt" -> verifyTransactionReceiptSignatures(decodeTransactionReceipt(wire))
        "verification_receipt" -> verifyVerificationReceipt(
            decodeVerificationReceipt(wire), key(vc.getString("verifier_key")), receiptHead(vc.getJSONObject("head")),
        )
        "receipt_bundle_binding" -> checkVerificationReceiptBundleBinding(decodeVerificationReceipt(wire), decodeProofBundle(bundle))
        else -> error("unknown kind $kind")
    }
}

fun reencode(kind: String, wire: ByteArray): ByteArray = when (kind) {
    "delegation_certificate" -> encodeDelegationCert(decodeDelegationCert(wire))
    "proof_bundle" -> encodeProofBundle(decodeProofBundle(wire))
    "revocation_list" -> encodeRevocationList(decodeRevocationList(wire))
    "revocation_push" -> encodeRevocationPush(decodeRevocationPush(wire))
    "key_rotation_statement" -> encodeKeyRotationStatement(decodeKeyRotationStatement(wire))
    "witness_entry" -> encodeWitnessEntry(decodeWitnessEntry(wire))
    "transaction_receipt" -> encodeTransactionReceipt(decodeTransactionReceipt(wire))
    "verification_receipt" -> encodeVerificationReceipt(decodeVerificationReceipt(wire))
    else -> error("unknown kind $kind")
}

/**
 * SPEC-v2 §5 projection for a signature field, recomputed here from the wire
 * JSON (independent of the core's projection functions), except the
 * transaction party statement, whose transcript is the SDK's sign bytes.
 */
fun projection(wire: ByteArray, field: String): ByteArray {
    val obj = JSONObject(String(wire, Charsets.UTF_8))
    fun drop(vararg fields: String): ByteArray {
        for (f in fields) obj.remove(f)
        return canonicalJson(obj.toString().toByteArray(Charsets.UTF_8))
    }
    return when {
        field == "signature" -> drop("signature")
        field == "challenge_sig" -> drop("delegations", "challenge_sig")
        field == "old_signature" || field == "new_signature" -> drop("old_signature", "new_signature")
        field.startsWith("delegations[") -> {
            val idx = field.removePrefix("delegations[").takeWhile { it.isDigit() }.toInt()
            projection((obj.getJSONArray("delegations").get(idx) as JSONObject).toString().toByteArray(), "signature")
        }
        field.startsWith("party_signatures[") -> transactionReceiptSignBytes(decodeTransactionReceipt(wire))
        else -> error("unknown signature field $field")
    }
}

