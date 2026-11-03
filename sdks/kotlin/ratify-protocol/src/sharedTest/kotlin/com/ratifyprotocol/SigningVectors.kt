package com.ratifyprotocol

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

import java.util.Base64
import kotlin.coroutines.cancellation.CancellationException

/**
 * delegation-signature.json, derive-external-mu.py, key-rotation-signature.json,
 * issuer-duties.json and external-signer.json through the public API.
 */
object SigningVectors {
    fun delegationSignature() {
        val v = Corpus.load("delegation-signature.json")
        val t = Tally("delegation-signature.json")
        check(v.getInt("object_type_code") == 1)
        val signable = v.b64("signable_bytes")
        t.check("transcript", "message", signingMessage(ObjectType.DELEGATION_CERTIFICATE, signable).contentEquals(v.b64("message")))
        val ctx = mldsaContext(ObjectType.DELEGATION_CERTIFICATE)
        t.check("transcript", "context", ctx.contentEquals(v.b64("mldsa_context")) && !ctx.contentEquals(v.b64("alternate_mldsa_context")))
        val key = publicKeyOf(v.getJSONObject("issuer_public_key"))
        t.check("keys", "key id", keyId(key) == v.getString("key_id_v2"))
        val seeds = v.getJSONObject("issuer_seeds")
        t.check("keys", "seeds", SoftwarePrivateKey.fromSeeds(seeds.b64("ed25519"), seeds.b64("ml_dsa_65")).publicKey == key)
        val sig = signatureOf(v.getJSONObject("signature"))
        t.check("verify", "pinned", classOf { verifyStatement(ObjectType.DELEGATION_CERTIFICATE, signable, sig, key) } == "ok")
        t.check("verify", "other code",
            classOf { verifyStatement(ObjectType.CHALLENGE_PRESENTATION, signable, sig, key) } == "invalid_signature")
        val neg = v.getJSONObject("negative_mutations")
        val mask = neg.getInt("xor_mask")
        val targets = neg.strings("targets")
        for (target in targets) {
            var sb = signable.copyOf()
            var ed = sig.ed25519
            var ml = sig.mlDsa65
            var ked = key.ed25519
            var kml = key.mlDsa65
            fun flip(b: ByteArray) = b.also { it[0] = (it[0].toInt() xor mask).toByte() }
            when (target) {
                "signable_bytes" -> sb = flip(sb)
                "signature.ed25519" -> ed = flip(ed)
                "signature.ml_dsa_65" -> ml = flip(ml)
                "issuer_public_key.ed25519" -> ked = flip(ked)
                "issuer_public_key.ml_dsa_65" -> kml = flip(kml)
                else -> error("unknown mutation target $target")
            }
            t.check("mutations", target,
                classOf { verifyStatement(ObjectType.DELEGATION_CERTIFICATE, sb, HybridSignature(ed, ml), HybridPublicKey(ked, kml)) } != "ok")
        }
        t.check("keys", "short ed25519", classOf { keyId(HybridPublicKey(key.ed25519.copyOf(31), key.mlDsa65)) } == "malformed")
        t.check("keys", "short ml-dsa", classOf { keyId(HybridPublicKey(key.ed25519, key.mlDsa65.copyOf(1951))) } == "malformed")
        t.finish(listOf("transcript" to 2, "keys" to 4, "verify" to 2, "mutations" to targets.size))
    }

    /** The derivation in derive-external-mu.py, independently and through the SDK. */
    fun deriveExternalMu() {
        val v = Corpus.load("delegation-signature.json")
        val t = Tally("derive-external-mu.py")
        val key = publicKeyOf(v.getJSONObject("issuer_public_key"))
        val ctx = v.b64("mldsa_context")
        val m = v.b64("message")
        check(ctx.size == 22 && m.size == 77)
        val tr = Shake256.hash(key.mlDsa65, 64)
        t.check("mu", "tr", tr.contentEquals(v.b64("mldsa_tr")))
        t.check("mu", "independent", Shake256.hash(tr + byteArrayOf(0, ctx.size.toByte()) + ctx + m, 64).contentEquals(v.b64("mldsa_mu")))
        t.check("mu", "sdk", externalMu(key.mlDsa65, ctx, m).contentEquals(v.b64("mldsa_mu")))
        t.check("mu", "script names the vector", String(Corpus.bytes("derive-external-mu.py")).contains("delegation-signature.json"))
        t.finish(listOf("mu" to 4))
    }

    fun keyRotationSignature() {
        val v = Corpus.load("key-rotation-signature.json")
        val t = Tally("key-rotation-signature.json")
        val cases = listOfNotNull(v, v.optJSONObject("continuation"))
        val row = "key-rotation-signature.json"
        for ((n, c) in cases.withIndex()) {
            val os = c.getJSONObject("old_key_seeds")
            val ns = c.getJSONObject("new_key_seeds")
            val old = SoftwarePrivateKey.fromSeeds(os.hex("ed25519"), os.hex("ml_dsa_65"))
            val new = SoftwarePrivateKey.fromSeeds(ns.hex("ed25519"), ns.hex("ml_dsa_65"))
            t.check(row, "case $n keys",
                old.publicKey == publicKeyOf(c.getJSONObject("old_key")) && new.publicKey == publicKeyOf(c.getJSONObject("new_key")))
            val stmt = KeyRotationStatement(
                c.getLong("version"), c.getString("authority_id"), c.getLong("recovery_epoch"), c.getString("role"),
                c.getLong("sequence"), c.b64("previous_statement_hash"), old.publicKey, new.publicKey,
                c.getString("old_key_id"), c.getString("new_key_id"), c.getLong("issued_at"), c.getLong("not_before"),
                signatureOf(c.getJSONObject("old_signature")), signatureOf(c.getJSONObject("new_signature")),
            )
            val signable = keyRotationStatementSignableBytes(stmt)
            t.check(row, "case $n signable", signable.contentEquals(c.b64("signable_bytes")))
            t.check(row, "case $n digest", keyRotationStatementDigest(stmt).hex() == c.getString("statement_body_digest"))
            t.check(row, "case $n contexts",
                mldsaContext(ObjectType.KEY_ROTATION_AUTHORIZATION).contentEquals(c.getString("old_mldsa_context").toByteArray()) &&
                    mldsaContext(ObjectType.KEY_ROTATION_PROOF_OF_POSSESSION).contentEquals(c.getString("new_mldsa_context").toByteArray()))
            fun bothVerify(s: KeyRotationStatement) =
                classOf { verifyStatement(ObjectType.KEY_ROTATION_AUTHORIZATION, signable, s.oldSignature, old.publicKey) } == "ok" &&
                    classOf { verifyStatement(ObjectType.KEY_ROTATION_PROOF_OF_POSSESSION, signable, s.newSignature, new.publicKey) } == "ok"
            t.check(row, "case $n signatures", bothVerify(stmt))
            val wire = encodeKeyRotationStatement(stmt)
            t.check(row, "case $n wire", wire.contentEquals(c.b64("wire")))
            t.check(row, "case $n decode", classOf { decodeKeyRotationStatement(wire) } == "ok")
            t.check(row, "case $n resign", bothVerify(signKeyRotationStatement(stmt, old, new)))
        }
        check(cases.size == 2)
        t.finish(listOf(row to 8 * cases.size))
    }

    fun issuerDuties() = runBlocking {
        val f = Corpus.load("issuer-duties.json")
        val t = Tally("issuer-duties.json")
        val vectors = f.arr("vectors")
        for (v in vectors) {
            val cert = decodeDelegationCert(v.b64("unsigned_certificate_b64"))
            val signer = ProviderSigner(v.getString("issuer"))
            val (ok, detail) = try {
                val signed = signDelegationCert(cert, signer)
                (v.getString("expected") == "sign" && classOf { verifyDelegationCertSignature(signed) } == "ok") to "signed"
            } catch (e: RatifyException.Signing) {
                (v.getString("expected") == "reject" && e.kind == SigningErrorKind.ISSUER_DUTY && signer.calls == 0) to
                    "$e, ${signer.calls} signer calls"
            }
            t.check("issuer-duties", v.getString("name"), ok) { detail }
        }
        t.finish(listOf("issuer-duties" to vectors.size))
    }

    /** A provider scripted by external-signer.json: records requests, then signs, fails, or cancels its caller. */
    class ScriptedSigner(
        override val publicKey: HybridPublicKey,
        override val mode: SignerMode,
        private val response: String,
        private val signature: HybridSignature,
    ) : ExternalSigner {
        val requests = java.util.Collections.synchronizedList(mutableListOf<SignRequest>())
        @Volatile var cancelCaller: (() -> Unit)? = null

        override suspend fun sign(request: SignRequest): HybridSignature {
            requests += request
            when (response) {
                "error" -> throw ProviderException("scripted provider failure")
                "cancel" -> cancelCaller?.invoke()
            }
            return signature
        }
    }

    /** The §2.7 class of a failed call; a cancelled coroutine reports the core's cause, or evaluation_cancelled if it never ran. */
    private fun outcomeClass(e: Throwable): String = when (e) {
        is RatifyException -> e.errorClass?.spelling ?: "internal"
        is CancellationException -> (e.cause as? RatifyException)?.errorClass?.spelling ?: "evaluation_cancelled"
        else -> "non-ratify $e"
    }

    fun externalSigner() = runBlocking {
        val f = Corpus.load("external-signer.json")
        val t = Tally("external-signer.json")
        val cases = f.arr("cases")
        for (c in cases) {
            val name = c.getString("name")
            val p = c.getJSONObject("provider")
            val sig = p.optJSONObject("signature")?.let(::signatureOf) ?: HybridSignature(ByteArray(0), ByteArray(0))
            val signer = ScriptedSigner(
                Fixture.key(p.getString("public_key")),
                if (p.getString("mode") == "direct") SignerMode.DIRECT else SignerMode.EXTERNAL_MU,
                p.getString("response"), sig,
            )
            val wire = c.b64("object_b64")
            val precancel = c.optBoolean("caller_cancelled", false)
            // A supervisor scope: an expected failure must not cancel the runner.
            val job = CoroutineScope(Dispatchers.Default + SupervisorJob()).async(start = CoroutineStart.LAZY) {
                when (val kind = c.getString("kind")) {
                    "delegation_certificate" -> encodeDelegationCert(signDelegationCert(decodeDelegationCert(wire), signer))
                    "revocation_list" -> {
                        val b = c.getJSONObject("binding")
                        encodeRevocationList(signRevocationList(decodeRevocationList(wire), b.getString("issuer_id"),
                            Fixture.key(b.getString("status_key")), signer))
                    }
                    "proof_bundle" -> encodeProofBundle(signProofBundle(decodeProofBundle(wire), signer))
                    else -> error("$name: unknown kind $kind")
                }
            }
            signer.cancelCaller = { (job as Job).cancel() }
            if (precancel) job.cancel()
            job.start()
            val signed = runCatching { job.await() }
            val e = c.getJSONObject("expected")
            val reqs = signer.requests.toList()
            var ok = reqs.size == e.getInt("provider_calls")
            var detail = "provider calls ${reqs.size}, want ${e.getInt("provider_calls")}"
            if (ok && !e.isNull("request")) {
                val want = e.getJSONObject("request")
                val r = reqs[0]
                val mode = if (r.mode == SignerMode.DIRECT) "direct" else "external_mu"
                val ctxOk = if (want.isNull("mldsa_context")) r.mlDsaContext == null
                else r.mlDsaContext?.contentEquals(want.getString("mldsa_context").toByteArray()) == true
                val muOk = if (want.isNull("mldsa_mu_b64")) r.mlDsaMu == null
                else r.mlDsaMu?.contentEquals(Base64.getDecoder().decode(want.getString("mldsa_mu_b64"))) == true
                ok = mode == want.getString("mode") && r.message.contentEquals(want.b64("message_b64")) && ctxOk && muOk &&
                    r.keyId == want.getString("key_id_v2") && r.publicKey == signer.publicKey
                detail = "provider request differs"
            }
            if (ok) {
                val err = signed.exceptionOrNull()
                if (e.getString("result") == "signed") {
                    ok = signed.getOrNull()?.contentEquals(e.b64("signed_wire_b64")) == true
                    detail = "signed object differs: $err"
                } else {
                    ok = err != null && outcomeClass(err) == e.getString("error_class")
                    detail = "${err?.let(::outcomeClass)}, want ${e.getString("error_class")}"
                }
            }
            t.check("external-signer", name, ok) { detail }
        }
        check(cases.size == 17) { "external signer cases" }
        t.finish(listOf("external-signer" to cases.size))
    }

}
