package com.ratifyprotocol

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Base64

/**
 * Produces the provider evidence record (build plan §6.4) for this device's
 * Keystore: public keys only, and three objects the platform key signed
 * through the public API: a delegation certificate it issues, a key rotation
 * into it (its proof of possession), and a revocation list it signs as status
 * key. Every object is verified here before it is written. The record is
 * written under the test package's external files directory and logged in
 * chunks between markers for the evidence run to collect; every SDK's generic
 * runner verifies the committed files.
 *
 * Evidence describes hardware, so the record is produced only on a physical
 * device whose Keystore Ed25519 key is hardware-backed (TEE or StrongBox);
 * an emulator or a software Keystore produces none.
 */
@RunWith(AndroidJUnit4::class)
class ProviderEvidenceTest {
    companion object {
        @BeforeClass @JvmStatic
        fun setUpCorpus() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            Corpus.read = { name -> assets.open(name).use { it.readBytes() } }
            Corpus.list = { dir -> assets.list(dir)!!.toList() }
        }

        private const val TAG = "RatifyEvidence"

        private fun isEmulator(): Boolean =
            Build.HARDWARE in setOf("ranchu", "goldfish", "cutf_cvm", "vsoc_x86_64") ||
                Build.FINGERPRINT.startsWith("generic") || Build.PRODUCT.startsWith("sdk_gphone") ||
                Build.MODEL.startsWith("sdk_gphone")
    }

    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)

    @Test
    fun keystoreEvidence() = runBlocking {
        if (Build.VERSION.SDK_INT < 33 || isEmulator()) {
            Log.i(TAG, "no evidence: not a physical API 33+ device")
            return@runBlocking
        }
        val key = KeystoreKey.generate()
        try {
            val edCustody = key.custody.first
            if (edCustody != KeystoreKey.Custody.TEE && edCustody != KeystoreKey.Custody.STRONGBOX) {
                Log.i(TAG, "no evidence: Keystore Ed25519 custody is $edCustody")
                return@runBlocking
            }
            val platform = SigningKey.Platform(key)
            val objects = Corpus.load("objects.json")

            // 1. A delegation certificate the platform key issues.
            val c = decodeDelegationCert(objectByKind(objects, "delegation_certificate").b64("wire_b64"))
            val cert = signDelegationCert(
                DelegationCert(c.version, c.certId, key.keyId, key.publicKey, c.subjectId, c.subjectPubKey, c.scope,
                    c.constraints, c.issuedAt, c.expiresAt, c.signature),
                platform,
            )
            verifyDelegationCertSignature(cert)

            // 2. A rotation from a fresh software key into the platform key.
            val software = SoftwarePrivateKey.generate()
            val rv = Corpus.load("key-rotation-signature.json")
            val rotation = signKeyRotationStatement(
                KeyRotationStatement(2, rv.getString("authority_id"), 1, rv.getString("role"), 1, ByteArray(48),
                    software.publicKey, key.publicKey, software.keyId, key.keyId, 1_800_000_000, 1_800_000_000,
                    HybridSignature(ByteArray(0), ByteArray(0)), HybridSignature(ByteArray(0), ByteArray(0))),
                SigningKey.Software(software), platform,
            )
            val signable = keyRotationStatementSignableBytes(rotation)
            verifyStatement(ObjectType.KEY_ROTATION_PROOF_OF_POSSESSION, signable, rotation.newSignature, key.publicKey)

            // 3. A revocation list the platform key signs as the issuer's status key.
            val l = decodeRevocationList(objectByKind(objects, "revocation_list").b64("wire_b64"))
            val list = signRevocationList(
                RevocationList(l.version, key.keyId, l.updatedAt, l.nextUpdate, l.sequence, l.revoked, l.signature),
                key.keyId, key.publicKey, platform,
            )
            verifyRevocationListSignature(list, key.keyId, key.publicKey)

            val custodyName = if (edCustody == KeystoreKey.Custody.STRONGBOX) "strongbox" else "tee"
            val record = JSONObject()
                .put("version", 1)
                .put("description", "Provider evidence: an Android Keystore split-custody key (Ed25519 in the Keystore, ML-DSA-65 from a software seed) signed these objects through the Kotlin SDK's public API on this device.")
                .put("platform", "android")
                .put("provider", "keystore")
                .put("sdk", "kotlin")
                .put("device_model", "${Build.MANUFACTURER} ${Build.MODEL}")
                .put("os_version", Build.VERSION.RELEASE)
                .put("os_build", Build.ID)
                .put("custody", JSONObject().put("ed25519", custodyName).put("ml_dsa_65", "software"))
                .put("public_key", JSONObject().put("ed25519", b64(key.publicKey.ed25519)).put("ml_dsa_65", b64(key.publicKey.mlDsa65)))
                .put("key_id_v2", key.keyId)
                .put("objects", JSONArray()
                    .put(JSONObject().put("kind", "delegation_certificate").put("role", "issuer").put("wire_b64", b64(encodeDelegationCert(cert))))
                    .put(JSONObject().put("kind", "key_rotation_statement").put("role", "new_key").put("wire_b64", b64(encodeKeyRotationStatement(rotation))))
                    .put(JSONObject().put("kind", "revocation_list").put("role", "status_key").put("wire_b64", b64(encodeRevocationList(list)))))
            val json = record.toString().toByteArray()

            val dir = InstrumentationRegistry.getInstrumentation().context.getExternalFilesDir(null)
            if (dir != null) File(dir, "android-keystore.json").writeBytes(json)
            val encoded = b64(json)
            Log.i(TAG, "RATIFY-PROVIDER-EVIDENCE-BEGIN android-keystore ${encoded.length}")
            encoded.chunked(3000).forEachIndexed { i, part -> Log.i(TAG, "RATIFY-PROVIDER-EVIDENCE-PART $i $part") }
            Log.i(TAG, "RATIFY-PROVIDER-EVIDENCE-END")
        } finally {
            key.deleteKeystoreEntry()
        }
    }
}
