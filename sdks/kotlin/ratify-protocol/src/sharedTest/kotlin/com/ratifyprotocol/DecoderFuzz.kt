package com.ratifyprotocol

import java.util.Random
import org.junit.Assert.assertTrue

/** Deterministic public-decoder mutations; CI runs one minute per kind. */
object DecoderFuzz {
    fun run() {
        val objects = Corpus.load("objects.json").arr("objects")
        val decoders: List<Pair<String, (ByteArray) -> Unit>> = listOf(
            "delegation_certificate" to { decodeDelegationCert(it); Unit },
            "proof_bundle" to { decodeProofBundle(it); Unit },
            "revocation_list" to { decodeRevocationList(it); Unit },
            "revocation_push" to { decodeRevocationPush(it); Unit },
            "key_rotation_statement" to { decodeKeyRotationStatement(it); Unit },
            "witness_entry" to { decodeWitnessEntry(it); Unit },
            "verification_receipt" to { decodeVerificationReceipt(it); Unit },
            "transaction_receipt" to { decodeTransactionReceipt(it); Unit },
        )
        val seeds = decoders.map { (kind, decode) ->
            Triple(kind, objects.first { it.getString("kind") == kind }.b64("wire_b64"), decode)
        }.toMutableList()
        val receipt = decodeVerificationReceipt(objects.first { it.getString("kind") == "verification_receipt" }.b64("wire_b64"))
        seeds.add(Triple("verification_receipt_body", verificationReceiptBody(receipt),
            { decodeVerificationReceiptBody(it); Unit }))
        seeds.add(Triple("status_evidence_batch", "[]".toByteArray(),
            { decodeStatusEvidenceBatch(it); Unit }))
        val snapshot = emptySecurityJournalSnapshot()
        seeds.add(Triple("security_journal_snapshot", snapshot.snapshot,
            { validateSecurityJournalSnapshot(it, snapshot.head) }))
        val ack = CheckpointAcknowledgement("0".repeat(32), 1, ByteArray(48), 1_800_000_000)
        val ackWire = encodeCheckpointAcknowledgement(ack)
        val decodedAck = decodeCheckpointAcknowledgement(ackWire)
        assertTrue(decodedAck.logId == ack.logId && decodedAck.entryHash.contentEquals(ack.entryHash))
        assertTrue(encodeCheckpointAcknowledgement(decodedAck).contentEquals(ackWire))
        assertTrue(classOf { decodeCheckpointAcknowledgement(ackWire + " ".toByteArray()) } == "malformed")
        seeds.add(Triple("checkpoint_acknowledgement", ackWire,
            { decodeCheckpointAcknowledgement(it); Unit }))

        val seconds = System.getenv("RATIFY_FUZZ_SECONDS")?.toDouble() ?: 60.0
        assertTrue(seconds > 0)
        val random = Random(0x7261746966797632L)
        for ((kind, wire, decode) in seeds) {
            decode(wire)
            val deadline = System.nanoTime() + (seconds * 1_000_000_000).toLong()
            var iterations = 0
            var peakHeapBytes = 0L
            do {
                val mutated = when (iterations % 4) {
                    0 -> wire.copyOf().also {
                        val offset = random.nextInt(it.size)
                        it[offset] = (it[offset].toInt() xor (1 shl random.nextInt(8))).toByte()
                    }
                    1 -> wire.copyOf(random.nextInt(wire.size))
                    2 -> {
                        val offset = random.nextInt(wire.size)
                        wire.copyOfRange(0, offset) + wire.copyOfRange(0, minOf(32, wire.size)) +
                            wire.copyOfRange(offset, wire.size)
                    }
                    else -> wire + ByteArray(if ((iterations / 4) % 2 == 0) 1_048_576 else 1_048_577) { 0x7b }
                }
                try { decode(mutated) } catch (_: RatifyException) { }
                iterations++
                val runtime = Runtime.getRuntime()
                peakHeapBytes = maxOf(peakHeapBytes, runtime.totalMemory() - runtime.freeMemory())
            } while (System.nanoTime() < deadline)
            assertTrue("$kind ran no mutations", iterations > 0)
            println("FUZZ Kotlin $kind: iterations=$iterations peak_heap_bytes=$peakHeapBytes")
        }
    }
}
