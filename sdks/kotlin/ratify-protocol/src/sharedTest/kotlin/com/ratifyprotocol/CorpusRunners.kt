package com.ratifyprotocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * The whole corpus through the public Kotlin API, run by both the host and
 * the device suite. Every entry of testvectors/v2 must have a runner here, or
 * be listed as pending for a named later milestone; each runner is executed
 * and must report a nonzero case count for its entry. A new corpus file, or
 * a runner that stops executing, fails here. At full parity `pending` is empty.
 */
object CorpusRunners {
    private fun annex(): String = String(Corpus.read("spec/SPEC-v2-ANNEX-A.md"), Charsets.UTF_8)

    val runners: Map<String, () -> Unit> = mapOf(
        "README.md" to CorpusReadmeVectors::run,
        "annex-a.json" to { AnnexAVectors.corpus(annex()) },
        "keys.json" to KeysVectors::corpus,
        "limits.json" to LimitsVectors::corpus,
        "operation-session-context.json" to OperationContextVectors::corpus,
        "objects.json" to ObjectsVectors::objects,
        "object-negatives.json" to ObjectsVectors::negatives,
        "hedged-signatures.json" to ObjectsVectors::hedged,
        "delegation-signature.json" to SigningVectors::delegationSignature,
        "derive-external-mu.py" to SigningVectors::deriveExternalMu,
        "key-rotation-signature.json" to SigningVectors::keyRotationSignature,
        "issuer-duties.json" to { SigningVectors.issuerDuties() },
        "external-signer.json" to { SigningVectors.externalSigner() },
        "archival.json" to ArchivalVectors::archival,
        "digest-functions.json" to ArchivalVectors::digestFunctions,
        "log-sequences.json" to LogsVectors::logSequences,
        "rotation-sequences.json" to LogsVectors::rotationSequences,
        "status-sequences.json" to StatusVectors::statusSequences,
        "challenge-claim.json" to StatusVectors::challengeClaim,
        "challenge-issuance.json" to ChallengeIssuanceVectors::run,
        "provider-evidence" to ProviderEvidenceVectors::run,
        "security-journal.json" to JournalVectors::run,
        "status-publisher.json" to PublisherVectors::run,
        "evaluator-profiles.json" to EvaluatorVectors::run,
        "transaction-verification.json" to TransactionVerifyVectors::run,
        "device-state.json" to DeviceStateVectors::run,
        "verifier-ordering.json" to VerifierOrderingVectors::run,
        "concurrency-scenarios.json" to ConcurrencyVectors::run,
        "lifecycle-scenarios.json" to {
            val tests = ClaimTest()
            tests.dualRootBothReleasedExecutesOnce()
            tests.singleDeviceReleaseRequiresComponentAck()
            tests.lifecycleBasicReleaseScenarios()
        },
    )

    /** Entries whose runners land in a later milestone (build plan §9). */
    val pending: Map<String, String> = mapOf(
        "cross-sdk" to "M4",
    )

    fun runAll() {
        val entries = Corpus.list("v2").toSet()
        assertTrue("an entry is both consumed and pending", runners.keys.intersect(pending.keys).isEmpty())
        assertEquals("runners + pending must equal the corpus", entries, runners.keys + pending.keys)
        Manifest.reset()
        for ((file, run) in runners.toSortedMap()) {
            run()
            assertTrue("$file: runner reported no executed cases", Manifest.count(file) > 0)
            if (file == "lifecycle-scenarios.json") {
                val corpus = Corpus.load(file)
                assertEquals(corpus.arr("scenarios").size + corpus.arr("profile_scenarios").size,
                    Manifest.count(file))
            }
            if (file == "concurrency-scenarios.json") {
                assertEquals(Corpus.load(file).arr("scenarios").size, Manifest.count(file))
            }
        }
    }
}
