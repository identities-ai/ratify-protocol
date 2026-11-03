package com.ratifyprotocol

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every entry of testvectors/v2 must be consumed by a Kotlin runner that
 * calls only the public API, or be listed as pending for a named later
 * milestone. A new corpus file, or a runner that stops reading its file,
 * fails here. At full parity the pending list is empty. Runs on the host
 * because it reads the runner sources.
 */
class ConsumedTest {
    private val corpus = File(System.getProperty("ratify.corpus")!!, "v2")
    private val sources = File("src/sharedTest/kotlin/com/ratifyprotocol")

    /** Corpus entry, runner file, and text the runner must contain to show it reads the entry. */
    private val consumed = listOf(
        Triple("annex-a.json", "AnnexAVectors.kt", "\"annex-a.json\""),
        Triple("keys.json", "KeysVectors.kt", "\"keys.json\""),
        Triple("limits.json", "LimitsVectors.kt", "\"limits.json\""),
        Triple("operation-session-context.json", "OperationContextVectors.kt", "\"operation-session-context.json\""),
    )

    /** Entries whose runners land in a later milestone (build plan §9). */
    private val pending = mapOf(
        "README.md" to "M3",
        "archival.json" to "M2",
        "challenge-claim.json" to "M2",
        "challenge-issuance.json" to "M3",
        "concurrency-scenarios.json" to "M4",
        "cross-sdk" to "M4",
        "delegation-signature.json" to "M2",
        "derive-external-mu.py" to "M2",
        "device-state.json" to "M3",
        "digest-functions.json" to "M2",
        "evaluator-profiles.json" to "M3",
        "external-signer.json" to "M2",
        "hedged-signatures.json" to "M2",
        "issuer-duties.json" to "M2",
        "key-rotation-signature.json" to "M2",
        "lifecycle-scenarios.json" to "M3",
        "log-sequences.json" to "M2",
        "object-negatives.json" to "M2",
        "objects.json" to "M2",
        "rotation-sequences.json" to "M2",
        "security-journal.json" to "M2",
        "status-publisher.json" to "M2",
        "status-sequences.json" to "M2",
        "transaction-verification.json" to "M3",
        "verifier-ordering.json" to "M3",
    )

    @Test
    fun everyCorpusEntryIsConsumedOrPending() {
        val entries = corpus.list()!!.toSet()
        val names = consumed.map { it.first }.toSet()
        assertTrue("an entry is both consumed and pending", names.intersect(pending.keys).isEmpty())
        for (e in entries.sorted()) assertTrue("corpus entry $e has no Kotlin runner", e in names || e in pending)
        for (e in names + pending.keys) assertTrue("table lists $e, which is not in the corpus", e in entries)
        for ((entry, runner, marker) in consumed) {
            assertTrue("$runner no longer reads $entry", File(sources, runner).readText().contains(marker))
        }
    }

    /** No runner may skip: a skipped case is a silent pass. */
    @Test
    fun noRunnerSkips() {
        val banned = listOf("@" + "Ignore", "assume" + "True", "assume" + "That", "Assume" + ".")
        val roots = listOf("src/sharedTest", "src/test", "src/androidTest").map(::File)
        for (f in roots.flatMap { it.walkTopDown().filter { f -> f.extension == "kt" }.toList() }) {
            val src = f.readText()
            for (b in banned) assertFalse("${f.name} uses $b", src.contains(b))
        }
    }
}
