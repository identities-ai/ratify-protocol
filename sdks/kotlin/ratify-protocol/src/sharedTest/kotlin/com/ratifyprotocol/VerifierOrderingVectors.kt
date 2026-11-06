package com.ratifyprotocol

import org.junit.Assert.assertEquals

/** The complete verifier-ordering corpus through the public Kotlin API. */
object VerifierOrderingVectors {
    fun run() {
        val file = "verifier-ordering.json"
        val vectors = Corpus.load(file).arr("vectors")
        val count = vectors.size
        assertEquals(515, count)
        assertEquals(setOf("preflight", "replay", "evaluating", "committed"),
            vectors.map { it.getJSONObject("expected").getString("stage") }.toSet())
        val test = ClaimTest()
        test.verifierCorpusPreflightOrdering()
        test.verifierCorpusReplay()
        test.verifierCorpusFinalizationRefusals()
        test.verifierCorpusCommittedReceipts()
        Manifest.record(file, count)
    }
}
