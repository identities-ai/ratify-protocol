package com.ratifyprotocol

import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/** No runner may skip: a skipped case is a silent pass. Runs on the host
 * because it reads the test sources. Corpus coverage is checked by
 * [CorpusRunners.runAll] on every platform. */
class ConsumedTest {
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

/** The published KEY_STORAGE.md vector is exactly what the SDK writes (host only: it reads the doc). */
class KeyStorageDocTest {
    @org.junit.Test
    fun publishedVectorMatchesTheSdk() {
        val root = java.io.File(System.getProperty("ratify.corpus")!!)
        Corpus.read = { java.io.File(root, it).readBytes() }
        val doc = java.io.File(root, "../sdks/kotlin/KEY_STORAGE.md").readText()
        val line = doc.lines().first { it.startsWith("5246594b") }
        val key = Fixture.privateKey("root")
        org.junit.Assert.assertEquals(line, key.storageRecord().hex())
        org.junit.Assert.assertTrue(doc.contains("has key ID `${key.keyId}`"))
    }
}
