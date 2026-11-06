package com.ratifyprotocol

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.util.Base64
import kotlinx.coroutines.runBlocking

class JournalTest {
    private class BrokenStore(private val initial: SecurityJournalSnapshot, private val conflict: Boolean) : SecurityJournalStore {
        override suspend fun load(): SecurityJournalSnapshot = initial
        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            if (conflict) throw SecurityJournalStoreError.Conflict()
        }
    }

    companion object {
        @BeforeClass @JvmStatic fun setUpCorpus() {
            val root = File(System.getProperty("ratify.corpus")!!)
            Corpus.read = { File(root, it).readBytes() }
            Corpus.list = { File(root, it).list()!!.toList() }
        }
    }

    private class Store(initial: SecurityJournalSnapshot) : SecurityJournalStore {
        private var current = initial
        var writes = 0
            private set

        override suspend fun load(): SecurityJournalSnapshot = synchronized(this) { current }

        override suspend fun compareAndSwap(expected: SecurityJournalHead, next: SecurityJournalSnapshot) {
            synchronized(this) {
                if (current.head.generation != expected.generation || current.head.digest != expected.digest) {
                    throw SecurityJournalStoreError.Conflict()
                }
                current = next
                writes++
            }
        }
    }

    @Test fun storeCallbackCommitsTheSharedJournalTransitionOnce() = runBlocking {
        val root = File(System.getProperty("ratify.corpus")!!)
        val vector = JSONObject(File(root, "v2/security-journal.json").readText())
        val step = vector.getJSONArray("scenarios").getJSONObject(0).getJSONArray("steps").getJSONObject(0)
        val store = Store(emptySecurityJournalSnapshot())
        val key = Fixture.key("verifier")
        val result = recordSecurityKeyRole(store, "verifier", key)
        assertEquals(step.getJSONObject("expect_head").getLong("generation").toULong(), result.head.generation)
        assertEquals(step.getJSONObject("expect_head").getString("digest"), result.head.digest)
        assertEquals(step.getString("expect_snapshot_b64"), Base64.getEncoder().encodeToString(result.snapshot))
        assertEquals(1, store.writes)
        val retry = recordSecurityKeyRole(store, "verifier", key)
        assertEquals(result.head.digest, retry.head.digest)
        assertEquals(1, store.writes)
    }

    @Test fun genesisRequiresIndependentHead() {
        val root = File(System.getProperty("ratify.corpus")!!)
        val vector = JSONObject(File(root, "v2/security-journal.json").readText())
        val genesis = emptySecurityJournalSnapshot()
        assertEquals(vector.getString("genesis_snapshot"), String(genesis.snapshot))
        assertEquals(vector.getString("genesis_digest"), genesis.head.digest)
        assertEquals(genesis.head.digest, securityJournalSnapshotDigest(genesis.snapshot))
        validateSecurityJournalSnapshot(genesis.snapshot, genesis.head)
        val negatives = vector.getJSONArray("import_negatives")
        for (i in 0 until negatives.length()) {
            val negative = negatives.getJSONObject(i)
            val head = negative.getJSONObject("head")
            try {
                validateSecurityJournalSnapshot(
                    Base64.getDecoder().decode(negative.getString("snapshot_b64")),
                    SecurityJournalHead(head.getLong("generation").toULong(), head.getString("digest")),
                )
                fail("${negative.getString("name")}: invalid journal was accepted")
            } catch (e: RatifyException) {
                assertEquals(negative.getString("name"), negative.getString("expect_error_class"), e.errorClass?.spelling)
            }
        }
    }

    @Test fun storeRejectsRolledBackHeadAndCompareAndSwapConflict() = runBlocking {
        val genesis = emptySecurityJournalSnapshot()
        val rolled = SecurityJournalSnapshot(genesis.snapshot, SecurityJournalHead(genesis.head.generation, "0".repeat(64)))
        val key = Fixture.key("verifier")
        for ((index, store) in listOf(BrokenStore(rolled, false), BrokenStore(genesis, true)).withIndex()) {
            try {
                recordSecurityKeyRole(store, "verifier", key)
                fail("invalid journal store state accepted")
            } catch (e: RatifyException) {
                assertEquals("status_object_rejected", e.errorClass?.spelling)
                if (index == 1) assertTrue(e.message!!.contains("security journal compare-and-swap conflict"))
            }
        }
    }
}
