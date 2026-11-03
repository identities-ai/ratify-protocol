package com.ratifyprotocol

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import java.security.MessageDigest
import java.util.Base64

/** Reads the shared corpus in place: a host directory or the test APK's assets. */
object Corpus {
    lateinit var read: (String) -> ByteArray

    fun bytes(name: String): ByteArray = read("v2/$name")
    fun load(name: String): JSONObject = JSONObject(String(bytes(name), Charsets.UTF_8))
}

fun JSONObject.arr(k: String): List<JSONObject> = getJSONArray(k).let { a -> List(a.length()) { a.getJSONObject(it) } }
fun JSONObject.strings(k: String): List<String> = getJSONArray(k).strings()
fun JSONArray.strings(): List<String> = List(length()) { getString(it) }
fun JSONObject.b64(k: String): ByteArray = Base64.getDecoder().decode(getString(k))
fun JSONObject.hex(k: String): ByteArray = getString(k).hexBytes()

fun String.hexBytes(): ByteArray {
    require(length % 2 == 0) { "odd hex" }
    return ByteArray(length / 2) { substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

/**
 * Counts executed checks per group. [finish] fails unless every group ran
 * exactly the number of cases computed from the file: no case is skipped.
 */
class Tally {
    private val counts = linkedMapOf<String, Int>()
    private val failures = mutableListOf<String>()

    fun check(group: String, name: String, ok: Boolean, detail: () -> String = { "" }) {
        counts[group] = (counts[group] ?: 0) + 1
        if (!ok) failures += "$group/$name: ${detail()}"
    }

    fun finish(expected: List<Pair<String, Int>>) {
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
        for ((g, n) in expected) {
            assertTrue("group $g must have cases", n > 0)
            assertEquals("group $g executed count", n, counts[g] ?: 0)
        }
        assertEquals("groups executed", expected.map { it.first }.toSet(), counts.keys)
    }
}

/** The §2.7 class a call fails with, "ok" on success. */
fun classOf(body: () -> Unit): String =
    try {
        body()
        "ok"
    } catch (e: RatifyException) {
        e.errorClass?.spelling ?: "internal"
    }
